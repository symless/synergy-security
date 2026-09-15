"""
Common utilities for Synergy security PoCs.
"""

import socket
import ssl


def create_ssl_context():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("ALL:@SECLEVEL=0")
    return context


def normalize_host(host):
    if host.startswith("tls://"):
        return host[6:]
    return host


def create_ssl_socket(host, port, timeout=5.0):
    context = create_ssl_context()
    sock = socket.create_connection((normalize_host(host), port), timeout=timeout)
    ssl_sock = context.wrap_socket(sock, server_hostname=host)
    ssl_sock.settimeout(timeout)
    return ssl_sock


def frame_message(payload, is_initial=False):
    if is_initial:
        return b"\x16\x03\x03\x00\x14\x00\x00\x00\x0b\x53\x79\x6e\x65\x72\x67\x79\x00\x01\x00\x08"

    MAX_CHUNK_SIZE = 16384 - 32
    handshake = b"\x00\x00\x00\x0b\x53\x79\x6e\x65\x72\x67\x79\x00\x01\x00\x08"

    if len(payload) <= MAX_CHUNK_SIZE:
        msg = handshake + payload
        tls_header = b"\x16\x03\x03" + len(msg).to_bytes(2, byteorder="big")
        return tls_header + msg

    chunks = []
    for i in range(0, len(payload), MAX_CHUNK_SIZE):
        msg = handshake + payload[i:i + MAX_CHUNK_SIZE]
        tls_header = b"\x16\x03\x03" + len(msg).to_bytes(2, byteorder="big")
        chunks.append(tls_header + msg)
    return b"".join(chunks)
