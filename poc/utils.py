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
