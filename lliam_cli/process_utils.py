"""Cross-platform process helpers (PID liveness, termination, start time).

Moved out of the removed messaging-gateway package (JER-198) so the desktop
backend, tools, and CLI keep one shared implementation. Nothing here is
gateway-specific.
"""

import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Optional

_IS_WINDOWS = sys.platform == "win32"


def terminate_pid(pid: int, *, force: bool = False) -> None:
    """Terminate a PID with platform-appropriate force semantics.

    POSIX uses SIGTERM/SIGKILL. Windows uses taskkill /T /F for true force-kill
    because os.kill(..., SIGTERM) is not equivalent to a tree-killing hard stop.
    """
    if force and _IS_WINDOWS:
        # CREATE_NO_WINDOW: terminate_pid runs from the windowless pythonw.exe
        # desktop backend, so a bare taskkill spawn would flash a
        # conhost window on every force-kill.
        from lliam_cli._subprocess_compat import windows_hide_flags

        try:
            result = subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=windows_hide_flags(),
            )
        except FileNotFoundError:
            os.kill(pid, signal.SIGTERM)
            return

        if result.returncode != 0:
            details = (result.stderr or result.stdout or "").strip()
            raise OSError(details or f"taskkill failed for PID {pid}")
        return

    sig = signal.SIGTERM if not force else getattr(signal, "SIGKILL", signal.SIGTERM)
    os.kill(pid, sig)


def _get_process_start_time(pid: int) -> Optional[int]:
    """Return a stable per-process start-time fingerprint, or None.

    Used as a PID-reuse guard: a ``(pid, start_time)`` pair uniquely identifies
    a process, so a recycled PID (same number, different process) yields a
    different value and is never mistaken for the original.

    On Linux this is field 22 of ``/proc/<pid>/stat`` (start time in clock
    ticks since boot, an int).  On platforms without ``/proc`` (macOS, Windows)
    we fall back to ``psutil.Process(pid).create_time()`` — a float epoch
    timestamp — quantized to an int (centiseconds) for stable equality.

    The two sources are never mixed on a single platform: ``/proc`` always
    succeeds first on Linux, and always fails on macOS/Windows so psutil is
    always used there.  Because the guard only compares the value recorded at
    spawn against the live value *on the same host*, the differing units across
    platforms are irrelevant — only same-source equality matters.
    """
    stat_path = Path(f"/proc/{pid}/stat")
    try:
        # Field 22 in /proc/<pid>/stat is process start time (clock ticks).
        return int(stat_path.read_text(encoding="utf-8").split()[21])
    except (FileNotFoundError, IndexError, PermissionError, ValueError, OSError):
        pass

    # No /proc (macOS / Windows): psutil is a hard dependency and exposes a
    # cross-platform creation time.  Quantize to centiseconds so repeated reads
    # of the same process compare equal without float-precision fragility.
    try:
        import psutil  # type: ignore
        return int(round(psutil.Process(pid).create_time() * 100))
    except Exception:
        return None


def get_process_start_time(pid: int) -> Optional[int]:
    """Public wrapper for retrieving a process start time when available."""
    return _get_process_start_time(pid)


def _read_process_cmdline(pid: int) -> Optional[str]:
    """Return the process command line as a space-separated string.

    On Linux, reads /proc/<pid>/cmdline directly.  On macOS and other
    platforms without /proc, falls back to ``ps -p <pid> -o command=``.
    On Windows (no /proc, no ps), uses psutil.
    """
    cmdline_path = Path(f"/proc/{pid}/cmdline")
    try:
        raw = cmdline_path.read_bytes()
    except (FileNotFoundError, PermissionError, OSError):
        pass
    else:
        if raw:
            return raw.replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()

    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "command="],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass

    # Windows fallback: psutil (already used by _pid_exists)
    try:
        import psutil  # type: ignore
        proc = psutil.Process(pid)
        cmdline_parts = proc.cmdline()
        if cmdline_parts:
            return " ".join(cmdline_parts)
    except Exception:
        pass

    return None


def _pid_exists(pid: int) -> bool:
    """Cross-platform "is this PID alive" check that does NOT kill the target.

    CRITICAL on Windows: Python's ``os.kill(pid, 0)`` is NOT a no-op like it
    is on POSIX. CPython's Windows implementation
    (``Modules/posixmodule.c::os_kill_impl``) treats ``sig=0`` as
    ``CTRL_C_EVENT`` because the two values collide at the C level, and
    routes it through ``GenerateConsoleCtrlEvent(0, pid)`` — which sends
    a Ctrl+C to the entire console process group containing the target
    PID, not just the PID itself. Any caller that wanted to "check if
    this PID is alive" via ``os.kill(pid, 0)`` on Windows was silently
    killing that process (and often unrelated processes in the same
    console group). Long-standing Python quirk; see bpo-14484.

    Implementation: prefer :mod:`psutil` (hard dependency — the canonical
    cross-platform answer, maintained by Giampaolo Rodolà, uses
    ``OpenProcess + GetExitCodeProcess`` on Windows internally). Fall back
    to a hand-rolled ctypes ``OpenProcess`` / ``WaitForSingleObject`` pair
    on Windows + ``os.kill(pid, 0)`` on POSIX if psutil is somehow
    unavailable — e.g. stripped-down install or import error during the
    scaffold phase before ``psutil`` is pip-installed.
    """
    try:
        import psutil  # type: ignore

        # A zombie (defunct) process is still in the process table, so
        # ``psutil.pid_exists()`` returns True for it — but it is already
        # dead: SIGKILL has no effect on it. Treating a zombie as alive makes
        # callers wait forever for a PID that only its parent can reap
        # (issue #42126). Report zombies as dead.
        # Best-effort: any failure to read status (partial/stub psutil,
        # access denied, transient race) falls through to the authoritative
        # ``pid_exists()`` below rather than raising.
        try:
            if psutil.Process(int(pid)).status() == psutil.STATUS_ZOMBIE:
                return False
        except getattr(psutil, "NoSuchProcess", ()):
            return False
        except Exception:
            pass
        return bool(psutil.pid_exists(int(pid)))

    except ImportError:
        pass  # Fall through to stdlib fallback.
    if _IS_WINDOWS:
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            # Pin return types — default ctypes restype is c_int (signed),
            # which mangles WAIT_* DWORD return codes into negative numbers.
            kernel32.OpenProcess.restype = ctypes.c_void_p
            kernel32.WaitForSingleObject.restype = ctypes.c_uint
            kernel32.GetLastError.restype = ctypes.c_uint
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            SYNCHRONIZE = 0x100000  # required for WaitForSingleObject
            WAIT_TIMEOUT = 0x00000102
            ERROR_INVALID_PARAMETER = 87
            ERROR_ACCESS_DENIED = 5
            handle = kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, False, int(pid)
            )
            if not handle:
                err = kernel32.GetLastError()
                if err == ERROR_INVALID_PARAMETER:
                    return False  # PID definitely gone
                if err == ERROR_ACCESS_DENIED:
                    return True   # Exists but owned by another user/session
                return False      # Conservative default for unknown errors
            try:
                wait_result = kernel32.WaitForSingleObject(handle, 0)
                # WAIT_TIMEOUT = still running; anything else (WAIT_OBJECT_0
                # via exit, WAIT_FAILED via handle issue) = treat as gone.
                return wait_result == WAIT_TIMEOUT
            finally:
                kernel32.CloseHandle(handle)
        except (OSError, AttributeError):
            return False
    else:
        # psutil missing (stripped install / scaffold phase). Catch the same
        # zombie case as the psutil path above (issue #42126): a zombie
        # answers os.kill(pid, 0) successfully.
        try:
            stat_fields = (
                Path(f"/proc/{int(pid)}/stat").read_text(encoding="utf-8").split()
            )
            if len(stat_fields) > 2 and stat_fields[2] == "Z":
                return False
        except FileNotFoundError:
            # No /proc (macOS/BSD) — fall back to ps state.
            try:
                r = subprocess.run(
                    ["ps", "-o", "state=", "-p", str(int(pid))],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if r.returncode == 0 and r.stdout.strip().startswith("Z"):
                    return False
            except Exception:
                pass
        except (IndexError, PermissionError, OSError):
            pass
        try:
            os.kill(int(pid), 0)  # windows-footgun: ok — POSIX-only branch (the whole point of _pid_exists)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            # Process exists but we can't signal it — still alive.
            return True
        except OSError:
            return False


# Public alias; ``_pid_exists`` keeps its historical name for existing callers.
pid_exists = _pid_exists
