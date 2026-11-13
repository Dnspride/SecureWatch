"""
SecureWatch Endpoint Agent – Process Monitor
=============================================
Monitors process creation events in a platform-aware manner.

Windows
  Primary: Windows Security Event ID 4688 (Process Create) via win32evtlog
  Fallback: Periodic psutil snapshot diff (every 5 seconds)

Linux
  Primary: psutil periodic snapshot diff
  Secondary: auditd EXECVE records from /var/log/audit/audit.log if available

Security heuristics applied to all platforms:
  - Suspicious parent→child combos (Office apps spawning shells/scripts)
  - PowerShell encoded commands or hidden windows
  - Shell spawned from non-terminal parent (Linux)

ETHICS / PRIVACY
  Command lines are captured but password-flag patterns are REDACTED before
  the event is emitted.  No environment variables or stdin/stdout are captured.
"""

from __future__ import annotations

import asyncio
import re
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Set

try:
    import psutil
except ImportError:
    psutil = None

try:
    import structlog
    logger = structlog.get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

EventCallback = Callable[[dict], None]

# ---------------------------------------------------------------------------
# Password pattern redaction
# ---------------------------------------------------------------------------

# Flags commonly used to pass a password on the command line.
# We redact the value that follows them.
_PASSWORD_FLAG_RE = re.compile(
    r"""
    (?:                     # Non-capturing group
        --password          # long form
      | --passwd
      | -p\b               # short form -p
      | --secret
      | --token
      | --api[-_]?key
    )
    \s*=?\s*               # optional = or space
    (\S+)                  # the VALUE we will redact
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _redact_cmdline(cmdline: List[str]) -> str:
    """
    Join a command-line list and redact password flag values.
    Returns a human-readable string safe to store/transmit.
    """
    joined = " ".join(cmdline)
    redacted = _PASSWORD_FLAG_RE.sub(
        lambda m: m.group(0).replace(m.group(1), "***REDACTED***"), joined
    )
    # Truncate very long command lines
    if len(redacted) > 2048:
        redacted = redacted[:2045] + "..."
    return redacted


# ---------------------------------------------------------------------------
# Heuristic flags
# ---------------------------------------------------------------------------

# Suspicious parent→child process name combos (lower-cased)
_SUSPICIOUS_COMBOS: Set[tuple] = {
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "wscript.exe"),
    ("winword.exe", "cscript.exe"),
    ("winword.exe", "mshta.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "powershell.exe"),
    ("excel.exe", "wscript.exe"),
    ("powerpnt.exe", "cmd.exe"),
    ("powerpnt.exe", "powershell.exe"),
    ("outlook.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("chrome.exe", "cmd.exe"),
    ("firefox.exe", "cmd.exe"),
    ("acrobat.exe", "cmd.exe"),
    ("acrobat.exe", "powershell.exe"),
}

# PowerShell command-line flags that indicate evasion
_PS_EVASION_FLAGS = re.compile(
    r"-(?:enc(?:oded(?:command)?)?|windowstyle\s+hidden|nop(?:rofile)?|e\s+[A-Za-z0-9+/=]{20,})",
    re.IGNORECASE,
)


def _flag_suspicious(name: str, cmdline_str: str, parent_name: str) -> List[str]:
    """Return a list of string flags describing suspicious indicators."""
    flags: List[str] = []
    n = name.lower()
    pn = parent_name.lower()

    if (pn, n) in _SUSPICIOUS_COMBOS:
        flags.append(f"suspicious_parent_child:{pn}->{n}")

    if n in ("powershell.exe", "pwsh.exe", "pwsh"):
        if _PS_EVASION_FLAGS.search(cmdline_str):
            flags.append("powershell_evasion_flags")

    if sys.platform != "win32":
        # Shell spawned by a non-tty parent is a common indicator
        shells = {"bash", "sh", "zsh", "fish", "dash", "ksh"}
        if n in shells and pn not in shells and pn not in {"sshd", "login", "su", "sudo", "xterm", "konsole", "gnome-terminal-", "tmux"}:
            flags.append(f"shell_from_non_terminal_parent:{pn}")

    return flags


# ---------------------------------------------------------------------------
# Shared event builder
# ---------------------------------------------------------------------------

def _process_event(proc: psutil.Process, change_type: str = "process_started") -> Optional[dict]:
    """Build a normalised process event dict from a psutil.Process object."""
    try:
        with proc.oneshot():
            pid = proc.pid
            name = proc.name() or ""
            exe = ""
            cmdline: List[str] = []
            ppid = 0
            parent_name = ""
            username = ""
            create_time = 0.0

            try:
                exe = proc.exe() or ""
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                cmdline = proc.cmdline() or []
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                ppid = proc.ppid() or 0
                parent = proc.parent()
                if parent:
                    parent_name = parent.name() or ""
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                username = proc.username() or ""
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            try:
                create_time = proc.create_time()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                create_time = time.time()

        cmdline_str = _redact_cmdline(cmdline)
        flags = _flag_suspicious(name, cmdline_str, parent_name)

        return {
            "event_category": "process",
            "event_type": change_type,
            "source": "process_monitor",
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "platform": sys.platform,
            "pid": pid,
            "name": name,
            "exe_path": exe,
            "cmdline": cmdline_str,
            "ppid": ppid,
            "parent_name": parent_name,
            "username": username,
            "create_time": create_time,
            "flags": flags,
            "severity": "high" if flags else "info",
        }

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None
    except Exception as exc:
        logger.debug("process_event_build_error", error=str(exc))
        return None


# ===========================================================================
# Windows – Event ID 4688 reader + psutil fallback
# ===========================================================================

class WindowsProcessMonitor:
    """
    Windows process creation monitor.

    Attempts to read Event ID 4688 (Process Create) from the Security event
    log.  Falls back to psutil snapshot diffing if the event log subscription
    fails (e.g., audit policy not configured).
    """

    POLL_INTERVAL = 5  # seconds

    def __init__(self, callback: EventCallback) -> None:
        self._callback = callback
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._known_pids: Set[int] = set()

    def start(self) -> None:
        # Seed the known PID set
        self._known_pids = {p.pid for p in psutil.process_iter()}
        self._thread = threading.Thread(
            target=self._run, name="win-process-monitor", daemon=True
        )
        self._thread.start()
        logger.info("windows_process_monitor_started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        # Try event log first
        if self._try_event_log():
            return
        # Fall back to psutil snapshot diff
        logger.info("process_monitor_fallback_psutil")
        self._run_psutil()

    def _try_event_log(self) -> bool:
        """
        Attempt to subscribe to Security event log for 4688 events.
        Returns False if win32evtlog is unavailable.
        """
        try:
            import win32evtlog
        except ImportError:
            return False

        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        try:
            log_handle = win32evtlog.OpenEventLog(None, "Security")
        except Exception as exc:
            logger.warning("win_security_log_open_failed", error=str(exc))
            return False

        try:
            while not self._stop_event.is_set():
                try:
                    events = win32evtlog.ReadEventLog(log_handle, flags, 0)
                    if not events:
                        time.sleep(1)
                        continue
                    for ev in events:
                        event_id = ev.EventID & 0xFFFF
                        if event_id == 4688:
                            evt = self._parse_4688(ev)
                            if evt:
                                self._callback(evt)
                except Exception as exc:
                    logger.warning("win_process_log_read_error", error=str(exc))
                    time.sleep(2)
        finally:
            win32evtlog.CloseEventLog(log_handle)

        return True

    def _parse_4688(self, ev: object) -> Optional[dict]:
        """Parse a 4688 Process Create event."""
        try:
            strings = ev.StringInserts or []  # type: ignore[attr-defined]

            def _get(idx: int, default: str = "") -> str:
                try:
                    return (strings[idx] or "").strip() or default
                except IndexError:
                    return default

            new_process_name = _get(5)
            cmdline_raw = _get(8)
            cmdline_str = _redact_cmdline(cmdline_raw.split() if cmdline_raw else [])
            parent_name = _get(13)
            name = new_process_name.split("\\")[-1] if new_process_name else ""
            flags = _flag_suspicious(name, cmdline_str, parent_name.split("\\")[-1])

            return {
                "event_category": "process",
                "event_type": "process_started",
                "source": "process_monitor_eventlog",
                "timestamp": ev.TimeGenerated.Format(),  # type: ignore[attr-defined]
                "platform": sys.platform,
                "event_id": 4688,
                "pid": int(_get(4, "0"), 16) if _get(4).startswith("0x") else 0,
                "name": name,
                "exe_path": new_process_name,
                "cmdline": cmdline_str,
                "parent_name": parent_name.split("\\")[-1],
                "username": _get(1),
                "flags": flags,
                "severity": "high" if flags else "info",
            }
        except Exception as exc:
            logger.debug("event_4688_parse_error", error=str(exc))
            return None

    def _run_psutil(self) -> None:
        """Poll psutil for new processes every POLL_INTERVAL seconds."""
        while not self._stop_event.is_set():
            current_pids: Set[int] = set()
            for proc in psutil.process_iter(["pid"]):
                try:
                    current_pids.add(proc.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            new_pids = current_pids - self._known_pids
            for pid in new_pids:
                try:
                    proc = psutil.Process(pid)
                    evt = _process_event(proc, "process_started")
                    if evt:
                        self._callback(evt)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            self._known_pids = current_pids
            self._stop_event.wait(timeout=self.POLL_INTERVAL)


# ===========================================================================
# Linux implementation
# ===========================================================================

_AUDITD_LOG = "/var/log/audit/audit.log"
_EXECVE_RE = re.compile(r'type=EXECVE\s+msg=audit\([\d.]+:(\d+)\):.*?argc=(\d+)\s+(.*)')
_EXECVE_ARG_RE = re.compile(r'a\d+="([^"]*)"')


class LinuxProcessMonitor:
    """
    Linux process monitor: psutil snapshot diff + optional auditd tail.
    """

    POLL_INTERVAL = 5  # seconds

    def __init__(self, callback: EventCallback) -> None:
        self._callback = callback
        self._stop_event = threading.Event()
        self._threads: List[threading.Thread] = []
        self._known_pids: Set[int] = set()

    def start(self) -> None:
        self._known_pids = {p.pid for p in psutil.process_iter()}

        t_psutil = threading.Thread(
            target=self._run_psutil, name="linux-process-psutil", daemon=True
        )
        t_psutil.start()
        self._threads.append(t_psutil)

        import os
        if os.path.exists(_AUDITD_LOG) and os.access(_AUDITD_LOG, os.R_OK):
            t_audit = threading.Thread(
                target=self._run_auditd, name="linux-process-auditd", daemon=True
            )
            t_audit.start()
            self._threads.append(t_audit)
            logger.info("auditd_tail_started", log=_AUDITD_LOG)

        logger.info("linux_process_monitor_started")

    def stop(self) -> None:
        self._stop_event.set()
        for t in self._threads:
            t.join(timeout=5)

    def _run_psutil(self) -> None:
        """Poll for new PIDs every POLL_INTERVAL seconds."""
        while not self._stop_event.is_set():
            current_pids: Set[int] = set()
            for proc in psutil.process_iter(["pid"]):
                try:
                    current_pids.add(proc.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            new_pids = current_pids - self._known_pids
            for pid in new_pids:
                try:
                    proc = psutil.Process(pid)
                    evt = _process_event(proc, "process_started")
                    if evt:
                        self._callback(evt)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            self._known_pids = current_pids
            self._stop_event.wait(timeout=self.POLL_INTERVAL)

    def _run_auditd(self) -> None:
        """Tail auditd log for EXECVE records."""
        import os
        try:
            with open(_AUDITD_LOG, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(0, 2)
                while not self._stop_event.is_set():
                    line = fh.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    evt = self._parse_execve(line)
                    if evt:
                        self._callback(evt)
        except (PermissionError, OSError) as exc:
            logger.warning("auditd_tail_error", error=str(exc))

    def _parse_execve(self, line: str) -> Optional[dict]:
        """Parse an auditd EXECVE line into a normalised event."""
        m = _EXECVE_RE.search(line)
        if not m:
            return None
        args = _EXECVE_ARG_RE.findall(m.group(3))
        if not args:
            return None

        name = args[0].split("/")[-1]
        cmdline_str = _redact_cmdline(args)
        flags = _flag_suspicious(name, cmdline_str, "")

        return {
            "event_category": "process",
            "event_type": "process_started",
            "source": "process_monitor_auditd",
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "platform": sys.platform,
            "name": name,
            "exe_path": args[0],
            "cmdline": cmdline_str,
            "flags": flags,
            "severity": "high" if flags else "info",
        }


# ===========================================================================
# Factory
# ===========================================================================

def create_process_monitor(callback: EventCallback) -> "WindowsProcessMonitor | LinuxProcessMonitor":
    """Return the appropriate platform process monitor."""
    if sys.platform == "win32":
        return WindowsProcessMonitor(callback)
    return LinuxProcessMonitor(callback)


class ProcessMonitor:
    """Cross-platform wrapper that delegates to WindowsProcessMonitor or LinuxProcessMonitor."""

    def __init__(self, event_callback: Optional[EventCallback] = None, callback: Optional[EventCallback] = None, **kwargs) -> None:
        cb = event_callback or callback or (lambda e: None)
        self.callback = cb
        self._impl = create_process_monitor(cb)

    def start(self) -> None:
        if hasattr(self._impl, "start"):
            self._impl.start()

    def stop(self) -> None:
        if hasattr(self._impl, "stop"):
            self._impl.stop()

    def poll(self) -> List[dict]:
        if hasattr(self._impl, "poll"):
            return self._impl.poll()
        return []

