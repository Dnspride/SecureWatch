"""
SecureWatch Endpoint Agent – Authentication Event Monitor
=========================================================
Monitors authentication events in a platform-appropriate way:

Windows
  Subscribes to the Windows Security event log via win32evtlog and watches
  for Event IDs related to logon, logoff, lockout, and account management.

Linux
  Tails /var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL/CentOS)
  and optionally streams journald output for SSH, sudo, and PAM events.

All events are normalised to a common dict schema before being handed to
the event_callback so the rest of the pipeline remains platform-agnostic.

ETHICS NOTICE
  This module only captures *authentication metadata* (who logged in, from
  where, success or failure).  No passwords, session tokens, or private
  communication content are ever collected.
"""

from __future__ import annotations

import asyncio
import re
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

try:
    import structlog
    logger = structlog.get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

EventCallback = Callable[[dict], None]

# ---------------------------------------------------------------------------
# Shared event schema
# ---------------------------------------------------------------------------

def _base_event(event_type: str) -> dict:
    return {
        "event_category": "authentication",
        "event_type": event_type,
        "source": "auth_monitor",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "platform": sys.platform,
    }


# ===========================================================================
# Windows implementation
# ===========================================================================

# Logon type descriptions from Microsoft documentation
_LOGON_TYPES: Dict[int, str] = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
    12: "CachedRemoteInteractive",
    13: "CachedUnlock",
}

# Security event IDs to monitor
_WATCHED_EVENT_IDS = {
    4624: "logon_success",
    4625: "logon_failure",
    4634: "logoff",
    4648: "explicit_credentials",
    4672: "special_privileges_assigned",
    4720: "user_account_created",
    4722: "user_account_enabled",
    4725: "user_account_disabled",
    4740: "account_lockout",
    4767: "account_unlocked",
}


class WindowsAuthMonitor:
    """
    Reads Windows Security event log using win32evtlog and emits normalised
    authentication events.
    """

    def __init__(self, callback: EventCallback) -> None:
        self._callback = callback
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="win-auth-monitor", daemon=True
        )
        self._thread.start()
        logger.info("windows_auth_monitor_started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        try:
            import win32evtlog
            import win32evtlogutil
            import win32con
            import pywintypes
        except ImportError:
            logger.error("pywin32_not_available_auth_monitor")
            return

        log_handle = win32evtlog.OpenEventLog(None, "Security")
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        while not self._stop_event.is_set():
            try:
                events = win32evtlog.ReadEventLog(log_handle, flags, 0)
                if not events:
                    time.sleep(1)
                    continue
                for ev in events:
                    if ev.EventID in _WATCHED_EVENT_IDS:
                        normalised = self._normalise(ev)
                        if normalised:
                            self._callback(normalised)
            except Exception as exc:
                logger.warning("win_eventlog_read_error", error=str(exc))
                time.sleep(2)

        win32evtlog.CloseEventLog(log_handle)

    def _normalise(self, ev: "pywintypes.EventLogRecord") -> Optional[dict]:  # type: ignore[name-defined]
        try:
            import win32evtlogutil
            event_id = ev.EventID & 0xFFFF
            event_name = _WATCHED_EVENT_IDS.get(event_id, "unknown")

            # InsertionStrings layout differs by Event ID; we do a best-effort
            # extraction using known positions from Microsoft documentation.
            strings: List[str] = ev.StringInserts or []

            def _get(idx: int, default: str = "") -> str:
                try:
                    return (strings[idx] or "").strip() or default
                except IndexError:
                    return default

            event = _base_event(event_name)
            event.update({
                "event_id": event_id,
                "computer_name": ev.ComputerName or "",
                "time_generated": ev.TimeGenerated.Format(),
            })

            if event_id in (4624, 4625, 4648):
                logon_type_raw = _get(8) if event_id == 4624 else _get(10)
                try:
                    lt = int(logon_type_raw)
                except ValueError:
                    lt = 0
                event.update({
                    "subject_username": _get(1),
                    "subject_domain": _get(2),
                    "target_username": _get(5),
                    "target_domain": _get(6),
                    "logon_type": lt,
                    "logon_type_desc": _LOGON_TYPES.get(lt, "Unknown"),
                    "workstation_name": _get(11),
                    "ip_address": _get(18) if event_id == 4624 else _get(13),
                    "failure_reason": _get(8) if event_id == 4625 else None,
                })

            elif event_id == 4672:
                event.update({
                    "subject_username": _get(1),
                    "subject_domain": _get(2),
                    "privileges": _get(4),
                })

            elif event_id in (4720, 4722, 4725, 4740, 4767):
                event.update({
                    "target_username": _get(0),
                    "target_domain": _get(1),
                    "subject_username": _get(4),
                    "subject_domain": _get(5),
                })

            return event

        except Exception as exc:
            logger.debug("win_event_parse_error", error=str(exc))
            return None


# ===========================================================================
# Linux implementation
# ===========================================================================

# Regex patterns for common auth log lines
_SSHD_SUCCESS = re.compile(
    r"sshd\[(?P<pid>\d+)\]:\s+Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)"
    r"\s+from\s+(?P<host>\S+)\s+port\s+(?P<port>\d+)"
)
_SSHD_FAIL = re.compile(
    r"sshd\[(?P<pid>\d+)\]:\s+Failed\s+(?P<method>\S+)\s+for\s+(?:invalid user\s+)?(?P<user>\S+)"
    r"\s+from\s+(?P<host>\S+)\s+port\s+(?P<port>\d+)"
)
_SSHD_DISCONNECT = re.compile(
    r"sshd\[(?P<pid>\d+)\]:\s+Disconnected\s+from\s+(?:(?:authenticating|invalid)\s+user\s+)?(?P<user>\S+)"
    r"\s+(?P<host>\S+)\s+port\s+(?P<port>\d+)"
)
_SUDO_OK = re.compile(
    r"sudo:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<command>.+)$"
)
_SUDO_FAIL = re.compile(
    r"sudo:\s+(?P<user>\S+)\s+:.*(?:incorrect password|authentication failure)"
)
_PAM_AUTH = re.compile(
    r"pam_unix\((?P<service>[^:]+):auth\):\s+(?P<result>authentication failure|session opened|session closed)"
    r"(?:.*user=(?P<user>\S+))?"
)
_USERADD = re.compile(r"useradd\[(?P<pid>\d+)\]:\s+new user: name=(?P<user>\S+)")
_USERDEL = re.compile(r"userdel\[(?P<pid>\d+)\]:\s+delete user '(?P<user>[^']+)'")

# Auth log locations by distro family
_AUTH_LOG_CANDIDATES = [
    "/var/log/auth.log",   # Debian/Ubuntu/Kali
    "/var/log/secure",     # RHEL/CentOS/Fedora
]


def _find_auth_log() -> Optional[str]:
    import os
    for path in _AUTH_LOG_CANDIDATES:
        if os.path.exists(path):
            return path
    return None


def _parse_auth_line(line: str) -> Optional[dict]:
    """Return a normalised event dict for a recognised auth log line."""
    line = line.rstrip()

    m = _SSHD_SUCCESS.search(line)
    if m:
        ev = _base_event("logon_success")
        ev.update({
            "service": "sshd",
            "pid": int(m.group("pid")),
            "username": m.group("user"),
            "remote_host": m.group("host"),
            "remote_port": int(m.group("port")),
            "auth_method": m.group("method"),
            "result": "success",
        })
        return ev

    m = _SSHD_FAIL.search(line)
    if m:
        ev = _base_event("logon_failure")
        ev.update({
            "service": "sshd",
            "pid": int(m.group("pid")),
            "username": m.group("user"),
            "remote_host": m.group("host"),
            "remote_port": int(m.group("port")),
            "auth_method": m.group("method"),
            "result": "failure",
        })
        return ev

    m = _SUDO_OK.search(line)
    if m:
        ev = _base_event("sudo_command")
        ev.update({
            "service": "sudo",
            "username": m.group("user"),
            "command": m.group("command").strip(),
            "result": "success",
        })
        return ev

    m = _SUDO_FAIL.search(line)
    if m:
        ev = _base_event("sudo_failure")
        ev.update({
            "service": "sudo",
            "username": m.group("user"),
            "result": "failure",
        })
        return ev

    m = _USERADD.search(line)
    if m:
        ev = _base_event("user_account_created")
        ev.update({
            "service": "useradd",
            "username": m.group("user"),
            "pid": int(m.group("pid")),
        })
        return ev

    m = _USERDEL.search(line)
    if m:
        ev = _base_event("user_account_deleted")
        ev.update({
            "service": "userdel",
            "username": m.group("user"),
            "pid": int(m.group("pid")),
        })
        return ev

    m = _PAM_AUTH.search(line)
    if m:
        result_str = m.group("result")
        ev = _base_event("pam_auth_event")
        ev.update({
            "service": m.group("service"),
            "pam_result": result_str,
            "username": m.group("user") or "",
        })
        return ev

    return None


class LinuxAuthMonitor:
    """
    Tails the system auth log file and emits normalised authentication events.
    Falls back gracefully if the log file doesn't exist (non-root agent).
    """

    def __init__(self, callback: EventCallback) -> None:
        self._callback = callback
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._log_path: Optional[str] = _find_auth_log()

    def start(self) -> None:
        if not self._log_path:
            logger.warning("linux_auth_log_not_found",
                           candidates=_AUTH_LOG_CANDIDATES)
            return
        self._thread = threading.Thread(
            target=self._run, name="linux-auth-monitor", daemon=True
        )
        self._thread.start()
        logger.info("linux_auth_monitor_started", log_path=self._log_path)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        """Tail the auth log and emit events for recognised lines."""
        import os
        try:
            with open(self._log_path, "r", encoding="utf-8", errors="replace") as fh:  # type: ignore[arg-type]
                # Seek to end so we only process new events
                fh.seek(0, 2)
                inode = os.stat(self._log_path).st_ino

                while not self._stop_event.is_set():
                    line = fh.readline()
                    if not line:
                        # Check for log rotation (inode change)
                        try:
                            current_inode = os.stat(self._log_path).st_ino  # type: ignore[arg-type]
                        except OSError:
                            current_inode = inode

                        if current_inode != inode:
                            logger.info("auth_log_rotated", path=self._log_path)
                            fh.close()
                            fh = open(self._log_path, "r", encoding="utf-8",  # type: ignore[assignment]
                                      errors="replace")
                            inode = current_inode
                        else:
                            time.sleep(0.5)
                        continue

                    event = _parse_auth_line(line)
                    if event:
                        self._callback(event)

        except (PermissionError, OSError) as exc:
            logger.error("auth_log_read_error", path=self._log_path, error=str(exc))


# ===========================================================================
# Factory
# ===========================================================================

def create_auth_monitor(callback: EventCallback) -> "WindowsAuthMonitor | LinuxAuthMonitor":
    """Return the appropriate platform auth monitor."""
    if sys.platform == "win32":
        return WindowsAuthMonitor(callback)
    return LinuxAuthMonitor(callback)


class AuthMonitor:
    """Cross-platform wrapper that delegates to WindowsAuthMonitor or LinuxAuthMonitor."""

    def __init__(self, callback: Optional[EventCallback] = None, event_callback: Optional[EventCallback] = None, **kwargs) -> None:
        self.callback = event_callback or callback or (lambda e: None)
        self._impl = create_auth_monitor(self.callback)

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

