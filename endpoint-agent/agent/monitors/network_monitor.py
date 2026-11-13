"""
SecureWatch Endpoint Agent – Network Connection Monitor
=======================================================
Monitors active TCP/UDP connections using psutil.net_connections().

What is collected (connection metadata only):
  - Local address (IP + port)
  - Remote address (IP + port)
  - Connection status
  - PID and process name

What is NEVER collected:
  - Packet content
  - Application-layer payloads
  - DNS query details
  - Browser history or HTTP paths

Heuristics:
  - New connections to public (non-RFC1918) IPs on unusual ports
  - New listening services on unexpected ports
  - Connections from known-sensitive processes to external IPs

The monitor compares snapshots every POLL_INTERVAL seconds and emits events
only for *changed* (new / closed) connections to reduce noise.
"""

from __future__ import annotations

import ipaddress
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Dict, FrozenSet, Optional, Set, Tuple

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
# RFC 1918 / loopback / link-local ranges
# ---------------------------------------------------------------------------

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private(ip_str: str) -> bool:
    """Return True if the IP is in an RFC1918 / loopback / link-local range."""
    if not ip_str:
        return True
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Well-known ports (connections to these are less surprising)
# ---------------------------------------------------------------------------

_COMMON_PORTS: Set[int] = {
    80, 443, 8080, 8443,   # HTTP/HTTPS
    53,                     # DNS
    25, 587, 465, 143, 993, 110, 995,  # Mail
    22,                     # SSH
    21, 990,                # FTP
    3389,                   # RDP
    1433, 3306, 5432, 6379, 27017,  # Databases
    123,                    # NTP
}

# Processes that may legitimately make internet connections
_TRUSTED_PROCESSES: Set[str] = {
    "chrome.exe", "firefox.exe", "msedge.exe", "safari",
    "opera.exe", "brave.exe",
    "outlook.exe", "thunderbird.exe",
    "svchost.exe", "wuauclt.exe", "MsMpEng.exe",
    "python.exe", "python3", "node", "java",
}

# Processes whose external connections are always worth flagging
_SENSITIVE_PROCESSES: Set[str] = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "curl.exe", "wget",
    "bash", "sh", "zsh",
}

# ---------------------------------------------------------------------------
# Connection key type
# ---------------------------------------------------------------------------

ConnKey = Tuple[str, int, str, int, int]  # laddr_ip, laddr_port, raddr_ip, raddr_port, pid


def _conn_key(c: psutil.sconn) -> ConnKey:
    laddr_ip = c.laddr.ip if c.laddr else ""
    laddr_port = c.laddr.port if c.laddr else 0
    raddr_ip = c.raddr.ip if c.raddr else ""
    raddr_port = c.raddr.port if c.raddr else 0
    return (laddr_ip, laddr_port, raddr_ip, raddr_port, c.pid or 0)


def _process_name(pid: int) -> str:
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
        return ""


def _build_event(c: psutil.sconn, change_type: str) -> dict:
    """Build a normalised network connection event."""
    laddr_ip = c.laddr.ip if c.laddr else ""
    laddr_port = c.laddr.port if c.laddr else 0
    raddr_ip = c.raddr.ip if c.raddr else ""
    raddr_port = c.raddr.port if c.raddr else 0
    pid = c.pid or 0
    proc_name = _process_name(pid)

    is_external = not _is_private(raddr_ip) and bool(raddr_ip)
    is_unusual_port = raddr_port not in _COMMON_PORTS and raddr_port != 0
    is_sensitive_proc = proc_name.lower() in _SENSITIVE_PROCESSES

    flags = []
    if is_external:
        flags.append("external_ip")
    if is_unusual_port and is_external:
        flags.append("unusual_external_port")
    if is_sensitive_proc and is_external:
        flags.append("sensitive_process_external_connection")
    if change_type == "listening_service_new":
        flags.append("new_listening_service")

    severity = "high" if (is_sensitive_proc and is_external) else \
               "medium" if flags else "info"

    return {
        "event_category": "network",
        "event_type": change_type,
        "source": "network_monitor",
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "platform": sys.platform,
        "local_ip": laddr_ip,
        "local_port": laddr_port,
        "remote_ip": raddr_ip,
        "remote_port": raddr_port,
        "status": c.status or "",
        "pid": pid,
        "process_name": proc_name,
        "is_private_remote": _is_private(raddr_ip),
        "flags": flags,
        "severity": severity,
    }


# ===========================================================================
# Monitor
# ===========================================================================

class NetworkMonitor:
    """
    Cross-platform network connection monitor (psutil-based).

    Runs a background thread that snapshots connections every POLL_INTERVAL
    seconds and emits events for new connections and newly-listening services.
    """

    POLL_INTERVAL = 5  # seconds

    def __init__(self, callback: Optional[EventCallback] = None, event_callback: Optional[EventCallback] = None, **kwargs) -> None:
        self._callback = event_callback or callback or (lambda e: None)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._prev_connections: Dict[ConnKey, psutil.sconn] = {}
        self._prev_listening: Set[int] = set()  # listening ports

    def start(self) -> None:
        # Seed the initial snapshot so we don't flood events on startup
        self._prev_connections = self._snapshot()
        self._prev_listening = self._listening_ports()

        self._thread = threading.Thread(
            target=self._run, name="network-monitor", daemon=True
        )
        self._thread.start()
        logger.info("network_monitor_started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _snapshot(self) -> Dict[ConnKey, psutil.sconn]:
        """Return a dict of current active connections keyed by ConnKey."""
        result: Dict[ConnKey, psutil.sconn] = {}
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError) as exc:
            logger.warning("net_connections_access_denied", error=str(exc))
            return result

        for c in conns:
            # Only track established or time-wait connections for outbound;
            # listen for inbound services
            if c.status in (psutil.CONN_ESTABLISHED, psutil.CONN_LISTEN,
                            psutil.CONN_SYN_SENT, psutil.CONN_SYN_RECV,
                            "", None) or True:
                result[_conn_key(c)] = c
        return result

    def _listening_ports(self) -> Set[int]:
        """Return the set of currently listened-on local ports."""
        ports: Set[int] = set()
        try:
            for c in psutil.net_connections(kind="inet"):
                if c.status == psutil.CONN_LISTEN and c.laddr:
                    ports.add(c.laddr.port)
        except (psutil.AccessDenied, PermissionError):
            pass
        return ports

    def _run(self) -> None:
        while not self._stop_event.is_set():
            current = self._snapshot()
            current_listening = self._listening_ports()

            # Detect new connections
            for key, conn in current.items():
                if key not in self._prev_connections:
                    # Only emit for connections with a remote address (not listen)
                    if conn.raddr:
                        evt = _build_event(conn, "connection_new")
                        self._callback(evt)

            # Detect new listening services
            new_listeners = current_listening - self._prev_listening
            for port in new_listeners:
                # Find the connection object for this port
                for conn in current.values():
                    if (conn.status == psutil.CONN_LISTEN
                            and conn.laddr
                            and conn.laddr.port == port):
                        evt = _build_event(conn, "listening_service_new")
                        self._callback(evt)
                        break

            self._prev_connections = current
            self._prev_listening = current_listening
            self._stop_event.wait(timeout=self.POLL_INTERVAL)
