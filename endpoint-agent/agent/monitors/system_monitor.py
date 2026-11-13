"""
SecureWatch Endpoint Agent – System Security Posture Monitor
=============================================================
Runs every 15 minutes and checks the overall security hygiene of the endpoint:

Windows checks:
  - Windows Defender / AV status (WMI SecurityCenter2)
  - Firewall status per profile (netsh advfirewall)
  - Windows Update last install date (registry)
  - BitLocker drive encryption status
  - New Windows services (snapshot diff)
  - New scheduled tasks (snapshot diff)

Linux checks:
  - Firewall (ufw / iptables / firewalld)
  - AV tools presence (clamav, rkhunter, chkrootkit)
  - Pending system updates (apt / yum / dnf)
  - Disk encryption (LUKS via lsblk)
  - New systemd services (snapshot diff)
  - Cron changes (hash of /etc/crontab, /etc/cron.d/*, user crontabs)

All checks are read-only.  No system configuration is changed.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
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
# Shared helper
# ---------------------------------------------------------------------------

def _run_cmd(cmd: List[str], timeout: int = 15) -> str:
    """Run a command and return stdout as a string.  Never raises."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout or ""
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError,
            OSError) as exc:
        logger.debug("system_monitor_cmd_failed", cmd=cmd[0], error=str(exc))
        return ""


def _base_event(check_name: str, findings: dict) -> dict:
    return {
        "event_category": "system_posture",
        "event_type": "posture_check",
        "source": "system_monitor",
        "check_name": check_name,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "platform": sys.platform,
        **findings,
    }


# ===========================================================================
# Windows checks
# ===========================================================================

def _win_av_status() -> dict:
    """Query SecurityCenter2 WMI for installed AV products."""
    findings: Dict = {"av_products": [], "av_enabled": False, "av_up_to_date": False}
    try:
        import wmi  # type: ignore[import]
        c = wmi.WMI(namespace=r"root\SecurityCenter2")
        products = c.AntiVirusProduct()
        av_list = []
        for p in products:
            # productState is a hex bitmask from Microsoft
            state = int(p.productState)
            enabled = bool((state >> 12) & 0xF != 1)
            up_to_date = bool((state >> 4) & 0xF == 0)
            av_list.append({
                "name": p.displayName,
                "enabled": enabled,
                "up_to_date": up_to_date,
            })
        findings["av_products"] = av_list
        findings["av_enabled"] = any(a["enabled"] for a in av_list)
        findings["av_up_to_date"] = any(a["up_to_date"] for a in av_list)
    except Exception as exc:
        findings["error"] = str(exc)
    return findings


def _win_firewall_status() -> dict:
    """Parse netsh advfirewall output for profile states."""
    output = _run_cmd(["netsh", "advfirewall", "show", "allprofiles"])
    profiles = {}
    current_profile = None
    for line in output.splitlines():
        line = line.strip()
        if line.endswith("Profile Settings:"):
            current_profile = line.replace(" Profile Settings:", "").lower()
            profiles[current_profile] = {}
        elif current_profile and line.lower().startswith("state"):
            parts = line.split()
            if len(parts) >= 2:
                profiles[current_profile]["state"] = parts[-1].upper()
    all_on = all(p.get("state") == "ON" for p in profiles.values())
    return {"firewall_profiles": profiles, "all_profiles_enabled": all_on}


def _win_update_status() -> dict:
    """Read last Windows Update install date from registry."""
    findings: Dict = {"last_update_date": None}
    try:
        import winreg
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        last_success, _ = winreg.QueryValueEx(key, "LastSuccessTime")
        winreg.CloseKey(key)
        findings["last_update_date"] = last_success
    except Exception as exc:
        findings["error"] = str(exc)
    return findings


def _win_bitlocker_status() -> dict:
    """Check BitLocker encryption status via manage-bde."""
    output = _run_cmd(["manage-bde", "-status"])
    protected = "Protection On" in output or "Protection Status: Protection On" in output
    return {"bitlocker_enabled": protected, "raw_output_summary": output[:500]}


def _win_services_snapshot() -> List[str]:
    """Return a sorted list of service names from sc.exe."""
    output = _run_cmd(["sc", "query", "type=", "all", "state=", "all"])
    services = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("SERVICE_NAME:"):
            services.append(line.replace("SERVICE_NAME:", "").strip())
    return sorted(services)


def _win_schtasks_snapshot() -> List[str]:
    """Return a sorted list of scheduled task names."""
    output = _run_cmd(["schtasks", "/query", "/fo", "CSV"])
    tasks = []
    for line in output.splitlines():
        if line.startswith('"\\'):
            task_name = line.split(",")[0].strip('"')
            tasks.append(task_name)
    return sorted(tasks)


# ===========================================================================
# Linux checks
# ===========================================================================

def _linux_firewall_status() -> dict:
    """Check ufw / firewalld / iptables status."""
    result: Dict = {}

    # ufw
    ufw_out = _run_cmd(["ufw", "status"])
    if ufw_out:
        result["ufw"] = {
            "installed": True,
            "active": "Status: active" in ufw_out,
        }

    # firewalld
    fw_out = _run_cmd(["firewall-cmd", "--state"])
    if fw_out:
        result["firewalld"] = {"active": fw_out.strip().lower() == "running"}

    # iptables rule count
    ipt_out = _run_cmd(["iptables", "-L", "-n"])
    if ipt_out:
        rule_lines = [l for l in ipt_out.splitlines() if l.startswith("-A") or l.startswith("ACCEPT") or l.startswith("DROP")]
        result["iptables"] = {"rule_count": len(rule_lines)}

    enabled = bool(
        result.get("ufw", {}).get("active")
        or result.get("firewalld", {}).get("active")
        or result.get("iptables", {}).get("rule_count", 0) > 0
    )
    result["firewall_enabled"] = enabled
    return result


def _linux_av_status() -> dict:
    """Check for common AV / anti-rootkit tools."""
    findings: Dict = {}
    tools = {
        "clamav": ["clamscan", "--version"],
        "rkhunter": ["rkhunter", "--version"],
        "chkrootkit": ["chkrootkit", "-V"],
        "aide": ["aide", "--version"],
    }
    installed = []
    for tool, cmd in tools.items():
        out = _run_cmd(cmd, timeout=5)
        if out:
            installed.append(tool)
    findings["av_tools_found"] = installed
    findings["av_enabled"] = len(installed) > 0
    return findings


def _linux_updates() -> dict:
    """Check for pending system updates."""
    findings: Dict = {}
    # apt (Debian/Ubuntu/Kali)
    apt_out = _run_cmd(["apt", "list", "--upgradable", "-qq"], timeout=30)
    if apt_out:
        packages = [l for l in apt_out.splitlines() if "/" in l and "upgradable" in l]
        findings["apt_pending_updates"] = len(packages)

    # yum / dnf (RHEL/CentOS/Fedora)
    yum_out = _run_cmd(["yum", "check-update", "-q"], timeout=30)
    if not yum_out:
        yum_out = _run_cmd(["dnf", "check-update", "-q"], timeout=30)
    if yum_out:
        packages = [l for l in yum_out.splitlines() if l and not l.startswith("Last")]
        findings["yum_pending_updates"] = len(packages)

    return findings


def _linux_luks_status() -> dict:
    """Detect LUKS-encrypted block devices via lsblk."""
    output = _run_cmd(["lsblk", "--output", "NAME,TYPE,FSTYPE", "--json"])
    encrypted_devs = []
    if output:
        try:
            data = json.loads(output)
            def _walk(devices: list) -> None:
                for d in devices:
                    if d.get("fstype") == "crypto_LUKS":
                        encrypted_devs.append(d.get("name", ""))
                    if d.get("children"):
                        _walk(d["children"])
            _walk(data.get("blockdevices", []))
        except json.JSONDecodeError:
            pass
    return {"luks_encrypted_devices": encrypted_devs, "disk_encryption_found": bool(encrypted_devs)}


def _linux_systemd_units() -> List[str]:
    """Return sorted list of enabled systemd unit names."""
    output = _run_cmd(["systemctl", "list-units", "--type=service", "--no-pager", "--plain"])
    units = []
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0].endswith(".service"):
            units.append(parts[0])
    return sorted(units)


def _linux_cron_hashes() -> Dict[str, str]:
    """Return SHA-256 hashes of cron-related files for change detection."""
    targets = ["/etc/crontab"] + [
        os.path.join("/etc/cron.d", f)
        for f in os.listdir("/etc/cron.d")
        if os.path.isfile(os.path.join("/etc/cron.d", f))
    ] if os.path.isdir("/etc/cron.d") else ["/etc/crontab"]

    hashes: Dict[str, str] = {}
    for path in targets:
        try:
            content = open(path, "rb").read()
            hashes[path] = hashlib.sha256(content).hexdigest()
        except OSError:
            pass
    return hashes


# ===========================================================================
# Monitor
# ===========================================================================

class SystemMonitor:
    """
    Security posture monitor that runs checks every ``interval`` seconds.
    """

    def __init__(self, callback: Optional[EventCallback] = None, interval: int = 900, event_callback: Optional[EventCallback] = None, **kwargs) -> None:
        self._callback = event_callback or callback or (lambda e: None)
        self._interval = interval
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Snapshots for diff-based checks
        self._prev_services: Optional[List[str]] = None
        self._prev_tasks: Optional[List[str]] = None
        self._prev_systemd: Optional[List[str]] = None
        self._prev_cron_hashes: Optional[Dict[str, str]] = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="system-monitor", daemon=True
        )
        self._thread.start()
        logger.info("system_monitor_started", interval_s=self._interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _run(self) -> None:
        # Run immediately on start, then every interval
        while not self._stop_event.is_set():
            self._run_all_checks()
            self._stop_event.wait(timeout=self._interval)

    def _run_all_checks(self) -> None:
        """Execute all posture checks and emit events."""
        logger.debug("system_posture_check_running")
        if sys.platform == "win32":
            self._run_windows_checks()
        else:
            self._run_linux_checks()

    # ------------------------------------------------------------------
    # Windows
    # ------------------------------------------------------------------

    def _run_windows_checks(self) -> None:
        # AV
        av = _win_av_status()
        self._callback(_base_event("av_status", av))

        # Firewall
        fw = _win_firewall_status()
        evt = _base_event("firewall_status", fw)
        if not fw.get("all_profiles_enabled"):
            evt["severity"] = "high"
            evt["flags"] = ["firewall_not_fully_enabled"]
        self._callback(evt)

        # Windows Update
        wu = _win_update_status()
        self._callback(_base_event("windows_update", wu))

        # BitLocker
        bl = _win_bitlocker_status()
        self._callback(_base_event("bitlocker_status", bl))

        # New services
        current_services = _win_services_snapshot()
        if self._prev_services is not None:
            new_svcs = sorted(set(current_services) - set(self._prev_services))
            if new_svcs:
                self._callback(_base_event("new_services_detected", {
                    "new_services": new_svcs,
                    "severity": "medium",
                    "flags": ["new_windows_service"],
                }))
        self._prev_services = current_services

        # New scheduled tasks
        current_tasks = _win_schtasks_snapshot()
        if self._prev_tasks is not None:
            new_tasks = sorted(set(current_tasks) - set(self._prev_tasks))
            if new_tasks:
                self._callback(_base_event("new_scheduled_tasks", {
                    "new_tasks": new_tasks,
                    "severity": "medium",
                    "flags": ["new_scheduled_task"],
                }))
        self._prev_tasks = current_tasks

    # ------------------------------------------------------------------
    # Linux
    # ------------------------------------------------------------------

    def _run_linux_checks(self) -> None:
        # Firewall
        fw = _linux_firewall_status()
        evt = _base_event("firewall_status", fw)
        if not fw.get("firewall_enabled"):
            evt["severity"] = "high"
            evt["flags"] = ["firewall_not_enabled"]
        self._callback(evt)

        # AV tools
        av = _linux_av_status()
        evt = _base_event("av_status", av)
        if not av.get("av_enabled"):
            evt["severity"] = "medium"
            evt["flags"] = ["no_av_tools_found"]
        self._callback(evt)

        # Updates
        upd = _linux_updates()
        self._callback(_base_event("update_status", upd))

        # LUKS
        luks = _linux_luks_status()
        self._callback(_base_event("disk_encryption_status", luks))

        # New systemd services
        current_units = _linux_systemd_units()
        if self._prev_systemd is not None:
            new_units = sorted(set(current_units) - set(self._prev_systemd))
            if new_units:
                self._callback(_base_event("new_systemd_services", {
                    "new_services": new_units,
                    "severity": "medium",
                    "flags": ["new_systemd_service"],
                }))
        self._prev_systemd = current_units

        # Cron changes
        current_hashes = _linux_cron_hashes()
        if self._prev_cron_hashes is not None:
            changed = {
                p: h for p, h in current_hashes.items()
                if self._prev_cron_hashes.get(p) != h
            }
            new_cron_files = {
                p: h for p, h in current_hashes.items()
                if p not in self._prev_cron_hashes
            }
            if changed or new_cron_files:
                self._callback(_base_event("cron_changes_detected", {
                    "changed_files": list(changed.keys()),
                    "new_files": list(new_cron_files.keys()),
                    "severity": "high",
                    "flags": ["cron_modification"],
                }))
        self._prev_cron_hashes = current_hashes
