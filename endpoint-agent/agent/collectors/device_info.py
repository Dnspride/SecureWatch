"""
Device Inventory Collector: Cross-platform metadata discovery.
Identifies OS distribution, kernel, architecture, and network hardware IDs.
"""
from __future__ import annotations

import platform
import socket
import os

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from typing import Any, Dict, List, Optional

try:
    import structlog
    log = structlog.get_logger(__name__)
except ImportError:
    import logging
    log = logging.getLogger(__name__)


def get_device_info(agent_version: str = "1.0.0") -> Dict[str, Any]:
    """
    Gather host system identification details for enrollment and inventory.
    """
    hostname = socket.gethostname()
    system = platform.system()
    release = platform.release()
    arch = platform.machine()

    os_name = system
    os_version = release

    if system == "Linux":
        try:
            import distro
            os_name = distro.name(pretty=True) or "Linux"
            os_version = distro.version(pretty=True) or release
        except ImportError:
            pass
    elif system == "Windows":
        os_name = f"Windows {release}"
        try:
            ver = platform.win32_ver()
            if ver and ver[0]:
                os_name = f"Windows {ver[0]}"
                os_version = ver[1] or release
        except Exception:
            pass

    # Collect IP addresses & MAC addresses
    private_ip = None
    mac_address = None
    ip_addresses: List[str] = []

    try:
        if HAS_PSUTIL:
            interfaces = psutil.net_if_addrs()
            for iface_name, addrs in interfaces.items():
                for addr in addrs:
                    # IPv4
                    if addr.family == socket.AF_INET:
                        if not addr.address.startswith("127."):
                            ip_addresses.append(addr.address)
                            if not private_ip:
                                private_ip = addr.address
                    # Hardware / MAC address
                    elif hasattr(psutil, "AF_LINK") and addr.family == psutil.AF_LINK:
                        if addr.address and not mac_address:
                            mac_address = addr.address
        else:
            try:
                private_ip = socket.gethostbyname(hostname)
                ip_addresses.append(private_ip)
            except Exception:
                private_ip = "127.0.0.1"
                ip_addresses.append(private_ip)
    except Exception as e:
        log.warning("Could not enumerate network interfaces", error=str(e))

    # Basic system hardware inventory
    cpu_count = psutil.cpu_count(logical=True) if HAS_PSUTIL else (os.cpu_count() or 1)
    memory_gb = round(psutil.virtual_memory().total / (1024 ** 3), 2) if HAS_PSUTIL else 4.0

    return {
        "hostname": hostname,
        "os_name": os_name,
        "os_version": os_version,
        "os_arch": arch,
        "private_ip": private_ip or "127.0.0.1",
        "mac_address": mac_address,
        "agent_version": agent_version,
        "system_metadata": {
            "platform": platform.platform(),
            "cpu_cores": cpu_count,
            "memory_gb": memory_gb,
            "interfaces": ip_addresses,
        },
    }
