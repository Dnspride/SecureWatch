"""
Network Connection Event Normalizer.
Collects socket metadata, source/destination IPs, ports, and listening services.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict
from normalizers.base import NormalizedEvent


def is_rfc1918(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return False


class NetworkEventNormalizer:
    @staticmethod
    def normalize(raw: Dict[str, Any], device_id: str = "", hostname: str = "") -> NormalizedEvent:
        src_ip = raw.get("source_ip") or raw.get("laddr_ip")
        dst_ip = raw.get("destination_ip") or raw.get("raddr_ip")
        dst_port = raw.get("destination_port") or raw.get("raddr_port")
        proto = raw.get("protocol", "TCP")
        proc_name = raw.get("process_name")

        severity = "informational"
        event_type = raw.get("event_type", "network_connection")

        # Threat heuristic: Connection to external high port from non-browser
        if dst_ip and not is_rfc1918(dst_ip):
            if dst_port and int(dst_port) > 49151:
                severity = "medium"
                event_type = "unusual_outbound_connection"

        return NormalizedEvent(
            device_id=device_id,
            hostname=hostname or raw.get("hostname", ""),
            event_source="network_monitor",
            event_category="network",
            event_type=event_type,
            severity=severity,
            source_ip=src_ip,
            destination_ip=dst_ip,
            destination_port=int(dst_port) if dst_port else None,
            process_name=proc_name,
            process_id=int(raw.get("process_id")) if raw.get("process_id") else None,
            description=f"Outbound {proto} connection to {dst_ip}:{dst_port} by {proc_name or 'unknown'}",
            raw_data=raw,
            tags=["network", proto.lower()],
        )
