"""
event-processing/normalizers/base.py

Canonical NormalizedEvent schema shared by all source-specific normalizers.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class NormalizedEvent:
    """
    Platform-canonical event representation.

    Every raw event from any source (Windows Event Log, Linux auth,
    sysmon, network tap, FIM, etc.) is mapped to this schema by a
    source-specific normalizer before being stored and evaluated.
    """

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------
    event_id: str = field(
        default_factory=lambda: str(uuid.uuid4()),
        metadata={"description": "Platform-generated UUID for this event."},
    )
    event_timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc),
        metadata={"description": "Timestamp of the event as reported by the source."},
    )
    received_timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc),
        metadata={"description": "Timestamp when the platform received this event."},
    )

    # ------------------------------------------------------------------
    # Device / agent context
    # ------------------------------------------------------------------
    device_id: str = field(
        default="",
        metadata={"description": "Platform-assigned UUID of the reporting endpoint."},
    )
    hostname: str = field(
        default="",
        metadata={"description": "Fully-qualified or short hostname of the source endpoint."},
    )
    agent_version: Optional[str] = field(
        default=None,
        metadata={"description": "SecureWatch agent version that collected this event."},
    )
    os_name: Optional[str] = field(
        default=None,
        metadata={"description": "Operating system name (e.g., 'Windows Server 2022')."},
    )
    os_version: Optional[str] = field(
        default=None,
        metadata={"description": "OS version string."},
    )

    # ------------------------------------------------------------------
    # Identity / principal
    # ------------------------------------------------------------------
    user_id: Optional[str] = field(
        default=None,
        metadata={"description": "Platform user UUID (resolved from username by enrichment)."},
    )
    username: Optional[str] = field(
        default=None,
        metadata={"description": "Username / UPN associated with the event."},
    )
    user_domain: Optional[str] = field(
        default=None,
        metadata={"description": "Windows domain or Kerberos realm."},
    )

    # ------------------------------------------------------------------
    # Event classification
    # ------------------------------------------------------------------
    event_source: str = field(
        default="",
        metadata={
            "description": (
                "Source log / sensor type. One of: "
                "windows_event_log, linux_auth, sshd, process_monitor, "
                "network_monitor, fim_monitor, fim_event, sysmon, auditd, "
                "edr, vpn_auth, firewall_log, directory_service, "
                "agent_inventory, securewatch_platform."
            )
        },
    )
    event_category: str = field(
        default="",
        metadata={
            "description": (
                "High-level category. One of: "
                "authentication, process, network, fim, system, "
                "availability, compliance."
            )
        },
    )
    event_type: str = field(
        default="",
        metadata={"description": "Specific event type (e.g., 'login_failed', 'process_created')."},
    )
    severity: str = field(
        default="info",
        metadata={"description": "Event severity: info | low | medium | high | critical."},
    )

    # ------------------------------------------------------------------
    # Network context
    # ------------------------------------------------------------------
    source_ip: Optional[str] = field(
        default=None,
        metadata={"description": "Source IP address (may be the endpoint itself)."},
    )
    source_port: Optional[int] = field(
        default=None,
        metadata={"description": "Source TCP/UDP port."},
    )
    destination_ip: Optional[str] = field(
        default=None,
        metadata={"description": "Destination IP address."},
    )
    destination_port: Optional[int] = field(
        default=None,
        metadata={"description": "Destination TCP/UDP port."},
    )
    protocol: Optional[str] = field(
        default=None,
        metadata={"description": "Network protocol (tcp, udp, icmp, …)."},
    )
    direction: Optional[str] = field(
        default=None,
        metadata={"description": "Connection direction: inbound | outbound | internal."},
    )
    bytes_sent: Optional[int] = field(default=None)
    bytes_received: Optional[int] = field(default=None)

    # ------------------------------------------------------------------
    # Process context
    # ------------------------------------------------------------------
    process_name: Optional[str] = field(
        default=None,
        metadata={"description": "Name of the process (without full path)."},
    )
    process_id: Optional[int] = field(
        default=None,
        metadata={"description": "Process ID (PID)."},
    )
    process_path: Optional[str] = field(
        default=None,
        metadata={"description": "Full path to the process executable."},
    )
    process_command_line: Optional[str] = field(
        default=None,
        metadata={"description": "Full process command line including arguments."},
    )
    process_hash_md5: Optional[str] = field(default=None)
    process_hash_sha256: Optional[str] = field(default=None)
    parent_process_name: Optional[str] = field(
        default=None,
        metadata={"description": "Name of the parent process."},
    )
    parent_process_id: Optional[int] = field(default=None)
    parent_process_path: Optional[str] = field(default=None)

    # ------------------------------------------------------------------
    # File / FIM context
    # ------------------------------------------------------------------
    file_path: Optional[str] = field(
        default=None,
        metadata={"description": "Full path of the affected file."},
    )
    file_name: Optional[str] = field(default=None)
    file_hash: Optional[str] = field(
        default=None,
        metadata={"description": "SHA-256 hash of the affected file."},
    )
    file_hash_md5: Optional[str] = field(default=None)
    file_size_bytes: Optional[int] = field(default=None)
    file_operation: Optional[str] = field(
        default=None,
        metadata={"description": "created | modified | deleted | renamed | permission_changed"},
    )
    file_old_path: Optional[str] = field(default=None)

    # ------------------------------------------------------------------
    # Service context
    # ------------------------------------------------------------------
    service_name: Optional[str] = field(default=None)
    service_path: Optional[str] = field(default=None)
    service_start_type: Optional[str] = field(default=None)

    # ------------------------------------------------------------------
    # Authentication context
    # ------------------------------------------------------------------
    logon_type: Optional[str] = field(
        default=None,
        metadata={"description": "Windows logon type name (Interactive, Network, RemoteInteractive…)"},
    )
    logon_type_id: Optional[int] = field(default=None)
    auth_method: Optional[str] = field(
        default=None,
        metadata={"description": "Authentication method: password, kerberos, ntlm, pki, otp, …"},
    )
    failure_reason: Optional[str] = field(default=None)
    target_username: Optional[str] = field(
        default=None,
        metadata={"description": "Account targeted by the action (e.g., in a runas / sudo context)."},
    )

    # ------------------------------------------------------------------
    # Threat intelligence enrichment (added by pipeline enricher)
    # ------------------------------------------------------------------
    threat_intel: Dict[str, Any] = field(
        default_factory=dict,
        metadata={
            "description": (
                "TI lookup results, e.g.: "
                "{'is_malicious_ip': True, 'ip_reputation_score': 95, "
                "'ip_category': 'C2', 'ip_country': 'RU'}"
            )
        },
    )

    # ------------------------------------------------------------------
    # Time enrichment (added by pipeline enricher)
    # ------------------------------------------------------------------
    outside_business_hours: Optional[bool] = field(
        default=None,
        metadata={"description": "True if event_timestamp is outside configured business hours."},
    )

    # ------------------------------------------------------------------
    # Raw and meta
    # ------------------------------------------------------------------
    description: str = field(
        default="",
        metadata={"description": "Human-readable description assembled by the normalizer."},
    )
    raw_data: Dict[str, Any] = field(
        default_factory=dict,
        metadata={"description": "Original, unparsed event data as received from the agent."},
    )
    tags: List[str] = field(
        default_factory=list,
        metadata={"description": "Arbitrary tags added by normalizer, enricher, or detection engine."},
    )
    mitre_techniques: List[str] = field(
        default_factory=list,
        metadata={"description": "MITRE ATT&CK technique IDs associated with this event."},
    )
    related_event_ids: List[str] = field(
        default_factory=list,
        metadata={"description": "Platform event IDs of related events (for correlation)."},
    )

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict (datetimes as ISO-8601 strings)."""
        import dataclasses

        result: Dict[str, Any] = {}
        for f in dataclasses.fields(self):
            value = getattr(self, f.name)
            if isinstance(value, datetime):
                result[f.name] = value.isoformat()
            else:
                result[f.name] = value
        return result

    def to_opensearch_doc(self) -> Dict[str, Any]:
        """Return dict shaped for direct OpenSearch indexing."""
        doc = self.to_dict()
        # OpenSearch uses @timestamp as the primary time field
        doc["@timestamp"] = doc.pop("event_timestamp")
        return doc


# ---------------------------------------------------------------------------
# Base normalizer interface
# ---------------------------------------------------------------------------

class BaseNormalizer:
    """
    Abstract base class for all source-specific normalizers.

    Subclasses must implement ``normalize(raw_event, device_id) → NormalizedEvent``.
    """

    #: Override in subclasses to filter only relevant event sources.
    supported_sources: List[str] = []

    def can_handle(self, raw_event: Dict[str, Any]) -> bool:
        """Return True if this normalizer can process the given raw event."""
        source = raw_event.get("source") or raw_event.get("event_source", "")
        return not self.supported_sources or source in self.supported_sources

    def normalize(
        self, raw_event: Dict[str, Any], device_id: str
    ) -> NormalizedEvent:
        """
        Normalize raw event into a NormalizedEvent.
        Must be overridden by subclasses.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Shared helper utilities available to all normalizers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _safe_str(value: Any) -> Optional[str]:
        return str(value).strip() if value is not None else None

    @staticmethod
    def _coerce_datetime(value: Any) -> datetime:
        """Parse various datetime representations to an aware UTC datetime."""
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        if isinstance(value, str):
            import dateutil.parser  # type: ignore[import]

            try:
                dt = dateutil.parser.parse(value)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception:  # noqa: BLE001
                pass
        return datetime.now(timezone.utc)
