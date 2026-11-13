"""
Windows Event Log Normalizer.
Maps Windows Security, System, and Sysmon event IDs to canonical NormalizedEvent schema.
Key IDs:
  4624 - Logon Success
  4625 - Logon Failure
  4648 - Explicit Credentials Logon
  4672 - Special Privileges Assigned
  4688 - Process Creation
  4720 - User Account Created
  4722 - User Account Enabled
  4725 - User Account Disabled
  4740 - User Account Locked Out
  7045 - Service Installed
  1102 - Audit Log Cleared
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
try:
    import structlog
    log = structlog.get_logger(__name__)
except ImportError:
    import logging
    log = logging.getLogger(__name__)

from normalizers.base import NormalizedEvent

WINDOWS_EVENT_MAP = {
    4624: ("authentication", "logon_success", "informational", "Windows logon succeeded"),
    4625: ("authentication", "logon_failure", "medium", "Windows logon failed"),
    4648: ("authentication", "explicit_logon", "low", "Logon attempted using explicit credentials"),
    4672: ("authentication", "special_privileges", "low", "Special privileges assigned to new logon"),
    4688: ("process", "process_creation", "informational", "New process has been created"),
    4720: ("iam", "user_created", "medium", "A user account was created"),
    4722: ("iam", "user_enabled", "low", "A user account was enabled"),
    4725: ("iam", "user_disabled", "low", "A user account was disabled"),
    4740: ("authentication", "account_lockout", "high", "A user account was locked out"),
    7045: ("system", "service_installed", "medium", "A service was installed in the system"),
    1102: ("system", "audit_log_cleared", "critical", "The audit log was cleared"),
}


class WindowsEventNormalizer:
    @staticmethod
    def normalize(raw: Dict[str, Any], device_id: str = "", hostname: str = "") -> NormalizedEvent:
        event_id = raw.get("EventID") or raw.get("event_id")
        try:
            event_id = int(event_id)
        except (ValueError, TypeError):
            event_id = 0

        category, event_type, severity, default_desc = WINDOWS_EVENT_MAP.get(
            event_id, ("system", f"win_event_{event_id}", "informational", f"Windows Event ID {event_id}")
        )

        data = raw.get("EventData") or raw
        username = (
            data.get("TargetUserName")
            or data.get("SubjectUserName")
            or raw.get("username")
        )
        domain = data.get("TargetDomainName") or data.get("SubjectDomainName")
        ip = data.get("IpAddress") or raw.get("source_ip")
        if ip in ("-", "::1", "127.0.0.1"):
            ip = None

        process_name = data.get("NewProcessName") or data.get("ProcessName") or raw.get("process_name")
        process_id = data.get("ProcessId") or raw.get("process_id")
        try:
            process_id = int(str(process_id), 16) if str(process_id).startswith("0x") else int(process_id)
        except (ValueError, TypeError):
            process_id = None

        return NormalizedEvent(
            device_id=device_id,
            hostname=hostname or raw.get("Computer") or raw.get("hostname", ""),
            event_source="windows_event_log",
            event_category=category,
            event_type=event_type,
            severity=severity,
            username=username,
            user_domain=domain,
            source_ip=ip,
            process_name=process_name,
            process_id=process_id,
            description=raw.get("event_description") or default_desc,
            raw_data=raw,
            tags=["windows", f"eid_{event_id}"],
        )
