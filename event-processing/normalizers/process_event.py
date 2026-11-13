"""
Process Creation Event Normalizer.
Maps endpoint process spawning, parent-child metadata, and command lines.
Redacts passwords and sensitive credentials.
"""
from __future__ import annotations

import re
from typing import Any, Dict
from normalizers.base import NormalizedEvent

PASSWORD_REDACT_REGEX = re.compile(r"(--password|-p)\s+([^\s]+)", re.IGNORECASE)


class ProcessEventNormalizer:
    @staticmethod
    def normalize(raw: Dict[str, Any], device_id: str = "", hostname: str = "") -> NormalizedEvent:
        cmdline = str(raw.get("cmdline") or "")
        clean_cmdline = PASSWORD_REDACT_REGEX.sub(r"\1 [REDACTED]", cmdline)

        process_name = raw.get("process_name") or raw.get("name")
        process_id = raw.get("process_id") or raw.get("pid")
        parent_name = raw.get("parent_process_name") or raw.get("parent_name")
        parent_id = raw.get("parent_process_id") or raw.get("ppid")

        severity = raw.get("severity", "informational")
        event_type = raw.get("event_type", "process_created")

        # Threat heuristic: Office or Scripting engines launching command shells
        if parent_name and process_name:
            pn = process_name.lower()
            parent_lower = parent_name.lower()
            if any(p in parent_lower for p in ("winword", "excel", "powerpnt", "outlook", "wscript", "cscript")):
                if any(sh in pn for sh in ("cmd.exe", "powershell.exe", "pwsh.exe", "bash", "sh")):
                    severity = "critical"
                    event_type = "suspicious_process_spawn"

        return NormalizedEvent(
            device_id=device_id,
            hostname=hostname or raw.get("hostname", ""),
            event_source="process_monitor",
            event_category="process",
            event_type=event_type,
            severity=severity,
            username=raw.get("username"),
            process_name=process_name,
            process_id=int(process_id) if process_id else None,
            parent_process_name=parent_name,
            parent_process_id=int(parent_id) if parent_id else None,
            description=f"Process execution: {process_name} (PID: {process_id})",
            raw_data={**raw, "cmdline": clean_cmdline},
            tags=["process", "execution"],
        )
