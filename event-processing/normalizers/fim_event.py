"""
File Integrity Monitoring (FIM) Event Normalizer.
Records file changes, creation, deletions, and cryptographic SHA-256 hash transitions.
"""
from __future__ import annotations

from typing import Any, Dict
from normalizers.base import NormalizedEvent


class FIMEventNormalizer:
    @staticmethod
    def normalize(raw: Dict[str, Any], device_id: str = "", hostname: str = "") -> NormalizedEvent:
        change_type = raw.get("change_type", "modified")
        path = raw.get("file_path", "")
        file_hash = raw.get("file_hash")

        severity = "high" if change_type in ("modified", "deleted") else "medium"
        desc = f"File integrity event ({change_type}) detected on: {path}"

        return NormalizedEvent(
            device_id=device_id,
            hostname=hostname or raw.get("hostname", ""),
            event_source="fim_monitor",
            event_category="fim",
            event_type=f"fim_{change_type}",
            severity=severity,
            file_path=path,
            file_hash=file_hash,
            description=desc,
            raw_data=raw,
            tags=["fim", change_type],
        )
