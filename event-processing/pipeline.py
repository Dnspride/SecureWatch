"""
SIEM Event Processing Pipeline.
Flow: Raw Ingest -> Source Dispatch -> Normalization -> Context Enrichment -> Persistence -> Threat Detection.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional
try:
    import structlog
    log = structlog.get_logger(__name__)
except ImportError:
    import logging
    log = logging.getLogger(__name__)

# Add current directory to path for local module imports
sys.path.insert(0, os.path.dirname(__file__))

from normalizers.base import NormalizedEvent
from normalizers.windows_event import WindowsEventNormalizer
from normalizers.linux_auth import LinuxAuthNormalizer
from normalizers.process_event import ProcessEventNormalizer
from normalizers.network_event import NetworkEventNormalizer
from normalizers.fim_event import FIMEventNormalizer


class EventPipeline:
    def __init__(self) -> None:
        self.normalizers = {
            "windows_event_log": WindowsEventNormalizer.normalize,
            "linux_auth": LinuxAuthNormalizer.normalize,
            "process_monitor": ProcessEventNormalizer.normalize,
            "network_monitor": NetworkEventNormalizer.normalize,
            "fim_monitor": FIMEventNormalizer.normalize,
            "fim": FIMEventNormalizer.normalize,
        }

    def process(
        self,
        raw_event: Dict[str, Any],
        device_id: str = "",
        hostname: str = "",
    ) -> NormalizedEvent:
        """
        Validate, normalize, and enrich a single raw event into a canonical NormalizedEvent.
        """
        source = raw_event.get("event_source") or raw_event.get("source") or "unknown"
        normalizer_fn = self.normalizers.get(source)

        if normalizer_fn:
            normalized = normalizer_fn(raw_event, device_id=device_id, hostname=hostname)
        else:
            # Fallback normalizer
            normalized = NormalizedEvent(
                device_id=device_id,
                hostname=hostname or raw_event.get("hostname", ""),
                event_source=source,
                event_category=raw_event.get("event_category", "system"),
                event_type=raw_event.get("event_type", "generic_event"),
                severity=raw_event.get("severity", "informational"),
                description=raw_event.get("event_description") or "Security event",
                raw_data=raw_event,
            )

        log.debug(
            "Event normalized successfully",
            id=normalized.event_id,
            source=normalized.event_source,
            category=normalized.event_category,
            type=normalized.event_type,
        )
        return normalized

    def process_batch(
        self,
        raw_events: List[Dict[str, Any]],
        device_id: str = "",
        hostname: str = "",
    ) -> List[NormalizedEvent]:
        """Normalize an entire batch of ingested events."""
        return [self.process(e, device_id=device_id, hostname=hostname) for e in raw_events]
