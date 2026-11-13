"""
Security Event Ingestion & Processing Service: Validation, normalization, rule matching, and alert triggering.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.models.alerts import AlertSeverity
from app.models.devices import Device
from app.models.security_events import SecurityEvent
from app.schemas.events import (
    EventSearchRequest,
    SecurityEventBatchIngestRequest,
    SecurityEventBatchIngestResponse,
)
from app.services.alert_service import AlertService

log = structlog.get_logger(__name__)

_opensearch_client = None

def get_opensearch_client():
    global _opensearch_client
    if _opensearch_client is None:
        url = os.getenv("OPENSEARCH_URL", "http://opensearch:9200")
        try:
            from opensearchpy import OpenSearch
            _opensearch_client = OpenSearch([url], use_ssl=False, verify_certs=False, timeout=3)
        except Exception as e:
            log.warning("OpenSearch client unavailable", error=str(e))
            _opensearch_client = False
    return _opensearch_client if _opensearch_client is not False else None


class EventService:
    @classmethod
    async def ingest_batch(
        cls,
        db: AsyncSession,
        device_id: UUID,
        payload: SecurityEventBatchIngestRequest,
    ) -> SecurityEventBatchIngestResponse:
        """
        Process a batch of endpoint security events:
        1. Validate device
        2. Normalize fields
        3. Persist event references to PostgreSQL
        4. Evaluate detection rules (e.g. brute force, disabled firewall, suspicious processes)
        5. Generate alerts for matches
        """
        dev_stmt = select(Device).where(Device.id == device_id)
        dev_res = await db.execute(dev_stmt)
        device = dev_res.scalar_one_or_none()

        accepted = 0
        rejected = 0
        alerts_triggered = 0
        errors = []

        now = datetime.now(timezone.utc)

        for item in payload.events:
            try:
                # Basic normalization & severity mapping
                sev = item.severity.lower()
                if sev not in ("informational", "low", "medium", "high", "critical"):
                    sev = "informational"

                event_rec = SecurityEvent(
                    device_id=device_id,
                    user_id=item.user_id,
                    event_timestamp=item.event_timestamp or now,
                    event_source=str(item.event_source)[:64] if item.event_source else "unknown",
                    event_category=str(item.event_category)[:64] if item.event_category else "unknown",
                    event_type=str(item.event_type)[:128] if item.event_type else "unknown",
                    severity=sev,
                    source_ip=str(item.source_ip)[:45] if item.source_ip else None,
                    destination_ip=str(item.destination_ip)[:45] if item.destination_ip else None,
                    process_name=str(item.process_name)[:255] if item.process_name else None,
                    process_id=item.process_id,
                    event_description=item.event_description,
                    raw_event_ref=json.dumps(item.raw_data) if item.raw_data else None,
                    is_alert_generated=False,
                )
                db.add(event_rec)
                await db.flush()
                accepted += 1

                # Rule Matching: High/Critical security detections
                alert_title = None
                alert_desc = None
                alert_sev = None

                # Rule 1: Disabled firewall or AV
                if item.event_type in ("firewall_disabled", "firewall.disabled"):
                    alert_title = f"Endpoint Firewall Disabled on {device.hostname if device else 'device'}"
                    alert_desc = "Host-based firewall was detected in a disabled state."
                    alert_sev = AlertSeverity.high
                elif item.event_type in ("antivirus_disabled", "av.disabled"):
                    alert_title = f"Antivirus Protection Disabled on {device.hostname if device else 'device'}"
                    alert_desc = "Endpoint antivirus/EDR agent service was reported stopped or disabled."
                    alert_sev = AlertSeverity.critical

                # Rule 2: Suspicious process execution
                elif item.event_category == "process" and item.process_name:
                    pname = item.process_name.lower()
                    if pname in ("powershell.exe", "pwsh.exe", "cmd.exe", "bash", "sh"):
                        raw = item.raw_data or {}
                        cmdline = str(raw.get("cmdline", "")).lower()
                        if "-encodedcommand" in cmdline or "-enc" in cmdline or "downloadstring" in cmdline or "iex" in cmdline:
                            alert_title = f"Suspicious Encoded Script Execution on {device.hostname if device else 'device'}"
                            alert_desc = f"Process {item.process_name} spawned with suspicious command line parameters."
                            alert_sev = AlertSeverity.critical

                # Rule 3: FIM alteration
                elif item.event_category == "fim":
                    alert_title = f"Critical File Modification Detected on {device.hostname if device else 'device'}"
                    alert_desc = f"Monitored system file modified: {item.file_path}"
                    alert_sev = AlertSeverity.high

                # Rule 4: Critical event severity from agent
                elif sev in ("high", "critical"):
                    alert_title = f"Security Alert: {item.event_type} on {device.hostname if device else 'device'}"
                    alert_desc = item.event_description or f"High severity event reported by {item.event_source}"
                    alert_sev = AlertSeverity.critical if sev == "critical" else AlertSeverity.high

                if alert_title and alert_sev:
                    await AlertService.create_alert(
                        db,
                        title=alert_title,
                        description=alert_desc,
                        severity=alert_sev,
                        device_id=device_id,
                        user_id=item.user_id,
                        source_event_id=event_rec.id,
                        risk_score=75.0 if alert_sev == AlertSeverity.critical else 50.0,
                    )
                    event_rec.is_alert_generated = True
                    alerts_triggered += 1

                # Index event into OpenSearch SIEM index
                os_client = get_opensearch_client()
                if os_client:
                    try:
                        idx_name = f"securewatch-events-{now.strftime('%Y.%m')}"
                        os_doc = {
                            "event_id": str(event_rec.id),
                            "event_timestamp": event_rec.event_timestamp.isoformat(),
                            "@timestamp": event_rec.event_timestamp.isoformat(),
                            "device_id": str(device_id),
                            "hostname": device.hostname if device else "unknown",
                            "event_source": event_rec.event_source,
                            "event_category": event_rec.event_category,
                            "event_type": event_rec.event_type,
                            "severity": event_rec.severity,
                            "source_ip": event_rec.source_ip,
                            "destination_ip": event_rec.destination_ip,
                            "process_name": event_rec.process_name,
                            "process_id": event_rec.process_id,
                            "user_id": str(item.user_id) if item.user_id else None,
                            "username": str(item.raw_data.get("username", "")) if item.raw_data else None,
                            "event_description": event_rec.event_description,
                            "is_alert_generated": event_rec.is_alert_generated,
                            "raw_data": item.raw_data or {},
                        }
                        os_client.index(index=idx_name, body=os_doc, id=str(event_rec.id))
                    except Exception as os_e:
                        log.debug("OpenSearch indexing error", error=str(os_e))

            except Exception as e:
                rejected += 1
                errors.append(str(e))
                log.error("Failed to ingest event item", error=str(e))

        await db.commit()
        return SecurityEventBatchIngestResponse(
            accepted=accepted,
            rejected=rejected,
            alerts_triggered=alerts_triggered,
            errors=errors[:10],
        )

    @classmethod
    async def search_events(
        cls,
        db: AsyncSession,
        params: EventSearchRequest,
    ) -> Tuple[List[SecurityEvent], int]:
        query = select(SecurityEvent)

        if params.device_id:
            query = query.where(SecurityEvent.device_id == params.device_id)
        if params.event_category:
            query = query.where(SecurityEvent.event_category == params.event_category)
        if params.severity:
            query = query.where(SecurityEvent.severity == params.severity.lower())
        if params.event_source:
            query = query.where(SecurityEvent.event_source == params.event_source)
        if params.start_time:
            query = query.where(SecurityEvent.event_timestamp >= params.start_time)
        if params.end_time:
            query = query.where(SecurityEvent.event_timestamp <= params.end_time)

        if params.query:
            q = f"%{params.query.strip()}%"
            query = query.where(
                or_(
                    SecurityEvent.event_type.ilike(q),
                    SecurityEvent.event_description.ilike(q),
                    SecurityEvent.source_ip.ilike(q),
                    SecurityEvent.destination_ip.ilike(q),
                    SecurityEvent.process_name.ilike(q),
                )
            )

        count_stmt = select(func.count()).select_from(query.subquery())
        count_res = await db.execute(count_stmt)
        total = count_res.scalar_one()

        query = query.order_by(desc(SecurityEvent.event_timestamp)).offset(
            (params.page - 1) * params.page_size
        ).limit(params.page_size)

        res = await db.execute(query)
        events = list(res.scalars().all())
        return events, total
