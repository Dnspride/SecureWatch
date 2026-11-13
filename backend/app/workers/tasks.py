"""
Celery background worker tasks for SecureWatch.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import structlog

from app.workers.celery_app import celery_app
from app.core.database import async_session_factory
from app.services.device_service import DeviceService

log = structlog.get_logger(__name__)


@celery_app.task
def check_device_heartbeats() -> int:
    """Periodic task: identify endpoints whose heartbeat timed out and mark them offline."""
    async def _run():
        async with async_session_factory() as db:
            count = await DeviceService.detect_offline_devices(db, timeout_seconds=300)
            log.info("Heartbeat check completed", offline_detected=count)
            return count

    return asyncio.run(_run())


@celery_app.task
def compute_all_device_risks() -> int:
    """Periodic task: recalculate risk scores across all registered endpoints."""
    async def _run():
        from sqlalchemy import select
        from app.models.devices import Device

        async with async_session_factory() as db:
            stmt = select(Device.id)
            res = await db.execute(stmt)
            device_ids = res.scalars().all()
            for dev_id in device_ids:
                await DeviceService.compute_risk_score(db, dev_id)
            log.info("Device risk score recomputation complete", total_devices=len(device_ids))
            return len(device_ids)

    return asyncio.run(_run())
