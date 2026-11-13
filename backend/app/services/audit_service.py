"""
Audit Service: Immutable, tamper-evident audit logging with SHA-256 hash chaining.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from app.models.audit_logs import AuditLog

log = structlog.get_logger(__name__)


class AuditService:
    @staticmethod
    def _compute_hash(
        previous_hash: str,
        timestamp_str: str,
        actor_id: Optional[str],
        action: str,
        resource_type: str,
        resource_id: Optional[str],
        result: str,
        new_value: Optional[Dict[str, Any]],
    ) -> str:
        payload = f"{previous_hash}|{timestamp_str}|{actor_id or ''}|{action}|{resource_type}|{resource_id or ''}|{result}|{json.dumps(new_value, sort_keys=True) if new_value else ''}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    async def log_action(
        cls,
        db: AsyncSession,
        *,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        actor_id: Optional[UUID] = None,
        actor_username: Optional[str] = None,
        source_ip: Optional[str] = None,
        result: str = "success",
        old_value: Optional[Dict[str, Any]] = None,
        new_value: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """
        Record an immutable action in the audit trail linked by SHA-256 hash chaining.
        """
        stmt = select(AuditLog.hash).order_by(desc(AuditLog.timestamp), desc(AuditLog.id)).limit(1)
        res = await db.execute(stmt)
        last_hash = res.scalar_one_or_none() or "0" * 64

        now = datetime.now(timezone.utc)
        record_hash = cls._compute_hash(
            previous_hash=last_hash,
            timestamp_str=now.isoformat(),
            actor_id=str(actor_id) if actor_id else None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            result=result,
            new_value=new_value,
        )

        entry = AuditLog(
            timestamp=now,
            actor_id=actor_id,
            actor_username=actor_username,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            source_ip=source_ip,
            result=result,
            old_value=old_value,
            new_value=new_value,
            hash=record_hash,
        )
        db.add(entry)
        await db.flush()
        log.info(
            "Audit log recorded",
            action=action,
            actor=actor_username,
            resource=f"{resource_type}:{resource_id}",
            result=result,
        )
        return entry

    @classmethod
    async def verify_chain_integrity(cls, db: AsyncSession, limit: int = 1000) -> bool:
        """
        Verify that the audit trail has not been altered or tampered with.
        """
        stmt = select(AuditLog).order_by(AuditLog.timestamp.asc(), AuditLog.id.asc()).limit(limit)
        res = await db.execute(stmt)
        records = res.scalars().all()

        current_prev_hash = "0" * 64
        for r in records:
            expected_hash = cls._compute_hash(
                previous_hash=current_prev_hash,
                timestamp_str=r.timestamp.isoformat(),
                actor_id=str(r.actor_id) if r.actor_id else None,
                action=r.action,
                resource_type=r.resource_type,
                resource_id=r.resource_id,
                result=r.result,
                new_value=r.new_value,
            )
            if expected_hash != r.hash:
                log.error("Audit log tampering detected!", record_id=str(r.id))
                return False
            current_prev_hash = r.hash
        return True
