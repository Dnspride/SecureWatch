"""
Alert Service: Alert lifecycle management, triage, assignment, investigation notes, and resolution.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, Tuple
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
import structlog

from app.models.alerts import Alert, AlertNote, AlertSeverity, AlertStatus
from app.models.detection_rules import DetectionRule
from app.models.devices import Device
from app.models.users import User
from app.schemas.alerts import AlertNoteCreate, AlertStatusUpdateRequest
from app.services.audit_service import AuditService

log = structlog.get_logger(__name__)


class AlertService:
    @classmethod
    async def get_alerts(
        cls,
        db: AsyncSession,
        *,
        severity: Optional[str] = None,
        status_filter: Optional[str] = None,
        device_id: Optional[UUID] = None,
        assigned_to: Optional[UUID] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> Tuple[List[Alert], int]:
        query = select(Alert).options(
            selectinload(Alert.device),
            selectinload(Alert.notes),
        )

        if severity:
            try:
                query = query.where(Alert.severity == AlertSeverity(severity))
            except ValueError:
                pass

        if status_filter:
            try:
                query = query.where(Alert.status == AlertStatus(status_filter))
            except ValueError:
                pass

        if device_id:
            query = query.where(Alert.device_id == device_id)
        if assigned_to:
            query = query.where(Alert.assigned_to == assigned_to)

        count_stmt = select(func.count()).select_from(query.subquery())
        count_res = await db.execute(count_stmt)
        total = count_res.scalar_one()

        query = query.order_by(desc(Alert.detection_time)).offset((page - 1) * page_size).limit(page_size)
        res = await db.execute(query)
        alerts = list(res.scalars().all())

        return alerts, total

    @classmethod
    async def get_by_id(cls, db: AsyncSession, alert_id: UUID) -> Optional[Alert]:
        stmt = (
            select(Alert)
            .options(
                selectinload(Alert.device),
                selectinload(Alert.notes).selectinload(AlertNote.author),
            )
            .where(Alert.id == alert_id)
        )
        res = await db.execute(stmt)
        return res.scalar_one_or_none()

    @classmethod
    async def create_alert(
        cls,
        db: AsyncSession,
        *,
        title: str,
        description: Optional[str] = None,
        severity: AlertSeverity = AlertSeverity.medium,
        device_id: Optional[UUID] = None,
        user_id: Optional[UUID] = None,
        source_event_id: Optional[UUID] = None,
        detection_rule_id: Optional[UUID] = None,
        risk_score: float = 0.0,
    ) -> Alert:
        now = datetime.now(timezone.utc)
        alert = Alert(
            title=title,
            description=description,
            severity=severity,
            status=AlertStatus.new,
            detection_time=now,
            device_id=device_id,
            user_id=user_id,
            source_event_id=source_event_id,
            detection_rule_id=detection_rule_id,
            risk_score=risk_score,
        )
        db.add(alert)
        await db.flush()

        # Update device risk score if device linked
        if device_id:
            from app.services.device_service import DeviceService
            await DeviceService.compute_risk_score(db, device_id)

        log.warn("New security alert generated", alert_id=str(alert.id), title=title, severity=severity.value)
        return alert

    @classmethod
    async def update_status(
        cls,
        db: AsyncSession,
        alert: Alert,
        data: AlertStatusUpdateRequest,
        actor: Optional[User] = None,
    ) -> Alert:
        old_status = alert.status
        alert.status = data.status

        if data.status in (AlertStatus.resolved, AlertStatus.false_positive):
            alert.resolved_at = datetime.now(timezone.utc)
            if data.resolution_notes:
                alert.resolution_notes = data.resolution_notes
        elif data.status == AlertStatus.new:
            alert.resolved_at = None

        await db.flush()

        # Recalculate device risk if alert was resolved
        if alert.device_id:
            from app.services.device_service import DeviceService
            await DeviceService.compute_risk_score(db, alert.device_id)

        await AuditService.log_action(
            db,
            action="alert.update_status",
            resource_type="alert",
            resource_id=str(alert.id),
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
            old_value={"status": old_status.value},
            new_value={"status": alert.status.value, "resolution_notes": alert.resolution_notes},
        )
        await db.commit()
        return alert

    @classmethod
    async def assign_alert(
        cls,
        db: AsyncSession,
        alert: Alert,
        assigned_to: Optional[UUID],
        actor: Optional[User] = None,
    ) -> Alert:
        alert.assigned_to = assigned_to
        if alert.status == AlertStatus.new and assigned_to is not None:
            alert.status = AlertStatus.investigating

        await db.flush()
        await AuditService.log_action(
            db,
            action="alert.assign",
            resource_type="alert",
            resource_id=str(alert.id),
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
            new_value={"assigned_to": str(assigned_to) if assigned_to else None},
        )
        await db.commit()
        return alert

    @classmethod
    async def add_note(
        cls,
        db: AsyncSession,
        alert: Alert,
        data: AlertNoteCreate,
        author: Optional[User] = None,
    ) -> AlertNote:
        note = AlertNote(
            alert_id=alert.id,
            author_id=author.id if author else None,
            content=data.content,
        )
        db.add(note)
        await db.flush()

        await AuditService.log_action(
            db,
            action="alert.add_note",
            resource_type="alert",
            resource_id=str(alert.id),
            actor_id=author.id if author else None,
            actor_username=author.username if author else "system",
        )
        await db.commit()
        return note
