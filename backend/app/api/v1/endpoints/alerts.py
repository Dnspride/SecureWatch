"""
Alert Management API Endpoints: Triage, investigation, status transitions, notes, and assignment.
"""
from __future__ import annotations

import math
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.alerts import Alert, AlertNote, AlertStatus
from app.models.users import User
from app.schemas.alerts import (
    AlertAssignRequest,
    AlertDetailResponse,
    AlertNoteCreate,
    AlertNoteResponse,
    AlertResponse,
    AlertStatusUpdateRequest,
    AlertUpdateRequest,
)
from app.schemas.common import MessageResponse, PaginatedResponse
from app.services.alert_service import AlertService
from app.services.auth_service import require_permission

router = APIRouter(prefix="/alerts", tags=["Threat Detection & Alerts"])


@router.get("", response_model=PaginatedResponse[AlertResponse], summary="List security alerts")
async def list_alerts(
    severity: Optional[str] = None,
    status_filter: Optional[str] = None,
    status: Optional[str] = None,
    device_id: Optional[UUID] = None,
    assigned_to: Optional[UUID] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(require_permission("alerts.manage")),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[AlertResponse]:
    effective_status = status_filter or status
    alerts, total = await AlertService.get_alerts(
        db,
        severity=severity,
        status_filter=effective_status,
        device_id=device_id,
        assigned_to=assigned_to,
        page=page,
        page_size=page_size,
    )
    pages = math.ceil(total / page_size) if total > 0 else 1
    items = [
        AlertResponse(
            id=a.id,
            title=a.title,
            description=a.description,
            severity=a.severity,
            status=a.status,
            detection_time=a.detection_time,
            device_id=a.device_id,
            device_name=a.device.hostname if a.device else None,
            user_id=a.user_id,
            source_event_id=a.source_event_id,
            detection_rule_id=a.detection_rule_id,
            risk_score=a.risk_score,
            assigned_to=a.assigned_to,
            resolved_at=a.resolved_at,
            resolution_notes=a.resolution_notes,
            notes_count=len(a.notes) if a.notes else 0,
        )
        for a in alerts
    ]
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/{alert_id}", response_model=AlertDetailResponse, summary="Get alert investigation details")
async def get_alert(
    alert_id: UUID,
    current_user: User = Depends(require_permission("alerts.manage")),
    db: AsyncSession = Depends(get_db),
) -> AlertDetailResponse:
    a = await AlertService.get_by_id(db, alert_id)
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    notes = [
        AlertNoteResponse(
            id=n.id,
            alert_id=n.alert_id,
            author_id=n.author_id,
            author_name=n.author.username if n.author else "System",
            content=n.content,
            created_at=n.created_at,
        )
        for n in a.notes
    ]

    return AlertDetailResponse(
        id=a.id,
        title=a.title,
        description=a.description,
        severity=a.severity,
        status=a.status,
        detection_time=a.detection_time,
        device_id=a.device_id,
        device_name=a.device.hostname if a.device else None,
        user_id=a.user_id,
        source_event_id=a.source_event_id,
        detection_rule_id=a.detection_rule_id,
        risk_score=a.risk_score,
        assigned_to=a.assigned_to,
        resolved_at=a.resolved_at,
        resolution_notes=a.resolution_notes,
        notes_count=len(notes),
        notes=notes,
        recommended_steps=[
            "Verify source endpoint integrity and active processes.",
            "Review recent authentication attempts from the observed IP address.",
            "Inspect process execution tree and parent-child anomalies.",
            "Isolate or revoke device access if malicious activity is confirmed.",
        ],
    )


@router.post("/{alert_id}/acknowledge", response_model=AlertResponse, summary="Acknowledge alert")
async def acknowledge_alert(
    alert_id: UUID,
    current_user: User = Depends(require_permission("alerts.manage")),
    db: AsyncSession = Depends(get_db),
) -> AlertResponse:
    a = await AlertService.get_by_id(db, alert_id)
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    updated = await AlertService.update_status(
        db, a, AlertStatusUpdateRequest(status=AlertStatus.acknowledged), actor=current_user
    )
    return AlertResponse(
        id=updated.id,
        title=updated.title,
        description=updated.description,
        severity=updated.severity,
        status=updated.status,
        detection_time=updated.detection_time,
        device_id=updated.device_id,
        device_name=updated.device.hostname if updated.device else None,
        risk_score=updated.risk_score,
        assigned_to=updated.assigned_to,
    )


@router.post("/{alert_id}/resolve", response_model=AlertResponse, summary="Resolve alert")
async def resolve_alert(
    alert_id: UUID,
    payload: AlertStatusUpdateRequest,
    current_user: User = Depends(require_permission("alerts.manage")),
    db: AsyncSession = Depends(get_db),
) -> AlertResponse:
    a = await AlertService.get_by_id(db, alert_id)
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    updated = await AlertService.update_status(db, a, payload, actor=current_user)
    return AlertResponse(
        id=updated.id,
        title=updated.title,
        description=updated.description,
        severity=updated.severity,
        status=updated.status,
        detection_time=updated.detection_time,
        device_id=updated.device_id,
        device_name=updated.device.hostname if updated.device else None,
        risk_score=updated.risk_score,
        assigned_to=updated.assigned_to,
        resolved_at=updated.resolved_at,
        resolution_notes=updated.resolution_notes,
    )


@router.patch("/{alert_id}", response_model=AlertResponse, summary="Update alert")
@router.put("/{alert_id}", response_model=AlertResponse, summary="Update alert")
async def update_alert(
    alert_id: UUID,
    payload: AlertUpdateRequest,
    current_user: User = Depends(require_permission("alerts.manage")),
    db: AsyncSession = Depends(get_db),
) -> AlertResponse:
    a = await AlertService.get_by_id(db, alert_id)
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    if payload.status:
        a = await AlertService.update_status(
            db, a, AlertStatusUpdateRequest(status=payload.status, resolution_notes=payload.resolution_notes), actor=current_user
        )
    target_assignee = payload.assigned_to or payload.user_id
    if target_assignee is not None:
        a = await AlertService.assign_alert(db, a, target_assignee, actor=current_user)

    return AlertResponse(
        id=a.id,
        title=a.title,
        description=a.description,
        severity=a.severity,
        status=a.status,
        detection_time=a.detection_time,
        device_id=a.device_id,
        device_name=a.device.hostname if a.device else None,
        risk_score=a.risk_score,
        assigned_to=a.assigned_to,
        resolved_at=a.resolved_at,
        resolution_notes=a.resolution_notes,
    )


@router.post("/{alert_id}/assign", response_model=AlertResponse, summary="Assign alert to analyst")
async def assign_alert(
    alert_id: UUID,
    payload: AlertAssignRequest,
    current_user: User = Depends(require_permission("alerts.manage")),
    db: AsyncSession = Depends(get_db),
) -> AlertResponse:
    a = await AlertService.get_by_id(db, alert_id)
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    target_assignee = payload.assigned_to or payload.user_id
    updated = await AlertService.assign_alert(db, a, target_assignee, actor=current_user)
    return AlertResponse(
        id=updated.id,
        title=updated.title,
        description=updated.description,
        severity=updated.severity,
        status=updated.status,
        detection_time=updated.detection_time,
        device_id=updated.device_id,
        device_name=updated.device.hostname if updated.device else None,
        risk_score=updated.risk_score,
        assigned_to=updated.assigned_to,
    )


@router.get("/{alert_id}/notes", response_model=List[AlertNoteResponse], summary="List investigation notes for alert")
async def get_alert_notes(
    alert_id: UUID,
    current_user: User = Depends(require_permission("alerts.manage")),
    db: AsyncSession = Depends(get_db),
) -> List[AlertNoteResponse]:
    a = await AlertService.get_by_id(db, alert_id)
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return [
        AlertNoteResponse(
            id=n.id,
            alert_id=n.alert_id,
            author_id=n.author_id,
            author_name=n.author.username if n.author else "System",
            content=n.content,
            created_at=n.created_at,
        )
        for n in a.notes
    ]


@router.post("/{alert_id}/notes", response_model=AlertNoteResponse, summary="Add investigation note to alert")
async def add_alert_note(
    alert_id: UUID,
    data: AlertNoteCreate,
    current_user: User = Depends(require_permission("alerts.manage")),
    db: AsyncSession = Depends(get_db),
) -> AlertNoteResponse:
    a = await AlertService.get_by_id(db, alert_id)
    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    note = await AlertService.add_note(db, a, data, author=current_user)
    return AlertNoteResponse(
        id=note.id,
        alert_id=note.alert_id,
        author_id=note.author_id,
        author_name=current_user.username,
        content=note.content,
        created_at=note.created_at,
    )
