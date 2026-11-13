"""
Security Events API Endpoints: Ingestion from endpoint agents and SIEM event search.
"""
from __future__ import annotations

import math
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import decode_device_token
from app.models.security_events import SecurityEvent
from app.models.users import User
from app.schemas.common import PaginatedResponse
from app.schemas.events import (
    EventSearchRequest,
    SecurityEventBatchIngestRequest,
    SecurityEventBatchIngestResponse,
    SecurityEventResponse,
)
from app.services.auth_service import require_permission
from app.services.event_service import EventService

router = APIRouter(prefix="/events", tags=["SIEM Security Events"])


@router.post("/ingest", response_model=SecurityEventBatchIngestResponse, summary="Ingest telemetry from endpoint agent")
async def ingest_events(
    payload: SecurityEventBatchIngestRequest,
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
) -> SecurityEventBatchIngestResponse:
    """Endpoint agents authenticate with their issued device JWT to stream security events."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Device credential required")

    raw_token = authorization.split(" ", 1)[1]
    claims = decode_device_token(raw_token)
    if not claims or "sub" not in claims:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device credential")

    try:
        device_id = UUID(claims["sub"])
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device ID in token")

    return await EventService.ingest_batch(db, device_id, payload)


@router.post("/search", response_model=PaginatedResponse[SecurityEventResponse], summary="Search and filter events")
async def search_events(
    params: EventSearchRequest,
    current_user: User = Depends(require_permission("security_events.read")),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[SecurityEventResponse]:
    events, total = await EventService.search_events(db, params)
    pages = math.ceil(total / params.page_size) if total > 0 else 1
    return PaginatedResponse(
        items=events,
        total=total,
        page=params.page,
        page_size=params.page_size,
        pages=pages,
    )


@router.get("", response_model=PaginatedResponse[SecurityEventResponse], summary="List latest security events")
async def list_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    category: Optional[str] = None,
    severity: Optional[str] = None,
    device_id: Optional[UUID] = None,
    current_user: User = Depends(require_permission("security_events.read")),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[SecurityEventResponse]:
    params = EventSearchRequest(
        page=page,
        page_size=page_size,
        event_category=category,
        severity=severity,
        device_id=device_id,
    )
    events, total = await EventService.search_events(db, params)
    pages = math.ceil(total / page_size) if total > 0 else 1
    return PaginatedResponse(
        items=events,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/export", summary="Export security events CSV")
async def export_events(
    category: Optional[str] = None,
    severity: Optional[str] = None,
    current_user: User = Depends(require_permission("security_events.read")),
    db: AsyncSession = Depends(get_db),
):
    import io
    import csv
    from fastapi.responses import StreamingResponse
    params = EventSearchRequest(
        event_category=category,
        severity=severity,
        page=1,
        page_size=500,
    )
    events, _ = await EventService.search_events(db, params)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Severity", "Category", "Event Type", "Source IP", "Process", "Description"])
    for e in events:
        writer.writerow([
            e.event_timestamp.isoformat() if hasattr(e, "event_timestamp") else "",
            getattr(e, "severity", ""),
            getattr(e, "event_category", ""),
            getattr(e, "event_type", ""),
            getattr(e, "source_ip", ""),
            getattr(e, "process_name", ""),
            getattr(e, "event_description", ""),
        ])
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=security_events.csv"},
    )


@router.get("/{event_id}", response_model=SecurityEventResponse, summary="Get event details")
async def get_event(
    event_id: UUID,
    current_user: User = Depends(require_permission("security_events.read")),
    db: AsyncSession = Depends(get_db),
) -> SecurityEvent:
    stmt = select(SecurityEvent).where(SecurityEvent.id == event_id)
    res = await db.execute(stmt)
    event = res.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return event
