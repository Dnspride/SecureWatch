"""
Audit Logs API Endpoints: Cryptographically chained immutable audit records.
"""
from __future__ import annotations

import math
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.audit_logs import AuditLog
from app.models.users import User
from app.schemas.audit import AuditLogResponse
from app.schemas.common import MessageResponse, PaginatedResponse
from app.services.audit_service import AuditService
from app.services.auth_service import require_permission

router = APIRouter(prefix="/audit-logs", tags=["Audit Logging"])


@router.get("", response_model=PaginatedResponse[AuditLogResponse], summary="List immutable audit records")
async def list_audit_logs(
    actor_username: Optional[str] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: User = Depends(require_permission("audit_logs.read")),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[AuditLogResponse]:
    query = select(AuditLog)

    if actor_username:
        query = query.where(AuditLog.actor_username.ilike(f"%{actor_username}%"))
    if action:
        query = query.where(AuditLog.action == action)
    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)

    count_stmt = select(func.count()).select_from(query.subquery())
    count_res = await db.execute(count_stmt)
    total = count_res.scalar_one()

    query = query.order_by(desc(AuditLog.timestamp)).offset((page - 1) * page_size).limit(page_size)
    res = await db.execute(query)
    records = list(res.scalars().all())

    pages = math.ceil(total / page_size) if total > 0 else 1
    return PaginatedResponse(
        items=records,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/export", summary="Export audit logs CSV")
async def export_audit_logs(
    action: Optional[str] = None,
    current_user: User = Depends(require_permission("audit_logs.read")),
    db: AsyncSession = Depends(get_db),
):
    import io
    import csv
    from fastapi.responses import StreamingResponse
    stmt = select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(1000)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    res = await db.execute(stmt)
    records = list(res.scalars().all())
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Actor", "Action", "Resource Type", "Resource ID", "Result", "Hash"])
    for r in records:
        writer.writerow([r.timestamp.isoformat(), r.actor_username or "System", r.action, r.resource_type, r.resource_id or "", r.result, r.hash])
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_logs.csv"},
    )


@router.post("/verify-integrity", response_model=MessageResponse, summary="Verify SHA-256 hash chain integrity")
async def verify_chain(
    limit: int = Query(1000, ge=10, le=10000),
    current_user: User = Depends(require_permission("audit_logs.read")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    is_valid = await AuditService.verify_chain_integrity(db, limit=limit)
    if is_valid:
        return MessageResponse(message=f"Audit chain integrity verified across last {limit} records: NO tampering detected.")
    return MessageResponse(
        message="CRITICAL: Audit log hash chain mismatch detected! Tampering suspected.",
        success=False,
    )
