"""
Security Reports API Endpoints: Compliance, posture, and threat export generation.
"""
from __future__ import annotations

import io
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.users import User
from app.schemas.common import PaginatedResponse
from app.services.auth_service import require_permission

router = APIRouter(prefix="/reports", tags=["Security Reports"])


class ReportGenerateRequest(BaseModel):
    report_type: str
    parameters: Optional[Dict[str, Any]] = None


class ReportItem(BaseModel):
    id: str
    name: str
    report_type: str
    file_format: str = "pdf"
    status: str = "completed"
    created_at: str
    completed_at: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None


# In-memory store for generated report metadata in demo / runtime
_SAMPLE_REPORTS: List[Dict[str, Any]] = [
    {
        "id": "1",
        "name": "Executive Cybersecurity Posture Summary",
        "report_type": "security_summary",
        "file_format": "pdf",
        "status": "completed",
        "created_at": "2026-11-10T12:00:00Z",
        "completed_at": "2026-11-10T12:01:00Z",
    },
    {
        "id": "2",
        "name": "Endpoint Security & Host Compliance Audit",
        "report_type": "compliance",
        "file_format": "pdf",
        "status": "completed",
        "created_at": "2026-11-11T08:30:00Z",
        "completed_at": "2026-11-11T08:31:00Z",
    },
    {
        "id": "3",
        "name": "MITRE ATT&CK Threat Detection Coverage",
        "report_type": "alert_summary",
        "file_format": "pdf",
        "status": "completed",
        "created_at": "2026-11-11T09:00:00Z",
        "completed_at": "2026-11-11T09:01:00Z",
    },
]


@router.get("", response_model=PaginatedResponse[ReportItem], summary="List generated security reports")
async def list_reports(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(require_permission("reports.export")),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[ReportItem]:
    total = len(_SAMPLE_REPORTS)
    items = [ReportItem(**r) for r in _SAMPLE_REPORTS]
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=1,
    )


@router.get("/{report_id}", response_model=ReportItem, summary="Get report details")
async def get_report(
    report_id: str,
    current_user: User = Depends(require_permission("reports.export")),
    db: AsyncSession = Depends(get_db),
) -> ReportItem:
    for r in _SAMPLE_REPORTS:
        if r["id"] == report_id:
            return ReportItem(**r)
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")


@router.post("/generate", response_model=ReportItem, summary="Generate on-demand security report")
async def generate_report(
    payload: ReportGenerateRequest,
    current_user: User = Depends(require_permission("reports.export")),
    db: AsyncSession = Depends(get_db),
) -> ReportItem:
    now_iso = datetime.now(timezone.utc).isoformat()
    new_report = {
        "id": str(uuid.uuid4()),
        "name": f"SecureWatch {payload.report_type.replace('_', ' ').title()} Export",
        "report_type": payload.report_type,
        "file_format": "pdf",
        "status": "completed",
        "created_at": now_iso,
        "completed_at": now_iso,
        "parameters": payload.parameters,
    }
    _SAMPLE_REPORTS.insert(0, new_report)
    return ReportItem(**new_report)


@router.get("/{report_id}/download", summary="Download report document")
async def download_report(
    report_id: str,
    current_user: User = Depends(require_permission("reports.export")),
    db: AsyncSession = Depends(get_db),
):
    content = f"SecureWatch Security Report - ID: {report_id}\nGenerated: {datetime.now(timezone.utc).isoformat()}\nConfidential"
    buf = io.BytesIO(content.encode("utf-8"))
    return StreamingResponse(
        buf,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename=report_{report_id}.txt"},
    )


@router.delete("/{report_id}", summary="Delete generated report")
async def delete_report(
    report_id: str,
    current_user: User = Depends(require_permission("reports.export")),
    db: AsyncSession = Depends(get_db),
):
    global _SAMPLE_REPORTS
    _SAMPLE_REPORTS = [r for r in _SAMPLE_REPORTS if r["id"] != report_id]
    return {"message": "Report deleted successfully"}
