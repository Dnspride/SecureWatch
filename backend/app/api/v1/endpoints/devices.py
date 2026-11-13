"""
Device Management API Endpoints: Enrollment tokens, agent registration, approvals, revocation, and heartbeats.
"""
from __future__ import annotations

import math
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import decode_device_token
from app.models.devices import Device, DeviceStatus
from app.models.users import User
from app.schemas.common import MessageResponse, PaginatedResponse
from app.schemas.devices import (
    DeviceActionRequest,
    DeviceEnrollRequest,
    DeviceEnrollResponse,
    DeviceHeartbeatRequest,
    DeviceHeartbeatResponse,
    DeviceResponse,
    EnrollmentTokenCreate,
    EnrollmentTokenResponse,
)
from app.schemas.events import SecurityEventResponse
from app.services.auth_service import require_permission
from app.services.device_service import DeviceService

router = APIRouter(prefix="/devices", tags=["Endpoint Device Management"])


@router.post("/enrollment-token", response_model=EnrollmentTokenResponse, summary="Generate device enrollment token")
async def generate_token(
    data: EnrollmentTokenCreate,
    current_user: User = Depends(require_permission("devices.register")),
    db: AsyncSession = Depends(get_db),
) -> EnrollmentTokenResponse:
    token_record, plain_token = await DeviceService.create_enrollment_token(db, data, actor=current_user)
    return EnrollmentTokenResponse(
        id=token_record.id,
        token=plain_token,
        created_at=token_record.created_at,
        expires_at=token_record.expires_at,
        requires_approval=token_record.requires_approval,
        is_used=token_record.is_used,
        enrollment_command=f"python main.py --enroll --server-url http://localhost:8000 --token {plain_token}",
    )


@router.get("/download-agent", summary="Download SecureWatch endpoint agent package")
@router.get("/package", summary="Download SecureWatch endpoint agent package (alias)")
async def download_agent_package(
    format: str = Query("tar.gz", description="Package format: tar.gz or zip")
):
    from pathlib import Path
    from fastapi.responses import FileResponse
    
    ext = "zip" if format.lower() == "zip" else "tar.gz"
    filename = f"securewatch-agent.{ext}"
    
    candidates = [
        Path("/app/app/static") / filename,
        Path(__file__).resolve().parent.parent.parent / "static" / filename,
    ]
    for p in candidates:
        if p.exists():
            media = "application/zip" if ext == "zip" else "application/gzip"
            return FileResponse(
                path=str(p),
                filename=filename,
                media_type=media,
            )
            
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent package not found")


@router.post("/enroll", response_model=DeviceEnrollResponse, summary="Enroll new endpoint agent")
async def enroll_device(
    request: Request,
    data: DeviceEnrollRequest,
    db: AsyncSession = Depends(get_db),
) -> DeviceEnrollResponse:
    """Agent calls this endpoint with the enrollment token to register itself."""
    client_ip = request.client.host if request.client else None
    return await DeviceService.enroll_device(db, data, client_ip=client_ip)


@router.post("/heartbeat", response_model=DeviceHeartbeatResponse, summary="Agent heartbeat telemetry")
async def record_heartbeat(
    request: Request,
    data: DeviceHeartbeatRequest,
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
) -> DeviceHeartbeatResponse:
    """Agent calls this endpoint periodically to signal health and posture."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Device credentials required")

    raw_token = authorization.split(" ", 1)[1]
    claims = decode_device_token(raw_token)
    if not claims or "sub" not in claims:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device credential")

    try:
        device_id = UUID(claims["sub"])
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid device ID format")

    client_ip = request.client.host if request.client else None
    return await DeviceService.process_heartbeat(db, device_id, data, client_ip=client_ip)


@router.get("", response_model=PaginatedResponse[DeviceResponse], summary="List enrolled endpoint devices")
async def list_devices(
    status_filter: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    department: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(require_permission("devices.read")),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[DeviceResponse]:
    effective_status = status_filter or status
    devices, total = await DeviceService.get_devices(
        db,
        status_filter=effective_status,
        search=search,
        department=department,
        page=page,
        page_size=page_size,
    )
    pages = math.ceil(total / page_size) if total > 0 else 1
    items = [
        DeviceResponse(
            id=d.id,
            hostname=d.hostname,
            os_name=d.os_name,
            os_version=d.os_version,
            os_arch=d.os_arch,
            device_owner_id=d.device_owner_id,
            device_owner_name=d.owner.full_name if d.owner else None,
            department=d.department,
            private_ip=d.private_ip,
            public_ip=d.public_ip,
            mac_address=d.mac_address,
            agent_version=d.agent_version,
            enrollment_date=d.enrollment_date,
            last_heartbeat=d.last_heartbeat,
            status=d.status,
            security_status=d.security_status,
            risk_score=d.risk_score,
        )
        for d in devices
    ]
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.get("/{device_id}", response_model=DeviceResponse, summary="Get device detail")
async def get_device(
    device_id: UUID,
    current_user: User = Depends(require_permission("devices.read")),
    db: AsyncSession = Depends(get_db),
) -> DeviceResponse:
    d = await DeviceService.get_by_id(db, device_id)
    if not d:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return DeviceResponse(
        id=d.id,
        hostname=d.hostname,
        os_name=d.os_name,
        os_version=d.os_version,
        os_arch=d.os_arch,
        device_owner_id=d.device_owner_id,
        device_owner_name=d.owner.full_name if d.owner else None,
        department=d.department,
        private_ip=d.private_ip,
        public_ip=d.public_ip,
        mac_address=d.mac_address,
        agent_version=d.agent_version,
        enrollment_date=d.enrollment_date,
        last_heartbeat=d.last_heartbeat,
        status=d.status,
        security_status=d.security_status,
        risk_score=d.risk_score,
    )


@router.post("/{device_id}/approve", response_model=DeviceResponse, summary="Approve pending device enrollment")
async def approve_device(
    device_id: UUID,
    current_user: User = Depends(require_permission("devices.register")),
    db: AsyncSession = Depends(get_db),
) -> DeviceResponse:
    await DeviceService.approve_device(db, device_id, actor=current_user)
    d = await DeviceService.get_by_id(db, device_id)
    if not d:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return DeviceResponse(
        id=d.id,
        hostname=d.hostname,
        os_name=d.os_name,
        os_version=d.os_version,
        os_arch=d.os_arch,
        device_owner_id=d.device_owner_id,
        device_owner_name=d.owner.full_name if d.owner else None,
        department=d.department,
        private_ip=d.private_ip,
        public_ip=d.public_ip,
        mac_address=d.mac_address,
        agent_version=d.agent_version,
        enrollment_date=d.enrollment_date,
        last_heartbeat=d.last_heartbeat,
        status=d.status,
        security_status=d.security_status,
        risk_score=d.risk_score,
    )


@router.post("/{device_id}/revoke", response_model=DeviceResponse, summary="Revoke device credentials & quarantine")
async def revoke_device(
    device_id: UUID,
    data: DeviceActionRequest,
    current_user: User = Depends(require_permission("devices.revoke")),
    db: AsyncSession = Depends(get_db),
) -> DeviceResponse:
    await DeviceService.revoke_device(db, device_id, reason=data.reason, actor=current_user)
    d = await DeviceService.get_by_id(db, device_id)
    if not d:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return DeviceResponse(
        id=d.id,
        hostname=d.hostname,
        os_name=d.os_name,
        os_version=d.os_version,
        os_arch=d.os_arch,
        device_owner_id=d.device_owner_id,
        device_owner_name=d.owner.full_name if d.owner else None,
        department=d.department,
        private_ip=d.private_ip,
        public_ip=d.public_ip,
        mac_address=d.mac_address,
        agent_version=d.agent_version,
        enrollment_date=d.enrollment_date,
        last_heartbeat=d.last_heartbeat,
        status=d.status,
        security_status=d.security_status,
        risk_score=d.risk_score,
    )


@router.post("/{device_id}/rotate-credentials", response_model=DeviceResponse, summary="Rotate device credentials")
async def rotate_credentials(
    device_id: UUID,
    data: Optional[DeviceActionRequest] = None,
    current_user: User = Depends(require_permission("devices.register")),
    db: AsyncSession = Depends(get_db),
) -> DeviceResponse:
    d = await DeviceService.get_by_id(db, device_id)
    if not d:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    d = await DeviceService.rotate_credentials(db, device_id, reason=data.reason if data else "Administrative rotation", actor=current_user)
    return DeviceResponse(
        id=d.id,
        hostname=d.hostname,
        os_name=d.os_name,
        os_version=d.os_version,
        os_arch=d.os_arch,
        device_owner_id=d.device_owner_id,
        device_owner_name=d.owner.full_name if d.owner else None,
        department=d.department,
        private_ip=d.private_ip,
        public_ip=d.public_ip,
        mac_address=d.mac_address,
        agent_version=d.agent_version,
        enrollment_date=d.enrollment_date,
        last_heartbeat=d.last_heartbeat,
        status=d.status,
        security_status=d.security_status,
        risk_score=d.risk_score,
    )


@router.delete("/{device_id}", response_model=MessageResponse, summary="Delete device record")
async def delete_device(
    device_id: UUID,
    current_user: User = Depends(require_permission("devices.revoke")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    d = await DeviceService.get_by_id(db, device_id)
    if not d:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    await db.delete(d)
    await db.commit()
    return MessageResponse(message="Device record deleted successfully")


@router.get("/{device_id}/events", response_model=PaginatedResponse[SecurityEventResponse], summary="List events for device")
async def get_device_events(
    device_id: UUID,
    category: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: User = Depends(require_permission("security_events.read")),
    db: AsyncSession = Depends(get_db),
):
    from app.services.event_service import EventService
    from app.schemas.events import EventSearchRequest
    params = EventSearchRequest(
        device_id=device_id,
        event_category=category,
        page=page,
        page_size=page_size,
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
