"""
Pydantic schemas for endpoint devices and enrollment.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.devices import DeviceStatus


class DeviceEnrollRequest(BaseModel):
    enrollment_token: str = Field(..., min_length=1)
    hostname: str = Field(..., min_length=1, max_length=255)
    os_name: str = Field(..., min_length=1, max_length=64)
    os_version: str = Field(..., min_length=1, max_length=64)
    os_arch: str = Field(..., min_length=1, max_length=32)
    private_ip: Optional[str] = None
    mac_address: Optional[str] = None
    agent_version: str = Field(..., min_length=1, max_length=32)
    system_metadata: Optional[Dict[str, Any]] = None


class DeviceEnrollResponse(BaseModel):
    device_id: UUID
    device_token: str
    server_time: datetime
    status: DeviceStatus
    heartbeat_interval: int = 60
    approved: bool


class DeviceHeartbeatRequest(BaseModel):
    agent_version: str
    status: Optional[str] = "online"
    security_status: Optional[str] = "healthy"
    cpu_percent: Optional[float] = None
    memory_percent: Optional[float] = None
    firewall_enabled: Optional[bool] = None
    antivirus_enabled: Optional[bool] = None
    disk_encrypted: Optional[bool] = None
    active_connections_count: Optional[int] = None
    running_processes_count: Optional[int] = None


class DeviceHeartbeatResponse(BaseModel):
    status: str = "ok"
    commands: List[Dict[str, Any]] = Field(default_factory=list)
    fim_paths: List[str] = Field(default_factory=list)


class EnrollmentTokenCreate(BaseModel):
    hours_valid: int = Field(24, ge=1, le=168)
    requires_approval: bool = False
    device_owner_id: Optional[UUID] = None
    department: Optional[str] = None


class EnrollmentTokenResponse(BaseModel):
    id: UUID
    token: str
    created_at: datetime
    expires_at: datetime
    requires_approval: bool
    is_used: bool
    enrollment_command: Optional[str] = None


class DeviceResponse(BaseModel):
    id: UUID
    hostname: str
    os_name: str
    os_version: str
    os_arch: str
    device_owner_id: Optional[UUID] = None
    device_owner_name: Optional[str] = None
    department: Optional[str] = None
    private_ip: Optional[str] = None
    public_ip: Optional[str] = None
    mac_address: Optional[str] = None
    agent_version: Optional[str] = None
    enrollment_date: Optional[datetime] = None
    last_heartbeat: Optional[datetime] = None
    status: DeviceStatus
    security_status: Optional[str] = None
    risk_score: float = 0.0

    model_config = {"from_attributes": True}


class DeviceActionRequest(BaseModel):
    reason: Optional[str] = None
