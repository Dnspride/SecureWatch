"""
Pydantic schemas for security events.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class SecurityEventIngestItem(BaseModel):
    event_timestamp: datetime
    event_source: str = Field(..., max_length=64)  # windows_event_log, linux_auth, process_monitor, etc.
    event_category: str = Field(..., max_length=64)  # authentication, process, network, fim, system
    event_type: str = Field(..., max_length=128)
    severity: str = Field(..., max_length=32)  # informational, low, medium, high, critical
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_process_id: Optional[int] = None
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    service_name: Optional[str] = None
    event_description: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    user_id: Optional[UUID] = None
    username: Optional[str] = None


class SecurityEventBatchIngestRequest(BaseModel):
    events: List[SecurityEventIngestItem] = Field(..., max_length=500)


class SecurityEventBatchIngestResponse(BaseModel):
    accepted: int
    rejected: int
    alerts_triggered: int
    errors: List[str] = Field(default_factory=list)


class SecurityEventResponse(BaseModel):
    id: UUID
    event_id: Optional[str] = None
    device_id: Optional[UUID] = None
    hostname: Optional[str] = None
    user_id: Optional[UUID] = None
    username: Optional[str] = None
    event_timestamp: datetime
    event_source: str
    event_category: str
    event_type: str
    severity: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    event_description: Optional[str] = None
    is_alert_generated: bool = False
    raw_event_ref: Optional[str] = None

    model_config = {"from_attributes": True}


class EventSearchRequest(BaseModel):
    query: Optional[str] = None
    device_id: Optional[UUID] = None
    event_category: Optional[str] = None
    severity: Optional[str] = None
    event_source: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    page: int = Field(1, ge=1)
    page_size: int = Field(50, ge=1, le=500)
