"""
Pydantic schemas for immutable audit logs.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

from pydantic import BaseModel


class AuditLogResponse(BaseModel):
    id: UUID
    timestamp: datetime
    actor_id: Optional[UUID] = None
    actor_username: Optional[str] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    source_ip: Optional[str] = None
    result: str
    old_value: Optional[Dict[str, Any]] = None
    new_value: Optional[Dict[str, Any]] = None
    hash: str

    model_config = {"from_attributes": True}


class AuditLogFilter(BaseModel):
    actor_username: Optional[str] = None
    action: Optional[str] = None
    resource_type: Optional[str] = None
    result: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    page: int = 1
    page_size: int = 50
