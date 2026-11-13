"""
Pydantic schemas for security alerts and investigation notes.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.alerts import AlertSeverity, AlertStatus


class AlertNoteCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=5000)


class AlertNoteResponse(BaseModel):
    id: UUID
    alert_id: UUID
    author_id: Optional[UUID] = None
    author_name: Optional[str] = None
    content: str
    created_at: datetime

    model_config = {"from_attributes": True}


class AlertStatusUpdateRequest(BaseModel):
    status: AlertStatus
    resolution_notes: Optional[str] = None


class AlertAssignRequest(BaseModel):
    assigned_to: Optional[UUID] = None
    user_id: Optional[UUID] = None


class AlertUpdateRequest(BaseModel):
    status: Optional[AlertStatus] = None
    assigned_to: Optional[UUID] = None
    user_id: Optional[UUID] = None
    resolution_notes: Optional[str] = None


class AlertResponse(BaseModel):
    id: UUID
    title: str
    description: Optional[str] = None
    severity: AlertSeverity
    status: AlertStatus
    detection_time: datetime
    device_id: Optional[UUID] = None
    device_name: Optional[str] = None
    user_id: Optional[UUID] = None
    user_name: Optional[str] = None
    source_event_id: Optional[UUID] = None
    detection_rule_id: Optional[UUID] = None
    detection_rule_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    risk_score: float = 0.0
    assigned_to: Optional[UUID] = None
    assigned_to_name: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolution_notes: Optional[str] = None
    notes_count: int = 0

    model_config = {"from_attributes": True}


class AlertDetailResponse(AlertResponse):
    notes: List[AlertNoteResponse] = Field(default_factory=list)
    recommended_steps: List[str] = Field(default_factory=list)
