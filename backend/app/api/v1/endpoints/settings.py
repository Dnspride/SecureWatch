"""
Platform Settings API Endpoints: IAM policy thresholds, telemetry intervals, and retention configuration.
"""
from __future__ import annotations

from typing import Any, Dict
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.users import User
from app.services.auth_service import require_permission
from app.services.audit_service import AuditService

router = APIRouter(prefix="/settings", tags=["Platform Settings"])

# In-memory settings state with enterprise defaults
_PLATFORM_SETTINGS: Dict[str, Any] = {
    "account_lockout_threshold": 5,
    "lockout_duration_minutes": 15,
    "min_password_length": 12,
    "agent_heartbeat_interval_seconds": 60,
    "offline_inactivity_timeout_seconds": 300,
    "siem_event_retention_days": 90,
    "audit_log_retention_days": 365,
    "mfa_enforced_globally": False,
}


class PlatformSettingsSchema(BaseModel):
    account_lockout_threshold: int = Field(5, ge=1, le=20)
    lockout_duration_minutes: int = Field(15, ge=1, le=1440)
    min_password_length: int = Field(12, ge=8, le=64)
    agent_heartbeat_interval_seconds: int = Field(60, ge=10, le=600)
    offline_inactivity_timeout_seconds: int = Field(300, ge=60, le=3600)
    siem_event_retention_days: int = Field(90, ge=7, le=3650)
    audit_log_retention_days: int = Field(365, ge=30, le=3650)
    mfa_enforced_globally: bool = False


@router.get("", response_model=PlatformSettingsSchema, summary="Retrieve platform security settings")
async def get_settings(
    current_user: User = Depends(require_permission("settings.manage")),
    db: AsyncSession = Depends(get_db),
) -> PlatformSettingsSchema:
    return PlatformSettingsSchema(**_PLATFORM_SETTINGS)


@router.put("", response_model=PlatformSettingsSchema, summary="Update platform security settings")
async def update_settings(
    payload: PlatformSettingsSchema,
    current_user: User = Depends(require_permission("settings.manage")),
    db: AsyncSession = Depends(get_db),
) -> PlatformSettingsSchema:
    global _PLATFORM_SETTINGS
    old_val = dict(_PLATFORM_SETTINGS)
    _PLATFORM_SETTINGS.update(payload.model_dump())
    await AuditService.log_action(
        db,
        action="settings.update",
        resource_type="system_settings",
        resource_id="global",
        actor_id=current_user.id,
        actor_username=current_user.username,
        old_value=old_val,
        new_value=_PLATFORM_SETTINGS,
    )
    await db.commit()
    return PlatformSettingsSchema(**_PLATFORM_SETTINGS)
