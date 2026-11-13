"""
Pydantic schemas for user management endpoints.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.schemas.roles import RoleResponse


class UserCreate(BaseModel):
    """Payload for creating a new user."""

    username: str = Field(..., min_length=3, max_length=64)
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=255)
    department: Optional[str] = Field(None, max_length=128)
    password: str = Field(..., min_length=12)
    is_active: bool = True
    is_superuser: bool = False
    role_ids: Optional[List[UUID]] = None


class UserUpdate(BaseModel):
    """Payload for updating an existing user (all fields optional)."""

    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(None, min_length=1, max_length=255)
    department: Optional[str] = Field(None, max_length=128)
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None
    role_ids: Optional[List[UUID]] = None


class PasswordChangeRequest(BaseModel):
    """Self-service password change."""

    current_password: str
    new_password: str = Field(..., min_length=12)


class UserResponse(BaseModel):
    """Public user representation returned by the API."""

    id: UUID
    username: str
    email: str
    full_name: str
    department: Optional[str]
    is_active: bool
    is_superuser: bool
    is_locked: bool
    mfa_enabled: bool
    created_at: datetime
    updated_at: datetime
    last_login_at: Optional[datetime]
    roles: List[RoleResponse] = []

    model_config = {"from_attributes": True}


class UserListResponse(BaseModel):
    """Minimal user record for list views."""

    id: UUID
    username: str
    email: str
    full_name: str
    department: Optional[str]
    is_active: bool
    is_locked: bool
    mfa_enabled: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class LoginHistoryResponse(BaseModel):
    """Single login history record."""

    id: UUID
    timestamp: datetime
    ip_address: Optional[str]
    user_agent: Optional[str]
    success: bool
    failure_reason: Optional[str]
    mfa_used: bool

    model_config = {"from_attributes": True}


class SessionResponse(BaseModel):
    """Active session information."""

    id: UUID
    ip_address: Optional[str]
    device_info: Optional[str]
    created_at: datetime
    expires_at: datetime
    last_activity: datetime

    model_config = {"from_attributes": True}
