"""
Pydantic schemas for RBAC roles.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class RoleBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=64)
    description: Optional[str] = Field(None, max_length=512)
    is_active: bool = True


class RoleCreate(RoleBase):
    permission_ids: List[UUID] = Field(default_factory=list)


class RoleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=64)
    description: Optional[str] = Field(None, max_length=512)
    is_active: Optional[bool] = None
    permission_ids: Optional[List[UUID]] = None


class PermissionSimple(BaseModel):
    id: UUID
    code: str
    name: str
    category: str

    model_config = {"from_attributes": True}


class RoleResponse(RoleBase):
    id: UUID
    is_system_role: bool
    created_at: datetime
    updated_at: datetime
    permissions: List[PermissionSimple] = Field(default_factory=list)
    user_count: Optional[int] = 0

    model_config = {"from_attributes": True}


class UserRoleAssignRequest(BaseModel):
    role_ids: List[UUID]
