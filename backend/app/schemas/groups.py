"""
Pydantic schemas for organizational groups.
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class GroupBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    description: Optional[str] = Field(None, max_length=512)
    department: Optional[str] = Field(None, max_length=128)


class GroupCreate(GroupBase):
    pass


class GroupUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=128)
    description: Optional[str] = Field(None, max_length=512)
    department: Optional[str] = Field(None, max_length=128)


class GroupMemberAdd(BaseModel):
    user_id: UUID


class GroupRoleAssign(BaseModel):
    role_id: UUID


class GroupUserSummary(BaseModel):
    id: UUID
    username: str
    email: str
    full_name: str
    department: Optional[str] = None

    model_config = {"from_attributes": True}


class GroupRoleSummary(BaseModel):
    id: UUID
    name: str
    description: Optional[str] = None

    model_config = {"from_attributes": True}


class GroupResponse(GroupBase):
    id: UUID
    created_at: datetime
    member_count: int = 0
    role_count: int = 0

    model_config = {"from_attributes": True}


class GroupDetailResponse(GroupResponse):
    members: List[GroupUserSummary] = Field(default_factory=list)
    roles: List[GroupRoleSummary] = Field(default_factory=list)
