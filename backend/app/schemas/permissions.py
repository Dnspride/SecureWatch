"""
Pydantic schemas for RBAC permissions.
"""
from __future__ import annotations

from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class PermissionResponse(BaseModel):
    id: UUID
    code: str
    name: str
    description: Optional[str] = None
    category: str

    model_config = {"from_attributes": True}


class PermissionGroupedByCategory(BaseModel):
    category: str
    permissions: List[PermissionResponse]
