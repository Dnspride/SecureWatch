"""
Role Management API Endpoints: RBAC roles, permission assignments, and role audits.
"""
from __future__ import annotations

from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.roles import Role
from app.models.users import User
from app.schemas.common import MessageResponse
from app.schemas.roles import RoleCreate, RoleResponse, RoleUpdate
from app.services.auth_service import require_permission
from app.services.rbac_service import RBACService

router = APIRouter(prefix="/roles", tags=["RBAC Roles"])


@router.get("", response_model=List[RoleResponse], summary="List all roles")
async def list_roles(
    current_user: User = Depends(require_permission("roles.manage")),
    db: AsyncSession = Depends(get_db),
) -> List[Role]:
    return await RBACService.get_roles(db)


@router.post("", response_model=RoleResponse, status_code=status.HTTP_201_CREATED, summary="Create custom role")
async def create_role(
    data: RoleCreate,
    current_user: User = Depends(require_permission("roles.manage")),
    db: AsyncSession = Depends(get_db),
) -> Role:
    return await RBACService.create_role(db, data)


@router.get("/{role_id}", response_model=RoleResponse, summary="Get role details")
async def get_role(
    role_id: UUID,
    current_user: User = Depends(require_permission("roles.manage")),
    db: AsyncSession = Depends(get_db),
) -> Role:
    role = await RBACService.get_role_by_id(db, role_id)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    return role


@router.put("/{role_id}", response_model=RoleResponse, summary="Update role permissions")
async def update_role(
    role_id: UUID,
    data: RoleUpdate,
    current_user: User = Depends(require_permission("roles.manage")),
    db: AsyncSession = Depends(get_db),
) -> Role:
    role = await RBACService.get_role_by_id(db, role_id)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    return await RBACService.update_role(db, role, data)


@router.delete("/{role_id}", response_model=MessageResponse, summary="Delete custom role")
async def delete_role(
    role_id: UUID,
    current_user: User = Depends(require_permission("roles.manage")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    role = await RBACService.get_role_by_id(db, role_id)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    try:
        await RBACService.delete_role(db, role)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return MessageResponse(message="Role deleted successfully")
