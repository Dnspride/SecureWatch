"""
Group Management API Endpoints: Organizational groups, membership, and group role mapping.
"""
from __future__ import annotations

from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.groups import Group
from app.models.users import User
from app.schemas.common import MessageResponse
from app.schemas.groups import (
    GroupCreate,
    GroupDetailResponse,
    GroupMemberAdd,
    GroupResponse,
    GroupRoleAssign,
    GroupUpdate,
)
from app.services.auth_service import require_permission
from app.services.group_service import GroupService

router = APIRouter(prefix="/groups", tags=["Group Management"])


@router.get("", response_model=List[GroupResponse], summary="List all groups")
async def list_groups(
    current_user: User = Depends(require_permission("groups.manage")),
    db: AsyncSession = Depends(get_db),
) -> List[GroupResponse]:
    groups = await GroupService.get_groups(db)
    return [
        GroupResponse(
            id=g.id,
            name=g.name,
            description=g.description,
            department=g.department,
            created_at=g.created_at,
            member_count=len(g.members) if g.members else 0,
            role_count=len(g.group_roles) if g.group_roles else 0,
        )
        for g in groups
    ]


@router.post("", response_model=GroupResponse, status_code=status.HTTP_201_CREATED, summary="Create group")
async def create_group(
    data: GroupCreate,
    current_user: User = Depends(require_permission("groups.manage")),
    db: AsyncSession = Depends(get_db),
) -> Group:
    return await GroupService.create_group(db, data, actor=current_user)


@router.get("/{group_id}", response_model=GroupDetailResponse, summary="Get group details")
async def get_group(
    group_id: UUID,
    current_user: User = Depends(require_permission("groups.manage")),
    db: AsyncSession = Depends(get_db),
) -> GroupDetailResponse:
    group = await GroupService.get_by_id(db, group_id)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")

    members = [
        {
            "id": m.user.id,
            "username": m.user.username,
            "email": m.user.email,
            "full_name": m.user.full_name,
            "department": m.user.department,
        }
        for m in group.members
        if m.user
    ]

    roles = [
        {
            "id": r.role.id,
            "name": r.role.name,
            "description": r.role.description,
        }
        for r in group.group_roles
        if r.role
    ]

    return GroupDetailResponse(
        id=group.id,
        name=group.name,
        description=group.description,
        department=group.department,
        created_at=group.created_at,
        member_count=len(members),
        role_count=len(roles),
        members=members,
        roles=roles,
    )


@router.put("/{group_id}", response_model=GroupResponse, summary="Update group")
async def update_group(
    group_id: UUID,
    data: GroupUpdate,
    current_user: User = Depends(require_permission("groups.manage")),
    db: AsyncSession = Depends(get_db),
) -> Group:
    group = await GroupService.get_by_id(db, group_id)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    return await GroupService.update_group(db, group, data, actor=current_user)


@router.delete("/{group_id}", response_model=MessageResponse, summary="Delete group")
async def delete_group(
    group_id: UUID,
    current_user: User = Depends(require_permission("groups.manage")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    group = await GroupService.get_by_id(db, group_id)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    await GroupService.delete_group(db, group, actor=current_user)
    return MessageResponse(message="Group deleted successfully")


@router.post("/{group_id}/members", response_model=MessageResponse, summary="Add user to group")
async def add_member(
    group_id: UUID,
    payload: GroupMemberAdd,
    current_user: User = Depends(require_permission("groups.manage")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    group = await GroupService.get_by_id(db, group_id)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    await GroupService.add_member(db, group, payload.user_id, actor=current_user)
    return MessageResponse(message="User added to group successfully")


@router.delete("/{group_id}/members/{user_id}", response_model=MessageResponse, summary="Remove user from group")
async def remove_member(
    group_id: UUID,
    user_id: UUID,
    current_user: User = Depends(require_permission("groups.manage")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    group = await GroupService.get_by_id(db, group_id)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    await GroupService.remove_member(db, group, user_id, actor=current_user)
    return MessageResponse(message="User removed from group successfully")


@router.post("/{group_id}/roles", response_model=MessageResponse, summary="Assign role to group")
async def assign_role(
    group_id: UUID,
    payload: GroupRoleAssign,
    current_user: User = Depends(require_permission("groups.manage")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    group = await GroupService.get_by_id(db, group_id)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    await GroupService.assign_role(db, group, payload.role_id, actor=current_user)
    return MessageResponse(message="Role assigned to group successfully")


@router.delete("/{group_id}/roles/{role_id}", response_model=MessageResponse, summary="Remove role from group")
async def remove_role(
    group_id: UUID,
    role_id: UUID,
    current_user: User = Depends(require_permission("groups.manage")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    group = await GroupService.get_by_id(db, group_id)
    if not group:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Group not found")
    await GroupService.remove_role(db, group, role_id, actor=current_user)
    return MessageResponse(message="Role removed from group successfully")
