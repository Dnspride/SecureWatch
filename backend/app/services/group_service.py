"""
Group Service: Organizational groups, membership management, and group role mapping.
"""
from __future__ import annotations

from typing import List, Optional
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
import structlog

from app.models.groups import Group, GroupMember, GroupRole
from app.models.roles import Role
from app.models.users import User
from app.schemas.groups import GroupCreate, GroupUpdate
from app.services.audit_service import AuditService

log = structlog.get_logger(__name__)


class GroupService:
    @classmethod
    async def get_groups(cls, db: AsyncSession) -> List[Group]:
        stmt = (
            select(Group)
            .options(selectinload(Group.members), selectinload(Group.group_roles))
            .order_by(Group.name.asc())
        )
        res = await db.execute(stmt)
        return list(res.scalars().all())

    @classmethod
    async def get_by_id(cls, db: AsyncSession, group_id: UUID) -> Optional[Group]:
        stmt = (
            select(Group)
            .options(
                selectinload(Group.members).selectinload(GroupMember.user),
                selectinload(Group.group_roles).selectinload(GroupRole.role),
            )
            .where(Group.id == group_id)
        )
        res = await db.execute(stmt)
        return res.scalar_one_or_none()

    @classmethod
    async def create_group(
        cls, db: AsyncSession, data: GroupCreate, actor: Optional[User] = None
    ) -> Group:
        # Check duplicate name
        existing_stmt = select(Group).where(Group.name == data.name)
        res = await db.execute(existing_stmt)
        if res.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A group with that name already exists",
            )

        group = Group(
            name=data.name,
            description=data.description,
            department=data.department,
        )
        db.add(group)
        await db.flush()

        await AuditService.log_action(
            db,
            action="group.create",
            resource_type="group",
            resource_id=str(group.id),
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
            new_value={"name": group.name, "department": group.department},
        )
        await db.commit()
        refreshed = await cls.get_by_id(db, group.id)
        return refreshed or group

    @classmethod
    async def update_group(
        cls, db: AsyncSession, group: Group, data: GroupUpdate, actor: Optional[User] = None
    ) -> Group:
        if data.name is not None and data.name != group.name:
            existing_stmt = select(Group).where(Group.name == data.name, Group.id != group.id)
            res = await db.execute(existing_stmt)
            if res.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Group name already in use",
                )
            group.name = data.name

        if data.description is not None:
            group.description = data.description
        if data.department is not None:
            group.department = data.department

        await db.flush()
        await AuditService.log_action(
            db,
            action="group.update",
            resource_type="group",
            resource_id=str(group.id),
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
        )
        await db.commit()
        refreshed = await cls.get_by_id(db, group.id)
        return refreshed or group

    @classmethod
    async def delete_group(
        cls, db: AsyncSession, group: Group, actor: Optional[User] = None
    ) -> bool:
        group_id_str = str(group.id)
        name = group.name
        await db.execute(delete(GroupMember).where(GroupMember.group_id == group.id))
        await db.execute(delete(GroupRole).where(GroupRole.group_id == group.id))
        await db.delete(group)
        await AuditService.log_action(
            db,
            action="group.delete",
            resource_type="group",
            resource_id=group_id_str,
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
            old_value={"name": name},
        )
        await db.commit()
        return True

    @classmethod
    async def add_member(
        cls, db: AsyncSession, group: Group, user_id: UUID, actor: Optional[User] = None
    ) -> GroupMember:
        user_stmt = select(User).where(User.id == user_id)
        user_res = await db.execute(user_stmt)
        user = user_res.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        # Check existing membership
        check_stmt = select(GroupMember).where(
            GroupMember.group_id == group.id, GroupMember.user_id == user_id
        )
        check_res = await db.execute(check_stmt)
        if check_res.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="User is already a member of this group"
            )

        member = GroupMember(group_id=group.id, user_id=user_id)
        db.add(member)
        await db.flush()

        await AuditService.log_action(
            db,
            action="group.add_member",
            resource_type="group",
            resource_id=str(group.id),
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
            new_value={"user_id": str(user_id), "username": user.username},
        )
        await db.commit()
        return member

    @classmethod
    async def remove_member(
        cls, db: AsyncSession, group: Group, user_id: UUID, actor: Optional[User] = None
    ) -> bool:
        stmt = select(GroupMember).where(
            GroupMember.group_id == group.id, GroupMember.user_id == user_id
        )
        res = await db.execute(stmt)
        member = res.scalar_one_or_none()
        if not member:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Membership not found")

        await db.delete(member)
        await AuditService.log_action(
            db,
            action="group.remove_member",
            resource_type="group",
            resource_id=str(group.id),
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
            old_value={"user_id": str(user_id)},
        )
        await db.commit()
        return True

    @classmethod
    async def assign_role(
        cls, db: AsyncSession, group: Group, role_id: UUID, actor: Optional[User] = None
    ) -> GroupRole:
        role_stmt = select(Role).where(Role.id == role_id)
        role_res = await db.execute(role_stmt)
        role = role_res.scalar_one_or_none()
        if not role:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")

        check_stmt = select(GroupRole).where(
            GroupRole.group_id == group.id, GroupRole.role_id == role_id
        )
        check_res = await db.execute(check_stmt)
        if check_res.scalar_one_or_none():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Role already assigned to group")

        group_role = GroupRole(group_id=group.id, role_id=role_id)
        db.add(group_role)
        await db.flush()

        await AuditService.log_action(
            db,
            action="group.assign_role",
            resource_type="group",
            resource_id=str(group.id),
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
            new_value={"role_id": str(role_id), "role_name": role.name},
        )
        await db.commit()
        refreshed = await cls.get_by_id(db, group.id)
        return refreshed or group_role

    @classmethod
    async def remove_role(
        cls, db: AsyncSession, group: Group, role_id: UUID, actor: Optional[User] = None
    ) -> bool:
        stmt = select(GroupRole).where(
            GroupRole.group_id == group.id, GroupRole.role_id == role_id
        )
        res = await db.execute(stmt)
        gr = res.scalar_one_or_none()
        if not gr:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role assignment not found")

        await db.delete(gr)
        await AuditService.log_action(
            db,
            action="group.remove_role",
            resource_type="group",
            resource_id=str(group.id),
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
            old_value={"role_id": str(role_id)},
        )
        await db.commit()
        return True
