"""
User Management Service: Full CRUD, password policies, account lock/unlock, and session termination.
"""
from __future__ import annotations

from typing import List, Optional, Tuple
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import delete, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
import structlog

from app.core.security import hash_password, validate_password_strength, verify_password
from app.models.login_history import LoginHistory
from app.models.roles import Role
from app.models.sessions import UserSession
from app.models.users import User
from app.schemas.users import PasswordChangeRequest, UserCreate, UserUpdate
from app.services.audit_service import AuditService

log = structlog.get_logger(__name__)


class UserService:
    @classmethod
    async def get_users(
        cls,
        db: AsyncSession,
        *,
        search: Optional[str] = None,
        department: Optional[str] = None,
        is_active: Optional[bool] = None,
        role_id: Optional[UUID] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> Tuple[List[User], int]:
        """Fetch paginated users with optional search and filters."""
        query = select(User).options(selectinload(User.roles).selectinload(Role.permissions))

        if search:
            search_filter = f"%{search.strip()}%"
            query = query.where(
                or_(
                    User.username.ilike(search_filter),
                    User.email.ilike(search_filter),
                    User.full_name.ilike(search_filter),
                )
            )
        if department:
            query = query.where(User.department == department)
        if is_active is not None:
            query = query.where(User.is_active.is_(is_active))
        if role_id:
            query = query.where(User.roles.any(Role.id == role_id))

        # Total count
        count_stmt = select(func.count()).select_from(query.subquery())
        count_res = await db.execute(count_stmt)
        total = count_res.scalar_one()

        # Paginated results
        query = query.order_by(User.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
        res = await db.execute(query)
        users = list(res.scalars().all())

        return users, total

    @classmethod
    async def get_by_id(cls, db: AsyncSession, user_id: UUID) -> Optional[User]:
        stmt = select(User).options(selectinload(User.roles).selectinload(Role.permissions)).where(User.id == user_id)
        res = await db.execute(stmt)
        return res.scalar_one_or_none()

    @classmethod
    async def get_by_username(cls, db: AsyncSession, username: str) -> Optional[User]:
        stmt = select(User).options(selectinload(User.roles).selectinload(Role.permissions)).where(User.username == username)
        res = await db.execute(stmt)
        return res.scalar_one_or_none()

    @classmethod
    async def create_user(
        cls,
        db: AsyncSession,
        data: UserCreate,
        actor: Optional[User] = None,
    ) -> User:
        """Create a new user, validate password, assign roles, and record audit log."""
        # Check duplicate username/email
        existing_stmt = select(User).where(
            or_(User.username == data.username, User.email == data.email)
        )
        res = await db.execute(existing_stmt)
        if res.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A user with that username or email already exists",
            )

        # Validate password policy
        strength_errors = validate_password_strength(data.password)
        if strength_errors:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Weak password: {', '.join(strength_errors)}",
            )

        user = User(
            username=data.username,
            email=data.email,
            full_name=data.full_name,
            department=data.department,
            hashed_password=hash_password(data.password),
            is_active=data.is_active,
            is_superuser=data.is_superuser,
        )

        # Assign roles
        if data.role_ids:
            role_stmt = select(Role).where(Role.id.in_(data.role_ids))
            roles_res = await db.execute(role_stmt)
            user.roles = list(roles_res.scalars().all())
        else:
            # Default to 'Standard User'
            std_role_stmt = select(Role).where(Role.name == "Standard User")
            std_res = await db.execute(std_role_stmt)
            std_role = std_res.scalar_one_or_none()
            if std_role:
                user.roles = [std_role]

        db.add(user)
        await db.flush()

        await AuditService.log_action(
            db,
            action="user.create",
            resource_type="user",
            resource_id=str(user.id),
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
            new_value={"username": user.username, "email": user.email, "department": user.department},
        )
        await db.commit()
        refreshed = await cls.get_by_id(db, user.id)
        return refreshed or user

    @classmethod
    async def update_user(
        cls,
        db: AsyncSession,
        user: User,
        data: UserUpdate,
        actor: Optional[User] = None,
    ) -> User:
        """Update user profile, status, or role assignments."""
        old_val = {
            "email": user.email,
            "full_name": user.full_name,
            "department": user.department,
            "is_active": user.is_active,
        }

        if data.email is not None and data.email != user.email:
            check_stmt = select(User).where(User.email == data.email, User.id != user.id)
            check_res = await db.execute(check_stmt)
            if check_res.scalar_one_or_none():
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Email already in use by another account",
                )
            user.email = data.email

        if data.full_name is not None:
            user.full_name = data.full_name
        if data.department is not None:
            user.department = data.department
        if data.is_active is not None:
            user.is_active = data.is_active
        if data.is_superuser is not None:
            user.is_superuser = data.is_superuser

        if data.role_ids is not None:
            role_stmt = select(Role).where(Role.id.in_(data.role_ids))
            roles_res = await db.execute(role_stmt)
            user.roles = list(roles_res.scalars().all())

        await db.flush()

        await AuditService.log_action(
            db,
            action="user.update",
            resource_type="user",
            resource_id=str(user.id),
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
            old_value=old_val,
            new_value={
                "email": user.email,
                "full_name": user.full_name,
                "department": user.department,
                "is_active": user.is_active,
            },
        )
        await db.commit()
        refreshed = await cls.get_by_id(db, user.id)
        return refreshed or user

    @classmethod
    async def change_password(
        cls,
        db: AsyncSession,
        user: User,
        data: PasswordChangeRequest,
    ) -> bool:
        """Self-service password change with current password verification."""
        if not verify_password(data.current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect",
            )

        errors = validate_password_strength(data.new_password)
        if errors:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Weak password: {', '.join(errors)}",
            )

        user.hashed_password = hash_password(data.new_password)
        await AuditService.log_action(
            db,
            action="user.change_password",
            resource_type="user",
            resource_id=str(user.id),
            actor_id=user.id,
            actor_username=user.username,
        )
        await db.commit()
        return True

    @classmethod
    async def lock_user(
        cls, db: AsyncSession, user: User, actor: Optional[User] = None
    ) -> User:
        """Manually lock user account."""
        user.is_locked = True
        await AuditService.log_action(
            db,
            action="user.lock",
            resource_type="user",
            resource_id=str(user.id),
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
        )
        await db.commit()
        refreshed = await cls.get_by_id(db, user.id)
        return refreshed or user

    @classmethod
    async def unlock_user(
        cls, db: AsyncSession, user: User, actor: Optional[User] = None
    ) -> User:
        """Unlock locked user account and reset failures."""
        user.is_locked = False
        user.failed_login_attempts = 0
        user.lockout_until = None
        await AuditService.log_action(
            db,
            action="user.unlock",
            resource_type="user",
            resource_id=str(user.id),
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
        )
        await db.commit()
        refreshed = await cls.get_by_id(db, user.id)
        return refreshed or user

    @classmethod
    async def delete_user(
        cls, db: AsyncSession, user: User, actor: Optional[User] = None
    ) -> bool:
        """Deactivate and delete user, terminating all active sessions."""
        if user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Superuser accounts cannot be deleted",
            )

        # Invalidate all user sessions
        sess_stmt = select(UserSession).where(UserSession.user_id == user.id)
        sess_res = await db.execute(sess_stmt)
        for s in sess_res.scalars().all():
            s.is_revoked = True

        from app.models.groups import GroupMember
        await db.execute(delete(GroupMember).where(GroupMember.user_id == user.id))

        username = user.username
        user_id_str = str(user.id)
        await db.delete(user)
        await AuditService.log_action(
            db,
            action="user.delete",
            resource_type="user",
            resource_id=user_id_str,
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
            old_value={"username": username},
        )
        await db.commit()
        return True

    @classmethod
    async def get_login_history(
        cls, db: AsyncSession, user_id: UUID, limit: int = 50
    ) -> List[LoginHistory]:
        stmt = (
            select(LoginHistory)
            .where(LoginHistory.user_id == user_id)
            .order_by(desc(LoginHistory.timestamp))
            .limit(limit)
        )
        res = await db.execute(stmt)
        return list(res.scalars().all())
