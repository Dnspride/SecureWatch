"""
User Management API Endpoints: CRUD, password changes, account lock/unlock, and login history.
"""
from __future__ import annotations

import math
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.users import User
from app.schemas.common import MessageResponse, PaginatedResponse
from app.schemas.users import (
    LoginHistoryResponse,
    PasswordChangeRequest,
    UserCreate,
    UserResponse,
    UserUpdate,
)
from app.core.security import hash_password, validate_password_strength
from app.models.sessions import UserSession
from app.services.audit_service import AuditService
from pydantic import BaseModel, Field


class AdminPasswordReset(BaseModel):
    new_password: str = Field(..., min_length=12)
from app.services.auth_service import get_current_user, require_permission
from app.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["User Management"])


@router.get("", response_model=PaginatedResponse[UserResponse], summary="List users")
async def list_users(
    search: Optional[str] = None,
    department: Optional[str] = None,
    is_active: Optional[bool] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(require_permission("users.read")),
    db: AsyncSession = Depends(get_db),
) -> PaginatedResponse[UserResponse]:
    """Retrieve paginated list of system users."""
    users, total = await UserService.get_users(
        db,
        search=search,
        department=department,
        is_active=is_active,
        page=page,
        page_size=page_size,
    )
    pages = math.ceil(total / page_size) if total > 0 else 1
    return PaginatedResponse(
        items=users,
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
    )


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED, summary="Create user")
async def create_user(
    data: UserCreate,
    current_user: User = Depends(require_permission("users.create")),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Create a new user with Argon2id password and role assignment."""
    return await UserService.create_user(db, data, actor=current_user)


@router.get("/{user_id}", response_model=UserResponse, summary="Get user details")
async def get_user(
    user_id: UUID,
    current_user: User = Depends(require_permission("users.read")),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Get user profile by UUID."""
    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.put("/{user_id}", response_model=UserResponse, summary="Update user profile")
async def update_user(
    user_id: UUID,
    data: UserUpdate,
    current_user: User = Depends(require_permission("users.update")),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Update profile attributes or assigned roles."""
    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return await UserService.update_user(db, user, data, actor=current_user)


@router.delete("/{user_id}", response_model=MessageResponse, summary="Delete user")
async def delete_user(
    user_id: UUID,
    current_user: User = Depends(require_permission("users.delete")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Deactivate and delete user, terminating all active sessions."""
    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    await UserService.delete_user(db, user, actor=current_user)
    return MessageResponse(message="User deleted successfully")


@router.post("/me/password", response_model=MessageResponse, summary="Change current user password")
async def change_own_password(
    data: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Self-service password update requiring current password."""
    await UserService.change_password(db, current_user, data)
    return MessageResponse(message="Password updated successfully")


@router.post("/{user_id}/lock", response_model=UserResponse, summary="Lock user account")
async def lock_user(
    user_id: UUID,
    current_user: User = Depends(require_permission("users.update")),
    db: AsyncSession = Depends(get_db),
) -> User:
    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return await UserService.lock_user(db, user, actor=current_user)


@router.post("/{user_id}/unlock", response_model=UserResponse, summary="Unlock user account")
async def unlock_user(
    user_id: UUID,
    current_user: User = Depends(require_permission("users.update")),
    db: AsyncSession = Depends(get_db),
) -> User:
    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return await UserService.unlock_user(db, user, actor=current_user)


@router.get("/{user_id}/login-history", response_model=List[LoginHistoryResponse], summary="Get user login history")
async def get_login_history(
    user_id: UUID,
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(require_permission("users.read")),
    db: AsyncSession = Depends(get_db),
) -> List[LoginHistoryResponse]:
    return await UserService.get_login_history(db, user_id, limit=limit)


@router.post("/{user_id}/reset-password", response_model=MessageResponse, summary="Administrative password reset")
async def admin_reset_password(
    user_id: UUID,
    payload: AdminPasswordReset,
    current_user: User = Depends(require_permission("users.update")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    user = await UserService.get_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    errors = validate_password_strength(payload.new_password)
    if errors:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Weak password: {', '.join(errors)}")
    user.hashed_password = hash_password(payload.new_password)
    await AuditService.log_action(
        db,
        action="user.admin_reset_password",
        resource_type="user",
        resource_id=str(user.id),
        actor_id=current_user.id,
        actor_username=current_user.username,
    )
    await db.commit()
    return MessageResponse(message="Password reset successfully")


@router.get("/{user_id}/sessions", summary="Get active sessions for user")
async def get_user_sessions(
    user_id: UUID,
    current_user: User = Depends(require_permission("users.read")),
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy import select
    stmt = select(UserSession).where(UserSession.user_id == user_id, UserSession.is_revoked.is_(False))
    res = await db.execute(stmt)
    sessions = res.scalars().all()
    return {
        "sessions": [
            {
                "id": str(s.id),
                "ip": s.ip_address or "127.0.0.1",
                "created_at": s.created_at.isoformat() if s.created_at else "",
                "last_active": s.last_activity.isoformat() if s.last_activity else "",
            }
            for s in sessions
        ]
    }


@router.delete("/{user_id}/sessions/{session_id}", response_model=MessageResponse, summary="Revoke specific user session")
async def revoke_session(
    user_id: UUID,
    session_id: UUID,
    current_user: User = Depends(require_permission("users.update")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    from sqlalchemy import select
    stmt = select(UserSession).where(UserSession.id == session_id, UserSession.user_id == user_id)
    res = await db.execute(stmt)
    sess = res.scalar_one_or_none()
    if sess:
        sess.is_revoked = True
        await db.commit()
    return MessageResponse(message="Session revoked successfully")
