"""
Authentication Service: User login, session management, MFA (TOTP), lockout policy, and RBAC auth dependencies.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional, Set
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
import structlog

from app.core.config import settings
from app.core.database import get_db
from app.core.redis_client import redis_pool
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decrypt_mfa_secret,
    encrypt_mfa_secret,
    generate_totp_qr_base64,
    get_totp_uri,
    hash_password,
    hash_token,
    setup_totp,
    verify_password,
    verify_totp,
)
from app.models.login_history import LoginHistory
from app.models.sessions import UserSession
from app.models.users import User
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    MFASetupResponse,
    MFAVerifyRequest,
    TokenResponse,
)
from app.services.audit_service import AuditService
from app.services.rbac_service import RBACService

log = structlog.get_logger(__name__)
security_bearer = HTTPBearer(auto_error=False)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


class AuthService:
    @classmethod
    async def record_login_attempt(
        cls,
        db: AsyncSession,
        user: Optional[User],
        ip_address: Optional[str],
        user_agent: Optional[str],
        success: bool,
        failure_reason: Optional[str] = None,
        mfa_used: bool = False,
    ) -> None:
        """Write entry to login_history table."""
        history = LoginHistory(
            user_id=user.id if user else None,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            failure_reason=failure_reason,
            mfa_used=mfa_used,
        )
        db.add(history)
        await db.flush()

    @classmethod
    async def authenticate(
        cls,
        db: AsyncSession,
        credentials: LoginRequest,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> LoginResponse:
        """
        Authenticate user credentials, check lockout, handle MFA, and issue tokens.
        """
        stmt = (
            select(User)
            .options(selectinload(User.roles))
            .where(User.username == credentials.username)
        )
        res = await db.execute(stmt)
        user = res.scalar_one_or_none()

        now = datetime.now(timezone.utc)

        if not user:
            # Generic fail to prevent user enumeration
            await cls.record_login_attempt(
                db, None, client_ip, user_agent, False, failure_reason="User not found"
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
            )

        # Check account lockout
        if user.is_locked:
            if user.lockout_until and user.lockout_until > now:
                await cls.record_login_attempt(
                    db, user, client_ip, user_agent, False, failure_reason="Account locked"
                )
                await db.commit()
                minutes_left = int((user.lockout_until - now).total_seconds() / 60) + 1
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Account is temporarily locked due to failed attempts. Try again in {minutes_left} minutes.",
                )
            else:
                # Lockout period expired: auto-unlock
                user.is_locked = False
                user.failed_login_attempts = 0
                user.lockout_until = None

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account has been deactivated. Contact an administrator.",
            )

        # Verify password with Argon2id
        valid_password = verify_password(credentials.password, user.hashed_password)
        if not valid_password:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
                user.is_locked = True
                user.lockout_until = now + timedelta(minutes=LOCKOUT_MINUTES)
                await AuditService.log_action(
                    db,
                    action="user.lockout",
                    resource_type="user",
                    resource_id=str(user.id),
                    source_ip=client_ip,
                    result="locked",
                    new_value={"reason": "Excessive failed logins", "attempts": user.failed_login_attempts},
                )

            await cls.record_login_attempt(
                db, user, client_ip, user_agent, False, failure_reason="Invalid password"
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
            )

        # Check MFA
        if user.mfa_enabled:
            if not credentials.mfa_code:
                # Signal frontend that MFA code is required
                return LoginResponse(
                    mfa_required=True,
                    user_id=user.id,
                    username=user.username,
                )
            # Verify provided MFA code
            secret = decrypt_mfa_secret(user.mfa_secret)
            if not verify_totp(secret, credentials.mfa_code):
                await cls.record_login_attempt(
                    db, user, client_ip, user_agent, False, failure_reason="Invalid MFA code", mfa_used=True
                )
                await db.commit()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid two-factor authentication code",
                )

        # Reset failed attempts on successful login
        user.failed_login_attempts = 0
        user.lockout_until = None
        user.last_login_at = now

        # Create session and tokens
        tokens = await cls.create_session(db, user, client_ip, user_agent)

        await cls.record_login_attempt(
            db, user, client_ip, user_agent, True, mfa_used=user.mfa_enabled
        )
        await AuditService.log_action(
            db,
            action="user.login",
            resource_type="user",
            resource_id=str(user.id),
            actor_id=user.id,
            actor_username=user.username,
            source_ip=client_ip,
            result="success",
        )
        await db.commit()

        return LoginResponse(
            tokens=tokens,
            mfa_required=False,
            user_id=user.id,
            username=user.username,
        )

    @classmethod
    async def create_session(
        cls,
        db: AsyncSession,
        user: User,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> TokenResponse:
        """Issue access + refresh token and persist user session."""
        perms = await RBACService.get_user_permissions(db, user.id)

        access_token = create_access_token(
            subject=str(user.id),
            extra_claims={
                "username": user.username,
                "email": user.email,
                "is_superuser": user.is_superuser,
                "permissions": list(perms),
            },
        )
        refresh_token = create_refresh_token()
        refresh_hash = hash_token(refresh_token)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        session = UserSession(
            user_id=user.id,
            refresh_token_hash=refresh_hash,
            ip_address=client_ip,
            device_info=user_agent,
            created_at=now,
            expires_at=expires_at,
            last_activity=now,
            is_revoked=False,
        )
        db.add(session)
        await db.flush()

        # Cache session in Redis for fast verification
        try:
            r = await redis_pool.get_client()
            if r:
                ttl = int(timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS).total_seconds())
                await r.setex(f"refresh_token:{refresh_hash}", ttl, str(user.id))
        except Exception as e:
            log.warning("Could not cache refresh token in Redis", error=str(e))

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    @classmethod
    async def refresh_tokens(cls, db: AsyncSession, refresh_token_plain: str) -> TokenResponse:
        """Validate refresh token and issue a fresh access + refresh pair."""
        token_hash = hash_token(refresh_token_plain)
        stmt = (
            select(UserSession)
            .where(
                UserSession.refresh_token_hash == token_hash,
                UserSession.is_revoked.is_(False),
                UserSession.expires_at > datetime.now(timezone.utc),
            )
        )
        res = await db.execute(stmt)
        session = res.scalar_one_or_none()

        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token",
            )

        user_stmt = select(User).where(User.id == session.user_id)
        user_res = await db.execute(user_stmt)
        user = user_res.scalar_one_or_none()

        if not user or not user.is_active or user.is_locked:
            session.is_revoked = True
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account is inactive or locked",
            )

        # Revoke old session and issue a new one (Token Rotation)
        session.is_revoked = True
        new_tokens = await cls.create_session(db, user, session.ip_address, session.device_info)
        await db.commit()
        return new_tokens

    @classmethod
    async def logout(cls, db: AsyncSession, refresh_token_plain: str, user_id: UUID) -> None:
        """Revoke refresh token and invalidate session."""
        token_hash = hash_token(refresh_token_plain)
        stmt = select(UserSession).where(
            UserSession.refresh_token_hash == token_hash,
            UserSession.user_id == user_id,
        )
        res = await db.execute(stmt)
        session = res.scalar_one_or_none()
        if session:
            session.is_revoked = True
            await db.commit()

        try:
            r = await redis_pool.get_client()
            if r:
                await r.delete(f"refresh_token:{token_hash}")
        except Exception:
            pass

    @classmethod
    async def init_mfa_setup(cls, user: User) -> MFASetupResponse:
        """Generate a new TOTP secret and QR code for the user."""
        secret = setup_totp()
        qr_code = generate_totp_qr_base64(secret, user.username)
        uri = get_totp_uri(secret, user.username)
        return MFASetupResponse(
            secret=secret,
            qr_code_base64=qr_code,
            provisioning_uri=uri,
        )

    @classmethod
    async def confirm_mfa_setup(
        cls, db: AsyncSession, user: User, secret: str, code: str
    ) -> bool:
        """Verify the first code and persist encrypted secret to user profile."""
        if not verify_totp(secret, code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification code. Please check your authenticator app.",
            )
        user.mfa_secret = encrypt_mfa_secret(secret)
        user.mfa_enabled = True
        await db.commit()
        await AuditService.log_action(
            db,
            action="user.mfa_enabled",
            resource_type="user",
            resource_id=str(user.id),
            actor_id=user.id,
            actor_username=user.username,
        )
        return True


# ---------------------------------------------------------------------------
# FastAPI Dependency: Get Current User
# ---------------------------------------------------------------------------

async def get_current_user(
    auth: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Authenticate request via JWT Bearer token and return active User instance.
    """
    if not auth or not auth.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth.credentials
    try:
        payload = decode_access_token(token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject claim",
        )

    try:
        user_uuid = UUID(user_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user ID format in token",
        )

    stmt = select(User).where(User.id == user_uuid)
    res = await db.execute(stmt)
    user = res.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive",
        )
    if user.is_locked:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is locked",
        )

    return user


def require_permission(permission_code: str) -> Callable:
    """
    Dependency factory: ensures current user has the required permission.
    Superusers bypass permission checks.
    """
    async def permission_checker(
        current_user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> User:
        if current_user.is_superuser:
            return current_user

        has_perm = await RBACService.has_permission(db, current_user.id, permission_code)
        if not has_perm:
            log.warning(
                "Access denied: missing permission",
                user=current_user.username,
                required=permission_code,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: requires '{permission_code}'",
            )
        return current_user

    return permission_checker
