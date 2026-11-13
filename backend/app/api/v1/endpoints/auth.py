"""
Authentication API Endpoints: Login, logout, token refresh, and MFA setup/verification.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.users import User
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    LogoutRequest,
    MFASetupResponse,
    MFAVerifyRequest,
    RefreshRequest,
    TokenResponse,
)
from app.schemas.common import MessageResponse
from app.schemas.users import UserResponse
from app.services.auth_service import AuthService, get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=LoginResponse, summary="Authenticate user")
async def login(
    request: Request,
    credentials: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    """
    Authenticate user using Argon2id password verification, lockout policy check, and optional MFA.
    """
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    return await AuthService.authenticate(db, credentials, client_ip, user_agent)


@router.post("/refresh", response_model=TokenResponse, summary="Refresh access token")
@router.post("/token/refresh", response_model=TokenResponse, summary="Refresh access token (alias)")
async def refresh_token(
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """
    Validate refresh token and issue a fresh access + refresh token pair (Token Rotation).
    """
    token_str = payload.token_value
    if not token_str:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Refresh token required")
    return await AuthService.refresh_tokens(db, token_str)


@router.post("/logout", response_model=MessageResponse, summary="Logout and revoke session")
async def logout(
    payload: LogoutRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """
    Revoke user session and delete refresh token from store.
    """
    await AuthService.logout(db, payload.refresh_token, current_user.id)
    return MessageResponse(message="Successfully logged out")


@router.get("/me", response_model=UserResponse, summary="Get current logged in user profile")
async def get_me(
    current_user: User = Depends(get_current_user),
) -> User:
    """Return profile and assigned roles for currently authenticated user."""
    return current_user


@router.post("/mfa/setup", response_model=MFASetupResponse, summary="Initialize TOTP MFA setup")
async def setup_mfa(
    current_user: User = Depends(get_current_user),
) -> MFASetupResponse:
    """Generate TOTP secret and QR code for scanning in Google Authenticator or 1Password."""
    return await AuthService.init_mfa_setup(current_user)


@router.post("/mfa/verify", response_model=MessageResponse, summary="Verify and enable TOTP MFA")
async def verify_mfa_setup(
    payload: MFAVerifyRequest,
    secret: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    """Validate initial TOTP code to confirm authenticator app enrollment."""
    await AuthService.confirm_mfa_setup(db, current_user, secret, payload.code)
    return MessageResponse(message="Two-factor authentication successfully enabled")
