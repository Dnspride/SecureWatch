"""
Pydantic schemas for authentication endpoints.
"""
from __future__ import annotations

from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    """Credentials submitted to the /auth/login endpoint."""

    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1)
    mfa_code: Optional[str] = Field(None, min_length=6, max_length=6)


class TokenResponse(BaseModel):
    """Access + refresh token pair."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class LoginResponse(BaseModel):
    """Full login response including token pair and MFA status."""

    tokens: Optional[TokenResponse] = None
    mfa_required: bool = False
    mfa_setup_required: bool = False
    user_id: Optional[UUID] = None
    username: Optional[str] = None


class RefreshRequest(BaseModel):
    """Refresh token submitted to get a new token pair."""

    refresh_token: Optional[str] = None
    refreshToken: Optional[str] = None

    @property
    def token_value(self) -> str:
        return self.refresh_token or self.refreshToken or ""


class MFASetupResponse(BaseModel):
    """TOTP setup response with QR code for the authenticator app."""

    secret: str
    qr_code_base64: str  # base64-encoded PNG
    provisioning_uri: str


class MFAVerifyRequest(BaseModel):
    """TOTP code submitted to complete MFA setup or login."""

    code: str = Field(..., min_length=6, max_length=6)


class LogoutRequest(BaseModel):
    """Logout request with the refresh token to revoke."""

    refresh_token: str


class PasswordResetRequest(BaseModel):
    """Admin-initiated password reset."""

    new_password: str = Field(..., min_length=12)
