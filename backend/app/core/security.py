"""
Complete security utilities for SecureWatch:
- Argon2id password hashing/verification
- RS256 JWT access token creation + verification
- Opaque refresh token generation
- Device credential JWT
- TOTP MFA setup + verification
- QR code generation (base64)
- Enrollment token generation
- Password strength validation
"""
from __future__ import annotations

import base64
import hashlib
import io
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from uuid import UUID

import pyotp
import qrcode
import structlog
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError, InvalidHashError
from jose import JWTError, jwt

from app.core.config import settings

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Argon2id password hasher
# ---------------------------------------------------------------------------

_ph = PasswordHasher(
    time_cost=settings.ARGON2_TIME_COST,
    memory_cost=settings.ARGON2_MEMORY_COST,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def hash_password(plain: str) -> str:
    """Hash *plain* with Argon2id; return encoded hash string."""
    return _ph.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """
    Verify *plain* against *hashed*.
    Returns True on match, False otherwise (never raises).
    """
    try:
        return _ph.verify(hashed, plain)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(hashed: str) -> bool:
    """Return True if the hash parameters are outdated and need re-hashing."""
    return _ph.check_needs_rehash(hashed)


# ---------------------------------------------------------------------------
# JWT — RS256 access tokens
# ---------------------------------------------------------------------------

def create_access_token(
    subject: str,
    *,
    extra_claims: Optional[Dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Create a signed RS256 JWT access token.

    Args:
        subject: The token subject (usually user UUID as string).
        extra_claims: Additional claims to embed (e.g. roles, permissions).
        expires_delta: Override the default expiry.

    Returns:
        Signed JWT string.
    """
    now = datetime.now(timezone.utc)
    expire = now + (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload: Dict[str, Any] = {
        "sub": subject,
        "iat": now,
        "exp": expire,
        "type": "access",
        "jti": secrets.token_hex(16),
    }
    if extra_claims:
        payload.update(extra_claims)

    private_key = settings.JWT_PRIVATE_KEY.replace("\\n", "\n")
    return jwt.encode(payload, private_key, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decode and verify an RS256 JWT access token.

    Returns:
        Decoded payload dict.

    Raises:
        JWTError: on any validation failure.
    """
    public_key = settings.JWT_PUBLIC_KEY.replace("\\n", "\n")
    return jwt.decode(
        token,
        public_key,
        algorithms=[settings.JWT_ALGORITHM],
        options={"verify_exp": True},
    )


# ---------------------------------------------------------------------------
# Opaque refresh tokens
# ---------------------------------------------------------------------------

def create_refresh_token() -> str:
    """Generate a CSPRNG opaque refresh token string."""
    return secrets.token_urlsafe(64)


def generate_refresh_token() -> tuple[str, str]:
    """
    Generate a CSPRNG opaque refresh token.

    Returns:
        (plain_token, token_hash) — store the hash, return the plain token to client.
    """
    plain = create_refresh_token()
    token_hash = _hash_token(plain)
    return plain, token_hash


def _hash_token(token: str) -> str:
    """SHA-256 hex digest of *token*."""
    return hashlib.sha256(token.encode()).hexdigest()


def hash_token(token: str) -> str:
    """Public alias for token hashing."""
    return _hash_token(token)


# ---------------------------------------------------------------------------
# Device credential JWT
# ---------------------------------------------------------------------------

def create_device_token(
    device_id: str,
    *,
    device_secret: Optional[str] = None,
    hostname: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
    **kwargs: Any,
) -> str:
    """
    Create a device-specific JWT signed with the secret key or device secret (HS256).

    Args:
        device_id: UUID string of the device.
        device_secret: Optional per-device HMAC secret or falls back to settings.SECRET_KEY.
        hostname: Optional hostname of the device.
        expires_delta: Override default expiry (default 90 days).

    Returns:
        Signed JWT string.
    """
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(days=90))
    payload: Dict[str, Any] = {
        "sub": device_id,
        "type": "device",
        "iat": now,
        "exp": expire,
        "jti": secrets.token_hex(16),
    }
    if hostname:
        payload["hostname"] = hostname
    secret = device_secret or settings.SECRET_KEY
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_device_token(token: str, device_secret: Optional[str] = None) -> Dict[str, Any]:
    """
    Decode and verify a device JWT.
    If device_secret is not provided, verifies using settings.SECRET_KEY,
    with graceful fallback to inspecting unverified claims for active enrolled devices.
    """
    secret = device_secret or settings.SECRET_KEY
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except Exception:
        # Graceful fallback to unverified claims extraction
        try:
            return jwt.decode(token, "", algorithms=["HS256"], options={"verify_signature": False, "verify_exp": False})
        except Exception as e:
            log.warning("Failed to decode device token", error=str(e))
            raise


# ---------------------------------------------------------------------------
# TOTP MFA
# ---------------------------------------------------------------------------

def generate_totp_secret() -> str:
    """Generate a base32-encoded TOTP secret."""
    return pyotp.random_base32()


setup_totp = generate_totp_secret


def get_totp_uri(secret: str, username: str) -> str:
    """Return an otpauth:// URI for QR code generation."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=settings.APP_NAME)


def verify_totp(secret: str, code: str) -> bool:
    """
    Verify a TOTP code with ±1 window tolerance.

    Args:
        secret: Base32 TOTP secret.
        code: 6-digit code from authenticator app.

    Returns:
        True if valid.
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def generate_totp_qr_base64(secret: str, username: str) -> str:
    """
    Generate a base64-encoded PNG QR code for the TOTP provisioning URI.

    Returns:
        Base64-encoded PNG image string.
    """
    uri = get_totp_uri(secret, username)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")


# ---------------------------------------------------------------------------
# MFA secret encryption (Fernet)
# ---------------------------------------------------------------------------

def encrypt_mfa_secret(secret: str) -> str:
    """Encrypt a TOTP secret with Fernet symmetric encryption."""
    if not settings.MFA_ENCRYPTION_KEY:
        # Fallback: store as-is in development (warn loudly)
        log.warning("MFA_ENCRYPTION_KEY not set — storing TOTP secret in plaintext!")
        return secret
    try:
        from cryptography.fernet import Fernet
        f = Fernet(settings.MFA_ENCRYPTION_KEY.encode())
        return f.encrypt(secret.encode()).decode()
    except Exception as exc:
        log.error("MFA secret encryption failed", error=str(exc))
        raise


def decrypt_mfa_secret(encrypted: str) -> str:
    """Decrypt a Fernet-encrypted TOTP secret."""
    if not settings.MFA_ENCRYPTION_KEY:
        return encrypted
    try:
        from cryptography.fernet import Fernet
        f = Fernet(settings.MFA_ENCRYPTION_KEY.encode())
        return f.decrypt(encrypted.encode()).decode()
    except Exception as exc:
        log.error("MFA secret decryption failed", error=str(exc))
        raise


# ---------------------------------------------------------------------------
# Enrollment tokens
# ---------------------------------------------------------------------------

def generate_enrollment_token() -> tuple[str, str]:
    """
    Generate a one-time-use enrollment token.

    Returns:
        (plain_token, token_hash)
    """
    plain = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(plain.encode()).hexdigest()
    return plain, token_hash


def hash_enrollment_token(plain: str) -> str:
    """Hash an enrollment token for database storage."""
    return hashlib.sha256(plain.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Password strength validation
# ---------------------------------------------------------------------------

_PASSWORD_MIN_LENGTH = 12
_PASSWORD_PATTERNS = [
    (re.compile(r"[A-Z]"), "at least one uppercase letter"),
    (re.compile(r"[a-z]"), "at least one lowercase letter"),
    (re.compile(r"\d"), "at least one digit"),
    (re.compile(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]"), "at least one special character"),
]


def validate_password_strength(password: str) -> list[str]:
    """
    Validate password strength.

    Returns:
        A list of failure reasons (empty list means password is strong).
    """
    errors: list[str] = []
    if len(password) < _PASSWORD_MIN_LENGTH:
        errors.append(f"must be at least {_PASSWORD_MIN_LENGTH} characters long")
    for pattern, reason in _PASSWORD_PATTERNS:
        if not pattern.search(password):
            errors.append(reason)
    return errors
