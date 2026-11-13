"""
Unit tests for Authentication, Argon2id, RS256 JWT, and Lockout policies.
"""
from __future__ import annotations

import pytest
from app.core.security import (
    hash_password,
    verify_password,
    validate_password_strength,
    create_access_token,
    decode_access_token,
    setup_totp,
    verify_totp,
)


def test_argon2id_password_hashing():
    pwd = "ComplexP@ssword2026!#"
    hashed = hash_password(pwd)
    assert hashed != pwd
    assert hashed.startswith("$argon2id$")
    assert verify_password(pwd, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False


def test_password_strength_validation():
    # Weak passwords
    assert len(validate_password_strength("short")) > 0
    assert len(validate_password_strength("alllowercase123!")) > 0
    assert len(validate_password_strength("NOLOWERCASE123!")) > 0
    assert len(validate_password_strength("NoDigitsHereAtAll!")) > 0
    assert len(validate_password_strength("NoSymbols1234567")) > 0

    # Strong password
    assert len(validate_password_strength("SuperS3cureP@ssword!")) == 0


def test_jwt_token_creation_and_decoding():
    sub = "123e4567-e89b-12d3-a456-426614174000"
    claims = {"username": "admin", "permissions": ["users.read", "devices.read"]}
    token = create_access_token(sub, extra_claims=claims)
    assert isinstance(token, str)

    decoded = decode_access_token(token)
    assert decoded is not None
    assert decoded["sub"] == sub
    assert decoded["username"] == "admin"
    assert "users.read" in decoded["permissions"]


def test_totp_mfa_generation_and_verification():
    secret = setup_totp()
    assert len(secret) >= 16

    import pyotp
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()

    assert verify_totp(secret, valid_code) is True
    assert verify_totp(secret, "000000") is False
