"""
SQLAlchemy model: User
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    Column,
    UniqueConstraint,
    Index,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base

# ---------------------------------------------------------------------------
# Association tables
# ---------------------------------------------------------------------------

user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base):
    """Platform user account."""

    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("username", name="uq_users_username"),
        UniqueConstraint("email", name="uq_users_email"),
        Index("ix_users_email", "email"),
        Index("ix_users_username", "username"),
        Index("ix_users_department", "department"),
        Index("ix_users_is_active", "is_active"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    department: Mapped[str | None] = mapped_column(String(128), nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(512), nullable=False)

    # Status flags
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_locked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Failed login tracking
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    lockout_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # MFA
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret: Mapped[str | None] = mapped_column(String(512), nullable=True)  # Fernet-encrypted

    # ------------------------------------------------------------------ #
    # Relationships
    # ------------------------------------------------------------------ #
    roles: Mapped[list["Role"]] = relationship(  # noqa: F821
        "Role", secondary=user_roles, back_populates="users", lazy="selectin"
    )
    devices: Mapped[list["Device"]] = relationship(  # noqa: F821
        "Device", back_populates="owner", lazy="dynamic"
    )
    sessions: Mapped[list["UserSession"]] = relationship(  # noqa: F821
        "UserSession", back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )
    login_history: Mapped[list["LoginHistory"]] = relationship(  # noqa: F821
        "LoginHistory", back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(  # noqa: F821
        "AuditLog", foreign_keys="AuditLog.actor_id", back_populates="actor", lazy="dynamic"
    )
    group_memberships: Mapped[list["GroupMember"]] = relationship(  # noqa: F821
        "GroupMember", back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )
    enrollment_tokens_created: Mapped[list["EnrollmentToken"]] = relationship(  # noqa: F821
        "EnrollmentToken", foreign_keys="EnrollmentToken.created_by", back_populates="creator", lazy="dynamic"
    )

    def __repr__(self) -> str:
        user_id = self.__dict__.get("id", "unloaded")
        username = self.__dict__.get("username", "unloaded")
        return f"<User id={user_id} username={username!r}>"
