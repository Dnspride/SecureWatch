"""
SQLAlchemy model: EnrollmentToken
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base


class EnrollmentToken(Base):
    """One-time-use token used to enrol a device into the platform."""

    __tablename__ = "enrollment_tokens"
    __table_args__ = (
        Index("ix_enrollment_tokens_is_used", "is_used"),
        Index("ix_enrollment_tokens_created_by", "created_by"),
        Index("ix_enrollment_tokens_expires_at", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    token_hash: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)

    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    is_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    used_by_device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    creator: Mapped["User"] = relationship(  # noqa: F821
        "User", foreign_keys=[created_by], back_populates="enrollment_tokens_created"
    )
    device: Mapped["Device | None"] = relationship(  # noqa: F821
        "Device", back_populates="enrollment_token",
        foreign_keys="Device.enrollment_token_id"
    )

    def __repr__(self) -> str:
        tok_id = self.__dict__.get("id", "unloaded")
        used = self.__dict__.get("is_used", "unloaded")
        return f"<EnrollmentToken id={tok_id} used={used}>"
