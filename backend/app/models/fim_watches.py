"""
SQLAlchemy models: FIMWatch and FIMEvent
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base


class FIMChangeType(str, enum.Enum):
    created = "created"
    modified = "modified"
    deleted = "deleted"


class FIMWatch(Base):
    """File Integrity Monitoring watch configuration for a device path."""

    __tablename__ = "fim_watches"
    __table_args__ = (
        Index("ix_fim_watches_device_id", "device_id"),
        Index("ix_fim_watches_is_active", "is_active"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    is_recursive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    device: Mapped["Device"] = relationship("Device", back_populates="fim_watches")  # noqa: F821
    events: Mapped[list["FIMEvent"]] = relationship(
        "FIMEvent", back_populates="watch", lazy="dynamic"
    )

    def __repr__(self) -> str:
        return f"<FIMWatch id={self.id} path={self.path!r}>"


class FIMEvent(Base):
    """A detected file system change event under a monitored path."""

    __tablename__ = "fim_events"
    __table_args__ = (
        Index("ix_fim_events_device_id", "device_id"),
        Index("ix_fim_events_watch_id", "watch_id"),
        Index("ix_fim_events_event_timestamp", "event_timestamp"),
        Index("ix_fim_events_change_type", "change_type"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    watch_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("fim_watches.id", ondelete="SET NULL"), nullable=True
    )
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    change_type: Mapped[FIMChangeType] = mapped_column(Enum(FIMChangeType), nullable=False)
    file_hash: Mapped[str | None] = mapped_column(String(256), nullable=True)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    device: Mapped["Device"] = relationship("Device", back_populates="fim_events")  # noqa: F821
    watch: Mapped["FIMWatch | None"] = relationship("FIMWatch", back_populates="events")

    def __repr__(self) -> str:
        return f"<FIMEvent id={self.id} path={self.file_path!r} type={self.change_type}>"
