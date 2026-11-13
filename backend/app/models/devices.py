"""
SQLAlchemy model: Device
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Index,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base


class DeviceStatus(str, enum.Enum):
    online = "online"
    offline = "offline"
    pending_approval = "pending_approval"
    unhealthy = "unhealthy"
    critical = "critical"
    revoked = "revoked"


class Device(Base):
    """An endpoint device enrolled in the SecureWatch platform."""

    __tablename__ = "devices"
    __table_args__ = (
        Index("ix_devices_hostname", "hostname"),
        Index("ix_devices_status", "status"),
        Index("ix_devices_department", "department"),
        Index("ix_devices_owner_id", "device_owner_id"),
        Index("ix_devices_last_heartbeat", "last_heartbeat"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    os_name: Mapped[str] = mapped_column(String(64), nullable=False)
    os_version: Mapped[str] = mapped_column(String(64), nullable=False)
    os_arch: Mapped[str] = mapped_column(String(32), nullable=False)

    device_owner_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    department: Mapped[str | None] = mapped_column(String(128), nullable=True)

    private_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    public_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)

    agent_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    enrollment_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_heartbeat: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    status: Mapped[DeviceStatus] = mapped_column(
        Enum(DeviceStatus), default=DeviceStatus.pending_approval, nullable=False
    )
    security_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    enrollment_token_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("enrollment_tokens.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Relationships
    owner: Mapped["User | None"] = relationship(  # noqa: F821
        "User", back_populates="devices"
    )
    credentials: Mapped[list["DeviceCredential"]] = relationship(  # noqa: F821
        "DeviceCredential", back_populates="device", cascade="all, delete-orphan"
    )
    enrollment_token: Mapped["EnrollmentToken | None"] = relationship(  # noqa: F821
        "EnrollmentToken", back_populates="device", foreign_keys=[enrollment_token_id]
    )
    security_events: Mapped[list["SecurityEvent"]] = relationship(  # noqa: F821
        "SecurityEvent", back_populates="device", lazy="dynamic"
    )
    alerts: Mapped[list["Alert"]] = relationship(  # noqa: F821
        "Alert", back_populates="device", lazy="dynamic"
    )
    fim_watches: Mapped[list["FIMWatch"]] = relationship(  # noqa: F821
        "FIMWatch", back_populates="device", lazy="dynamic"
    )
    fim_events: Mapped[list["FIMEvent"]] = relationship(  # noqa: F821
        "FIMEvent", back_populates="device", lazy="dynamic"
    )

    def __repr__(self) -> str:
        dev_id = self.__dict__.get("id", "unloaded")
        hostname = self.__dict__.get("hostname", "unloaded")
        status = self.__dict__.get("status", "unloaded")
        return f"<Device id={dev_id} hostname={hostname!r} status={status}>"
