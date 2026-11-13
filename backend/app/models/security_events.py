"""
SQLAlchemy model: SecurityEvent
(PostgreSQL reference record; primary document storage is in OpenSearch)
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base


class SecurityEvent(Base):
    """
    Lightweight PostgreSQL reference for security events.
    Full raw event JSON is stored in OpenSearch; this table holds
    indexed metadata for fast cross-join queries and alert linkage.
    """

    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_device_id", "device_id"),
        Index("ix_security_events_user_id", "user_id"),
        Index("ix_security_events_severity", "severity"),
        Index("ix_security_events_event_category", "event_category"),
        Index("ix_security_events_event_timestamp", "event_timestamp"),
        Index("ix_security_events_is_alert_generated", "is_alert_generated"),
        Index("ix_security_events_detection_rule_id", "detection_rule_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    event_id: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)  # OpenSearch doc ID

    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    event_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_source: Mapped[str] = mapped_column(String(64), nullable=False)
    event_category: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)

    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    process_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    event_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_event_ref: Mapped[str | None] = mapped_column(Text, nullable=True)

    detection_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True
    )
    is_alert_generated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    device: Mapped["Device | None"] = relationship("Device", back_populates="security_events")  # noqa: F821
    detection_rule: Mapped["DetectionRule | None"] = relationship(  # noqa: F821
        "DetectionRule", back_populates="security_events"
    )
    alerts: Mapped[list["Alert"]] = relationship(  # noqa: F821
        "Alert", back_populates="source_event", foreign_keys="Alert.source_event_id", lazy="dynamic"
    )

    def __repr__(self) -> str:
        return f"<SecurityEvent id={self.id} type={self.event_type!r} severity={self.severity!r}>"
