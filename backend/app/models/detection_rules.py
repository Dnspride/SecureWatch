"""
SQLAlchemy model: DetectionRule
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, Index
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.core.database import Base


class DetectionRule(Base):
    """
    Configurable rule that evaluates incoming events and raises alerts.
    condition_config is a JSONB field encoding the rule logic.
    """

    __tablename__ = "detection_rules"
    __table_args__ = (
        Index("ix_detection_rules_is_active", "is_active"),
        Index("ix_detection_rules_event_source", "event_source"),
        Index("ix_detection_rules_severity", "severity"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_source: Mapped[str] = mapped_column(String(64), nullable=False)
    condition_config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)

    mitre_tactic: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(128), nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_custom: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    recommended_steps: Mapped[str | None] = mapped_column(Text, nullable=True)
    suppress_duplicate_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    # Relationships
    security_events: Mapped[list["SecurityEvent"]] = relationship(  # noqa: F821
        "SecurityEvent", back_populates="detection_rule", lazy="dynamic"
    )

    def __repr__(self) -> str:
        return f"<DetectionRule id={self.id} name={self.name!r} active={self.is_active}>"
