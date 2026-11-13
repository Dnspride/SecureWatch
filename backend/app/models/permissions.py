"""
SQLAlchemy model: Permission
"""
from __future__ import annotations

import uuid

from sqlalchemy import Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base
from app.models.roles import role_permissions


class Permission(Base):
    """
    Granular permission code, e.g. "users.read".
    Permissions are seeded at startup and not user-editable.
    """

    __tablename__ = "permissions"
    __table_args__ = (
        UniqueConstraint("code", name="uq_permissions_code"),
        Index("ix_permissions_code", "code"),
        Index("ix_permissions_category", "category"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    code: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)
    category: Mapped[str] = mapped_column(String(64), nullable=False)

    # Relationships
    roles: Mapped[list["Role"]] = relationship(  # noqa: F821
        "Role", secondary=role_permissions, back_populates="permissions", lazy="dynamic"
    )

    def __repr__(self) -> str:
        return f"<Permission code={self.code!r}>"
