"""
Common shared Pydantic schemas used across the API.
"""
from __future__ import annotations

from typing import Any, Generic, List, Optional, TypeVar
from uuid import UUID

from pydantic import BaseModel

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """Wrapper for paginated list endpoints."""

    items: List[T]
    total: int
    page: int
    page_size: int
    pages: int


class ErrorResponse(BaseModel):
    """Standard error response body."""

    detail: str
    code: Optional[str] = None
    field: Optional[str] = None


class HealthResponse(BaseModel):
    """Application health check response."""

    status: str
    version: str
    environment: str
    database: str
    redis: str
    opensearch: str


class MessageResponse(BaseModel):
    """Generic success message."""

    message: str
    success: bool = True
