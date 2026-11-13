"""
API v1 Router aggregation.
"""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints import (
    alerts,
    audit,
    auth,
    dashboard,
    devices,
    events,
    groups,
    permissions,
    reports,
    roles,
    settings,
    users,
)

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(roles.router)
api_router.include_router(permissions.router)
api_router.include_router(groups.router)
api_router.include_router(devices.router)
api_router.include_router(events.router)
api_router.include_router(alerts.router)
api_router.include_router(audit.router)
api_router.include_router(dashboard.router)
api_router.include_router(reports.router)
api_router.include_router(settings.router)
