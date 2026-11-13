"""
Dashboard & Health API Endpoints: Aggregated SOC overview metrics and system status.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.redis_client import redis_pool
from app.models.users import User
from app.schemas.common import HealthResponse
from app.schemas.dashboard import DashboardStats
from app.services.auth_service import get_current_user
from app.services.dashboard_service import DashboardService

router = APIRouter(prefix="/dashboard", tags=["SOC Dashboard"])


@router.get("/stats", response_model=DashboardStats, summary="Retrieve SOC dashboard overview metrics")
async def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> DashboardStats:
    """Returns aggregated real-time counts, severity breakdowns, OS distribution, and trend series."""
    return await DashboardService.get_stats(db)


@router.get("/health", response_model=HealthResponse, summary="System health check")
async def health_check(
    db: AsyncSession = Depends(get_db),
) -> HealthResponse:
    # 1. Database check
    db_status = "connected"
    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {e}"

    # 2. Redis check
    redis_status = "connected"
    try:
        r = await redis_pool.get_client()
        if r:
            await r.ping()
        else:
            redis_status = "disabled/unavailable"
    except Exception as e:
        redis_status = f"unhealthy: {e}"

    return HealthResponse(
        status="healthy" if db_status == "connected" else "degraded",
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        database=db_status,
        redis=redis_status,
        opensearch="standalone_postgres_mode",
    )
