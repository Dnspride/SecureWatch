"""
SecureWatch Platform: FastAPI Application Entrypoint.
Unified IAM, Endpoint Security Monitoring, EDR & SIEM Platform.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import structlog

from app.api.v1.router import api_router
from app.api.websocket import ws_router
from app.core.config import settings
from app.core.database import async_session_factory, init_db
from app.core.middleware import (
    AuditMiddleware,
    RateLimitMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
)
from app.core.redis_client import redis_pool
from app.services.rbac_service import RBACService
from app.services.user_service import UserService
from app.schemas.users import UserCreate

log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup & shutdown events."""
    log.info("Starting SecureWatch Cybersecurity Platform", version=settings.APP_VERSION)

    # 1. Initialize DB tables
    try:
        await init_db()
        log.info("Database tables initialized successfully")
    except Exception as e:
        log.error("Failed to initialize database tables", error=str(e))

    # 2. Seed initial RBAC roles & permissions
    try:
        async with async_session_factory() as session:
            await RBACService.seed_defaults(session)

            # Ensure default Super Admin user exists
            admin_user = await UserService.get_by_username(session, "admin")
            if not admin_user:
                await UserService.create_user(
                    session,
                    UserCreate(
                        username="admin",
                        email="admin@securewatch.io",
                        full_name="Platform Administrator",
                        password=settings.DEFAULT_ADMIN_PASSWORD if hasattr(settings, "DEFAULT_ADMIN_PASSWORD") else "SecureWatch@2026!",
                        department="Security Operations",
                        is_active=True,
                        is_superuser=True,
                    ),
                )
                log.info("Created default platform Super Administrator user 'admin'")
    except Exception as e:
        log.error("Failed to seed initial RBAC & Admin account", error=str(e))

    # 3. Redis connection test
    try:
        r = await redis_pool.get_client()
        if r:
            await r.ping()
            log.info("Redis cache & session store connected successfully")
    except Exception as e:
        log.warning("Redis not available — running in fallback mode", error=str(e))

    yield

    # Shutdown
    log.info("Shutting down SecureWatch platform")
    await redis_pool.close()


def create_application() -> FastAPI:
    """FastAPI application factory."""
    app = FastAPI(
        title="SecureWatch Cybersecurity Platform API",
        description="Unified Enterprise IAM, Endpoint Security Monitoring, EDR and SIEM Platform.",
        version=settings.APP_VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS if hasattr(settings, "CORS_ORIGINS") else ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Security & Logging Middlewares
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(AuditMiddleware)
    app.add_middleware(RateLimitMiddleware)

    # Include API routes
    app.include_router(api_router)
    app.include_router(ws_router)

    @app.get("/health", tags=["System"], summary="Platform Liveness & Health Check")
    async def health_check():
        return {
            "status": "healthy",
            "app": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
        }

    return app


app = create_application()
