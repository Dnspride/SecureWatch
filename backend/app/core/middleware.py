"""
ASGI middleware stack for SecureWatch:
- RateLimitMiddleware   — sliding-window rate limiting via Redis
- RequestLoggingMiddleware — structured request/response logging
- SecurityHeadersMiddleware — HSTS, CSP, X-Frame-Options, etc.
- AuditMiddleware       — capture request actor context for audit logs
"""
from __future__ import annotations

import time
import uuid
from typing import Callable

import structlog
from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Rate Limit Middleware
# ---------------------------------------------------------------------------

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window rate limiter using Redis.
    Exempt paths: /health, /docs, /openapi.json, /redoc.
    """

    EXEMPT_PATHS = {"/health", "/docs", "/openapi.json", "/redoc", "/favicon.ico"}

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)

        # Import lazily to avoid circular imports at module load
        from app.core.redis_client import check_rate_limit
        from app.core.config import settings

        # Identify by IP (use X-Forwarded-For if behind proxy)
        client_ip = (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )

        try:
            allowed, current, retry_after = await check_rate_limit(
                identifier=client_ip,
                max_requests=settings.RATE_LIMIT_REQUESTS,
                window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
            )
        except Exception:
            # Redis down — fail open in development, fail closed in production
            if settings.is_production:
                return JSONResponse(
                    status_code=503,
                    content={"detail": "Rate limiter unavailable"},
                )
            return await call_next(request)

        response = await call_next(request) if allowed else JSONResponse(
            status_code=429,
            content={"detail": "Too many requests. Please slow down."},
        )

        response.headers["X-RateLimit-Limit"] = str(settings.RATE_LIMIT_REQUESTS)
        response.headers["X-RateLimit-Remaining"] = str(
            max(0, settings.RATE_LIMIT_REQUESTS - current)
        )
        if not allowed:
            response.headers["Retry-After"] = str(retry_after)

        return response


# ---------------------------------------------------------------------------
# Request Logging Middleware
# ---------------------------------------------------------------------------

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log every request and response with structured fields."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        start = time.perf_counter()

        # Bind request context to structlog
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            client_ip=request.client.host if request.client else "unknown",
        )

        log.info("Request started")

        try:
            response = await call_next(request)
        except Exception as exc:
            log.exception("Unhandled exception during request", error=str(exc))
            raise

        elapsed_ms = (time.perf_counter() - start) * 1000
        log.info(
            "Request completed",
            status_code=response.status_code,
            duration_ms=round(elapsed_ms, 2),
        )

        response.headers["X-Request-ID"] = request_id
        return response


# ---------------------------------------------------------------------------
# Security Headers Middleware
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Add security headers to every response:
    HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.
    """

    _HEADERS = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "0",  # Disabled — modern browsers handle this via CSP
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        ),
        "Cache-Control": "no-store",
    }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        for name, value in self._HEADERS.items():
            response.headers[name] = value
        return response


# ---------------------------------------------------------------------------
# Audit Context Middleware
# ---------------------------------------------------------------------------

class AuditMiddleware(BaseHTTPMiddleware):
    """
    Extract the authenticated actor from the JWT and attach to request.state
    so audit logging services can read it without re-parsing the token.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request.state.actor_id = None
        request.state.actor_username = None

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                from app.core.security import decode_access_token
                payload = decode_access_token(token)
                request.state.actor_id = payload.get("sub")
                request.state.actor_username = payload.get("username")
            except Exception:
                # Invalid token — let the auth dependency handle it
                pass

        return await call_next(request)
