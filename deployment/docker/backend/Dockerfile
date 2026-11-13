# =============================================================================
# SecureWatch Backend – Multi-stage Python 3.11 Dockerfile
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: builder – compile wheels for all dependencies
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS builder

# Install build tools needed for C-extension packages (psycopg2, cryptography…)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libffi-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy only requirements first to exploit Docker layer caching
COPY backend/requirements.txt ./requirements.txt

# Build wheels into /build/wheels so we can copy them to the production stage
RUN pip install --upgrade pip wheel \
    && pip wheel --no-cache-dir --wheel-dir /build/wheels -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2: production – lean final image
# -----------------------------------------------------------------------------
FROM python:3.11-slim AS production

LABEL maintainer="SecureWatch Platform <platform@securewatch.io>"
LABEL org.opencontainers.image.title="SecureWatch Backend"
LABEL org.opencontainers.image.description="FastAPI backend for the SecureWatch SIEM platform"

# Runtime dependencies only (libpq for asyncpg psycopg drivers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user and group for the application
RUN groupadd --gid 1001 appgroup \
    && useradd --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

WORKDIR /app

# Install pre-built wheels from the builder stage (no compiler required here)
COPY --from=builder /build/wheels /tmp/wheels
RUN pip install --no-cache-dir --no-index --find-links /tmp/wheels /tmp/wheels/*.whl \
    && rm -rf /tmp/wheels

# Copy application source
COPY --chown=appuser:appgroup backend/ /app/

# Create directories the app needs at runtime
RUN mkdir -p /app/logs /app/data \
    && chown -R appuser:appgroup /app/logs /app/data

# Drop to non-root
USER appuser

# Expose port used by uvicorn
EXPOSE 8000

# Health check – FastAPI exposes /health
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fs http://localhost:8000/health || exit 1

# Default command – can be overridden in docker-compose for celery workers
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "4", \
     "--loop", "uvloop", \
     "--http", "httptools", \
     "--access-log", \
     "--log-level", "info"]
