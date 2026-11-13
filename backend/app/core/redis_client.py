"""
Redis connection pool, refresh-token store, rate-limiting, and session helpers.
"""
from __future__ import annotations

import hashlib
import time
from typing import Optional

import redis.asyncio as aioredis
import structlog

from app.core.config import settings

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Connection pool (module-level singleton)
# ---------------------------------------------------------------------------

_pool: Optional[aioredis.ConnectionPool] = None
_client: Optional[aioredis.Redis] = None


async def init_redis() -> None:
    """Create the Redis connection pool and test connectivity."""
    global _pool, _client
    _pool = aioredis.ConnectionPool.from_url(
        settings.REDIS_URL,
        max_connections=20,
        decode_responses=True,
    )
    _client = aioredis.Redis(connection_pool=_pool)
    await _client.ping()
    log.info("Redis connected", url=settings.REDIS_URL)


async def close_redis() -> None:
    """Close the Redis connection pool."""
    global _client, _pool
    if _client:
        await _client.aclose()
    if _pool:
        await _pool.aclose()
    log.info("Redis connection closed")


def get_redis() -> aioredis.Redis:
    """Return the shared Redis client (must call init_redis first)."""
    if _client is None:
        raise RuntimeError("Redis not initialised — call init_redis() first")
    return _client


class RedisPoolManager:
    """Manages Redis connection pooling and client retrieval."""

    async def get_client(self) -> aioredis.Redis:
        global _pool, _client
        if _client is None:
            _pool = aioredis.ConnectionPool.from_url(
                settings.REDIS_URL,
                max_connections=20,
                decode_responses=True,
            )
            _client = aioredis.Redis(connection_pool=_pool)
        return _client

    async def close(self) -> None:
        await close_redis()


redis_pool = RedisPoolManager()


# ---------------------------------------------------------------------------
# Key builders
# ---------------------------------------------------------------------------

_REFRESH_PREFIX = "rt:"          # refresh token store
_SESSION_PREFIX = "sess:"         # session data
_RATE_PREFIX = "rl:"              # rate-limit sliding window
_BLACKLIST_PREFIX = "jti:"        # JTI blacklist for revoked access tokens


def _refresh_key(token_hash: str) -> str:
    return f"{_REFRESH_PREFIX}{token_hash}"


def _session_key(session_id: str) -> str:
    return f"{_SESSION_PREFIX}{session_id}"


def _rate_key(identifier: str) -> str:
    return f"{_RATE_PREFIX}{identifier}"


def _jti_key(jti: str) -> str:
    return f"{_BLACKLIST_PREFIX}{jti}"


# ---------------------------------------------------------------------------
# Refresh token helpers
# ---------------------------------------------------------------------------

async def store_refresh_token(
    token_hash: str,
    user_id: str,
    session_id: str,
    ttl_seconds: int,
) -> None:
    """Store a refresh token hash in Redis with the user's session context."""
    r = get_redis()
    key = _refresh_key(token_hash)
    await r.hset(
        key,
        mapping={"user_id": user_id, "session_id": session_id, "created_at": int(time.time())},
    )
    await r.expire(key, ttl_seconds)
    log.debug("Refresh token stored", session_id=session_id)


async def get_refresh_token_data(token_hash: str) -> Optional[dict]:
    """Return stored refresh token metadata, or None if not found/expired."""
    r = get_redis()
    data = await r.hgetall(_refresh_key(token_hash))
    return data or None


async def revoke_refresh_token(token_hash: str) -> bool:
    """Delete a refresh token from Redis. Returns True if it existed."""
    r = get_redis()
    deleted = await r.delete(_refresh_key(token_hash))
    return bool(deleted)


async def revoke_all_user_refresh_tokens(user_id: str) -> int:
    """
    Revoke all refresh tokens for a given user by scanning for their keys.
    Returns the number of tokens revoked.
    """
    r = get_redis()
    revoked = 0
    async for key in r.scan_iter(f"{_REFRESH_PREFIX}*"):
        data = await r.hgetall(key)
        if data.get("user_id") == user_id:
            await r.delete(key)
            revoked += 1
    log.info("Revoked all user refresh tokens", user_id=user_id, count=revoked)
    return revoked


# ---------------------------------------------------------------------------
# Access token JTI blacklist
# ---------------------------------------------------------------------------

async def blacklist_jti(jti: str, ttl_seconds: int) -> None:
    """Add a JWT ID to the blacklist (for logout before expiry)."""
    r = get_redis()
    await r.set(_jti_key(jti), "1", ex=ttl_seconds)


async def is_jti_blacklisted(jti: str) -> bool:
    """Return True if the JTI is blacklisted."""
    r = get_redis()
    return bool(await r.exists(_jti_key(jti)))


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

async def store_session(session_id: str, data: dict, ttl_seconds: int) -> None:
    """Store session data in Redis."""
    r = get_redis()
    await r.hset(_session_key(session_id), mapping=data)
    await r.expire(_session_key(session_id), ttl_seconds)


async def get_session(session_id: str) -> Optional[dict]:
    """Retrieve session data from Redis."""
    r = get_redis()
    data = await r.hgetall(_session_key(session_id))
    return data or None


async def delete_session(session_id: str) -> None:
    """Remove a session from Redis."""
    r = get_redis()
    await r.delete(_session_key(session_id))


async def touch_session(session_id: str, ttl_seconds: int) -> None:
    """Refresh the TTL of an active session."""
    r = get_redis()
    await r.expire(_session_key(session_id), ttl_seconds)


# ---------------------------------------------------------------------------
# Sliding-window rate limiter
# ---------------------------------------------------------------------------

async def check_rate_limit(
    identifier: str,
    max_requests: int = settings.RATE_LIMIT_REQUESTS,
    window_seconds: int = settings.RATE_LIMIT_WINDOW_SECONDS,
) -> tuple[bool, int, int]:
    """
    Sliding-window rate limit check using a Redis sorted set.

    Args:
        identifier: Unique key (e.g. IP address or user_id).
        max_requests: Allowed requests per window.
        window_seconds: Window size in seconds.

    Returns:
        (allowed, current_count, retry_after_seconds)
    """
    r = get_redis()
    now = time.time()
    window_start = now - window_seconds
    key = _rate_key(identifier)

    pipe = r.pipeline()
    pipe.zremrangebyscore(key, 0, window_start)
    pipe.zadd(key, {f"{now}-{secrets.token_hex(4)}": now})
    pipe.zcard(key)
    pipe.expire(key, window_seconds + 1)
    results = await pipe.execute()

    current_count: int = results[2]
    allowed = current_count <= max_requests
    retry_after = window_seconds if not allowed else 0
    return allowed, current_count, retry_after


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

import secrets as _secrets  # noqa: E402 — avoids circular at top-level

async def set_cache(key: str, value: str, ttl_seconds: int) -> None:
    """Generic cache setter."""
    await get_redis().set(key, value, ex=ttl_seconds)


async def get_cache(key: str) -> Optional[str]:
    """Generic cache getter."""
    return await get_redis().get(key)


async def delete_cache(key: str) -> None:
    """Generic cache deleter."""
    await get_redis().delete(key)
