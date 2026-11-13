"""
SecureWatch Endpoint Agent – Secure API Client
===============================================
Provides async HTTP communication with the central SecureWatch server.

Features:
  - TLS certificate verification (never disabled)
  - JWT Bearer-token authentication
  - Automatic token refresh before expiry
  - Exponential back-off via tenacity
  - Event queue buffering when the server is unreachable
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import logging
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

try:
    import httpx
    HAS_HTTPX = True
    _RETRY_EXCEPTIONS = (
        httpx.TimeoutException,
        httpx.ConnectError,
        httpx.RemoteProtocolError,
    )
    DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=5.0)
except ImportError:
    httpx = None
    HAS_HTTPX = False
    _RETRY_EXCEPTIONS = (Exception,)
    DEFAULT_TIMEOUT = None

try:
    import structlog
    logger = structlog.get_logger(__name__)
except ImportError:
    logger = logging.getLogger(__name__)

try:
    from tenacity import (
        retry,
        retry_if_exception_type,
        stop_after_attempt,
        wait_exponential,
        before_sleep_log,
    )
except ImportError:
    def retry(*args, **kwargs):
        def decorator(f):
            return f
        return decorator
    def retry_if_exception_type(*args, **kwargs):
        return None
    def wait_exponential(*args, **kwargs):
        return None
    def stop_after_attempt(*args, **kwargs):
        return None
    def before_sleep_log(*args, **kwargs):
        return None

from agent.config import AgentConfig, AGENT_VERSION

# ---------------------------------------------------------------------------
# Retry policy – used for transient network / server errors
# ---------------------------------------------------------------------------

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class _RetryableHTTPError(Exception):
    """Raised internally when a retryable HTTP status is returned."""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class SecureWatchClient:
    """
    Async HTTPS client for the SecureWatch server API.

    Usage::

        async with SecureWatchClient(config) as client:
            await client.send_heartbeat(health_data)
    """

    def __init__(self, config: AgentConfig) -> None:
        self._config = config
        self._client: Optional[httpx.AsyncClient] = None
        # In-memory buffer for events that couldn't be delivered
        self._offline_buffer: List[dict] = []
        self._buffer_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Context-manager helpers
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "SecureWatchClient":
        await self._open()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self._close()

    async def _open(self) -> None:
        if HAS_HTTPX:
            try:
                self._client = httpx.AsyncClient(
                    base_url=self._config.server_url,
                    timeout=DEFAULT_TIMEOUT,
                    verify=True,          # Always verify TLS – never set to False
                    http2=True,
                    headers={
                        "User-Agent": f"SecureWatchAgent/{AGENT_VERSION}",
                        "Accept": "application/json",
                    },
                )
            except Exception:
                self._client = httpx.AsyncClient(
                    base_url=self._config.server_url,
                    timeout=DEFAULT_TIMEOUT,
                    verify=True,
                    http2=False,
                    headers={
                        "User-Agent": f"SecureWatchAgent/{AGENT_VERSION}",
                        "Accept": "application/json",
                    },
                )
        else:
            self._client = object()

    async def _close(self) -> None:
        if HAS_HTTPX and self._client and hasattr(self._client, "aclose"):
            await self._client.aclose()
        self._client = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def enroll(self, enrollment_token_or_payload: Any) -> Dict[str, Any]:
        """
        Enroll this device with the server.
        POST /api/v1/devices/enroll

        Returns the server response dict containing device_id and device_token.
        """
        from agent.collectors.device_info import get_device_info
        if isinstance(enrollment_token_or_payload, dict):
            payload = enrollment_token_or_payload
        else:
            info = get_device_info()
            payload = {
                "enrollment_token": str(enrollment_token_or_payload),
                "hostname": str(info.get("hostname", "unknown")),
                "os_name": str(info.get("os_name", "unknown")),
                "os_version": str(info.get("os_version", "1.0")),
                "os_arch": str(info.get("os_arch", "x86_64")),
                "private_ip": info.get("private_ip"),
                "mac_address": info.get("mac_address"),
                "agent_version": str(info.get("agent_version", AGENT_VERSION)),
                "system_metadata": info,
            }
        resp = await self._request("POST", "/api/v1/devices/enroll", data=payload,
                                   authenticated=False)
        return resp

    async def send_heartbeat(self, health_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Send a heartbeat to signal the agent is alive.
        POST /api/v1/devices/heartbeat
        """
        payload = {
            "device_id": self._config.device_id,
            "timestamp": time.time(),
            "agent_version": AGENT_VERSION,
            **health_data,
        }
        try:
            return await self._request("POST", "/api/v1/devices/heartbeat", data=payload)
        except Exception as exc:
            logger.warning("heartbeat_failed", error=str(exc))
            return None

    async def send_events(self, events: List[Dict[str, Any]]) -> bool:
        """
        Ship a batch of security events to the server.
        POST /api/v1/events/ingest

        Returns True on success. On failure, events are buffered for later
        delivery and False is returned.
        """
        if not events:
            return True

        normalized_events = []
        now_iso = datetime.now(timezone.utc).isoformat()
        for ev in events:
            item = dict(ev)
            ts = item.get("event_timestamp") or item.get("timestamp") or now_iso
            source = item.get("event_source") or item.get("source") or "endpoint_agent"
            cat = item.get("event_category") or item.get("category") or "system"
            ev_type = item.get("event_type") or item.get("type") or "generic_event"
            sev = item.get("severity") or "informational"
            desc = item.get("event_description") or item.get("description") or f"{ev_type} detected"

            norm = {
                "event_timestamp": ts,
                "event_source": str(source)[:64],
                "event_category": str(cat)[:64],
                "event_type": str(ev_type)[:128],
                "severity": str(sev).lower()[:32],
                "event_description": desc,
                "source_ip": item.get("source_ip"),
                "destination_ip": item.get("destination_ip"),
                "process_name": item.get("process_name") or item.get("name"),
                "process_id": item.get("process_id") or item.get("pid"),
                "raw_data": item.get("raw_data") or item,
            }
            normalized_events.append(norm)

        payload = {
            "events": normalized_events,
        }
        try:
            resp = await self._request("POST", "/api/v1/events/ingest", data=payload)
            # Flush any previously buffered events piggy-backed on this call
            await self._flush_offline_buffer()
            return resp if isinstance(resp, dict) else {"accepted": len(events)}
        except Exception as exc:
            logger.warning("event_send_failed_buffering",
                           count=len(events), error=str(exc))
            await self._buffer_events(events)
            return None

    async def refresh_token(self) -> None:
        """
        Refresh the JWT access token using the device credentials.
        POST /api/v1/auth/refresh
        """
        payload = {
            "device_id": self._config.device_id,
            "device_secret": self._config.device_secret,
        }
        resp = await self._request("POST", "/api/v1/auth/refresh",
                                   data=payload, authenticated=False)
        token = resp.get("access_token", "")
        expiry = resp.get("expires_at", 0.0)
        if token:
            self._config.access_token = token
            self._config.token_expiry = float(expiry)
            self._config.save()
            logger.info("token_refreshed", expires_at=expiry)
        else:
            logger.error("token_refresh_no_token", response=resp)
            raise RuntimeError("Token refresh returned no access_token")

    # ------------------------------------------------------------------
    # Internal request machinery
    # ------------------------------------------------------------------

    @retry(
        retry=retry_if_exception_type((_RetryableHTTPError, *_RETRY_EXCEPTIONS)),
        wait=wait_exponential(multiplier=1, min=2, max=60),
        stop=stop_after_attempt(5),
        before_sleep=before_sleep_log(logging.getLogger(__name__), logging.WARNING),
        reraise=True,
    )
    async def _request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        authenticated: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute an authenticated HTTPS request with automatic retry.

        Args:
            method: HTTP verb (GET, POST, etc.)
            path: API path relative to server_url
            data: JSON body payload
            authenticated: Whether to include the JWT Bearer header

        Returns:
            Parsed JSON response body as a dict.

        Raises:
            _RetryableHTTPError: on 429/5xx so tenacity will retry
            httpx.HTTPStatusError: on non-retryable 4xx errors
        """
        if self._client is None:
            await self._open()

        if not HAS_HTTPX:
            base = self._config.server_url.rstrip("/")
            url = f"{base}/{path.lstrip('/')}"
            req_headers = {
                "User-Agent": f"SecureWatchAgent/{AGENT_VERSION}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
            if authenticated and self._config.access_token:
                req_headers["Authorization"] = f"Bearer {self._config.access_token}"

            def _do_sync():
                body = json.dumps(data).encode("utf-8") if data is not None else None
                req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
                try:
                    with urllib.request.urlopen(req, timeout=30) as resp:
                        content = resp.read().decode("utf-8")
                        return json.loads(content) if content else {}
                except urllib.error.HTTPError as e:
                    err_body = e.read().decode("utf-8") if e.fp else ""
                    try:
                        return json.loads(err_body)
                    except Exception:
                        raise RuntimeError(f"HTTP {e.code}: {e.reason} ({err_body})")

            return await asyncio.to_thread(_do_sync)

        headers: Dict[str, str] = {}
        if authenticated and self._config.access_token:
            headers["Authorization"] = f"Bearer {self._config.access_token}"

        response = await self._client.request(  # type: ignore[union-attr]
            method,
            path,
            json=data,
            headers=headers,
        )

        if response.status_code in _RETRYABLE_STATUS:
            raise _RetryableHTTPError(
                f"Retryable HTTP {response.status_code} from {path}"
            )

        response.raise_for_status()

        # Return empty dict for 204 No Content
        if response.status_code == 204 or not response.content:
            return {}

        return response.json()

    # ------------------------------------------------------------------
    # Offline event buffer
    # ------------------------------------------------------------------

    async def _buffer_events(self, events: List[Dict[str, Any]]) -> None:
        """Add events to the in-memory offline buffer (max 10 000 events)."""
        MAX_BUFFER = 10_000
        async with self._buffer_lock:
            self._offline_buffer.extend(events)
            # Evict oldest first if we exceed the cap
            if len(self._offline_buffer) > MAX_BUFFER:
                overflow = len(self._offline_buffer) - MAX_BUFFER
                self._offline_buffer = self._offline_buffer[overflow:]
                logger.warning("offline_buffer_evicted", evicted=overflow)

    async def _flush_offline_buffer(self) -> None:
        """Attempt to deliver buffered events that failed previously."""
        async with self._buffer_lock:
            if not self._offline_buffer:
                return
            to_send = list(self._offline_buffer)
            self._offline_buffer.clear()

        logger.info("flushing_offline_buffer", count=len(to_send))
        payload = {
            "device_id": self._config.device_id,
            "events": to_send,
        }
        try:
            await self._request("POST", "/api/v1/events/ingest", data=payload)
        except Exception as exc:
            logger.warning("offline_flush_failed", error=str(exc))
            # Put them back
            await self._buffer_events(to_send)
