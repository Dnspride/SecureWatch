"""
SecureWatch Endpoint Agent – Event Queue
========================================
In-memory + disk-backed event queue that buffers security events when the
central server is unreachable, ensuring no events are silently dropped.

Design:
  - Thread-safe asyncio.Queue for in-process passing between monitors and
    the flush loop.
  - On graceful shutdown, undelivered events are persisted to a JSON-lines
    spool file so they survive restarts.
  - On startup, any spool file is re-hydrated into the queue.
  - Queue capacity is bounded; when full, the *oldest* events are evicted
    (FIFO drop from head) to make room for newer, more time-relevant data.
  - Flush runs in configurable batches (event_batch_size) every
    event_flush_interval seconds.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import AsyncIterator, List, Optional

try:
    import structlog
    logger = structlog.get_logger(__name__)
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Spool path (persists events across restarts)
# ---------------------------------------------------------------------------

if sys.platform == "win32":
    import os
    _PROGRAMDATA = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
    SPOOL_PATH = Path(_PROGRAMDATA) / "SecureWatch" / "event_spool.jsonl"
else:
    SPOOL_PATH = Path("/var/lib/securewatch/event_spool.jsonl")


class EventQueue:
    """
    Bounded, persistent event queue.

    Parameters
    ----------
    max_size : int
        Maximum number of events held in memory.  Exceeding this causes the
        oldest events to be evicted.
    batch_size : int
        Number of events returned per ``drain_batch()`` call.
    spool_path : Path
        Location of the on-disk spool file.
    """

    def __init__(
        self,
        max_size: int = 10_000,
        batch_size: int = 50,
        spool_path: Path = SPOOL_PATH,
    ) -> None:
        self._max_size = max_size
        self._batch_size = batch_size
        self._spool_path = spool_path
        # Internal deque backed by a list (asyncio.Queue doesn't allow
        # random eviction, so we manage it ourselves with a lock).
        self._events: List[dict] = []
        self._lock: Optional[asyncio.Lock] = None
        self._not_empty: Optional[asyncio.Event] = None

    @property
    def lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    @property
    def not_empty(self) -> asyncio.Event:
        if self._not_empty is None:
            self._not_empty = asyncio.Event()
        return self._not_empty

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def load_spool(self) -> int:
        """
        Re-hydrate undelivered events from the on-disk spool file.
        Returns the number of events loaded.
        """
        if not self._spool_path.exists():
            return 0

        loaded = 0
        try:
            lines = self._spool_path.read_text(encoding="utf-8").splitlines()
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    await self.put(event)
                    loaded += 1
                except json.JSONDecodeError:
                    continue
            # Clear the spool after successful load
            self._spool_path.unlink(missing_ok=True)
            logger.info("spool_loaded", count=loaded)
        except OSError as exc:
            logger.warning("spool_load_failed", error=str(exc))

        return loaded

    async def persist_spool(self) -> int:
        """
        Write all queued events to the on-disk spool file.
        Called on graceful shutdown.  Returns number of events persisted.
        """
        async with self.lock:
            if not self._events:
                return 0
            events = list(self._events)

        try:
            self._spool_path.parent.mkdir(parents=True, exist_ok=True)
            with self._spool_path.open("w", encoding="utf-8") as fh:
                for ev in events:
                    fh.write(json.dumps(ev) + "\n")
            logger.info("spool_persisted", count=len(events))
            return len(events)
        except OSError as exc:
            logger.error("spool_persist_failed", error=str(exc))
            return 0

    # ------------------------------------------------------------------
    # Queue operations
    # ------------------------------------------------------------------

    def put(self, event: dict) -> None:
        """
        Enqueue a single event synchronously. If the queue is full, the oldest event is evicted.
        """
        event.setdefault("queued_at", time.time())
        if len(self._events) >= self._max_size:
            self._events.pop(0)
            logger.debug("queue_eviction", queue_size=self._max_size)
        self._events.append(event)
        if self._not_empty is not None:
            self._not_empty.set()

    def put_many(self, events: List[dict]) -> None:
        """Enqueue multiple events at once."""
        for ev in events:
            self.put(ev)

    async def drain_batch(
        self, timeout: Optional[float] = None
    ) -> List[dict]:
        """
        Wait until at least one event is available, then return up to
        ``batch_size`` events.
        """
        if not self._events and timeout is not None:
            try:
                await asyncio.wait_for(self.not_empty.wait(), timeout=timeout)
            except (TimeoutError, asyncio.TimeoutError):
                return []

        batch = self.get_batch(max_items=self._batch_size)
        return batch

    def get_batch(self, max_items: int = 50, batch_size: int = 50, **kwargs) -> List[dict]:
        """Return up to limit events synchronously."""
        limit = max_items or batch_size or 50
        if not self._events:
            return []
        batch = self._events[:limit]
        self._events = self._events[limit:]
        if not self._events and self._not_empty is not None:
            self._not_empty.clear()
        return batch

    async def drain_all(self) -> List[dict]:
        """Return and clear all queued events (used during shutdown)."""
        async with self.lock:
            events = list(self._events)
            self._events.clear()
            self._not_empty.clear()
        return events

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    @property
    def size(self) -> int:
        """Current number of queued events (non-blocking)."""
        return len(self._events)

    async def __aiter__(self) -> AsyncIterator[List[dict]]:
        """Async iterator that yields batches indefinitely."""
        while True:
            batch = await self.drain_batch(timeout=1.0)
            if batch:
                yield batch
