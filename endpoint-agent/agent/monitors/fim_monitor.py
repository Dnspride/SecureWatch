"""
File Integrity Monitor (FIM): Configurable integrity monitoring using watchdog and SHA-256.
Monitors critical system files and configuration directories for unauthorized modifications.
Never uploads file contents — only tracks path, modification type, and cryptographic hash.
"""
from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

try:
    import structlog
    log = structlog.get_logger(__name__)
except ImportError:
    import logging
    log = logging.getLogger(__name__)

try:
    from watchdog.events import FileSystemEvent, FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    FileSystemEvent = object
    FileSystemEventHandler = object
    Observer = None


def compute_sha256(path: str) -> Optional[str]:
    """Compute SHA-256 hash of a file safely."""
    if not os.path.isfile(path):
        return None
    try:
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        log.warning("Could not compute file hash", path=path, error=str(e))
        return None


class FIMEventHandler(FileSystemEventHandler):
    def __init__(self, callback: Callable[[dict], None]) -> None:
        super().__init__()
        self.callback = callback
        self._last_events: Dict[str, float] = {}

    def _debounce(self, path: str, threshold: float = 1.0) -> bool:
        now = time.time()
        last = self._last_events.get(path, 0)
        if now - last < threshold:
            return False
        self._last_events[path] = now
        return True

    def _emit(self, change_type: str, path: str) -> None:
        if not self._debounce(f"{change_type}:{path}"):
            return

        file_hash = compute_sha256(path) if change_type != "deleted" else None
        event = {
            "event_timestamp": datetime.now(timezone.utc).isoformat(),
            "event_source": "fim_monitor",
            "event_category": "fim",
            "event_type": f"file_{change_type}",
            "severity": "high" if change_type in ("modified", "deleted") else "medium",
            "file_path": path,
            "file_hash": file_hash,
            "event_description": f"File integrity event: {change_type} on {path}",
            "raw_data": {
                "change_type": change_type,
                "file_path": path,
                "file_hash": file_hash,
                "size_bytes": os.path.getsize(path) if os.path.isfile(path) else 0,
            },
        }
        self.callback(event)

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._emit("created", event.src_path)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._emit("modified", event.src_path)

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._emit("deleted", event.src_path)


class FIMMonitor:
    def __init__(
        self,
        watched_paths: List[str],
        event_callback: Callable[[dict], None],
    ) -> None:
        self.watched_paths = watched_paths
        self.callback = event_callback
        self.observer = Observer()
        self.handler = FIMEventHandler(event_callback)
        self._running = False

    def start(self) -> None:
        for p in self.watched_paths:
            if os.path.exists(p):
                if os.path.isdir(p):
                    self.observer.schedule(self.handler, p, recursive=False)
                    log.info("FIM watching directory", path=p)
                else:
                    parent_dir = os.path.dirname(p)
                    self.observer.schedule(self.handler, parent_dir, recursive=False)
                    log.info("FIM watching file", path=p)

        self.observer.start()
        self._running = True
        log.info("FIM Monitor started", total_targets=len(self.watched_paths))

    def stop(self) -> None:
        if self._running:
            self.observer.stop()
            self.observer.join(timeout=3)
            self._running = False
            log.info("FIM Monitor stopped")
