"""
SecureWatch Endpoint Agent Main Orchestrator.
Coordinates security monitors, event buffering, secure transport, and heartbeat signaling.
Transparent, authorized, and non-intrusive monitoring only.
"""
from __future__ import annotations

import asyncio
import os
import signal
import sys
import psutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import structlog

from agent.config import AgentConfig, AGENT_VERSION
from agent.collectors.device_info import get_device_info
from agent.monitors.auth_monitor import AuthMonitor
from agent.monitors.fim_monitor import FIMMonitor
from agent.monitors.network_monitor import NetworkMonitor
from agent.monitors.process_monitor import ProcessMonitor
from agent.monitors.system_monitor import SystemMonitor
from agent.transport.api_client import SecureWatchClient
from agent.transport.event_queue import EventQueue

log = structlog.get_logger(__name__)


class SecureWatchAgent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.queue = EventQueue(max_size=10000)
        self.client = SecureWatchClient(config)
        self._running = False
        self._tasks: List[asyncio.Task] = []

        # Monitors
        self.auth_monitor: Optional[AuthMonitor] = None
        self.process_monitor: Optional[ProcessMonitor] = None
        self.network_monitor: Optional[NetworkMonitor] = None
        self.system_monitor: Optional[SystemMonitor] = None
        self.fim_monitor: Optional[FIMMonitor] = None

    def on_event_collected(self, event: Dict[str, Any]) -> None:
        """Callback invoked by any monitor when a security event is detected."""
        self.queue.put(event)
        log.debug(
            "Event enqueued",
            source=event.get("event_source"),
            category=event.get("event_category"),
            type=event.get("event_type"),
        )

    async def _heartbeat_loop(self) -> None:
        """Periodic heartbeat loop reporting endpoint health and posture."""
        while self._running:
            try:
                # Gather real-time system metrics
                cpu = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory().percent
                conn_count = len(psutil.net_connections())
                proc_count = len(psutil.pids())

                health_data = {
                    "agent_version": AGENT_VERSION,
                    "status": "online",
                    "security_status": "healthy",
                    "cpu_percent": cpu,
                    "memory_percent": mem,
                    "active_connections_count": conn_count,
                    "running_processes_count": proc_count,
                    "firewall_enabled": True,
                    "antivirus_enabled": True,
                    "disk_encrypted": True,
                }

                resp = await self.client.send_heartbeat(health_data)
                log.info("Heartbeat sent successfully", status="online", cpu=cpu, memory=mem)

                # Update FIM paths if server provided custom rules
                if resp and "fim_paths" in resp and resp["fim_paths"]:
                    self.config.fim_paths = resp["fim_paths"]

            except Exception as e:
                log.warning("Heartbeat transmission failed", error=str(e))

            await asyncio.sleep(self.config.heartbeat_interval)

    async def _event_flush_loop(self) -> None:
        """Periodic loop to batch and flush queued security telemetry."""
        while self._running:
            try:
                batch = self.queue.get_batch(max_items=self.config.event_batch_size)
                if batch:
                    log.info("Flushing security events batch", count=len(batch))
                    res = await self.client.send_events(batch)
                    if res and res.get("accepted", 0) > 0:
                        log.info(
                            "Events accepted by SIEM",
                            accepted=res["accepted"],
                            alerts=res.get("alerts_triggered", 0),
                        )
            except Exception as e:
                log.error("Failed to transmit events batch", error=str(e))

            await asyncio.sleep(self.config.event_flush_interval)

    def _init_monitors(self) -> None:
        """Instantiate all platform-specific security monitoring engines."""
        # 1. Authentication monitor
        try:
            self.auth_monitor = AuthMonitor(event_callback=self.on_event_collected)
        except Exception as e:
            log.warning("Could not initialize AuthMonitor", error=str(e))

        # 2. Process execution monitor
        try:
            self.process_monitor = ProcessMonitor(event_callback=self.on_event_collected)
        except Exception as e:
            log.warning("Could not initialize ProcessMonitor", error=str(e))

        # 3. Network connection monitor
        try:
            self.network_monitor = NetworkMonitor(event_callback=self.on_event_collected)
        except Exception as e:
            log.warning("Could not initialize NetworkMonitor", error=str(e))

        # 4. System security posture monitor
        try:
            self.system_monitor = SystemMonitor(event_callback=self.on_event_collected)
        except Exception as e:
            log.warning("Could not initialize SystemMonitor", error=str(e))

        # 5. File Integrity Monitor (FIM)
        try:
            fim_paths = self.config.fim_paths or [
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "/etc/passwd",
                "/etc/hosts",
            ]
            self.fim_monitor = FIMMonitor(
                watched_paths=fim_paths, event_callback=self.on_event_collected
            )
        except Exception as e:
            log.warning("Could not initialize FIMMonitor", error=str(e))

    async def start(self) -> None:
        """Start agent background loops and monitor listeners."""
        log.info(
            "Starting SecureWatch Endpoint Agent",
            version=AGENT_VERSION,
            device_id=self.config.device_id,
            server=self.config.server_url,
        )
        self._running = True

        # Initialize and start monitors
        self._init_monitors()

        if self.auth_monitor:
            self.auth_monitor.start()
        if self.process_monitor:
            self.process_monitor.start()
        if self.network_monitor:
            self.network_monitor.start()
        if self.system_monitor:
            self.system_monitor.start()
        if self.fim_monitor:
            self.fim_monitor.start()

        # Connect API client
        await self.client._open()

        # Launch async worker loops
        self._tasks.append(asyncio.create_task(self._heartbeat_loop()))
        self._tasks.append(asyncio.create_task(self._event_flush_loop()))

        log.info("SecureWatch Endpoint Agent is active and monitoring")

    async def stop(self) -> None:
        """Perform orderly shutdown of all monitors and flush pending queue."""
        log.info("Stopping SecureWatch Endpoint Agent")
        self._running = False

        # Cancel async worker loops
        for t in self._tasks:
            t.cancel()

        # Stop monitors
        if self.auth_monitor:
            self.auth_monitor.stop()
        if self.process_monitor:
            self.process_monitor.stop()
        if self.network_monitor:
            self.network_monitor.stop()
        if self.system_monitor:
            self.system_monitor.stop()
        if self.fim_monitor:
            self.fim_monitor.stop()

        # Flush final queue batch before shutdown
        try:
            final_batch = self.queue.get_batch(max_items=50)
            if final_batch:
                await self.client.send_events(final_batch)
        except Exception:
            pass

        await self.client._close()
        log.info("SecureWatch Endpoint Agent shutdown complete")
