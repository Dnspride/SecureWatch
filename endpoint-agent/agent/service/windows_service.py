"""
Windows Service wrapper for SecureWatch Endpoint Agent.
Allows running the agent as an automatic background service with service manager controls.
"""
from __future__ import annotations

import asyncio
import os
import sys
import structlog

log = structlog.get_logger(__name__)

try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False


class SecureWatchWindowsService:
    """Service framework stub/implementation for Windows."""
    _svc_name_ = "SecureWatchAgent"
    _svc_display_name_ = "SecureWatch Endpoint Security Agent"
    _svc_description_ = "Continuous endpoint security telemetry, EDR monitoring, and SIEM event collection."

    def __init__(self, args=None) -> None:
        if HAS_WIN32:
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.agent = None

    def SvcStop(self) -> None:
        if HAS_WIN32:
            win32serviceutil.ReportServiceStatus(
                self._svc_name_, win32service.SERVICE_STOP_PENDING
            )
            win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self) -> None:
        from agent.config import AgentConfig
        from agent.agent import SecureWatchAgent

        config = AgentConfig.load()
        if not config:
            log.error("Could not load agent configuration. Service exiting.")
            return

        async def _main():
            self.agent = SecureWatchAgent(config)
            await self.agent.start()
            while True:
                await asyncio.sleep(1)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_main())
        except (KeyboardInterrupt, SystemExit):
            if self.agent:
                loop.run_until_complete(self.agent.stop())


if __name__ == "__main__" and HAS_WIN32:
    win32serviceutil.HandleCommandLine(SecureWatchWindowsService)
