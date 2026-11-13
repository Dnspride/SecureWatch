"""
Linux Daemon wrapper for SecureWatch Endpoint Agent.
Handles SIGTERM/SIGINT, writes PID files, and logs to systemd journal.
"""
from __future__ import annotations

import asyncio
import os
import signal
import sys
import structlog

log = structlog.get_logger(__name__)

PID_FILE = "/var/run/securewatch-agent.pid"


def write_pid_file() -> None:
    try:
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))
    except Exception as e:
        log.warning("Could not write PID file", path=PID_FILE, error=str(e))


def remove_pid_file() -> None:
    try:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
    except Exception:
        pass


def run_linux_service() -> None:
    from agent.config import AgentConfig
    from agent.agent import SecureWatchAgent

    config = AgentConfig.load()
    if not config:
        log.error("Could not load configuration at /etc/securewatch/config.json")
        sys.exit(1)

    write_pid_file()

    agent = SecureWatchAgent(config)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def _sig_handler(sig, frame):
        log.info("Received stop signal", signal=sig)
        loop.create_task(agent.stop())
        remove_pid_file()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _sig_handler)
    signal.signal(signal.SIGINT, _sig_handler)

    try:
        loop.run_until_complete(agent.start())
        loop.run_forever()
    except (KeyboardInterrupt, SystemExit):
        loop.run_until_complete(agent.stop())
    finally:
        remove_pid_file()
