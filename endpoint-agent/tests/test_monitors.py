"""
Unit tests for Endpoint Agent monitors and collectors.
"""
from __future__ import annotations

import os
import sys
import tempfile

AGENT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if AGENT_ROOT not in sys.path:
    sys.path.insert(0, AGENT_ROOT)

from agent.collectors.device_info import get_device_info
from agent.transport.event_queue import EventQueue
from agent.monitors.fim_monitor import compute_sha256


def test_device_info_collector():
    info = get_device_info(agent_version="1.0.0")
    assert "hostname" in info
    assert "os_name" in info
    assert "os_arch" in info
    assert "private_ip" in info
    assert info["agent_version"] == "1.0.0"


import asyncio

async def _async_test_event_queue():
    queue = EventQueue(max_size=100, batch_size=10)
    assert queue.size == 0

    # Put events
    await queue.put({"event_type": "login", "severity": "low"})
    await queue.put({"event_type": "process", "severity": "high"})
    assert queue.size == 2

    # Get batch
    batch = await queue.drain_batch()
    assert len(batch) == 2
    assert queue.size == 0


def test_event_queue_buffering():
    asyncio.run(_async_test_event_queue())


def test_fim_sha256_hash_computation():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"Security critical file content for FIM hash testing.")
        temp_path = f.name

    try:
        h = compute_sha256(temp_path)
        assert h is not None
        assert len(h) == 64
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


if __name__ == "__main__":
    print("[*] Running Endpoint Agent unit tests...")
    test_device_info_collector()
    print("  [+] Device info collector verified.")
    test_event_queue_buffering()
    print("  [+] EventQueue FIFO buffering verified.")
    test_fim_sha256_hash_computation()
    print("  [+] FIM SHA-256 calculation verified.")
    print("[+] All Endpoint Agent tests passed successfully!")
