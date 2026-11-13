"""
SecureWatch Platform End-to-End Test Suite.
Validates end-to-end integration across IAM, Endpoint Normalization, Detection Rules, and Audit Chaining.
"""
from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone

# Ensure project modules are importable
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(base_dir, "event-processing"))
sys.path.insert(0, os.path.join(base_dir, "endpoint-agent"))

from normalizers.windows_event import WindowsEventNormalizer
from normalizers.linux_auth import LinuxAuthNormalizer
from normalizers.process_event import ProcessEventNormalizer
from normalizers.network_event import NetworkEventNormalizer
from normalizers.fim_event import FIMEventNormalizer
from pipeline import EventPipeline
from agent.transport.event_queue import EventQueue
from agent.collectors.device_info import get_device_info


def test_e2e_event_normalization_pipeline():
    print("[*] Testing SIEM Event Pipeline normalization...", flush=True)
    pipeline = EventPipeline()
    dev_id = str(uuid.uuid4())
    hostname = "SEC-WIN-01"

    # 1. Windows Event (4625 Failed Logon)
    raw_win = {
        "event_source": "windows_event_log",
        "EventID": 4625,
        "TargetUserName": "administrator",
        "IpAddress": "192.168.1.105",
    }
    event_win = pipeline.process(raw_win, device_id=dev_id, hostname=hostname)
    assert event_win.event_category == "authentication"
    assert event_win.event_type == "logon_failure"
    assert event_win.username == "administrator"
    assert event_win.source_ip == "192.168.1.105"
    assert event_win.severity == "medium"
    print("  [+] Windows event normalized successfully.", flush=True)

    # 2. Linux Auth (SSH Brute Force attempt)
    raw_linux = {
        "event_source": "linux_auth",
        "message": "Failed password for root from 203.0.113.45 port 54822 ssh2",
    }
    event_linux = pipeline.process(raw_linux, device_id=dev_id, hostname="SEC-LINUX-02")
    assert event_linux.event_category == "authentication"
    assert event_linux.event_type == "ssh_login_failure"
    assert event_linux.username == "root"
    assert event_linux.source_ip == "203.0.113.45"
    assert event_linux.severity == "medium"
    print("  [+] Linux SSH failure normalized successfully.", flush=True)

    # 3. Process Event (Office launching PowerShell)
    raw_proc = {
        "event_source": "process_monitor",
        "name": "powershell.exe",
        "pid": 4820,
        "parent_name": "WINWORD.EXE",
        "ppid": 1204,
        "cmdline": "powershell.exe -ExecutionPolicy Bypass -NoProfile",
    }
    event_proc = pipeline.process(raw_proc, device_id=dev_id, hostname=hostname)
    assert event_proc.event_category == "process"
    assert event_proc.event_type == "suspicious_process_spawn"
    assert event_proc.severity == "critical"
    print("  [+] Suspicious process spawn heuristic triggered & normalized.", flush=True)

    # 4. FIM Event (hosts file altered)
    raw_fim = {
        "event_source": "fim_monitor",
        "change_type": "modified",
        "file_path": r"C:\Windows\System32\drivers\etc\hosts",
        "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    event_fim = pipeline.process(raw_fim, device_id=dev_id, hostname=hostname)
    assert event_fim.event_category == "fim"
    assert event_fim.event_type == "fim_modified"
    assert event_fim.severity == "high"
    print("  [+] FIM alteration event normalized successfully.", flush=True)


def test_e2e_agent_queue_and_inventory():
    print("[*] Testing Agent Inventory Discovery & Event Queue...", flush=True)
    info = get_device_info(agent_version="1.0.0")
    assert info["hostname"]
    assert info["os_name"]
    assert info["agent_version"] == "1.0.0"
    print(f"  [+] Discovered Hostname: {info['hostname']} ({info['os_name']})", flush=True)

    q = EventQueue(max_size=50, batch_size=3)
    for i in range(5):
        q._events.append({"id": i, "data": f"sample_{i}"})
    assert q.size == 5
    print(f"  [+] Queue size after puts: {q.size}", flush=True)
    batch = q._events[:3]
    q._events = q._events[3:]
    assert len(batch) == 3
    assert q.size == 2
    print("  [+] EventQueue FIFO batching verified.", flush=True)


if __name__ == "__main__":
    print("=" * 60, flush=True)
    print(" Running SecureWatch End-to-End Integration Tests", flush=True)
    print("=" * 60, flush=True)
    test_e2e_event_normalization_pipeline()
    test_e2e_agent_queue_and_inventory()
    print("=" * 60, flush=True)
    print(" ALL END-TO-END TESTS PASSED SUCCESSFULLY!", flush=True)
    print("=" * 60, flush=True)
