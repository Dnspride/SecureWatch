"""
Linux Authentication and Journald Normalizer.
Parses syslog, auth.log, pam, sudo, and sshd authentication messages.
"""
from __future__ import annotations

import re
from typing import Any, Dict
from normalizers.base import NormalizedEvent

SSHD_FAIL_REGEX = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)")
SSHD_ACCEPT_REGEX = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)")
SUDO_REGEX = re.compile(r"(\S+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(.*)")


class LinuxAuthNormalizer:
    @staticmethod
    def normalize(raw: Dict[str, Any], device_id: str = "", hostname: str = "") -> NormalizedEvent:
        message = str(raw.get("message") or raw.get("event_description") or "")
        severity = "informational"
        event_type = "auth_event"
        username = raw.get("username")
        source_ip = raw.get("source_ip")
        desc = message or "Linux authentication event"

        # Check SSHD login failure
        fail_match = SSHD_FAIL_REGEX.search(message)
        if fail_match:
            event_type = "ssh_login_failure"
            severity = "medium"
            username = fail_match.group(1)
            source_ip = fail_match.group(2)
            desc = f"Failed SSH login for user '{username}' from {source_ip}"

        # Check SSHD login success
        accept_match = SSHD_ACCEPT_REGEX.search(message)
        if accept_match:
            event_type = "ssh_login_success"
            severity = "informational"
            username = accept_match.group(1)
            source_ip = accept_match.group(2)
            desc = f"Successful SSH login for user '{username}' from {source_ip}"

        # Check sudo execution
        sudo_match = SUDO_REGEX.search(message)
        if sudo_match:
            event_type = "sudo_execution"
            severity = "low"
            actor = sudo_match.group(1)
            target = sudo_match.group(4)
            cmd = sudo_match.group(5)
            username = actor
            desc = f"User '{actor}' ran sudo command '{cmd}' as '{target}'"

        return NormalizedEvent(
            device_id=device_id,
            hostname=hostname or raw.get("hostname", ""),
            event_source="linux_auth",
            event_category="authentication",
            event_type=event_type,
            severity=severity,
            username=username,
            source_ip=source_ip,
            description=desc,
            raw_data=raw,
            tags=["linux", "auth"],
        )
