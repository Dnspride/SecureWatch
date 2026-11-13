"""
Unit tests for RBAC permissions and hash-chained audit integrity.
"""
from __future__ import annotations

import pytest
from app.services.rbac_service import DEFAULT_PERMISSIONS, DEFAULT_ROLES_MAP
from app.services.audit_service import AuditService


def test_default_permissions_completeness():
    expected_categories = {"users", "roles", "groups", "devices", "security_events", "alerts", "incidents", "audit", "reports", "settings"}
    found_categories = {p[3] for p in DEFAULT_PERMISSIONS}
    assert expected_categories.issubset(found_categories)
    assert len(DEFAULT_PERMISSIONS) >= 15


def test_system_roles_permission_mapping():
    assert "Super Administrator" in DEFAULT_ROLES_MAP
    assert "SOC Analyst" in DEFAULT_ROLES_MAP
    assert "Auditor" in DEFAULT_ROLES_MAP

    soc_perms = DEFAULT_ROLES_MAP["SOC Analyst"]
    assert "security_events.read" in soc_perms
    assert "alerts.manage" in soc_perms
    # SOC Analyst should not be able to delete users
    assert "users.delete" not in soc_perms


def test_audit_hash_chain_calculation():
    prev_hash = "0" * 64
    timestamp = "2026-11-10T12:00:00Z"
    h1 = AuditService._compute_hash(
        previous_hash=prev_hash,
        timestamp_str=timestamp,
        actor_id="admin-id",
        action="user.create",
        resource_type="user",
        resource_id="user-123",
        result="success",
        new_value={"username": "alice"},
    )
    assert len(h1) == 64

    # Different inputs yield different hashes
    h2 = AuditService._compute_hash(
        previous_hash=h1,
        timestamp_str=timestamp,
        actor_id="admin-id",
        action="device.enroll",
        resource_type="device",
        resource_id="dev-456",
        result="success",
        new_value={"hostname": "DESKTOP-1"},
    )
    assert h2 != h1
    assert len(h2) == 64
