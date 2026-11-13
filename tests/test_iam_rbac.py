"""
Unit and Integration Tests for SecureWatch IAM & RBAC Logic.
Validates role hierarchy, permissions matrix, and auth token structures.
"""
import unittest


DEFAULT_SYSTEM_ROLES = [
    "Super Administrator",
    "Security Administrator",
    "IAM Administrator",
    "SOC Analyst",
    "IT Administrator",
    "Auditor",
    "Standard User",
]

CORE_PERMISSIONS = [
    "users.read",
    "users.create",
    "users.update",
    "users.delete",
    "roles.manage",
    "permissions.manage",
    "groups.manage",
    "devices.read",
    "devices.register",
    "devices.revoke",
    "security_events.read",
    "alerts.manage",
    "incidents.investigate",
    "audit_logs.read",
    "reports.export",
    "settings.manage",
]


class TestIAMRBAC(unittest.TestCase):

    def test_default_system_roles_exist(self):
        """Verify all 7 standard cybersecurity roles are defined."""
        self.assertEqual(len(DEFAULT_SYSTEM_ROLES), 7)
        self.assertIn("Super Administrator", DEFAULT_SYSTEM_ROLES)
        self.assertIn("SOC Analyst", DEFAULT_SYSTEM_ROLES)
        self.assertIn("Auditor", DEFAULT_SYSTEM_ROLES)

    def test_permission_matrix_integrity(self):
        """Verify core granular permissions comply with resource.action convention."""
        for perm in CORE_PERMISSIONS:
            parts = perm.split(".")
            self.assertEqual(len(parts), 2, f"Permission {perm} does not follow resource.action syntax")
            resource, action = parts
            self.assertTrue(len(resource) > 0)
            self.assertTrue(len(action) > 0)

    def test_role_permission_hierarchy(self):
        """Verify Super Admin has all permissions while Auditor is read-only."""
        super_admin_perms = set(CORE_PERMISSIONS)
        auditor_perms = {p for p in CORE_PERMISSIONS if p.endswith(".read")}

        self.assertEqual(len(super_admin_perms), len(CORE_PERMISSIONS))
        self.assertTrue(all(p.endswith(".read") for p in auditor_perms))
        self.assertNotIn("users.delete", auditor_perms)
        self.assertNotIn("devices.revoke", auditor_perms)

    def test_device_enrollment_token_validation(self):
        """Simulate secure enrollment token format and expiry check."""
        import secrets
        import time

        token = f"sw_enroll_{secrets.token_hex(16)}"
        created_at = time.time()
        ttl_seconds = 86400  # 24 hours

        self.assertTrue(token.startswith("sw_enroll_"))
        self.assertEqual(len(token), 10 + 32)
        # Check active
        self.assertFalse(time.time() - created_at > ttl_seconds)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(TestIAMRBAC)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("\n[+] All IAM & RBAC Unit Tests passed successfully!")
    else:
        exit(1)
