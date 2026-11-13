"""
Models package — import all models so Alembic auto-discovers them.
"""
from app.models.users import User, user_roles  # noqa: F401
from app.models.roles import Role, role_permissions  # noqa: F401
from app.models.permissions import Permission  # noqa: F401
from app.models.groups import Group, GroupMember, GroupRole  # noqa: F401
from app.models.devices import Device, DeviceStatus  # noqa: F401
from app.models.device_credentials import DeviceCredential  # noqa: F401
from app.models.enrollment_tokens import EnrollmentToken  # noqa: F401
from app.models.detection_rules import DetectionRule  # noqa: F401
from app.models.security_events import SecurityEvent  # noqa: F401
from app.models.alerts import Alert, AlertNote, AlertSeverity, AlertStatus  # noqa: F401
from app.models.fim_watches import FIMWatch, FIMEvent, FIMChangeType  # noqa: F401
from app.models.audit_logs import AuditLog  # noqa: F401
from app.models.sessions import UserSession, LoginHistory  # noqa: F401

__all__ = [
    "User",
    "user_roles",
    "Role",
    "role_permissions",
    "Permission",
    "Group",
    "GroupMember",
    "GroupRole",
    "Device",
    "DeviceStatus",
    "DeviceCredential",
    "EnrollmentToken",
    "DetectionRule",
    "SecurityEvent",
    "Alert",
    "AlertNote",
    "AlertSeverity",
    "AlertStatus",
    "FIMWatch",
    "FIMEvent",
    "FIMChangeType",
    "AuditLog",
    "UserSession",
    "LoginHistory",
]
