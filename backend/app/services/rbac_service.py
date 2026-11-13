"""
RBAC Service: Granular role, permission, and access control management.
"""
from __future__ import annotations

from typing import List, Optional, Set
from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
import structlog

from app.models.groups import GroupMember, GroupRole
from app.models.permissions import Permission
from app.models.roles import Role, role_permissions
from app.models.users import User, user_roles
from app.schemas.roles import RoleCreate, RoleUpdate

log = structlog.get_logger(__name__)

DEFAULT_PERMISSIONS = [
    # Users
    ("users.read", "Read Users", "View user accounts and profiles", "users"),
    ("users.create", "Create Users", "Create new user accounts", "users"),
    ("users.update", "Update Users", "Modify existing user accounts", "users"),
    ("users.delete", "Delete Users", "Deactivate or delete user accounts", "users"),
    # Roles & Permissions
    ("roles.manage", "Manage Roles", "Create, update, and assign RBAC roles", "roles"),
    ("permissions.manage", "Manage Permissions", "View and configure system permissions", "roles"),
    # Groups
    ("groups.manage", "Manage Groups", "Create and manage organizational groups", "groups"),
    # Devices
    ("devices.read", "Read Devices", "View enrolled devices and their telemetry", "devices"),
    ("devices.register", "Register Devices", "Generate enrollment tokens and register devices", "devices"),
    ("devices.revoke", "Revoke Devices", "Revoke or quarantine endpoint devices", "devices"),
    # Security Events & SIEM
    ("security_events.read", "Read Events", "View SIEM security events and log entries", "security_events"),
    # Alerts & Incidents
    ("alerts.manage", "Manage Alerts", "Acknowledge, assign, and update security alerts", "alerts"),
    ("incidents.investigate", "Investigate Incidents", "Perform deep dive incident triage", "incidents"),
    # Audit & Reports
    ("audit_logs.read", "Read Audit Logs", "View system audit trail", "audit"),
    ("reports.export", "Export Reports", "Generate and download security posture reports", "reports"),
    # Settings
    ("settings.manage", "Manage Settings", "Configure system security policies and detection rules", "settings"),
]

DEFAULT_ROLES_MAP = {
    "Super Administrator": [p[0] for p in DEFAULT_PERMISSIONS],
    "Security Administrator": [
        "users.read", "devices.read", "devices.register", "devices.revoke",
        "security_events.read", "alerts.manage", "incidents.investigate",
        "audit_logs.read", "reports.export", "settings.manage"
    ],
    "IAM Administrator": [
        "users.read", "users.create", "users.update", "users.delete",
        "roles.manage", "permissions.manage", "groups.manage",
        "audit_logs.read", "reports.export"
    ],
    "SOC Analyst": [
        "users.read", "devices.read", "security_events.read",
        "alerts.manage", "incidents.investigate", "reports.export"
    ],
    "IT Administrator": [
        "users.read", "devices.read", "devices.register", "devices.revoke"
    ],
    "Auditor": [
        "users.read", "devices.read", "security_events.read",
        "audit_logs.read", "reports.export"
    ],
    "Standard User": []
}


class RBACService:
    @classmethod
    async def seed_defaults(cls, db: AsyncSession) -> None:
        """Seed default permissions and system roles if not present."""
        # 1. Seed permissions
        existing_perms_res = await db.execute(select(Permission))
        existing_perms = {p.code: p for p in existing_perms_res.scalars().all()}

        for code, name, desc, cat in DEFAULT_PERMISSIONS:
            if code not in existing_perms:
                perm = Permission(code=code, name=name, description=desc, category=cat)
                db.add(perm)
                existing_perms[code] = perm
        await db.flush()

        # 2. Seed system roles
        existing_roles_res = await db.execute(select(Role).options(selectinload(Role.permissions)))
        existing_roles = {r.name: r for r in existing_roles_res.scalars().all()}

        for role_name, perm_codes in DEFAULT_ROLES_MAP.items():
            if role_name not in existing_roles:
                role = Role(
                    name=role_name,
                    description=f"System predefined role: {role_name}",
                    is_system_role=True,
                    is_active=True,
                )
                role.permissions = [existing_perms[c] for c in perm_codes if c in existing_perms]
                db.add(role)
            else:
                role = existing_roles[role_name]
                if role.is_system_role:
                    # Sync permissions for system roles
                    target_perms = [existing_perms[c] for c in perm_codes if c in existing_perms]
                    role.permissions = target_perms

        await db.commit()
        log.info("Default RBAC permissions and roles verified and seeded")

    @classmethod
    async def get_user_permissions(cls, db: AsyncSession, user_id: UUID) -> Set[str]:
        """
        Aggregate all permission codes for a user from both direct roles and group roles.
        """
        # Check if superuser
        user_res = await db.execute(select(User).where(User.id == user_id))
        user = user_res.scalar_one_or_none()
        if not user or not user.is_active or user.is_locked:
            return set()
        if user.is_superuser:
            all_p_res = await db.execute(select(Permission.code))
            return set(all_p_res.scalars().all())

        permissions: Set[str] = set()

        # 1. Direct user roles
        stmt_user_roles = (
            select(Permission.code)
            .join(role_permissions, Permission.id == role_permissions.c.permission_id)
            .join(Role, Role.id == role_permissions.c.role_id)
            .join(user_roles, user_roles.c.role_id == Role.id)
            .where(user_roles.c.user_id == user_id, Role.is_active.is_(True))
        )
        res_direct = await db.execute(stmt_user_roles)
        permissions.update(res_direct.scalars().all())

        # 2. Roles inherited via groups
        stmt_group_roles = (
            select(Permission.code)
            .join(role_permissions, Permission.id == role_permissions.c.permission_id)
            .join(Role, Role.id == role_permissions.c.role_id)
            .join(GroupRole, GroupRole.role_id == Role.id)
            .join(GroupMember, GroupMember.group_id == GroupRole.group_id)
            .where(GroupMember.user_id == user_id, Role.is_active.is_(True))
        )
        res_group = await db.execute(stmt_group_roles)
        permissions.update(res_group.scalars().all())

        return permissions

    @classmethod
    async def has_permission(cls, db: AsyncSession, user_id: UUID, permission_code: str) -> bool:
        """Check if user has specific granular permission."""
        perms = await cls.get_user_permissions(db, user_id)
        return permission_code in perms

    @classmethod
    async def get_roles(cls, db: AsyncSession) -> List[Role]:
        stmt = select(Role).options(selectinload(Role.permissions)).order_by(Role.name.asc())
        res = await db.execute(stmt)
        return list(res.scalars().all())

    @classmethod
    async def get_role_by_id(cls, db: AsyncSession, role_id: UUID) -> Optional[Role]:
        stmt = select(Role).options(selectinload(Role.permissions)).where(Role.id == role_id)
        res = await db.execute(stmt)
        return res.scalar_one_or_none()

    @classmethod
    async def create_role(cls, db: AsyncSession, data: RoleCreate) -> Role:
        role = Role(
            name=data.name,
            description=data.description,
            is_active=data.is_active,
            is_system_role=False,
        )
        if data.permission_ids:
            stmt = select(Permission).where(Permission.id.in_(data.permission_ids))
            res = await db.execute(stmt)
            role.permissions = list(res.scalars().all())
        db.add(role)
        await db.flush()
        refreshed = await cls.get_role_by_id(db, role.id)
        return refreshed or role

    @classmethod
    async def update_role(cls, db: AsyncSession, role: Role, data: RoleUpdate) -> Role:
        if data.name is not None and not role.is_system_role:
            role.name = data.name
        if data.description is not None:
            role.description = data.description
        if data.is_active is not None and not role.is_system_role:
            role.is_active = data.is_active

        if data.permission_ids is not None:
            stmt = select(Permission).where(Permission.id.in_(data.permission_ids))
            res = await db.execute(stmt)
            role.permissions = list(res.scalars().all())

        await db.flush()
        refreshed = await cls.get_role_by_id(db, role.id)
        return refreshed or role

    @classmethod
    async def delete_role(cls, db: AsyncSession, role: Role) -> bool:
        if role.is_system_role:
            raise ValueError("System predefined roles cannot be deleted.")
        await db.execute(delete(GroupRole).where(GroupRole.role_id == role.id))
        await db.delete(role)
        await db.flush()
        return True
