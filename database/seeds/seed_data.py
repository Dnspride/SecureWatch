"""
Database Seeding Script for SecureWatch.
Seeds default permissions, roles, and initial super administrator user.
Run with: python -m database.seeds.seed_data
"""
from __future__ import annotations

import asyncio
import os
import sys

# Ensure backend root is on path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend"))
sys.path.insert(0, backend_path)

from app.core.database import async_session_factory, init_db
from app.services.rbac_service import RBACService
from app.services.user_service import UserService
from app.schemas.users import UserCreate


async def run_seed():
    print("[*] Initializing database tables...")
    await init_db()

    print("[*] Seeding default RBAC permissions and system roles...")
    async with async_session_factory() as session:
        await RBACService.seed_defaults(session)

        # Check / create Super Admin
        admin = await UserService.get_by_username(session, "admin")
        if not admin:
            print("[*] Creating default Platform Super Administrator: admin")
            await UserService.create_user(
                session,
                UserCreate(
                    username="admin",
                    email="admin@securewatch.io",
                    full_name="Platform Administrator",
                    password=os.getenv("ADMIN_PASSWORD", "SecureWatch@2026!"),
                    department="Cybersecurity Operations",
                    is_active=True,
                    is_superuser=True,
                ),
            )
            print("[+] Super Administrator 'admin' created successfully.")
        else:
            print("[*] Super Administrator 'admin' already exists.")

    print("[+] Seeding completed successfully.")


if __name__ == "__main__":
    asyncio.run(run_seed())
