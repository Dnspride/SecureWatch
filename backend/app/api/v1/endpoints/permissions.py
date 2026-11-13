"""
Permission API Endpoints: Granular permission catalog.
"""
from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.permissions import Permission
from app.models.users import User
from app.schemas.permissions import PermissionGroupedByCategory, PermissionResponse
from app.services.auth_service import require_permission

router = APIRouter(prefix="/permissions", tags=["Permissions"])


@router.get("", response_model=List[PermissionResponse], summary="List all permissions")
async def list_permissions(
    current_user: User = Depends(require_permission("permissions.manage")),
    db: AsyncSession = Depends(get_db),
) -> List[Permission]:
    stmt = select(Permission).order_by(Permission.category.asc(), Permission.code.asc())
    res = await db.execute(stmt)
    return list(res.scalars().all())


@router.get("/grouped", response_model=List[PermissionGroupedByCategory], summary="List permissions grouped by category")
async def list_permissions_grouped(
    current_user: User = Depends(require_permission("permissions.manage")),
    db: AsyncSession = Depends(get_db),
) -> List[PermissionGroupedByCategory]:
    stmt = select(Permission).order_by(Permission.category.asc(), Permission.code.asc())
    res = await db.execute(stmt)
    all_perms = list(res.scalars().all())

    categories: dict[str, list[Permission]] = {}
    for p in all_perms:
        categories.setdefault(p.category, []).append(p)

    return [
        PermissionGroupedByCategory(category=cat, permissions=perms)
        for cat, perms in categories.items()
    ]
