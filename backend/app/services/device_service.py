"""
Device Management Service: Enrollment workflows, device credentials, heartbeat tracking, and risk scoring.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
import structlog

from app.core.config import settings
from app.core.security import (
    create_device_token,
    generate_enrollment_token,
    hash_enrollment_token,
    hash_token,
)
from app.models.alerts import Alert, AlertSeverity, AlertStatus
from app.models.device_credentials import DeviceCredential
from app.models.devices import Device, DeviceStatus
from app.models.enrollment_tokens import EnrollmentToken
from app.models.users import User
from app.schemas.devices import (
    DeviceEnrollRequest,
    DeviceEnrollResponse,
    DeviceHeartbeatRequest,
    DeviceHeartbeatResponse,
    EnrollmentTokenCreate,
)
from app.services.audit_service import AuditService

log = structlog.get_logger(__name__)


class DeviceService:
    @classmethod
    async def create_enrollment_token(
        cls,
        db: AsyncSession,
        data: EnrollmentTokenCreate,
        actor: Optional[User] = None,
    ) -> Tuple[EnrollmentToken, str]:
        """Generate a cryptographically secure, one-time enrollment token."""
        plain_token, token_hash = generate_enrollment_token()
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=data.hours_valid)

        creator_id = actor.id if actor else None
        if not creator_id:
            admin_stmt = select(User.id).where(User.username == "admin")
            creator_id = (await db.execute(admin_stmt)).scalar_one_or_none()

        token_record = EnrollmentToken(
            token_hash=token_hash,
            created_by=creator_id,
            created_at=now,
            expires_at=expires_at,
            is_used=False,
            requires_approval=data.requires_approval,
        )
        db.add(token_record)
        await db.flush()

        await AuditService.log_action(
            db,
            action="device.enrollment_token_created",
            resource_type="enrollment_token",
            resource_id=str(token_record.id),
            actor_id=creator_id,
            actor_username=actor.username if actor else "admin",
            new_value={"expires_at": expires_at.isoformat(), "requires_approval": data.requires_approval},
        )
        await db.commit()
        await db.refresh(token_record)
        return token_record, plain_token

    @classmethod
    async def enroll_device(
        cls,
        db: AsyncSession,
        data: DeviceEnrollRequest,
        client_ip: Optional[str] = None,
    ) -> DeviceEnrollResponse:
        """
        Authenticate enrollment request using the one-time token,
        provision the device record, issue device credential token,
        and establish baseline posture.
        """
        token_hash = hash_enrollment_token(data.enrollment_token)
        now = datetime.now(timezone.utc)

        stmt = select(EnrollmentToken).where(
            EnrollmentToken.token_hash == token_hash,
            EnrollmentToken.is_used.is_(False),
            EnrollmentToken.expires_at > now,
        )
        res = await db.execute(stmt)
        token_record = res.scalar_one_or_none()

        if not token_record:
            log.warning("Invalid or expired enrollment token attempted", client_ip=client_ip)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid, expired, or already used enrollment token",
            )

        # Mark token as consumed
        token_record.is_used = True

        # Determine initial device status
        initial_status = (
            DeviceStatus.pending_approval
            if token_record.requires_approval
            else DeviceStatus.online
        )

        device = Device(
            hostname=data.hostname,
            os_name=data.os_name,
            os_version=data.os_version,
            os_arch=data.os_arch,
            private_ip=data.private_ip or client_ip,
            public_ip=client_ip,
            mac_address=data.mac_address,
            agent_version=data.agent_version,
            enrollment_date=now,
            last_heartbeat=now,
            status=initial_status,
            security_status="healthy",
            risk_score=0.0,
            enrollment_token_id=token_record.id,
        )
        db.add(device)
        await db.flush()

        token_record.used_by_device_id = device.id

        # Generate unique per-device credential secret & JWT
        device_secret = secrets.token_hex(32)
        device_cred_hash = hash_token(device_secret)
        device_token = create_device_token(
            device_id=str(device.id),
            hostname=device.hostname,
            device_secret=settings.SECRET_KEY,
        )

        cred_record = DeviceCredential(
            device_id=device.id,
            credential_hash=device_cred_hash,
            is_active=True,
            issued_at=now,
            expires_at=now + timedelta(days=90),
            last_used_at=now,
        )
        db.add(cred_record)
        await db.flush()

        await AuditService.log_action(
            db,
            action="device.enrolled",
            resource_type="device",
            resource_id=str(device.id),
            source_ip=client_ip,
            result="success",
            new_value={
                "hostname": device.hostname,
                "os": f"{device.os_name} {device.os_version}",
                "status": device.status.value,
            },
        )
        await db.commit()

        return DeviceEnrollResponse(
            device_id=device.id,
            device_token=device_token,
            server_time=now,
            status=device.status,
            heartbeat_interval=60,
            approved=not token_record.requires_approval,
        )

    @classmethod
    async def process_heartbeat(
        cls,
        db: AsyncSession,
        device_id: UUID,
        data: DeviceHeartbeatRequest,
        client_ip: Optional[str] = None,
    ) -> DeviceHeartbeatResponse:
        """Update last heartbeat timestamp and endpoint health telemetry."""
        stmt = select(Device).where(Device.id == device_id)
        res = await db.execute(stmt)
        device = res.scalar_one_or_none()

        if not device:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

        if device.status == DeviceStatus.revoked:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Device access has been revoked by security administrator",
            )

        now = datetime.now(timezone.utc)
        device.last_heartbeat = now
        if client_ip:
            device.public_ip = client_ip
        if data.agent_version:
            device.agent_version = data.agent_version

        # Update status if it was offline or unhealthy
        if device.status not in (DeviceStatus.pending_approval, DeviceStatus.critical):
            device.status = DeviceStatus.online

        # Calculate security posture from reported health
        if (data.firewall_enabled is False) or (data.antivirus_enabled is False):
            device.security_status = "warning"
            device.risk_score = max(device.risk_score, 45.0)
        else:
            device.security_status = "healthy"

        await db.commit()

        # Return standard monitored FIM paths
        fim_paths = [
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/hosts",
            "/etc/crontab",
        ]
        return DeviceHeartbeatResponse(status="ok", fim_paths=fim_paths)

    @classmethod
    async def approve_device(
        cls, db: AsyncSession, device_id: UUID, actor: Optional[User] = None
    ) -> Device:
        stmt = select(Device).where(Device.id == device_id)
        res = await db.execute(stmt)
        device = res.scalar_one_or_none()
        if not device:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

        device.status = DeviceStatus.online
        await AuditService.log_action(
            db,
            action="device.approve",
            resource_type="device",
            resource_id=str(device.id),
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
        )
        await db.commit()
        return device

    @classmethod
    async def revoke_device(
        cls,
        db: AsyncSession,
        device_id: UUID,
        reason: Optional[str] = None,
        actor: Optional[User] = None,
    ) -> Device:
        """Revoke device credentials and quarantine endpoint communication."""
        stmt = select(Device).options(selectinload(Device.credentials)).where(Device.id == device_id)
        res = await db.execute(stmt)
        device = res.scalar_one_or_none()
        if not device:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

        device.status = DeviceStatus.revoked

        # Invalidate all credentials for this device
        for cred in device.credentials:
            cred.is_active = False

        await AuditService.log_action(
            db,
            action="device.revoke",
            resource_type="device",
            resource_id=str(device.id),
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
            new_value={"reason": reason or "Administrative revocation"},
        )
        await db.commit()
        return device

    @classmethod
    async def rotate_credentials(
        cls,
        db: AsyncSession,
        device_id: UUID,
        reason: Optional[str] = None,
        actor: Optional[User] = None,
    ) -> Device:
        stmt = select(Device).options(selectinload(Device.credentials), selectinload(Device.owner)).where(Device.id == device_id)
        res = await db.execute(stmt)
        device = res.scalar_one_or_none()
        if not device:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

        for cred in device.credentials:
            cred.is_active = False

        now = datetime.now(timezone.utc)
        new_secret = secrets.token_hex(32)
        cred = DeviceCredential(
            device_id=device.id,
            credential_hash=hash_token(new_secret),
            is_active=True,
            issued_at=now,
            expires_at=now + timedelta(days=90),
            last_used_at=now,
        )
        db.add(cred)

        await AuditService.log_action(
            db,
            action="device.rotate_credentials",
            resource_type="device",
            resource_id=str(device.id),
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
            new_value={"reason": reason or "Administrative key rotation"},
        )
        await db.commit()
        refreshed = await cls.get_by_id(db, device_id)
        return refreshed or device

    @classmethod
    async def get_devices(
        cls,
        db: AsyncSession,
        *,
        status_filter: Optional[str] = None,
        search: Optional[str] = None,
        department: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> Tuple[List[Device], int]:
        query = select(Device).options(selectinload(Device.owner))

        if status_filter:
            try:
                st = DeviceStatus(status_filter)
                query = query.where(Device.status == st)
            except ValueError:
                pass

        if search:
            sf = f"%{search.strip()}%"
            query = query.where(
                or_(
                    Device.hostname.ilike(sf),
                    Device.private_ip.ilike(sf),
                    Device.public_ip.ilike(sf),
                    Device.os_name.ilike(sf),
                )
            )

        if department:
            query = query.where(Device.department == department)

        count_stmt = select(func.count()).select_from(query.subquery())
        count_res = await db.execute(count_stmt)
        total = count_res.scalar_one()

        query = query.order_by(Device.last_heartbeat.desc().nullslast()).offset((page - 1) * page_size).limit(page_size)
        res = await db.execute(query)
        devices = list(res.scalars().all())

        return devices, total

    @classmethod
    async def get_by_id(cls, db: AsyncSession, device_id: UUID) -> Optional[Device]:
        stmt = select(Device).options(selectinload(Device.owner)).where(Device.id == device_id)
        res = await db.execute(stmt)
        return res.scalar_one_or_none()

    @classmethod
    async def detect_offline_devices(cls, db: AsyncSession, timeout_seconds: int = 300) -> int:
        """Check all active devices and mark offline if no heartbeat within timeout."""
        threshold = datetime.now(timezone.utc) - timedelta(seconds=timeout_seconds)
        stmt = select(Device).where(
            Device.status == DeviceStatus.online,
            or_(Device.last_heartbeat < threshold, Device.last_heartbeat.is_(None)),
        )
        res = await db.execute(stmt)
        offline_devices = res.scalars().all()

        count = 0
        for dev in offline_devices:
            dev.status = DeviceStatus.offline
            count += 1

        if count > 0:
            await db.commit()
            log.info("Detected and updated offline devices", count=count)
        return count

    @classmethod
    async def compute_risk_score(cls, db: AsyncSession, device_id: UUID) -> float:
        """Calculate weighted risk score based on active alerts and health."""
        stmt = select(Alert).where(
            Alert.device_id == device_id,
            Alert.status.in_([AlertStatus.new, AlertStatus.acknowledged, AlertStatus.investigating]),
        )
        res = await db.execute(stmt)
        active_alerts = res.scalars().all()

        score = 0.0
        for alert in active_alerts:
            if alert.severity == AlertSeverity.critical:
                score += 35.0
            elif alert.severity == AlertSeverity.high:
                score += 20.0
            elif alert.severity == AlertSeverity.medium:
                score += 10.0
            elif alert.severity == AlertSeverity.low:
                score += 3.0

        # Cap score at 100.0
        score = min(score, 100.0)

        dev_stmt = select(Device).where(Device.id == device_id)
        dev_res = await db.execute(dev_stmt)
        device = dev_res.scalar_one_or_none()
        if device:
            device.risk_score = score
            if score >= 70:
                device.status = DeviceStatus.critical
            elif score >= 40 and device.status == DeviceStatus.online:
                device.status = DeviceStatus.unhealthy
            await db.commit()

        return score
