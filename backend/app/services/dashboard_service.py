"""
Dashboard Service: Aggregates real-time SOC metrics, alert distributions, and telemetry trends.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.alerts import Alert, AlertSeverity, AlertStatus
from app.models.audit_logs import AuditLog
from app.models.devices import Device, DeviceStatus
from app.models.login_history import LoginHistory
from app.models.security_events import SecurityEvent
from app.models.users import User
from app.schemas.alerts import AlertResponse
from app.schemas.dashboard import DashboardStats


class DashboardService:
    @classmethod
    async def get_stats(cls, db: AsyncSession) -> DashboardStats:
        now = datetime.now(timezone.utc)
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        day_ago = now - timedelta(days=1)

        # 1. User stats
        u_total = (await db.execute(select(func.count(User.id)))).scalar_one()
        u_active = (await db.execute(select(func.count(User.id)).where(User.is_active.is_(True)))).scalar_one()

        # 2. Device stats
        d_total = (await db.execute(select(func.count(Device.id)))).scalar_one()
        d_online = (await db.execute(select(func.count(Device.id)).where(Device.status == DeviceStatus.online))).scalar_one()
        d_offline = (await db.execute(select(func.count(Device.id)).where(Device.status == DeviceStatus.offline))).scalar_one()
        d_issues = (await db.execute(
            select(func.count(Device.id)).where(Device.status.in_([DeviceStatus.unhealthy, DeviceStatus.critical]))
        )).scalar_one()

        # 3. Alert stats (active/unresolved)
        active_statuses = [AlertStatus.new, AlertStatus.acknowledged, AlertStatus.investigating]
        c_crit = (await db.execute(
            select(func.count(Alert.id)).where(Alert.status.in_(active_statuses), Alert.severity == AlertSeverity.critical)
        )).scalar_one()
        c_high = (await db.execute(
            select(func.count(Alert.id)).where(Alert.status.in_(active_statuses), Alert.severity == AlertSeverity.high)
        )).scalar_one()
        c_med = (await db.execute(
            select(func.count(Alert.id)).where(Alert.status.in_(active_statuses), Alert.severity == AlertSeverity.medium)
        )).scalar_one()
        c_low = (await db.execute(
            select(func.count(Alert.id)).where(Alert.status.in_(active_statuses), Alert.severity == AlertSeverity.low)
        )).scalar_one()

        # 4. Events & Logins
        events_today = (await db.execute(
            select(func.count(SecurityEvent.id)).where(SecurityEvent.event_timestamp >= today_start)
        )).scalar_one()

        failed_logins = (await db.execute(
            select(func.count(LoginHistory.id)).where(
                LoginHistory.timestamp >= day_ago,
                LoginHistory.success.is_(False),
            )
        )).scalar_one()

        # Overall risk score (average of device risk scores)
        avg_risk = (await db.execute(select(func.coalesce(func.avg(Device.risk_score), 0.0)))).scalar_one()

        # OS distribution
        os_stmt = select(Device.os_name, func.count(Device.id)).group_by(Device.os_name)
        os_res = await db.execute(os_stmt)
        os_dist = {str(row[0]): int(row[1]) for row in os_res.all()}
        if not os_dist:
            os_dist = {"Windows": 0, "Linux": 0, "macOS": 0}

        # Events over last 7 days
        events_over_time = []
        for i in range(6, -1, -1):
            day_target = (now - timedelta(days=i)).strftime("%Y-%m-%d")
            d_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
            d_end = d_start + timedelta(days=1)

            crit_count = (await db.execute(
                select(func.count(SecurityEvent.id)).where(
                    SecurityEvent.event_timestamp >= d_start,
                    SecurityEvent.event_timestamp < d_end,
                    SecurityEvent.severity.in_(["critical", "high"])
                )
            )).scalar_one()

            total_day = (await db.execute(
                select(func.count(SecurityEvent.id)).where(
                    SecurityEvent.event_timestamp >= d_start,
                    SecurityEvent.event_timestamp < d_end,
                )
            )).scalar_one()

            events_over_time.append({
                "date": day_target,
                "total": total_day,
                "critical": crit_count,
            })

        # Failed logins trend (last 6 hours)
        failed_trend = []
        for i in range(5, -1, -1):
            h_start = now - timedelta(hours=i + 1)
            h_end = now - timedelta(hours=i)
            cnt = (await db.execute(
                select(func.count(LoginHistory.id)).where(
                    LoginHistory.timestamp >= h_start,
                    LoginHistory.timestamp < h_end,
                    LoginHistory.success.is_(False),
                )
            )).scalar_one()
            failed_trend.append({"hour": f"-{i}h", "count": cnt})

        # Recent critical alerts
        crit_alerts_stmt = (
            select(Alert)
            .options(selectinload(Alert.device))
            .where(Alert.severity.in_([AlertSeverity.critical, AlertSeverity.high]))
            .order_by(desc(Alert.detection_time))
            .limit(5)
        )
        crit_alerts_res = await db.execute(crit_alerts_stmt)
        raw_alerts = crit_alerts_res.scalars().all()
        recent_crit_alerts = [
            AlertResponse(
                id=a.id,
                title=a.title,
                description=a.description,
                severity=a.severity,
                status=a.status,
                detection_time=a.detection_time,
                device_id=a.device_id,
                device_name=a.device.hostname if a.device else None,
                risk_score=a.risk_score,
                assigned_to=a.assigned_to,
                resolved_at=a.resolved_at,
                resolution_notes=a.resolution_notes,
                notes_count=0,
            )
            for a in raw_alerts
        ]

        # Recent activities (audit trail)
        audit_stmt = select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(10)
        audit_res = await db.execute(audit_stmt)
        recent_activities = [
            {
                "id": str(entry.id),
                "timestamp": entry.timestamp.isoformat(),
                "actor": entry.actor_username or "System",
                "action": entry.action,
                "resource": f"{entry.resource_type}:{entry.resource_id or ''}",
                "result": entry.result,
            }
            for entry in audit_res.scalars().all()
        ]

        return DashboardStats(
            total_users=u_total,
            active_users=u_active,
            total_devices=d_total,
            online_devices=d_online,
            offline_devices=d_offline,
            devices_with_issues=d_issues,
            critical_alerts=c_crit,
            high_alerts=c_high,
            medium_alerts=c_med,
            low_alerts=c_low,
            total_events_today=events_today,
            failed_logins_24h=failed_logins,
            overall_risk_score=round(float(avg_risk), 1),
            events_over_time=events_over_time,
            alerts_by_severity={
                "critical": c_crit,
                "high": c_high,
                "medium": c_med,
                "low": c_low,
            },
            os_distribution=os_dist,
            failed_logins_trend=failed_trend,
            recent_critical_alerts=recent_crit_alerts,
            recent_activities=recent_activities,
        )
