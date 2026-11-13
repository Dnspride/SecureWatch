"""
Pydantic schemas for the SOC Dashboard.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import UUID
from pydantic import BaseModel

from app.schemas.alerts import AlertResponse


class DashboardStats(BaseModel):
    total_users: int
    active_users: int
    total_devices: int
    online_devices: int
    offline_devices: int
    devices_with_issues: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    total_events_today: int
    failed_logins_24h: int
    overall_risk_score: float

    # Trend / chart data
    events_over_time: List[Dict[str, Any]]
    alerts_by_severity: Dict[str, int]
    os_distribution: Dict[str, int]
    failed_logins_trend: List[Dict[str, Any]]

    recent_critical_alerts: List[AlertResponse]
    recent_activities: List[Dict[str, Any]]
