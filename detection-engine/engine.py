"""
detection-engine/engine.py

SecureWatch Detection Engine — evaluates NormalizedEvents against loaded
DetectionRules and emits Alerts via an async callback.

Architecture:
  - Rules are held in memory and hot-reloaded from DB on demand.
  - Threshold counting uses Redis INCR + EXPIRE (atomic, TTL-based windows).
  - Duplicate suppression uses a Redis SET with per-rule/entity TTL.
  - Every evaluation is non-blocking (asyncio + aioredis).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import operator as op
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import redis.asyncio as aioredis

from rules_schema import ConditionOperator, DetectionRule, RuleCondition

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Alert dataclass
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    id: str
    rule_id: str
    rule_name: str
    severity: str
    mitre_tactic: str
    mitre_technique: str
    device_id: str
    hostname: str
    username: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    description: str
    recommended_steps: List[str]
    event_id: str
    triggered_at: datetime
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Operator dispatch table
# ---------------------------------------------------------------------------

def _get_nested(obj: Any, path: str) -> Any:
    """
    Traverse dot-notation path through nested dicts / dataclass attributes.
    Returns None if any step is missing.
    """
    parts = path.split(".")
    current = obj
    for part in parts:
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        else:
            current = getattr(current, part, None)
    return current


_NUMERIC_OPS = {
    ConditionOperator.GT:  op.gt,
    ConditionOperator.GTE: op.ge,
    ConditionOperator.LT:  op.lt,
    ConditionOperator.LTE: op.le,
}


# ---------------------------------------------------------------------------
# Detection Engine
# ---------------------------------------------------------------------------

class DetectionEngine:
    """
    Async detection engine.

    Parameters
    ----------
    rules:
        Pre-loaded list of DetectionRule objects.
    alert_callback:
        Async callable(alert: Alert) invoked for each generated alert.
    redis_client:
        aioredis.Redis instance for threshold counting and suppression.
    """

    def __init__(
        self,
        rules: List[DetectionRule],
        alert_callback: Callable[[Alert], Any],
        redis_client: aioredis.Redis,
    ) -> None:
        self._rules: List[DetectionRule] = [r for r in rules if r.is_active]
        self._alert_callback = alert_callback
        self._redis = redis_client
        self._rule_index: Dict[str, DetectionRule] = {r.id: r for r in self._rules}
        logger.info("DetectionEngine initialised with %d active rules.", len(self._rules))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def evaluate_event(self, event: Any) -> List[Alert]:
        """
        Evaluate a NormalizedEvent against all applicable rules.

        Returns a list of Alert objects generated (may be empty).
        Alerts are also delivered to alert_callback concurrently.
        """
        alerts: List[Alert] = []
        tasks = [self._evaluate_rule(rule, event) for rule in self._rules]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.error("Rule evaluation error: %s", result, exc_info=result)
            elif result is not None:
                alerts.append(result)
                asyncio.create_task(self._fire_callback(result))

        return alerts

    async def reload_rules(self, new_rules: List[DetectionRule]) -> None:
        """Hot-reload rules without restarting the engine."""
        self._rules = [r for r in new_rules if r.is_active]
        self._rule_index = {r.id: r for r in self._rules}
        logger.info("DetectionEngine hot-reloaded — %d active rules.", len(self._rules))

    # ------------------------------------------------------------------
    # Internal rule evaluation
    # ------------------------------------------------------------------

    async def _evaluate_rule(
        self, rule: DetectionRule, event: Any
    ) -> Optional[Alert]:
        """
        Return an Alert if the rule fires for this event, otherwise None.
        """
        # 1. Source / category filter
        if rule.event_sources and getattr(event, "event_source", None) not in rule.event_sources:
            return None
        if rule.event_categories and getattr(event, "event_category", None) not in rule.event_categories:
            return None

        # 2. Evaluate conditions
        if not await self._evaluate_conditions(rule, event):
            return None

        # 3. Threshold check (if count-based rule)
        if rule.threshold_count > 1:
            if not await self._check_threshold_rule(rule, event):
                return None

        # 4. Duplicate suppression
        if rule.suppress_duplicate_seconds > 0:
            if await self._is_duplicate_suppressed(rule, event):
                logger.debug(
                    "Alert for rule '%s' suppressed (duplicate within %ds window).",
                    rule.id,
                    rule.suppress_duplicate_seconds,
                )
                return None

        # 5. Create and return alert
        return await self._create_alert(rule, event)

    async def _evaluate_conditions(
        self, rule: DetectionRule, event: Any
    ) -> bool:
        """Apply condition_logic (all/any) across all rule conditions."""
        if not rule.conditions:
            return True

        results = [
            await self._check_condition(cond, event)
            for cond in rule.conditions
        ]

        if rule.condition_logic == "all":
            return all(results)
        return any(results)

    async def _check_condition(
        self, condition: RuleCondition, event: Any
    ) -> bool:
        """
        Evaluate a single RuleCondition against the event.
        Supports all operators defined in ConditionOperator.
        """
        raw_value = _get_nested(event, condition.field)
        expected = condition.value

        # Normalise strings for case-insensitive comparison
        if condition.case_insensitive:
            if isinstance(raw_value, str):
                raw_value = raw_value.lower()
            if isinstance(expected, str):
                expected = expected.lower()
            if isinstance(expected, list):
                expected = [v.lower() if isinstance(v, str) else v for v in expected]

        result: bool = False

        match condition.operator:
            case ConditionOperator.EQ:
                result = raw_value == expected
            case ConditionOperator.NEQ:
                result = raw_value != expected
            case ConditionOperator.GT | ConditionOperator.GTE | ConditionOperator.LT | ConditionOperator.LTE:
                if raw_value is None:
                    result = False
                else:
                    try:
                        result = _NUMERIC_OPS[condition.operator](float(raw_value), float(expected))
                    except (TypeError, ValueError):
                        result = False
            case ConditionOperator.CONTAINS:
                result = expected in str(raw_value) if raw_value is not None else False
            case ConditionOperator.REGEX:
                flags = re.IGNORECASE if condition.case_insensitive else 0
                try:
                    result = bool(re.search(expected, str(raw_value), flags)) if raw_value is not None else False
                except re.error as exc:
                    logger.warning("Invalid regex in rule condition '%s': %s", condition.field, exc)
                    result = False
            case ConditionOperator.IN:
                result = raw_value in expected if isinstance(expected, (list, set, tuple)) else False
            case ConditionOperator.NOT_IN:
                result = raw_value not in expected if isinstance(expected, (list, set, tuple)) else True
            case ConditionOperator.EXISTS:
                result = raw_value is not None
            case ConditionOperator.NOT_EXISTS:
                result = raw_value is None
            case _:
                logger.warning("Unknown operator '%s' — skipping condition.", condition.operator)
                result = False

        return not result if condition.negate else result

    async def _check_threshold_rule(
        self, rule: DetectionRule, event: Any
    ) -> bool:
        """
        Increment a Redis counter keyed on (rule.id + group_by field values).
        Returns True when the counter reaches rule.threshold_count for the
        first time within the time window (i.e., the alert should fire now).
        """
        group_key = self._build_group_key(rule, event)
        redis_key = f"sw:threshold:{rule.id}:{group_key}"

        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.incr(redis_key)
            pipe.expire(redis_key, rule.time_window_seconds)
            results = await pipe.execute()

        count: int = results[0]
        logger.debug("Threshold key=%s count=%d threshold=%d", redis_key, count, rule.threshold_count)
        # Fire exactly once when count reaches the threshold
        return count == rule.threshold_count

    async def _is_duplicate_suppressed(
        self, rule: DetectionRule, event: Any
    ) -> bool:
        """
        Returns True if an alert for this rule+entity was already raised within
        the suppress_duplicate_seconds window.
        Uses Redis SET NX with TTL to atomically check-and-mark.
        """
        group_key = self._build_group_key(rule, event)
        redis_key = f"sw:suppress:{rule.id}:{group_key}"

        # SET key value EX ttl NX — returns True if key was newly set
        was_set = await self._redis.set(
            redis_key,
            "1",
            ex=rule.suppress_duplicate_seconds,
            nx=True,
        )
        # If the key already existed (was_set is None/False) → suppressed
        return was_set is None or not was_set

    async def _create_alert(self, rule: DetectionRule, event: Any) -> Alert:
        """Build an Alert dataclass from the matched rule and event."""
        # Mark the suppression key so the next identical alert is suppressed
        if rule.suppress_duplicate_seconds > 0:
            group_key = self._build_group_key(rule, event)
            redis_key = f"sw:suppress:{rule.id}:{group_key}"
            await self._redis.set(redis_key, "1", ex=rule.suppress_duplicate_seconds, nx=True)

        return Alert(
            id=str(uuid.uuid4()),
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            mitre_tactic=rule.mitre_tactic,
            mitre_technique=rule.mitre_technique,
            device_id=getattr(event, "device_id", "unknown"),
            hostname=getattr(event, "hostname", "unknown"),
            username=getattr(event, "username", None),
            source_ip=getattr(event, "source_ip", None),
            destination_ip=getattr(event, "destination_ip", None),
            description=(
                f"Rule '{rule.name}' triggered: {rule.description[:200]}"
            ),
            recommended_steps=rule.recommended_steps,
            event_id=getattr(event, "event_id", ""),
            triggered_at=datetime.now(timezone.utc),
            tags=rule.tags,
            metadata={
                "event_source": getattr(event, "event_source", ""),
                "event_category": getattr(event, "event_category", ""),
                "event_type": getattr(event, "event_type", ""),
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_group_key(self, rule: DetectionRule, event: Any) -> str:
        """
        Build a compact, deterministic string key from group_by field values.
        Falls back to device_id if no group_by is defined.
        """
        if rule.group_by:
            parts = [
                str(_get_nested(event, g.field) or "")
                for g in rule.group_by
            ]
        else:
            parts = [getattr(event, "device_id", "unknown")]

        raw = ":".join(parts)
        # Hash long keys to keep Redis memory predictable
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    async def _fire_callback(self, alert: Alert) -> None:
        try:
            await self._alert_callback(alert)
        except Exception as exc:  # noqa: BLE001
            logger.error("Alert callback failed for alert %s: %s", alert.id, exc)


# ---------------------------------------------------------------------------
# DB-backed rule loader (called from API / Celery tasks)
# ---------------------------------------------------------------------------

async def load_rules_from_db(db_session: Any) -> List[DetectionRule]:
    """
    Load all active detection rules from the PostgreSQL database.
    Assumes SQLAlchemy async session and a DetectionRuleModel ORM class.

    Import is deferred to avoid circular dependency at module level.
    """
    from sqlalchemy import select  # noqa: PLC0415

    # Import the ORM model here (defined in backend/app/models/)
    try:
        from app.models.detection_rule import DetectionRuleModel  # noqa: PLC0415
    except ImportError:
        logger.warning("ORM model not found — returning empty rule set.")
        return []

    result = await db_session.execute(
        select(DetectionRuleModel).where(DetectionRuleModel.is_active.is_(True))
    )
    rows = result.scalars().all()

    rules: List[DetectionRule] = []
    for row in rows:
        try:
            rule = DetectionRule.model_validate(row.to_dict())
            rules.append(rule)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to parse rule id=%s from DB: %s", row.id, exc)

    logger.info("Loaded %d active rules from database.", len(rules))
    return rules
