"""
detection-engine/rules_schema.py
Detection rule schema using Pydantic v2 dataclass-style models.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ConditionOperator(str, Enum):
    EQ = "eq"
    NEQ = "neq"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    CONTAINS = "contains"
    REGEX = "regex"
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


class RuleSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConditionLogic(str, Enum):
    ALL = "all"   # AND – every condition must match
    ANY = "any"   # OR  – at least one condition must match


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

class RuleCondition(BaseModel):
    """A single field-level condition evaluated against a NormalizedEvent."""

    field: str = Field(
        ...,
        description="Dot-notation path into the NormalizedEvent or raw_data, e.g. 'username', 'raw_data.EventID'",
    )
    operator: ConditionOperator = Field(
        ...,
        description="Comparison operator",
    )
    value: Optional[Any] = Field(
        default=None,
        description="Expected value. Not required for 'exists'/'not_exists' operators.",
    )
    case_insensitive: bool = Field(
        default=False,
        description="When true, string comparisons are case-insensitive.",
    )
    negate: bool = Field(
        default=False,
        description="When true, the result of the condition is inverted (logical NOT).",
    )

    @field_validator("value", mode="before")
    @classmethod
    def coerce_value(cls, v: Any) -> Any:  # noqa: N805
        # Accept YAML-parsed lists or scalars as-is
        return v


class GroupByField(BaseModel):
    """Fields used to group events for threshold-based rules."""

    field: str = Field(..., description="Event field used as grouping key.")


# ---------------------------------------------------------------------------
# Main rule model
# ---------------------------------------------------------------------------

class DetectionRule(BaseModel):
    """
    Complete definition of a detection rule.

    Threshold rules (threshold_count > 1) use Redis INCR + EXPIRE to count
    matching events within time_window_seconds and fire only when the counter
    reaches threshold_count.

    Single-event rules (threshold_count == 1) fire immediately on match.
    """

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------
    id: str = Field(
        ...,
        description="Unique rule identifier (kebab-case recommended). Used as Redis key prefix.",
    )
    name: str = Field(..., description="Human-readable rule name.")
    description: str = Field(..., description="What the rule detects and why it matters.")
    version: str = Field(
        default="1.0.0",
        description="Semantic version of the rule; increment on changes.",
    )

    # ------------------------------------------------------------------
    # Scope
    # ------------------------------------------------------------------
    event_sources: List[str] = Field(
        default_factory=list,
        description="List of event_source values this rule applies to, e.g. ['windows_event_log']. Empty = all.",
    )
    event_categories: List[str] = Field(
        default_factory=list,
        description="List of event_category values this rule applies to. Empty = all.",
    )

    # ------------------------------------------------------------------
    # Conditions
    # ------------------------------------------------------------------
    conditions: List[RuleCondition] = Field(
        default_factory=list,
        description="List of field-level conditions to evaluate.",
    )
    condition_logic: ConditionLogic = Field(
        default=ConditionLogic.ALL,
        description="'all' = AND across all conditions; 'any' = OR.",
    )

    # ------------------------------------------------------------------
    # Threshold / time-window (count-based rules)
    # ------------------------------------------------------------------
    time_window_seconds: int = Field(
        default=0,
        ge=0,
        description="Rolling window in seconds for counting. 0 = no windowing (single-event rule).",
    )
    threshold_count: int = Field(
        default=1,
        ge=1,
        description="Minimum number of matching events within time_window_seconds to trigger an alert.",
    )
    group_by: List[GroupByField] = Field(
        default_factory=list,
        description="Fields to group by when counting (e.g., username + source_ip for brute-force).",
    )

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------
    severity: RuleSeverity = Field(
        default=RuleSeverity.MEDIUM,
        description="Alert severity when rule fires.",
    )
    mitre_tactic: str = Field(
        default="",
        description="MITRE ATT&CK tactic (e.g., 'Credential Access').",
    )
    mitre_technique: str = Field(
        default="",
        description="MITRE ATT&CK technique ID (e.g., 'T1110.001').",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Arbitrary tags for filtering and reporting.",
    )

    # ------------------------------------------------------------------
    # Response guidance
    # ------------------------------------------------------------------
    recommended_steps: List[str] = Field(
        default_factory=list,
        description="Analyst response steps displayed in the alert details pane.",
    )

    # ------------------------------------------------------------------
    # Suppression
    # ------------------------------------------------------------------
    suppress_duplicate_seconds: int = Field(
        default=300,
        ge=0,
        description="Suppress duplicate alerts for the same rule+entity within this window (seconds). 0 = no suppression.",
    )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    is_active: bool = Field(
        default=True,
        description="Whether the rule is currently evaluated by the engine.",
    )
    is_builtin: bool = Field(
        default=False,
        description="True for built-in rules shipped with the platform (read-only in UI).",
    )
    created_by: Optional[str] = Field(
        default=None,
        description="User ID or 'system' for built-in rules.",
    )

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# YAML loader helper
# ---------------------------------------------------------------------------

import yaml  # noqa: E402  (stdlib import after model definitions)
from pathlib import Path


def load_rule_from_yaml(path: Path) -> DetectionRule:
    """Load and validate a DetectionRule from a YAML file."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return DetectionRule.model_validate(raw)


def load_all_rules(rules_dir: Path) -> List[DetectionRule]:
    """
    Recursively load all *.yaml / *.yml files from rules_dir.
    Invalid files are logged and skipped.
    """
    import logging

    logger = logging.getLogger(__name__)
    rules: List[DetectionRule] = []

    for rule_file in sorted(rules_dir.rglob("*.y*ml")):
        try:
            rule = load_rule_from_yaml(rule_file)
            if rule.is_active:
                rules.append(rule)
                logger.debug("Loaded rule %s from %s", rule.id, rule_file.name)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to load rule from %s: %s", rule_file, exc)

    logger.info("Loaded %d active rules from %s", len(rules), rules_dir)
    return rules
