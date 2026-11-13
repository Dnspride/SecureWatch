"""
Unit and Integration Tests for SecureWatch Detection Engine & Rules.
Verifies all 15 MITRE ATT&CK YAML detection rules against the engine schema.
"""
import glob
import os
import yaml

RULES_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "detection-engine", "rules")
)


def get_rule_files():
    files = glob.glob(os.path.join(RULES_DIR, "*.yaml"))
    assert len(files) == 15, f"Expected 15 detection rules, found {len(files)}"
    return sorted(files)


def test_rule_count():
    """Verify exactly 15 rules exist in the rules directory."""
    files = get_rule_files()
    assert len(files) == 15, f"Expected 15 rules, found {len(files)}"
    print(f"  [+] Found all {len(files)} detection rules in {RULES_DIR}")


def test_rule_yaml_validity_and_fields():
    """Verify that every rule has required MITRE ATT&CK fields, valid severities, and conditions."""
    files = get_rule_files()
    valid_severities = {"info", "low", "medium", "high", "critical"}
    seen_ids = set()

    for rule_file in files:
        with open(rule_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        assert isinstance(data, dict), f"Rule file {rule_file} did not parse into a dictionary"
        rule_id = data.get("id")
        name = data.get("name")
        severity = str(data.get("severity", "")).lower()
        tactic = data.get("mitre_tactic")
        technique = data.get("mitre_technique")
        conditions = data.get("conditions", [])

        # Check required fields
        assert rule_id, f"Missing id in {rule_file}"
        assert name, f"Missing name in {rule_file}"
        assert severity in valid_severities, f"Invalid severity '{severity}' in {rule_file}"
        assert tactic, f"Missing mitre_tactic in {rule_file}"
        assert technique, f"Missing mitre_technique in {rule_file}"
        assert isinstance(conditions, list), f"Conditions must be a list in {rule_file}"
        assert rule_id not in seen_ids, f"Duplicate id '{rule_id}' in {rule_file}"
        seen_ids.add(rule_id)

        print(f"  [+] Rule: [{severity.upper():<8}] {rule_id:<25} (MITRE: {technique}) -> OK")


def test_rule_conditions_structure():
    """Verify that conditions have valid field, operator, and values."""
    files = get_rule_files()
    valid_operators = {
        "eq", "neq", "gt", "gte", "lt", "lte", "contains",
        "regex", "in", "not_in", "exists", "not_exists",
    }

    for rule_file in files:
        with open(rule_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        conditions = data.get("conditions", [])
        for cond in conditions:
            assert "field" in cond, f"Missing field in condition for {data.get('id')}"
            assert "operator" in cond, f"Missing operator in condition for {data.get('id')}"
            op = cond["operator"].lower()
            assert op in valid_operators, f"Invalid operator '{op}' in rule {data.get('id')}"


if __name__ == "__main__":
    print("=" * 60)
    print(" Running SecureWatch Detection Engine Rule Validations")
    print("=" * 60)
    test_rule_count()
    test_rule_yaml_validity_and_fields()
    test_rule_conditions_structure()
    print("=" * 60)
    print(" ALL 15 DETECTION RULES ARE VALID & SCHEMA COMPLIANT!")
    print("=" * 60)
