"""Tests for SAST rules registry."""
import pytest
from backend.scanners.rules import ALL_RULES, get_rules_by_language, get_rules_by_severity, get_rules_by_category
from backend.scanners.rules.python_rules import PYTHON_RULES
from backend.scanners.rules.javascript_rules import JS_RULES


def test_python_rules_count():
    assert len(PYTHON_RULES) >= 150, f"Expected >=150 Python rules, got {len(PYTHON_RULES)}"


def test_js_rules_count():
    assert len(JS_RULES) >= 200, f"Expected >=200 JS rules, got {len(JS_RULES)}"


REQUIRED_FIELDS = {"rule_id", "severity", "pattern", "cwe_id", "description", "recommendation"}


def test_all_rules_have_required_fields():
    missing = []
    for rule in ALL_RULES:
        for field in REQUIRED_FIELDS:
            if not rule.get(field):
                missing.append(f"{rule.get('rule_id', '?')}: missing {field}")
    assert not missing, "Rules missing required fields:\n" + "\n".join(missing[:20])


def test_get_rules_by_language_python():
    py_rules = get_rules_by_language("python")
    assert all(r["language"] == "python" for r in py_rules)
    assert len(py_rules) >= 150


def test_get_rules_by_language_javascript():
    js_rules = get_rules_by_language("javascript")
    ts_rules = get_rules_by_language("typescript")
    # JS + TS rules should account for most of JS_RULES
    assert len(js_rules) + len(ts_rules) >= 180


def test_get_rules_by_severity_critical():
    critical = get_rules_by_severity("CRITICAL")
    assert len(critical) > 10
    assert all(r["severity"] == "CRITICAL" for r in critical)


def test_get_rules_by_category_injection():
    injection = get_rules_by_category("INJECTION")
    assert len(injection) > 5


def test_all_rule_ids_unique():
    ids = [r["rule_id"] for r in ALL_RULES]
    assert len(ids) == len(set(ids)), "Duplicate rule IDs found"


def test_all_severities_valid():
    valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    bad = [r["rule_id"] for r in ALL_RULES if r.get("severity") not in valid]
    assert not bad, f"Rules with invalid severity: {bad[:10]}"


def test_all_patterns_are_strings():
    bad = [r["rule_id"] for r in ALL_RULES if not isinstance(r.get("pattern"), str)]
    assert not bad, f"Rules with non-string pattern: {bad[:10]}"


def test_all_patterns_are_valid_regex():
    import re
    bad = []
    for rule in ALL_RULES:
        try:
            re.compile(rule["pattern"])
        except re.error as e:
            bad.append(f"{rule['rule_id']}: {e}")
    assert not bad, "Rules with invalid regex:\n" + "\n".join(bad[:10])
