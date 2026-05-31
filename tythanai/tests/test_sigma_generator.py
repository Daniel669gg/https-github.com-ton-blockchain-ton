"""Tests for backend/scanners/sigma_generator.py — Sigma Detection Rule Generator."""
from __future__ import annotations

import os
import tempfile
import uuid

import pytest
import yaml

from backend.core.confidence import Finding
from backend.scanners.sigma_generator import (
    SigmaLevel,
    SigmaRule,
    SigmaRuleGenerator,
    SigmaStatus,
    export_sigma_ruleset,
    generate_sigma_rules,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


def _make_finding(**kwargs) -> Finding:
    """Create a Finding with sensible defaults, overridable via kwargs."""
    defaults = dict(
        rule_id="PY-001",
        file="/app/api/views.py",
        line=42,
        severity="HIGH",
        confidence=0.9,
        cwe_id="CWE-89",
        description="SQL Injection via f-string interpolation in query builder",
        recommendation="Use parameterised queries instead of string formatting.",
        sources=["https://owasp.org/www-community/attacks/SQL_Injection"],
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ─────────────────────────────────────────────────────────────────────────────
# Test 1 — SigmaRule has all required fields
# ─────────────────────────────────────────────────────────────────────────────


def test_generate_from_finding_structure():
    """SigmaRule generated from a Finding must have all required Sigma fields."""
    generator = SigmaRuleGenerator()
    finding = _make_finding()
    rule = generator.generate_from_finding(finding)

    assert isinstance(rule, SigmaRule)
    assert rule.title, "title must be non-empty"
    assert rule.id, "id must be non-empty"
    assert rule.status in SigmaStatus.__members__.values()
    assert rule.description, "description must be non-empty"
    assert rule.author
    assert rule.date  # YYYY-MM-DD
    assert isinstance(rule.tags, list)
    assert isinstance(rule.logsource, dict)
    assert rule.logsource  # must not be empty
    assert isinstance(rule.detection, dict)
    assert "selection" in rule.detection
    assert "condition" in rule.detection
    assert isinstance(rule.fields, list)
    assert isinstance(rule.falsepositives, list)
    assert rule.level in SigmaLevel.__members__.values()


# ─────────────────────────────────────────────────────────────────────────────
# Test 2 — to_yaml() output is valid YAML
# ─────────────────────────────────────────────────────────────────────────────


def test_sigma_yaml_valid():
    """to_yaml() must produce parseable YAML."""
    generator = SigmaRuleGenerator()
    rule = generator.generate_from_finding(_make_finding())
    yaml_text = generator.to_yaml(rule)

    assert isinstance(yaml_text, str), "to_yaml must return a string"
    assert len(yaml_text) > 0, "YAML output must not be empty"

    # Must parse without error
    parsed = yaml.safe_load(yaml_text)
    assert isinstance(parsed, dict), "Parsed YAML must be a dict"


# ─────────────────────────────────────────────────────────────────────────────
# Test 3 — YAML contains all required Sigma fields
# ─────────────────────────────────────────────────────────────────────────────


def test_sigma_yaml_has_required_fields():
    """Parsed YAML from to_yaml() must contain title, id, detection, and level."""
    generator = SigmaRuleGenerator()
    rule = generator.generate_from_finding(_make_finding())
    parsed = yaml.safe_load(generator.to_yaml(rule))

    required_fields = {"title", "id", "detection", "level", "status", "logsource"}
    for field in required_fields:
        assert field in parsed, f"YAML is missing required field: {field}"

    # detection must have a selection and a condition
    detection = parsed["detection"]
    assert "selection" in detection, "detection block must have a 'selection' key"
    assert "condition" in detection, "detection block must have a 'condition' key"

    # id must be a valid UUID
    try:
        uuid.UUID(parsed["id"])
    except ValueError:
        pytest.fail(f"id field '{parsed['id']}' is not a valid UUID")


# ─────────────────────────────────────────────────────────────────────────────
# Test 4 — CWE → MITRE ATT&CK tag mapping
# ─────────────────────────────────────────────────────────────────────────────


def test_cwe_to_attack_mapping():
    """Finding with CWE-78 must produce ATT&CK T1059 tags in the Sigma rule."""
    generator = SigmaRuleGenerator()
    finding = _make_finding(
        cwe_id="CWE-78",
        description="OS command injection via subprocess",
    )
    rule = generator.generate_from_finding(finding)

    # CWE-78 maps to T1059.004 and T1059.001
    assert len(rule.tags) >= 1, "CWE-78 must produce at least one ATT&CK tag"
    # At least one tag should reference T1059
    t1059_tags = [t for t in rule.tags if "T1059" in t]
    assert t1059_tags, f"Expected T1059 in tags, got: {rule.tags}"

    # Verify tag prefix format
    for tag in rule.tags:
        assert tag.startswith("attack."), f"Tag must start with 'attack.': {tag}"


# ─────────────────────────────────────────────────────────────────────────────
# Test 5 — severity → SigmaLevel mapping
# ─────────────────────────────────────────────────────────────────────────────


def test_severity_to_level_mapping():
    """CRITICAL finding severity must produce SigmaLevel.CRITICAL."""
    generator = SigmaRuleGenerator()
    finding = _make_finding(severity="CRITICAL", cwe_id="CWE-78")
    rule = generator.generate_from_finding(finding)
    assert rule.level == SigmaLevel.CRITICAL, (
        f"Expected SigmaLevel.CRITICAL for severity=CRITICAL, got {rule.level}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 6 — generate_bulk deduplicates same rule_id + file
# ─────────────────────────────────────────────────────────────────────────────


def test_bulk_generate_deduplicates():
    """Identical (rule_id, file) pairs must produce exactly one Sigma rule."""
    generator = SigmaRuleGenerator()

    # Three findings: two share the same rule_id + file
    same_file = "/app/db/queries.py"
    findings = [
        _make_finding(rule_id="PY-SQLI", file=same_file, line=10),
        _make_finding(rule_id="PY-SQLI", file=same_file, line=20),  # duplicate key
        _make_finding(rule_id="PY-SQLI", file="/app/other.py", line=5),  # different file
    ]

    rules = generator.generate_bulk(findings)

    assert len(rules) == 2, (
        f"Expected 2 rules (one per unique rule_id+file), got {len(rules)}"
    )

    rule_ids = [r.id for r in rules]
    assert len(set(rule_ids)) == 2, "Deduplicated rules must have distinct UUIDs"


# ─────────────────────────────────────────────────────────────────────────────
# Test 7 — export_ruleset creates severity subdirectories
# ─────────────────────────────────────────────────────────────────────────────


def test_export_ruleset_creates_dirs():
    """export_ruleset must create severity subdirectories and write .yml files."""
    findings = [
        _make_finding(rule_id="PY-CRITICAL", file="/app/a.py", severity="CRITICAL"),
        _make_finding(rule_id="PY-HIGH", file="/app/b.py", severity="HIGH"),
        _make_finding(rule_id="PY-MEDIUM", file="/app/c.py", severity="MEDIUM"),
        _make_finding(rule_id="PY-LOW", file="/app/d.py", severity="LOW"),
    ]

    with tempfile.TemporaryDirectory() as tmp_dir:
        written = export_sigma_ruleset(findings, tmp_dir)

        # Must have written exactly 4 files
        assert len(written) == 4, f"Expected 4 files written, got {len(written)}"

        # Each written path must exist on disk
        for path in written:
            assert os.path.isfile(path), f"Expected file to exist: {path}"
            assert path.endswith(".yml"), f"Rule file must end with .yml: {path}"

        # Severity subdirectories must all exist
        for sev_dir in ("critical", "high", "medium", "low"):
            full_dir = os.path.join(tmp_dir, sev_dir)
            assert os.path.isdir(full_dir), f"Missing severity subdir: {sev_dir}"

        # Each file must contain valid YAML with required fields
        for path in written:
            with open(path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            assert "title" in doc, f"Rule file missing 'title': {path}"
            assert "id" in doc, f"Rule file missing 'id': {path}"
            assert "level" in doc, f"Rule file missing 'level': {path}"


# ─────────────────────────────────────────────────────────────────────────────
# Test 8 — all four primary severities map to correct SigmaLevel
# ─────────────────────────────────────────────────────────────────────────────


def test_sigma_level_from_severity():
    """All four main severity levels must map to the correct SigmaLevel value."""
    generator = SigmaRuleGenerator()

    expected_mappings = [
        ("CRITICAL", SigmaLevel.CRITICAL),
        ("HIGH", SigmaLevel.HIGH),
        ("MEDIUM", SigmaLevel.MEDIUM),
        ("LOW", SigmaLevel.LOW),
    ]

    for severity, expected_level in expected_mappings:
        finding = _make_finding(
            rule_id=f"PY-{severity}",
            file=f"/app/{severity.lower()}.py",
            severity=severity,
        )
        rule = generator.generate_from_finding(finding)
        assert rule.level == expected_level, (
            f"Severity {severity!r} should map to {expected_level!r}, "
            f"but got {rule.level!r}"
        )
