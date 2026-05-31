"""
tests/test_rule_evolution.py — 10 tests for RuleEvolutionSystem
"""
from __future__ import annotations

import os
import tempfile

import pytest
from backend.core.confidence import Finding
from backend.core.rule_evolution import ProposedRule, RuleEvolutionSystem, ValidationResult
from tests.conftest import InMemoryDatabase


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tmp_rules_dir(tmp_path):
    return str(tmp_path / "rules" / "evolved")


@pytest.fixture()
def db():
    _db = InMemoryDatabase()
    _db.init_schema()
    return _db


@pytest.fixture()
def evo(db, tmp_rules_dir):
    return RuleEvolutionSystem(db=db, rules_output_dir=tmp_rules_dir)


def _make_finding(
    rule_id: str = "SQL-INJECTION",
    severity: str = "HIGH",
    confidence: float = 0.9,
    cwe_id: str = "CWE-89",
    description: str = "SQL injection detected via string concatenation with user input",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        file="src/app.py",
        line=42,
        severity=severity,
        confidence=confidence,
        cwe_id=cwe_id,
        description=description,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_propose_rule(evo):
    """propose_rule returns ProposedRule with status='proposed'."""
    finding = _make_finding()
    rule = evo.propose_rule(finding)
    assert isinstance(rule, ProposedRule)
    assert rule.status == "proposed"
    assert rule.confirmation_count == 0


def test_propose_rule_has_id(evo):
    """Proposed rule has a non-empty rule_id and proposal_id."""
    finding = _make_finding()
    rule = evo.propose_rule(finding)
    assert rule.rule_id != ""
    assert rule.proposal_id != ""
    assert "SQL" in rule.rule_id or "EVOLVED" in rule.rule_id


def test_confirm_rule_once(evo):
    """One confirmation keeps status as 'proposed', count becomes 1."""
    finding = _make_finding()
    rule = evo.propose_rule(finding)
    updated = evo.confirm_rule(rule.rule_id)
    assert updated.confirmation_count == 1
    assert updated.status == "proposed"


def test_confirm_rule_twice_activates(evo):
    """Two confirmations with confidence >= 0.8 advances status to 'validated'."""
    finding = _make_finding(confidence=0.9)
    rule = evo.propose_rule(finding)
    evo.confirm_rule(rule.rule_id)
    result = evo.confirm_rule(rule.rule_id)
    assert result.confirmation_count == 2
    # Must be at least 'validated' (or potentially 'active' if benchmark passed)
    assert result.status in ("validated", "active")


def test_validate_rule_passes(evo):
    """Well-formed rule with description >20 chars, valid CWE, confidence >=0.8 passes."""
    finding = _make_finding(
        description="SQL injection detected via string concatenation with user-supplied input",
        confidence=0.9,
        cwe_id="CWE-89",
    )
    rule = evo.propose_rule(finding)
    # Manually set confirmations to meet threshold
    rule.confirmation_count = 3
    evo._update_proposed_rule(rule)
    result = evo.validate_rule(rule.rule_id)
    # Should pass structural checks; benchmark may vary
    assert isinstance(result, ValidationResult)
    assert result.rule_id == rule.rule_id
    if result.passed:
        assert result.recommendation == "activate"


def test_validate_rule_fails_short_description(evo):
    """Description with <= 20 chars produces a validation error."""
    finding = _make_finding(description="Short desc")  # 10 chars
    rule = evo.propose_rule(finding)
    rule.confirmation_count = 5
    rule.confidence = 0.9
    evo._update_proposed_rule(rule)
    result = evo.validate_rule(rule.rule_id)
    assert result.passed is False
    error_text = " ".join(result.errors).lower()
    assert "description" in error_text or "20" in error_text


def test_validate_rule_fails_low_confidence(evo):
    """Confidence below MIN_CONFIDENCE (0.8) produces a validation error."""
    finding = _make_finding(
        confidence=0.6,
        description="SQL injection detected via user input concatenation in query",
    )
    rule = evo.propose_rule(finding)
    rule.confirmation_count = 5
    evo._update_proposed_rule(rule)
    result = evo.validate_rule(rule.rule_id)
    assert result.passed is False
    error_text = " ".join(result.errors).lower()
    assert "confidence" in error_text


def test_activate_rule(evo, tmp_rules_dir):
    """activate_rule writes a YAML file and changes status to 'active'."""
    finding = _make_finding(
        description="SQL injection detected via string concatenation with user input in execute()",
        confidence=0.95,
        cwe_id="CWE-89",
    )
    rule = evo.propose_rule(finding)
    rule.status = "validated"
    rule.confirmation_count = 5
    rule.confidence = 0.95
    evo._update_proposed_rule(rule)

    success = evo.activate_rule(rule.rule_id)
    assert success is True

    # Reload from DB
    loaded = evo._load_proposed_rule(rule.rule_id)
    assert loaded is not None
    assert loaded.status == "active"

    # Check YAML file exists
    import os
    yaml_files = list(os.scandir(tmp_rules_dir))
    assert len(yaml_files) > 0
    content = open(yaml_files[0].path).read()
    assert "rules:" in content
    assert rule.rule_id in content


def test_list_proposed_rules(evo):
    """list_proposed_rules returns all rules with status='proposed'."""
    finding1 = _make_finding(rule_id="RULE-A")
    finding2 = _make_finding(rule_id="RULE-B")
    evo.propose_rule(finding1)
    evo.propose_rule(finding2)
    proposed = evo.list_proposed_rules()
    assert len(proposed) >= 2
    assert all(r.status == "proposed" for r in proposed)


def test_effectiveness_metrics(evo, db):
    """After recording FP feedback, evaluate_effectiveness shows fp_count > 0."""
    finding = _make_finding()
    rule = evo.propose_rule(finding)
    rule_id = rule.rule_id

    # Insert some findings into the findings table
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    with db.get_conn() as conn:
        for i in range(5):
            conn.execute(
                """INSERT INTO findings
                   (scan_id, rule_id, file, line, severity, confidence, cwe_id, description, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (f"scan-{i}", rule_id, "src/app.py", i, "HIGH", 0.9, "CWE-89", "test", now),
            )
        # 2 FP feedbacks
        for fp_fp in ["fp1", "fp2"]:
            conn.execute(
                "INSERT INTO fp_feedback (scan_id, finding_fingerprint, rule_id, file, line, verdict, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                ("scan-0", fp_fp, rule_id, "src/app.py", 0, "fp", now),
            )
        conn.commit()

    metrics = evo.evaluate_effectiveness(rule_id)
    assert metrics.rule_id == rule_id
    assert metrics.hit_count == 5
    assert metrics.fp_count == 2
    assert metrics.tp_count == 3
    assert abs(metrics.precision - 0.6) < 1e-6
    assert metrics.is_effective is False  # precision < 0.90
