"""
tests/test_explainability.py — 10 tests for ExplainabilityEngine
"""
import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest
from backend.core.confidence import Finding
from backend.core.explainability import (
    ExplainabilityEngine,
    Explanation,
    ChainExplanation,
    Evidence,
    ConfidenceExplanation,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def make_finding(**kwargs) -> Finding:
    defaults = dict(
        rule_id="SQLI-001",
        file="app/db.py",
        line=42,
        severity="HIGH",
        confidence=0.85,
        cwe_id="CWE-89",
        description="SQL query built with unsanitized user input",
        context_lines=["user_id = request.args.get('id')", "cursor.execute('SELECT * FROM users WHERE id=' + user_id)"],
    )
    defaults.update(kwargs)
    return Finding(**defaults)


ENGINE = ExplainabilityEngine()


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_explain_finding_returns_explanation():
    """explain_finding returns an Explanation with all required fields populated."""
    finding = make_finding()
    expl = ENGINE.explain_finding(finding)

    assert isinstance(expl, Explanation)
    assert expl.finding_fingerprint == finding.fingerprint()
    assert expl.rule_id == finding.rule_id
    assert expl.false_positive_risk in ("low", "medium", "high")
    assert isinstance(expl.evidence, list)
    assert isinstance(expl.reasoning_chain, list)
    assert isinstance(expl.triggered_rules, list)


def test_why_detected_not_empty():
    """why_detected field must be a non-empty string."""
    finding = make_finding()
    expl = ENGINE.explain_finding(finding)
    assert expl.why_detected, "why_detected should not be empty"
    assert len(expl.why_detected) > 10, "why_detected is suspiciously short"


def test_reasoning_chain_has_steps():
    """reasoning_chain must have at least 3 steps."""
    finding = make_finding()
    expl = ENGINE.explain_finding(finding)
    assert len(expl.reasoning_chain) >= 3, (
        f"Expected >= 3 reasoning steps, got {len(expl.reasoning_chain)}"
    )


def test_evidence_extraction():
    """Finding with context_lines produces a non-empty evidence list."""
    finding = make_finding(
        context_lines=["cursor.execute('SELECT * FROM users WHERE id=' + user_id)"]
    )
    evidence = ENGINE.extract_evidence(finding)
    assert len(evidence) >= 1, "Expected at least one evidence item"
    assert all(isinstance(e, Evidence) for e in evidence)
    assert all(0.0 <= e.weight <= 1.0 for e in evidence)
    assert all(e.content for e in evidence)


def test_confidence_explanation_total():
    """base_confidence + sum(adjustments.delta) ≈ final_confidence (within tolerance)."""
    finding = make_finding(confidence=0.85, is_test_file=False)
    conf_expl = ENGINE.explain_confidence(finding)

    computed_final = conf_expl.base_confidence + sum(
        a["delta"] for a in conf_expl.adjustments
    )
    # Clamp to [0.0, 1.0] to match engine behavior
    computed_final = max(0.0, min(1.0, computed_final))

    assert abs(computed_final - conf_expl.final_confidence) < 0.01, (
        f"Base {conf_expl.base_confidence} + adjustments should sum to final "
        f"{conf_expl.final_confidence}, got {computed_final}"
    )


def test_fp_risk_test_file_is_high():
    """A finding in a test file should have FP risk of 'high'."""
    finding = make_finding(is_test_file=True, confidence=0.9)
    risk = ENGINE.assess_fp_risk(finding)
    assert risk == "high", f"Expected 'high' for test file, got '{risk}'"


def test_fp_risk_high_confidence_is_low():
    """A non-test, non-suppressed finding with confidence=0.95 should have FP risk 'low'."""
    finding = make_finding(
        confidence=0.95,
        is_test_file=False,
        is_suppressed=False,
        context_lines=["cursor.execute(query, params)"],  # no sanitization keywords
    )
    # Override context_lines to avoid sanitization detection
    finding = finding.model_copy(update={"context_lines": ["cursor.execute(malicious)"]})
    risk = ENGINE.assess_fp_risk(finding)
    assert risk == "low", f"Expected 'low' for high-confidence non-test finding, got '{risk}'"


def test_explain_chain():
    """explain_chain returns a ChainExplanation with a non-empty narrative."""
    findings = [
        make_finding(rule_id="SQLI-001", cwe_id="CWE-89"),
        make_finding(
            rule_id="NO-AUTH",
            cwe_id="CWE-306",
            file="app/auth.py",
            line=20,
            severity="HIGH",
        ),
    ]
    fps = [f.fingerprint() for f in findings]
    chain = {
        "chain_id": "test-chain-1",
        "finding_fingerprints": fps,
        "severity": "CRITICAL",
        "narrative": "SQL injection + missing auth creates unauthenticated data breach path",
        "combined_risk_score": 9.0,
    }

    chain_expl = ENGINE.explain_chain(chain, findings)

    assert isinstance(chain_expl, ChainExplanation)
    assert chain_expl.chain_id == "test-chain-1"
    assert chain_expl.exploitation_narrative, "exploitation_narrative should not be empty"
    assert chain_expl.why_critical, "why_critical should not be empty"
    assert len(chain_expl.component_explanations) == 2


def test_batch_explain():
    """batch_explain on 3 findings returns a dict with 3 entries keyed by fingerprint."""
    findings = [
        make_finding(rule_id="SQLI-001", file="app/db.py", line=1),
        make_finding(rule_id="XSS-001", cwe_id="CWE-79", file="app/views.py", line=2),
        make_finding(rule_id="AUTH-001", cwe_id="CWE-306", file="app/auth.py", line=3),
    ]
    result = ENGINE.batch_explain(findings)

    assert len(result) == 3, f"Expected 3 explanations, got {len(result)}"
    for f in findings:
        fp = f.fingerprint()
        assert fp in result, f"Fingerprint {fp} missing from batch_explain result"
        assert isinstance(result[fp], Explanation)


def test_verification_steps_cwe89():
    """Verification steps for a CWE-89 finding should mention SQL."""
    finding = make_finding(cwe_id="CWE-89")
    steps = ENGINE.generate_verification_steps(finding)
    assert steps, "Verification steps should not be empty"
    assert "sql" in steps.lower() or "query" in steps.lower(), (
        f"Verification steps for CWE-89 should mention SQL or query. Got: {steps}"
    )
