"""
tests/test_multi_agent_orchestrator.py — 12 tests for MultiAgentOrchestrator
and its constituent agents.
"""
import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest
from backend.core.confidence import Finding
from backend.agents.multi_agent_orchestrator import (
    PlannerAgent,
    ResearcherAgent,
    SecurityAnalystAgent,
    VerifierAgent,
    CriticAgent,
    RuleGeneratorAgent,
    ReportWriterAgent,
    MultiAgentOrchestrator,
    OrchestratorReport,
    AnalysisPlan,
    ResearchResult,
    AnalysisResult,
    VerificationResult,
    CritiqueResult,
    GeneratedRule,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def make_finding(**kwargs) -> Finding:
    defaults = dict(
        rule_id="TEST-RULE",
        file="app/main.py",
        line=10,
        severity="MEDIUM",
        confidence=0.85,
        cwe_id="CWE-89",
        description="Test vulnerability in user input handling",
        recommendation="Use parameterized queries",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ─────────────────────────────────────────────────────────────────────────────
# PlannerAgent tests
# ─────────────────────────────────────────────────────────────────────────────

def test_planner_sorts_by_severity():
    """CRITICAL findings should come first in priority_order."""
    findings = [
        make_finding(rule_id="LOW-RULE", severity="LOW", confidence=0.9),
        make_finding(rule_id="CRIT-RULE", severity="CRITICAL", confidence=0.9, file="app/db.py", line=1),
        make_finding(rule_id="HIGH-RULE", severity="HIGH", confidence=0.9, file="app/auth.py", line=2),
    ]
    plan = PlannerAgent().plan(findings)

    assert isinstance(plan, AnalysisPlan)
    assert len(plan.priority_order) == 3

    # Build fingerprint → severity map
    fp_to_sev = {f.fingerprint(): f.severity for f in findings}

    # The first fingerprint in priority_order should be the CRITICAL finding
    first_sev = fp_to_sev[plan.priority_order[0]]
    assert first_sev == "CRITICAL", (
        f"Expected CRITICAL finding first, got {first_sev}"
    )


def test_planner_identifies_focus_areas():
    """Findings with SQLI in rule_id should add 'injection' to focus_areas."""
    findings = [
        make_finding(rule_id="SQLI-001", cwe_id="CWE-89", severity="HIGH"),
        make_finding(rule_id="AUTH-MISSING", cwe_id="CWE-306", severity="HIGH", file="auth.py", line=5),
    ]
    plan = PlannerAgent().plan(findings)

    assert "injection" in plan.focus_areas, (
        f"Expected 'injection' in focus_areas. Got: {plan.focus_areas}"
    )
    assert "authentication" in plan.focus_areas, (
        f"Expected 'authentication' in focus_areas. Got: {plan.focus_areas}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# ResearcherAgent tests
# ─────────────────────────────────────────────────────────────────────────────

def test_researcher_returns_cwe_details():
    """CWE-89 finding should return exploit_likelihood > 0.8."""
    finding = make_finding(cwe_id="CWE-89", confidence=1.0)
    result = ResearcherAgent().research(finding)

    assert isinstance(result, ResearchResult)
    assert result.exploit_likelihood > 0.8, (
        f"Expected exploit_likelihood > 0.8 for CWE-89, got {result.exploit_likelihood}"
    )
    assert result.cwe_details.get("name"), "cwe_details.name should be non-empty"
    assert result.cwe_details.get("description"), "cwe_details.description should be non-empty"
    assert result.cwe_details.get("impact"), "cwe_details.impact should be non-empty"


def test_researcher_unknown_cwe():
    """Unknown CWE should still return a valid ResearchResult."""
    finding = make_finding(cwe_id="CWE-99999")
    result = ResearcherAgent().research(finding)

    assert isinstance(result, ResearchResult)
    assert result.finding_fingerprint == finding.fingerprint()
    # exploit_likelihood must be in valid range
    assert 0.0 <= result.exploit_likelihood <= 1.0
    # Should have some default details
    assert result.cwe_details.get("name"), "Should have a default CWE name"


# ─────────────────────────────────────────────────────────────────────────────
# VerifierAgent tests
# ─────────────────────────────────────────────────────────────────────────────

def test_verifier_suppressed_is_fp():
    """is_suppressed=True should yield verdict='false_positive'."""
    finding = make_finding(is_suppressed=True)
    result = VerifierAgent().verify(finding)

    assert isinstance(result, VerificationResult)
    assert result.verdict == "false_positive", (
        f"Expected 'false_positive' for suppressed finding, got '{result.verdict}'"
    )


def test_verifier_test_file_needs_review():
    """is_test_file=True with non-CRITICAL severity should yield 'needs_review'."""
    finding = make_finding(is_test_file=True, severity="HIGH")
    result = VerifierAgent().verify(finding)

    assert isinstance(result, VerificationResult)
    assert result.verdict == "needs_review", (
        f"Expected 'needs_review' for test file finding, got '{result.verdict}'"
    )


def test_verifier_sanitization_context():
    """context_lines with 'parameterized' pattern should yield 'false_positive'."""
    finding = make_finding(
        context_lines=[
            "# Using parameterized queries to prevent injection",
            "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
        ]
    )
    result = VerifierAgent().verify(finding)

    assert isinstance(result, VerificationResult)
    assert result.verdict == "false_positive", (
        f"Expected 'false_positive' when 'parameterized' is in context, got '{result.verdict}'"
    )


# ─────────────────────────────────────────────────────────────────────────────
# CriticAgent tests
# ─────────────────────────────────────────────────────────────────────────────

def test_critic_flags_unsupported_escalation():
    """Severity escalation with no evidence should produce an issue in CritiqueResult."""
    finding = make_finding(severity="LOW", confidence=0.6, context_lines=[])

    # Researcher result (minimal)
    research = ResearcherAgent().research(finding)

    # Force an escalation in analysis result with no evidence
    analysis = AnalysisResult(
        finding_fingerprint=finding.fingerprint(),
        adjusted_severity="CRITICAL",    # escalated from LOW → CRITICAL
        adjusted_confidence=0.6,
        impact_assessment="Severe",
        attack_vectors=[],
        requires_chain_analysis=False,
        reasoning="Escalated without evidence.",
    )

    # Verification with no evidence
    verification = VerificationResult(
        finding_fingerprint=finding.fingerprint(),
        verdict="confirmed",
        evidence_found=[],  # no evidence
        confidence_adjustment=0.0,
        reasoning="",
    )

    critique = CriticAgent().critique(finding, analysis, verification)

    assert isinstance(critique, CritiqueResult)
    assert not critique.is_sound, "Should not be sound when escalation lacks evidence"
    assert len(critique.issues_found) >= 1, (
        "Expected at least one issue for unsupported severity escalation"
    )


# ─────────────────────────────────────────────────────────────────────────────
# RuleGeneratorAgent tests
# ─────────────────────────────────────────────────────────────────────────────

def test_rule_generator_groups_cwes():
    """3 confirmed CWE-89 findings with matching prefix should produce 1 proposed rule."""
    findings = [
        make_finding(
            rule_id="SQLI-BASIC",
            cwe_id="CWE-89",
            description="SQL injection via user input in query string",
            file=f"app/module{i}.py",
            line=i * 10,
        )
        for i in range(1, 4)
    ]
    rules = RuleGeneratorAgent().generate_proposals(findings)

    assert len(rules) >= 1, f"Expected >= 1 proposed rule, got {len(rules)}"
    assert all(isinstance(r, GeneratedRule) for r in rules)
    assert all(r.cwe_id == "CWE-89" for r in rules)
    # Each rule should reference the source fingerprints
    all_fps = {f.fingerprint() for f in findings}
    for rule in rules:
        assert any(fp in all_fps for fp in rule.based_on_fingerprints)


# ─────────────────────────────────────────────────────────────────────────────
# MultiAgentOrchestrator tests
# ─────────────────────────────────────────────────────────────────────────────

def test_orchestrator_run_empty():
    """run([]) should return an OrchestratorReport with all empty lists."""
    report = MultiAgentOrchestrator().run([])

    assert isinstance(report, OrchestratorReport)
    assert report.original_findings == []
    assert report.confirmed_findings == []
    assert report.removed_findings == []
    assert report.attack_chains == []


def test_orchestrator_run_with_findings():
    """5 findings → report has confirmed + removed lists, non-zero total."""
    findings = [
        make_finding(
            rule_id="SQLI-001",
            cwe_id="CWE-89",
            severity="HIGH",
            confidence=0.9,
            file="app/db.py",
            line=10,
        ),
        make_finding(
            rule_id="AUTH-BYPASS",
            cwe_id="CWE-306",
            severity="HIGH",
            confidence=0.88,
            file="app/auth.py",
            line=20,
        ),
        make_finding(
            rule_id="XSS-REFL",
            cwe_id="CWE-79",
            severity="MEDIUM",
            confidence=0.75,
            file="app/views.py",
            line=30,
            is_suppressed=True,
        ),
        make_finding(
            rule_id="HARDCODED-SECRET",
            cwe_id="CWE-798",
            severity="CRITICAL",
            confidence=0.95,
            file="app/config.py",
            line=5,
            context_lines=["API_KEY = 'abc123secret'"],
        ),
        make_finding(
            rule_id="PATH-TRAV",
            cwe_id="CWE-22",
            severity="HIGH",
            confidence=0.8,
            file="app/files.py",
            line=50,
            is_test_file=True,
        ),
    ]

    report = MultiAgentOrchestrator().run(findings)

    assert isinstance(report, OrchestratorReport)
    assert len(report.original_findings) == 5
    # Confirmed + removed must account for all findings
    total = len(report.confirmed_findings) + len(report.removed_findings)
    assert total == 5, f"Expected confirmed+removed=5, got {total}"
    # At least the suppressed finding should be removed
    removed_rules = {f.rule_id for f in report.removed_findings}
    assert "XSS-REFL" in removed_rules, "Suppressed finding should be in removed_findings"


def test_orchestrator_run_produces_report():
    """report_markdown should be a non-empty string containing 'TythanAI'."""
    findings = [
        make_finding(
            rule_id="SQLI-001",
            cwe_id="CWE-89",
            severity="HIGH",
            confidence=0.9,
        ),
    ]
    report = MultiAgentOrchestrator().run(findings)

    assert isinstance(report.report_markdown, str)
    assert len(report.report_markdown) > 100, "report_markdown is suspiciously short"
    assert "TythanAI" in report.report_markdown, (
        "report_markdown should contain 'TythanAI'"
    )
