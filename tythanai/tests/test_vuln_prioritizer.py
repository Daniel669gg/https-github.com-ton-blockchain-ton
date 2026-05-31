"""Tests for VulnPrioritizer (SSVC-inspired scoring).

All tests are offline — no HTTP calls are made.
"""
from __future__ import annotations

import pytest

from backend.core.confidence import Finding
from backend.intelligence.vuln_prioritizer import (
    PrioritizationReport,
    SSVCDecision,
    VulnPrioritizer,
    VulnPriority,
    prioritize_vulnerabilities,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    rule_id: str = "TEST-001",
    file: str = "app.py",
    severity: str = "HIGH",
    **kwargs,
) -> Finding:
    return Finding(rule_id=rule_id, file=file, line=1, severity=severity, **kwargs)


# ---------------------------------------------------------------------------
# Test 1 — KEV finding with CRITICAL severity → IMMEDIATE
# ---------------------------------------------------------------------------


def test_kev_finding_gets_immediate():
    """A CRITICAL-severity finding backed by a KEV entry must receive IMMEDIATE decision."""
    finding = _finding(severity="CRITICAL", rule_id="CVE-2023-9999")

    cve_records = {
        "CVE-2023-9999": {
            "is_kev": True,
            "epss_score": 0.95,
        }
    }
    reachability_scores = {"app.py": 0.9}

    # Inject cve_id onto finding via model extra
    finding_with_cve = finding.model_copy(update={"cve_id": "CVE-2023-9999"})

    report = prioritize_vulnerabilities(
        [finding_with_cve],
        cve_records=cve_records,
        reachability_scores=reachability_scores,
    )

    assert len(report.immediate) == 1, (
        f"Expected 1 IMMEDIATE, got {len(report.immediate)}. "
        f"Decisions: {[(v.ssvc_decision, v.signals) for v in report.immediate + report.out_of_cycle + report.scheduled + report.defer]}"
    )
    assert report.immediate[0].ssvc_decision == SSVCDecision.IMMEDIATE


# ---------------------------------------------------------------------------
# Test 2 — Low severity, low reachability → DEFER or SCHEDULED
# ---------------------------------------------------------------------------


def test_low_severity_unreachable_gets_defer():
    """A LOW-severity finding with low reachability should receive DEFER or SCHEDULED."""
    finding = _finding(severity="LOW", rule_id="INFO-001")

    report = prioritize_vulnerabilities(
        [finding],
        cve_records={},
        reachability_scores={"app.py": 0.1},
    )

    decisions = {v.ssvc_decision for v in report.immediate + report.out_of_cycle + report.scheduled + report.defer}
    # Must not be IMMEDIATE or OUT_OF_CYCLE
    assert SSVCDecision.IMMEDIATE not in decisions
    assert SSVCDecision.OUT_OF_CYCLE not in decisions

    all_decisions = report.immediate + report.out_of_cycle + report.scheduled + report.defer
    assert len(all_decisions) == 1
    assert all_decisions[0].ssvc_decision in (SSVCDecision.DEFER, SSVCDecision.SCHEDULED)


# ---------------------------------------------------------------------------
# Test 3 — All priority scores are in the 0–100 range
# ---------------------------------------------------------------------------


def test_priority_score_range():
    """Every VulnPriority.priority_score must be between 0.0 and 100.0 inclusive."""
    findings = [
        _finding(severity="CRITICAL", rule_id="A"),
        _finding(severity="HIGH", rule_id="B"),
        _finding(severity="MEDIUM", rule_id="C"),
        _finding(severity="LOW", rule_id="D"),
        _finding(severity="INFO", rule_id="E"),
    ]

    cve_records = {
        "A": {"is_kev": True, "epss_score": 0.99},
        "B": {"is_kev": False, "epss_score": 0.6},
    }

    report = prioritize_vulnerabilities(findings, cve_records=cve_records)

    all_priorities = (
        report.immediate + report.out_of_cycle + report.scheduled + report.defer
    )
    assert len(all_priorities) == len(findings)

    for vp in all_priorities:
        assert 0.0 <= vp.priority_score <= 100.0, (
            f"Score out of range: {vp.priority_score} for {vp.finding_rule_id}"
        )


# ---------------------------------------------------------------------------
# Test 4 — Sum of bucket counts equals total_findings
# ---------------------------------------------------------------------------


def test_report_totals_match():
    """Sum of immediate + out_of_cycle + scheduled + defer must equal total_findings."""
    findings = [_finding(rule_id=f"RULE-{i}", severity="MEDIUM") for i in range(10)]

    report = prioritize_vulnerabilities(findings)

    bucket_total = (
        len(report.immediate)
        + len(report.out_of_cycle)
        + len(report.scheduled)
        + len(report.defer)
    )
    assert bucket_total == report.total_findings, (
        f"Bucket sum {bucket_total} != total_findings {report.total_findings}"
    )
    assert report.total_findings == len(findings)


# ---------------------------------------------------------------------------
# Test 5 — SSVCDecision enum has exactly the 4 required values
# ---------------------------------------------------------------------------


def test_ssvc_decision_enum_values():
    """SSVCDecision must contain IMMEDIATE, OUT_OF_CYCLE, SCHEDULED, DEFER."""
    values = {v.value for v in SSVCDecision}
    assert "immediate" in values
    assert "out_of_cycle" in values
    assert "scheduled" in values
    assert "defer" in values
    assert len(values) == 4


# ---------------------------------------------------------------------------
# Test 6 — Markdown output contains expected column headers
# ---------------------------------------------------------------------------


def test_to_markdown_has_columns():
    """to_markdown should produce a table with '| CVE' column header."""
    finding = _finding(severity="HIGH", rule_id="CVE-2024-1234")
    finding_with_cve = finding.model_copy(update={"cve_id": "CVE-2024-1234"})

    cve_records = {"CVE-2024-1234": {"is_kev": False, "epss_score": 0.3}}
    reachability_scores = {"app.py": 0.75}

    report = prioritize_vulnerabilities(
        [finding_with_cve],
        cve_records=cve_records,
        reachability_scores=reachability_scores,
    )

    prioritizer = VulnPrioritizer()
    md = prioritizer.to_markdown(report)

    assert isinstance(md, str)
    assert len(md) > 0
    # The markdown table must contain the CVE / Finding header
    assert "| CVE" in md or "| Finding" in md, (
        f"Expected '| CVE' or '| Finding' in markdown output:\n{md[:500]}"
    )
    # And decision column
    assert "Decision" in md or "decision" in md.lower()
