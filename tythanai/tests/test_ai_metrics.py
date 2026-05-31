"""
tests/test_ai_metrics.py
Tests for backend/core/ai_metrics.py — AI Performance Metrics module.

7 tests covering:
1. test_fp_reduction_rate_nonzero       — test-file findings → FP reduction > 0
2. test_confidence_distribution_computed — distribution has valid mean/std
3. test_kev_boosted_count_tracked       — findings with is_kev=True get boosted
4. test_summary_contains_percentage     — summary paragraph contains "%" string
5. test_markdown_has_table              — to_markdown output contains "|" characters
6. test_report_has_all_fields           — AIPerformanceReport has timestamp, fp_metrics, summary
7. test_zero_findings_handled           — empty findings list → no crash, rate=0.0
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from backend.core.confidence import Finding
from backend.core.fp_reducer import FPContext
from backend.core.ai_metrics import (
    AIMetricsCollector,
    AIPerformanceReport,
    ConfidenceDistribution,
    FPReductionMetrics,
    measure_ai_performance,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(
    rule_id: str = "TAINT001",
    file: str = "src/app.py",
    line: int = 10,
    severity: str = "MEDIUM",
    confidence: float = 0.8,
    cwe_id: str = "",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        file=file,
        line=line,
        severity=severity,
        confidence=confidence,
        cwe_id=cwe_id,
    )


# ---------------------------------------------------------------------------
# 1. test_fp_reduction_rate_nonzero
# ---------------------------------------------------------------------------

def test_fp_reduction_rate_nonzero():
    """With test-file findings, the FP reduction rate must be > 0."""
    findings = [
        _finding(file="tests/test_auth.py", confidence=0.75),
        _finding(file="tests/test_login.py", confidence=0.70),
        _finding(file="src/app.py", confidence=0.9),   # production file — kept
    ]
    collector = AIMetricsCollector(min_confidence=0.5)
    metrics = collector.measure_fp_reduction(findings)

    assert metrics.fp_reduction_rate > 0.0, (
        f"Expected fp_reduction_rate > 0, got {metrics.fp_reduction_rate}"
    )
    assert metrics.suppressed_count > 0
    assert metrics.total_raw_findings == 3


# ---------------------------------------------------------------------------
# 2. test_confidence_distribution_computed
# ---------------------------------------------------------------------------

def test_confidence_distribution_computed():
    """Distribution fields must be valid: mean in [0,1] and std >= 0."""
    findings = [
        _finding(confidence=0.9),
        _finding(confidence=0.7, file="src/b.py"),
        _finding(confidence=0.5, file="src/c.py"),
        _finding(confidence=0.6, file="src/d.py"),
    ]
    collector = AIMetricsCollector()
    metrics = collector.measure_fp_reduction(findings)

    dist = metrics.confidence_before
    assert isinstance(dist.mean, float)
    assert 0.0 <= dist.mean <= 1.0, f"Mean out of range: {dist.mean}"
    assert dist.std >= 0.0, f"Std must be >= 0, got {dist.std}"
    assert dist.median >= 0.0
    assert dist.p25 <= dist.p75, f"p25 {dist.p25} > p75 {dist.p75}"
    # Bucket counts must sum to total findings
    total_buckets = dist.below_0_5 + dist.between_0_5_0_7 + dist.above_0_7
    assert total_buckets == len(findings), (
        f"Bucket sum {total_buckets} != finding count {len(findings)}"
    )


# ---------------------------------------------------------------------------
# 3. test_kev_boosted_count_tracked
# ---------------------------------------------------------------------------

def test_kev_boosted_count_tracked():
    """Findings whose context marks is_kev=True should count as KEV-boosted."""
    # One KEV finding with low-ish confidence that will be boosted
    kev_file = "src/vuln.py"
    findings = [
        _finding(file=kev_file, confidence=0.65),
        _finding(file="src/safe.py", confidence=0.80),
    ]
    contexts = {
        kev_file: FPContext(is_kev=True),
    }
    collector = AIMetricsCollector(min_confidence=0.0)
    metrics = collector.measure_fp_reduction(findings, contexts=contexts)

    # The KEV finding confidence should be boosted (+0.15 from ExploitabilityPass)
    # so kev_boosted_count should be 1
    assert metrics.kev_boosted_count >= 1, (
        f"Expected kev_boosted_count >= 1, got {metrics.kev_boosted_count}"
    )


# ---------------------------------------------------------------------------
# 4. test_summary_contains_percentage
# ---------------------------------------------------------------------------

def test_summary_contains_percentage():
    """The generated summary paragraph must contain a '%' character."""
    findings = [
        _finding(file="tests/test_api.py", confidence=0.7),
        _finding(file="src/models.py", confidence=0.85),
    ]
    collector = AIMetricsCollector()
    report = collector.generate_report("myproject", findings)

    assert "%" in report.summary, (
        f"Summary does not contain '%': {report.summary!r}"
    )


# ---------------------------------------------------------------------------
# 5. test_markdown_has_table
# ---------------------------------------------------------------------------

def test_markdown_has_table():
    """to_markdown() output must contain '|' characters (markdown table syntax)."""
    findings = [
        _finding(file="src/auth.py", confidence=0.8, severity="HIGH"),
        _finding(file="tests/test_auth.py", confidence=0.7),
        _finding(file="vendor/lib.py", confidence=0.9),
    ]
    collector = AIMetricsCollector()
    report = collector.generate_report("test_project", findings)
    markdown = collector.to_markdown(report)

    assert "|" in markdown, "Markdown output should contain table separator '|'"
    # Verify it has at least one real table row
    lines_with_pipe = [l for l in markdown.splitlines() if "|" in l]
    assert len(lines_with_pipe) >= 3, (
        f"Expected at least 3 table lines, got {len(lines_with_pipe)}"
    )


# ---------------------------------------------------------------------------
# 6. test_report_has_all_fields
# ---------------------------------------------------------------------------

def test_report_has_all_fields():
    """AIPerformanceReport must have all required fields populated."""
    findings = [_finding(confidence=0.8)]
    collector = AIMetricsCollector()
    report = collector.generate_report("test/path", findings)

    assert isinstance(report, AIPerformanceReport)
    assert report.timestamp, "timestamp must be non-empty"
    assert report.project_path == "test/path"
    assert isinstance(report.fp_metrics, FPReductionMetrics)
    assert isinstance(report.summary, str) and len(report.summary) > 0
    assert isinstance(report.reachability_impact, dict)
    assert isinstance(report.interprocedural_findings, int)
    assert isinstance(report.knowledge_graph_coverage, dict)
    assert isinstance(report.benchmark_reference, dict)
    # Verify fp_metrics sub-fields
    m = report.fp_metrics
    assert isinstance(m.confidence_before, ConfidenceDistribution)
    assert isinstance(m.confidence_after, ConfidenceDistribution)
    assert isinstance(m.notes, list)
    assert isinstance(m.severity_breakdown_before, dict)
    assert isinstance(m.severity_breakdown_after, dict)


# ---------------------------------------------------------------------------
# 7. test_zero_findings_handled
# ---------------------------------------------------------------------------

def test_zero_findings_handled():
    """Empty findings list must not crash — rate must be 0.0."""
    collector = AIMetricsCollector()

    # measure_fp_reduction with empty list
    metrics = collector.measure_fp_reduction([])
    assert metrics.fp_reduction_rate == 0.0
    assert metrics.total_raw_findings == 0
    assert metrics.suppressed_count == 0
    assert metrics.kev_boosted_count == 0

    # generate_report with empty list
    report = collector.generate_report("empty_project", [])
    assert isinstance(report, AIPerformanceReport)
    assert report.fp_metrics.total_raw_findings == 0
    assert "%" in report.summary   # summary still mentions percentage

    # Module-level convenience function
    report2 = measure_ai_performance("empty_project", [])
    assert report2.fp_metrics.fp_reduction_rate == 0.0
