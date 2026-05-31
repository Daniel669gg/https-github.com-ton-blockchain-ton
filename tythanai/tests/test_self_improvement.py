"""
tests/test_self_improvement.py — 10 tests for SelfImprovementEngine
"""
from __future__ import annotations

import pytest
from backend.core.confidence import Finding
from backend.core.self_improvement import (
    ImprovementAction,
    ImprovementReport,
    ScanAnalysis,
    SelfImprovementEngine,
)
from tests.conftest import InMemoryDatabase


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db():
    """In-memory SQLite database (shared persistent connection)."""
    _db = InMemoryDatabase()
    _db.init_schema()
    return _db


@pytest.fixture()
def engine(db):
    return SelfImprovementEngine(db=db)


def _make_finding(rule_id: str = "RULE-001", file: str = "src/app.py",
                  line: int = 10, confidence: float = 0.9) -> Finding:
    return Finding(
        rule_id=rule_id,
        file=file,
        line=line,
        severity="HIGH",
        confidence=confidence,
        cwe_id="CWE-89",
        description="SQL injection via user input",
        context_lines=[f"query = 'SELECT * FROM users WHERE id=' + user_id"],
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_analyze_scan_empty(engine):
    """Empty findings list → analysis with 0 FPs and 0 confirmed."""
    analysis = engine.analyze_scan("scan-001", findings=[], fp_fingerprints=[], fn_count=0)
    assert analysis.total_findings == 0
    assert analysis.fp_findings == 0
    assert analysis.confirmed_findings == 0
    assert analysis.fp_rate == 0.0


def test_analyze_scan_with_fps(engine):
    """Findings with some FP fingerprints → precision < 1.0."""
    findings = [_make_finding(line=i) for i in range(1, 6)]
    # Mark 2 of 5 as FPs
    fp_fingerprints = [findings[0].fingerprint(), findings[1].fingerprint()]
    analysis = engine.analyze_scan("scan-002", findings=findings,
                                   fp_fingerprints=fp_fingerprints)
    assert analysis.fp_findings == 2
    assert analysis.confirmed_findings == 3
    assert analysis.precision < 1.0
    assert round(analysis.precision, 4) == round(3 / 5, 4)


def test_fp_pattern_analysis(engine):
    """FPs in test files → common_file_patterns includes 'test_'."""
    findings = [
        _make_finding(file="tests/test_auth.py", line=1),
        _make_finding(file="tests/test_login.py", line=2),
        _make_finding(file="tests/test_utils.py", line=3),
        _make_finding(file="src/app.py", line=4),
    ]
    fp_fingerprints = [findings[0].fingerprint(), findings[1].fingerprint(), findings[2].fingerprint()]
    patterns = engine.analyze_fp_patterns(findings, fp_fingerprints)
    assert len(patterns) > 0
    rule_pattern = patterns[0]
    assert rule_pattern.total_fps == 3
    # At least one file pattern should involve "test_"
    joined = " ".join(rule_pattern.common_file_patterns)
    assert "test_" in joined


def test_improvement_actions_high_fp(engine):
    """Rule with 50% FP rate (≥5 samples) → action to increase threshold."""
    # 10 findings, 5 FPs
    findings = [_make_finding(line=i) for i in range(1, 11)]
    fp_fingerprints = [f.fingerprint() for f in findings[:5]]
    analysis = engine.analyze_scan("scan-003", findings=findings,
                                   fp_fingerprints=fp_fingerprints)
    increase_actions = [
        a for a in analysis.improvement_actions if a.action_type == "increase_threshold"
    ]
    assert len(increase_actions) > 0
    assert increase_actions[0].target_rule_id == "RULE-001"


def test_save_and_load_analysis(engine):
    """save_analysis persists correctly; data is retrievable from DB."""
    findings = [_make_finding(line=i) for i in range(1, 4)]
    analysis = engine.analyze_scan("scan-004", findings=findings, fp_fingerprints=[])
    # Verify it was saved by running the improvement cycle (reads from DB)
    with engine.db.get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scan_analyses WHERE scan_id=?", ("scan-004",)
        ).fetchone()
    assert row is not None
    assert dict(row)["total_findings"] == 3


def test_historical_precision(engine):
    """Store 3 analyses, retrieve historical precision for a specific rule."""
    for i in range(1, 4):
        findings = [_make_finding(line=j) for j in range(1, 11)]
        fp_fingerprints = [findings[0].fingerprint()]  # 1 FP out of 10 → precision=0.9
        engine.analyze_scan(f"scan-hist-{i}", findings=findings,
                            fp_fingerprints=fp_fingerprints)
    prec = engine.get_historical_precision("RULE-001", lookback_days=30)
    # Should be close to 0.9 (9 TPs, 1 FP)
    assert 0.0 < prec <= 1.0


def test_run_improvement_cycle(engine):
    """Full improvement cycle runs without errors and returns ImprovementReport."""
    # Seed some analyses
    for i in range(3):
        findings = [_make_finding(line=j) for j in range(1, 4)]
        engine.analyze_scan(f"scan-cycle-{i}", findings=findings)
    report = engine.run_improvement_cycle(recent_scans=10)
    assert isinstance(report, ImprovementReport)
    assert isinstance(report.generated_at, str)
    assert report.scans_analyzed >= 0


def test_precision_recall_calculation(engine):
    """8 TPs, 2 FPs, 2 FNs → precision=0.8, recall=0.8."""
    # 10 total findings; 2 are FPs
    findings = [_make_finding(line=i) for i in range(1, 11)]
    fp_fingerprints = [findings[8].fingerprint(), findings[9].fingerprint()]
    analysis = engine.analyze_scan("scan-precrecall", findings=findings,
                                   fp_fingerprints=fp_fingerprints, fn_count=2)
    # precision = 8 / (8+2) = 0.8
    assert abs(analysis.precision - 0.8) < 1e-6
    # recall = 8 / (8+2) = 0.8
    assert abs(analysis.recall - 0.8) < 1e-6


def test_no_actions_for_good_rules(engine):
    """Rule with 0% FP rate and only 3 hits → no 'increase_threshold' action."""
    # 3 findings, 0 FPs — below MIN_SAMPLES_FOR_ANALYSIS threshold
    findings = [_make_finding(line=i) for i in range(1, 4)]
    analysis = engine.analyze_scan("scan-good-rule", findings=findings, fp_fingerprints=[])
    increase_actions = [
        a for a in analysis.improvement_actions if a.action_type == "increase_threshold"
    ]
    assert len(increase_actions) == 0


def test_improvement_report_structure(engine):
    """ImprovementReport has all required fields."""
    report = engine.run_improvement_cycle()
    assert hasattr(report, "generated_at")
    assert hasattr(report, "scans_analyzed")
    assert hasattr(report, "total_actions")
    assert hasattr(report, "fp_patterns")
    assert hasattr(report, "actions")
    assert hasattr(report, "precision_delta")
    assert hasattr(report, "recall_delta")
    assert isinstance(report.fp_patterns, list)
    assert isinstance(report.actions, list)
