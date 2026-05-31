"""Tests for backend/core/patch_validator.py."""
from __future__ import annotations
import sys, pathlib
_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.confidence import Finding
from backend.core.patch_validator import PatchValidator, PatchValidationReport, validate_patch


def _f(rule_id="SQLI-001", file="app.py", line=10, severity="CRITICAL", cwe="CWE-89"):
    return Finding(rule_id=rule_id, file=file, line=line, severity=severity,
                   cwe_id=cwe, description=f"{rule_id} at {file}:{line}")


def test_all_fixed():
    # Use widely separated lines to avoid ±5 window cross-matching
    baseline = [_f(line=i*100) for i in range(1, 6)]
    current = []
    validator = PatchValidator()
    report = validator.validate(baseline, current)
    assert report.fixed_count == 5
    assert report.remaining_count == 0
    assert report.regressed_count == 0
    assert report.verdict == "APPROVED"


def test_one_remaining():
    """5 critical baseline → 4 fixed, 1 remaining → PARTIAL verdict."""
    # Use widely separated lines (100, 200, 300, 400, 500) so ±5 matching is unambiguous
    baseline = [_f(line=i*100) for i in range(1, 6)]
    # Keep only line=100 in current (matches baseline[0] only)
    current = [_f(line=100)]
    validator = PatchValidator()
    report = validator.validate(baseline, current)
    assert report.fixed_count == 4, f"Expected 4 fixed, got {report.fixed_count}"
    assert report.remaining_count == 1, f"Expected 1 remaining, got {report.remaining_count}"
    assert report.regressed_count == 0
    assert report.verdict == "PARTIAL"


def test_regression_detected():
    baseline = [_f(rule_id="SQLI-001", line=100, severity="HIGH")]
    current = [
        _f(rule_id="SQLI-001", line=100, severity="HIGH"),   # still there
        _f(rule_id="RCE-001", line=500, severity="CRITICAL"), # new!
    ]
    validator = PatchValidator()
    report = validator.validate(baseline, current)
    assert report.regressed_count == 1
    assert report.verdict == "REJECTED"


def test_patch_effectiveness_calculation():
    # Use widely separated lines (100-step increments) to avoid ambiguous matching
    baseline = [_f(line=i*100) for i in range(1, 11)]  # lines 100,200,...,1000
    current = [_f(line=100), _f(line=200)]             # 2 remaining, 8 fixed
    validator = PatchValidator()
    report = validator.validate(baseline, current)
    # 8 fixed, 2 remaining → effectiveness = 8/10 = 80%
    assert 70.0 <= report.patch_effectiveness <= 90.0, (
        f"Expected 70-90%, got {report.patch_effectiveness:.1f}%  "
        f"(fixed={report.fixed_count} remaining={report.remaining_count})"
    )


def test_summary_line_format():
    baseline = [_f(line=i) for i in range(5)]
    current = [_f(line=0)]
    validator = PatchValidator()
    report = validator.validate(baseline, current)
    summary = report.summary_line()
    assert isinstance(summary, str)
    assert "fixed" in summary.lower() or "✅" in summary


def test_to_markdown():
    baseline = [_f(line=i) for i in range(3)]
    current = [_f(line=0)]
    validator = PatchValidator()
    report = validator.validate(baseline, current)
    md = report.to_markdown()
    assert isinstance(md, str)
    assert len(md) > 50


def test_module_level_validate_patch():
    baseline = [_f(line=i) for i in range(3)]
    current = []
    report = validate_patch(baseline, current)
    assert isinstance(report, PatchValidationReport)
    assert report.fixed_count == 3
