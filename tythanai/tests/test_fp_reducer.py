"""
tests/test_fp_reducer.py
Unit tests for backend/core/fp_reducer.py

Tests cover:
1. Test-file detection → confidence reduced by ≥ 0.3
2. Vendor/generated file → suppressed
3. KEV finding → confidence increased
4. Non-reachable finding → confidence reduced
5. CRITICAL severity not suppressed even at low confidence
6. LOW severity at very low confidence → is_suppressed=True
7. Full pipeline with mixed findings → correct aggregate stats
8. Empty contexts defaults → no changes from context-only passes
"""
from __future__ import annotations

import sys
import os

# Ensure project root is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from backend.core.confidence import Finding
from backend.core.fp_reducer import (
    FPContext,
    FPReductionPipeline,
    reduce_false_positives,
)


# ---------------------------------------------------------------------------
# Helper factories
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
# 1. Test file → confidence reduced by ≥ 0.3
# ---------------------------------------------------------------------------

class TestTestFilePass:
    def test_test_file_path_reduces_confidence(self):
        finding = _finding(file="tests/test_auth.py", confidence=0.8)
        pipeline = FPReductionPipeline(min_confidence=0.0)  # don't suppress
        [result] = pipeline.reduce([finding], {})

        assert result.is_test_file is True
        assert result.confidence <= 0.8 - 0.3

    def test_test_file_marker_in_path(self):
        """Any marker like 'test_' in the path should trigger the pass."""
        finding = _finding(file="project/test_utils.py", confidence=0.9)
        pipeline = FPReductionPipeline(min_confidence=0.0)
        [result] = pipeline.reduce([finding], {})

        assert result.is_test_file is True
        assert result.confidence <= 0.9 - 0.3

    def test_test_file_via_context_flag(self):
        """ctx.is_test_file=True should also trigger the pass."""
        finding = _finding(file="src/app.py", confidence=0.75)
        ctx = FPContext(is_test_file=True)
        pipeline = FPReductionPipeline(min_confidence=0.0)
        [result] = pipeline.reduce([finding], {"src/app.py": ctx})

        assert result.is_test_file is True
        assert result.confidence <= 0.75 - 0.3

    def test_non_test_file_unaffected(self):
        """A regular production file should NOT be flagged as test."""
        finding = _finding(file="src/handlers/auth.py", confidence=0.8)
        pipeline = FPReductionPipeline(min_confidence=0.0)
        [result] = pipeline.reduce([finding], {})

        assert result.is_test_file is False
        # confidence unchanged by TestFilePass (other passes may apply, but
        # for a default context none of them should fire except SeverityConsistency)
        assert result.confidence == pytest.approx(0.8, abs=0.01)


# ---------------------------------------------------------------------------
# 2. Vendor/generated file → suppressed
# ---------------------------------------------------------------------------

class TestGeneratedFilePass:
    def test_vendor_path_confidence_reduced(self):
        """vendor/ path triggers GeneratedFilePass: confidence -= 0.4."""
        finding = _finding(file="vendor/requests/api.py", confidence=0.9)
        pipeline = FPReductionPipeline(min_confidence=0.5)
        [result] = pipeline.reduce([finding], {})

        # 0.9 - 0.4 = 0.5 which is NOT < 0.5 (strict), so not suppressed
        assert result.confidence == pytest.approx(0.5, abs=0.01)
        assert result.is_suppressed is False

    def test_vendor_path_suppressed_when_confidence_falls_below_threshold(self):
        """vendor/ at confidence 0.8 → 0.8 - 0.4 = 0.4 < 0.5 → suppressed."""
        finding = _finding(file="vendor/requests/api.py", confidence=0.8)
        pipeline = FPReductionPipeline(min_confidence=0.5)
        [result] = pipeline.reduce([finding], {})

        assert result.confidence == pytest.approx(0.4, abs=0.01)
        assert result.is_suppressed is True

    def test_vendor_via_context_flag(self):
        finding = _finding(file="src/app.py", confidence=0.9)
        ctx = FPContext(is_vendor=True)
        pipeline = FPReductionPipeline(min_confidence=0.5)
        [result] = pipeline.reduce([finding], {"src/app.py": ctx})

        assert result.confidence == pytest.approx(0.9 - 0.4, abs=0.01)

    def test_node_modules_suppressed(self):
        finding = _finding(file="frontend/node_modules/lodash/index.js", confidence=0.85)
        pipeline = FPReductionPipeline(min_confidence=0.5)
        [result] = pipeline.reduce([finding], {})

        # 0.85 - 0.4 = 0.45 < 0.5 → suppressed
        assert result.is_suppressed is True

    def test_migrations_suppressed(self):
        finding = _finding(file="backend/migrations/0001_initial.py", confidence=0.8)
        pipeline = FPReductionPipeline(min_confidence=0.5)
        [result] = pipeline.reduce([finding], {})

        # 0.8 - 0.4 = 0.4 < 0.5 → suppressed
        assert result.is_suppressed is True

    def test_generated_context_flag(self):
        finding = _finding(file="app/models.py", confidence=0.8)
        ctx = FPContext(is_generated=True)
        pipeline = FPReductionPipeline(min_confidence=0.5)
        [result] = pipeline.reduce([finding], {"app/models.py": ctx})

        assert result.confidence == pytest.approx(0.8 - 0.4, abs=0.01)
        assert result.is_suppressed is True  # 0.4 < 0.5


# ---------------------------------------------------------------------------
# 3. KEV finding → confidence increased
# ---------------------------------------------------------------------------

class TestExploitabilityPassKEV:
    def test_kev_boosts_confidence(self):
        finding = _finding(confidence=0.7)
        ctx = FPContext(is_kev=True)
        pipeline = FPReductionPipeline(min_confidence=0.0)
        [result] = pipeline.reduce([finding], {"src/app.py": ctx})

        assert result.confidence > 0.7
        # ExploitabilityPass adds +0.15
        assert result.confidence == pytest.approx(0.7 + 0.15, abs=0.01)

    def test_high_epss_boosts_confidence(self):
        finding = _finding(confidence=0.6)
        ctx = FPContext(cve_epss=0.55)
        pipeline = FPReductionPipeline(min_confidence=0.0)
        [result] = pipeline.reduce([finding], {"src/app.py": ctx})

        assert result.confidence == pytest.approx(0.6 + 0.10, abs=0.01)

    def test_medium_epss_boosts_confidence(self):
        finding = _finding(confidence=0.6)
        ctx = FPContext(cve_epss=0.15)
        pipeline = FPReductionPipeline(min_confidence=0.0)
        [result] = pipeline.reduce([finding], {"src/app.py": ctx})

        assert result.confidence == pytest.approx(0.6 + 0.05, abs=0.01)


# ---------------------------------------------------------------------------
# 4. Non-reachable finding → confidence reduced
# ---------------------------------------------------------------------------

class TestExploitabilityPassNonReachable:
    def test_non_reachable_reduces_confidence(self):
        finding = _finding(confidence=0.75)
        ctx = FPContext(reachable_from_entrypoint=False)
        pipeline = FPReductionPipeline(min_confidence=0.0)
        [result] = pipeline.reduce([finding], {"src/app.py": ctx})

        assert result.confidence == pytest.approx(0.75 - 0.25, abs=0.01)

    def test_reachable_entrypoint_no_penalty(self):
        finding = _finding(confidence=0.75)
        ctx = FPContext(reachable_from_entrypoint=True)
        pipeline = FPReductionPipeline(min_confidence=0.0)
        [result] = pipeline.reduce([finding], {"src/app.py": ctx})

        # No penalty from ExploitabilityPass (reachable=True, no KEV/EPSS)
        assert result.confidence == pytest.approx(0.75, abs=0.01)

    def test_non_reachable_can_trigger_suppression(self):
        """0.6 - 0.25 = 0.35 < 0.5 → suppressed."""
        finding = _finding(confidence=0.6)
        ctx = FPContext(reachable_from_entrypoint=False)
        pipeline = FPReductionPipeline(min_confidence=0.5)
        [result] = pipeline.reduce([finding], {"src/app.py": ctx})

        assert result.is_suppressed is True


# ---------------------------------------------------------------------------
# 5. CRITICAL severity not suppressed even at low confidence
# ---------------------------------------------------------------------------

class TestSeverityConsistencyPassCritical:
    def test_critical_confidence_clamped_at_0_6(self):
        """A CRITICAL finding at confidence 0.4 should be bumped to 0.6."""
        finding = _finding(severity="CRITICAL", confidence=0.4)
        pipeline = FPReductionPipeline(min_confidence=0.5)
        [result] = pipeline.reduce([finding], {})

        assert result.confidence >= 0.6
        assert result.is_suppressed is False

    def test_critical_not_suppressed_below_min_confidence_threshold(self):
        """Even if raw delta would push below threshold, CRITICAL is protected."""
        finding = _finding(severity="CRITICAL", confidence=0.3)
        ctx = FPContext(reachable_from_entrypoint=False)  # -0.25 → 0.05 → bumped to 0.6
        pipeline = FPReductionPipeline(min_confidence=0.5)
        [result] = pipeline.reduce([finding], {"src/app.py": ctx})

        # SeverityConsistencyPass bumps confidence to 0.6 BEFORE suppression check
        assert result.is_suppressed is False
        assert result.confidence >= 0.6


# ---------------------------------------------------------------------------
# 6. LOW severity at very low confidence → is_suppressed=True
# ---------------------------------------------------------------------------

class TestSeverityConsistencyPassLow:
    def test_low_severity_very_low_confidence_suppressed(self):
        finding = _finding(severity="LOW", confidence=0.25)
        pipeline = FPReductionPipeline(min_confidence=0.5)
        [result] = pipeline.reduce([finding], {})

        assert result.is_suppressed is True

    def test_low_severity_adequate_confidence_not_suppressed(self):
        finding = _finding(severity="LOW", confidence=0.6)
        pipeline = FPReductionPipeline(min_confidence=0.5)
        [result] = pipeline.reduce([finding], {})

        assert result.is_suppressed is False

    def test_low_severity_at_exactly_0_3_boundary(self):
        """Confidence exactly at 0.3 should NOT trigger the LOW suppression (< 0.3)."""
        finding = _finding(severity="LOW", confidence=0.3)
        pipeline = FPReductionPipeline(min_confidence=0.0)
        [result] = pipeline.reduce([finding], {})

        # 0.3 is NOT < 0.3, so SeverityConsistencyPass should NOT suppress
        assert result.is_suppressed is False


# ---------------------------------------------------------------------------
# 7. Full pipeline with mixed findings → correct stats
# ---------------------------------------------------------------------------

class TestFullPipelineStats:
    def test_mixed_findings_stats(self):
        # vendor/lib.py: 0.9 - 0.4 = 0.5 → NOT suppressed (0.5 is not < 0.5)
        # app/views.py: 0.8 → NOT suppressed
        # tests/test_auth.py: 0.7 - 0.3 = 0.4 → suppressed
        # app/exec.py: CRITICAL 0.9 → NOT suppressed (CRITICAL protected)
        # app/misc.py: LOW 0.2 → suppressed by SeverityConsistencyPass (< 0.3)
        findings = [
            _finding(rule_id="SQLI001", file="vendor/lib.py", confidence=0.9, severity="HIGH"),
            _finding(rule_id="XSS001", file="app/views.py", confidence=0.8, severity="HIGH"),
            _finding(rule_id="TAINT001", file="tests/test_auth.py", confidence=0.7, severity="MEDIUM"),
            _finding(rule_id="RCE001", file="app/exec.py", confidence=0.9, severity="CRITICAL"),
            _finding(rule_id="INFO001", file="app/misc.py", confidence=0.2, severity="LOW"),
        ]

        pipeline = FPReductionPipeline(min_confidence=0.5)
        results = pipeline.reduce(findings, {})
        stats = pipeline.get_stats(results)

        assert stats["total"] == 5
        # test file (0.4 < 0.5) + LOW (0.2 < 0.3) = 2 suppressed
        assert stats["suppressed"] >= 2
        assert stats["by_severity"]["CRITICAL"] == 1
        assert stats["by_severity"]["HIGH"] == 2
        assert isinstance(stats["suppression_rate"], float)
        assert 0.0 <= stats["suppression_rate"] <= 1.0

    def test_mixed_findings_critical_not_suppressed(self):
        """CRITICAL findings must never appear as suppressed in the stats."""
        findings = [
            _finding(rule_id="RCE001", file="app/exec.py", confidence=0.9, severity="CRITICAL"),
            _finding(rule_id="XSS001", file="app/views.py", confidence=0.8, severity="HIGH"),
        ]
        pipeline = FPReductionPipeline(min_confidence=0.5)
        results = pipeline.reduce(findings, {})

        critical = [r for r in results if r.severity == "CRITICAL"]
        assert all(not r.is_suppressed for r in critical)

    def test_all_suppressed_gives_rate_1_0(self):
        # Use confidences that will both fall strictly below min_confidence=0.5
        # after the -0.4 GeneratedFilePass delta:
        # 0.8 - 0.4 = 0.4 < 0.5 → suppressed
        # 0.7 - 0.4 = 0.3 < 0.5 → suppressed
        findings = [
            _finding(file="vendor/a.py", confidence=0.8),
            _finding(file="vendor/b.py", confidence=0.7),
        ]
        pipeline = FPReductionPipeline(min_confidence=0.5)
        results = pipeline.reduce(findings, {})
        stats = pipeline.get_stats(results)

        assert stats["suppression_rate"] == pytest.approx(1.0, abs=0.01)

    def test_empty_findings_gives_zero_rate(self):
        pipeline = FPReductionPipeline()
        stats = pipeline.get_stats([])

        assert stats["total"] == 0
        assert stats["suppression_rate"] == 0.0


# ---------------------------------------------------------------------------
# 8. Empty contexts defaults to no change
# ---------------------------------------------------------------------------

class TestEmptyContexts:
    def test_no_context_no_change_for_normal_file(self):
        """With empty contexts and a normal file, no passes should fire (except
        SeverityConsistencyPass which only modifies edge cases)."""
        finding = _finding(
            file="src/models/user.py",
            confidence=0.8,
            severity="MEDIUM",
        )
        pipeline = FPReductionPipeline(min_confidence=0.5)
        [result] = pipeline.reduce([finding], {})

        # No test/vendor/generated markers, reachable by default, no KEV/EPSS
        assert result.is_suppressed is False
        assert result.confidence == pytest.approx(0.8, abs=0.01)

    def test_reduce_false_positives_convenience_function(self):
        """The module-level helper with contexts=None should work identically."""
        findings = [_finding(file="src/auth.py", confidence=0.8)]
        results = reduce_false_positives(findings, contexts=None, min_confidence=0.5)

        assert len(results) == 1
        assert results[0].is_suppressed is False
        assert results[0].confidence == pytest.approx(0.8, abs=0.01)

    def test_reduce_false_positives_empty_list(self):
        results = reduce_false_positives([], contexts=None)
        assert results == []

    def test_default_context_reachable_true(self):
        """Default FPContext has reachable_from_entrypoint=True; ExploitabilityPass
        should not add the -0.25 penalty."""
        finding = _finding(confidence=0.6)
        ctx = FPContext()  # default
        pipeline = FPReductionPipeline(min_confidence=0.0)
        [result] = pipeline.reduce([finding], {"src/app.py": ctx})

        assert result.confidence == pytest.approx(0.6, abs=0.01)
