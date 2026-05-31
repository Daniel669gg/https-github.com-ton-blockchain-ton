"""
tests/test_benchmark.py
Unit tests for backend/core/benchmark.py (OWASP-style benchmark suite).

Tests:
1. Single TP case → precision=1.0, recall=1.0
2. FP case (scanner fires unexpected rule) → precision < 1.0
3. FN case (scanner misses expected rule) → recall < 1.0
4. run_owasp_benchmark with a trivial scanner → BenchmarkSuite returned
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from backend.core.confidence import Finding
from backend.core.benchmark import (
    BenchmarkResult,
    BenchmarkRunner,
    BenchmarkSuite,
    OWASP_TEST_CASES,
    TestCase,
    run_owasp_benchmark,
)


# ---------------------------------------------------------------------------
# Helper scanner factories
# ---------------------------------------------------------------------------

def _scanner_returns(*rule_ids: str):
    """Return a scanner callable that always returns the given rule_ids."""
    def scanner(file_path: str):
        return [
            Finding(rule_id=rid, file=file_path, line=1, severity="MEDIUM")
            for rid in rule_ids
        ]
    return scanner


def _scanner_returns_none(_: str):
    """Scanner that finds nothing."""
    return []


# ---------------------------------------------------------------------------
# 1. Single TP case → precision=1.0, recall=1.0
# ---------------------------------------------------------------------------

class TestSingleTruePositive:
    def setup_method(self):
        self.runner = BenchmarkRunner(
            precision_threshold=0.85,
            recall_threshold=0.80,
        )

    def test_single_tp_precision_and_recall_are_1(self):
        """Scanner fires exactly the expected rule → perfect precision and recall."""
        test_case = TestCase(
            name="tp_test",
            code="x = eval(user_input)",
            expected_findings=["CODE_INJECTION"],
            expected_no_findings=["SQLI001"],
        )
        scanner = _scanner_returns("CODE_INJECTION")
        result = self.runner.run_test(test_case, scanner)

        assert result.true_positives == 1
        assert result.false_positives == 0
        assert result.false_negatives == 0
        assert result.precision == pytest.approx(1.0, abs=1e-6)
        assert result.recall == pytest.approx(1.0, abs=1e-6)
        assert result.f1_score == pytest.approx(1.0, abs=1e-6)

    def test_single_tp_passes(self):
        test_case = TestCase(
            name="tp_pass_test",
            code="import pickle; pickle.loads(data)",
            expected_findings=["INSECURE_DESERIALIZATION"],
        )
        scanner = _scanner_returns("INSECURE_DESERIALIZATION")
        result = self.runner.run_test(test_case, scanner)

        assert result.passed is True

    def test_multiple_expected_all_fired(self):
        """All expected rules fire → TP=2, precision=recall=1.0."""
        test_case = TestCase(
            name="multi_tp",
            code="",
            expected_findings=["RULE_A", "RULE_B"],
        )
        scanner = _scanner_returns("RULE_A", "RULE_B")
        result = self.runner.run_test(test_case, scanner)

        assert result.true_positives == 2
        assert result.false_positives == 0
        assert result.false_negatives == 0
        assert result.precision == pytest.approx(1.0, abs=1e-6)
        assert result.recall == pytest.approx(1.0, abs=1e-6)


# ---------------------------------------------------------------------------
# 2. FP case → precision < 1.0
# ---------------------------------------------------------------------------

class TestFalsePositiveCase:
    def setup_method(self):
        self.runner = BenchmarkRunner(
            precision_threshold=0.85,
            recall_threshold=0.80,
        )

    def test_fp_reduces_precision(self):
        """Scanner fires an extra rule not in expected_findings → FP → precision < 1.0."""
        test_case = TestCase(
            name="fp_test",
            code="x = 1 + 1",
            expected_findings=["RULE_A"],
        )
        # Scanner fires RULE_A (TP) AND UNEXPECTED_RULE (FP)
        scanner = _scanner_returns("RULE_A", "UNEXPECTED_RULE")
        result = self.runner.run_test(test_case, scanner)

        assert result.false_positives >= 1
        assert result.precision < 1.0

    def test_fp_without_tp_gives_precision_zero(self):
        """Scanner fires only unexpected rules → TP=0, precision=0.0."""
        test_case = TestCase(
            name="fp_no_tp",
            code="",
            expected_findings=["CORRECT_RULE"],
        )
        scanner = _scanner_returns("WRONG_RULE")
        result = self.runner.run_test(test_case, scanner)

        assert result.true_positives == 0
        assert result.false_positives == 1
        assert result.false_negatives == 1
        assert result.precision == pytest.approx(0.0, abs=1e-6)
        assert result.recall == pytest.approx(0.0, abs=1e-6)
        assert result.passed is False

    def test_expected_no_findings_triggered_fails_test(self):
        """If a rule in expected_no_findings fires, the test should fail."""
        test_case = TestCase(
            name="no_findings_violated",
            code="",
            expected_findings=["RULE_A"],
            expected_no_findings=["BANNED_RULE"],
        )
        # Scanner fires RULE_A (TP) and BANNED_RULE (should not fire)
        scanner = _scanner_returns("RULE_A", "BANNED_RULE")
        result = self.runner.run_test(test_case, scanner)

        assert result.passed is False

    def test_negative_test_with_scanner_firing_fails(self):
        """A negative test (no expected_findings) with a scanner finding should fail."""
        test_case = TestCase(
            name="negative_fires",
            code="x = 1",
            expected_findings=[],
            expected_no_findings=["WRONG_RULE"],
        )
        scanner = _scanner_returns("WRONG_RULE")
        result = self.runner.run_test(test_case, scanner)

        assert result.passed is False


# ---------------------------------------------------------------------------
# 3. FN case → recall < 1.0
# ---------------------------------------------------------------------------

class TestFalseNegativeCase:
    def setup_method(self):
        self.runner = BenchmarkRunner(
            precision_threshold=0.85,
            recall_threshold=0.80,
        )

    def test_fn_reduces_recall(self):
        """Scanner misses expected rule → FN → recall < 1.0."""
        test_case = TestCase(
            name="fn_test",
            code="import os; os.system(cmd)",
            expected_findings=["CMDI001"],
        )
        scanner = _scanner_returns_none  # misses the finding entirely
        result = self.runner.run_test(test_case, scanner)

        assert result.false_negatives >= 1
        assert result.recall < 1.0

    def test_fn_no_tp_gives_recall_zero(self):
        """Scanner returns nothing for a case with expected findings → recall=0."""
        test_case = TestCase(
            name="fn_complete_miss",
            code="",
            expected_findings=["SQLI001", "XSS001"],
        )
        result = self.runner.run_test(test_case, _scanner_returns_none)

        assert result.true_positives == 0
        assert result.false_negatives == 2
        assert result.recall == pytest.approx(0.0, abs=1e-6)
        assert result.passed is False

    def test_partial_recall(self):
        """Scanner fires only one of two expected rules → recall=0.5."""
        test_case = TestCase(
            name="partial_recall",
            code="",
            expected_findings=["RULE_A", "RULE_B"],
        )
        scanner = _scanner_returns("RULE_A")
        result = self.runner.run_test(test_case, scanner)

        assert result.true_positives == 1
        assert result.false_negatives == 1
        assert result.recall == pytest.approx(0.5, abs=1e-6)

    def test_fn_result_not_passed_with_low_recall(self):
        test_case = TestCase(
            name="fn_not_passed",
            code="",
            expected_findings=["RULE_A", "RULE_B", "RULE_C"],
        )
        # Only fires RULE_A: recall = 1/3 ≈ 0.33 < 0.80 threshold
        scanner = _scanner_returns("RULE_A")
        result = self.runner.run_test(test_case, scanner)

        assert result.passed is False


# ---------------------------------------------------------------------------
# 4. run_owasp_benchmark with trivial scanner → BenchmarkSuite returned
# ---------------------------------------------------------------------------

class TestRunOwaspBenchmark:
    def test_returns_benchmark_suite_instance(self):
        """run_owasp_benchmark must return a BenchmarkSuite regardless of scanner."""
        suite = run_owasp_benchmark(_scanner_returns_none)

        assert isinstance(suite, BenchmarkSuite)

    def test_suite_name_is_owasp_benchmark(self):
        suite = run_owasp_benchmark(_scanner_returns_none)

        assert suite.name == "OWASP-Benchmark"

    def test_suite_total_equals_owasp_test_cases_count(self):
        suite = run_owasp_benchmark(_scanner_returns_none)

        assert suite.total == len(OWASP_TEST_CASES)
        assert len(suite.results) == len(OWASP_TEST_CASES)

    def test_suite_has_aggregated_metrics(self):
        """Aggregate precision/recall/f1 must be in [0, 1]."""
        suite = run_owasp_benchmark(_scanner_returns_none)

        assert 0.0 <= suite.precision <= 1.0
        assert 0.0 <= suite.recall <= 1.0
        assert 0.0 <= suite.f1_score <= 1.0

    def test_each_result_has_test_name(self):
        """Every BenchmarkResult should have a non-empty test_name."""
        suite = run_owasp_benchmark(_scanner_returns_none)

        for result in suite.results:
            assert isinstance(result, BenchmarkResult)
            assert result.test_name != ""

    def test_trivial_scanner_finds_nothing_recall_is_low(self):
        """A scanner that never fires should have very low aggregate recall."""
        suite = run_owasp_benchmark(_scanner_returns_none)

        # Cases with expected_findings will all be FN → recall ≈ 0
        positive_cases = [tc for tc in OWASP_TEST_CASES if tc.expected_findings]
        positive_results = [r for r in suite.results if r.test_name in {tc.name for tc in positive_cases}]
        for r in positive_results:
            assert r.recall == pytest.approx(0.0, abs=1e-6)

    def test_perfect_scanner_passes_suite(self):
        """
        A scanner that fires exactly the first expected_finding for every test
        case should achieve decent recall (1 TP per case).
        """
        def perfect_scanner(file_path: str) -> list:
            # Look up the test case by name via the temp file path trick
            # (we can't easily correlate file → test case name, so just
            #  return findings for all possible expected rule IDs)
            findings = []
            for tc in OWASP_TEST_CASES:
                for rid in tc.expected_findings:
                    findings.append(
                        Finding(rule_id=rid, file=file_path, line=1, severity="MEDIUM")
                    )
            return findings

        suite = run_owasp_benchmark(perfect_scanner)

        assert isinstance(suite, BenchmarkSuite)
        # All expected findings fired → every positive test has recall=1.0
        for result in suite.results:
            tc = next(tc for tc in OWASP_TEST_CASES if tc.name == result.test_name)
            if tc.expected_findings:
                assert result.recall == pytest.approx(1.0, abs=1e-6)

    def test_benchmark_runner_meets_thresholds(self):
        """meets_thresholds returns False for a trivial scanner."""
        runner = BenchmarkRunner()
        suite = runner.run_suite(OWASP_TEST_CASES, _scanner_returns_none, "test")

        assert runner.meets_thresholds(suite) is False

    def test_owasp_test_cases_have_at_least_20_entries(self):
        """Verify the OWASP_TEST_CASES list has the minimum required cases."""
        assert len(OWASP_TEST_CASES) >= 20

    def test_all_test_cases_have_name_and_code(self):
        """All test cases must have a name and non-empty code."""
        for tc in OWASP_TEST_CASES:
            assert tc.name, f"TestCase missing name: {tc}"
            assert tc.code.strip(), f"TestCase '{tc.name}' has empty code"
