"""Tests for backend/core/benchmark.py — Module 2."""
import pytest
from backend.core.benchmark import BenchmarkReport, BenchmarkRunner, GroundTruthItem
from backend.core.confidence import Finding


def _finding(rule_id: str, file: str = "app.py", line: int = 0) -> Finding:
    return Finding(rule_id=rule_id, file=file, line=line)


def _gt(rule_id: str, file: str = "app.py", line: int = 0) -> GroundTruthItem:
    return GroundTruthItem(rule_id=rule_id, file=file, line=line)


class TestBenchmarkRunner:
    def setup_method(self):
        self.runner = BenchmarkRunner(
            precision_threshold=0.85,
            recall_threshold=0.80,
            line_tolerance=0,
        )

    def test_perfect_score(self):
        preds = [_finding("R1", "a.py", 10), _finding("R2", "a.py", 20)]
        gt = [_gt("R1", "a.py", 10), _gt("R2", "a.py", 20)]
        report = self.runner.evaluate(preds, gt)
        assert report.precision == 1.0
        assert report.recall == 1.0
        assert report.f1 == 1.0
        assert report.passed is True

    def test_all_false_positives(self):
        preds = [_finding("R1", "a.py", 10)]
        gt = [_gt("R2", "a.py", 20)]
        report = self.runner.evaluate(preds, gt)
        assert report.precision == 0.0
        assert report.recall == 0.0
        assert report.false_positives == 1
        assert report.false_negatives == 1
        assert report.passed is False

    def test_all_false_negatives(self):
        preds: list = []
        gt = [_gt("R1", "a.py", 10), _gt("R2", "a.py", 20)]
        report = self.runner.evaluate(preds, gt)
        assert report.recall == 0.0
        assert report.false_negatives == 2
        assert report.passed is False

    def test_partial_detection(self):
        preds = [_finding("R1", "a.py", 10)]
        gt = [_gt("R1", "a.py", 10), _gt("R2", "a.py", 20)]
        report = self.runner.evaluate(preds, gt)
        assert report.true_positives == 1
        assert report.false_negatives == 1
        assert report.precision == 1.0
        assert report.recall == 0.5

    def test_f1_calculation(self):
        # precision=1.0, recall=0.5 → F1 = 2*1.0*0.5/1.5 ≈ 0.667
        preds = [_finding("R1", "a.py", 10)]
        gt = [_gt("R1", "a.py", 10), _gt("R2", "a.py", 20)]
        report = self.runner.evaluate(preds, gt)
        assert abs(report.f1 - 2 / 3) < 0.01

    def test_pass_threshold_met(self):
        preds = [_finding(f"R{i}", "a.py", i * 10) for i in range(9)]
        gt = [_gt(f"R{i}", "a.py", i * 10) for i in range(10)]
        report = self.runner.evaluate(preds, gt)
        # precision=1.0 recall=0.9 → pass
        assert report.passed is True

    def test_fail_below_threshold(self):
        preds = [_finding("R1", "a.py", 10), _finding("FP", "a.py", 99)]
        gt = [_gt("R1", "a.py", 10)]
        report = self.runner.evaluate(preds, gt)
        # precision = 0.5 → fails
        assert report.passed is False

    def test_empty_both(self):
        report = self.runner.evaluate([], [])
        assert report.precision == 1.0
        assert report.recall == 1.0
        assert report.passed is True

    def test_report_has_details(self):
        preds = [_finding("FP", "a.py", 5)]
        gt = [_gt("R1", "a.py", 10)]
        report = self.runner.evaluate(preds, gt)
        assert "false_positive_findings" in report.details
        assert "missed_findings" in report.details

    def test_summary_format(self):
        report = self.runner.evaluate(
            [_finding("R1", "a.py", 10)],
            [_gt("R1", "a.py", 10)],
            module_name="test_module",
        )
        summary = report.summary()
        assert "PASS" in summary
        assert "test_module" in summary

    def test_run_suite(self):
        cases = [
            {
                "name": "case_a",
                "predicted": [_finding("R1", "a.py", 10)],
                "ground_truth": [_gt("R1", "a.py", 10)],
            },
            {
                "name": "case_b",
                "predicted": [],
                "ground_truth": [_gt("R2", "b.py", 5)],
            },
        ]
        results = self.runner.run_suite_gt(cases)
        assert "case_a" in results
        assert "case_b" in results
        assert results["case_a"].passed is True
        assert results["case_b"].passed is False

    def test_from_raw_dicts(self):
        raw_f = [{"rule_id": "R", "file": "x.py", "line": 1}]
        raw_gt = [{"rule_id": "R", "file": "x.py", "line": 1}]
        findings, gt_items = BenchmarkRunner.from_raw_dicts(raw_f, raw_gt)
        assert len(findings) == 1
        assert len(gt_items) == 1
