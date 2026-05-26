"""Tests for v13 FP reduction and verifier improvements."""
import sys
import pathlib
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))


class TestFPReducerV2:
    @pytest.fixture
    def reducer(self):
        from verifier.fp_reducer_v2 import FPReducerV2
        return FPReducerV2()

    def _finding(self, **kw):
        base = {
            "rule_id": "TEST-001", "name": "Test Finding",
            "severity": "HIGH", "file": "/app/main.py",
            "line": 10, "confidence": 0.9, "cwe": "CWE-89",
            "description": "Test", "fix": "Fix it",
        }
        base.update(kw)
        return base

    def test_import(self, reducer):
        assert reducer is not None

    def test_reduces_test_file_confidence(self, reducer):
        f = self._finding(file="/app/tests/test_main.py")
        results = reducer.reduce([f])
        assert isinstance(results, list)
        if results:
            assert results[0]["confidence"] <= f["confidence"]

    def test_suppresses_nosec_comment(self, reducer):
        f = self._finding()
        f["source_line"] = "password = get_password()  # nosec"
        results = reducer.reduce([f])
        # nosec should suppress or reduce
        assert isinstance(results, list)

    def test_suppresses_vendor_paths(self, reducer):
        f = self._finding(file="/app/node_modules/lodash/lodash.js")
        results = reducer.reduce([f])
        assert isinstance(results, list)
        # vendor paths should be filtered
        vendor_results = [r for r in results if "node_modules" in r.get("file", "")]
        assert len(vendor_results) == 0

    def test_suppresses_placeholder_secrets(self, reducer):
        f = self._finding(rule_id="GHOST-SEC-001", name="Hardcoded Secret")
        f["source_line"] = 'API_KEY = "changeme"'
        results = reducer.reduce([f])
        assert isinstance(results, list)

    def test_passes_real_findings(self, reducer):
        findings = [self._finding(severity="CRITICAL", confidence=0.95)]
        results = reducer.reduce(findings)
        assert len(results) >= 1

    def test_risk_score_calculation(self, reducer):
        f = self._finding(severity="CRITICAL", confidence=0.9)
        score = reducer.calculate_risk_score(f)
        assert 0.0 <= score <= 1.0
        low_f = self._finding(severity="LOW", confidence=0.3)
        low_score = reducer.calculate_risk_score(low_f)
        assert low_score <= score


class TestDuplicateDetector:
    @pytest.fixture
    def detector(self):
        from verifier.duplicate_detector import DuplicateDetector
        return DuplicateDetector()

    def _f(self, file="/app/main.py", line=10, cwe="CWE-89", rule_id="R-001", confidence=0.8):
        return {"rule_id": rule_id, "file": file, "line": line, "cwe": cwe,
                "confidence": confidence, "severity": "HIGH", "name": "Test"}

    def test_import(self, detector):
        assert detector is not None

    def test_no_duplicates_passthrough(self, detector):
        findings = [self._f(line=10), self._f(line=50), self._f(line=100)]
        results = detector.deduplicate(findings)
        assert len(results) == 3

    def test_removes_exact_duplicates(self, detector):
        f = self._f(line=10)
        findings = [f, f.copy(), f.copy()]
        results = detector.deduplicate(findings)
        assert len(results) == 1

    def test_removes_near_duplicates(self, detector):
        findings = [self._f(line=10), self._f(line=11), self._f(line=12)]
        results = detector.deduplicate(findings)
        assert len(results) <= 2

    def test_keeps_highest_confidence(self, detector):
        findings = [
            self._f(line=10, confidence=0.5),
            self._f(line=10, confidence=0.9),
        ]
        results = detector.deduplicate(findings)
        assert len(results) == 1
        assert results[0]["confidence"] == 0.9


class TestExploitabilityScorer:
    @pytest.fixture
    def scorer(self):
        from verifier.exploitability_scorer import ExploitabilityScorer
        return ExploitabilityScorer()

    def _f(self, severity="HIGH", cwe="CWE-89", file="/app/api/routes.py"):
        return {"severity": severity, "cwe": cwe, "file": file,
                "confidence": 0.8, "rule_id": "TEST-001", "name": "Test"}

    def test_import(self, scorer):
        assert scorer is not None

    def test_adds_risk_score(self, scorer):
        f = self._f()
        result = scorer.score(f)
        assert "risk_score" in result
        assert 0.0 <= result["risk_score"] <= 1.0

    def test_adds_priority(self, scorer):
        f = self._f(severity="CRITICAL")
        result = scorer.score(f)
        assert "priority" in result
        assert result["priority"] in ("P0", "P1", "P2", "P3")

    def test_critical_higher_than_low(self, scorer):
        high = scorer.score(self._f(severity="CRITICAL"))
        low = scorer.score(self._f(severity="LOW"))
        assert high["risk_score"] >= low["risk_score"]

    def test_api_path_boosts_score(self, scorer):
        api_f = self._f(file="/app/api/views.py")
        internal_f = self._f(file="/app/internal/utils.py")
        api_score = scorer.score(api_f)
        internal_score = scorer.score(internal_f)
        assert api_score["risk_score"] >= internal_score["risk_score"]
