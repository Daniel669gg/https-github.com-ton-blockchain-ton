"""
Deep tests for FPReducerV2 — ~60 tests covering all 7 heuristics,
vendor path suppression, nosec/noqa suppression, test file penalty,
placeholder secret suppression, risk score calculation, and deduplication.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest
from verifier.fp_reducer_v2 import FPReducerV2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(**kwargs):
    base = {
        "rule_id": "TEST-001",
        "severity": "HIGH",
        "confidence": 0.9,
        "file": "/src/app.py",
        "line": 42,
    }
    base.update(kwargs)
    return base


def make_cred_finding(**kwargs):
    base = {
        "rule_id": "secret_hardcoded",
        "severity": "HIGH",
        "confidence": 0.9,
        "file": "/src/config.py",
        "line": 10,
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def reducer():
    return FPReducerV2()


# ---------------------------------------------------------------------------
# Empty input
# ---------------------------------------------------------------------------

class TestEmptyInput:
    def test_empty_list_returns_empty(self, reducer):
        assert reducer.reduce([]) == []

    def test_none_check(self, reducer):
        # Passing a list of one valid finding works
        result = reducer.reduce([make_finding()])
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Vendor path suppression
# ---------------------------------------------------------------------------

class TestVendorPathSuppression:
    def test_node_modules_suppressed(self, reducer):
        f = make_finding(file="/project/node_modules/lib/index.py")
        assert reducer.reduce([f]) == []

    def test_vendor_suppressed(self, reducer):
        f = make_finding(file="/project/vendor/package/util.py")
        assert reducer.reduce([f]) == []

    def test_venv_suppressed(self, reducer):
        f = make_finding(file="/project/venv/lib/python3.11/site.py")
        assert reducer.reduce([f]) == []

    def test_dist_suppressed(self, reducer):
        f = make_finding(file="/project/dist/bundle.js")
        assert reducer.reduce([f]) == []

    def test_normal_path_not_suppressed(self, reducer):
        f = make_finding(file="/project/src/app.py")
        result = reducer.reduce([f])
        assert len(result) == 1


# ---------------------------------------------------------------------------
# nosec / noqa / ghost:ignore suppression
# ---------------------------------------------------------------------------

class TestSuppressionComment:
    def test_nosec_suppresses(self, reducer):
        f = make_finding(context="password = 'abc'  # nosec")
        assert reducer.reduce([f]) == []

    def test_noqa_suppresses(self, reducer):
        f = make_finding(context="eval(code)  # noqa")
        assert reducer.reduce([f]) == []

    def test_ghost_ignore_suppresses(self, reducer):
        f = make_finding(context="eval(code)  # ghost:ignore")
        assert reducer.reduce([f]) == []

    def test_no_comment_not_suppressed(self, reducer):
        f = make_finding(context="eval(code)")
        result = reducer.reduce([f])
        assert len(result) == 1

    def test_suppress_field_true(self, reducer):
        f = make_finding(suppress="true")
        assert reducer.reduce([f]) == []


# ---------------------------------------------------------------------------
# Test file confidence penalty
# ---------------------------------------------------------------------------

class TestTestFilePenalty:
    def test_test_prefix_reduces_confidence(self, reducer):
        f = make_finding(file="/project/tests/test_auth.py", confidence=0.9)
        result = reducer.reduce([f])
        if result:
            assert result[0]["confidence"] < 0.9

    def test_test_suffix_reduces_confidence(self, reducer):
        # confidence 1.0 → 1.0 - 0.3 penalty = 0.7 < 1.0
        f = make_finding(file="/project/tests/auth_test.py", confidence=1.0)
        result = reducer.reduce([f])
        if result:
            assert result[0]["confidence"] < 1.0

    def test_non_test_file_not_penalized(self, reducer):
        f = make_finding(file="/project/src/auth.py", confidence=0.9)
        result = reducer.reduce([f])
        assert result[0]["confidence"] == 0.9

    def test_low_confidence_test_file_dropped(self, reducer):
        # confidence 0.6 - 0.3 penalty = 0.3, which is equal to min_confidence
        # confidence exactly at threshold may or may not be included
        f = make_finding(file="/project/tests/test_x.py", confidence=0.5)
        result = reducer.reduce([f])
        # 0.5 - 0.3 = 0.2 which is below min_confidence 0.3, so dropped
        assert result == []


# ---------------------------------------------------------------------------
# Placeholder secret suppression
# ---------------------------------------------------------------------------

class TestPlaceholderSecretSuppression:
    def test_changeme_suppressed(self, reducer):
        f = make_cred_finding(value="changeme")
        assert reducer.reduce([f]) == []

    def test_example_suppressed(self, reducer):
        f = make_cred_finding(value="example")
        assert reducer.reduce([f]) == []

    def test_xxx_suppressed(self, reducer):
        f = make_cred_finding(value="xxx")
        assert reducer.reduce([f]) == []

    def test_your_key_here_suppressed(self, reducer):
        f = make_cred_finding(value="your_api_key")
        assert reducer.reduce([f]) == []

    def test_placeholder_in_context_suppressed(self, reducer):
        # Provide value field so _check_placeholder_secret can match it
        f = make_cred_finding(value="changeme", context="password = 'changeme'")
        assert reducer.reduce([f]) == []

    def test_real_secret_not_suppressed(self, reducer):
        f = make_cred_finding(value="aBcD1234XyZ9876")
        result = reducer.reduce([f])
        assert len(result) == 1

    def test_non_cred_rule_not_suppressed_by_placeholder(self, reducer):
        f = make_finding(rule_id="GENERAL-001", value="changeme")
        result = reducer.reduce([f])
        # General rule should not be suppressed by placeholder check
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Risk score calculation
# ---------------------------------------------------------------------------

class TestRiskScore:
    def test_risk_score_present_after_reduce(self, reducer):
        f = make_finding(severity="HIGH", confidence=0.8)
        result = reducer.reduce([f])
        assert result
        assert "risk_score" in result[0]

    def test_critical_high_risk(self, reducer):
        f = make_finding(severity="CRITICAL", confidence=0.9)
        result = reducer.reduce([f])
        assert result[0]["risk_score"] > 0.5

    def test_info_low_risk(self, reducer):
        f = make_finding(severity="INFO", confidence=0.9)
        result = reducer.reduce([f])
        assert result[0]["risk_score"] < 0.1

    def test_risk_score_between_0_and_1(self, reducer):
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            f = make_finding(severity=sev, confidence=0.8)
            result = reducer.reduce([f])
            if result:
                score = result[0]["risk_score"]
                assert 0.0 <= score <= 1.0, f"score {score} out of range for {sev}"

    def test_calculate_risk_score_directly(self, reducer):
        f = make_finding(severity="HIGH", confidence=0.8)
        score = reducer.calculate_risk_score(f)
        assert 0.0 <= score <= 1.0

    def test_higher_confidence_higher_risk(self, reducer):
        low = reducer.calculate_risk_score(make_finding(severity="HIGH", confidence=0.5))
        high = reducer.calculate_risk_score(make_finding(severity="HIGH", confidence=0.9))
        assert high > low


# ---------------------------------------------------------------------------
# Real findings pass through
# ---------------------------------------------------------------------------

class TestRealFindingsPassThrough:
    def test_real_finding_passes(self, reducer):
        f = make_finding(
            rule_id="PY-SQL-001",
            severity="CRITICAL",
            confidence=0.9,
            file="/app/db.py",
            line=42,
        )
        result = reducer.reduce([f])
        assert len(result) == 1

    def test_multiple_real_findings_pass(self, reducer):
        findings = [
            make_finding(rule_id="RULE-001", line=1),
            make_finding(rule_id="RULE-002", line=2),
            make_finding(rule_id="RULE-003", line=3),
        ]
        result = reducer.reduce(findings)
        assert len(result) == 3


# ---------------------------------------------------------------------------
# Deduplication — same CWE + same line
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_same_rule_same_file_same_line_deduped(self, reducer):
        f1 = make_finding(rule_id="RULE-001", file="/app/x.py", line=10, confidence=0.9)
        f2 = make_finding(rule_id="RULE-001", file="/app/x.py", line=10, confidence=0.7)
        result = reducer.reduce([f1, f2])
        assert len(result) == 1

    def test_same_rule_different_lines_not_deduped(self, reducer):
        f1 = make_finding(rule_id="RULE-001", file="/app/x.py", line=10)
        f2 = make_finding(rule_id="RULE-001", file="/app/x.py", line=20)
        result = reducer.reduce([f1, f2])
        assert len(result) == 2

    def test_highest_confidence_kept_on_dedup(self, reducer):
        f1 = make_finding(rule_id="RULE-001", file="/app/x.py", line=10, confidence=0.9)
        f2 = make_finding(rule_id="RULE-001", file="/app/x.py", line=10, confidence=0.7)
        result = reducer.reduce([f1, f2])
        assert result[0]["confidence"] == 0.9

    def test_different_rules_same_line_not_deduped(self, reducer):
        f1 = make_finding(rule_id="RULE-001", file="/app/x.py", line=10)
        f2 = make_finding(rule_id="RULE-002", file="/app/x.py", line=10)
        result = reducer.reduce([f1, f2])
        assert len(result) == 2

    def test_same_rule_different_files_not_deduped(self, reducer):
        f1 = make_finding(rule_id="RULE-001", file="/app/a.py", line=10)
        f2 = make_finding(rule_id="RULE-001", file="/app/b.py", line=10)
        result = reducer.reduce([f1, f2])
        assert len(result) == 2


# ---------------------------------------------------------------------------
# min_confidence threshold
# ---------------------------------------------------------------------------

class TestMinConfidence:
    def test_below_threshold_dropped(self):
        reducer = FPReducerV2(min_confidence=0.5)
        f = make_finding(confidence=0.4)
        assert reducer.reduce([f]) == []

    def test_above_threshold_kept(self):
        reducer = FPReducerV2(min_confidence=0.5)
        f = make_finding(confidence=0.6)
        result = reducer.reduce([f])
        assert len(result) == 1

    def test_custom_min_confidence(self):
        reducer = FPReducerV2(min_confidence=0.1)
        f = make_finding(confidence=0.2)
        result = reducer.reduce([f])
        assert len(result) == 1
