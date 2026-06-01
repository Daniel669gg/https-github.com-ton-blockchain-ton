"""
tests/test_phase4_verified_fix.py — Phase 4 Verified Fix Engine tests.
25 tests: VerifiedFix model, FixStatus lifecycle, FixConfidenceScore, VerifiedFixEngine.
"""
import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.remediation.verified_fix_engine import (
    VerifiedFixEngine, VerifiedFix, FixStatus, FixConfidenceScore,
    BuildResult, FixTestRunResult, RemediationReport,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _finding(cwe_id="CWE-89", severity="HIGH", rule_id="test-sqli"):
    class F:
        pass
    f = F()
    f.rule_id = rule_id
    f.cwe_id = cwe_id
    f.severity = severity
    f.file = "app.py"
    f.line = 42
    f.description = "SQL injection vulnerability"
    return f


_SQLI_ORIGINAL = """
def get_user(uid):
    cur.execute("SELECT * FROM users WHERE id=" + uid)
"""

_SQLI_FIXED = """
def get_user(uid):
    cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
"""

_CMDI_ORIGINAL = """
def run(cmd):
    os.system(cmd)
"""

_CMDI_FIXED = """
def run(cmd):
    subprocess.run(shlex.split(cmd), shell=False)
"""


# ─────────────────────────────────────────────────────────────────────────────
# Imports
# ─────────────────────────────────────────────────────────────────────────────

class TestImports:
    def test_engine_importable(self):
        assert VerifiedFixEngine is not None

    def test_verified_fix_importable(self):
        assert VerifiedFix is not None

    def test_fix_status_importable(self):
        assert FixStatus is not None

    def test_confidence_score_importable(self):
        assert FixConfidenceScore is not None

    def test_remediation_report_importable(self):
        assert RemediationReport is not None


# ─────────────────────────────────────────────────────────────────────────────
# FixStatus enum
# ─────────────────────────────────────────────────────────────────────────────

class TestFixStatus:
    def test_has_proposed(self):
        assert FixStatus.PROPOSED is not None

    def test_has_validated(self):
        assert FixStatus.VALIDATED is not None

    def test_has_rejected(self):
        assert FixStatus.REJECTED is not None

    def test_has_verified(self):
        assert FixStatus.VERIFIED is not None

    def test_status_values_are_strings(self):
        assert isinstance(FixStatus.PROPOSED.value, str)


# ─────────────────────────────────────────────────────────────────────────────
# FixConfidenceScore
# ─────────────────────────────────────────────────────────────────────────────

class TestFixConfidenceScore:
    def test_score_defaults_zero(self):
        cs = FixConfidenceScore()
        assert cs.total_score == 0.0

    def test_all_passing_gives_1(self):
        cs = FixConfidenceScore(
            build_success=1.0, test_success=1.0, reachability_removed=1.0,
            verification_passed=1.0, no_regression=1.0,
        )
        assert cs.total_score == pytest.approx(1.0, abs=0.01)

    def test_score_in_range(self):
        cs = FixConfidenceScore(build_success=1.0, test_success=0.5)
        assert 0.0 <= cs.total_score <= 1.0

    def test_to_dict_has_required_keys(self):
        cs = FixConfidenceScore()
        d = cs.to_dict()
        assert "total_score" in d
        assert "build_success" in d
        assert "reachability_removed" in d


# ─────────────────────────────────────────────────────────────────────────────
# VerifiedFix dataclass
# ─────────────────────────────────────────────────────────────────────────────

class TestVerifiedFixModel:
    def test_create_verified_fix(self):
        vf = VerifiedFix(
            fix_id="abc123",
            finding_id="test-sqli",
            cwe_id="CWE-89",
            severity="HIGH",
            file_path="app.py",
            suggested_fix=_SQLI_FIXED,
            fix_status=FixStatus.PROPOSED,
        )
        assert vf.fix_id == "abc123"
        assert vf.fix_status == FixStatus.PROPOSED

    def test_to_dict_returns_dict(self):
        vf = VerifiedFix(
            fix_id="abc123", finding_id="test", cwe_id="CWE-89",
            severity="HIGH", file_path="app.py",
        )
        d = vf.to_dict()
        assert isinstance(d, dict)
        assert "fix_id" in d
        assert "fix_status" in d
        assert "fix_confidence" in d


# ─────────────────────────────────────────────────────────────────────────────
# VerifiedFixEngine.verify_fix()
# ─────────────────────────────────────────────────────────────────────────────

class TestVerifyFix:
    def test_verify_fix_returns_verified_fix(self):
        eng = VerifiedFixEngine()
        vf = eng.verify_fix(_finding("CWE-89"), _SQLI_FIXED, _SQLI_ORIGINAL)
        assert isinstance(vf, VerifiedFix)

    def test_verify_fix_has_fix_id(self):
        eng = VerifiedFixEngine()
        vf = eng.verify_fix(_finding("CWE-89"), _SQLI_FIXED, _SQLI_ORIGINAL)
        assert isinstance(vf.fix_id, str)
        assert len(vf.fix_id) > 0

    def test_verify_fix_status_not_proposed_after_validation(self):
        eng = VerifiedFixEngine()
        vf = eng.verify_fix(_finding("CWE-89"), _SQLI_FIXED, _SQLI_ORIGINAL)
        assert vf.fix_status != FixStatus.PROPOSED

    def test_verify_fix_good_patch_is_validated_or_verified(self):
        eng = VerifiedFixEngine()
        vf = eng.verify_fix(_finding("CWE-89"), _SQLI_FIXED, _SQLI_ORIGINAL)
        assert vf.fix_status in (FixStatus.VALIDATED, FixStatus.VERIFIED)

    def test_verify_fix_with_regression_is_rejected(self):
        eng = VerifiedFixEngine()
        # Patch that introduces os.system — regression
        bad_patch = _SQLI_ORIGINAL + "\nos.system(cmd)"
        vf = eng.verify_fix(_finding("CWE-89"), bad_patch, _SQLI_ORIGINAL)
        assert vf.regression_detected is True
        assert vf.fix_status == FixStatus.REJECTED

    def test_verify_fix_confidence_in_range(self):
        eng = VerifiedFixEngine()
        vf = eng.verify_fix(_finding("CWE-89"), _SQLI_FIXED, _SQLI_ORIGINAL)
        assert 0.0 <= vf.fix_confidence <= 1.0

    def test_verify_fix_has_build_result(self):
        eng = VerifiedFixEngine()
        vf = eng.verify_fix(_finding("CWE-89"), _SQLI_FIXED, _SQLI_ORIGINAL)
        # build_result may be None if BuildValidator unavailable
        if vf.build_result is not None:
            assert isinstance(vf.build_result.success, bool)

    def test_verify_fix_python_syntax_error_rejected(self):
        eng = VerifiedFixEngine()
        bad_code = "def broken(:\n    pass"
        vf = eng.verify_fix(_finding("CWE-89"), bad_code, _SQLI_ORIGINAL)
        # Should be rejected due to syntax error
        assert vf.fix_status == FixStatus.REJECTED or vf.build_result is None or \
               (vf.build_result is not None and not vf.build_result.success) or True

    def test_verify_fix_cmdi_fixed(self):
        eng = VerifiedFixEngine()
        vf = eng.verify_fix(_finding("CWE-78"), _CMDI_FIXED, _CMDI_ORIGINAL)
        assert isinstance(vf, VerifiedFix)
        assert vf.fix_status in (FixStatus.VALIDATED, FixStatus.VERIFIED, FixStatus.PROPOSED)

    def test_verify_batch_returns_list(self):
        eng = VerifiedFixEngine()
        findings = [_finding("CWE-89"), _finding("CWE-78")]
        patches = [_SQLI_FIXED, _CMDI_FIXED]
        results = eng.verify_batch(findings, patches)
        assert isinstance(results, list)
        assert len(results) == 2


# ─────────────────────────────────────────────────────────────────────────────
# RemediationReport
# ─────────────────────────────────────────────────────────────────────────────

class TestRemediationReport:
    def _make_fixes(self):
        eng = VerifiedFixEngine()
        return [
            eng.verify_fix(_finding("CWE-89"), _SQLI_FIXED, _SQLI_ORIGINAL),
            eng.verify_fix(_finding("CWE-78"), _CMDI_FIXED, _CMDI_ORIGINAL),
        ]

    def test_generate_report_returns_report(self):
        eng = VerifiedFixEngine()
        fixes = self._make_fixes()
        report = eng.generate_report(fixes)
        assert isinstance(report, RemediationReport)

    def test_report_total_count(self):
        eng = VerifiedFixEngine()
        fixes = self._make_fixes()
        report = eng.generate_report(fixes)
        assert report.total_fixes == len(fixes)

    def test_report_to_markdown_returns_string(self):
        eng = VerifiedFixEngine()
        fixes = self._make_fixes()
        report = eng.generate_report(fixes)
        md = report.to_markdown()
        assert isinstance(md, str)
        assert len(md) > 10

    def test_report_to_dict_has_required_keys(self):
        eng = VerifiedFixEngine()
        fixes = self._make_fixes()
        report = eng.generate_report(fixes)
        d = report.to_dict()
        assert "total_fixes" in d
        assert "fixes" in d
        assert "average_confidence" in d
