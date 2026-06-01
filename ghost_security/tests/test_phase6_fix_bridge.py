"""
tests/test_phase6_fix_bridge.py
TythanAI V6.5 Phase 6 — Real Detection Engine
Tests for backend/core/engine/fix_bridge.py
"""
import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.engine.fix_bridge import FixBridge
from backend.core.engine.finding_normalizer import FindingNormalizer


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

def _finding(cwe="CWE-89"):
    """Create a NormalizedFinding using FindingNormalizer for the given CWE."""
    n = FindingNormalizer()
    return n.normalize(
        {"severity": "HIGH", "cwe": cwe, "file": "app.py", "line": 42, "message": "vuln"},
        "test",
    )


# ---------------------------------------------------------------------------
# 1. TestImports
# ---------------------------------------------------------------------------

class TestImports:
    def test_fix_bridge_importable(self):
        """FixBridge can be imported from the module."""
        from backend.core.engine.fix_bridge import FixBridge  # noqa: F401
        assert FixBridge is not None

    def test_fix_bridge_instantiable(self):
        """FixBridge instantiates without arguments."""
        fb = FixBridge()
        assert fb is not None


# ---------------------------------------------------------------------------
# 2. TestTemplateFixes
# ---------------------------------------------------------------------------

class TestTemplateFixes:
    def setup_method(self):
        self.fb = FixBridge()

    def test_get_template_fix_cwe89_non_empty(self):
        """get_template_fix('CWE-89') returns a non-empty string."""
        result = self.fb.get_template_fix("CWE-89")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_get_template_fix_cwe78_contains_subprocess(self):
        """get_template_fix('CWE-78') returns code referencing subprocess."""
        result = self.fb.get_template_fix("CWE-78")
        assert isinstance(result, str)
        assert "subprocess" in result

    def test_get_template_fix_cwe798_contains_environ(self):
        """get_template_fix('CWE-798') returns code referencing environ."""
        result = self.fb.get_template_fix("CWE-798")
        assert isinstance(result, str)
        assert "environ" in result

    def test_get_template_fix_cwe502_contains_safe_load(self):
        """get_template_fix('CWE-502') returns code referencing safe_load."""
        result = self.fb.get_template_fix("CWE-502")
        assert isinstance(result, str)
        assert "safe_load" in result

    def test_get_template_fix_unknown_cwe_returns_string(self):
        """get_template_fix with an unknown CWE returns a string (may be empty)."""
        result = self.fb.get_template_fix("CWE-UNKNOWN")
        # Fallback: either an empty string or a generic hint — must be a str
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# 3. TestSuggestFix
# ---------------------------------------------------------------------------

class TestSuggestFix:
    def setup_method(self):
        self.fb = FixBridge()

    def test_suggest_fix_cwe89_returns_result(self):
        """suggest_fix with a CWE-89 NormalizedFinding returns a non-None result."""
        f = _finding("CWE-89")
        result = self.fb.suggest_fix(f)
        # CWE-89 has a template, so result should not be None
        assert result is not None

    def test_suggest_fix_returns_verified_fix_or_none(self):
        """suggest_fix returns a VerifiedFix-like object or None — never raises."""
        f = _finding("CWE-89")
        result = self.fb.suggest_fix(f)
        # Acceptable: a VerifiedFix object OR None
        assert result is None or hasattr(result, "fix_status") or hasattr(result, "suggested_fix")

    def test_verified_fix_has_fix_status_field(self):
        """If suggest_fix returns a VerifiedFix, it has a fix_status attribute."""
        f = _finding("CWE-89")
        result = self.fb.suggest_fix(f)
        if result is not None:
            assert hasattr(result, "fix_status")

    def test_suggest_fixes_batch_returns_list(self):
        """suggest_fixes_batch with 3 findings returns a list."""
        findings = [_finding("CWE-89"), _finding("CWE-78"), _finding("CWE-798")]
        results = self.fb.suggest_fixes_batch(findings)
        assert isinstance(results, list)

    def test_suggest_fixes_batch_len_lte_input(self):
        """suggest_fixes_batch result length is <= input length (only non-None included)."""
        findings = [_finding("CWE-89"), _finding("CWE-78"), _finding("CWE-798")]
        results = self.fb.suggest_fixes_batch(findings)
        assert len(results) <= len(findings)

    def test_suggest_fixes_batch_caps_at_20(self):
        """suggest_fixes_batch processes at most 20 findings even with a larger list."""
        findings = [_finding("CWE-89") for _ in range(25)]
        results = self.fb.suggest_fixes_batch(findings)
        # The internal cap is [:20], so results can be at most 20
        assert len(results) <= 20

    def test_suggest_fix_empty_cwe_does_not_crash(self):
        """suggest_fix with a finding that has an empty cwe_id must not raise."""
        n = FindingNormalizer()
        f = n.normalize(
            {"severity": "HIGH", "file": "app.py", "line": 1, "message": "no cwe"},
            "test",
        )
        # Should return None gracefully (no template, no source_code)
        try:
            result = self.fb.suggest_fix(f)
            assert result is None or hasattr(result, "fix_status")
        except Exception as exc:
            pytest.fail(f"suggest_fix with empty cwe_id raised: {exc}")

    def test_suggest_fix_no_source_code_still_works(self):
        """suggest_fix without source_code argument uses template fallback."""
        f = _finding("CWE-89")
        # No source_code kwarg — should still succeed via template
        result = self.fb.suggest_fix(f)
        assert result is not None
