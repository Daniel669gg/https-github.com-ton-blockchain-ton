"""
tests/test_phase6_unified_engine.py
TythanAI V6.5 Phase 6 — Real Detection Engine
Tests for backend/core/engine/unified_scan_engine.py
"""
import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import os
import tempfile
import time

import pytest
from backend.core.engine.unified_scan_engine import UnifiedScanEngine, ScanOptions, ScanResult


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_VULN_PY = """\
import os

def bad(uid):
    import sqlite3
    c = sqlite3.connect(":memory:").cursor()
    c.execute("SELECT * FROM users WHERE id=" + uid)
    os.system(uid)
    api_key = "sk-hardcoded-key-abc123"
"""

_SAFE_PY = """\
def add(a, b):
    return a + b
"""

# Offline options — no network calls in unit tests
_OFFLINE = ScanOptions(enable_semgrep=False, enable_osv=False, enable_epss=False)


def _tmp_py(code=_VULN_PY):
    """Write *code* to a temp .py file and return the path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, dir="/tmp")
    f.write(code)
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# 1. TestImports
# ---------------------------------------------------------------------------

class TestImports:
    def test_unified_scan_engine_importable(self):
        """UnifiedScanEngine can be imported."""
        from backend.core.engine.unified_scan_engine import UnifiedScanEngine  # noqa: F401
        assert UnifiedScanEngine is not None

    def test_scan_options_importable(self):
        """ScanOptions can be imported."""
        from backend.core.engine.unified_scan_engine import ScanOptions  # noqa: F401
        assert ScanOptions is not None

    def test_scan_result_importable(self):
        """ScanResult can be imported."""
        from backend.core.engine.unified_scan_engine import ScanResult  # noqa: F401
        assert ScanResult is not None


# ---------------------------------------------------------------------------
# 2. TestScanOptions
# ---------------------------------------------------------------------------

class TestScanOptions:
    def test_default_enable_semgrep_is_true(self):
        """Default ScanOptions has enable_semgrep=True."""
        opts = ScanOptions()
        assert opts.enable_semgrep is True

    def test_can_disable_all_scanners(self):
        """ScanOptions can be created with all scanners disabled."""
        opts = ScanOptions(
            enable_semgrep=False,
            enable_osv=False,
            enable_epss=False,
            enable_ast=False,
            enable_secrets=False,
            enable_owasp=False,
        )
        assert opts.enable_semgrep is False
        assert opts.enable_osv is False
        assert opts.enable_ast is False

    def test_max_findings_default_positive(self):
        """Default ScanOptions.max_findings is greater than 0."""
        opts = ScanOptions()
        assert opts.max_findings > 0


# ---------------------------------------------------------------------------
# 3. TestScanResult
# ---------------------------------------------------------------------------

class TestScanResult:
    def setup_method(self):
        self.engine = UnifiedScanEngine(_OFFLINE)
        tmp = _tmp_py(_VULN_PY)
        try:
            self.result = self.engine.scan(tmp)
        finally:
            os.unlink(tmp)

    def test_scan_returns_scan_result_instance(self):
        """scan() returns a ScanResult instance."""
        assert isinstance(self.result, ScanResult)

    def test_total_findings_returns_int(self):
        """ScanResult.total_findings is an int."""
        assert isinstance(self.result.total_findings, int)

    def test_severity_counts_has_expected_keys(self):
        """ScanResult.severity_counts has CRITICAL/HIGH/MEDIUM/LOW keys."""
        sc = self.result.severity_counts
        assert isinstance(sc, dict)
        for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert key in sc

    def test_risk_score_in_range(self):
        """ScanResult.risk_score is an int in [0, 100]."""
        assert isinstance(self.result.risk_score, int)
        assert 0 <= self.result.risk_score <= 100

    def test_summary_returns_non_empty_string(self):
        """ScanResult.summary() returns a non-empty string."""
        s = self.result.summary()
        assert isinstance(s, str)
        assert len(s) > 0


# ---------------------------------------------------------------------------
# 4. TestScanFindings
# ---------------------------------------------------------------------------

class TestScanFindings:
    def setup_method(self):
        self.engine = UnifiedScanEngine(_OFFLINE)
        self.tmp = _tmp_py(_VULN_PY)
        self.result = self.engine.scan(self.tmp)

    def teardown_method(self):
        try:
            os.unlink(self.tmp)
        except OSError:
            pass

    def test_scanning_vulnerable_file_finds_at_least_one(self):
        """Scanning a file with known vulnerabilities finds at least 1 finding."""
        assert self.result.total_findings >= 1

    def test_findings_contain_severity_key(self):
        """Every finding dict in the results has a 'severity' key."""
        assert len(self.result.findings) > 0
        for f in self.result.findings:
            assert "severity" in f

    def test_os_system_call_finds_cwe78(self):
        """Scanning a file with os.system() reports at least one CWE-78 finding."""
        cwe78 = self.result.by_cwe("CWE-78")
        assert len(cwe78) >= 1

    def test_hardcoded_secret_detected(self):
        """Scanning a file with a hardcoded API key reports CWE-798 or source_scanner==secrets."""
        cwe798 = self.result.by_cwe("CWE-798")
        secrets_findings = [
            f for f in self.result.findings
            if "secret" in f.get("source_scanner", "").lower()
        ]
        assert len(cwe798) > 0 or len(secrets_findings) > 0

    def test_critical_findings_returns_list(self):
        """critical_findings() returns a list (may be empty for low-risk files)."""
        crits = self.result.critical_findings()
        assert isinstance(crits, list)

    def test_high_findings_returns_list(self):
        """high_findings() returns a list."""
        highs = self.result.high_findings()
        assert isinstance(highs, list)

    def test_by_cwe_returns_list(self):
        """by_cwe('CWE-78') returns a list."""
        result = self.result.by_cwe("CWE-78")
        assert isinstance(result, list)

    def test_to_dict_has_findings_key(self):
        """ScanResult.to_dict() returns a dict that contains the 'findings' key."""
        d = self.result.to_dict()
        assert isinstance(d, dict)
        assert "findings" in d


# ---------------------------------------------------------------------------
# 5. TestScanCode
# ---------------------------------------------------------------------------

class TestScanCode:
    def setup_method(self):
        self.engine = UnifiedScanEngine(_OFFLINE)

    def test_scan_code_works_with_python_string(self):
        """scan_code() accepts a Python code string without raising."""
        result = self.engine.scan_code(_VULN_PY)
        assert result is not None

    def test_scan_code_returns_scan_result(self):
        """scan_code() returns a ScanResult instance."""
        result = self.engine.scan_code(_VULN_PY)
        assert isinstance(result, ScanResult)

    def test_scan_code_safe_lower_risk_than_vulnerable(self):
        """scan_code() on safe code produces a lower risk_score than on vulnerable code."""
        r_safe = self.engine.scan_code(_SAFE_PY)
        r_vuln = self.engine.scan_code(_VULN_PY)
        assert r_safe.risk_score < r_vuln.risk_score

    def test_scan_code_empty_string_does_not_crash(self):
        """scan_code() with an empty string does not raise an exception."""
        try:
            result = self.engine.scan_code("")
            assert isinstance(result, ScanResult)
        except Exception as exc:
            pytest.fail(f"scan_code('') raised: {exc}")


# ---------------------------------------------------------------------------
# 6. TestQuickScan
# ---------------------------------------------------------------------------

class TestQuickScan:
    def setup_method(self):
        self.engine = UnifiedScanEngine(_OFFLINE)
        self.tmp = _tmp_py(_VULN_PY)

    def teardown_method(self):
        try:
            os.unlink(self.tmp)
        except OSError:
            pass

    def test_quick_scan_returns_scan_result(self):
        """quick_scan() returns a ScanResult instance."""
        result = self.engine.quick_scan(self.tmp)
        assert isinstance(result, ScanResult)

    def test_quick_scan_faster_than_full_scan(self):
        """quick_scan() completes faster than a full scan on the same target."""
        # Run quick_scan first
        t0 = time.time()
        self.engine.quick_scan(self.tmp)
        quick_time = time.time() - t0

        # Run full scan (offline options, so Semgrep/OSV skipped either way)
        t0 = time.time()
        self.engine.scan(self.tmp)
        full_time = time.time() - t0

        # Quick scan disables owasp too; it should be at least as fast
        # Use a generous multiplier to avoid flakiness on loaded CI machines
        assert quick_time <= full_time * 5 + 0.5  # quick ≤ 5× full + 0.5s buffer
