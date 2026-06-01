"""
tests/test_phase6_integration.py
TythanAI V6.5 Phase 6 — Real Detection Engine
Full pipeline integration tests.
"""
import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import json
import os
import tempfile
import shutil

import pytest
from backend.core.engine.unified_scan_engine import UnifiedScanEngine, ScanOptions
from backend.core.engine.finding_normalizer import FindingNormalizer
from backend.core.engine.fix_bridge import FixBridge
from backend.core.engine.scan_report import ReportGenerator
from scanners.security_pipeline import SecurityPipeline


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_OFFLINE = ScanOptions(enable_semgrep=False, enable_osv=False, enable_epss=False)

_VULN_PY = """\
import os

def bad(uid):
    import sqlite3
    c = sqlite3.connect(":memory:").cursor()
    c.execute("SELECT * FROM users WHERE id=" + uid)
    os.system(uid)
    api_key = "sk-hardcoded-key-abc123"
"""


def _make_isolated_tmpdir(code: str = _VULN_PY) -> str:
    """
    Create an isolated temp directory with a single Python file.

    Returns the path to the directory.  Caller is responsible for cleanup.
    """
    tmpdir = tempfile.mkdtemp(prefix="tythanai_test_")
    filepath = os.path.join(tmpdir, "vuln.py")
    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write(code)
    return tmpdir


# ---------------------------------------------------------------------------
# 1. TestPipelineIntegration
# ---------------------------------------------------------------------------

class TestPipelineIntegration:
    """Tests that SecurityPipeline loads and wires up correctly."""

    def setup_method(self):
        self.pipeline = SecurityPipeline()

    def test_security_pipeline_instantiates(self):
        """SecurityPipeline instantiates without error."""
        assert self.pipeline is not None

    def test_security_pipeline_has_semgrep_attribute(self):
        """SecurityPipeline has a _semgrep attribute (may be None if unavailable)."""
        assert hasattr(self.pipeline, "_semgrep")
        # May be None if semgrep binary not found, but the attribute must exist

    def test_security_pipeline_has_osv_attribute(self):
        """SecurityPipeline has an _osv attribute."""
        assert hasattr(self.pipeline, "_osv")

    def test_security_pipeline_has_epss_attribute(self):
        """SecurityPipeline has an _epss attribute."""
        assert hasattr(self.pipeline, "_epss")

    def test_security_pipeline_scan_returns_dict_with_findings(self):
        """SecurityPipeline.scan() on an isolated directory returns a dict with 'findings' key."""
        tmpdir = _make_isolated_tmpdir()
        try:
            result = self.pipeline.scan(tmpdir)
            assert isinstance(result, dict)
            assert "findings" in result
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# 2. TestScanToReport
# ---------------------------------------------------------------------------

class TestScanToReport:
    """End-to-end: UnifiedScanEngine → ReportGenerator → output formats."""

    def setup_method(self):
        self.engine = UnifiedScanEngine(_OFFLINE)
        self.gen = ReportGenerator()
        self.tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, dir="/tmp"
        )
        self.tmp.write(_VULN_PY)
        self.tmp.close()
        self.scan_result = self.engine.scan(self.tmp.name)
        # Re-normalise findings for the report generator
        norm = FindingNormalizer()
        self.normalized = norm.normalize_batch(
            [
                {
                    "severity": f.get("severity", "HIGH"),
                    "cwe": f.get("cwe_id", ""),
                    "file": f.get("file_path", ""),
                    "line": f.get("line", 0),
                    "message": f.get("description", ""),
                }
                for f in self.scan_result.findings
            ],
            "unified",
        )
        self.report = self.gen.generate(
            self.normalized,
            self.tmp.name,
            self.scan_result.scan_duration_s,
            self.scan_result.scanners_used,
        )

    def teardown_method(self):
        try:
            os.unlink(self.tmp.name)
        except OSError:
            pass

    def test_scan_report_sarif_valid(self):
        """Full pipeline: scan → report → SARIF produces a dict with 'version'."""
        sarif = self.gen.to_sarif(self.report)
        assert isinstance(sarif, dict)
        assert "version" in sarif

    def test_scan_report_markdown_non_empty(self):
        """Full pipeline: scan → report → Markdown is a non-empty string."""
        md = self.gen.to_markdown(self.report)
        assert isinstance(md, str)
        assert len(md) > 0

    def test_scan_report_json_valid(self):
        """Full pipeline: scan → report → JSON is valid JSON."""
        j = self.gen.to_json(self.report)
        parsed = json.loads(j)
        assert isinstance(parsed, dict)

    def test_sarif_version_2_1_0(self):
        """SARIF output from scan result has version == '2.1.0'."""
        sarif = self.gen.to_sarif(self.report)
        assert sarif["version"] == "2.1.0"

    def test_report_total_findings_matches_scan(self):
        """Report total_findings equals the number of findings passed to generate()."""
        assert self.report.total_findings == len(self.normalized)


# ---------------------------------------------------------------------------
# 3. TestScanToFix
# ---------------------------------------------------------------------------

class TestScanToFix:
    """End-to-end: UnifiedScanEngine findings → FixBridge."""

    def setup_method(self):
        self.engine = UnifiedScanEngine(_OFFLINE)
        self.bridge = FixBridge()
        self.norm = FindingNormalizer()
        self.tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, dir="/tmp"
        )
        self.tmp.write(_VULN_PY)
        self.tmp.close()
        self.scan_result = self.engine.scan(self.tmp.name)

    def teardown_method(self):
        try:
            os.unlink(self.tmp.name)
        except OSError:
            pass

    def _to_normalized(self):
        """Convert scan_result.findings to NormalizedFinding objects."""
        return self.norm.normalize_batch(
            [
                {
                    "severity": f.get("severity", "HIGH"),
                    "cwe": f.get("cwe_id", ""),
                    "file": f.get("file_path", ""),
                    "line": f.get("line", 0),
                    "message": f.get("description", ""),
                }
                for f in self.scan_result.findings
            ],
            "unified",
        )

    def test_fix_bridge_suggest_fix_on_engine_finding(self):
        """FixBridge.suggest_fix does not crash when given a finding from UnifiedScanEngine."""
        findings = self._to_normalized()
        assert len(findings) > 0
        try:
            result = self.bridge.suggest_fix(findings[0])
            # None is acceptable; it must simply not raise
            assert result is None or hasattr(result, "fix_status")
        except Exception as exc:
            pytest.fail(f"suggest_fix raised on engine finding: {exc}")

    def test_fix_bridge_suggest_fixes_batch_returns_list(self):
        """FixBridge.suggest_fixes_batch returns a list for engine findings."""
        findings = self._to_normalized()
        results = self.bridge.suggest_fixes_batch(findings)
        assert isinstance(results, list)

    def test_fix_bridge_batch_result_is_subset_of_input(self):
        """suggest_fixes_batch result length <= input length."""
        findings = self._to_normalized()
        results = self.bridge.suggest_fixes_batch(findings)
        assert len(results) <= len(findings)

    def test_full_chain_cwe78_template(self):
        """Full chain: scan → normalize → fix_bridge.get_template returns code for CWE-78."""
        # CWE-78 is os.system injection — present in the vulnerable file
        cwe78_findings = [
            f for f in self._to_normalized()
            if f.cwe_id == "CWE-78"
        ]
        assert len(cwe78_findings) > 0, "Expected CWE-78 finding from vulnerable file"
        template = self.bridge.get_template_fix("CWE-78")
        assert isinstance(template, str)
        assert len(template) > 0
        assert "subprocess" in template

    def test_full_chain_scan_report_save_to_temp_file(self):
        """Full chain: scan → report → save to a temp file succeeds."""
        findings = self._to_normalized()
        gen = ReportGenerator()
        report = gen.generate(
            findings,
            self.tmp.name,
            self.scan_result.scan_duration_s,
            self.scan_result.scanners_used,
        )
        tmp_out = tempfile.mktemp(suffix=".json")
        try:
            gen.save(report, tmp_out, "json")
            assert os.path.exists(tmp_out)
            with open(tmp_out, "r", encoding="utf-8") as fh:
                parsed = json.loads(fh.read())
            assert "findings" in parsed
        finally:
            if os.path.exists(tmp_out):
                os.unlink(tmp_out)
