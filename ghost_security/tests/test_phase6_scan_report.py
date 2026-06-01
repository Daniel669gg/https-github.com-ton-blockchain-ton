"""
tests/test_phase6_scan_report.py
TythanAI V6.5 Phase 6 — Real Detection Engine
Tests for backend/core/engine/scan_report.py
"""
import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import json
import os
import tempfile

import pytest
from backend.core.engine.scan_report import ReportGenerator, ScanReport
from backend.core.engine.finding_normalizer import FindingNormalizer


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

def _make_findings(n=3):
    """Return *n* NormalizedFinding objects for CWE-89/HIGH."""
    norm = FindingNormalizer()
    raw = [
        {"severity": "HIGH", "cwe": "CWE-89", "file": "app.py", "line": i + 1, "message": "SQLi"}
        for i in range(n)
    ]
    return norm.normalize_batch(raw, "test")


# ---------------------------------------------------------------------------
# 1. TestImports
# ---------------------------------------------------------------------------

class TestImports:
    def test_report_generator_importable(self):
        """ReportGenerator can be imported from the module."""
        from backend.core.engine.scan_report import ReportGenerator  # noqa: F401
        assert ReportGenerator is not None

    def test_scan_report_importable(self):
        """ScanReport can be imported from the module."""
        from backend.core.engine.scan_report import ScanReport  # noqa: F401
        assert ScanReport is not None

    def test_report_generator_instantiable(self):
        """ReportGenerator can be instantiated without arguments."""
        gen = ReportGenerator()
        assert gen is not None


# ---------------------------------------------------------------------------
# 2. TestScanReport
# ---------------------------------------------------------------------------

class TestScanReport:
    def setup_method(self):
        gen = ReportGenerator()
        self.report = gen.generate(_make_findings(3), "app.py", 1.0, ["test"])

    def test_has_total_findings_field(self):
        """ScanReport has a total_findings field with correct value."""
        assert hasattr(self.report, "total_findings")
        assert self.report.total_findings == 3

    def test_has_severity_counts_dict(self):
        """ScanReport has a severity_counts dict."""
        assert hasattr(self.report, "severity_counts")
        assert isinstance(self.report.severity_counts, dict)

    def test_risk_score_in_range(self):
        """ScanReport.risk_score is an int in [0, 100]."""
        assert hasattr(self.report, "risk_score")
        assert isinstance(self.report.risk_score, int)
        assert 0 <= self.report.risk_score <= 100

    def test_risk_level_valid_string(self):
        """ScanReport.risk_level is one of the four canonical levels."""
        valid_levels = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        assert hasattr(self.report, "risk_level")
        assert self.report.risk_level in valid_levels


# ---------------------------------------------------------------------------
# 3. TestReportGenerator
# ---------------------------------------------------------------------------

class TestReportGenerator:
    def setup_method(self):
        self.gen = ReportGenerator()
        self.findings = _make_findings(3)
        self.report = self.gen.generate(self.findings, "app.py", 1.0, ["test"])

    # --- generate() --------------------------------------------------------

    def test_generate_returns_scan_report(self):
        """generate() returns a ScanReport instance."""
        assert isinstance(self.report, ScanReport)

    def test_generate_total_findings_matches_input(self):
        """total_findings == number of findings passed to generate()."""
        assert self.report.total_findings == len(self.findings)

    # --- SARIF -------------------------------------------------------------

    def test_to_sarif_version_2_1_0(self):
        """to_sarif() produces a dict with 'version' == '2.1.0'."""
        sarif = self.gen.to_sarif(self.report)
        assert isinstance(sarif, dict)
        assert sarif.get("version") == "2.1.0"

    def test_to_sarif_has_runs_list(self):
        """to_sarif() produces a dict with a 'runs' key containing a list."""
        sarif = self.gen.to_sarif(self.report)
        assert "runs" in sarif
        assert isinstance(sarif["runs"], list)
        assert len(sarif["runs"]) >= 1

    def test_to_sarif_has_results_when_findings_present(self):
        """to_sarif() includes at least one result entry when findings > 0."""
        sarif = self.gen.to_sarif(self.report)
        results = sarif["runs"][0]["results"]
        assert len(results) > 0

    # --- Markdown ----------------------------------------------------------

    def test_to_markdown_contains_cwe_id(self):
        """to_markdown() output contains the 'CWE-89' string."""
        md = self.gen.to_markdown(self.report)
        assert isinstance(md, str)
        assert "CWE-89" in md

    def test_to_markdown_contains_severity_header(self):
        """to_markdown() output contains a 'Severity' column header (case-insensitive)."""
        md = self.gen.to_markdown(self.report)
        assert "severity" in md.lower()

    # --- JSON --------------------------------------------------------------

    def test_to_json_returns_valid_json_string(self):
        """to_json() returns a string that is valid JSON."""
        j = self.gen.to_json(self.report)
        assert isinstance(j, str)
        parsed = json.loads(j)
        assert isinstance(parsed, dict)

    def test_to_json_has_total_findings_key(self):
        """Parsed JSON from to_json() has a 'total_findings' key in 'summary'."""
        parsed = json.loads(self.gen.to_json(self.report))
        # total_findings is nested under 'summary'
        assert "total_findings" in parsed.get("summary", parsed)

    # --- HTML --------------------------------------------------------------

    def test_to_html_starts_with_html_tag(self):
        """to_html() returns a string that starts with '<' (HTML content)."""
        html_str = self.gen.to_html(self.report)
        assert isinstance(html_str, str)
        assert html_str.strip().startswith("<")

    def test_to_html_contains_cwe_id(self):
        """to_html() output includes 'CWE-89'."""
        html_str = self.gen.to_html(self.report)
        assert "CWE-89" in html_str

    # --- CSV ---------------------------------------------------------------

    def test_to_csv_contains_severity_header(self):
        """to_csv() output contains a 'severity' column header (case-insensitive)."""
        csv_str = self.gen.to_csv(self.report)
        assert isinstance(csv_str, str)
        assert "severity" in csv_str.lower()

    # --- save() ------------------------------------------------------------

    def test_save_creates_file_on_disk(self):
        """save() writes a file to disk in the requested format."""
        tmp_path = tempfile.mktemp(suffix=".json")
        try:
            self.gen.save(self.report, tmp_path, "json")
            assert os.path.exists(tmp_path)
            # File should not be empty and should be valid JSON
            with open(tmp_path, "r", encoding="utf-8") as fh:
                content = fh.read()
            parsed = json.loads(content)
            assert isinstance(parsed, dict)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
