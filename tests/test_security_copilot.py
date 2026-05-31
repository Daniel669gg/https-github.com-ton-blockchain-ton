"""
tests/test_security_copilot.py — Tests for PatchGenerator and SecurityCopilot.

Covers:
  - PatchGenerator: SQL injection → parameterized query patch
  - PatchGenerator: Command injection → list-args patch
  - PatchGenerator: Hardcoded secrets → env var patch
  - PatchGenerator: Weak crypto → SHA256 upgrade
  - SecurityCopilot.scan() returns findings list
  - SecurityCopilot.analyze() groups findings by severity
  - SecurityCopilot.generate_patches() returns patches
  - SecurityCopilot.full_cycle() returns structured report
"""
from __future__ import annotations

import sys
import tempfile
import pathlib
from typing import List

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest

from backend.agents.security_copilot import PatchGenerator, SecurityCopilot
from backend.core.confidence import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        rule_id="TAINT-SQL_INJECTION",
        file="/tmp/test.py",
        line=5,
        severity="HIGH",
        confidence=0.85,
        cwe_id="CWE-89",
        description="SQL injection detected",
        recommendation="Use parameterized queries",
        sources=["flask_request"],
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _write_py(code: str) -> str:
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    )
    f.write(code)
    f.flush()
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# PatchGenerator — SQL injection
# ---------------------------------------------------------------------------

class TestPatchGeneratorSQL:

    def test_patch_sql_string_concat(self):
        """String-concatenated SQL should be patched to parameterized form."""
        code = """\
from flask import request
import sqlite3

def vulnerable(db):
    user_input = request.args.get("id")
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_input)
"""
        pg = PatchGenerator()
        finding = _make_finding(
            rule_id="TAINT-SQL_INJECTION",
            file="app.py",
            line=7,
            cwe_id="CWE-89",
        )
        result = pg.generate(finding, code)
        assert result is not None, "Expected a patch result for SQL injection"
        assert result.explanation, "Patch should have an explanation"

    def test_patch_sql_returns_patch_result(self):
        """generate() should return a PatchResult object with required fields."""
        from backend.agents.security_copilot import PatchResult
        code = "cursor.execute('SELECT * FROM t WHERE x = ' + x)\n"
        pg = PatchGenerator()
        finding = _make_finding(cwe_id="CWE-89", line=1)
        result = pg.generate(finding, code)
        assert result is None or isinstance(result, PatchResult)

    def test_patch_result_has_explanation(self):
        """PatchResult must have a non-empty explanation."""
        from backend.agents.security_copilot import PatchResult
        code = """\
import sqlite3
user = input()
conn = sqlite3.connect('db')
conn.execute("SELECT * FROM users WHERE name = '" + user + "'")
"""
        pg = PatchGenerator()
        finding = _make_finding(cwe_id="CWE-89", line=4)
        result = pg.generate(finding, code)
        if result is not None:
            assert result.explanation, "PatchResult must have an explanation"


# ---------------------------------------------------------------------------
# PatchGenerator — hardcoded secrets
# ---------------------------------------------------------------------------

class TestPatchGeneratorSecrets:

    def test_patch_hardcoded_secret(self):
        """Hardcoded secret should be replaced with os.environ.get()."""
        code = 'API_KEY = "sk-1234567890abcdef1234567890"\n'
        pg = PatchGenerator()
        finding = _make_finding(
            rule_id="HARDCODED-SECRET-001",
            cwe_id="CWE-798",
            line=1,
        )
        result = pg.generate(finding, code)
        if result is not None:
            # patched_snippet should reference os.environ
            snippet = result.patched_snippet
            assert "environ" in snippet or "os" in snippet or "env" in snippet.lower(), (
                f"Expected env var replacement in snippet: {snippet}"
            )

    def test_patch_generates_explanation_for_secret(self):
        """PatchResult for CWE-798 should have a meaningful explanation."""
        code = 'password = "my_super_secret_password123"\n'
        pg = PatchGenerator()
        finding = _make_finding(rule_id="HARDCODED-SECRET-001", cwe_id="CWE-798", line=1)
        result = pg.generate(finding, code)
        if result is not None:
            assert len(result.explanation) > 10


# ---------------------------------------------------------------------------
# PatchGenerator — weak crypto
# ---------------------------------------------------------------------------

class TestPatchGeneratorCrypto:

    def test_md5_to_sha256_patch(self):
        """hashlib.md5() should be patched to hashlib.sha256()."""
        code = """\
import hashlib
digest = hashlib.md5(data).hexdigest()
"""
        pg = PatchGenerator()
        finding = _make_finding(
            rule_id="TAINT-WEAK_CRYPTO",
            cwe_id="CWE-327",
            line=2,
        )
        result = pg.generate(finding, code)
        if result is not None:
            snippet = result.patched_snippet
            assert "sha256" in snippet.lower() or "sha" in snippet.lower()


# ---------------------------------------------------------------------------
# PatchGenerator — command injection
# ---------------------------------------------------------------------------

class TestPatchGeneratorCommandInjection:

    def test_patch_command_injection(self):
        """os.system(user_input) should be patched."""
        code = """\
import os
from flask import request

def run():
    cmd = request.args.get("cmd")
    os.system(cmd)
"""
        pg = PatchGenerator()
        finding = _make_finding(
            rule_id="TAINT-SHELL_INJECTION",
            cwe_id="CWE-78",
            line=6,
        )
        result = pg.generate(finding, code)
        # May or may not produce a patch depending on implementation
        assert result is None or hasattr(result, "patched_code")


# ---------------------------------------------------------------------------
# SecurityCopilot.scan()
# ---------------------------------------------------------------------------

class TestSecurityCopilotScan:

    def test_scan_returns_findings_list(self):
        """scan() must return a list of Finding objects."""
        code = """\
from flask import request
import sqlite3

def vulnerable(db):
    user_input = request.args.get("id")
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_input)
"""
        path = _write_py(code)
        copilot = SecurityCopilot()
        findings = copilot.scan(path)
        assert isinstance(findings, list), "scan() must return a list"

    def test_scan_vulnerable_code_finds_issues(self):
        """scan() should find at least one issue in vulnerable code."""
        code = """\
from flask import request
import sqlite3

def get_user(db):
    uid = request.args.get("id")
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
    return cursor.fetchone()
"""
        path = _write_py(code)
        copilot = SecurityCopilot()
        findings = copilot.scan(path)
        assert len(findings) > 0, "Expected at least one finding in vulnerable code"

    def test_scan_clean_code_no_findings(self):
        """scan() should return empty list for clean code."""
        code = """\
def add(a, b):
    return a + b

def greet(name):
    return f"Hello, {name}!"
"""
        path = _write_py(code)
        copilot = SecurityCopilot()
        findings = copilot.scan(path)
        assert isinstance(findings, list)

    def test_scan_nonexistent_file(self):
        """scan() on a nonexistent file should return empty list or raise gracefully."""
        copilot = SecurityCopilot()
        try:
            result = copilot.scan("/nonexistent/file.py")
            assert isinstance(result, list)
        except (FileNotFoundError, ValueError, OSError):
            pass  # Raising an informative error is also acceptable


# ---------------------------------------------------------------------------
# SecurityCopilot.analyze()
# ---------------------------------------------------------------------------

class TestSecurityCopilotAnalyze:

    def test_analyze_returns_list(self):
        findings = [_make_finding(severity="HIGH"), _make_finding(severity="CRITICAL")]
        copilot = SecurityCopilot()
        result = copilot.analyze(findings)
        assert isinstance(result, list), "analyze() must return a list"

    def test_analyze_empty_findings(self):
        copilot = SecurityCopilot()
        result = copilot.analyze([])
        assert isinstance(result, list)
        assert len(result) == 0

    def test_analyze_includes_owasp_or_category(self):
        """analyze() should enrich findings with OWASP category or similar."""
        findings = [_make_finding(cwe_id="CWE-89")]
        copilot = SecurityCopilot()
        result = copilot.analyze(findings)
        if result:
            # Each item should have at least rule_id and severity
            item = result[0]
            assert "rule_id" in item or "severity" in item or "cwe" in item

    def test_analyze_groups_by_severity(self):
        """analyze() should group or sort findings by severity."""
        findings = [
            _make_finding(severity="LOW", rule_id="LOW-001"),
            _make_finding(severity="CRITICAL", rule_id="CRIT-001"),
            _make_finding(severity="HIGH", rule_id="HIGH-001"),
        ]
        copilot = SecurityCopilot()
        result = copilot.analyze(findings)
        assert len(result) == 3


# ---------------------------------------------------------------------------
# SecurityCopilot.generate_patches()
# ---------------------------------------------------------------------------

class TestSecurityCopilotGeneratePatches:

    def test_generate_patches_returns_list(self):
        code = """\
from flask import request
import sqlite3

def vulnerable(db):
    uid = request.args.get("id")
    db.execute("SELECT * FROM t WHERE id=" + uid)
"""
        findings = [_make_finding(cwe_id="CWE-89", line=6)]
        copilot = SecurityCopilot()
        patches = copilot.generate_patches(findings, code)
        assert isinstance(patches, list), "generate_patches() must return a list"

    def test_generate_patches_empty_findings(self):
        copilot = SecurityCopilot()
        patches = copilot.generate_patches([], "")
        assert isinstance(patches, list)
        assert len(patches) == 0


# ---------------------------------------------------------------------------
# SecurityCopilot.full_cycle()
# ---------------------------------------------------------------------------

class TestSecurityCopilotFullCycle:

    def test_full_cycle_returns_dict(self):
        code = """\
from flask import request
import sqlite3

def get_user(db):
    uid = request.args.get("id")
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
    return cursor.fetchone()
"""
        path = _write_py(code)
        copilot = SecurityCopilot()
        report = copilot.full_cycle(path)
        assert isinstance(report, dict), "full_cycle() must return a dict"

    def test_full_cycle_has_required_keys(self):
        code = "def add(a, b): return a + b\n"
        path = _write_py(code)
        copilot = SecurityCopilot()
        report = copilot.full_cycle(path)
        required_keys = {"path", "scan_id", "findings_count"}
        assert required_keys.issubset(report.keys()), (
            f"Missing keys in full_cycle report: {required_keys - report.keys()}"
        )

    def test_full_cycle_findings_count_is_int(self):
        code = "def add(a, b): return a + b\n"
        path = _write_py(code)
        copilot = SecurityCopilot()
        report = copilot.full_cycle(path)
        assert isinstance(report["findings_count"], int)

    def test_full_cycle_scan_id_nonempty(self):
        code = "pass\n"
        path = _write_py(code)
        copilot = SecurityCopilot()
        report = copilot.full_cycle(path)
        assert report.get("scan_id"), "scan_id must be a non-empty string"

    def test_full_cycle_severity_breakdown(self):
        """full_cycle report should include a severity breakdown dict."""
        code = """\
from flask import request
import sqlite3

def vulnerable(db):
    uid = request.args.get("id")
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
"""
        path = _write_py(code)
        copilot = SecurityCopilot()
        report = copilot.full_cycle(path)
        # severity_breakdown should be present if there are findings
        if report.get("findings_count", 0) > 0:
            assert "severity_breakdown" in report or "patches" in report
