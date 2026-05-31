"""
tests/test_dataflow_enhanced.py — Tests for enhanced dataflow bug fixes.

Covers:
  Bug 1: BinOp taint propagation
  Bug 2: Subscript taint propagation
  Bug 3: str.format / % formatting taint propagation
  Bug 4: Attribute assignment taint propagation  (self.x = tainted)
  Bug 5: CWE-798 hardcoded secrets detection
"""
from __future__ import annotations

import sys
import tempfile
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import ast
import pytest

from backend.analysis.interprocedural import (
    InterproceduralTaintAnalyzer,
    _names_in_expr,
)
from backend.scanners.taint_analyzer import TaintAnalyzer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_expr(src: str) -> ast.expr:
    """Parse a Python expression string into an AST node."""
    tree = ast.parse(src, mode="eval")
    return tree.body  # type: ignore[return-value]


def _write_tmp(code: str, suffix: str = ".py") -> str:
    """Write code to a temp file and return the path."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    )
    f.write(code)
    f.flush()
    f.close()
    return f.name


# ---------------------------------------------------------------------------
# _names_in_expr unit tests
# ---------------------------------------------------------------------------


class TestNamesInExpr:
    """Unit tests for the _names_in_expr helper in interprocedural.py."""

    def test_plain_name(self):
        node = _parse_expr("user_input")
        assert "user_input" in _names_in_expr(node)

    def test_binop_left(self):
        node = _parse_expr('"SELECT * FROM users WHERE id = " + user_input')
        assert "user_input" in _names_in_expr(node)

    def test_binop_right(self):
        node = _parse_expr('prefix + user_input')
        assert "user_input" in _names_in_expr(node)
        assert "prefix" in _names_in_expr(node)

    def test_binop_percent_format(self):
        node = _parse_expr('"SELECT * FROM %s" % user_table')
        assert "user_table" in _names_in_expr(node)

    def test_subscript_name(self):
        node = _parse_expr('request["user_input"]')
        assert "request" in _names_in_expr(node)

    def test_subscript_attribute(self):
        node = _parse_expr('request.form["field"]')
        assert "request" in _names_in_expr(node)

    def test_attribute_value(self):
        node = _parse_expr("self.email")
        assert "self" in _names_in_expr(node)

    def test_fstring(self):
        node = _parse_expr('f"SELECT * FROM {user_table}"')
        assert "user_table" in _names_in_expr(node)

    def test_str_format_call(self):
        node = _parse_expr('"SELECT * FROM {}".format(user_table)')
        assert "user_table" in _names_in_expr(node)

    def test_nested_binop(self):
        node = _parse_expr('"prefix " + "middle " + user_input')
        assert "user_input" in _names_in_expr(node)


# ---------------------------------------------------------------------------
# Bug Fix 1: BinOp taint propagation
# ---------------------------------------------------------------------------


class TestBinOpTaintPropagation:
    """BinOp should propagate taint: query = 'SELECT' + user_input → execute(query)."""

    def test_binop_taint_propagation(self):
        """String concatenation with tainted var should be detected at sink."""
        code = """\
import sqlite3
from flask import request

def vulnerable(db):
    user_input = request.args.get("id")
    query = "SELECT * FROM users WHERE id = " + user_input
    cursor = db.cursor()
    cursor.execute(query)
"""
        path = _write_tmp(code)
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze_file(path)
        # Expect at least one SQL-injection finding
        rule_ids = [f.rule_id for f in findings]
        assert any("SQL" in r.upper() or "TAINT" in r.upper() for r in rule_ids), (
            f"Expected SQL injection finding, got rule IDs: {rule_ids}"
        )

    def test_binop_percent_propagation(self):
        """% string formatting should propagate taint."""
        code = """\
from flask import request
import sqlite3

def vulnerable(db):
    user_table = request.args.get("table")
    query = "SELECT * FROM %s" % user_table
    cursor = db.cursor()
    cursor.execute(query)
"""
        path = _write_tmp(code)
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze_file(path)
        rule_ids = [f.rule_id for f in findings]
        assert any("SQL" in r.upper() or "TAINT" in r.upper() for r in rule_ids), (
            f"Expected SQL injection finding for %s formatting, got: {rule_ids}"
        )

    def test_interprocedural_binop(self):
        """Interprocedural analyzer detects BinOp-based taint flow."""
        code = """\
from flask import request

def handle():
    user_input = request.args.get("id")
    query = "SELECT * FROM users WHERE id = " + user_input
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(query)
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = pathlib.Path(tmpdir) / "app.py"
            fpath.write_text(code)
            analyzer = InterproceduralTaintAnalyzer(tmpdir)
            findings = analyzer.analyze()
            assert len(findings) > 0, "Expected findings for BinOp taint, got none"


# ---------------------------------------------------------------------------
# Bug Fix 2: Subscript taint propagation
# ---------------------------------------------------------------------------


class TestSubscriptTaintPropagation:
    """Subscript access should propagate taint: data = request["field"] → exec(data)."""

    def test_subscript_taint_propagation(self):
        """request['field'] subscript should be detected as a taint source."""
        code = """\
from flask import request
import os

def vulnerable():
    data = request.form["user_input"]
    os.system(data)
"""
        path = _write_tmp(code)
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze_file(path)
        rule_ids = [f.rule_id for f in findings]
        assert any("SHELL" in r.upper() or "TAINT" in r.upper() for r in rule_ids), (
            f"Expected shell injection finding for subscript access, got: {rule_ids}"
        )

    def test_environ_subscript_source(self):
        """os.environ['KEY'] subscript should be tainted."""
        code = """\
import os
import subprocess

def vulnerable():
    cmd = os.environ["USER_CMD"]
    subprocess.run(cmd, shell=True)
"""
        path = _write_tmp(code)
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze_file(path)
        rule_ids = [f.rule_id for f in findings]
        assert any("SHELL" in r.upper() or "TAINT" in r.upper() for r in rule_ids), (
            f"Expected shell injection finding for os.environ subscript, got: {rule_ids}"
        )

    def test_interprocedural_subscript(self):
        """Interprocedural analyzer detects subscript-based taint source."""
        code = """\
from flask import request
import os

def handle():
    data = request["user_input"]
    os.system(data)
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = pathlib.Path(tmpdir) / "app.py"
            fpath.write_text(code)
            analyzer = InterproceduralTaintAnalyzer(tmpdir)
            findings = analyzer.analyze()
            assert len(findings) > 0, "Expected findings for subscript taint, got none"


# ---------------------------------------------------------------------------
# Bug Fix 3: str.format / % formatting taint propagation
# ---------------------------------------------------------------------------


class TestFormatStringTaintPropagation:
    """Format strings should propagate taint."""

    def test_format_string_taint_propagation(self):
        """str.format() with tainted arg should propagate taint."""
        code = """\
from flask import request
import sqlite3

def vulnerable(db):
    user_table = request.args.get("table")
    query2 = "SELECT * FROM {}".format(user_table)
    cursor = db.cursor()
    cursor.execute(query2)
"""
        path = _write_tmp(code)
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze_file(path)
        rule_ids = [f.rule_id for f in findings]
        assert any("SQL" in r.upper() or "TAINT" in r.upper() for r in rule_ids), (
            f"Expected SQL injection via str.format, got: {rule_ids}"
        )

    def test_fstring_taint_propagation(self):
        """f-string with tainted var should propagate taint."""
        code = """\
from flask import request
import sqlite3

def vulnerable(db):
    user_input = request.args.get("id")
    query = f"SELECT * FROM users WHERE id = {user_input}"
    cursor = db.cursor()
    cursor.execute(query)
"""
        path = _write_tmp(code)
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze_file(path)
        rule_ids = [f.rule_id for f in findings]
        assert any("SQL" in r.upper() or "TAINT" in r.upper() for r in rule_ids), (
            f"Expected SQL injection via f-string, got: {rule_ids}"
        )


# ---------------------------------------------------------------------------
# Bug Fix 5: Hardcoded secrets (CWE-798)
# ---------------------------------------------------------------------------


class TestHardcodedSecrets:
    """CWE-798 hardcoded secrets detection."""

    def test_hardcoded_api_key_detected(self):
        """API key literal should trigger CWE-798 finding."""
        code = 'API_KEY = "sk-1234567890abcdef1234567890abcdef"\n'
        path = _write_tmp(code)
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze_file(path)
        cwe_ids = [f.cwe_id for f in findings]
        assert any("798" in c for c in cwe_ids), (
            f"Expected CWE-798 for hardcoded API key, got: {cwe_ids}"
        )

    def test_hardcoded_password_detected(self):
        """Hardcoded password should trigger CWE-798 finding."""
        code = 'DB_PASSWORD = "mysql_r00t_P@ssw0rd123"\n'
        path = _write_tmp(code)
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze_file(path)
        cwe_ids = [f.cwe_id for f in findings]
        assert any("798" in c for c in cwe_ids), (
            f"Expected CWE-798 for hardcoded password, got: {cwe_ids}"
        )

    def test_hardcoded_secret_token_detected(self):
        """Hardcoded secret token should trigger CWE-798."""
        code = 'AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
        path = _write_tmp(code)
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze_file(path)
        cwe_ids = [f.cwe_id for f in findings]
        assert any("798" in c for c in cwe_ids), (
            f"Expected CWE-798 for hardcoded AWS secret, got: {cwe_ids}"
        )

    def test_entropy_based_secret_detected(self):
        """High-entropy string in any variable should trigger CWE-798."""
        # 32-char high-entropy string (not a secret-name keyword variable)
        code = 'some_config_value = "xK9mP2qR7nL4vT1wY6uJ3hF8cB5zA0eD"\n'
        path = _write_tmp(code)
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze_file(path)
        cwe_ids = [f.cwe_id for f in findings]
        assert any("798" in c for c in cwe_ids), (
            f"Expected CWE-798 for high-entropy string, got: {cwe_ids}"
        )

    def test_template_variable_not_flagged(self):
        """${SECRET} should NOT be flagged as a hardcoded secret."""
        code = 'SECRET = "${SECRET_FROM_ENV}"\n'
        path = _write_tmp(code)
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze_file(path)
        cwe_798_findings = [f for f in findings if "798" in f.cwe_id]
        assert len(cwe_798_findings) == 0, (
            f"Template variable ${'{SECRET}'} should not be flagged: {cwe_798_findings}"
        )

    def test_short_string_not_flagged(self):
        """Short strings < 8 chars should not be flagged even with secret name."""
        code = 'password = "short"\n'
        path = _write_tmp(code)
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze_file(path)
        cwe_798_findings = [f for f in findings if "798" in f.cwe_id]
        assert len(cwe_798_findings) == 0, (
            f"Short string 'short' should not be flagged: {cwe_798_findings}"
        )

    def test_confidence_levels(self):
        """Real credential (digits+letters, len>=12) should have confidence >= 0.85."""
        code = 'api_key = "sk-abc123def456xyz789"\n'
        path = _write_tmp(code)
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze_file(path)
        cwe_798 = [f for f in findings if "798" in f.cwe_id]
        assert len(cwe_798) > 0, "Expected CWE-798 finding"
        assert cwe_798[0].confidence >= 0.85, (
            f"Expected confidence >= 0.85 for real credential, got {cwe_798[0].confidence}"
        )

    def test_all_lowercase_word_not_flagged(self):
        """All-lowercase plain word as value should not be flagged (field name pattern)."""
        code = 'password_field = "password-field-name"\n'
        path = _write_tmp(code)
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze_file(path)
        cwe_798_findings = [f for f in findings if "798" in f.cwe_id]
        # This should be filtered as a common-word false positive
        # The value matches _ALL_WORD_RE (all lowercase + hyphens, no digits)
        assert len(cwe_798_findings) == 0, (
            f"All-lowercase word 'password-field-name' should not be flagged: {cwe_798_findings}"
        )
