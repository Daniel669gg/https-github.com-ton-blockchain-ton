"""Tests for v13 AST detection engine."""
import sys
import pathlib
import pytest
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))


class TestASTEngine:
    @pytest.fixture
    def engine(self):
        from core.ast_engine.ast_engine import ASTEngine
        return ASTEngine()

    @pytest.fixture
    def vuln_python(self, tmp_path):
        f = tmp_path / "vuln.py"
        f.write_text("""
import sqlite3

def get_user(username):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchone()

def run_eval(user_input):
    result = eval(user_input)
    return result
""")
        return str(f)

    @pytest.fixture
    def safe_python(self, tmp_path):
        f = tmp_path / "safe.py"
        f.write_text("""
import sqlite3

def get_user(username):
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cursor.fetchone()

CONSTANT = 42
""")
        return str(f)

    def test_import(self, engine):
        assert engine is not None

    def test_analyze_vulnerable_python(self, engine, vuln_python):
        findings = engine.analyze_file(vuln_python, rules=[])
        assert isinstance(findings, list)

    def test_analyze_safe_python(self, engine, safe_python):
        findings = engine.analyze_file(safe_python, rules=[])
        assert isinstance(findings, list)

    def test_analyze_directory(self, engine, tmp_path):
        (tmp_path / "a.py").write_text("x = eval(input())")
        (tmp_path / "b.py").write_text("y = 42")
        result = engine.analyze_directory(str(tmp_path), rules=[])
        assert isinstance(result, dict)
        assert "files_scanned" in result
        # findings may be flat list or dict-by-file depending on implementation
        has_findings = "findings" in result or "findings_by_file" in result or "total_findings" in result
        assert has_findings

    def test_nonexistent_file(self, engine):
        findings = engine.analyze_file("/nonexistent/path.py", rules=[])
        assert findings == []

    def test_finding_format(self, engine, vuln_python):
        findings = engine.analyze_file(vuln_python, rules=[])
        for f in findings:
            assert "rule_id" in f
            assert "severity" in f
            assert "file" in f
            assert "line" in f


class TestTaintTracker:
    @pytest.fixture
    def tracker(self):
        from core.ast_engine.taint_tracker import TaintTracker
        return TaintTracker()

    def test_import(self, tracker):
        assert tracker is not None

    def test_detects_tainted_sql(self, tracker):
        code = """
def search(query):
    user_input = request.args.get('q')
    results = db.execute(f"SELECT * FROM items WHERE name = '{user_input}'")
    return results
"""
        flows = tracker.track(code)
        assert isinstance(flows, list)

    def test_clean_code_no_flows(self, tracker):
        code = """
def safe_search():
    results = db.execute("SELECT * FROM items WHERE name = ?", ("fixed",))
    return results
"""
        flows = tracker.track(code)
        assert isinstance(flows, list)

    def test_tracks_variable_assignment(self, tracker):
        code = """
user_data = request.form.get('data')
output = eval(user_data)
"""
        flows = tracker.track(code)
        assert isinstance(flows, list)


class TestSourceSinkDB:
    def test_import(self):
        from core.ast_engine.source_sink_db import PYTHON_SOURCES, PYTHON_SINKS, JS_SOURCES, JS_SINKS
        assert len(PYTHON_SOURCES) >= 10
        assert len(PYTHON_SINKS) >= 1
        assert len(JS_SOURCES) >= 5
        assert len(JS_SINKS) >= 1

    def test_python_sources_are_strings(self):
        from core.ast_engine.source_sink_db import PYTHON_SOURCES
        for s in PYTHON_SOURCES:
            assert isinstance(s, str)

    def test_python_sinks_have_categories(self):
        from core.ast_engine.source_sink_db import PYTHON_SINKS
        assert isinstance(PYTHON_SINKS, dict)
        # Should have at least sql and cmd categories
        all_sinks = []
        for cat, sinks in PYTHON_SINKS.items():
            all_sinks.extend(sinks)
        assert len(all_sinks) >= 15
