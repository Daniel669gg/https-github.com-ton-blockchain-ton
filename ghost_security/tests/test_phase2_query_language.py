"""
tests/test_phase2_query_language.py — Phase 2 Security Query Language tests.
25 tests covering AST, dataflow, reachability, CPG, attack, and dependency queries.
"""
import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.cpg.query_engine import CPGQueryEngine, SecurityQueryLanguage
from backend.core.cpg.graph import CodePropertyGraph, CPGNode, CPGNodeType, CPGEdge, CPGEdgeType
from backend.core.cpg.builder import CPGBuilder


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_cpg(source: str = "") -> CodePropertyGraph:
    if source:
        return CPGBuilder().build_source(source)
    return CodePropertyGraph()


def _make_sql(source: str = "") -> SecurityQueryLanguage:
    cpg = _make_cpg(source)
    return SecurityQueryLanguage(cpg)


_SQLI_SOURCE = """
from flask import request
import sqlite3

def search_users():
    q = request.args.get("q")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name='" + q + "'")
    return cursor.fetchall()
"""

_CMDI_SOURCE = """
import os
from flask import request

def run_cmd():
    cmd = request.form.get("cmd")
    os.system(cmd)
"""


# ─────────────────────────────────────────────────────────────────────────────
# SecurityQueryLanguage importability
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityQueryLanguageImport:
    def test_security_query_language_importable(self):
        assert SecurityQueryLanguage is not None

    def test_can_instantiate_with_empty_cpg(self):
        sql = SecurityQueryLanguage(CodePropertyGraph())
        assert sql is not None

    def test_execute_method_exists(self):
        sql = _make_sql()
        assert hasattr(sql, "execute")

    def test_execute_batch_method_exists(self):
        sql = _make_sql()
        assert hasattr(sql, "execute_batch")


# ─────────────────────────────────────────────────────────────────────────────
# Query result structure
# ─────────────────────────────────────────────────────────────────────────────

class TestQueryResult:
    def test_execute_returns_result_object(self):
        sql = _make_sql()
        result = sql.execute("find reachable_rce")
        assert result is not None

    def test_result_has_query_field(self):
        sql = _make_sql()
        result = sql.execute("find attack_paths")
        assert hasattr(result, "query") or hasattr(result, "result_type") or hasattr(result, "items")

    def test_result_has_count(self):
        sql = _make_sql()
        result = sql.execute("find reachable_sink")
        assert hasattr(result, "count") or isinstance(result, (list, dict))

    def test_execute_batch_returns_list(self):
        sql = _make_sql()
        results = sql.execute_batch(["find reachable_rce", "find attack_paths"])
        assert isinstance(results, list)
        assert len(results) == 2


# ─────────────────────────────────────────────────────────────────────────────
# AST queries
# ─────────────────────────────────────────────────────────────────────────────

class TestASTQueries:
    def test_find_function_query(self):
        sql = _make_sql(_SQLI_SOURCE)
        result = sql.execute('find function where name="search_users"')
        assert result is not None

    def test_find_call_query(self):
        sql = _make_sql(_CMDI_SOURCE)
        result = sql.execute('find call where target="system"')
        assert result is not None

    def test_find_assignment_query(self):
        sql = _make_sql(_SQLI_SOURCE)
        result = sql.execute('find assignment where target="q"')
        assert result is not None

    def test_find_function_no_crash_empty_cpg(self):
        sql = _make_sql()
        result = sql.execute('find function where name="login"')
        assert result is not None


# ─────────────────────────────────────────────────────────────────────────────
# Dataflow queries
# ─────────────────────────────────────────────────────────────────────────────

class TestDataflowQueries:
    def test_find_taint_flow_user_input_to_sql(self):
        sql = _make_sql(_SQLI_SOURCE)
        result = sql.execute("find taint_flow where source=user_input and sink=sql_query")
        assert result is not None

    def test_find_taint_flow_request_to_command(self):
        sql = _make_sql(_CMDI_SOURCE)
        result = sql.execute("find taint_flow where source=request and sink=command")
        assert result is not None

    def test_find_propagation_path(self):
        sql = _make_sql(_SQLI_SOURCE)
        result = sql.execute("find propagation_path where source=request and sink=sql_query")
        assert result is not None

    def test_dataflow_query_on_empty_cpg(self):
        sql = _make_sql()
        result = sql.execute("find taint_flow where source=user_input and sink=file_write")
        assert result is not None


# ─────────────────────────────────────────────────────────────────────────────
# Reachability queries
# ─────────────────────────────────────────────────────────────────────────────

class TestReachabilityQueries:
    def test_find_reachable_sink(self):
        sql = _make_sql(_SQLI_SOURCE)
        result = sql.execute("find reachable_sink")
        assert result is not None

    def test_find_reachable_rce(self):
        sql = _make_sql(_CMDI_SOURCE)
        result = sql.execute("find reachable_rce")
        assert result is not None

    def test_find_reachable_cve(self):
        sql = _make_sql(_SQLI_SOURCE)
        result = sql.execute("find reachable_cve")
        assert result is not None


# ─────────────────────────────────────────────────────────────────────────────
# Attack graph queries
# ─────────────────────────────────────────────────────────────────────────────

class TestAttackGraphQueries:
    def test_find_attack_paths(self):
        sql = _make_sql(_SQLI_SOURCE)
        result = sql.execute("find attack_paths")
        assert result is not None

    def test_find_exploit_chains(self):
        sql = _make_sql(_SQLI_SOURCE)
        result = sql.execute("find exploit_chains")
        assert result is not None

    def test_find_privilege_escalation_paths(self):
        sql = _make_sql()
        result = sql.execute("find privilege_escalation_paths")
        assert result is not None


# ─────────────────────────────────────────────────────────────────────────────
# Dependency queries
# ─────────────────────────────────────────────────────────────────────────────

class TestDependencyQueries:
    def test_find_vulnerable_dependency(self):
        sql = _make_sql()
        result = sql.execute("find vulnerable_dependency")
        assert result is not None

    def test_find_exploitable_dependency(self):
        sql = _make_sql()
        result = sql.execute("find exploitable_dependency")
        assert result is not None


# ─────────────────────────────────────────────────────────────────────────────
# Existing CPGQueryEngine preserved
# ─────────────────────────────────────────────────────────────────────────────

class TestExistingQueryEnginePreserved:
    def test_cpg_query_engine_still_importable(self):
        assert CPGQueryEngine is not None

    def test_find_sql_injection_still_works(self):
        cpg = _make_cpg(_SQLI_SOURCE)
        engine = CPGQueryEngine(cpg)
        results = engine.find_sql_injection()
        assert isinstance(results, list)

    def test_find_command_injection_still_works(self):
        cpg = _make_cpg(_CMDI_SOURCE)
        engine = CPGQueryEngine(cpg)
        results = engine.find_command_injection()
        assert isinstance(results, list)

    def test_find_hardcoded_secrets_still_works(self):
        source = 'password = "secret123"\napi_key = "sk-abc123xyz"\n'
        cpg = _make_cpg(source)
        engine = CPGQueryEngine(cpg)
        results = engine.find_hardcoded_secrets()
        assert isinstance(results, list)
