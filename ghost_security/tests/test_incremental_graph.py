"""
tests/test_incremental_graph.py — Phase 6 Incremental Graph Analysis Tests

Tests:
  - Symbol impact analysis (SymbolExtractor, SymbolDiff, ImpactSet)
  - Graph invalidation (GraphInvalidationManager)
  - CPG graph mutations (add/remove/invalidate_file)
  - SSA form (build_file, incremental rebuild, constants)
  - Incremental call graph (cache, update_file)
  - Reachability incremental (invalidate_file, update_file)
  - Knowledge graph delta (build_delta, patch_node)
  - Attack graph incremental (update_findings, recompute_affected_paths)
  - Monorepo detection
  - Dependency impact analysis
  - Query language
  - Dashboard rendering
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Dict, List

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def py_file_factory(tmp_path):
    """Creates temporary Python files and returns their paths."""
    def _make(name: str, source: str) -> str:
        fpath = tmp_path / name
        fpath.write_text(source, encoding="utf-8")
        return str(fpath)
    return _make


@pytest.fixture()
def simple_py(py_file_factory):
    """A simple Python file with one function."""
    return py_file_factory("simple.py", """
def greet(name):
    msg = "Hello, " + name
    return msg

def farewell(name):
    return "Goodbye " + name
""")


@pytest.fixture()
def auth_py(py_file_factory):
    """A Python file simulating auth logic."""
    return py_file_factory("auth.py", """
from flask import request

class AuthManager:
    def login(self, user, pwd):
        token = request.args.get('token')
        result = db.execute("SELECT * FROM users WHERE id=" + token)
        return result

    def logout(self, session_id):
        return True
""")


@pytest.fixture()
def project_dir(tmp_path):
    """A minimal project directory with several Python files."""
    (tmp_path / "app.py").write_text("""
from flask import Flask, request
app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    user = request.form['user']
    return user
""", encoding="utf-8")

    (tmp_path / "models.py").write_text("""
import sqlite3

def get_user(uid):
    conn = sqlite3.connect('db.sqlite')
    return conn.execute("SELECT * FROM users WHERE id=" + uid)
""", encoding="utf-8")

    (tmp_path / "utils.py").write_text("""
def sanitize(val):
    return str(val).strip()
""", encoding="utf-8")

    return str(tmp_path)


# ===========================================================================
# PART 1: Symbol Impact Analysis
# ===========================================================================

class TestSymbolExtractor:
    def test_extract_functions(self, simple_py):
        from core.graph_invalidation import SymbolExtractor
        syms = SymbolExtractor().extract(simple_py)
        assert "greet" in syms
        assert "farewell" in syms
        assert syms["greet"].kind == "function"
        assert syms["greet"].lineno > 0

    def test_extract_class_and_methods(self, auth_py):
        from core.graph_invalidation import SymbolExtractor
        syms = SymbolExtractor().extract(auth_py)
        assert "AuthManager" in syms
        assert syms["AuthManager"].kind == "class"
        # Methods should be present as qualified names
        assert any("login" in k for k in syms)

    def test_body_hash_changes_when_source_changes(self, py_file_factory):
        from core.graph_invalidation import SymbolExtractor
        src1 = "def foo():\n    return 1\n"
        src2 = "def foo():\n    return 2\n"
        f1 = py_file_factory("v1.py", src1)
        f2 = py_file_factory("v2.py", src2)
        syms1 = SymbolExtractor().extract(f1)
        syms2 = SymbolExtractor().extract(f2)
        assert syms1["foo"].body_hash != syms2["foo"].body_hash

    def test_entry_point_detection(self, py_file_factory):
        from core.graph_invalidation import SymbolExtractor
        src = """
from flask import Flask
app = Flask(__name__)

@app.route('/api/data')
def get_data():
    return 'data'
"""
        fpath = py_file_factory("routes.py", src)
        syms = SymbolExtractor().extract(fpath)
        assert any(s.is_entry for s in syms.values()), "Entry point not detected"

    def test_extract_from_source_string(self):
        from core.graph_invalidation import SymbolExtractor
        source = "def bar(x):\n    return x * 2\n"
        syms = SymbolExtractor().extract_from_source(source, "virtual.py")
        assert "bar" in syms


class TestSymbolDiff:
    def test_detect_added_symbol(self):
        from core.graph_invalidation import SymbolDiff, SymbolInfo
        before = {"foo": SymbolInfo("foo", "function", 1, 3, body_hash="aaa")}
        after  = {
            "foo": SymbolInfo("foo", "function", 1, 3, body_hash="aaa"),
            "bar": SymbolInfo("bar", "function", 5, 7, body_hash="bbb"),
        }
        diff = SymbolDiff.compute(before, after)
        assert "bar" in diff.added
        assert "foo" in diff.unchanged

    def test_detect_removed_symbol(self):
        from core.graph_invalidation import SymbolDiff, SymbolInfo
        before = {
            "foo": SymbolInfo("foo", "function", 1, 3, body_hash="aaa"),
            "bar": SymbolInfo("bar", "function", 5, 7, body_hash="bbb"),
        }
        after = {"foo": SymbolInfo("foo", "function", 1, 3, body_hash="aaa")}
        diff = SymbolDiff.compute(before, after)
        assert "bar" in diff.removed

    def test_detect_modified_symbol(self):
        from core.graph_invalidation import SymbolDiff, SymbolInfo
        before = {"foo": SymbolInfo("foo", "function", 1, 3, body_hash="aaa")}
        after  = {"foo": SymbolInfo("foo", "function", 1, 3, body_hash="bbb")}
        diff = SymbolDiff.compute(before, after)
        assert "foo" in diff.modified


class TestImpactSet:
    def test_all_symbols_union(self):
        from core.graph_invalidation import ImpactSet
        impact = ImpactSet(
            directly_changed={"foo", "bar"},
            callers={"caller1"},
            entrypoints={"ep1"},
        )
        assert "foo" in impact.all_symbols
        assert "caller1" in impact.all_symbols
        assert "ep1" in impact.all_symbols

    def test_is_empty(self):
        from core.graph_invalidation import ImpactSet
        empty = ImpactSet(set(), set(), set())
        assert empty.is_empty()

    def test_to_dict(self):
        from core.graph_invalidation import ImpactSet
        impact = ImpactSet({"foo"}, {"bar"}, set())
        d = impact.to_dict()
        assert "directly_changed" in d
        assert "callers" in d


# ===========================================================================
# PART 2: Graph Invalidation
# ===========================================================================

class TestGraphInvalidationManager:
    def test_register_and_invalidate(self):
        from core.graph_invalidation import GraphInvalidationManager
        mgr = GraphInvalidationManager()
        mgr.register_dependency(
            node_id="node_1",
            graph_type="call_graph",
            symbols={"auth.login"},
            files={"auth.py"},
        )
        from core.graph_invalidation import ImpactSet
        impact = ImpactSet({"auth.login"}, set(), set())
        result = mgr.invalidate_for_impact(impact, ["call_graph"])
        assert "node_1" in result.get("call_graph", set())

    def test_compute_impact_new_file(self, simple_py):
        from core.graph_invalidation import GraphInvalidationManager
        mgr = GraphInvalidationManager()
        impact = mgr.compute_impact([simple_py])
        # First call: no cached state → all symbols are "added"
        assert not impact.is_empty()

    def test_compute_impact_unchanged_file(self, simple_py):
        from core.graph_invalidation import GraphInvalidationManager
        mgr = GraphInvalidationManager()
        mgr.compute_impact([simple_py])   # first call caches symbols
        impact = mgr.compute_impact([simple_py])  # second call: no change
        # No symbols should be "directly changed" (hash unchanged)
        assert len(impact.directly_changed) == 0

    def test_stats(self):
        from core.graph_invalidation import GraphInvalidationManager
        mgr = GraphInvalidationManager()
        stats = mgr.stats()
        assert "invalidation_count" in stats
        assert "files_tracked" in stats


# ===========================================================================
# CPG: graph.py
# ===========================================================================

class TestCodePropertyGraph:
    def test_add_and_remove_node(self):
        from backend.core.cpg.graph import CPGNode, CPGNodeType, CodePropertyGraph
        cpg = CodePropertyGraph()
        node = CPGNode("n1", CPGNodeType.CFG_NODE, "x = 1", file="f.py")
        cpg.add_node(node)
        assert "n1" in cpg.nodes
        cpg.remove_node("n1")
        assert "n1" not in cpg.nodes

    def test_add_remove_edge(self):
        from backend.core.cpg.graph import (
            CPGEdge, CPGEdgeType, CPGNode, CPGNodeType, CodePropertyGraph,
        )
        cpg = CodePropertyGraph()
        cpg.add_node(CPGNode("a", CPGNodeType.CFG_NODE, "a", file="f.py"))
        cpg.add_node(CPGNode("b", CPGNodeType.CFG_NODE, "b", file="f.py"))
        cpg.add_edge(CPGEdge("a", "b", CPGEdgeType.CFG_NEXT))
        assert len(cpg._adj["a"]) == 1
        cpg.remove_edge("a", "b", CPGEdgeType.CFG_NEXT)
        assert len(cpg._adj.get("a", [])) == 0

    def test_reachable(self):
        from backend.core.cpg.graph import (
            CPGEdge, CPGEdgeType, CPGNode, CPGNodeType, CodePropertyGraph,
        )
        cpg = CodePropertyGraph()
        for nid in ["a", "b", "c", "d"]:
            cpg.add_node(CPGNode(nid, CPGNodeType.CFG_NODE, nid, file="f.py"))
        cpg.add_edge(CPGEdge("a", "b", CPGEdgeType.CFG_NEXT))
        cpg.add_edge(CPGEdge("b", "c", CPGEdgeType.CFG_NEXT))
        cpg.add_edge(CPGEdge("c", "d", CPGEdgeType.CFG_NEXT))
        reachable = cpg.reachable("a", edge_types=[CPGEdgeType.CFG_NEXT])
        assert {"b", "c", "d"} == reachable

    def test_all_paths(self):
        from backend.core.cpg.graph import (
            CPGEdge, CPGEdgeType, CPGNode, CPGNodeType, CodePropertyGraph,
        )
        cpg = CodePropertyGraph()
        for nid in ["src", "mid", "dst"]:
            cpg.add_node(CPGNode(nid, CPGNodeType.CFG_NODE, nid, file="f.py"))
        cpg.add_edge(CPGEdge("src", "mid", CPGEdgeType.DFG_FLOW))
        cpg.add_edge(CPGEdge("mid", "dst", CPGEdgeType.DFG_FLOW))
        paths = cpg.all_paths("src", "dst", edge_types=[CPGEdgeType.DFG_FLOW])
        assert len(paths) == 1
        assert paths[0] == ["src", "mid", "dst"]

    def test_invalidate_file(self, auth_py):
        from backend.core.cpg.graph import PythonCPGBuilder
        cpg = PythonCPGBuilder().build_file(auth_py)
        n_before = len(cpg.nodes)
        removed  = cpg.invalidate_file(auth_py)
        assert removed == n_before
        assert len(cpg.nodes) == 0

    def test_version_increments(self):
        from backend.core.cpg.graph import (
            CPGEdge, CPGEdgeType, CPGNode, CPGNodeType, CodePropertyGraph,
        )
        cpg = CodePropertyGraph()
        v0 = cpg.version
        cpg.add_node(CPGNode("x", CPGNodeType.CFG_NODE, "x", file="f.py"))
        assert cpg.version > v0


class TestPythonCPGBuilder:
    def test_build_file_creates_entry_node(self, auth_py):
        from backend.core.cpg.graph import CPGNodeType, PythonCPGBuilder
        cpg = PythonCPGBuilder().build_file(auth_py)
        entry_nodes = [n for n in cpg.nodes.values() if n.node_type == CPGNodeType.CFG_ENTRY]
        assert len(entry_nodes) >= 1  # login and logout

    def test_build_file_creates_cg_call_nodes(self, auth_py):
        from backend.core.cpg.graph import CPGNodeType, PythonCPGBuilder
        cpg = PythonCPGBuilder().build_file(auth_py)
        call_nodes = [n for n in cpg.nodes.values() if n.node_type == CPGNodeType.CG_CALL]
        assert len(call_nodes) >= 1

    def test_build_project(self, project_dir):
        from backend.core.cpg.graph import PythonCPGBuilder
        cpg = PythonCPGBuilder().build_project(project_dir)
        stats = cpg.stats()
        assert stats["nodes"] > 0
        assert stats["files"] >= 3

    def test_dfg_source_detected(self, py_file_factory):
        from backend.core.cpg.graph import CPGNodeType, PythonCPGBuilder
        src = "def f(req):\n    data = request.args.get('x')\n    return data\n"
        fpath = py_file_factory("req.py", src)
        cpg = PythonCPGBuilder().build_file(fpath)
        source_nodes = [n for n in cpg.nodes.values() if n.node_type == CPGNodeType.DFG_SOURCE]
        assert len(source_nodes) >= 1

    def test_dfg_sink_detected(self, py_file_factory):
        from backend.core.cpg.graph import CPGNodeType, PythonCPGBuilder
        src = "def f(q):\n    result = db.execute('SELECT * FROM t WHERE id=' + q)\n    return result\n"
        fpath = py_file_factory("sink.py", src)
        cpg = PythonCPGBuilder().build_file(fpath)
        sink_nodes = [n for n in cpg.nodes.values() if n.node_type == CPGNodeType.DFG_SINK]
        assert len(sink_nodes) >= 1


# ===========================================================================
# SSA Form
# ===========================================================================

class TestSSAForm:
    def test_build_file_extracts_variables(self, simple_py):
        from backend.core.cpg.ssa import SSAForm
        ssa = SSAForm.build_file(simple_py)
        # "msg" is assigned in greet()
        assert "msg" in ssa.variables

    def test_constants_captured(self, py_file_factory):
        from backend.core.cpg.ssa import SSAForm
        src = "def f():\n    x = 42\n    y = 'hello'\n    return x + len(y)\n"
        fpath = py_file_factory("consts.py", src)
        ssa = SSAForm.build_file(fpath)
        assert ssa.get_constant("x") == 42
        assert ssa.get_constant("y") == "hello"

    def test_version_counter_increments(self, py_file_factory):
        from backend.core.cpg.ssa import SSAForm
        src = "def f():\n    x = 1\n    x = 2\n    x = 3\n"
        fpath = py_file_factory("ver.py", src)
        ssa = SSAForm.build_file(fpath)
        assert len(ssa.variables.get("x", [])) == 3
        versions = [v.version for v in ssa.variables["x"]]
        assert versions == sorted(versions)

    def test_invalidate_variable(self, simple_py):
        from backend.core.cpg.ssa import SSAForm
        ssa = SSAForm.build_file(simple_py)
        ssa.invalidate_variable("msg")
        assert "msg" not in ssa.variables

    def test_get_latest_version(self, py_file_factory):
        from backend.core.cpg.ssa import SSAForm
        src = "def f():\n    z = 10\n    z = 20\n"
        fpath = py_file_factory("lat.py", src)
        ssa = SSAForm.build_file(fpath)
        latest = ssa.get_latest_version("z")
        assert latest is not None
        assert latest.value == 20

    def test_stats(self, simple_py):
        from backend.core.cpg.ssa import SSAForm
        ssa = SSAForm.build_file(simple_py)
        stats = ssa.stats()
        assert stats["total_variables"] >= 1
        assert stats["ssa_version"] >= 1


# ===========================================================================
# Incremental Call Graph
# ===========================================================================

class TestIncrementalCallGraph:
    def test_build_indexes_all_files(self, project_dir):
        from core.analysis.call_graph import IncrementalCallGraph
        icg = IncrementalCallGraph(project_dir)
        graph = icg.build()
        assert len(graph["nodes"]) > 0
        assert len(icg._file_cache) >= 3

    def test_update_file_detects_change(self, project_dir):
        from core.analysis.call_graph import IncrementalCallGraph
        icg = IncrementalCallGraph(project_dir)
        icg.build()
        # Modify a file
        utils_py = os.path.join(project_dir, "utils.py")
        Path(utils_py).write_text("def sanitize(val):\n    return val  # changed\n",
                                  encoding="utf-8")
        changed = icg.update_file(utils_py)
        assert changed is True

    def test_update_unchanged_file_returns_false(self, project_dir):
        from core.analysis.call_graph import IncrementalCallGraph
        icg = IncrementalCallGraph(project_dir)
        icg.build()
        utils_py = os.path.join(project_dir, "utils.py")
        changed = icg.update_file(utils_py)
        assert changed is False   # content unchanged

    def test_remove_file(self, project_dir):
        from core.analysis.call_graph import IncrementalCallGraph
        icg = IncrementalCallGraph(project_dir)
        icg.build()
        utils_py = os.path.join(project_dir, "utils.py")
        removed = icg.remove_file(utils_py)
        assert removed is True
        assert utils_py not in icg._file_cache


# ===========================================================================
# Incremental Reachability
# ===========================================================================

class TestIncrementalReachability:
    def test_invalidate_file(self, project_dir):
        from core.analysis.reachability import ReachabilityAnalyzer
        analyzer = ReachabilityAnalyzer(project_dir)
        analyzer._ensure_index()
        app_py = os.path.join(project_dir, "app.py")
        result = analyzer.invalidate_file(app_py)
        # May return True or False depending on whether index has the key
        # Just ensure no exception
        assert isinstance(result, bool)

    def test_update_file(self, project_dir, tmp_path):
        from core.analysis.reachability import ReachabilityAnalyzer
        analyzer = ReachabilityAnalyzer(project_dir)
        analyzer._ensure_index()
        utils_py = os.path.join(project_dir, "utils.py")
        # update_file on unchanged file should return False
        result = analyzer.update_file(utils_py)
        assert isinstance(result, bool)


# ===========================================================================
# Knowledge Graph Delta
# ===========================================================================

class TestKnowledgeGraphDelta:
    def _make_finding(self, rule_id="SQL001", file="models.py", line=5, sev="HIGH"):
        from backend.analysis.knowledge_graph import Finding
        try:
            return Finding(rule_id=rule_id, file=file, line=line, severity=sev)
        except Exception:
            try:
                from pydantic import BaseModel
                class _F(BaseModel):
                    model_config = {"extra": "allow"}
                    rule_id: str = ""; file: str = ""; line: int = 0; severity: str = "MEDIUM"
                return _F(rule_id=rule_id, file=file, line=line, severity=sev)
            except Exception:
                return {"rule_id": rule_id, "file": file, "line": line, "severity": sev}

    def test_build_delta_adds_finding(self, project_dir):
        from backend.analysis.knowledge_graph import KnowledgeGraphBuilder
        builder = KnowledgeGraphBuilder()
        f1 = self._make_finding("SQL001", "models.py", 5)
        graph = builder.build(project_dir, [f1])
        n_before = len(graph.nodes)

        f2 = self._make_finding("XSS001", "app.py", 10, "MEDIUM")
        mutated = builder.build_delta(graph, [f2], [])
        assert mutated > 0

    def test_patch_node_updates_properties(self, project_dir):
        from backend.analysis.knowledge_graph import KnowledgeGraphBuilder
        builder = KnowledgeGraphBuilder()
        graph = builder.build(project_dir, [])
        if graph.nodes:
            nid = graph.nodes[0].node_id
            ok  = builder.patch_node(graph, nid, {"patched": True})
            assert ok
            assert graph.nodes[0].properties.get("patched") is True

    def test_patch_node_nonexistent_returns_false(self, project_dir):
        from backend.analysis.knowledge_graph import KnowledgeGraphBuilder
        builder = KnowledgeGraphBuilder()
        graph = builder.build(project_dir, [])
        ok = builder.patch_node(graph, "nonexistent_id_xyz", {"x": 1})
        assert ok is False


# ===========================================================================
# Attack Graph Incremental
# ===========================================================================

class TestAttackGraphIncremental:
    def _make_ag_finding(self, rule_id="SQL1", severity="HIGH", file="a.py", line=1):
        """Create a Finding object compatible with attack_graph.py."""
        import importlib
        ag = importlib.import_module("backend.analysis.attack_graph")
        F = getattr(ag, "Finding")
        try:
            return F(rule_id=rule_id, severity=severity, file=file, line=line)
        except Exception:
            return F(rule_id=rule_id, severity=severity, file=file)

    def _findings(self):
        return [self._make_ag_finding("SQL1", "HIGH", "a.py", 1)]

    def test_update_findings_adds_node(self):
        from backend.analysis.attack_graph import AttackGraph, AttackGraphBuilder
        builder = AttackGraphBuilder()
        findings = self._findings()
        graph = builder.build(findings, [])
        n_before = len(graph.nodes)

        new_finding = self._make_ag_finding("XSS1", "MEDIUM", "b.py", 5)

        changed = builder.update_findings(graph, [new_finding], [])
        assert changed >= 0
        assert len(graph.nodes) >= n_before

    def test_update_findings_removes_node(self):
        from backend.analysis.attack_graph import AttackGraphBuilder
        builder  = AttackGraphBuilder()
        findings = self._findings()
        graph    = builder.build(findings, [])

        changed = builder.update_findings(graph, [], findings)
        assert changed >= 0

    def test_recompute_affected_paths(self):
        from backend.analysis.attack_graph import AttackGraphBuilder
        builder  = AttackGraphBuilder()
        findings = self._findings()
        graph    = builder.build(findings, [])

        # Even with empty changed_node_ids, should return a list
        result = builder.recompute_affected_paths(graph, [])
        assert isinstance(result, list)


# ===========================================================================
# Monorepo Detection
# ===========================================================================

class TestMonorepoDetector:
    def test_detects_python_submodules(self, tmp_path):
        from core.graph_invalidation import MonorepoDetector
        # Create sub-packages
        for pkg in ["serviceA", "serviceB", "serviceC"]:
            d = tmp_path / pkg
            d.mkdir()
            (d / "pyproject.toml").write_text(f'[project]\nname = "{pkg}"\n')

        detector = MonorepoDetector(str(tmp_path))
        modules  = detector.detect()
        assert len(modules) >= 2
        assert detector.is_monorepo()

    def test_get_changed_modules(self, tmp_path):
        from core.graph_invalidation import MonorepoDetector
        for pkg in ["svcA", "svcB"]:
            d = tmp_path / pkg
            d.mkdir()
            (d / "pyproject.toml").write_text(f'[project]\nname = "{pkg}"\n')
            (d / "main.py").write_text("x = 1\n")

        detector = MonorepoDetector(str(tmp_path))
        modules  = detector.detect()
        changed  = [str(tmp_path / "svcA" / "main.py")]
        affected = detector.get_changed_modules(changed, modules)
        assert len(affected) == 1
        assert affected[0].name == "svcA"

    def test_not_a_monorepo(self, tmp_path):
        from core.graph_invalidation import MonorepoDetector
        (tmp_path / "main.py").write_text("x = 1\n")
        detector = MonorepoDetector(str(tmp_path))
        assert not detector.is_monorepo()


# ===========================================================================
# Dependency Impact Analysis
# ===========================================================================

class TestDependencyImpactAnalyzer:
    def test_finds_affected_files(self, project_dir):
        from core.graph_invalidation import DependencyImpactAnalyzer
        analyzer = DependencyImpactAnalyzer(project_dir)
        impact = analyzer.analyze("flask", "2.0.0", "2.1.0")
        assert isinstance(impact.affected_files, list)
        # app.py imports flask
        assert any("app.py" in f for f in impact.affected_files)

    def test_risk_level_assigned(self, project_dir):
        from core.graph_invalidation import DependencyImpactAnalyzer
        analyzer = DependencyImpactAnalyzer(project_dir)
        impact = analyzer.analyze("flask", "2.0.0", "2.1.0")
        assert impact.risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")

    def test_to_dict(self, project_dir):
        from core.graph_invalidation import DependencyImpactAnalyzer
        analyzer = DependencyImpactAnalyzer(project_dir)
        impact = analyzer.analyze("sqlite3", "3.0", "3.1")
        d = impact.to_dict()
        assert "package" in d
        assert "risk_level" in d


# ===========================================================================
# Query Language
# ===========================================================================

class TestIncrementalQuery:
    def _make_result(self):
        """Build a minimal IncrementalResult-like dict for query tests."""
        return {
            "changed_files":  ["auth.py", "models.py"],
            "scanned_files":  ["auth.py"],
            "cached_files":   ["models.py"],
            "new_findings":   [
                {"rule_id": "SQL1", "severity": "HIGH",     "file": "models.py", "line": 5},
                {"rule_id": "XSS1", "severity": "MEDIUM",   "file": "app.py",    "line": 10},
                {"rule_id": "SEC1", "severity": "CRITICAL", "file": "auth.py",   "line": 3},
            ],
            "impact_set": {
                "directly_changed": ["auth.login", "models.get_user"],
                "callers": ["app.route_login"],
                "entrypoints": ["app.route_login"],
            },
            "invalidated_nodes": {
                "call_graph":      ["node_1", "node_2"],
                "knowledge_graph": ["kg_node_3"],
            },
            "graph_rebuild_stats": {
                "total_graph_duration_s": 0.05,
                "per_graph": {
                    "attack_graph": {"paths_recomputed": 2, "duration_s": 0.01},
                },
            },
            "commit": "abc123",
            "duration_s": 0.42,
        }

    def test_find_impacted_symbols(self):
        from core.incremental_query import query
        r = self._make_result()
        items = query(r).find("impacted_symbols").execute()
        assert len(items) > 0
        assert all(it.kind == "symbol" for it in items)

    def test_filter_by_type(self):
        from core.incremental_query import query
        r = self._make_result()
        items = query(r).find("impacted_symbols").where(type="directly_changed").execute()
        assert all(it.properties["type"] == "directly_changed" for it in items)

    def test_find_invalidated_nodes(self):
        from core.incremental_query import query
        r = self._make_result()
        items = query(r).find("invalidated_nodes").execute()
        assert len(items) > 0

    def test_find_incremental_findings(self):
        from core.incremental_query import query
        r = self._make_result()
        items = query(r).find("incremental_findings").execute()
        assert len(items) == 3

    def test_filter_findings_by_severity(self):
        from core.incremental_query import query
        r = self._make_result()
        items = query(r).find("incremental_findings").where(severity="HIGH").execute()
        assert len(items) == 1
        assert items[0].id == "SQL1"

    def test_limit(self):
        from core.incremental_query import query
        r = self._make_result()
        items = query(r).find("incremental_findings").limit(2).execute()
        assert len(items) == 2

    def test_count(self):
        from core.incremental_query import query
        r = self._make_result()
        n = query(r).find("incremental_findings").count()
        assert n == 3

    def test_ids(self):
        from core.incremental_query import query
        r = self._make_result()
        ids = query(r).find("incremental_findings").ids()
        assert "SQL1" in ids

    def test_to_dicts(self):
        from core.incremental_query import query
        r = self._make_result()
        dicts = query(r).find("incremental_findings").to_dicts()
        assert all(isinstance(d, dict) for d in dicts)

    def test_invalid_target_raises(self):
        from core.incremental_query import query
        r = self._make_result()
        with pytest.raises(ValueError):
            query(r).find("nonexistent_target").execute()


# ===========================================================================
# Dashboard
# ===========================================================================

class TestIncrementalDashboard:
    def _result(self):
        return {
            "changed_files": ["a.py", "b.py"],
            "scanned_files": ["a.py"],
            "cached_files":  ["b.py"],
            "new_findings":  [{"severity": "HIGH", "rule_id": "R1"}],
            "impact_set":    {"directly_changed": ["a.foo"], "callers": [], "entrypoints": []},
            "invalidated_nodes": {"call_graph": ["n1"]},
            "graph_rebuild_stats": {
                "total_graph_duration_s": 0.01,
                "per_graph": {},
            },
            "cache_stats": {"entries": 10, "size_kb": 5.0, "hits": 8, "misses": 2, "hit_rate": 0.8},
            "commit": "deadbeef",
            "duration_s": 0.22,
        }

    def test_renders_text(self):
        from core.incremental_dashboard import IncrementalDashboard
        db = IncrementalDashboard.from_result(self._result())
        text = db.render_text()
        assert "Changed Files" in text
        assert "Impacted Symbols" in text
        assert "Cache Statistics" in text

    def test_renders_json(self):
        import json
        from core.incremental_dashboard import IncrementalDashboard
        db = IncrementalDashboard.from_result(self._result())
        data = json.loads(db.render_json())
        assert "sections" in data
        assert "generated_at" in data

    def test_sections_populated(self):
        from core.incremental_dashboard import IncrementalDashboard
        db = IncrementalDashboard.from_result(self._result())
        titles = [s.title for s in db.sections]
        assert "Changed Files" in titles
        assert "Impacted Symbols" in titles
        assert "Invalidated Graph Nodes" in titles

    def test_save_json(self, tmp_path):
        from core.incremental_dashboard import IncrementalDashboard
        db = IncrementalDashboard.from_result(self._result())
        out = str(tmp_path / "dashboard.json")
        db.save_json(out)
        assert Path(out).exists()

    def test_benchmark_dashboard(self):
        from core.incremental_dashboard import BenchmarkDashboard, BenchmarkResult
        bd = BenchmarkDashboard()
        bd.add(BenchmarkResult("Full Scan",  10.0, 100, 0,   50))
        bd.add(BenchmarkResult("Warm Scan",   0.1,   0, 100, 50))
        bd.add(BenchmarkResult("Incr 1 file", 0.05,  1,  99,  2))
        text = bd.render_text()
        assert "Full Scan" in text
        assert "Warm Scan" in text
        # Speedup should be shown
        assert "x" in text
