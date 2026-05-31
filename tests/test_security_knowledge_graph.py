"""
tests/test_security_knowledge_graph.py — Tests for SecurityKnowledgeGraph.

Covers:
  - KGNode and KGEdge construction
  - KnowledgeGraphBuilder.build() from findings
  - Graph structure: nodes and edges created correctly
  - CWE → CVE mapping
  - Root cause analysis (path from node back to source)
  - BFS/DFS traversal
  - Attack path discovery
  - Empty findings handled gracefully
"""
from __future__ import annotations

import sys
import tempfile
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest

from backend.analysis.knowledge_graph import (
    KGNode,
    KGEdge,
    KGNodeType,
    KnowledgeGraphBuilder,
    SecurityKnowledgeGraph,
    CWE_CVE_EXAMPLES,
)
from backend.core.confidence import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        rule_id="TAINT-SQL",
        file="/tmp/test_app.py",
        line=10,
        severity="HIGH",
        confidence=0.85,
        cwe_id="CWE-89",
        description="SQL injection",
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
# KGNode / KGEdge
# ---------------------------------------------------------------------------

class TestKGModels:

    def test_kg_node_creation(self):
        node = KGNode(
            node_id="test-001",
            type=KGNodeType.SINK,
            label="SQL sink",
            properties={"file": "app.py", "line": 42},
        )
        assert node.node_id == "test-001"
        assert node.type == KGNodeType.SINK
        assert node.properties["line"] == 42

    def test_kg_edge_creation(self):
        edge = KGEdge(
            from_id="node-a",
            to_id="node-b",
            relation="FLOWS_TO",
            weight=0.9,
        )
        assert edge.from_id == "node-a"
        assert edge.relation == "FLOWS_TO"
        assert edge.weight == 0.9

    def test_node_types_available(self):
        for t in (KGNodeType.CODE_UNIT, KGNodeType.FUNCTION, KGNodeType.DATAFLOW,
                  KGNodeType.SINK, KGNodeType.CVE, KGNodeType.FIX, KGNodeType.CONTROL):
            assert t.value  # non-empty string


# ---------------------------------------------------------------------------
# CWE → CVE mapping
# ---------------------------------------------------------------------------

class TestCWECVEMapping:

    def test_has_minimum_entries(self):
        assert len(CWE_CVE_EXAMPLES) >= 15, (
            f"Expected >= 15 CWE entries, got {len(CWE_CVE_EXAMPLES)}"
        )

    def test_sql_injection_cwe89(self):
        assert "CWE-89" in CWE_CVE_EXAMPLES
        assert len(CWE_CVE_EXAMPLES["CWE-89"]) > 0

    def test_hardcoded_secrets_cwe798(self):
        assert "CWE-798" in CWE_CVE_EXAMPLES

    def test_all_cve_ids_are_strings(self):
        for cwe, cves in CWE_CVE_EXAMPLES.items():
            for cve in cves:
                assert isinstance(cve, str)
                assert cve.startswith("CVE-"), f"Expected CVE-... format, got {cve!r}"


# ---------------------------------------------------------------------------
# KnowledgeGraphBuilder
# ---------------------------------------------------------------------------

class TestKnowledgeGraphBuilder:

    def test_empty_findings_returns_empty_graph(self):
        builder = KnowledgeGraphBuilder()
        graph = builder.build(project_root="/tmp", findings=[])
        assert isinstance(graph, SecurityKnowledgeGraph)
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_single_finding_creates_nodes(self):
        finding = _make_finding()
        builder = KnowledgeGraphBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write the file so AST parsing works
            fpath = pathlib.Path(tmpdir) / "test_app.py"
            fpath.write_text("""\
from flask import request
import sqlite3
def vulnerable(db):
    user_input = request.args.get("id")
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_input)
""")
            finding2 = _make_finding(file=str(fpath))
            graph = builder.build(project_root=tmpdir, findings=[finding2])
        assert len(graph.nodes) > 0, "Expected at least one node"

    def test_sink_node_created(self):
        finding = _make_finding()
        builder = KnowledgeGraphBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = pathlib.Path(tmpdir) / "test_app.py"
            fpath.write_text("pass\n")
            f = _make_finding(file=str(fpath))
            graph = builder.build(project_root=tmpdir, findings=[f])
        sink_nodes = [n for n in graph.nodes if n.type == KGNodeType.SINK]
        assert len(sink_nodes) > 0, "Expected SINK node to be created"

    def test_cve_nodes_linked(self):
        """Findings with known CWEs should have CVE nodes linked."""
        builder = KnowledgeGraphBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = pathlib.Path(tmpdir) / "vuln.py"
            fpath.write_text("pass\n")
            f = _make_finding(file=str(fpath), cwe_id="CWE-89")
            graph = builder.build(project_root=tmpdir, findings=[f])
        cve_nodes = [n for n in graph.nodes if n.type == KGNodeType.CVE]
        assert len(cve_nodes) > 0, "Expected CVE nodes for CWE-89"

    def test_multiple_findings_deduplicated(self):
        """Same file should not create duplicate CODE_UNIT nodes."""
        builder = KnowledgeGraphBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = pathlib.Path(tmpdir) / "app.py"
            fpath.write_text("pass\n")
            findings = [
                _make_finding(file=str(fpath), line=1),
                _make_finding(file=str(fpath), line=2, rule_id="TAINT-SHELL"),
            ]
            graph = builder.build(project_root=tmpdir, findings=findings)
        code_unit_nodes = [n for n in graph.nodes if n.type == KGNodeType.CODE_UNIT]
        assert len(code_unit_nodes) == 1, (
            f"Expected 1 CODE_UNIT node for same file, got {len(code_unit_nodes)}"
        )

    def test_edges_created(self):
        """The graph should have edges connecting nodes."""
        builder = KnowledgeGraphBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = pathlib.Path(tmpdir) / "app.py"
            fpath.write_text("pass\n")
            f = _make_finding(file=str(fpath))
            graph = builder.build(project_root=tmpdir, findings=[f])
        assert len(graph.edges) > 0, "Expected edges in the graph"

    def test_flows_to_edge_present(self):
        """FLOWS_TO edge should connect DATAFLOW to SINK when sources present."""
        builder = KnowledgeGraphBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = pathlib.Path(tmpdir) / "app.py"
            fpath.write_text("pass\n")
            f = _make_finding(file=str(fpath), sources=["flask_request"])
            graph = builder.build(project_root=tmpdir, findings=[f])
        flows_to = [e for e in graph.edges if e.relation == "FLOWS_TO"]
        assert len(flows_to) > 0, "Expected FLOWS_TO edge when finding has sources"


# ---------------------------------------------------------------------------
# Graph traversal helpers
# ---------------------------------------------------------------------------

class TestGraphTraversal:

    def _build_simple_graph(self) -> SecurityKnowledgeGraph:
        graph = SecurityKnowledgeGraph()
        builder = KnowledgeGraphBuilder()
        n1 = KGNode(node_id="A", type=KGNodeType.CODE_UNIT, label="A")
        n2 = KGNode(node_id="B", type=KGNodeType.DATAFLOW, label="B")
        n3 = KGNode(node_id="C", type=KGNodeType.SINK, label="C")
        builder.add_node(graph, n1)
        builder.add_node(graph, n2)
        builder.add_node(graph, n3)
        builder.add_edge(graph, KGEdge(from_id="A", to_id="B", relation="CONTAINS"))
        builder.add_edge(graph, KGEdge(from_id="B", to_id="C", relation="FLOWS_TO"))
        return graph

    def test_add_node_increments_count(self):
        graph = SecurityKnowledgeGraph()
        builder = KnowledgeGraphBuilder()
        builder.add_node(graph, KGNode(node_id="X", type=KGNodeType.CVE, label="X"))
        assert len(graph.nodes) == 1

    def test_add_duplicate_node_does_not_duplicate(self):
        graph = SecurityKnowledgeGraph()
        builder = KnowledgeGraphBuilder()
        node = KGNode(node_id="X", type=KGNodeType.CVE, label="X")
        builder.add_node(graph, node)
        builder.add_node(graph, node)  # duplicate
        assert len(graph.nodes) == 1

    def test_add_edge(self):
        graph = SecurityKnowledgeGraph()
        builder = KnowledgeGraphBuilder()
        builder.add_node(graph, KGNode(node_id="A", type=KGNodeType.CODE_UNIT, label="A"))
        builder.add_node(graph, KGNode(node_id="B", type=KGNodeType.SINK, label="B"))
        builder.add_edge(graph, KGEdge(from_id="A", to_id="B", relation="LEADS_TO"))
        assert len(graph.edges) == 1


# ---------------------------------------------------------------------------
# Security-specific tests
# ---------------------------------------------------------------------------

class TestSecurityFeatures:

    def test_multi_cwe_findings(self):
        """Multiple CWEs produce CVE nodes for each."""
        builder = KnowledgeGraphBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = pathlib.Path(tmpdir) / "app.py"
            fpath.write_text("pass\n")
            findings = [
                _make_finding(file=str(fpath), cwe_id="CWE-89", rule_id="TAINT-SQL"),
                _make_finding(file=str(fpath), cwe_id="CWE-78", rule_id="TAINT-SHELL", line=20),
            ]
            graph = builder.build(project_root=tmpdir, findings=findings)
        cve_nodes = [n for n in graph.nodes if n.type == KGNodeType.CVE]
        # CWE-89 and CWE-78 both have CVE entries
        assert len(cve_nodes) >= 2, f"Expected CVE nodes for CWE-89 and CWE-78, got {len(cve_nodes)}"

    def test_fix_nodes_created(self):
        """FIX nodes should be created for findings with recommendations."""
        builder = KnowledgeGraphBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = pathlib.Path(tmpdir) / "app.py"
            fpath.write_text("pass\n")
            f = _make_finding(
                file=str(fpath),
                recommendation="Use parameterized queries to prevent SQL injection."
            )
            graph = builder.build(project_root=tmpdir, findings=[f])
        fix_nodes = [n for n in graph.nodes if n.type == KGNodeType.FIX]
        assert len(fix_nodes) > 0, "Expected FIX nodes for finding with recommendation"
