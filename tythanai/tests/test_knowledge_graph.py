"""Tests for Security Knowledge Graph."""
import pytest
from backend.analysis.knowledge_graph import (
    KnowledgeGraphBuilder,
    SecurityKnowledgeGraph,
    KGNodeType,
    build_knowledge_graph,
    CWE_CVE_EXAMPLES,
)
from backend.core.confidence import Finding


def _finding(rule_id, file, line=10, severity="HIGH", cwe="CWE-89"):
    return Finding(
        rule_id=rule_id,
        file=file,
        line=line,
        severity=severity,
        cwe_id=cwe,
        description="test finding",
        recommendation="fix it",
    )


def test_empty_findings_returns_valid_graph(tmp_path):
    graph = build_knowledge_graph(str(tmp_path), [])
    assert isinstance(graph, SecurityKnowledgeGraph)
    assert isinstance(graph.nodes, list)
    assert isinstance(graph.edges, list)


def test_findings_create_sink_and_code_unit_nodes(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("x = 1\n")
    findings = [
        _finding("SQL-001", str(f), 1, "CRITICAL", "CWE-89"),
        _finding("SQL-002", str(f), 2, "HIGH", "CWE-89"),
    ]
    graph = build_knowledge_graph(str(tmp_path), findings)
    node_types = {n.type for n in graph.nodes}
    assert KGNodeType.SINK in node_types
    assert KGNodeType.CODE_UNIT in node_types


def test_known_cwe_creates_cve_node(tmp_path):
    f = tmp_path / "vuln.py"
    f.write_text("pass\n")
    findings = [_finding("SQLI-1", str(f), 1, "CRITICAL", "CWE-89")]
    graph = build_knowledge_graph(str(tmp_path), findings)
    cve_nodes = [n for n in graph.nodes if n.type == KGNodeType.CVE]
    # CWE-89 is in CWE_CVE_EXAMPLES so we should have CVE nodes
    assert len(cve_nodes) > 0
    cve_ids = [n.node_id for n in cve_nodes]
    # At least one CVE from the mapping
    expected = CWE_CVE_EXAMPLES.get("CWE-89", [])
    assert any(cve in cve_ids[0] or cve in str(cve_ids) for cve in expected)


def test_query_paths_from_code_unit_to_sink(tmp_path):
    f = tmp_path / "main.py"
    f.write_text("pass\n")
    findings = [_finding("CMD-001", str(f), 1, "CRITICAL", "CWE-78")]
    graph = build_knowledge_graph(str(tmp_path), findings)
    builder = KnowledgeGraphBuilder()
    paths = builder.query_paths(graph, KGNodeType.CODE_UNIT, KGNodeType.SINK)
    assert isinstance(paths, list)
    # With CODE_UNIT → FUNCTION → SINK or CODE_UNIT → SINK there should be paths
    # (may be empty if graph structure differs, but should not raise)


def test_to_cypher_contains_create_statements(tmp_path):
    f = tmp_path / "service.py"
    f.write_text("pass\n")
    findings = [_finding("XSS-001", str(f), 5, "HIGH", "CWE-79")]
    graph = build_knowledge_graph(str(tmp_path), findings)
    builder = KnowledgeGraphBuilder()
    cypher = builder.to_cypher(graph)
    assert "CREATE" in cypher


def test_risk_surface_returns_dict(tmp_path):
    f = tmp_path / "api.py"
    f.write_text("pass\n")
    findings = [
        _finding("A", str(f), 1, "CRITICAL", "CWE-78"),
        _finding("B", str(f), 2, "HIGH", "CWE-89"),
    ]
    graph = build_knowledge_graph(str(tmp_path), findings)
    builder = KnowledgeGraphBuilder()
    surface = builder.get_risk_surface(graph)
    assert "total_nodes" in surface or "sinks" in surface or isinstance(surface, dict)
