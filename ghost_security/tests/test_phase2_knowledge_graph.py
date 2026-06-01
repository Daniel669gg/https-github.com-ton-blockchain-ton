"""
tests/test_phase2_knowledge_graph.py — Phase 2 Knowledge Graph 2.0 tests.
25 tests covering new node types, relations, finding ingestion, and export formats.
"""
import sys
import pathlib
import json

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.analysis.knowledge_graph import (
    SecurityKnowledgeGraph, KnowledgeGraphBuilder, KGNode, KGEdge, KGNodeType,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_finding(
    cwe_id="CWE-89", severity="HIGH", confidence=0.85,
    file="app.py", line=42, description="SQL injection",
):
    """Create a minimal finding-like object (duck-typed)."""
    class MockFinding:
        rule_id = f"test-{cwe_id}"
    f = MockFinding()
    f.cwe_id = cwe_id
    f.severity = severity
    f.confidence = confidence
    f.file = file
    f.line = line
    f.description = description
    # Attributes expected by KnowledgeGraphBuilder.build()
    f.sources = []
    f.recommendation = ""
    f.owasp = ""
    return f


def _make_builder(findings=None):
    return KnowledgeGraphBuilder(findings or [])


# ─────────────────────────────────────────────────────────────────────────────
# New node types (Phase 2)
# ─────────────────────────────────────────────────────────────────────────────

class TestNewNodeTypes:
    def test_source_node_type_exists(self):
        assert hasattr(KGNodeType, "SOURCE")

    def test_finding_node_type_exists(self):
        assert hasattr(KGNodeType, "FINDING")

    def test_verification_node_type_exists(self):
        assert hasattr(KGNodeType, "VERIFICATION")

    def test_endpoint_node_type_exists(self):
        assert hasattr(KGNodeType, "ENDPOINT") or hasattr(KGNodeType, "API_ROUTE")

    def test_dependency_node_type_exists(self):
        assert hasattr(KGNodeType, "DEPENDENCY") or hasattr(KGNodeType, "PACKAGE")

    def test_cwe_node_type_exists(self):
        assert hasattr(KGNodeType, "CWE_NODE") or hasattr(KGNodeType, "CWE")

    def test_asset_node_type_exists(self):
        assert hasattr(KGNodeType, "ASSET")

    def test_class_node_type_exists(self):
        assert hasattr(KGNodeType, "CLASS") or hasattr(KGNodeType, "METHOD")


# ─────────────────────────────────────────────────────────────────────────────
# Finding ingestion
# ─────────────────────────────────────────────────────────────────────────────

class TestFindingIngestion:
    def test_ingest_finding_returns_node_ids(self):
        builder = _make_builder()
        kg = SecurityKnowledgeGraph()
        finding = _make_finding()
        node_ids = builder.ingest_finding(kg, finding)
        assert isinstance(node_ids, list)
        assert len(node_ids) >= 1

    def test_ingest_finding_creates_finding_node(self):
        builder = _make_builder()
        kg = SecurityKnowledgeGraph()
        finding = _make_finding()
        node_ids = builder.ingest_finding(kg, finding)
        assert len(node_ids) >= 1 or len(kg.nodes) >= 1

    def test_ingest_finding_handles_multiple_findings(self):
        builder = _make_builder()
        kg = SecurityKnowledgeGraph()
        for cwe in ["CWE-89", "CWE-79", "CWE-78"]:
            ids = builder.ingest_finding(kg, _make_finding(cwe_id=cwe))
            assert isinstance(ids, list)

    def test_ingest_finding_no_crash_on_minimal_finding(self):
        builder = _make_builder()
        kg = SecurityKnowledgeGraph()
        finding = _make_finding(description="")
        ids = builder.ingest_finding(kg, finding)
        assert isinstance(ids, list)

    def test_build_with_findings_creates_nodes(self):
        findings = [_make_finding("CWE-89"), _make_finding("CWE-79")]
        builder = _make_builder(findings)
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            kg = builder.build(project_root=tmpdir, findings=findings)
        assert isinstance(kg, SecurityKnowledgeGraph)
        assert len(kg.nodes) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Node and edge creation
# ─────────────────────────────────────────────────────────────────────────────

class TestNodeEdgeCreation:
    def test_add_node_returns_id(self):
        builder = _make_builder()
        kg = SecurityKnowledgeGraph()
        node = KGNode(node_id="func1", type=KGNodeType.FUNCTION, label="my_func", properties={"file": "app.py"})
        node_id = builder.add_node(kg, node)
        assert isinstance(node_id, str)
        assert len(node_id) > 0

    def test_add_duplicate_node_returns_same_id(self):
        builder = _make_builder()
        kg = SecurityKnowledgeGraph()
        node = KGNode(node_id="func1", type=KGNodeType.FUNCTION, label="my_func", properties={})
        id1 = builder.add_node(kg, node)
        id2 = builder.add_node(kg, node)
        assert id1 == id2

    def test_add_edge_creates_relation(self):
        builder = _make_builder()
        kg = SecurityKnowledgeGraph()
        src_node = KGNode(node_id="src1", type=KGNodeType.SOURCE, label="user_input", properties={})
        sink_node = KGNode(node_id="sink1", type=KGNodeType.SINK, label="db_query", properties={})
        builder.add_node(kg, src_node)
        builder.add_node(kg, sink_node)
        edge = KGEdge(from_id="src1", to_id="sink1", relation="FLOWS_TO", weight=1.0)
        builder.add_edge(kg, edge)
        edges = [e for e in kg.edges if e.from_id == "src1" and e.to_id == "sink1"]
        assert len(edges) >= 1

    def test_new_relation_types_accepted(self):
        builder = _make_builder()
        kg = SecurityKnowledgeGraph()
        n1 = KGNode(node_id="n1", type=KGNodeType.FUNCTION, label="handler", properties={})
        n2 = KGNode(node_id="n2", type=KGNodeType.SINK, label="query", properties={})
        builder.add_node(kg, n1)
        builder.add_node(kg, n2)
        for relation in ["PROPAGATES_TO", "REACHES", "VULNERABLE_TO", "EXPLOITABLE_VIA"]:
            edge = KGEdge(from_id="n1", to_id="n2", relation=relation, weight=1.0)
            builder.add_edge(kg, edge)
        # No exception = pass


# ─────────────────────────────────────────────────────────────────────────────
# Graph enrichment
# ─────────────────────────────────────────────────────────────────────────────

class TestGraphEnrichment:
    def test_enrichment_pipeline_importable(self):
        from backend.analysis.graph_enrichment import GraphEnrichmentPipeline
        assert GraphEnrichmentPipeline is not None

    def test_enrichment_pipeline_accepts_kg(self):
        from backend.analysis.graph_enrichment import GraphEnrichmentPipeline
        kg = SecurityKnowledgeGraph()
        pipeline = GraphEnrichmentPipeline(kg)
        assert pipeline is not None

    def test_enrich_from_findings_no_crash(self):
        from backend.analysis.graph_enrichment import GraphEnrichmentPipeline
        kg = SecurityKnowledgeGraph()
        pipeline = GraphEnrichmentPipeline(kg)
        findings = [_make_finding("CWE-89"), _make_finding("CWE-78")]
        result = pipeline.enrich_from_findings(findings)
        assert result is not None
        assert hasattr(result, "nodes_added") or hasattr(result, "edges_added")

    def test_run_full_pipeline_with_empty_inputs(self):
        from backend.analysis.graph_enrichment import GraphEnrichmentPipeline
        kg = SecurityKnowledgeGraph()
        pipeline = GraphEnrichmentPipeline(kg)
        result = pipeline.run_full_pipeline()
        assert result is not None


# ─────────────────────────────────────────────────────────────────────────────
# Export formats
# ─────────────────────────────────────────────────────────────────────────────

class TestExportFormats:
    @staticmethod
    def _built_builder_and_kg():
        import tempfile
        findings = [_make_finding()]
        builder = _make_builder(findings)
        with tempfile.TemporaryDirectory() as tmpdir:
            kg = builder.build(project_root=tmpdir, findings=findings)
        return builder, kg

    def test_to_json_still_works(self):
        builder, kg = self._built_builder_and_kg()
        j = builder.to_json(kg)
        data = json.loads(j)
        assert "nodes" in data or "edges" in data

    def test_to_graphml_returns_xml(self):
        builder, kg = self._built_builder_and_kg()
        graphml = builder.to_graphml(kg)
        assert isinstance(graphml, str)
        assert "graphml" in graphml.lower() or "<graph" in graphml

    def test_to_html_returns_html_string(self):
        builder, kg = self._built_builder_and_kg()
        html = builder.to_html(kg)
        assert isinstance(html, str)
        assert "<html" in html.lower() or "<!DOCTYPE" in html.lower() or "vis" in html.lower()

    def test_to_cypher_still_works(self):
        builder, kg = self._built_builder_and_kg()
        cypher = builder.to_cypher(kg)
        assert isinstance(cypher, str)
        assert "CREATE" in cypher

    def test_risk_surface_has_new_counts(self):
        import tempfile
        findings = [_make_finding("CWE-89"), _make_finding("CWE-79")]
        builder = _make_builder(findings)
        with tempfile.TemporaryDirectory() as tmpdir:
            kg = builder.build(project_root=tmpdir, findings=findings)
        surface = builder.get_risk_surface(kg)
        assert isinstance(surface, dict)
        assert "total_nodes" in surface
