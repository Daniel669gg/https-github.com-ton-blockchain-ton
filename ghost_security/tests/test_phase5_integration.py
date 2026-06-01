"""
tests/test_phase5_integration.py — Phase 5 full integration tests.
25 tests: corpus → pattern extraction → rule proposal → KG nodes → SGL queries.
"""
import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import json
import pytest
from backend.core.knowledge.security_corpus import (
    SecurityCorpus, CorpusEntryType, VerificationStatus,
)
from backend.core.knowledge.ingestion_pipeline import CorpusIngestionPipeline, IngestionResult
from backend.core.knowledge.pattern_extractor import (
    PatternExtractor, PatternType, ExtractedPattern,
)
from backend.core.knowledge.rule_proposer import (
    CorpusRuleProposer, RuleProposalStatus, ProposedRuleFromCorpus,
)
from backend.analysis.knowledge_graph import (
    SecurityKnowledgeGraph, KnowledgeGraphBuilder, KGNodeType, KGNode, KGEdge,
)
from backend.core.cpg.query_engine import SecurityQueryLanguage
from backend.core.cpg.graph import CodePropertyGraph


# ─────────────────────────────────────────────────────────────────────────────
# Full corpus pipeline
# ─────────────────────────────────────────────────────────────────────────────

class TestFullCorpusPipeline:
    def _make_corpus(self) -> SecurityCorpus:
        corpus = SecurityCorpus()
        pipeline = CorpusIngestionPipeline(corpus)
        pipeline.run_full_ingestion()
        return corpus

    def test_corpus_builds_with_embedded_data(self):
        corpus = self._make_corpus()
        assert corpus.size > 0

    def test_corpus_has_cwe_entries(self):
        corpus = self._make_corpus()
        assert corpus.cwe_count > 0

    def test_corpus_has_capec_entries(self):
        corpus = self._make_corpus()
        assert corpus.capec_count > 0

    def test_corpus_cve_count_starts_zero(self):
        corpus = SecurityCorpus()
        assert corpus.cve_count == 0

    def test_ingest_then_extract_patterns(self):
        corpus = self._make_corpus()
        extractor = PatternExtractor()
        result = extractor.extract_all(corpus)
        assert result is not None

    def test_patterns_exist_after_extraction(self):
        corpus = self._make_corpus()
        extractor = PatternExtractor()
        extractor.extract_all(corpus)
        patterns = extractor.get_all_patterns()
        assert len(patterns) > 0

    def test_patterns_lead_to_rule_proposal(self):
        corpus = self._make_corpus()
        extractor = PatternExtractor()
        extractor.extract_all(corpus)
        all_patterns = extractor.get_all_patterns()
        proposer = CorpusRuleProposer()
        if all_patterns:
            rule = proposer.propose_from_pattern(all_patterns[0])
            assert isinstance(rule, ProposedRuleFromCorpus)

    def test_pipeline_idempotent(self):
        corpus = SecurityCorpus()
        pipeline = CorpusIngestionPipeline(corpus)
        r1 = pipeline.run_full_ingestion()
        size_after_first = corpus.size
        pipeline.run_full_ingestion()
        assert corpus.size == size_after_first


# ─────────────────────────────────────────────────────────────────────────────
# Knowledge Graph Phase 5 node types
# ─────────────────────────────────────────────────────────────────────────────

class TestKGPhase5Nodes:
    def test_research_node_type_exists(self):
        assert hasattr(KGNodeType, "RESEARCH")
        assert KGNodeType.RESEARCH.value == "research"

    def test_advisory_node_type_exists(self):
        assert hasattr(KGNodeType, "ADVISORY")
        assert KGNodeType.ADVISORY.value == "advisory"

    def test_exploit_node_type_exists(self):
        assert hasattr(KGNodeType, "EXPLOIT")
        assert KGNodeType.EXPLOIT.value == "exploit"

    def test_remediation_pattern_node_type_exists(self):
        assert hasattr(KGNodeType, "REMEDIATION_PATTERN")

    def test_generated_rule_node_type_exists(self):
        assert hasattr(KGNodeType, "GENERATED_RULE")

    def test_add_research_node_to_kg(self):
        kg = SecurityKnowledgeGraph()
        builder = KnowledgeGraphBuilder()
        node = KGNode(
            node_id="research::cve-2021-44228",
            type=KGNodeType.RESEARCH,
            label="Log4Shell Research",
            properties={"cve_id": "CVE-2021-44228", "source": "NIST"},
        )
        nid = builder.add_node(kg, node)
        assert isinstance(nid, str)
        assert nid == "research::cve-2021-44228"

    def test_add_exploit_node_to_kg(self):
        kg = SecurityKnowledgeGraph()
        builder = KnowledgeGraphBuilder()
        node = KGNode(
            node_id="exploit::sqli-1",
            type=KGNodeType.EXPLOIT,
            label="SQLi Exploit",
            properties={"cwe_id": "CWE-89"},
        )
        nid = builder.add_node(kg, node)
        assert isinstance(nid, str)

    def test_phase5_relations_accepted(self):
        kg = SecurityKnowledgeGraph()
        builder = KnowledgeGraphBuilder()
        n1 = KGNode(node_id="research::1", type=KGNodeType.RESEARCH, label="R1", properties={})
        n2 = KGNode(node_id="cve::1", type=KGNodeType.CVE, label="CVE", properties={})
        builder.add_node(kg, n1)
        builder.add_node(kg, n2)
        for relation in ["DERIVED_FROM", "VALIDATED_BY", "MITIGATED_BY", "EXPLOITS_VIA", "DETECTS"]:
            edge = KGEdge(from_id="research::1", to_id="cve::1", relation=relation, weight=1.0)
            builder.add_edge(kg, edge)


# ─────────────────────────────────────────────────────────────────────────────
# Security Query Language Phase 5 queries
# ─────────────────────────────────────────────────────────────────────────────

class TestSGLPhase5Queries:
    def _sql(self):
        return SecurityQueryLanguage(CodePropertyGraph())

    def test_find_research_for_cve(self):
        result = self._sql().execute("find research_for_cve")
        assert result is not None

    def test_find_rules_for_cwe(self):
        result = self._sql().execute("find rules_for_cwe")
        assert result is not None

    def test_find_exploit_patterns(self):
        result = self._sql().execute("find exploit_patterns")
        assert result is not None

    def test_find_remediation_patterns(self):
        result = self._sql().execute("find remediation_patterns")
        assert result is not None

    def test_find_generated_rules(self):
        result = self._sql().execute("find generated_rules")
        assert result is not None

    def test_find_validated_rules(self):
        result = self._sql().execute("find validated_rules")
        assert result is not None

    def test_find_research_sources(self):
        result = self._sql().execute("find research_sources")
        assert result is not None

    def test_knowledge_query_has_explanation(self):
        result = self._sql().execute("find research_for_cve")
        assert hasattr(result, "explanation")
        assert len(result.explanation) > 0
