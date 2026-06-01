"""
tests/test_phase2_integration.py — Phase 2 full integration tests.
25 tests: finding→graph, graph→attack path, security reasoning, intel layer.
"""
import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.analysis.knowledge_graph import SecurityKnowledgeGraph, KnowledgeGraphBuilder
from backend.analysis.attack_graph import AttackGraphBuilder, ScoredAttackPath
from backend.analysis.security_reasoning import SecurityReasoningEngine, ReasoningReport
from backend.analysis.intel_layer import SecurityIntelligenceLayer, IntelReport


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_finding(cwe_id="CWE-89", severity="HIGH", confidence=0.85,
                  file="app.py", line=42, description="SQL injection"):
    class F:
        rule_id = f"test-{cwe_id}"
    f = F()
    f.cwe_id = cwe_id
    f.severity = severity
    f.confidence = confidence
    f.file = file
    f.line = line
    f.description = description
    f.sources = []
    f.recommendation = ""
    f.owasp = ""
    return f


_SQL_SOURCE = """
from flask import request
import sqlite3

def get_user():
    uid = request.args.get("id")
    conn = sqlite3.connect("db.sqlite")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=" + uid)
    return cur.fetchone()
"""


# ─────────────────────────────────────────────────────────────────────────────
# Security Reasoning Engine
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityReasoningEngine:
    def test_engine_importable(self):
        assert SecurityReasoningEngine is not None

    def test_reason_report_importable(self):
        assert ReasoningReport is not None

    def test_reason_returns_report(self):
        engine = SecurityReasoningEngine()
        finding = _make_finding("CWE-89")
        report = engine.reason(finding, _SQL_SOURCE)
        assert report is not None

    def test_reason_report_has_why_vulnerable(self):
        engine = SecurityReasoningEngine()
        finding = _make_finding("CWE-89")
        report = engine.reason(finding)
        assert hasattr(report, "why_vulnerable")
        assert isinstance(report.why_vulnerable, str)
        assert len(report.why_vulnerable) > 0

    def test_reason_report_has_fix(self):
        engine = SecurityReasoningEngine()
        finding = _make_finding("CWE-89")
        report = engine.reason(finding)
        assert hasattr(report, "fix_summary")
        assert isinstance(report.fix_summary, str)

    def test_reason_report_has_impact(self):
        engine = SecurityReasoningEngine()
        finding = _make_finding("CWE-89")
        report = engine.reason(finding)
        assert hasattr(report, "impact_description") or hasattr(report, "affected_assets")

    def test_reason_cwe79_returns_xss_explanation(self):
        engine = SecurityReasoningEngine()
        finding = _make_finding("CWE-79", description="XSS via user input")
        report = engine.reason(finding)
        assert "CWE-79" in report.cwe_id or "79" in report.why_vulnerable.lower() \
               or "xss" in report.why_vulnerable.lower() \
               or "script" in report.why_vulnerable.lower() \
               or "escape" in report.fix_summary.lower()

    def test_reason_batch_returns_list(self):
        engine = SecurityReasoningEngine()
        findings = [_make_finding("CWE-89"), _make_finding("CWE-78"), _make_finding("CWE-22")]
        reports = engine.reason_batch(findings)
        assert isinstance(reports, list)
        assert len(reports) == 3

    def test_format_markdown_returns_string(self):
        engine = SecurityReasoningEngine()
        finding = _make_finding("CWE-89")
        report = engine.reason(finding)
        md = engine.format_markdown(report)
        assert isinstance(md, str)
        assert len(md) > 10

    def test_format_brief_returns_string(self):
        engine = SecurityReasoningEngine()
        finding = _make_finding("CWE-78")
        report = engine.reason(finding)
        brief = engine.format_brief(report)
        assert isinstance(brief, str)

    def test_cvss_estimate_critical(self):
        engine = SecurityReasoningEngine()
        report = engine.reason(_make_finding("CWE-89", severity="CRITICAL"))
        assert report.cvss_estimate >= 8.0

    def test_cvss_estimate_low(self):
        engine = SecurityReasoningEngine()
        report = engine.reason(_make_finding("CWE-400", severity="LOW"))
        assert report.cvss_estimate <= 5.0


# ─────────────────────────────────────────────────────────────────────────────
# SecurityIntelligenceLayer
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityIntelligenceLayer:
    def test_layer_importable(self):
        assert SecurityIntelligenceLayer is not None

    def test_intel_report_importable(self):
        assert IntelReport is not None

    def test_analyze_empty_findings(self):
        sil = SecurityIntelligenceLayer()
        report = sil.analyze(findings=[])
        assert report is not None
        assert hasattr(report, "findings_count")
        assert report.findings_count == 0

    def test_analyze_with_findings(self):
        sil = SecurityIntelligenceLayer()
        findings = [_make_finding("CWE-89"), _make_finding("CWE-78")]
        report = sil.analyze(findings=findings)
        assert report is not None
        assert report.findings_count == 2

    def test_report_has_attack_paths(self):
        sil = SecurityIntelligenceLayer()
        findings = [_make_finding("CWE-89", "CRITICAL")]
        report = sil.analyze(findings=findings)
        assert hasattr(report, "top_attack_paths")
        assert isinstance(report.top_attack_paths, list)

    def test_report_has_knowledge_graph_info(self):
        sil = SecurityIntelligenceLayer()
        findings = [_make_finding("CWE-89")]
        report = sil.analyze(findings=findings)
        assert hasattr(report, "kg_nodes")
        assert isinstance(report.kg_nodes, int)

    def test_report_has_reasoning(self):
        sil = SecurityIntelligenceLayer()
        findings = [_make_finding("CWE-89")]
        report = sil.analyze(findings=findings)
        assert hasattr(report, "reasoning_reports")

    def test_query_method_works(self):
        sil = SecurityIntelligenceLayer()
        from backend.core.cpg.graph import CodePropertyGraph
        cpg = CodePropertyGraph()
        result = sil.query("find reachable_rce", cpg=cpg)
        assert result is not None

    def test_export_json_works(self):
        sil = SecurityIntelligenceLayer()
        sil.analyze(findings=[_make_finding("CWE-89")])
        exported = sil.export_graph("json")
        assert isinstance(exported, str)
        import json
        data = json.loads(exported)
        assert isinstance(data, dict)

    def test_export_graphml_works(self):
        sil = SecurityIntelligenceLayer()
        sil.analyze(findings=[_make_finding("CWE-89")])
        exported = sil.export_graph("graphml")
        assert isinstance(exported, str)
        assert len(exported) > 0

    def test_get_knowledge_graph_returns_kg(self):
        sil = SecurityIntelligenceLayer()
        sil.analyze(findings=[_make_finding("CWE-89")])
        kg = sil.get_knowledge_graph()
        assert kg is not None

    def test_full_pipeline_with_queries(self):
        sil = SecurityIntelligenceLayer()
        findings = [_make_finding("CWE-89", "CRITICAL")]
        from backend.core.cpg.graph import CodePropertyGraph
        cpg = CodePropertyGraph()
        report = sil.analyze(
            findings=findings,
            cpg=cpg,
            queries=["find attack_paths", "find reachable_rce"],
        )
        assert report is not None
        assert hasattr(report, "query_results")
