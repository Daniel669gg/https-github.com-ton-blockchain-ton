"""
backend/analysis/intel_layer.py — Security Intelligence Layer integration.

Ties together:
  CPG → Dataflow → Reachability → Verification → Attack Graph → Knowledge Graph

Single entry point for Phase 2 security intelligence.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("tythanai.intel_layer")

# ---------------------------------------------------------------------------
# Optional imports — handle gracefully if a component is not yet present
# ---------------------------------------------------------------------------

try:
    from backend.analysis.knowledge_graph import (
        SecurityKnowledgeGraph,
        KnowledgeGraphBuilder,
        KGNodeType,
    )
    _HAS_KG = True
except ImportError as _kg_err:
    logger.debug("knowledge_graph not available: %s", _kg_err)
    SecurityKnowledgeGraph = None  # type: ignore[assignment,misc]
    KnowledgeGraphBuilder = None   # type: ignore[assignment,misc]
    KGNodeType = None              # type: ignore[assignment,misc]
    _HAS_KG = False

try:
    from backend.analysis.attack_graph import AttackGraphBuilder, ScoredAttackPath
    _HAS_ATTACK = True
except ImportError as _ag_err:
    logger.debug("attack_graph not available: %s", _ag_err)
    AttackGraphBuilder = None   # type: ignore[assignment,misc]
    ScoredAttackPath = None     # type: ignore[assignment,misc]
    _HAS_ATTACK = False

try:
    from backend.core.cpg.query_engine import CPGQueryEngine, SecurityQueryLanguage
    _HAS_SQL = True
except ImportError as _sql_err:
    logger.debug("query_engine not available: %s", _sql_err)
    CPGQueryEngine = None          # type: ignore[assignment,misc]
    SecurityQueryLanguage = None   # type: ignore[assignment,misc]
    _HAS_SQL = False

try:
    from backend.analysis.graph_enrichment import GraphEnrichmentPipeline
    _HAS_ENRICHMENT = True
except ImportError as _enrich_err:
    logger.debug("graph_enrichment not available: %s", _enrich_err)
    GraphEnrichmentPipeline = None  # type: ignore[assignment,misc]
    _HAS_ENRICHMENT = False

try:
    from backend.analysis.security_reasoning import SecurityReasoningEngine
    _HAS_REASONING = True
except ImportError as _reason_err:
    logger.debug("security_reasoning not available: %s", _reason_err)
    SecurityReasoningEngine = None  # type: ignore[assignment,misc]
    _HAS_REASONING = False


# ---------------------------------------------------------------------------
# Report dataclass
# ---------------------------------------------------------------------------

@dataclass
class IntelReport:
    """
    Unified output of the Phase 2 Security Intelligence Layer analysis pipeline.
    """

    # Knowledge Graph statistics
    kg_nodes: int = 0
    kg_edges: int = 0
    kg_risk_surface: Dict[str, Any] = field(default_factory=dict)

    # Attack Graph results
    top_attack_paths: List[Any] = field(default_factory=list)    # List[ScoredAttackPath] or paths
    top_exploit_chains: List[Any] = field(default_factory=list)
    top_reachable_risks: List[Any] = field(default_factory=list)
    attack_risk_score: float = 0.0

    # Security query results
    query_results: Dict[str, Any] = field(default_factory=dict)  # query_str → QueryResult

    # Automated reasoning reports
    reasoning_reports: List[Any] = field(default_factory=list)   # List[ReasoningReport]

    # Metadata
    findings_count: int = 0
    analysis_time_ms: float = 0.0
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the report to a plain dict."""
        return {
            "kg_nodes":            self.kg_nodes,
            "kg_edges":            self.kg_edges,
            "kg_risk_surface":     self.kg_risk_surface,
            "top_attack_paths":    _serialise_list(self.top_attack_paths),
            "top_exploit_chains":  _serialise_list(self.top_exploit_chains),
            "top_reachable_risks": _serialise_list(self.top_reachable_risks),
            "attack_risk_score":   self.attack_risk_score,
            "query_results":       {
                k: (v.to_dict() if hasattr(v, "to_dict") else v)
                for k, v in self.query_results.items()
            },
            "reasoning_reports":   _serialise_list(self.reasoning_reports),
            "findings_count":      self.findings_count,
            "analysis_time_ms":    self.analysis_time_ms,
            "timestamp":           self.timestamp,
        }


def _serialise_list(items: List[Any]) -> List[Any]:
    """Best-effort serialisation of a heterogeneous list."""
    out = []
    for item in items:
        if hasattr(item, "to_dict"):
            out.append(item.to_dict())
        elif hasattr(item, "__dict__"):
            out.append(item.__dict__)
        else:
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# SecurityIntelligenceLayer
# ---------------------------------------------------------------------------

class SecurityIntelligenceLayer:
    """
    Phase 2 unified Security Intelligence Layer.

    Orchestrates:
    - Knowledge Graph enrichment from all sources
    - Attack path ranking and scoring
    - Security query execution
    - Automated finding reasoning
    """

    def __init__(self) -> None:
        self._kg_builder:     Optional[Any] = KnowledgeGraphBuilder()   if _HAS_KG       else None
        self._attack_builder: Optional[Any] = AttackGraphBuilder()      if _HAS_ATTACK   else None
        # GraphEnrichmentPipeline requires a graph argument — instantiated lazily
        self._enrichment:     Optional[Any] = None
        self._reasoning:      Optional[Any] = SecurityReasoningEngine() if _HAS_REASONING else None

        # CPG-specific components (initialised lazily when a CPG is provided)
        self._query_engine:   Optional[Any] = None  # CPGQueryEngine
        self._sql:            Optional[Any] = None  # SecurityQueryLanguage

        # Cached knowledge graph from the most recent analyze() call
        self._current_kg:     Optional[Any] = None  # SecurityKnowledgeGraph

    # ------------------------------------------------------------------
    # Primary analysis entry point
    # ------------------------------------------------------------------

    def analyze(
        self,
        findings: List[Any],
        source_files: Optional[Dict[str, str]] = None,
        cpg: Optional[Any] = None,
        reachability_result: Optional[Any] = None,
        dep_result: Optional[Any] = None,
        queries: Optional[List[str]] = None,
    ) -> IntelReport:
        """
        Full Phase 2 analysis pipeline:

        1. Build/enrich Knowledge Graph from findings + CPG + deps
        2. Build Attack Graph, rank paths
        3. Execute security queries
        4. Generate reasoning for each finding
        5. Return IntelReport
        """
        t0 = time.monotonic()
        report = IntelReport(
            findings_count=len(findings),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # ── Step 1: Knowledge Graph ─────────────────────────────────────────────
        try:
            self._current_kg = self._build_knowledge_graph(
                findings=findings,
                source_files=source_files,
                cpg=cpg,
                dep_result=dep_result,
            )
            if self._current_kg is not None:
                report.kg_nodes = len(self._current_kg.nodes)
                report.kg_edges = len(self._current_kg.edges)
                if self._kg_builder is not None and _HAS_KG:
                    try:
                        report.kg_risk_surface = self._kg_builder.get_risk_surface(
                            self._current_kg
                        )
                    except Exception as _e:  # noqa: BLE001
                        logger.debug("get_risk_surface failed: %s", _e)
                        report.kg_risk_surface = {}
        except Exception as exc:  # noqa: BLE001
            logger.warning("Knowledge Graph build failed: %s", exc)

        # ── Step 2: Attack Graph ────────────────────────────────────────────────
        try:
            attack_paths, exploit_chains, reachable_risks, risk_score = (
                self._build_attack_graph(findings=findings, cpg=cpg)
            )
            report.top_attack_paths    = attack_paths
            report.top_exploit_chains  = exploit_chains
            report.top_reachable_risks = reachable_risks
            report.attack_risk_score   = risk_score
        except Exception as exc:  # noqa: BLE001
            logger.warning("Attack Graph build failed: %s", exc)

        # ── Step 3: Security queries ────────────────────────────────────────────
        if queries:
            try:
                report.query_results = self._run_queries(queries=queries, cpg=cpg)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Query execution failed: %s", exc)

        # ── Step 4: Reasoning ──────────────────────────────────────────────────
        try:
            report.reasoning_reports = self._generate_reasoning(findings=findings)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Reasoning engine failed: %s", exc)

        report.analysis_time_ms = (time.monotonic() - t0) * 1000.0
        return report

    # ------------------------------------------------------------------
    # Single query interface
    # ------------------------------------------------------------------

    def query(self, query_str: str, cpg: Optional[Any] = None) -> Any:
        """Execute a single security query. Returns QueryResult."""
        if not _HAS_SQL:
            logger.warning("SecurityQueryLanguage is not available.")
            return None

        sql = self._get_sql(cpg=cpg)
        if sql is None:
            logger.warning("Cannot execute query: no CPG or SecurityQueryLanguage available.")
            return None

        return sql.execute(query_str)

    # ------------------------------------------------------------------
    # Knowledge Graph access / export
    # ------------------------------------------------------------------

    def get_knowledge_graph(self) -> Optional[Any]:
        """Return current SecurityKnowledgeGraph (or None if not built)."""
        return self._current_kg

    def export_graph(self, format: str = "json") -> str:
        """
        Export the current knowledge graph.

        Formats: json, graphml, cypher, html
        """
        if self._current_kg is None or self._kg_builder is None:
            return "{}"

        fmt = format.lower()
        try:
            if fmt == "graphml":
                return self._kg_builder.to_graphml(self._current_kg)
            elif fmt == "cypher":
                return self._kg_builder.to_cypher(self._current_kg)
            elif fmt == "html":
                # Fall back to JSON inside an HTML scaffold if no dedicated method
                if hasattr(self._kg_builder, "to_html"):
                    return self._kg_builder.to_html(self._current_kg)
                json_data = self._kg_builder.to_json(self._current_kg) \
                    if hasattr(self._kg_builder, "to_json") else "{}"
                return (
                    f"<!DOCTYPE html><html><body>"
                    f"<pre>{json_data}</pre>"
                    f"</body></html>"
                )
            else:
                # json (default)
                if hasattr(self._kg_builder, "to_json"):
                    return self._kg_builder.to_json(self._current_kg)
                import json
                return json.dumps(self._current_kg.dict() if hasattr(self._current_kg, "dict") else {})
        except Exception as exc:  # noqa: BLE001
            logger.warning("Graph export failed (format=%s): %s", format, exc)
            return "{}"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_knowledge_graph(
        self,
        findings: List[Any],
        source_files: Optional[Dict[str, str]],
        cpg: Optional[Any],
        dep_result: Optional[Any],
    ) -> Optional[Any]:
        """Build and optionally enrich a SecurityKnowledgeGraph."""
        if not _HAS_KG or self._kg_builder is None:
            return None

        project_root = ""
        if source_files:
            # Infer project root from the first file path
            import os
            first_path = next(iter(source_files), "")
            project_root = os.path.dirname(first_path) if first_path else ""

        cve_records: Optional[List[Any]] = None
        if dep_result is not None:
            # dep_result may carry CVE records; duck-type access
            cve_records = getattr(dep_result, "cve_records", None) or getattr(dep_result, "cves", None)

        kg = self._kg_builder.build(
            project_root=project_root,
            findings=findings,
            cve_records=cve_records,
        )

        # Optional: run enrichment pipeline if available
        if _HAS_ENRICHMENT and GraphEnrichmentPipeline is not None:
            try:
                enricher = GraphEnrichmentPipeline(kg)
                kg = enricher.enrich() if hasattr(enricher, "enrich") else kg
            except Exception as _e:  # noqa: BLE001
                logger.debug("Graph enrichment skipped: %s", _e)

        return kg

    def _build_attack_graph(
        self,
        findings: List[Any],
        cpg: Optional[Any],
    ):
        """Build attack graph, returning (attack_paths, exploit_chains, reachable_risks, risk_score)."""
        if not _HAS_ATTACK or self._attack_builder is None:
            return [], [], [], 0.0

        # Gather entry points from CPG if available
        entry_points: List[Any] = []
        if cpg is not None:
            entry_points = getattr(cpg, "entry_points", [])

        # Build primary attack graph
        attack_graph = self._attack_builder.build(
            findings=findings,
            entrypoints=entry_points,
        )

        # Find critical paths (top 10)
        critical_paths = self._attack_builder.find_critical_paths(
            attack_graph, max_paths=10
        )

        # Build exploit chains
        exploit_chain_graph = self._attack_builder.build_exploit_chain(
            findings=findings,
            entry_points=entry_points,
        )
        exploit_critical = self._attack_builder.find_critical_paths(
            exploit_chain_graph, max_paths=5
        )

        # Reachable risks: highest-scoring vulnerability nodes
        reachable_risks = self._extract_reachable_risks(attack_graph, findings)

        # Overall risk score
        risk_score = 0.0
        try:
            risk_score = self._attack_builder.compute_risk_score(attack_graph)
        except Exception as _e:  # noqa: BLE001
            logger.debug("compute_risk_score failed: %s", _e)
            # Fallback: average of per-finding confidences
            if findings:
                risk_score = sum(
                    getattr(f, "confidence", 0.5) for f in findings
                ) / len(findings)

        return critical_paths, exploit_critical, reachable_risks, risk_score

    def _extract_reachable_risks(
        self,
        attack_graph: Any,
        findings: List[Any],
    ) -> List[Any]:
        """Extract the top reachable risk nodes from an AttackGraph."""
        if attack_graph is None:
            return []

        try:
            # Nodes of type VULNERABILITY or EXPLOIT, ranked by risk
            from backend.analysis.attack_graph import NodeType
            risky_nodes = [
                n for n in attack_graph.nodes
                if getattr(n, "type", None) in (NodeType.VULNERABILITY, NodeType.EXPLOIT)
            ]
            # Sort by risk_score property descending
            risky_nodes.sort(
                key=lambda n: n.properties.get("risk_score", 0.0),
                reverse=True,
            )
            return risky_nodes[:10]
        except Exception as _e:  # noqa: BLE001
            logger.debug("_extract_reachable_risks failed: %s", _e)
            return []

    def _get_sql(self, cpg: Optional[Any] = None) -> Optional[Any]:
        """Return or create a SecurityQueryLanguage instance for the given CPG."""
        if not _HAS_SQL:
            return None

        if cpg is None:
            # Use a minimal empty CPG if none supplied
            try:
                from backend.core.cpg.graph import CodePropertyGraph
                cpg = CodePropertyGraph()
            except ImportError:
                return None

        # Create or update the cached SQL instance
        if self._sql is None or getattr(self._sql, "cpg", None) is not cpg:
            try:
                self._query_engine = CPGQueryEngine(cpg)
                self._sql = SecurityQueryLanguage(cpg, query_engine=self._query_engine)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not create SecurityQueryLanguage: %s", exc)
                return None

        return self._sql

    def _run_queries(
        self,
        queries: List[str],
        cpg: Optional[Any],
    ) -> Dict[str, Any]:
        """Execute a list of security queries and return a dict of results."""
        sql = self._get_sql(cpg=cpg)
        if sql is None:
            return {}

        results: Dict[str, Any] = {}
        for q in queries:
            try:
                result = sql.execute(q)
                results[q] = result
            except Exception as exc:  # noqa: BLE001
                logger.warning("Query '%s' failed: %s", q, exc)
                results[q] = {"error": str(exc)}

        return results

    def _generate_reasoning(self, findings: List[Any]) -> List[Any]:
        """Generate automated reasoning reports for each finding."""
        if not _HAS_REASONING or self._reasoning is None:
            return []

        reports = []
        for finding in findings:
            try:
                report = self._reasoning.reason(finding)
                if report is not None:
                    reports.append(report)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Reasoning failed for finding %s: %s", getattr(finding, "rule_id", "?"), exc)

        return reports
