"""
backend/analysis/graph_enrichment.py — Graph Enrichment Pipeline.

Automatically enriches the SecurityKnowledgeGraph by pulling data from:
- CPG (Code Property Graph) nodes and edges
- Dataflow analysis results
- Reachability analysis results
- Verification reports
- Dependency taint analysis

Does NOT recreate any of these components — imports and reads from them.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, List, Optional

from backend.analysis.knowledge_graph import (
    KGEdge,
    KGNode,
    KGNodeType,
    KnowledgeGraphBuilder,
    SecurityKnowledgeGraph,
)

# CPG types — imported for type annotations but used defensively so the module
# remains importable even if cpg.graph is refactored.
try:
    from backend.core.cpg.graph import (
        CodePropertyGraph,
        CPGEdgeType,
        CPGNodeType,
    )
except ImportError:  # pragma: no cover
    CodePropertyGraph = Any  # type: ignore[assignment,misc]
    CPGNodeType = None  # type: ignore[assignment]
    CPGEdgeType = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class EnrichmentResult:
    """Summary of a single enrichment pass."""

    nodes_added: int = 0
    edges_added: int = 0
    sources: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    elapsed_ms: float = 0.0

    # ------------------------------------------------------------------
    # Convenience: merge another result into this one
    # ------------------------------------------------------------------
    def merge(self, other: "EnrichmentResult") -> None:
        self.nodes_added += other.nodes_added
        self.edges_added += other.edges_added
        self.sources.extend(other.sources)
        self.errors.extend(other.errors)
        self.elapsed_ms += other.elapsed_ms


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


class GraphEnrichmentPipeline:
    """
    Enriches a SecurityKnowledgeGraph by ingesting data from multiple analysis
    sources (CPG, findings, reachability, dependency taint).

    Each ``enrich_from_*`` method is idempotent — running it twice produces
    no duplicate nodes or edges because ``KnowledgeGraphBuilder.add_node`` and
    ``add_edge`` silently skip duplicates.
    """

    def __init__(self, graph: SecurityKnowledgeGraph) -> None:
        self._graph = graph
        self._builder = KnowledgeGraphBuilder()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _node_count(self) -> int:
        return len(self._graph.nodes)

    def _edge_count(self) -> int:
        return len(self._graph.edges)

    # ------------------------------------------------------------------
    # CPG enrichment
    # ------------------------------------------------------------------

    def enrich_from_cpg(self, cpg: Any) -> EnrichmentResult:
        """
        Add CPG nodes into the KnowledgeGraph.

        - DFG_DEF nodes  → SOURCE nodes (taint definition sites)
        - DFG_USE nodes  → SINK nodes   (taint use / sink sites)
        - CG_CALL edges  → CALLS relations between FUNCTION nodes
        """
        start = time.monotonic()
        n0, e0 = self._node_count(), self._edge_count()
        errors: List[str] = []

        try:
            # Iterate CPG nodes
            cpg_nodes = getattr(cpg, "nodes", {})
            if isinstance(cpg_nodes, dict):
                node_iter = cpg_nodes.values()
            else:
                node_iter = list(cpg_nodes)

            for cpg_node in node_iter:
                try:
                    node_type_val = getattr(
                        getattr(cpg_node, "node_type", None), "value", None
                    )
                    nid_raw = getattr(cpg_node, "node_id", None)
                    if nid_raw is None:
                        continue
                    code = getattr(cpg_node, "code", "") or ""
                    fpath = getattr(cpg_node, "file", "") or ""
                    line = getattr(cpg_node, "line", 0) or 0

                    if node_type_val == "DFG_DEF":
                        kg_node = KGNode(
                            node_id=f"source::cpg::{nid_raw}",
                            type=KGNodeType.SOURCE,
                            label=code[:64] or f"def@{line}",
                            properties={
                                "cpg_node_id": str(nid_raw),
                                "file": fpath,
                                "line": line,
                                "code": code[:256],
                            },
                        )
                        self._builder.add_node(self._graph, kg_node)

                    elif node_type_val == "DFG_USE":
                        kg_node = KGNode(
                            node_id=f"sink::cpg::{nid_raw}",
                            type=KGNodeType.SINK,
                            label=code[:64] or f"use@{line}",
                            properties={
                                "cpg_node_id": str(nid_raw),
                                "file": fpath,
                                "line": line,
                                "code": code[:256],
                            },
                        )
                        self._builder.add_node(self._graph, kg_node)

                except Exception as exc:  # noqa: BLE001
                    errors.append(f"cpg_node error: {exc}")

            # Iterate CPG edges
            cpg_edges = getattr(cpg, "edges", {})
            if isinstance(cpg_edges, dict):
                edge_iter = cpg_edges.values()
            else:
                edge_iter = list(cpg_edges)

            for cpg_edge in edge_iter:
                try:
                    edge_type_val = getattr(
                        getattr(cpg_edge, "edge_type", None), "value", None
                    )
                    if edge_type_val != "CG_CALL":
                        continue
                    from_id = getattr(cpg_edge, "from_id", None)
                    to_id = getattr(cpg_edge, "to_id", None)
                    if from_id is None or to_id is None:
                        continue

                    # Map CPG call-site nodes to KG FUNCTION nodes using
                    # the cpg_node_id property we stored above.
                    kg_from = f"source::cpg::{from_id}"
                    kg_to = f"sink::cpg::{to_id}"

                    # Only add edge if both endpoints already exist in the KG
                    if (
                        kg_from in self._graph.node_index
                        and kg_to in self._graph.node_index
                    ):
                        self._builder.add_edge(
                            self._graph,
                            KGEdge(from_id=kg_from, to_id=kg_to, relation="CALLS"),
                        )

                except Exception as exc:  # noqa: BLE001
                    errors.append(f"cpg_edge error: {exc}")

        except Exception as exc:  # noqa: BLE001
            errors.append(f"enrich_from_cpg: {exc}")

        elapsed_ms = (time.monotonic() - start) * 1000
        return EnrichmentResult(
            nodes_added=self._node_count() - n0,
            edges_added=self._edge_count() - e0,
            sources=["cpg"],
            errors=errors,
            elapsed_ms=elapsed_ms,
        )

    # ------------------------------------------------------------------
    # Findings enrichment
    # ------------------------------------------------------------------

    def enrich_from_findings(self, findings: List[Any]) -> EnrichmentResult:
        """
        Call ``ingest_finding()`` for every finding in the list.

        Builds the full chain per finding:
            Source → Function → TaintFlow → Sink → Vulnerability → CVE
        """
        start = time.monotonic()
        n0, e0 = self._node_count(), self._edge_count()
        errors: List[str] = []

        for finding in findings:
            try:
                # ingest_finding creates FINDING, CWE_NODE, SOURCE, SINK + edges
                self._builder.ingest_finding(self._graph, finding)

                # Additional chain: link SOURCE → FUNCTION if we can locate one
                fpath = getattr(finding, "file", "") or ""
                line = getattr(finding, "line", 0) or 0
                rule_id = getattr(finding, "rule_id", "") or ""
                cwe_id = getattr(finding, "cwe_id", "") or ""

                # Link SOURCE → existing CODE_UNIT if present
                source_nid = f"source::{fpath}::{line}"
                code_unit_nid = f"code_unit::{fpath}"
                if (
                    code_unit_nid in self._graph.node_index
                    and source_nid in self._graph.node_index
                ):
                    self._builder.add_edge(
                        self._graph,
                        KGEdge(
                            from_id=code_unit_nid,
                            to_id=source_nid,
                            relation="CONTAINS",
                        ),
                    )

                # SINK → CVE via CWE_CVE_EXAMPLES mapping
                from backend.analysis.knowledge_graph import CWE_CVE_EXAMPLES

                if cwe_id and cwe_id in CWE_CVE_EXAMPLES:
                    sink_nid = f"sink::{rule_id}::{fpath}::{line}"
                    for cve_id in CWE_CVE_EXAMPLES[cwe_id]:
                        cve_nid = f"cve::{cve_id}"
                        if cve_nid not in self._graph.node_index:
                            self._builder.add_node(
                                self._graph,
                                KGNode(
                                    node_id=cve_nid,
                                    type=KGNodeType.CVE,
                                    label=cve_id,
                                    properties={"cve_id": cve_id, "cwe_id": cwe_id},
                                ),
                            )
                        if sink_nid in self._graph.node_index:
                            self._builder.add_edge(
                                self._graph,
                                KGEdge(
                                    from_id=sink_nid,
                                    to_id=cve_nid,
                                    relation="EXPLOITS",
                                ),
                            )

            except Exception as exc:  # noqa: BLE001
                errors.append(f"finding error: {exc}")

        elapsed_ms = (time.monotonic() - start) * 1000
        return EnrichmentResult(
            nodes_added=self._node_count() - n0,
            edges_added=self._edge_count() - e0,
            sources=["findings"],
            errors=errors,
            elapsed_ms=elapsed_ms,
        )

    # ------------------------------------------------------------------
    # Reachability enrichment
    # ------------------------------------------------------------------

    def enrich_from_reachability(self, reach_result: Any) -> EnrichmentResult:
        """
        Add ENDPOINT nodes and REACHES edges from a reachability analysis result.

        Accepts:
        - A list of ``AttackPath`` objects (from ``ReachabilityAnalyzer``), or
        - Any object with an ``attack_paths`` attribute containing a list of such objects.
        """
        start = time.monotonic()
        n0, e0 = self._node_count(), self._edge_count()
        errors: List[str] = []

        # Normalise: accept a bare list or an object with .attack_paths
        if isinstance(reach_result, list):
            attack_paths = reach_result
        else:
            attack_paths = getattr(reach_result, "attack_paths", []) or []

        for ap in attack_paths:
            try:
                entry = getattr(ap, "entry", None)
                if entry is None:
                    continue

                # --- ENDPOINT node for the entry-point ---
                ep_file = getattr(entry, "file", "") or ""
                ep_line = getattr(entry, "line", 0) or 0
                ep_name = getattr(entry, "name", "") or ""
                ep_path = getattr(entry, "path", "") or ""
                ep_type = getattr(entry, "type", "HTTP_ROUTE") or "HTTP_ROUTE"
                ep_method = getattr(entry, "method", "") or ""

                endpoint_nid = f"endpoint::{ep_file}::{ep_line}::{ep_name}"
                endpoint_node = KGNode(
                    node_id=endpoint_nid,
                    type=KGNodeType.ENDPOINT,
                    label=ep_path or ep_name or f"endpoint@{ep_line}",
                    properties={
                        "file": ep_file,
                        "line": ep_line,
                        "name": ep_name,
                        "path": ep_path,
                        "entry_type": ep_type,
                        "http_method": ep_method,
                    },
                )
                self._builder.add_node(self._graph, endpoint_node)

                # --- API_ROUTE node (HTTP routes only) ---
                if ep_path:
                    route_nid = f"api_route::{ep_method}::{ep_path}"
                    route_node = KGNode(
                        node_id=route_nid,
                        type=KGNodeType.API_ROUTE,
                        label=f"{ep_method} {ep_path}".strip(),
                        properties={"method": ep_method, "path": ep_path},
                    )
                    self._builder.add_node(self._graph, route_node)
                    self._builder.add_edge(
                        self._graph,
                        KGEdge(
                            from_id=endpoint_nid,
                            to_id=route_nid,
                            relation="EXPOSED_THROUGH",
                        ),
                    )

                # --- REACHES edge: ENDPOINT → SINK ---
                sink_file = getattr(ap, "sink_file", "") or ""
                sink_line = getattr(ap, "sink_line", 0) or 0
                sink_type = getattr(ap, "sink_type", "") or ""
                r_score = getattr(ap, "reachability_score", 1.0) or 1.0

                # Look for an existing SINK node matching this location
                # (created earlier by ingest_finding)
                matching_sinks = [
                    n.node_id
                    for n in self._graph.nodes
                    if n.type == KGNodeType.SINK
                    and n.properties.get("file") == sink_file
                    and n.properties.get("line") == sink_line
                ]
                if not matching_sinks:
                    # Create a minimal SINK if not yet present
                    sink_nid = f"sink::reach::{sink_file}::{sink_line}"
                    self._builder.add_node(
                        self._graph,
                        KGNode(
                            node_id=sink_nid,
                            type=KGNodeType.SINK,
                            label=sink_type or f"sink@{sink_line}",
                            properties={
                                "file": sink_file,
                                "line": sink_line,
                                "sink_type": sink_type,
                            },
                        ),
                    )
                    matching_sinks = [sink_nid]

                for sink_nid in matching_sinks:
                    self._builder.add_edge(
                        self._graph,
                        KGEdge(
                            from_id=endpoint_nid,
                            to_id=sink_nid,
                            relation="REACHES",
                            weight=r_score,
                        ),
                    )

                # Link CWE nodes from the attack path
                for cwe_id in getattr(ap, "cwe_ids", []):
                    cwe_nid = f"cwe::{cwe_id}"
                    if cwe_nid not in self._graph.node_index:
                        self._builder.add_node(
                            self._graph,
                            KGNode(
                                node_id=cwe_nid,
                                type=KGNodeType.CWE_NODE,
                                label=cwe_id,
                                properties={"cwe_id": cwe_id},
                            ),
                        )
                    for sink_nid in matching_sinks:
                        self._builder.add_edge(
                            self._graph,
                            KGEdge(
                                from_id=sink_nid,
                                to_id=cwe_nid,
                                relation="VULNERABLE_TO",
                            ),
                        )

            except Exception as exc:  # noqa: BLE001
                errors.append(f"reach_path error: {exc}")

        elapsed_ms = (time.monotonic() - start) * 1000
        return EnrichmentResult(
            nodes_added=self._node_count() - n0,
            edges_added=self._edge_count() - e0,
            sources=["reachability"],
            errors=errors,
            elapsed_ms=elapsed_ms,
        )

    # ------------------------------------------------------------------
    # Dependency enrichment
    # ------------------------------------------------------------------

    def enrich_from_dependencies(self, dep_result: Any) -> EnrichmentResult:
        """
        Add PACKAGE nodes, DEPENDENCY edges, and VULNERABLE_TO edges from a
        ``DependencyAnalysisResult`` (or any duck-typed equivalent).

        Expected attributes on dep_result:
          - vulnerable_packages: List[Tuple[InstalledPackage, VulnerablePackage]]
          - import_usages: Dict[str, List[ImportUsage]]
        """
        start = time.monotonic()
        n0, e0 = self._node_count(), self._edge_count()
        errors: List[str] = []

        vulnerable_packages = getattr(dep_result, "vulnerable_packages", []) or []
        import_usages = getattr(dep_result, "import_usages", {}) or {}

        for installed_pkg, vuln_pkg in vulnerable_packages:
            try:
                pkg_name = getattr(installed_pkg, "name", None) or getattr(
                    vuln_pkg, "name", ""
                )
                installed_version = getattr(installed_pkg, "version", "unknown") or "unknown"
                ecosystem = getattr(vuln_pkg, "ecosystem", "pypi") or "pypi"
                fixed_version = getattr(vuln_pkg, "fixed_version", "") or ""
                severity = getattr(vuln_pkg, "severity", "MEDIUM") or "MEDIUM"
                cve_ids = getattr(vuln_pkg, "cve_ids", []) or []
                cwe_ids = getattr(vuln_pkg, "cwe_ids", []) or []
                description = getattr(vuln_pkg, "description", "") or ""
                cvss = getattr(vuln_pkg, "cvss_v3", 0.0) or 0.0

                # --- PACKAGE node ---
                pkg_nid = f"package::{ecosystem}::{pkg_name}::{installed_version}"
                pkg_node = KGNode(
                    node_id=pkg_nid,
                    type=KGNodeType.PACKAGE,
                    label=f"{pkg_name}@{installed_version}",
                    properties={
                        "name": pkg_name,
                        "version": installed_version,
                        "ecosystem": ecosystem,
                        "fixed_version": fixed_version,
                        "severity": severity,
                        "cvss_v3": cvss,
                        "description": description[:256],
                    },
                )
                self._builder.add_node(self._graph, pkg_node)

                # --- CWE_NODE nodes and VULNERABLE_TO edges ---
                for cwe_id in cwe_ids:
                    cwe_nid = f"cwe::{cwe_id}"
                    if cwe_nid not in self._graph.node_index:
                        self._builder.add_node(
                            self._graph,
                            KGNode(
                                node_id=cwe_nid,
                                type=KGNodeType.CWE_NODE,
                                label=cwe_id,
                                properties={"cwe_id": cwe_id},
                            ),
                        )
                    self._builder.add_edge(
                        self._graph,
                        KGEdge(
                            from_id=pkg_nid,
                            to_id=cwe_nid,
                            relation="VULNERABLE_TO",
                        ),
                    )

                # --- CVE nodes and EXPLOITS edges ---
                for cve_id in cve_ids:
                    cve_nid = f"cve::{cve_id}"
                    if cve_nid not in self._graph.node_index:
                        self._builder.add_node(
                            self._graph,
                            KGNode(
                                node_id=cve_nid,
                                type=KGNodeType.CVE,
                                label=cve_id,
                                properties={"cve_id": cve_id, "package": pkg_name},
                            ),
                        )
                    self._builder.add_edge(
                        self._graph,
                        KGEdge(
                            from_id=pkg_nid,
                            to_id=cve_nid,
                            relation="EXPLOITS",
                        ),
                    )

                # --- DEPENDENCY edges: CODE_UNIT → PACKAGE for each import usage ---
                usages = import_usages.get(pkg_name, [])
                for usage in usages:
                    u_file = getattr(usage, "file", "") or ""
                    if not u_file:
                        continue
                    dep_nid = f"dependency::{pkg_name}::{u_file}"
                    dep_node = KGNode(
                        node_id=dep_nid,
                        type=KGNodeType.DEPENDENCY,
                        label=f"import {pkg_name}",
                        properties={
                            "package": pkg_name,
                            "file": u_file,
                            "line": getattr(usage, "line", 0),
                        },
                    )
                    self._builder.add_node(self._graph, dep_node)

                    # DEPENDENCY → PACKAGE: DEPENDS_ON
                    self._builder.add_edge(
                        self._graph,
                        KGEdge(
                            from_id=dep_nid,
                            to_id=pkg_nid,
                            relation="DEPENDS_ON",
                        ),
                    )

                    # CODE_UNIT → DEPENDENCY: IMPORTS (if code_unit node exists)
                    code_unit_nid = f"code_unit::{u_file}"
                    if code_unit_nid in self._graph.node_index:
                        self._builder.add_edge(
                            self._graph,
                            KGEdge(
                                from_id=code_unit_nid,
                                to_id=dep_nid,
                                relation="IMPORTS",
                            ),
                        )

            except Exception as exc:  # noqa: BLE001
                errors.append(f"dep_pkg error: {exc}")

        elapsed_ms = (time.monotonic() - start) * 1000
        return EnrichmentResult(
            nodes_added=self._node_count() - n0,
            edges_added=self._edge_count() - e0,
            sources=["dependencies"],
            errors=errors,
            elapsed_ms=elapsed_ms,
        )

    # ------------------------------------------------------------------
    # Full pipeline
    # ------------------------------------------------------------------

    def run_full_pipeline(
        self,
        cpg: Optional[Any] = None,
        findings: Optional[List[Any]] = None,
        reach_result: Optional[Any] = None,
        dep_result: Optional[Any] = None,
    ) -> EnrichmentResult:
        """
        Run all enrichment sources that are not None and return a combined
        ``EnrichmentResult`` summing all contributions.
        """
        combined = EnrichmentResult()

        if cpg is not None:
            combined.merge(self.enrich_from_cpg(cpg))

        if findings is not None:
            combined.merge(self.enrich_from_findings(findings))

        if reach_result is not None:
            combined.merge(self.enrich_from_reachability(reach_result))

        if dep_result is not None:
            combined.merge(self.enrich_from_dependencies(dep_result))

        return combined
