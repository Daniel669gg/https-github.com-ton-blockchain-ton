"""
backend/analysis/attack_graph.py
Attack Graph Engine: Source → Vulnerability → Reachability → Asset → Exploit Path.

Constructs a directed property graph from findings and entrypoints, identifies
critical attack paths via DFS, computes a composite risk score, and can render
the graph as Graphviz DOT or JSON.
"""
from __future__ import annotations

import json
import logging
from collections import deque
from dataclasses import dataclass, field as dc_field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

try:
    from backend.core.confidence import Finding
except ImportError:
    try:
        from backend.core.engine.finding_normalizer import Finding  # type: ignore[no-redef]
    except ImportError:
        from pydantic import BaseModel as _BM  # type: ignore[no-redef]
        class Finding(_BM):  # type: ignore[no-redef]
            model_config = {"extra": "allow"}
            rule_id: str = ""; file: str = ""; line: int = 0
            severity: str = "MEDIUM"; confidence: float = 0.8
            cwe_id: str = ""; description: str = ""

logger = logging.getLogger("tythanai.attack_graph")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class NodeType(str, Enum):
    SOURCE = "source"           # attacker entry
    VULNERABILITY = "vuln"      # CVE/finding
    ASSET = "asset"             # protected resource
    CONTROL = "control"         # security control (auth, WAF)
    EXPLOIT = "exploit"         # exploit technique


class GraphNode(BaseModel):
    node_id: str
    type: NodeType
    label: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    from_id: str
    to_id: str
    label: str = ""             # "triggers", "leads_to", "bypasses", "exposes"
    probability: float = 1.0    # 0.0–1.0
    risk_weight: float = 0.0    # risk contribution of this edge
    impact_weight: float = 0.0  # impact contribution of this edge


class AttackGraph(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    critical_paths: List[List[str]] = Field(default_factory=list)  # list of node_id paths
    risk_score: float = 0.0


# ---------------------------------------------------------------------------
# Scored attack path
# ---------------------------------------------------------------------------

@dataclass
class ScoredAttackPath:
    """A fully-scored, ranked attack path through the graph."""
    path_nodes: List[str]           # node_ids in path order
    path_labels: List[str]          # human-readable labels
    path_score: float               # 0.0-1.0 overall score
    reachability_score: float       # how reachable is the entry
    exploitability_score: float     # how easy to exploit (based on CVSS)
    impact_score: float             # asset impact (CRITICAL=1.0, HIGH=0.7, etc.)
    confidence_score: float         # evidence confidence
    risk_score: float               # reachability × exploitability × impact × confidence
    cwe_ids: List[str] = dc_field(default_factory=list)
    attack_techniques: List[str] = dc_field(default_factory=list)  # MITRE ATT&CK technique IDs
    description: str = ""
    is_verified: bool = False       # whether any finding on path is verified


# ---------------------------------------------------------------------------
# Severity weights
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.75,
    "MEDIUM": 0.5,
    "LOW": 0.25,
    "INFO": 0.1,
}

# CWE IDs that map to "database" or "credential" assets
_DB_CWES: Set[str] = {"CWE-89", "CWE-564", "CWE-943"}
_AUTH_CWES: Set[str] = {"CWE-306", "CWE-862", "CWE-863", "CWE-284"}
_DATA_CWES: Set[str] = {"CWE-200", "CWE-359", "CWE-312", "CWE-313"}

# Asset impact scores for weighted edge computation
_ASSET_IMPACT_SCORES: Dict[str, float] = {
    "asset:database": 1.0,
    "asset:auth_system": 0.9,
    "asset:sensitive_data": 0.8,
    "asset:application_data": 0.5,
}

# Rule-ID prefixes that imply specific assets
_SQLI_PREFIXES = ("SQLI", "SQL_INJ", "CWE-89")
_AUTH_PREFIXES = ("AUTH", "AUTHZ", "AUTHN", "IDOR")
_DATA_PREFIXES = ("SSRF", "PATH_TRAV", "LFI", "RFI", "IDOR")


def _asset_for_finding(finding: Finding) -> Optional[str]:
    """Infer an asset node ID from a finding's rule and CWE."""
    rid = finding.rule_id.upper()
    cwe = finding.cwe_id.upper()

    if any(rid.startswith(p) for p in _SQLI_PREFIXES) or cwe in _DB_CWES:
        return "asset:database"
    if any(rid.startswith(p) for p in _AUTH_PREFIXES) or cwe in _AUTH_CWES:
        return "asset:auth_system"
    if any(rid.startswith(p) for p in _DATA_PREFIXES) or cwe in _DATA_CWES:
        return "asset:sensitive_data"
    # Default: generic application data asset
    return "asset:application_data"


def _finding_node_id(finding: Finding) -> str:
    return f"vuln:{finding.rule_id}:{finding.file}:{finding.line}"


def _entry_node_id(entry: Any) -> str:
    """Deterministic node ID for an entrypoint (duck-typed)."""
    ep_file = getattr(entry, "file", "unknown")
    ep_name = getattr(entry, "name", "unknown")
    return f"source:{ep_file}:{ep_name}"


# ---------------------------------------------------------------------------
# AttackGraphBuilder
# ---------------------------------------------------------------------------

class AttackGraphBuilder:
    """
    Builds an :py:class:`AttackGraph` from findings and optional entrypoints.

    The graph structure is::

        SOURCE (entrypoint)
          └─[triggers]─► VULNERABILITY (finding)
               └─[exposes]─► ASSET
               └─[leads_to]─► VULNERABILITY (chained taint)

    A generic Internet SOURCE node is always included.
    """

    def __init__(
        self,
        findings: Optional[List[Finding]] = None,
        entrypoints: Optional[List[Any]] = None,
    ) -> None:
        """
        Optionally pre-load findings and entrypoints so that the ranked-path
        helpers (``rank_attack_paths``, ``get_top_exploit_chains``, etc.) can
        build the graph on demand without requiring callers to pass it explicitly.
        """
        self._findings: List[Finding] = findings if findings is not None else []
        self._entrypoints: List[Any] = entrypoints if entrypoints is not None else []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(
        self,
        findings: List[Finding],
        entrypoints: List[Any],
        cve_records: Optional[List[Any]] = None,
    ) -> AttackGraph:
        """
        Build the attack graph.

        Parameters
        ----------
        findings:
            List of :py:class:`~backend.core.confidence.Finding` objects.
        entrypoints:
            List of :py:class:`~backend.analysis.reachability.EntryPoint`-like
            objects (must have ``file``, ``name``, ``type``, and ``method``
            attributes/fields).
        cve_records:
            Optional list of CVE metadata dicts (currently unused; reserved for
            future enrichment).
        """
        graph = AttackGraph()

        # ── Internet source node ────────────────────────────────────────────────
        internet_node = GraphNode(
            node_id="source:internet",
            type=NodeType.SOURCE,
            label="Internet / Attacker",
            properties={"description": "Unauthenticated internet attacker"},
        )
        graph.nodes.append(internet_node)

        # ── Entrypoint nodes ────────────────────────────────────────────────────
        seen_node_ids: Set[str] = {"source:internet"}

        for ep in entrypoints:
            ep_id = _entry_node_id(ep)
            if ep_id in seen_node_ids:
                continue
            seen_node_ids.add(ep_id)
            ep_type = getattr(ep, "type", "UNKNOWN")
            ep_method = getattr(ep, "method", "")
            ep_path = getattr(ep, "path", "")
            label = (
                f"{ep_type}: {ep_method} {ep_path}".strip()
                if ep_path
                else f"{ep_type}: {getattr(ep, 'name', ep_id)}"
            )
            graph.nodes.append(
                GraphNode(
                    node_id=ep_id,
                    type=NodeType.SOURCE,
                    label=label,
                    properties={
                        "file": getattr(ep, "file", ""),
                        "line": getattr(ep, "line", 0),
                        "ep_type": ep_type,
                        "method": ep_method,
                        "path": ep_path,
                    },
                )
            )
            # Internet → entrypoint edge
            graph.edges.append(
                GraphEdge(
                    from_id="source:internet",
                    to_id=ep_id,
                    label="reaches",
                    probability=0.9 if ep_method == "GET" else 0.8,
                )
            )

        # ── Vulnerability nodes ─────────────────────────────────────────────────
        # Build a set of finding node IDs for taint-chain detection
        finding_node_map: Dict[str, Finding] = {}
        for finding in findings:
            fid = _finding_node_id(finding)
            if fid in seen_node_ids:
                continue
            seen_node_ids.add(fid)
            sev = finding.severity.upper()
            graph.nodes.append(
                GraphNode(
                    node_id=fid,
                    type=NodeType.VULNERABILITY,
                    label=f"{sev}: {finding.rule_id}",
                    properties={
                        "rule_id": finding.rule_id,
                        "file": finding.file,
                        "line": finding.line,
                        "severity": sev,
                        "confidence": finding.confidence,
                        "cwe_id": finding.cwe_id,
                        "description": finding.description,
                    },
                )
            )
            finding_node_map[fid] = finding

        # ── Asset nodes ─────────────────────────────────────────────────────────
        asset_labels: Dict[str, str] = {
            "asset:database": "Database",
            "asset:auth_system": "Authentication System",
            "asset:sensitive_data": "Sensitive Data Store",
            "asset:application_data": "Application Data",
        }
        used_assets: Set[str] = set()
        for finding in findings:
            asset_id = _asset_for_finding(finding)
            if asset_id and asset_id not in used_assets:
                used_assets.add(asset_id)
                if asset_id not in seen_node_ids:
                    seen_node_ids.add(asset_id)
                    graph.nodes.append(
                        GraphNode(
                            node_id=asset_id,
                            type=NodeType.ASSET,
                            label=asset_labels.get(asset_id, asset_id),
                            properties={},
                        )
                    )

        # ── Edges: entrypoint → finding ─────────────────────────────────────────
        # For each finding, connect the "nearest" entrypoint
        ep_ids = [_entry_node_id(ep) for ep in entrypoints]

        for finding in findings:
            fid = _finding_node_id(finding)
            asset_id = _asset_for_finding(finding)
            conf = finding.confidence
            sev_score = _SEVERITY_WEIGHTS.get(finding.severity.upper(), 0.5)
            asset_impact = _ASSET_IMPACT_SCORES.get(asset_id or "", 0.5)

            # Connect from an entrypoint (or internet if no entrypoints)
            source_id = self._best_source_for_finding(finding, entrypoints, ep_ids)
            edge_prob = round(conf * 0.9, 4)
            graph.edges.append(
                GraphEdge(
                    from_id=source_id,
                    to_id=fid,
                    label="triggers",
                    probability=edge_prob,
                    risk_weight=round(edge_prob * sev_score, 4),
                    impact_weight=round(asset_impact * conf, 4),
                )
            )

            # Connect finding → asset
            if asset_id:
                asset_edge_prob = round(conf, 4)
                graph.edges.append(
                    GraphEdge(
                        from_id=fid,
                        to_id=asset_id,
                        label="exposes",
                        probability=asset_edge_prob,
                        risk_weight=round(asset_edge_prob * sev_score, 4),
                        impact_weight=round(asset_impact, 4),
                    )
                )

        # ── Taint chains: finding → finding ─────────────────────────────────────
        # Heuristic: findings in the same file with taint-related rule IDs chain
        # in line-number order.
        taint_prefixes = ("TAINT", "XSS", "SQLI", "INJECTION", "SSRF")
        taint_findings = [
            (fid, f)
            for fid, f in finding_node_map.items()
            if any(f.rule_id.upper().startswith(p) for p in taint_prefixes)
        ]
        # Group by file
        by_file: Dict[str, List[Tuple[str, Finding]]] = {}
        for fid, f in taint_findings:
            by_file.setdefault(f.file, []).append((fid, f))
        for file_findings in by_file.values():
            file_findings.sort(key=lambda x: x[1].line)
            for (fid_a, fa), (fid_b, fb) in zip(file_findings, file_findings[1:]):
                graph.edges.append(
                    GraphEdge(
                        from_id=fid_a,
                        to_id=fid_b,
                        label="leads_to",
                        probability=round((fa.confidence + fb.confidence) / 2, 4),
                    )
                )

        # ── Risk score ──────────────────────────────────────────────────────────
        graph.risk_score = self._compute_risk_score(findings)

        # ── Critical paths ──────────────────────────────────────────────────────
        graph.critical_paths = self.find_critical_paths(graph)

        logger.info(
            "build: %d nodes, %d edges, risk_score=%.4f, %d critical paths",
            len(graph.nodes),
            len(graph.edges),
            graph.risk_score,
            len(graph.critical_paths),
        )
        return graph

    @staticmethod
    def _best_source_for_finding(
        finding: Finding,
        entrypoints: List[Any],
        ep_ids: List[str],
    ) -> str:
        """Pick the closest entrypoint to *finding* by file path similarity."""
        if not entrypoints:
            return "source:internet"
        best_ep = None
        best_common = -1
        for ep, ep_id in zip(entrypoints, ep_ids):
            ep_file = getattr(ep, "file", "")
            if ep_file == finding.file:
                return ep_id
            # Count common path segments
            finding_parts = finding.file.split("/")
            ep_parts = ep_file.split("/")
            common = sum(1 for a, b in zip(finding_parts, ep_parts) if a == b)
            if common > best_common:
                best_common = common
                best_ep = ep_id
        return best_ep or "source:internet"

    @staticmethod
    def _compute_risk_score(findings: List[Finding]) -> float:
        """
        Weighted risk score = sum(severity_weight × confidence) / total count.
        Returns 0.0 if there are no findings.
        """
        if not findings:
            return 0.0
        total_weight = sum(
            _SEVERITY_WEIGHTS.get(f.severity.upper(), 0.5) * f.confidence
            for f in findings
        )
        return round(total_weight / len(findings), 4)

    # ------------------------------------------------------------------
    # Critical paths
    # ------------------------------------------------------------------

    def find_critical_paths(
        self,
        graph: AttackGraph,
        max_paths: int = 10,
    ) -> List[List[str]]:
        """
        DFS from every SOURCE node to every ASSET node.

        Returns up to *max_paths* paths, ranked by the product of edge
        probabilities along the path (highest probability first).
        """
        # Build adjacency map and edge probability map
        adj: Dict[str, List[str]] = {}
        prob_map: Dict[Tuple[str, str], float] = {}
        for edge in graph.edges:
            adj.setdefault(edge.from_id, []).append(edge.to_id)
            prob_map[(edge.from_id, edge.to_id)] = edge.probability

        source_ids = {n.node_id for n in graph.nodes if n.type == NodeType.SOURCE}
        asset_ids = {n.node_id for n in graph.nodes if n.type == NodeType.ASSET}

        if not source_ids or not asset_ids:
            return []

        all_paths: List[Tuple[float, List[str]]] = []

        for src in source_ids:
            self._dfs_paths(
                src, asset_ids, adj, prob_map,
                [src], {src}, 1.0, all_paths, max_paths * 5,
            )

        # Sort descending by probability product, keep top max_paths
        all_paths.sort(key=lambda x: x[0], reverse=True)
        return [path for _, path in all_paths[:max_paths]]

    def _dfs_paths(
        self,
        node: str,
        targets: Set[str],
        adj: Dict[str, List[str]],
        prob_map: Dict[Tuple[str, str], float],
        current_path: List[str],
        visited: Set[str],
        current_prob: float,
        results: List[Tuple[float, List[str]]],
        limit: int,
    ) -> None:
        """Recursive DFS helper for critical path finding."""
        if len(results) >= limit:
            return
        if node in targets:
            results.append((current_prob, list(current_path)))
            # Continue searching (the path might extend further)
        for neighbor in adj.get(node, []):
            if neighbor in visited:
                continue
            edge_prob = prob_map.get((node, neighbor), 1.0)
            new_prob = current_prob * edge_prob
            visited.add(neighbor)
            current_path.append(neighbor)
            self._dfs_paths(
                neighbor, targets, adj, prob_map,
                current_path, visited, new_prob, results, limit,
            )
            current_path.pop()
            visited.discard(neighbor)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    @staticmethod
    def to_dot(graph: AttackGraph) -> str:
        """
        Render the attack graph as a Graphviz DOT string.

        Color coding:
        - SOURCE → red
        - VULNERABILITY → orange
        - ASSET → green
        - CONTROL → blue
        - EXPLOIT → purple
        """
        color_map = {
            NodeType.SOURCE: "red",
            NodeType.VULNERABILITY: "orange",
            NodeType.ASSET: "green",
            NodeType.CONTROL: "blue",
            NodeType.EXPLOIT: "purple",
        }

        lines = [
            "digraph AttackGraph {",
            "    rankdir=LR;",
            '    node [shape=box, style=filled, fontsize=10];',
            "",
        ]

        for node in graph.nodes:
            color = color_map.get(node.type, "grey")
            safe_label = node.label.replace('"', '\\"').replace("\n", "\\n")
            lines.append(
                f'    "{node.node_id}" [label="{safe_label}", fillcolor="{color}", fontcolor="white"];'
            )

        lines.append("")

        for edge in graph.edges:
            safe_label = edge.label.replace('"', '\\"')
            prob_str = f"{edge.probability:.2f}"
            lines.append(
                f'    "{edge.from_id}" -> "{edge.to_id}" '
                f'[label="{safe_label} ({prob_str})"];'
            )

        # Highlight critical paths
        if graph.critical_paths:
            lines.append("")
            lines.append("    // Critical paths highlighted with bold edges")
            crit_edges: Set[Tuple[str, str]] = set()
            for path in graph.critical_paths:
                for a, b in zip(path, path[1:]):
                    crit_edges.add((a, b))
            for a, b in crit_edges:
                lines.append(
                    f'    "{a}" -> "{b}" [style=bold, color=red, penwidth=2];'
                )

        lines.append("}")
        return "\n".join(lines)

    @staticmethod
    def to_json(graph: AttackGraph) -> str:
        """Serialise the attack graph to a JSON string."""
        return graph.model_dump_json(indent=2)

    # ------------------------------------------------------------------
    # Exploit chain builder
    # ------------------------------------------------------------------

    def build_exploit_chain(
        self,
        findings: List[Finding],
        entry_points: List[Any],
        reachability_paths: Optional[List[Any]] = None,
    ) -> AttackGraph:
        """
        Build a specific exploit chain following the pattern:

        HTTP Endpoint → Tainted Input → Vulnerability → Exploit Path → Asset

        Node types used in order:
            SOURCE → VULNERABILITY → CONTROL (auth bypass) → EXPLOIT → ASSET

        Each edge has a ``probability`` based on reachability score and
        confidence.  ``graph.critical_paths`` is populated via DFS.

        Parameters
        ----------
        findings:
            List of Finding objects to model.
        entry_points:
            List of entrypoint-like objects (must have ``file``, ``name``,
            ``method``, ``path`` attributes/fields).
        reachability_paths:
            Optional list of reachability path objects; used to adjust edge
            probabilities.  If None, defaults are used.
        """
        graph = AttackGraph()
        seen_node_ids: Set[str] = set()

        # ── Step 1: SOURCE nodes — HTTP entry points ───────────────────────────
        if entry_points:
            for ep in entry_points:
                ep_id = _entry_node_id(ep)
                if ep_id in seen_node_ids:
                    continue
                seen_node_ids.add(ep_id)
                ep_method = getattr(ep, "method", "GET")
                ep_path = getattr(ep, "path", getattr(ep, "name", "unknown"))
                label = f"HTTP {ep_method} {ep_path}\n(Entry Point)"
                graph.nodes.append(
                    GraphNode(
                        node_id=ep_id,
                        type=NodeType.SOURCE,
                        label=label,
                        properties={
                            "file": getattr(ep, "file", ""),
                            "method": ep_method,
                            "path": ep_path,
                        },
                    )
                )
        else:
            # Generic internet source if no explicit entry points
            graph.nodes.append(
                GraphNode(
                    node_id="source:internet",
                    type=NodeType.SOURCE,
                    label="Internet / Attacker\n(Entry Point)",
                    properties={"description": "Unauthenticated internet attacker"},
                )
            )
            seen_node_ids.add("source:internet")

        source_ids = [n.node_id for n in graph.nodes if n.type == NodeType.SOURCE]

        # ── Step 2: VULNERABILITY nodes from findings ──────────────────────────
        finding_node_map: Dict[str, Finding] = {}
        reachability_lookup: Dict[str, float] = {}

        # Build a reachability score map from paths (if provided)
        if reachability_paths:
            for rp in reachability_paths:
                rp_file = getattr(rp, "file", None) or getattr(rp, "sink_file", None)
                rp_score = getattr(rp, "score", getattr(rp, "probability", 0.8))
                if rp_file:
                    reachability_lookup[rp_file] = float(rp_score)

        for finding in findings:
            fid = _finding_node_id(finding)
            if fid in seen_node_ids:
                continue
            seen_node_ids.add(fid)
            sev = finding.severity.upper()
            reachability_score = reachability_lookup.get(finding.file, 0.8)
            graph.nodes.append(
                GraphNode(
                    node_id=fid,
                    type=NodeType.VULNERABILITY,
                    label=f"{finding.rule_id}\n{sev} | {finding.cwe_id or 'N/A'}",
                    properties={
                        "rule_id": finding.rule_id,
                        "file": finding.file,
                        "line": finding.line,
                        "severity": sev,
                        "confidence": finding.confidence,
                        "cwe_id": finding.cwe_id,
                        "description": finding.description,
                        "reachability_score": reachability_score,
                    },
                )
            )
            finding_node_map[fid] = finding

        # ── Step 3: CONTROL nodes — auth bypass for auth-related CWEs ─────────
        auth_cwes = {"CWE-306", "CWE-862", "CWE-863", "CWE-284", "CWE-285"}
        control_fids: Set[str] = set()
        for fid, finding in finding_node_map.items():
            if finding.cwe_id in auth_cwes:
                ctrl_id = f"control:auth_bypass:{finding.file}:{finding.line}"
                if ctrl_id not in seen_node_ids:
                    seen_node_ids.add(ctrl_id)
                    graph.nodes.append(
                        GraphNode(
                            node_id=ctrl_id,
                            type=NodeType.CONTROL,
                            label=f"Auth Bypass\n({finding.cwe_id})",
                            properties={
                                "finding_id": fid,
                                "cwe_id": finding.cwe_id,
                            },
                        )
                    )
                    control_fids.add(ctrl_id)

        # ── Step 4: EXPLOIT nodes — one per high/critical finding ──────────────
        exploit_node_ids: Dict[str, str] = {}
        for fid, finding in finding_node_map.items():
            sev = finding.severity.upper()
            if sev in ("CRITICAL", "HIGH"):
                exploit_id = f"exploit:{finding.rule_id}:{finding.line}"
                if exploit_id not in seen_node_ids:
                    seen_node_ids.add(exploit_id)
                    technique = self._exploit_technique(finding)
                    graph.nodes.append(
                        GraphNode(
                            node_id=exploit_id,
                            type=NodeType.EXPLOIT,
                            label=f"{technique}\n(via {finding.rule_id})",
                            properties={
                                "finding_id": fid,
                                "technique": technique,
                                "severity": sev,
                            },
                        )
                    )
                    exploit_node_ids[fid] = exploit_id

        # ── Step 5: ASSET nodes ────────────────────────────────────────────────
        asset_labels: Dict[str, str] = {
            "asset:database": "Database\n(data store)",
            "asset:auth_system": "Authentication System\n(credentials/sessions)",
            "asset:sensitive_data": "Sensitive Data Store\n(PII/secrets)",
            "asset:application_data": "Application Data\n(business logic)",
        }
        used_assets: Set[str] = set()
        for finding in findings:
            asset_id = _asset_for_finding(finding)
            if asset_id and asset_id not in used_assets:
                used_assets.add(asset_id)
                if asset_id not in seen_node_ids:
                    seen_node_ids.add(asset_id)
                    graph.nodes.append(
                        GraphNode(
                            node_id=asset_id,
                            type=NodeType.ASSET,
                            label=asset_labels.get(asset_id, asset_id),
                            properties={},
                        )
                    )

        # ── Step 6: Edges ──────────────────────────────────────────────────────
        ep_ids = [n.node_id for n in graph.nodes if n.type == NodeType.SOURCE]

        for fid, finding in finding_node_map.items():
            reachability_score = reachability_lookup.get(finding.file, 0.8)
            edge_prob = round(finding.confidence * reachability_score, 4)

            # SOURCE → VULNERABILITY
            source_id = self._best_source_for_finding(finding, entry_points, ep_ids)
            graph.edges.append(
                GraphEdge(
                    from_id=source_id,
                    to_id=fid,
                    label="tainted input",
                    probability=edge_prob,
                )
            )

            # VULNERABILITY → CONTROL (if auth-related)
            for ctrl_id in control_fids:
                ctrl_props = next(
                    (n.properties for n in graph.nodes if n.node_id == ctrl_id), {}
                )
                if ctrl_props.get("finding_id") == fid:
                    graph.edges.append(
                        GraphEdge(
                            from_id=fid,
                            to_id=ctrl_id,
                            label="bypasses auth",
                            probability=round(finding.confidence * 0.9, 4),
                        )
                    )

            # VULNERABILITY → EXPLOIT
            exploit_id = exploit_node_ids.get(fid)
            if exploit_id:
                graph.edges.append(
                    GraphEdge(
                        from_id=fid,
                        to_id=exploit_id,
                        label="exploit path",
                        probability=round(finding.confidence * reachability_score * 0.85, 4),
                    )
                )
                # EXPLOIT → ASSET
                asset_id = _asset_for_finding(finding)
                if asset_id:
                    graph.edges.append(
                        GraphEdge(
                            from_id=exploit_id,
                            to_id=asset_id,
                            label="data exfiltration",
                            probability=round(finding.confidence * 0.9, 4),
                        )
                    )
            else:
                # VULNERABILITY → ASSET (direct for low/medium)
                asset_id = _asset_for_finding(finding)
                if asset_id:
                    graph.edges.append(
                        GraphEdge(
                            from_id=fid,
                            to_id=asset_id,
                            label="exposes",
                            probability=round(finding.confidence, 4),
                        )
                    )

        # ── Step 7: Risk score + critical paths ────────────────────────────────
        graph.risk_score = self.compute_risk_score(graph)
        graph.critical_paths = self.find_critical_paths(graph)

        logger.info(
            "build_exploit_chain: %d nodes, %d edges, risk_score=%.2f, %d critical paths",
            len(graph.nodes),
            len(graph.edges),
            graph.risk_score,
            len(graph.critical_paths),
        )
        return graph

    @staticmethod
    def _exploit_technique(finding: Finding) -> str:
        """Map a finding to a human-readable exploit technique name."""
        rid = finding.rule_id.upper()
        cwe = finding.cwe_id.upper()
        if "SQLI" in rid or cwe == "CWE-89":
            return "SQL Injection"
        if "XSS" in rid or cwe == "CWE-79":
            return "Cross-Site Scripting"
        if "CMDI" in rid or "COMMAND" in rid or cwe == "CWE-78":
            return "Command Injection"
        if "SSRF" in rid or cwe == "CWE-918":
            return "Server-Side Request Forgery"
        if "DESERI" in rid or cwe == "CWE-502":
            return "Insecure Deserialization"
        if "PATH" in rid or cwe in ("CWE-22", "CWE-73"):
            return "Path Traversal"
        if "AUTH" in rid or cwe in ("CWE-306", "CWE-862"):
            return "Authentication Bypass"
        return "Exploit Technique"

    # ------------------------------------------------------------------
    # Mermaid export
    # ------------------------------------------------------------------

    @staticmethod
    def to_mermaid(graph: AttackGraph) -> str:
        """
        Render the attack graph as a Mermaid diagram (GitHub markdown compatible).

        Node styling by type:
        - SOURCE  → red (#ff6b6b)
        - VULN    → orange (#f39c12)
        - CONTROL → blue (#3498db)
        - EXPLOIT → purple (#9b59b6)
        - ASSET   → green (#27ae60)
        """
        lines = ["graph TD"]

        _CSS_CLASS: Dict[str, str] = {
            NodeType.SOURCE: "source",
            NodeType.VULNERABILITY: "vuln",
            NodeType.CONTROL: "control",
            NodeType.EXPLOIT: "exploit",
            NodeType.ASSET: "asset",
        }

        def _safe_id(node_id: str) -> str:
            """Convert a node_id into a Mermaid-safe identifier."""
            return node_id.replace(":", "_").replace("/", "_").replace(".", "_").replace("-", "_")

        def _escape_label(label: str) -> str:
            return label.replace('"', "'")

        # Node declarations
        for node in graph.nodes:
            safe = _safe_id(node.node_id)
            css = _CSS_CLASS.get(node.type, "")
            escaped = _escape_label(node.label)
            lines.append(f'  {safe}["{escaped}"]:::{css}')

        lines.append("")

        # Edges
        for edge in graph.edges:
            src = _safe_id(edge.from_id)
            dst = _safe_id(edge.to_id)
            prob_str = f"{edge.probability:.2f}"
            label_text = _escape_label(edge.label or "")
            if label_text:
                lines.append(f'  {src} -->|"{label_text} ({prob_str})"| {dst}')
            else:
                lines.append(f'  {src} -->|"{prob_str}"| {dst}')

        # Highlight critical path edges
        if graph.critical_paths:
            lines.append("")
            lines.append("  %% Critical paths highlighted")
            crit_pairs: Set[Tuple[str, str]] = set()
            for path in graph.critical_paths:
                for a, b in zip(path, path[1:]):
                    crit_pairs.add((_safe_id(a), _safe_id(b)))
            for src, dst in sorted(crit_pairs):
                lines.append(f"  {src} ==>|critical| {dst}")

        lines.append("")

        # Class definitions
        lines.extend([
            "  classDef source fill:#ff6b6b,stroke:#c0392b,color:#fff",
            "  classDef vuln fill:#f39c12,stroke:#e67e22,color:#fff",
            "  classDef control fill:#3498db,stroke:#2980b9,color:#fff",
            "  classDef exploit fill:#9b59b6,stroke:#8e44ad,color:#fff",
            "  classDef asset fill:#27ae60,stroke:#219a52,color:#fff",
        ])

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Ranked attack paths
    # ------------------------------------------------------------------

    # CWE → MITRE ATT&CK technique mapping (used for ScoredAttackPath)
    _CWE_TECHNIQUES: Dict[str, str] = {
        "CWE-89":  "T1190",
        "CWE-79":  "T1059.007",
        "CWE-78":  "T1059.004",
        "CWE-22":  "T1083",
        "CWE-798": "T1552.001",
        "CWE-502": "T1059",
        "CWE-918": "T1090.002",
        "CWE-94":  "T1059.007",
        "CWE-287": "T1556",
        "CWE-611": "T1005",
    }

    def _score_path(
        self,
        path: List[str],
        node_map: Dict[str, GraphNode],
        prob_map: Dict[Tuple[str, str], float],
    ) -> ScoredAttackPath:
        """Compute a :py:class:`ScoredAttackPath` for a single node-id path."""
        # -- Labels --
        path_labels = [node_map[n].label if n in node_map else n for n in path]

        # -- reachability_score from source node type --
        reachability_score = 0.3  # default: internal
        for nid in path:
            node = node_map.get(nid)
            if node and node.type == NodeType.SOURCE:
                ep_type = node.properties.get("ep_type", "").upper()
                method = node.properties.get("method", "").upper()
                if nid == "source:internet" or ep_type in ("HTTP", "HTTPS", "REST", "API"):
                    reachability_score = 0.9
                elif ep_type in ("AUTHENTICATED", "AUTH"):
                    reachability_score = 0.5
                else:
                    reachability_score = 0.9 if method in ("GET", "POST") else 0.5
                break

        # -- exploitability_score from VULNERABILITY severity --
        exploitability_score = 0.5
        sev_to_exploit: Dict[str, float] = {
            "CRITICAL": 0.95,
            "HIGH": 0.75,
            "MEDIUM": 0.5,
            "LOW": 0.2,
            "INFO": 0.05,
        }
        cwe_ids: List[str] = []
        confidence_values: List[float] = []
        is_verified = False
        for nid in path:
            node = node_map.get(nid)
            if node and node.type == NodeType.VULNERABILITY:
                sev = node.properties.get("severity", "MEDIUM").upper()
                exploitability_score = max(
                    exploitability_score,
                    sev_to_exploit.get(sev, 0.5),
                )
                cwe = node.properties.get("cwe_id", "")
                if cwe and cwe not in cwe_ids:
                    cwe_ids.append(cwe)
                conf = float(node.properties.get("confidence", 0.8))
                confidence_values.append(conf)
                # check verified markers on description
                desc = node.properties.get("description", "").lower()
                if any(tok in desc for tok in ("verified", "reproduced", "confirmed")):
                    is_verified = True

        # -- impact_score from ASSET node type --
        impact_score = 0.5
        asset_impact_map: Dict[str, float] = {
            "asset:database": 1.0,
            "asset:auth_system": 0.9,
            "asset:sensitive_data": 0.8,
            "asset:application_data": 0.5,
        }
        for nid in path:
            node = node_map.get(nid)
            if node and node.type == NodeType.ASSET:
                impact_score = max(impact_score, asset_impact_map.get(nid, 0.5))

        # -- confidence_score: average of vuln node confidence --
        confidence_score = (
            sum(confidence_values) / len(confidence_values)
            if confidence_values
            else 0.8
        )

        # -- probability product along path edges --
        prob_product = 1.0
        for a, b in zip(path, path[1:]):
            prob_product *= prob_map.get((a, b), 1.0)

        # -- risk_score --
        risk_score = round(
            reachability_score * exploitability_score * impact_score * confidence_score,
            4,
        )

        # -- path_score --
        path_score = round((risk_score + prob_product) / 2.0, 4)

        # -- attack_techniques from CWE IDs --
        attack_techniques = list(
            filter(None, [self._CWE_TECHNIQUES.get(c) for c in cwe_ids])
        )

        # -- description --
        desc_parts = []
        for nid in path:
            node = node_map.get(nid)
            if node:
                desc_parts.append(node.label.split("\n")[0])
        description = " → ".join(desc_parts)

        return ScoredAttackPath(
            path_nodes=list(path),
            path_labels=path_labels,
            path_score=path_score,
            reachability_score=reachability_score,
            exploitability_score=exploitability_score,
            impact_score=impact_score,
            confidence_score=confidence_score,
            risk_score=risk_score,
            cwe_ids=cwe_ids,
            attack_techniques=attack_techniques,
            description=description,
            is_verified=is_verified,
        )

    def _build_helpers(
        self, graph: AttackGraph
    ) -> Tuple[
        Dict[str, GraphNode],
        Dict[Tuple[str, str], float],
    ]:
        """Build node_map and prob_map for path scoring helpers."""
        node_map: Dict[str, GraphNode] = {n.node_id: n for n in graph.nodes}
        prob_map: Dict[Tuple[str, str], float] = {
            (e.from_id, e.to_id): e.probability for e in graph.edges
        }
        return node_map, prob_map

    def rank_attack_paths(
        self,
        max_paths: int = 10,
        graph: Optional[AttackGraph] = None,
    ) -> List[ScoredAttackPath]:
        """
        Return the top *max_paths* attack paths, ranked by path_score descending.

        If *graph* is not provided the builder uses the stored findings/entrypoints
        from ``__init__`` (empty lists produce an empty result gracefully).
        """
        if graph is None:
            graph = self.build(self._findings, self._entrypoints)

        raw_paths = self.find_critical_paths(graph, max_paths=max_paths * 5)
        if not raw_paths:
            return []

        node_map, prob_map = self._build_helpers(graph)
        scored = [self._score_path(p, node_map, prob_map) for p in raw_paths]
        scored.sort(key=lambda sp: sp.path_score, reverse=True)
        return scored[:max_paths]

    def get_top_exploit_chains(
        self,
        max_chains: int = 10,
        graph: Optional[AttackGraph] = None,
    ) -> List[ScoredAttackPath]:
        """
        Return paths that pass through at least one EXPLOIT node, ranked by
        path_score descending.
        """
        if graph is None:
            graph = self.build(self._findings, self._entrypoints)

        exploit_ids: Set[str] = {
            n.node_id for n in graph.nodes if n.type == NodeType.EXPLOIT
        }
        raw_paths = self.find_critical_paths(graph, max_paths=max_chains * 10)
        if not raw_paths:
            return []

        node_map, prob_map = self._build_helpers(graph)
        scored: List[ScoredAttackPath] = []
        for path in raw_paths:
            if exploit_ids and not any(nid in exploit_ids for nid in path):
                # No exploit node on this path — skip
                continue
            scored.append(self._score_path(path, node_map, prob_map))

        scored.sort(key=lambda sp: sp.path_score, reverse=True)
        return scored[:max_chains]

    def get_top_reachable_risks(
        self,
        max_risks: int = 10,
        graph: Optional[AttackGraph] = None,
    ) -> List[ScoredAttackPath]:
        """
        Return paths where the ASSET node has the highest impact, sorted by
        ``impact_score × reachability_score`` descending.
        """
        if graph is None:
            graph = self.build(self._findings, self._entrypoints)

        raw_paths = self.find_critical_paths(graph, max_paths=max_risks * 10)
        if not raw_paths:
            return []

        node_map, prob_map = self._build_helpers(graph)
        scored = [self._score_path(p, node_map, prob_map) for p in raw_paths]
        scored.sort(
            key=lambda sp: sp.impact_score * sp.reachability_score,
            reverse=True,
        )
        return scored[:max_risks]

    # ------------------------------------------------------------------
    # Risk / impact propagation
    # ------------------------------------------------------------------

    def propagate_risk(
        self,
        node_id: str,
        propagation_depth: int = 3,
        graph: Optional[AttackGraph] = None,
    ) -> Dict[str, float]:
        """
        BFS from *node_id* (typically a VULNERABILITY node), spreading risk to
        connected nodes.  Each hop reduces risk by factor 0.7.

        Returns a mapping ``{node_id: propagated_risk_score}``.
        The starting node receives the risk score derived from its own severity
        (or 1.0 if it cannot be determined).
        """
        if graph is None:
            graph = self.build(self._findings, self._entrypoints)

        node_map: Dict[str, GraphNode] = {n.node_id: n for n in graph.nodes}
        adj: Dict[str, List[str]] = {}
        for edge in graph.edges:
            adj.setdefault(edge.from_id, []).append(edge.to_id)

        # Determine initial risk for the seed node
        seed_node = node_map.get(node_id)
        if seed_node and seed_node.type == NodeType.VULNERABILITY:
            sev = seed_node.properties.get("severity", "MEDIUM").upper()
            initial_risk = _SEVERITY_WEIGHTS.get(sev, 0.5)
        else:
            initial_risk = 1.0

        propagated: Dict[str, float] = {node_id: initial_risk}
        queue: deque = deque([(node_id, initial_risk, 0)])

        while queue:
            current, current_risk, depth = queue.popleft()
            if depth >= propagation_depth:
                continue
            for neighbor in adj.get(current, []):
                new_risk = round(current_risk * 0.7, 6)
                # Keep the highest risk value seen at this neighbor
                if neighbor not in propagated or propagated[neighbor] < new_risk:
                    propagated[neighbor] = new_risk
                    queue.append((neighbor, new_risk, depth + 1))

        return propagated

    def propagate_impact(
        self,
        asset_node_id: str,
        graph: Optional[AttackGraph] = None,
    ) -> Dict[str, float]:
        """
        BFS *backwards* from an ASSET node, spreading impact score upstream to
        predecessor nodes.

        Returns a mapping ``{node_id: impact_score}``.
        """
        if graph is None:
            graph = self.build(self._findings, self._entrypoints)

        node_map: Dict[str, GraphNode] = {n.node_id: n for n in graph.nodes}

        # Determine initial impact of the asset node
        asset_node = node_map.get(asset_node_id)
        initial_impact = _ASSET_IMPACT_SCORES.get(asset_node_id, 0.5)
        if asset_node and asset_node.type != NodeType.ASSET:
            # Caller passed a non-asset node; use a neutral impact
            initial_impact = 0.5

        # Build reverse adjacency map
        rev_adj: Dict[str, List[str]] = {}
        for edge in graph.edges:
            rev_adj.setdefault(edge.to_id, []).append(edge.from_id)

        propagated: Dict[str, float] = {asset_node_id: initial_impact}
        queue: deque = deque([(asset_node_id, initial_impact)])

        visited: Set[str] = {asset_node_id}
        while queue:
            current, current_impact = queue.popleft()
            upstream_impact = round(current_impact * 0.7, 6)
            for predecessor in rev_adj.get(current, []):
                if predecessor not in visited:
                    visited.add(predecessor)
                    propagated[predecessor] = upstream_impact
                    queue.append((predecessor, upstream_impact))

        return propagated

    # ------------------------------------------------------------------
    # Risk score (public method, supersedes the private _compute_risk_score)
    # ------------------------------------------------------------------

    def compute_risk_score(self, graph: AttackGraph) -> float:
        """
        Compute a 0-100 risk score for the attack graph.

        Weighting:
        - CRITICAL = 10 points
        - HIGH     = 7  points
        - MEDIUM   = 4  points
        - LOW      = 1  point

        Each severity weight is multiplied by the node's confidence and
        reachability_score.  The sum is normalized to 0-100 using the
        theoretical maximum (all CRITICAL, fully confident and reachable).

        Updates ``graph.risk_score`` in-place and returns it.
        """
        _SEVERITY_POINTS: Dict[str, float] = {
            "CRITICAL": 10.0,
            "HIGH": 7.0,
            "MEDIUM": 4.0,
            "LOW": 1.0,
            "INFO": 0.5,
        }

        vuln_nodes = [n for n in graph.nodes if n.type == NodeType.VULNERABILITY]
        if not vuln_nodes:
            graph.risk_score = 0.0
            return 0.0

        raw_score = 0.0
        max_possible = 0.0
        for node in vuln_nodes:
            sev = node.properties.get("severity", "MEDIUM").upper()
            conf = float(node.properties.get("confidence", 0.5))
            reach = float(node.properties.get("reachability_score", 0.8))
            pts = _SEVERITY_POINTS.get(sev, 4.0)
            raw_score += pts * conf * reach
            max_possible += pts  # perfect confidence + reachability

        if max_possible == 0.0:
            graph.risk_score = 0.0
            return 0.0

        normalized = round((raw_score / max_possible) * 100.0, 2)
        normalized = max(0.0, min(100.0, normalized))
        graph.risk_score = normalized
        return normalized


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

def build_attack_graph(
    findings: List[Finding],
    entrypoints: Optional[List[Any]] = None,
) -> AttackGraph:
    """
    Convenience wrapper: construct an :py:class:`AttackGraphBuilder` and build
    the graph in one call.
    """
    builder = AttackGraphBuilder()
    return builder.build(findings, entrypoints or [])


def build_exploit_chain(
    findings: List[Finding],
    entry_points: Optional[List[Any]] = None,
    reachability_paths: Optional[List[Any]] = None,
) -> AttackGraph:
    """
    Convenience wrapper: build a full exploit chain attack graph.

    Follows the pattern:
        HTTP Endpoint → Tainted Input → Vulnerability → Exploit Path → Asset
    """
    builder = AttackGraphBuilder()
    return builder.build_exploit_chain(findings, entry_points or [], reachability_paths)


# ---------------------------------------------------------------------------
# Incremental Attack Graph methods (Phase 6, Part 6)
# ---------------------------------------------------------------------------

import time as _ag_time


def _ag_update_findings(
    self: "AttackGraphBuilder",
    graph: AttackGraph,
    added_findings: List[Finding],
    removed_findings: List[Finding],
) -> int:
    """
    Update an existing AttackGraph incrementally.

    For removed findings:  remove their VULNERABILITY nodes and any edges/paths
                           that reference those nodes.
    For added findings:    add new VULNERABILITY nodes and re-score affected paths.

    Returns the count of attack paths that were recomputed.
    """
    recomputed = 0

    # Step 1: build set of IDs to remove
    remove_ids: set = set()
    for f in removed_findings:
        fid = getattr(f, "rule_id", None) or (f.get("rule_id") if isinstance(f, dict) else None)
        ffile = getattr(f, "file", None) or (f.get("file") if isinstance(f, dict) else None)
        for node in graph.nodes:
            props = node.properties
            if (node.type == NodeType.VULNERABILITY
                    and props.get("rule_id") == fid
                    and props.get("file") == ffile):
                remove_ids.add(node.node_id)

    if remove_ids:
        graph.nodes = [n for n in graph.nodes if n.node_id not in remove_ids]
        graph.edges = [e for e in graph.edges
                       if e.from_id not in remove_ids and e.to_id not in remove_ids]
        # Remove paths that traversed any removed node
        before = len(graph.critical_paths)
        graph.critical_paths = [
            p for p in graph.critical_paths
            if not any(nid in remove_ids for nid in p)
        ]
        recomputed += before - len(graph.critical_paths)

    # Step 2: add new VULNERABILITY nodes for added findings
    existing_node_ids = {n.node_id for n in graph.nodes}
    _sev_w = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25, "INFO": 0.1}

    for f in added_findings:
        if isinstance(f, dict):
            rule_id  = f.get("rule_id", f.get("type", "unknown"))
            severity = f.get("severity", "MEDIUM").upper()
            ffile    = f.get("file", "")
            desc     = f.get("description", rule_id)
        else:
            rule_id  = getattr(f, "rule_id", "unknown")
            severity = getattr(f, "severity", "MEDIUM").upper()
            ffile    = getattr(f, "file", "")
            desc     = getattr(f, "description", rule_id)

        nid = f"vuln::{rule_id}::{ffile}"
        if nid in existing_node_ids:
            continue

        prob = _sev_w.get(severity, 0.5)
        new_node = GraphNode(
            node_id=nid,
            type=NodeType.VULNERABILITY,
            label=f"{rule_id} ({severity})",
            properties={
                "rule_id":  rule_id,
                "severity": severity,
                "file":     ffile,
                "description": desc,
            },
        )
        graph.nodes.append(new_node)
        existing_node_ids.add(nid)

        # Connect Internet SOURCE → this VULNERABILITY
        for src_node in graph.nodes:
            if src_node.type == NodeType.SOURCE:
                graph.edges.append(GraphEdge(
                    from_id=src_node.node_id,
                    to_id=nid,
                    label="exposes",
                    probability=prob,
                    risk_weight=prob,
                ))
                break

        recomputed += 1

    # Step 3: recompute risk score from current state
    if added_findings or removed_findings:
        graph.risk_score = self.compute_risk_score(graph)

    return recomputed


def _ag_recompute_affected_paths(
    self: "AttackGraphBuilder",
    graph: AttackGraph,
    changed_node_ids: List[str],
) -> List[ScoredAttackPath]:
    """
    Recompute only attack paths that pass through any of *changed_node_ids*.
    Leaves unaffected paths untouched.

    Returns the list of recomputed ScoredAttackPath objects.
    """
    if not changed_node_ids:
        return []

    changed_set = set(changed_node_ids)
    recomputed: List[ScoredAttackPath] = []

    # Identify which critical_paths are affected
    affected_paths = [p for p in graph.critical_paths if any(n in changed_set for n in p)]
    unaffected     = [p for p in graph.critical_paths if p not in affected_paths]

    # Re-score each affected path
    node_map = {n.node_id: n for n in graph.nodes}
    for path_ids in affected_paths:
        path_nodes = [node_map[nid] for nid in path_ids if nid in node_map]
        if not path_nodes:
            continue
        scored = self._score_path(path_nodes, graph)   # type: ignore[attr-defined]
        if scored:
            recomputed.append(scored)

    # Rebuild critical_paths: keep unaffected + re-scored
    rescored_paths = [sp.path_nodes for sp in recomputed]
    graph.critical_paths = unaffected + rescored_paths
    graph.risk_score = self.compute_risk_score(graph)

    return recomputed


AttackGraphBuilder.update_findings          = _ag_update_findings          # type: ignore[attr-defined]
AttackGraphBuilder.recompute_affected_paths = _ag_recompute_affected_paths # type: ignore[attr-defined]
