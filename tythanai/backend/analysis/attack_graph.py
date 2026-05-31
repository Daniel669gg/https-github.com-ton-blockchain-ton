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
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from backend.core.confidence import Finding

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


class AttackGraph(BaseModel):
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    critical_paths: List[List[str]] = Field(default_factory=list)  # list of node_id paths
    risk_score: float = 0.0


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

            # Connect from an entrypoint (or internet if no entrypoints)
            source_id = self._best_source_for_finding(finding, entrypoints, ep_ids)
            graph.edges.append(
                GraphEdge(
                    from_id=source_id,
                    to_id=fid,
                    label="triggers",
                    probability=round(conf * 0.9, 4),
                )
            )

            # Connect finding → asset
            if asset_id:
                graph.edges.append(
                    GraphEdge(
                        from_id=fid,
                        to_id=asset_id,
                        label="exposes",
                        probability=round(conf, 4),
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
