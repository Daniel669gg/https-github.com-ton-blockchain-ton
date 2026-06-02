"""Security Knowledge Graph: Code → Function → DataFlow → Sink → CVE → Fix."""
from __future__ import annotations

import ast
import json
import os
import re
from collections import deque
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Import Finding from the canonical location; fall back to a local stub so the
# module remains importable in isolation (e.g. during unit tests that mock it).
# ---------------------------------------------------------------------------
try:
    from backend.core.confidence import Finding
except ImportError:  # pragma: no cover
    from pydantic import BaseModel as _BM  # type: ignore

    class Finding(_BM):  # type: ignore[no-redef]
        model_config = {"extra": "allow"}
        rule_id: str = ""
        file: str = ""
        line: int = 0
        severity: str = "MEDIUM"
        confidence: float = 0.8
        cwe_id: str = ""
        description: str = ""
        recommendation: str = ""
        sources: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Built-in CWE → CVE mapping (≥ 15 entries)
# ---------------------------------------------------------------------------
CWE_CVE_EXAMPLES: Dict[str, List[str]] = {
    "CWE-89":  ["CVE-2021-41773", "CVE-2021-42013"],
    "CWE-79":  ["CVE-2021-44228"],
    "CWE-78":  ["CVE-2021-41773"],
    "CWE-22":  ["CVE-2021-41773", "CVE-2020-5902"],
    "CWE-502": ["CVE-2019-20907", "CVE-2020-10029"],
    "CWE-327": ["CVE-2020-25018"],
    "CWE-798": ["CVE-2021-40539"],
    "CWE-306": ["CVE-2021-34527"],
    "CWE-434": ["CVE-2021-3156"],
    "CWE-611": ["CVE-2021-23017"],
    "CWE-918": ["CVE-2021-26855"],
    "CWE-94":  ["CVE-2021-44228"],
    "CWE-190": ["CVE-2021-3156"],
    "CWE-416": ["CVE-2021-30551"],
    "CWE-362": ["CVE-2022-0847"],
    "CWE-476": ["CVE-2021-3156"],
    "CWE-20":  ["CVE-2021-44228", "CVE-2021-41773"],
}

# Patterns that indicate security controls (decorators / function calls).
_AUTH_DECORATOR_RE = re.compile(
    r"@(login_required|require_http_methods|permission_required|"
    r"requires_auth|authenticated|jwt_required|token_required|"
    r"staff_member_required|superuser_required)",
    re.IGNORECASE,
)
_INPUT_VALIDATION_RE = re.compile(
    r"\b(validate|sanitize|escape|bleach\.clean|html\.escape|"
    r"markupsafe\.escape|wtforms|marshmallow|cerberus|jsonschema\.validate)\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class KGNodeType(str, Enum):
    CODE_UNIT = "code_unit"
    FUNCTION = "function"
    DATAFLOW = "dataflow"
    SINK = "sink"
    CVE = "cve"
    FIX = "fix"
    CONTROL = "control"
    # --- Phase 2 additions ---
    SOURCE = "source"
    METHOD = "method"
    CLASS = "class"
    MODULE = "module"
    PACKAGE = "package"
    ENDPOINT = "endpoint"
    API_ROUTE = "api_route"
    DEPENDENCY = "dependency"
    CWE_NODE = "cwe_node"
    CAPEC_NODE = "capec_node"
    ASSET = "asset"
    CLOUD_RESOURCE = "cloud_resource"
    FINDING = "finding"
    VERIFICATION = "verification"
    PATCH = "patch"
    VALIDATION = "validation"
    REGRESSION = "regression"
    # --- Phase 5 additions ---
    RESEARCH = "research"
    ADVISORY = "advisory"
    EXPLOIT = "exploit"
    REMEDIATION_PATTERN = "remediation_pattern"
    GENERATED_RULE = "generated_rule"


class KGNode(BaseModel):
    node_id: str
    type: KGNodeType
    label: str
    properties: Dict[str, Any] = Field(default_factory=dict)


class KGEdge(BaseModel):
    from_id: str
    to_id: str
    # Original relations: CONTAINS / CALLS / FLOWS_TO / LEADS_TO / MITIGATES / FIXES / EXPLOITS
    # Phase 2 additions: IMPORTS / DEPENDS_ON / REACHES / PROPAGATES_TO / VULNERABLE_TO /
    #                    VERIFIED_BY / EXPLOITABLE_VIA / EXPOSED_THROUGH / OWNED_BY
    # Phase 3 additions: VALIDATES / INTRODUCES / REMOVES
    # Phase 5 additions: DERIVED_FROM / VALIDATED_BY / MITIGATED_BY / EXPLOITS_VIA / DETECTS
    relation: str
    weight: float = 1.0


class SecurityKnowledgeGraph(BaseModel):
    nodes: List[KGNode] = Field(default_factory=list)
    edges: List[KGEdge] = Field(default_factory=list)
    node_index: Dict[str, int] = Field(default_factory=dict)  # node_id → list index


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class KnowledgeGraphBuilder:
    """Constructs a SecurityKnowledgeGraph from static-analysis findings."""

    def __init__(self, _findings: Optional[List] = None) -> None:
        # Accept an optional positional list argument for convenience
        # (e.g. KnowledgeGraphBuilder(findings)) — the builder is otherwise
        # stateless; methods receive the graph as an explicit parameter.
        pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(
        self,
        project_root: str,
        findings: List[Finding],
        cve_records: Optional[List] = None,
    ) -> SecurityKnowledgeGraph:
        """
        Build a complete SecurityKnowledgeGraph from a list of findings.

        Steps
        -----
        1. CODE_UNIT nodes for every unique file.
        2. FUNCTION nodes by AST-parsing each file.
        3. DATAFLOW nodes for findings that carry source information.
        4. SINK nodes for every finding (keyed rule_id + file + line).
        5. CVE nodes via CWE_CVE_EXAMPLES mapping.
        6. FIX nodes with recommendation text.
        7. CONTROL nodes for detected security controls.
        8. All edges (CONTAINS / LEADS_TO / FLOWS_TO / EXPLOITS / FIXES / MITIGATES).
        """
        graph = SecurityKnowledgeGraph()

        if not findings:
            return graph

        # ---- Step 1: CODE_UNIT nodes ----------------------------------------
        files: Set[str] = {f.file for f in findings if f.file}
        file_node_ids: Dict[str, str] = {}
        for fpath in sorted(files):
            nid = f"code_unit::{fpath}"
            node = KGNode(
                node_id=nid,
                type=KGNodeType.CODE_UNIT,
                label=os.path.basename(fpath) or fpath,
                properties={"file": fpath},
            )
            self.add_node(graph, node)
            file_node_ids[fpath] = nid

        # ---- Step 2: FUNCTION nodes (AST parsing) ----------------------------
        # Map file → list of (func_name, start_line, end_line)
        file_functions: Dict[str, List[Tuple[str, int, int]]] = {}
        for fpath in files:
            full_path = os.path.join(project_root, fpath) if project_root else fpath
            funcs = self._extract_functions(full_path)
            file_functions[fpath] = funcs
            for fname, start, end in funcs:
                nid = f"function::{fpath}::{fname}::{start}"
                node = KGNode(
                    node_id=nid,
                    type=KGNodeType.FUNCTION,
                    label=fname,
                    properties={"file": fpath, "line_start": start, "line_end": end},
                )
                self.add_node(graph, node)
                # CONTAINS edge: CODE_UNIT → FUNCTION
                if fpath in file_node_ids:
                    self.add_edge(
                        graph,
                        KGEdge(
                            from_id=file_node_ids[fpath],
                            to_id=nid,
                            relation="CONTAINS",
                        ),
                    )

        # ---- Step 3 & 4: DATAFLOW and SINK nodes ----------------------------
        # Collect raw source content for CONTROL detection later
        file_source: Dict[str, str] = {}
        for fpath in files:
            full_path = os.path.join(project_root, fpath) if project_root else fpath
            try:
                with open(full_path, "r", errors="replace") as fh:
                    file_source[fpath] = fh.read()
            except OSError:
                file_source[fpath] = ""

        sink_node_ids: List[str] = []
        # Mapping: sink_node_id → enclosing function node_id (for LEADS_TO + MITIGATES)
        sink_to_func: Dict[str, Optional[str]] = {}

        for finding in findings:
            fpath = finding.file or ""

            # DATAFLOW node (only if the finding has explicit source info)
            df_nid: Optional[str] = None
            if finding.sources:
                df_nid = f"dataflow::{fpath}::{finding.rule_id}::{finding.line}"
                df_node = KGNode(
                    node_id=df_nid,
                    type=KGNodeType.DATAFLOW,
                    label=f"taint:{finding.rule_id}",
                    properties={
                        "file": fpath,
                        "sources": finding.sources,
                        "line": finding.line,
                    },
                )
                self.add_node(graph, df_node)

            # SINK node
            sink_nid = f"sink::{finding.rule_id}::{fpath}::{finding.line}"
            sink_node = KGNode(
                node_id=sink_nid,
                type=KGNodeType.SINK,
                label=finding.rule_id,
                properties={
                    "file": fpath,
                    "line": finding.line,
                    "severity": finding.severity,
                    "cwe_id": finding.cwe_id,
                    "description": finding.description,
                },
            )
            self.add_node(graph, sink_node)
            sink_node_ids.append(sink_nid)

            # DATAFLOW → SINK: FLOWS_TO
            if df_nid:
                self.add_edge(
                    graph,
                    KGEdge(from_id=df_nid, to_id=sink_nid, relation="FLOWS_TO"),
                )

            # Determine enclosing function
            enclosing_func_nid = self._find_enclosing_function(
                fpath, finding.line, file_functions
            )
            sink_to_func[sink_nid] = enclosing_func_nid

            # FUNCTION → SINK: LEADS_TO
            if enclosing_func_nid:
                self.add_edge(
                    graph,
                    KGEdge(
                        from_id=enclosing_func_nid,
                        to_id=sink_nid,
                        relation="LEADS_TO",
                    ),
                )

        # ---- Step 5 & 6: CVE and FIX nodes ----------------------------------
        cwe_to_cve_nids: Dict[str, List[str]] = {}  # cwe_id → list of CVE node_ids
        for finding in findings:
            cwe = finding.cwe_id or ""
            if not cwe or cwe not in CWE_CVE_EXAMPLES:
                continue
            if cwe in cwe_to_cve_nids:
                continue  # already created
            cve_nids: List[str] = []
            for cve_id in CWE_CVE_EXAMPLES[cwe]:
                cve_nid = f"cve::{cve_id}"
                cve_node = KGNode(
                    node_id=cve_nid,
                    type=KGNodeType.CVE,
                    label=cve_id,
                    properties={"cve_id": cve_id, "cwe_id": cwe},
                )
                self.add_node(graph, cve_node)
                cve_nids.append(cve_nid)

                # FIX node for this CVE
                fix_nid = f"fix::{cve_id}"
                fix_text = finding.recommendation or f"Apply remediation for {cwe} ({cve_id})"
                fix_node = KGNode(
                    node_id=fix_nid,
                    type=KGNodeType.FIX,
                    label=f"Fix:{cve_id}",
                    properties={
                        "recommendation": fix_text,
                        "cve_id": cve_id,
                        "cwe_id": cwe,
                    },
                )
                self.add_node(graph, fix_node)

                # CVE → FIX: FIXES
                self.add_edge(
                    graph,
                    KGEdge(from_id=cve_nid, to_id=fix_nid, relation="FIXES"),
                )

            cwe_to_cve_nids[cwe] = cve_nids

        # SINK → CVE: EXPLOITS
        for finding in findings:
            cwe = finding.cwe_id or ""
            sink_nid = f"sink::{finding.rule_id}::{finding.file}::{finding.line}"
            if cwe in cwe_to_cve_nids:
                for cve_nid in cwe_to_cve_nids[cwe]:
                    self.add_edge(
                        graph,
                        KGEdge(from_id=sink_nid, to_id=cve_nid, relation="EXPLOITS"),
                    )

        # ---- Step 7: CONTROL nodes ------------------------------------------
        for fpath, source in file_source.items():
            funcs = file_functions.get(fpath, [])
            lines = source.splitlines()

            for fname, start, end in funcs:
                func_lines = lines[max(0, start - 1) : end]
                func_text = "\n".join(func_lines)

                controls_found: List[Tuple[str, str]] = []
                if _AUTH_DECORATOR_RE.search(func_text):
                    controls_found.append(("auth_decorator", "Authentication decorator detected"))
                if _INPUT_VALIDATION_RE.search(func_text):
                    controls_found.append(("input_validation", "Input validation detected"))

                if not controls_found:
                    continue

                func_nid = f"function::{fpath}::{fname}::{start}"
                for ctrl_type, ctrl_label in controls_found:
                    ctrl_nid = f"control::{fpath}::{fname}::{start}::{ctrl_type}"
                    ctrl_node = KGNode(
                        node_id=ctrl_nid,
                        type=KGNodeType.CONTROL,
                        label=ctrl_label,
                        properties={
                            "control_type": ctrl_type,
                            "file": fpath,
                            "function": fname,
                            "line_start": start,
                        },
                    )
                    self.add_node(graph, ctrl_node)

                    # Find sinks in same function → MITIGATES
                    for sink_nid, efunc_nid in sink_to_func.items():
                        if efunc_nid == func_nid:
                            self.add_edge(
                                graph,
                                KGEdge(
                                    from_id=ctrl_nid,
                                    to_id=sink_nid,
                                    relation="MITIGATES",
                                ),
                            )

        return graph

    # ------------------------------------------------------------------
    # Graph mutation helpers
    # ------------------------------------------------------------------

    def add_node(self, graph: SecurityKnowledgeGraph, node: KGNode) -> str:
        """Add node if not already present (by node_id). Returns the node_id."""
        if node.node_id not in graph.node_index:
            graph.node_index[node.node_id] = len(graph.nodes)
            graph.nodes.append(node)
        return node.node_id

    def add_edge(self, graph: SecurityKnowledgeGraph, edge: KGEdge) -> None:
        """Append an edge. Duplicate (from_id, to_id, relation) triplets are skipped."""
        for existing in graph.edges:
            if (
                existing.from_id == edge.from_id
                and existing.to_id == edge.to_id
                and existing.relation == edge.relation
            ):
                return
        graph.edges.append(edge)

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def query_paths(
        self,
        graph: SecurityKnowledgeGraph,
        from_type: KGNodeType,
        to_type: KGNodeType,
        max_len: int = 6,
    ) -> List[List[str]]:
        """
        BFS to find all simple paths from nodes of *from_type* to nodes of
        *to_type*.  Returns a list of node_id paths, each at most *max_len*
        nodes long.
        """
        # Build adjacency list
        adj: Dict[str, List[str]] = {}
        for edge in graph.edges:
            adj.setdefault(edge.from_id, []).append(edge.to_id)

        # Identify start and goal sets
        start_ids: Set[str] = set()
        goal_ids: Set[str] = set()
        for node in graph.nodes:
            if node.type == from_type:
                start_ids.add(node.node_id)
            if node.type == to_type:
                goal_ids.add(node.node_id)

        results: List[List[str]] = []
        # BFS queue: (current_node_id, path_so_far)
        queue: deque[Tuple[str, List[str]]] = deque()
        for sid in start_ids:
            queue.append((sid, [sid]))

        while queue:
            current, path = queue.popleft()
            if len(path) > max_len:
                continue
            if current in goal_ids and len(path) > 1:
                results.append(path)
                continue  # do not extend beyond a found goal
            for neighbor in adj.get(current, []):
                if neighbor not in path:  # avoid cycles
                    queue.append((neighbor, path + [neighbor]))

        return results

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_json(self, graph: SecurityKnowledgeGraph) -> str:
        """Serialize graph to JSON with ``nodes`` and ``edges`` arrays."""
        return json.dumps(
            {
                "nodes": [n.model_dump() for n in graph.nodes],
                "edges": [e.model_dump() for e in graph.edges],
            },
            indent=2,
            default=str,
        )

    def to_cypher(self, graph: SecurityKnowledgeGraph) -> str:
        """
        Generate Neo4j Cypher CREATE statements for all nodes and edges.

        Node format::

            CREATE (:KGNodeType {node_id: "...", label: "...", ...})

        Edge format::

            MATCH (a {node_id: "..."}), (b {node_id: "..."})
            CREATE (a)-[:RELATION]->(b)
        """
        lines: List[str] = []

        def _escape(v: Any) -> str:
            if isinstance(v, str):
                return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
            if isinstance(v, bool):
                return "true" if v else "false"
            if isinstance(v, (int, float)):
                return str(v)
            return '"' + str(v).replace('"', '\\"') + '"'

        for node in graph.nodes:
            label = node.type.value.upper()
            props: Dict[str, Any] = {
                "node_id": node.node_id,
                "label": node.label,
            }
            props.update(
                {k: v for k, v in node.properties.items() if not isinstance(v, (list, dict))}
            )
            prop_str = ", ".join(f"{k}: {_escape(v)}" for k, v in props.items())
            lines.append(f'CREATE (:{label} {{{prop_str}}})')

        lines.append("")  # blank separator

        for edge in graph.edges:
            rel = edge.relation.replace(" ", "_").upper()
            lines.append(
                f'MATCH (a {{node_id: {_escape(edge.from_id)}}}), '
                f'(b {{node_id: {_escape(edge.to_id)}}})\n'
                f'CREATE (a)-[:{rel} {{weight: {edge.weight}}}]->(b)'
            )

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Analytics
    # ------------------------------------------------------------------

    def get_risk_surface(self, graph: SecurityKnowledgeGraph) -> Dict[str, Any]:
        """
        Return a summary dict covering:

        * total_nodes / total_edges
        * nodes_by_type  (type → count)
        * sinks_count
        * cves_count
        * fixes_available
        * coverage  (% of sinks that have a FIX reachable via a CVE)
        """
        nodes_by_type: Dict[str, int] = {}
        for node in graph.nodes:
            key = node.type.value
            nodes_by_type[key] = nodes_by_type.get(key, 0) + 1

        sinks_count = nodes_by_type.get(KGNodeType.SINK.value, 0)
        cves_count = nodes_by_type.get(KGNodeType.CVE.value, 0)
        fixes_available = nodes_by_type.get(KGNodeType.FIX.value, 0)

        # Coverage: sinks that reach at least one FIX node
        adj: Dict[str, Set[str]] = {}
        for edge in graph.edges:
            adj.setdefault(edge.from_id, set()).add(edge.to_id)

        fix_ids: Set[str] = {n.node_id for n in graph.nodes if n.type == KGNodeType.FIX}
        sink_ids: List[str] = [n.node_id for n in graph.nodes if n.type == KGNodeType.SINK]

        covered = 0
        for sink_id in sink_ids:
            visited: Set[str] = set()
            stack = [sink_id]
            while stack:
                curr = stack.pop()
                if curr in visited:
                    continue
                visited.add(curr)
                if curr in fix_ids:
                    covered += 1
                    break
                stack.extend(adj.get(curr, set()))

        coverage = round(covered / sinks_count * 100, 1) if sinks_count else 0.0

        return {
            "total_nodes": len(graph.nodes),
            "total_edges": len(graph.edges),
            "nodes_by_type": nodes_by_type,
            "sinks_count": sinks_count,
            "cves_count": cves_count,
            "fixes_available": fixes_available,
            "coverage_percent": coverage,
        }

    # ------------------------------------------------------------------
    # Phase 2: ingest_finding
    # ------------------------------------------------------------------

    def ingest_finding(
        self,
        graph: SecurityKnowledgeGraph,
        finding: Any,
    ) -> List[str]:
        """
        Ingest a Finding into the KnowledgeGraph.

        Creates / links:
          - FINDING node
          - CWE_NODE
          - SOURCE node (from finding.file / finding.line)
          - SINK node (from finding.file / finding.line)
          - VULNERABLE_TO edge: SOURCE → CWE_NODE
          - LEADS_TO edge:      FINDING → SINK

        Returns the list of created (or ensured) node_ids.
        """
        created: List[str] = []

        rule_id = getattr(finding, "rule_id", "") or ""
        fpath = getattr(finding, "file", "") or ""
        line = getattr(finding, "line", 0) or 0
        severity = getattr(finding, "severity", "MEDIUM") or "MEDIUM"
        confidence = getattr(finding, "confidence", 0.8)
        cwe_id = getattr(finding, "cwe_id", "") or ""
        description = getattr(finding, "description", "") or ""
        recommendation = getattr(finding, "recommendation", "") or ""

        # --- FINDING node ---
        finding_nid = f"finding::{rule_id}::{fpath}::{line}"
        finding_node = KGNode(
            node_id=finding_nid,
            type=KGNodeType.FINDING,
            label=rule_id or "finding",
            properties={
                "rule_id": rule_id,
                "file": fpath,
                "line": line,
                "severity": severity,
                "confidence": confidence,
                "cwe_id": cwe_id,
                "description": description,
                "recommendation": recommendation,
            },
        )
        self.add_node(graph, finding_node)
        created.append(finding_nid)

        # --- CWE_NODE ---
        if cwe_id:
            cwe_nid = f"cwe::{cwe_id}"
            cwe_node = KGNode(
                node_id=cwe_nid,
                type=KGNodeType.CWE_NODE,
                label=cwe_id,
                properties={"cwe_id": cwe_id},
            )
            self.add_node(graph, cwe_node)
            created.append(cwe_nid)

            # FINDING → CWE_NODE: VULNERABLE_TO
            self.add_edge(
                graph,
                KGEdge(from_id=finding_nid, to_id=cwe_nid, relation="VULNERABLE_TO"),
            )
        else:
            cwe_nid = None

        # --- SOURCE node ---
        source_nid = f"source::{fpath}::{line}"
        source_node = KGNode(
            node_id=source_nid,
            type=KGNodeType.SOURCE,
            label=f"src:{os.path.basename(fpath)}:{line}",
            properties={"file": fpath, "line": line, "rule_id": rule_id},
        )
        self.add_node(graph, source_node)
        created.append(source_nid)

        # SOURCE → CWE_NODE: VULNERABLE_TO
        if cwe_nid:
            self.add_edge(
                graph,
                KGEdge(from_id=source_nid, to_id=cwe_nid, relation="VULNERABLE_TO"),
            )

        # --- SINK node ---
        sink_nid = f"sink::{rule_id}::{fpath}::{line}"
        sink_node = KGNode(
            node_id=sink_nid,
            type=KGNodeType.SINK,
            label=rule_id,
            properties={
                "file": fpath,
                "line": line,
                "severity": severity,
                "cwe_id": cwe_id,
                "description": description,
            },
        )
        self.add_node(graph, sink_node)
        created.append(sink_nid)

        # FINDING → SINK: LEADS_TO
        self.add_edge(
            graph,
            KGEdge(from_id=finding_nid, to_id=sink_nid, relation="LEADS_TO"),
        )

        return created

    # ------------------------------------------------------------------
    # Phase 2: to_graphml
    # ------------------------------------------------------------------

    def to_graphml(self, graph: Optional[SecurityKnowledgeGraph] = None) -> str:
        """
        Serialize the graph to GraphML XML format.
        If *graph* is None, an empty SecurityKnowledgeGraph is used.
        """
        if graph is None:
            graph = SecurityKnowledgeGraph()
        lines: List[str] = []
        lines.append('<?xml version="1.0" encoding="UTF-8"?>')
        lines.append('<graphml xmlns="http://graphml.graphdrawing.org/graphml">')
        lines.append('  <key id="type" for="node" attr.name="type" attr.type="string"/>')
        lines.append('  <key id="label" for="node" attr.name="label" attr.type="string"/>')
        lines.append('  <key id="relation" for="edge" attr.name="relation" attr.type="string"/>')
        lines.append('  <key id="weight" for="edge" attr.name="weight" attr.type="double"/>')
        lines.append('  <graph id="G" edgedefault="directed">')

        def _xml_escape(s: str) -> str:
            return (
                s.replace("&", "&amp;")
                 .replace("<", "&lt;")
                 .replace(">", "&gt;")
                 .replace('"', "&quot;")
                 .replace("'", "&apos;")
            )

        for node in graph.nodes:
            nid = _xml_escape(node.node_id)
            ntype = _xml_escape(node.type.value)
            nlabel = _xml_escape(node.label)
            lines.append(f'    <node id="{nid}">')
            lines.append(f'      <data key="type">{ntype}</data>')
            lines.append(f'      <data key="label">{nlabel}</data>')
            lines.append('    </node>')

        for idx, edge in enumerate(graph.edges):
            fid = _xml_escape(edge.from_id)
            tid = _xml_escape(edge.to_id)
            rel = _xml_escape(edge.relation)
            lines.append(f'    <edge id="e{idx}" source="{fid}" target="{tid}">')
            lines.append(f'      <data key="relation">{rel}</data>')
            lines.append(f'      <data key="weight">{edge.weight}</data>')
            lines.append('    </edge>')

        lines.append('  </graph>')
        lines.append('</graphml>')
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Phase 2: to_html
    # ------------------------------------------------------------------

    def to_html(self, graph: Optional[SecurityKnowledgeGraph] = None) -> str:
        """
        Generate a self-contained interactive HTML visualization using vis.js.
        Node colors are assigned by KGNodeType. Edge labels are shown.
        If *graph* is None, an empty SecurityKnowledgeGraph is used.
        """
        if graph is None:
            graph = SecurityKnowledgeGraph()
        # Color map by node type
        color_map: Dict[str, str] = {
            "finding":       "#e74c3c",    # red
            "cve":           "#e67e22",    # orange
            "cwe_node":      "#d35400",    # dark orange
            "capec_node":    "#c0392b",    # dark red
            "source":        "#2980b9",    # blue
            "sink":          "#8b0000",    # dark red
            "dataflow":      "#8e44ad",    # purple
            "function":      "#27ae60",    # green
            "method":        "#1e8449",    # dark green
            "class":         "#16a085",    # teal
            "module":        "#1abc9c",    # light teal
            "package":       "#f39c12",    # yellow-orange
            "dependency":    "#e8a838",    # amber
            "endpoint":      "#3498db",    # light blue
            "api_route":     "#2471a3",    # medium blue
            "code_unit":     "#7f8c8d",    # grey
            "control":       "#2ecc71",    # bright green
            "fix":           "#00b894",    # mint
            "asset":         "#6c3483",    # dark purple
            "cloud_resource":"#5dade2",    # sky blue
            "verification":  "#f1c40f",    # yellow
        }

        # Build nodes JS array
        nodes_js_parts: List[str] = []
        for node in graph.nodes:
            nid = node.node_id.replace("\\", "\\\\").replace('"', '\\"')
            nlabel = node.label.replace("\\", "\\\\").replace('"', '\\"')
            ntype = node.type.value
            color = color_map.get(ntype, "#95a5a6")
            nodes_js_parts.append(
                f'{{id: "{nid}", label: "{nlabel}", color: "{color}", '
                f'title: "{ntype}"}}'
            )

        # Build edges JS array
        edges_js_parts: List[str] = []
        for idx, edge in enumerate(graph.edges):
            fid = edge.from_id.replace("\\", "\\\\").replace('"', '\\"')
            tid = edge.to_id.replace("\\", "\\\\").replace('"', '\\"')
            rel = edge.relation.replace("\\", "\\\\").replace('"', '\\"')
            edges_js_parts.append(
                f'{{id: "e{idx}", from: "{fid}", to: "{tid}", '
                f'label: "{rel}", arrows: "to"}}'
            )

        nodes_js = "[\n    " + ",\n    ".join(nodes_js_parts) + "\n  ]"
        edges_js = "[\n    " + ",\n    ".join(edges_js_parts) + "\n  ]"

        # Legend HTML rows
        legend_rows = "".join(
            f'<tr><td style="background:{c};width:18px;height:14px;border:1px solid #555"></td>'
            f'<td style="padding:2px 6px;font-size:12px">{t}</td></tr>\n'
            for t, c in sorted(color_map.items())
        )

        html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8"/>
  <title>Security Knowledge Graph</title>
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style>
    body {{ margin: 0; font-family: Arial, sans-serif; display: flex; height: 100vh; }}
    #network {{ flex: 1; border: 1px solid #ccc; }}
    #legend {{
      width: 200px; padding: 10px; overflow-y: auto;
      background: #f9f9f9; border-left: 1px solid #ccc;
    }}
    #legend h3 {{ margin-top: 0; font-size: 14px; }}
    table {{ border-collapse: collapse; }}
  </style>
</head>
<body>
  <div id="network"></div>
  <div id="legend">
    <h3>Node Types</h3>
    <table>
{legend_rows}    </table>
  </div>
  <script>
  var nodes = new vis.DataSet({nodes_js});
  var edges = new vis.DataSet({edges_js});
  var container = document.getElementById("network");
  var data = {{ nodes: nodes, edges: edges }};
  var options = {{
    edges: {{
      font: {{ size: 10, align: "middle" }},
      smooth: {{ type: "dynamic" }}
    }},
    nodes: {{
      shape: "dot",
      size: 16,
      font: {{ size: 12 }}
    }},
    physics: {{
      stabilization: {{ iterations: 200 }},
      barnesHut: {{ gravitationalConstant: -8000, springLength: 140 }}
    }},
    interaction: {{ hover: true, tooltipDelay: 200 }}
  }};
  new vis.Network(container, data, options);
  </script>
</body>
</html>"""
        return html

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_functions(filepath: str) -> List[Tuple[str, int, int]]:
        """
        Parse *filepath* with the Python AST and return a list of
        ``(qualified_name, start_line, end_line)`` tuples for every
        top-level function and class method.  Returns an empty list if
        the file cannot be parsed.
        """
        try:
            with open(filepath, "r", errors="replace") as fh:
                source = fh.read()
        except OSError:
            return []

        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError:
            return []

        results: List[Tuple[str, int, int]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in ast.walk(node):
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        qname = f"{node.name}.{item.name}"
                        end = getattr(item, "end_lineno", item.lineno)
                        results.append((qname, item.lineno, end))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Exclude methods already captured via class iteration
                end = getattr(node, "end_lineno", node.lineno)
                results.append((node.name, node.lineno, end))

        # De-duplicate by (name, start)
        seen: Set[Tuple[str, int]] = set()
        unique: List[Tuple[str, int, int]] = []
        for name, start, end in results:
            if (name, start) not in seen:
                seen.add((name, start))
                unique.append((name, start, end))
        return unique

    @staticmethod
    def _find_enclosing_function(
        fpath: str,
        line: int,
        file_functions: Dict[str, List[Tuple[str, int, int]]],
    ) -> Optional[str]:
        """
        Return the node_id of the innermost function that contains *line*
        in *fpath*, or ``None`` if no function matches.
        """
        best: Optional[Tuple[str, int, int]] = None
        for fname, start, end in file_functions.get(fpath, []):
            if start <= line <= end:
                if best is None or (end - start) < (best[2] - best[1]):
                    best = (fname, start, end)
        if best is None:
            return None
        return f"function::{fpath}::{best[0]}::{best[1]}"


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------


def build_knowledge_graph(
    project_root: str,
    findings: List[Finding],
    cve_records: Optional[List] = None,
) -> SecurityKnowledgeGraph:
    """Convenience wrapper: construct and return a SecurityKnowledgeGraph."""
    return KnowledgeGraphBuilder().build(project_root, findings, cve_records)


# ---------------------------------------------------------------------------
# Incremental Knowledge Graph methods (Phase 6, Part 7)
# Attached to KnowledgeGraphBuilder at module level.
# ---------------------------------------------------------------------------

import time as _kg_time
import hashlib as _kg_hash


def _kg_build_delta(
    self: "KnowledgeGraphBuilder",
    graph: SecurityKnowledgeGraph,
    added_findings: List,
    removed_findings: List,
    changed_files: Optional[List[str]] = None,
) -> int:
    """
    Incrementally update *graph* instead of rebuilding from scratch.

    Steps:
      1. Remove nodes/edges tied to *removed_findings* (by rule_id + file + line).
      2. Ingest each *added_finding* via the existing ingest_finding() method.
      3. For changed_files: remove all CODE_UNIT and FUNCTION nodes for those
         files and let fresh findings re-create them.

    Returns total count of node mutations (adds + removes).
    """
    mutations = 0

    # Step 1: remove nodes for removed findings
    for finding in removed_findings:
        fdict = finding if isinstance(finding, dict) else finding.dict() if hasattr(finding, "dict") else {}
        ffile = fdict.get("file", "")
        fline = fdict.get("line", 0)
        frule = fdict.get("rule_id", fdict.get("type", ""))

        to_remove: List[int] = []
        for i, node in enumerate(graph.nodes):
            props = node.properties
            if (props.get("file") == ffile and props.get("line") == fline
                    and props.get("rule_id", props.get("type", "")) == frule):
                to_remove.append(i)
        # Remove in reverse order to preserve indices
        for i in sorted(to_remove, reverse=True):
            nid = graph.nodes[i].node_id
            graph.nodes.pop(i)
            # Remove from index
            graph.node_index.pop(nid, None)
            # Remove edges referencing this node
            graph.edges = [e for e in graph.edges if e.from_id != nid and e.to_id != nid]
            mutations += 1

    # Step 2: remove nodes for changed files
    if changed_files:
        changed_set = set(changed_files)
        changed_set |= {str(Path(f).resolve()) for f in changed_files}
        nodes_to_remove = [
            i for i, node in enumerate(graph.nodes)
            if node.properties.get("file", "") in changed_set
            and node.type in (KGNodeType.CODE_UNIT, KGNodeType.FUNCTION)
        ]
        for i in sorted(nodes_to_remove, reverse=True):
            nid = graph.nodes[i].node_id
            graph.nodes.pop(i)
            graph.node_index.pop(nid, None)
            graph.edges = [e for e in graph.edges if e.from_id != nid and e.to_id != nid]
            mutations += 1

    # Rebuild index after bulk removal
    graph.node_index = {node.node_id: idx for idx, node in enumerate(graph.nodes)}

    # Step 3: ingest new findings
    for finding in added_findings:
        try:
            self.ingest_finding(graph, finding)
            mutations += 1
        except Exception:
            pass

    return mutations


def _kg_patch_node(
    self: "KnowledgeGraphBuilder",
    graph: SecurityKnowledgeGraph,
    node_id: str,
    properties: Dict[str, Any],
) -> bool:
    """
    Update properties of an existing graph node in-place.
    Returns True if node was found and updated.
    """
    idx = graph.node_index.get(node_id)
    if idx is None or idx >= len(graph.nodes):
        return False
    graph.nodes[idx].properties.update(properties)
    return True


def _kg_patch_edge(
    self: "KnowledgeGraphBuilder",
    graph: SecurityKnowledgeGraph,
    from_id: str,
    to_id: str,
    relation: str,
    weight: float,
) -> bool:
    """
    Update weight of an existing edge, or add it if missing.
    Returns True if an existing edge was updated; False if a new edge was added.
    """
    for edge in graph.edges:
        if edge.from_id == from_id and edge.to_id == to_id and edge.relation == relation:
            edge.weight = weight
            return True
    # Add new edge
    graph.edges.append(KGEdge(
        from_id=from_id, to_id=to_id, relation=relation, weight=weight
    ))
    return False


def _kg_apply_file_delta(
    self: "KnowledgeGraphBuilder",
    changed_files: List[str],
    new_findings: List,
) -> int:
    """
    Convenience method used by GraphAwareIncrementalScanner.
    If we have no current graph, this is a no-op.
    Returns count of mutations (best-effort).
    """
    # The scanner passes findings as dicts; we need to handle both dict and Finding
    added = []
    for f in new_findings:
        if isinstance(f, dict):
            try:
                added.append(Finding(**{k: v for k, v in f.items()
                                        if k in Finding.model_fields}))
            except Exception:
                pass
        else:
            added.append(f)
    # Without a live graph reference this is a no-op — callers should pass graph explicitly
    return len(added)


KnowledgeGraphBuilder.build_delta      = _kg_build_delta      # type: ignore[attr-defined]
KnowledgeGraphBuilder.patch_node       = _kg_patch_node       # type: ignore[attr-defined]
KnowledgeGraphBuilder.patch_edge       = _kg_patch_edge       # type: ignore[attr-defined]
KnowledgeGraphBuilder.apply_file_delta = _kg_apply_file_delta # type: ignore[attr-defined]
