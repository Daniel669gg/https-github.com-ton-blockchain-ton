"""
backend/core/cpg/query_engine.py — Graph query engine for vulnerability detection.

Provides typed queries over a CodePropertyGraph for:
  - Taint source → sink path detection
  - SQL injection patterns (string concat in execute() call)
  - Command injection (os.system/subprocess with tainted args)
  - Path traversal
  - Hardcoded secrets
  - Privilege escalation paths
  - Cross-function taint flows
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .graph import (
    CPGEdgeType,
    CPGNode,
    CPGNodeType,
    CodePropertyGraph,
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class TaintPath:
    """A discovered source-to-sink taint flow."""
    src_node:   CPGNode
    dst_node:   CPGNode
    path:       List[CPGNode]        # ordered list of CPGNodes from source to sink
    confidence: float                # 0.0 – 1.0
    sink_type:  str                  # e.g. "sql_injection", "command_injection"
    vuln_desc:  str = ""
    file:       str = ""
    line:       int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_node":   self.src_node.to_dict(),
            "dst_node":   self.dst_node.to_dict(),
            "path":       [n.to_dict() for n in self.path],
            "confidence": self.confidence,
            "sink_type":  self.sink_type,
            "vuln_desc":  self.vuln_desc,
            "file":       self.file,
            "line":       self.line,
        }


# ---------------------------------------------------------------------------
# Source and sink pattern registries
# ---------------------------------------------------------------------------

# Patterns that flag a node's `code` as a taint source
_SQL_SOURCE_PATTERNS: List[str] = [
    r"request\.args",
    r"request\.form",
    r"request\.json",
    r"request\.data",
    r"request\.get_json",
    r"request\.values",
    r"request\.cookies",
    r"request\.headers",
    r"request\.files",
    r"\binput\s*\(",
    r"sys\.stdin",
    r"os\.environ",
    r"environ\.get",
    r"getenv\s*\(",
    r"flask\.request",
    r"bottle\.request",
    r"django\..*request",
    r"urllib\..*read",
    r"urlopen\s*\(",
]

_SQL_SINK_PATTERNS: List[str] = [
    r"cursor\.execute\s*\(",
    r"\.execute\s*\(",
    r"executemany\s*\(",
    r"raw\s*\(",          # Django ORM raw()
    r"extra\s*\(",        # Django ORM extra()
]

_CMD_SINK_PATTERNS: List[str] = [
    r"os\.system\s*\(",
    r"subprocess\.run\s*\(",
    r"subprocess\.Popen\s*\(",
    r"subprocess\.call\s*\(",
    r"subprocess\.check_output\s*\(",
    r"subprocess\.check_call\s*\(",
    r"popen\s*\(",
    r"commands\.getoutput\s*\(",
    r"commands\.getstatusoutput\s*\(",
]

_PATH_SINK_PATTERNS: List[str] = [
    r"\bopen\s*\(",
    r"os\.path\.join\s*\(",
    r"shutil\.copy\s*\(",
    r"shutil\.move\s*\(",
    r"shutil\.rmtree\s*\(",
    r"pathlib\.Path\s*\(",
    r"os\.remove\s*\(",
    r"os\.unlink\s*\(",
    r"os\.makedirs\s*\(",
    r"os\.listdir\s*\(",
]

_EVAL_SINK_PATTERNS: List[str] = [
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"compile\s*\(",
    r"__import__\s*\(",
    r"importlib\.import_module\s*\(",
    r"pickle\.loads\s*\(",
    r"yaml\.load\s*\(",
    r"marshal\.loads\s*\(",
]

# Hardcoded secret regexes (applied to string literal node code)
_SECRET_PATTERNS: List[tuple[str, str]] = [
    (r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]",  "hardcoded_password"),
    (r"(?i)(secret|secret_key|api_secret)\s*=\s*['\"][^'\"]{8,}['\"]", "hardcoded_secret"),
    (r"(?i)(api_key|apikey|access_key)\s*=\s*['\"][^'\"]{8,}['\"]", "hardcoded_api_key"),
    (r"(?i)(token|auth_token|bearer)\s*=\s*['\"][^'\"]{8,}['\"]", "hardcoded_token"),
    (r"(?i)aws_access_key_id\s*=\s*['\"]AKIA[0-9A-Z]{16}['\"]", "aws_access_key"),
    (r"(?i)aws_secret_access_key\s*=\s*['\"][^'\"]{40}['\"]", "aws_secret_key"),
    (r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----", "private_key"),
    (r"(?i)(database_url|db_url|connection_string)\s*=\s*['\"][^'\"]+://[^'\"]+:[^'\"]+@", "db_credentials"),
    (r"(?i)(smtp_password|mail_password)\s*=\s*['\"][^'\"]{4,}['\"]", "mail_credentials"),
    (r"ghp_[0-9A-Za-z]{36}", "github_personal_access_token"),
    (r"sk-[0-9A-Za-z]{48}", "openai_api_key"),
]


def _matches_any(code: str, patterns: List[str]) -> bool:
    return any(re.search(p, code) for p in patterns)


def _match_pattern(code: str, patterns: List[str]) -> Optional[str]:
    for p in patterns:
        if re.search(p, code):
            return p
    return None


# ---------------------------------------------------------------------------
# CPGQueryEngine
# ---------------------------------------------------------------------------

class CPGQueryEngine:
    """
    Runs vulnerability-detection graph queries over a CodePropertyGraph.

    All query methods return lists of TaintPath or Dict findings.
    """

    def __init__(self, cpg: CodePropertyGraph) -> None:
        self.cpg = cpg

    # ------------------------------------------------------------------
    # Core taint-path engine
    # ------------------------------------------------------------------

    def find_taint_paths(
        self,
        sources: List[str],   # list of regex patterns for source nodes
        sinks:   List[str],   # list of regex patterns for sink nodes
        sink_type: str = "generic",
        max_depth: int = 30,
    ) -> List[TaintPath]:
        """
        Find all taint paths from nodes matching *sources* to nodes matching *sinks*.

        Traversal order: DFG_FLOW edges (data propagation) then CFG edges
        (to cross basic-block boundaries), and CG_CALL edges for interprocedural flow.
        """
        flow_edge_types = [
            CPGEdgeType.DFG_FLOW,
            CPGEdgeType.CFG_NEXT,
            CPGEdgeType.CFG_BRANCH_TRUE,
            CPGEdgeType.CFG_BRANCH_FALSE,
            CPGEdgeType.CG_CALL,
        ]

        # Identify source nodes
        source_nodes: List[CPGNode] = []
        for node in self.cpg.nodes.values():
            if _matches_any(node.code, sources):
                source_nodes.append(node)

        # Identify sink nodes
        sink_node_ids: Set[str] = set()
        for node in self.cpg.nodes.values():
            if _matches_any(node.code, sinks):
                sink_node_ids.add(node.node_id)

        results: List[TaintPath] = []
        seen_pairs: Set[tuple[str, str]] = set()

        for src_node in source_nodes:
            # BFS to find all reachable nodes from this source
            reachable = self.cpg.reachable(
                src_node.node_id,
                edge_types=flow_edge_types,
                max_depth=max_depth,
            )

            # Check if any sink is reachable
            reachable_sinks = reachable & sink_node_ids
            if not reachable_sinks:
                continue

            for sink_id in reachable_sinks:
                pair = (src_node.node_id, sink_id)
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)

                sink_node = self.cpg.nodes[sink_id]

                # Find concrete paths (limited to first 3 for performance)
                raw_paths = self.cpg.all_paths(
                    src_node.node_id,
                    sink_id,
                    edge_types=flow_edge_types,
                    max_depth=max_depth,
                )

                if raw_paths:
                    for raw_path in raw_paths[:3]:
                        node_path = [
                            self.cpg.nodes[nid]
                            for nid in raw_path
                            if nid in self.cpg.nodes
                        ]
                        confidence = self._compute_confidence(
                            src_node, sink_node, node_path, sink_type
                        )
                        results.append(TaintPath(
                            src_node=src_node,
                            dst_node=sink_node,
                            path=node_path,
                            confidence=confidence,
                            sink_type=sink_type,
                            vuln_desc=self._describe(sink_type, src_node, sink_node),
                            file=src_node.file,
                            line=src_node.line,
                        ))
                else:
                    # Reachable but no explicit path found — report with lower confidence
                    confidence = self._compute_confidence(
                        src_node, sink_node, [], sink_type
                    ) * 0.7
                    results.append(TaintPath(
                        src_node=src_node,
                        dst_node=sink_node,
                        path=[src_node, sink_node],
                        confidence=confidence,
                        sink_type=sink_type,
                        vuln_desc=self._describe(sink_type, src_node, sink_node),
                        file=src_node.file,
                        line=src_node.line,
                    ))

        return results

    def _compute_confidence(
        self,
        src: CPGNode,
        dst: CPGNode,
        path: List[CPGNode],
        sink_type: str,
    ) -> float:
        """
        Heuristic confidence score in [0, 1].

        Factors:
          - Direct DFG flow: +0.4
          - Short path (≤3 hops): +0.2
          - Known high-risk source (request.*): +0.2
          - Known high-risk sink: +0.2
        """
        score = 0.3  # base

        # DFG flow in path?
        if path:
            dfg_hop = any(
                any(
                    e.edge_type == CPGEdgeType.DFG_FLOW
                    for e in self.cpg._adj.get(path[i].node_id, [])
                    if e.dst_id == path[i + 1].node_id
                )
                for i in range(len(path) - 1)
            )
            if dfg_hop:
                score += 0.25

        # Short path bonus
        if 2 <= len(path) <= 4:
            score += 0.15

        # High-value source patterns
        high_risk_sources = [
            "request.args", "request.form", "request.json", "input(",
        ]
        if any(p in src.code for p in high_risk_sources):
            score += 0.15

        # High-value sinks
        high_risk_sinks = {
            "sql_injection": ["execute(", "executemany("],
            "command_injection": ["os.system(", "subprocess.run(", "Popen("],
            "path_traversal": ["open(", "rmtree("],
            "code_injection": ["eval(", "exec("],
        }
        for s_patterns in high_risk_sinks.get(sink_type, []):
            if s_patterns in dst.code:
                score += 0.15
                break

        # Penalize if sink uses parameterized query form (reduces FP for safe code)
        if sink_type == "sql_injection":
            import re as _re
            # Parameterized: execute(sql, params) with tuple argument
            parameterized = bool(_re.search(
                r'execute\s*\([^)]+,\s*[\(\[]', dst.code
            ))
            if parameterized:
                score = max(0.1, score - 0.4)

        # Penalize if command sink uses list args (subprocess with list = safe)
        if sink_type == "command_injection":
            import re as _re
            if _re.search(r'subprocess\.\w+\s*\(\s*\[', dst.code):
                score = max(0.1, score - 0.35)

        return min(score, 1.0)

    def _describe(self, sink_type: str, src: CPGNode, dst: CPGNode) -> str:
        desc_map = {
            "sql_injection": (
                f"User-controlled data from '{src.code[:60]}' "
                f"flows into SQL execution at '{dst.code[:60]}'"
            ),
            "command_injection": (
                f"User-controlled data from '{src.code[:60]}' "
                f"flows into OS command at '{dst.code[:60]}'"
            ),
            "path_traversal": (
                f"User-controlled data from '{src.code[:60]}' "
                f"used in file-system operation at '{dst.code[:60]}'"
            ),
            "code_injection": (
                f"User-controlled data from '{src.code[:60]}' "
                f"flows into code evaluation at '{dst.code[:60]}'"
            ),
        }
        return desc_map.get(
            sink_type,
            f"Taint flows from '{src.code[:60]}' to '{dst.code[:60]}'",
        )

    # ------------------------------------------------------------------
    # Specialised vuln queries
    # ------------------------------------------------------------------

    def find_sql_injection(self) -> List[TaintPath]:
        """Detect SQL injection: tainted data into cursor.execute / ORM raw()."""
        return self.find_taint_paths(
            sources=_SQL_SOURCE_PATTERNS,
            sinks=_SQL_SINK_PATTERNS,
            sink_type="sql_injection",
        )

    def find_command_injection(self) -> List[TaintPath]:
        """Detect OS command injection: tainted data into os.system / subprocess."""
        return self.find_taint_paths(
            sources=_SQL_SOURCE_PATTERNS,
            sinks=_CMD_SINK_PATTERNS,
            sink_type="command_injection",
        )

    def find_path_traversal(self) -> List[TaintPath]:
        """Detect path traversal: tainted data used in file-system ops."""
        return self.find_taint_paths(
            sources=_SQL_SOURCE_PATTERNS,
            sinks=_PATH_SINK_PATTERNS,
            sink_type="path_traversal",
        )

    def find_code_injection(self) -> List[TaintPath]:
        """Detect code injection: tainted data reaching eval/exec."""
        return self.find_taint_paths(
            sources=_SQL_SOURCE_PATTERNS,
            sinks=_EVAL_SINK_PATTERNS,
            sink_type="code_injection",
        )

    # ------------------------------------------------------------------
    # Hardcoded secrets
    # ------------------------------------------------------------------

    def find_hardcoded_secrets(self) -> List[Dict[str, Any]]:
        """
        Scan all AST string-literal nodes and assignment nodes for
        hardcoded credentials / secrets using regex patterns.
        """
        findings: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        for node in self.cpg.nodes.values():
            # Check the node's code text against every secret pattern
            for pattern, secret_type in _SECRET_PATTERNS:
                match = re.search(pattern, node.code)
                if match:
                    # Deduplicate by (file, line, secret_type)
                    dedup_key = f"{node.file}:{node.line}:{secret_type}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    # Mask the matched value
                    matched_text = match.group(0)
                    masked = re.sub(
                        r"(['\"])(.{2}).+(.{2})\1",
                        r"\1\2****\3\1",
                        matched_text,
                    )

                    findings.append({
                        "type":        secret_type,
                        "file":        node.file,
                        "line":        node.line,
                        "col":         node.col,
                        "code":        node.code[:120],
                        "matched":     masked,
                        "node_id":     node.node_id,
                        "confidence":  0.85,
                        "severity":    "HIGH",
                        "description": (
                            f"Potential {secret_type.replace('_', ' ')} "
                            f"found hardcoded at {node.file}:{node.line}"
                        ),
                    })

        return findings

    # ------------------------------------------------------------------
    # Cross-function taint flows
    # ------------------------------------------------------------------

    def find_cross_function_flows(self) -> List[TaintPath]:
        """
        Detect taint flows that cross function boundaries via CG_CALL edges.

        Strategy:
          1. Find all taint sources.
          2. From each source, follow DFG_FLOW + CG_CALL edges.
          3. Report any path that crosses at least one CG_CALL edge
             and reaches a sink.
        """
        flow_edge_types = [
            CPGEdgeType.DFG_FLOW,
            CPGEdgeType.CG_CALL,
            CPGEdgeType.CFG_NEXT,
            CPGEdgeType.CFG_BRANCH_TRUE,
            CPGEdgeType.CFG_BRANCH_FALSE,
        ]

        all_sink_patterns = (
            _SQL_SINK_PATTERNS
            + _CMD_SINK_PATTERNS
            + _PATH_SINK_PATTERNS
            + _EVAL_SINK_PATTERNS
        )

        source_nodes = [
            n for n in self.cpg.nodes.values()
            if _matches_any(n.code, _SQL_SOURCE_PATTERNS)
        ]
        sink_ids = {
            n.node_id
            for n in self.cpg.nodes.values()
            if _matches_any(n.code, all_sink_patterns)
        }

        results: List[TaintPath] = []
        seen: Set[tuple[str, str]] = set()

        for src in source_nodes:
            reachable = self.cpg.reachable(
                src.node_id,
                edge_types=flow_edge_types,
                max_depth=40,
            )
            for sink_id in reachable & sink_ids:
                pair = (src.node_id, sink_id)
                if pair in seen:
                    continue
                seen.add(pair)

                # Get all paths and keep only those crossing a CG_CALL
                paths = self.cpg.all_paths(
                    src.node_id, sink_id,
                    edge_types=flow_edge_types,
                    max_depth=40,
                )
                cross_paths = [
                    p for p in paths
                    if self._path_crosses_call(p)
                ]
                if not cross_paths:
                    continue

                sink_node = self.cpg.nodes[sink_id]
                for raw_path in cross_paths[:2]:
                    node_path = [
                        self.cpg.nodes[nid]
                        for nid in raw_path
                        if nid in self.cpg.nodes
                    ]
                    # Determine sink type
                    sink_type = self._classify_sink(sink_node.code)
                    results.append(TaintPath(
                        src_node=src,
                        dst_node=sink_node,
                        path=node_path,
                        confidence=0.75,
                        sink_type=f"cross_function_{sink_type}",
                        vuln_desc=(
                            f"Cross-function taint: data from '{src.code[:50]}' "
                            f"reaches '{sink_node.code[:50]}' via function calls"
                        ),
                        file=src.file,
                        line=src.line,
                    ))

        return results

    def _path_crosses_call(self, path: List[str]) -> bool:
        """
        Return True if any edge on this path is a CG_CALL, or if the path
        traverses a DFG_FLOW edge into a CFG_ENTRY node (interprocedural
        argument→parameter binding produced by the builder).
        """
        for i in range(len(path) - 1):
            src_id = path[i]
            dst_id = path[i + 1]
            for edge in self.cpg._adj.get(src_id, []):
                if edge.dst_id != dst_id:
                    continue
                if edge.edge_type == CPGEdgeType.CG_CALL:
                    return True
                # Interprocedural DFG_FLOW: def_site → CFG_ENTRY (argument passing)
                if edge.edge_type == CPGEdgeType.DFG_FLOW:
                    dst_node = self.cpg.nodes.get(dst_id)
                    if dst_node and dst_node.node_type == CPGNodeType.CFG_ENTRY:
                        return True
        return False

    def _classify_sink(self, code: str) -> str:
        if _matches_any(code, _SQL_SINK_PATTERNS):
            return "sql_injection"
        if _matches_any(code, _CMD_SINK_PATTERNS):
            return "command_injection"
        if _matches_any(code, _PATH_SINK_PATTERNS):
            return "path_traversal"
        if _matches_any(code, _EVAL_SINK_PATTERNS):
            return "code_injection"
        return "unknown"

    # ------------------------------------------------------------------
    # Attack path search (endpoints → sensitive assets)
    # ------------------------------------------------------------------

    def attack_path_search(
        self,
        entry_points: List[str],   # regex patterns identifying HTTP entry points
        target_assets: List[str],  # regex patterns identifying sensitive assets
        max_depth: int = 50,
    ) -> List[List[CPGNode]]:
        """
        Find paths from HTTP endpoints (entry_points) to sensitive assets
        (target_assets) using all edge types.

        This models the attacker's perspective: starting from an API endpoint,
        can they reach a database write, file operation, or secret access?
        """
        all_edge_types = [
            CPGEdgeType.DFG_FLOW,
            CPGEdgeType.CFG_NEXT,
            CPGEdgeType.CFG_BRANCH_TRUE,
            CPGEdgeType.CFG_BRANCH_FALSE,
            CPGEdgeType.CG_CALL,
        ]

        entry_nodes = [
            n for n in self.cpg.nodes.values()
            if _matches_any(n.code, entry_points)
        ]
        asset_ids = {
            n.node_id
            for n in self.cpg.nodes.values()
            if _matches_any(n.code, target_assets)
        }

        attack_paths: List[List[CPGNode]] = []
        seen: Set[tuple[str, str]] = set()

        for entry in entry_nodes:
            reachable = self.cpg.reachable(
                entry.node_id,
                edge_types=all_edge_types,
                max_depth=max_depth,
            )
            for asset_id in reachable & asset_ids:
                pair = (entry.node_id, asset_id)
                if pair in seen:
                    continue
                seen.add(pair)

                paths = self.cpg.all_paths(
                    entry.node_id,
                    asset_id,
                    edge_types=all_edge_types,
                    max_depth=max_depth,
                )
                for raw in paths[:2]:
                    node_path = [
                        self.cpg.nodes[nid]
                        for nid in raw
                        if nid in self.cpg.nodes
                    ]
                    attack_paths.append(node_path)

        return attack_paths

    # ------------------------------------------------------------------
    # Combined scan
    # ------------------------------------------------------------------

    def run_all_queries(self) -> Dict[str, Any]:
        """
        Execute every built-in query and return a consolidated findings dict.
        """
        sql_inj    = self.find_sql_injection()
        cmd_inj    = self.find_command_injection()
        path_trav  = self.find_path_traversal()
        code_inj   = self.find_code_injection()
        secrets    = self.find_hardcoded_secrets()
        cross_fn   = self.find_cross_function_flows()

        all_taint = sql_inj + cmd_inj + path_trav + code_inj + cross_fn

        return {
            "sql_injection":     [t.to_dict() for t in sql_inj],
            "command_injection": [t.to_dict() for t in cmd_inj],
            "path_traversal":    [t.to_dict() for t in path_trav],
            "code_injection":    [t.to_dict() for t in code_inj],
            "hardcoded_secrets": secrets,
            "cross_function":    [t.to_dict() for t in cross_fn],
            "summary": {
                "total_taint_paths":   len(all_taint),
                "total_secrets":       len(secrets),
                "high_confidence":     sum(1 for t in all_taint if t.confidence >= 0.7),
                "medium_confidence":   sum(1 for t in all_taint if 0.4 <= t.confidence < 0.7),
            },
        }


# ---------------------------------------------------------------------------
# SecurityQueryLanguage — natural-language-style security query interface
# ---------------------------------------------------------------------------

@dataclass
class QueryResult:
    """Result returned by SecurityQueryLanguage.execute()."""
    query:       str
    result_type: str          # "nodes", "paths", "findings", "paths_list"
    items:       List[Any]    # actual results
    count:       int
    elapsed_ms:  float
    explanation: str          # human-readable explanation of what was found

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query":       self.query,
            "result_type": self.result_type,
            "count":       self.count,
            "elapsed_ms":  self.elapsed_ms,
            "explanation": self.explanation,
        }


# ---------------------------------------------------------------------------
# Source/sink keyword → regex pattern lists
# ---------------------------------------------------------------------------

_KEYWORD_SOURCE_MAP: Dict[str, List[str]] = {
    "user_input":   [r"request\.args", r"request\.form", r"request\.json", r"\binput\s*\("],
    "request":      [r"request\.args", r"request\.form", r"request\.get_json", r"flask\.request"],
    "env_var":      [r"os\.environ", r"os\.getenv"],
    "sql_query":    [r"cursor\.execute", r"db\.execute", r"session\.execute"],
    "file_write":   [r"\bopen\s*\(", r"write\s*\(", r"os\.path"],
    "command":      [r"os\.system", r"subprocess", r"\bexec\s*\("],
}

_KEYWORD_SINK_MAP: Dict[str, List[str]] = {
    "sql_query":  _SQL_SINK_PATTERNS,
    "file_write": _PATH_SINK_PATTERNS,
    "command":    _CMD_SINK_PATTERNS,
    "eval":       _EVAL_SINK_PATTERNS,
}

# Subject classification sets
_AST_SUBJECTS          = {"function", "call", "assignment", "class", "method"}
_DATAFLOW_SUBJECTS     = {"taint_flow", "propagation_path"}
_REACHABILITY_SUBJECTS = {
    "reachable_sink", "reachable_cve", "reachable_rce",
    "reachable_sqli", "reachable_cmdi",
}
_CPG_SUBJECTS          = {"path", "call_chain"}
_ATTACK_SUBJECTS       = {
    "attack_paths", "exploit_chains",
    "privilege_escalation_paths", "lateral_movement_paths",
}
_DEPENDENCY_SUBJECTS   = {"vulnerable_dependency", "exploitable_dependency"}
_REMEDIATION_SUBJECTS  = {
    "verified_fixes",
    "rejected_fixes",
    "vulnerable_patch",
    "regression_after_fix",
    "attack_paths_removed",
    "fixes_for_cve",
}


class SecurityQueryLanguage:
    """
    Natural language security query interface for CPG analysis.

    Supports:

    AST QUERIES:
      find function where name="login"
      find call where target="exec"
      find assignment where target="password"

    DATAFLOW QUERIES:
      find taint_flow where source=user_input and sink=sql_query
      find propagation_path where source=request and sink=file_write
      find taint_flow where source=env_var and sink=command

    REACHABILITY QUERIES:
      find reachable_sink
      find reachable_cve
      find reachable_rce

    CPG QUERIES:
      find path between source and sink
      find call_chain from controller to database

    ATTACK GRAPH QUERIES:
      find attack_paths
      find exploit_chains
      find privilege_escalation_paths

    DEPENDENCY QUERIES:
      find vulnerable_dependency
      find reachable_cve
      find exploitable_dependency
    """

    def __init__(
        self,
        cpg: CodePropertyGraph,
        query_engine: Optional[CPGQueryEngine] = None,
    ) -> None:
        self.cpg = cpg
        self._engine: CPGQueryEngine = query_engine if query_engine is not None else CPGQueryEngine(cpg)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(self, query: str) -> QueryResult:
        """Parse and execute a query string. Returns QueryResult."""
        t0 = time.monotonic()
        parsed = self._parse_query(query)
        q_type   = parsed.get("type", "unknown")
        subject  = parsed.get("subject", "")
        conds    = parsed.get("conditions", {})

        items: List[Any] = []
        result_type = "findings"
        explanation = ""

        try:
            if q_type == "ast":
                items = self._execute_ast_query(subject, conds)
                result_type = "nodes"
                explanation = (
                    f"Found {len(items)} AST node(s) of type '{subject}'"
                    + (f" matching {conds}" if conds else "")
                )

            elif q_type == "dataflow":
                items = self._execute_dataflow_query(subject, conds)
                result_type = "paths"
                src = conds.get("source", "any")
                snk = conds.get("sink", "any")
                explanation = (
                    f"Found {len(items)} taint flow(s) from source='{src}' to sink='{snk}'"
                )

            elif q_type == "reachability":
                items = self._execute_reachability_query(subject)
                result_type = "findings"
                explanation = (
                    f"Reachability analysis for '{subject}': {len(items)} result(s)"
                )

            elif q_type == "cpg":
                items = self._execute_cpg_query(subject, conds)
                result_type = "paths_list"
                explanation = (
                    f"CPG path query '{subject}': {len(items)} path(s) found"
                )

            elif q_type == "attack":
                items = self._execute_attack_query(subject)
                result_type = "paths_list"
                explanation = (
                    f"Attack graph query '{subject}': {len(items)} path(s) found"
                )

            elif q_type == "dependency":
                items = self._execute_dependency_query(subject)
                result_type = "findings"
                explanation = (
                    f"Dependency query '{subject}': {len(items)} result(s)"
                )

            elif q_type == "remediation":
                items, explanation = self._execute_remediation_query(subject, conds)
                result_type = subject

            else:
                explanation = f"Unknown query type for subject='{subject}'"

        except Exception as exc:  # noqa: BLE001
            explanation = f"Query execution error: {exc}"
            items = []

        elapsed_ms = (time.monotonic() - t0) * 1000.0

        return QueryResult(
            query=query,
            result_type=result_type,
            items=items,
            count=len(items),
            elapsed_ms=elapsed_ms,
            explanation=explanation,
        )

    def execute_batch(self, queries: List[str]) -> List[QueryResult]:
        """Execute multiple queries. Returns list of results."""
        return [self.execute(q) for q in queries]

    # ------------------------------------------------------------------
    # Query parsing
    # ------------------------------------------------------------------

    def _parse_query(self, query: str) -> Dict[str, Any]:
        """Parse query string into {type, subject, conditions, args}.

        Supported forms:
          find <subject>
          find <subject> where <key>=<value> [and <key>=<value> ...]
          find <subject> between <a> and <b>
          find <subject> from <a> to <b>
        """
        q = query.strip().lower()

        # Strip leading 'find '
        if q.startswith("find "):
            q = q[5:].strip()
        else:
            # Best effort: take everything as the subject
            return {"type": "unknown", "subject": q, "conditions": {}, "args": []}

        # Extract subject (first word / underscore-separated token)
        subject_match = re.match(r"^([a-z_]+)", q)
        if not subject_match:
            return {"type": "unknown", "subject": q, "conditions": {}, "args": []}

        subject = subject_match.group(1)
        remainder = q[len(subject):].strip()

        conditions: Dict[str, str] = {}
        args: List[str] = []

        if remainder.startswith("where "):
            # Parse conditions: key=value [and key=value ...]
            cond_str = remainder[6:].strip()
            # Match key="value" or key=value patterns
            for m in re.finditer(
                r'([a-z_]+)\s*=\s*(?:"([^"]*?)"|([^\s"]+(?:\s+(?!and\b)[^\s"]+)*))',
                cond_str,
            ):
                key = m.group(1)
                val = m.group(2) if m.group(2) is not None else m.group(3)
                conditions[key] = val.strip()

        elif remainder.startswith("between "):
            # find path between <a> and <b>
            between_match = re.match(r"between\s+(\S+)\s+and\s+(\S+)", remainder)
            if between_match:
                conditions["from"] = between_match.group(1)
                conditions["to"]   = between_match.group(2)
                args = [between_match.group(1), between_match.group(2)]

        elif remainder.startswith("from "):
            # find call_chain from <a> to <b>
            from_match = re.match(r"from\s+(\S+)\s+to\s+(\S+)", remainder)
            if from_match:
                conditions["from"] = from_match.group(1)
                conditions["to"]   = from_match.group(2)
                args = [from_match.group(1), from_match.group(2)]

        # Determine query type from subject
        q_type = self._classify_subject(subject)

        return {
            "type":       q_type,
            "subject":    subject,
            "conditions": conditions,
            "args":       args,
        }

    def _classify_subject(self, subject: str) -> str:
        """Map subject keyword to a query type string."""
        if subject in _AST_SUBJECTS:
            return "ast"
        if subject in _DATAFLOW_SUBJECTS:
            return "dataflow"
        if subject in _REACHABILITY_SUBJECTS:
            return "reachability"
        if subject in _CPG_SUBJECTS:
            return "cpg"
        if subject in _ATTACK_SUBJECTS:
            return "attack"
        if subject in _DEPENDENCY_SUBJECTS:
            return "dependency"
        if subject in _REMEDIATION_SUBJECTS:
            return "remediation"
        return "unknown"

    # ------------------------------------------------------------------
    # Query execution helpers
    # ------------------------------------------------------------------

    def _execute_ast_query(self, subject: str, conditions: Dict[str, str]) -> List[Any]:
        """Execute AST-type queries (find function, find call, etc.)."""
        results: List[CPGNode] = []

        for node in self.cpg.nodes.values():
            matched = False

            if subject == "function":
                # CFG_ENTRY nodes represent function entry points
                if node.node_type == CPGNodeType.CFG_ENTRY:
                    name_filter = conditions.get("name", "")
                    if not name_filter or name_filter.lower() in node.properties.get("label", node.code).lower():
                        matched = True

            elif subject == "call":
                # CG_CALL nodes represent call sites
                if node.node_type == CPGNodeType.CG_CALL:
                    target_filter = conditions.get("target", "")
                    callee = node.properties.get("callee", node.code)
                    if not target_filter or target_filter.lower() in callee.lower():
                        matched = True

            elif subject == "assignment":
                # DFG_DEF nodes represent variable definitions/assignments
                if node.node_type == CPGNodeType.DFG_DEF:
                    target_filter = conditions.get("target", "")
                    if not target_filter or target_filter.lower() in node.properties.get("label", node.code).lower():
                        matched = True

            elif subject in ("class", "method"):
                # Generic AST_NODE lookup for class or method patterns
                if node.node_type == CPGNodeType.AST_NODE:
                    name_filter = conditions.get("name", conditions.get("target", ""))
                    if not name_filter or name_filter.lower() in node.properties.get("label", node.code).lower():
                        if subject in node.ast_type.lower():
                            matched = True

            else:
                # Fallback: search any node whose label matches
                name_filter = conditions.get("name", conditions.get("target", ""))
                if name_filter and name_filter.lower() in node.properties.get("label", node.code).lower():
                    matched = True

            if matched:
                results.append(node)

        return results

    def _resolve_source_patterns(self, source_keyword: str) -> List[str]:
        """Resolve a source keyword into a list of regex patterns."""
        # Direct keyword lookup
        if source_keyword in _KEYWORD_SOURCE_MAP:
            return _KEYWORD_SOURCE_MAP[source_keyword]
        # Fallback: treat as a raw pattern
        return [re.escape(source_keyword)]

    def _resolve_sink_patterns(self, sink_keyword: str) -> List[str]:
        """Resolve a sink keyword into a list of regex patterns."""
        if sink_keyword in _KEYWORD_SINK_MAP:
            return _KEYWORD_SINK_MAP[sink_keyword]
        if sink_keyword in _KEYWORD_SOURCE_MAP:
            # Some keywords appear as both source and sink (e.g. 'command')
            return _KEYWORD_SOURCE_MAP[sink_keyword]
        return [re.escape(sink_keyword)]

    def _execute_dataflow_query(self, subject: str, conditions: Dict[str, str]) -> List[Any]:
        """Execute dataflow queries using CPGQueryEngine.find_taint_paths()."""
        source_kw = conditions.get("source", "user_input")
        sink_kw   = conditions.get("sink", "sql_query")

        source_patterns = self._resolve_source_patterns(source_kw)
        sink_patterns   = self._resolve_sink_patterns(sink_kw)

        # Choose a meaningful sink_type label
        sink_type_map = {
            "sql_query":  "sql_injection",
            "command":    "command_injection",
            "file_write": "path_traversal",
            "eval":       "code_injection",
        }
        sink_type = sink_type_map.get(sink_kw, f"taint_{sink_kw}")

        return self._engine.find_taint_paths(
            sources=source_patterns,
            sinks=sink_patterns,
            sink_type=sink_type,
        )

    def _execute_reachability_query(self, subject: str) -> List[Any]:
        """Execute reachability queries."""
        if subject in ("reachable_rce", "reachable_cmdi"):
            return self._engine.find_command_injection()
        elif subject == "reachable_sqli":
            return self._engine.find_sql_injection()
        elif subject == "reachable_sink":
            # Return all taint paths to any sink
            sql  = self._engine.find_sql_injection()
            cmd  = self._engine.find_command_injection()
            path = self._engine.find_path_traversal()
            code = self._engine.find_code_injection()
            return sql + cmd + path + code
        elif subject == "reachable_cve":
            # CVE reachability: look for nodes whose code matches known CVE patterns
            cve_patterns = [
                r"pickle\.loads\s*\(",     # deserialization (CVE class)
                r"yaml\.load\s*\(",        # unsafe yaml
                r"eval\s*\(",              # code exec
                r"exec\s*\(",              # code exec
                r"os\.system\s*\(",        # OS command
                r"subprocess\.Popen\s*\(", # OS command
            ]
            results = []
            for node in self.cpg.nodes.values():
                if _matches_any(node.code, cve_patterns):
                    results.append(node)
            return results
        else:
            # Generic: return all cross-function flows
            return self._engine.find_cross_function_flows()

    def _execute_cpg_query(self, subject: str, conditions: Dict[str, str]) -> List[Any]:
        """Execute CPG path queries."""
        from_kw = conditions.get("from", conditions.get("source", ""))
        to_kw   = conditions.get("to",   conditions.get("sink",   ""))

        if not from_kw and not to_kw:
            # No conditions — return all attack paths
            return self._engine.attack_path_search(
                entry_points=list(_SQL_SOURCE_PATTERNS),
                target_assets=list(_SQL_SINK_PATTERNS + _CMD_SINK_PATTERNS),
            )

        # Resolve from/to keywords
        from_patterns = self._resolve_source_patterns(from_kw) if from_kw else _SQL_SOURCE_PATTERNS
        to_patterns   = self._resolve_sink_patterns(to_kw)   if to_kw   else _SQL_SINK_PATTERNS

        if subject == "call_chain":
            # call_chain: follow CG_CALL edges only
            entry_nodes = [
                n for n in self.cpg.nodes.values()
                if _matches_any(n.code, from_patterns)
            ]
            target_ids = {
                n.node_id
                for n in self.cpg.nodes.values()
                if _matches_any(n.code, to_patterns)
            }
            call_edge_types = [CPGEdgeType.CG_CALL, CPGEdgeType.CFG_NEXT]
            paths: List[List[CPGNode]] = []
            seen: Set[Tuple[str, str]] = set()
            for entry in entry_nodes:
                reachable = self.cpg.reachable(entry.node_id, edge_types=call_edge_types, max_depth=20)
                for t_id in reachable & target_ids:
                    if (entry.node_id, t_id) in seen:
                        continue
                    seen.add((entry.node_id, t_id))
                    raw_paths = self.cpg.all_paths(entry.node_id, t_id, edge_types=call_edge_types, max_depth=20)
                    for rp in raw_paths[:2]:
                        paths.append([self.cpg.nodes[nid] for nid in rp if nid in self.cpg.nodes])
            return paths

        return self._engine.attack_path_search(
            entry_points=from_patterns,
            target_assets=to_patterns,
        )

    def _execute_attack_query(self, subject: str) -> List[Any]:
        """Execute attack graph queries."""
        if subject == "exploit_chains":
            # Exploit chains: RCE-focused paths
            return self._engine.attack_path_search(
                entry_points=_SQL_SOURCE_PATTERNS,
                target_assets=_CMD_SINK_PATTERNS + _EVAL_SINK_PATTERNS,
            )
        elif subject == "privilege_escalation_paths":
            # Privilege escalation: auth-related patterns
            priv_sources = [r"request\.", r"\binput\s*\("]
            priv_sinks   = [
                r"os\.setuid\s*\(",
                r"os\.setgid\s*\(",
                r"subprocess\.run\s*\(",
                r"os\.system\s*\(",
            ]
            return self._engine.attack_path_search(
                entry_points=priv_sources,
                target_assets=priv_sinks,
            )
        elif subject == "lateral_movement_paths":
            # Lateral movement: network/socket calls
            net_sinks = [
                r"socket\.\w+\s*\(",
                r"requests\.\w+\s*\(",
                r"urllib\.\w+",
                r"http\.client",
            ]
            return self._engine.attack_path_search(
                entry_points=_SQL_SOURCE_PATTERNS,
                target_assets=net_sinks,
            )
        else:
            # attack_paths (default): full attack surface
            all_sinks = (
                _SQL_SINK_PATTERNS
                + _CMD_SINK_PATTERNS
                + _PATH_SINK_PATTERNS
                + _EVAL_SINK_PATTERNS
            )
            return self._engine.attack_path_search(
                entry_points=_SQL_SOURCE_PATTERNS,
                target_assets=all_sinks,
            )

    def _execute_remediation_query(
        self, subject: str, conditions: Dict[str, str]
    ) -> tuple[List[Any], str]:
        """Execute remediation / fix-tracking queries.

        These queries return structure rather than live data — the engine
        provides the QueryResult schema; callers populate items by attaching
        a VerifiedFixEngine or KnowledgeGraph store.

        Returns
        -------
        (items, explanation) where items is always [] (no live store attached).
        """
        _EXPLANATIONS: Dict[str, str] = {
            "verified_fixes": (
                "Returns verified fixes from the KG — fixes whose VerifiedFix.fix_status "
                "is VERIFIED and fix_confidence >= threshold."
            ),
            "rejected_fixes": (
                "Returns rejected fixes from the KG — fixes whose VerifiedFix.fix_status "
                "is REJECTED due to build failure, regression, or low confidence."
            ),
            "vulnerable_patch": (
                "Returns patches that introduced a new vulnerability — fixes where "
                "VerifiedFix.regression_detected is True and the regression is a security issue."
            ),
            "regression_after_fix": (
                "Returns fixes that caused functional regressions — fixes where "
                "VerifiedFix.regression_detected is True regardless of security impact."
            ),
            "attack_paths_removed": (
                "Returns attack paths eliminated by applied fixes — KG edges of type "
                "REMOVES connecting FIX nodes to former SINK or DATAFLOW nodes."
            ),
            "fixes_for_cve": (
                "Returns fixes linked to a specific CVE or CWE — FIX nodes reachable "
                "from CVE nodes via FIXES edges, optionally filtered by cve= condition."
            ),
        }
        explanation = _EXPLANATIONS.get(
            subject,
            f"Remediation query '{subject}': no live store attached — returns empty result set.",
        )
        cve_filter = conditions.get("cve", "")
        if cve_filter:
            explanation += f" (CVE/CWE filter: '{cve_filter}')"
        return [], explanation

    def _execute_dependency_query(self, subject: str) -> List[Any]:
        """Execute dependency queries."""
        # Without a live dependency scanner attached, scan the CPG for
        # known-dangerous import/require patterns that indicate vulnerable deps.
        vuln_import_patterns = [
            r"\bimport\s+pickle\b",
            r"\bimport\s+yaml\b",
            r"from\s+yaml\s+import",
            r"\bimport\s+marshal\b",
            r"from\s+cryptography",
            r"\bimport\s+paramiko\b",
            r"\bimport\s+requests\b",
        ]
        if subject == "exploitable_dependency":
            # Exploitable: dep import AND a dangerous call site
            dangerous_calls = _CMD_SINK_PATTERNS + _EVAL_SINK_PATTERNS
            all_results: List[CPGNode] = []
            for node in self.cpg.nodes.values():
                if _matches_any(node.code, vuln_import_patterns) or _matches_any(node.code, dangerous_calls):
                    all_results.append(node)
            return all_results
        else:
            # vulnerable_dependency: any known-risky imports
            return [
                node
                for node in self.cpg.nodes.values()
                if _matches_any(node.code, vuln_import_patterns)
            ]
