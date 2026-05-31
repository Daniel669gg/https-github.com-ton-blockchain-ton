"""AST-based dependency graph for taint flow visualization."""
from __future__ import annotations

import ast
import json
import logging
import math
import os
import shutil
import subprocess
import textwrap
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("tythanai.dependency_graph")

# ---------------------------------------------------------------------------
# Node / Edge types
# ---------------------------------------------------------------------------

_NODE_TYPE_MODULE   = "module"
_NODE_TYPE_FUNCTION = "function"
_NODE_TYPE_CLASS    = "class"

_EDGE_IMPORT   = "imports"
_EDGE_CALL     = "calls"
_EDGE_INHERITS = "inherits"

# FastAPI / common entry-point decorators
_ENTRY_POINT_DECORATORS = {
    "get", "post", "put", "delete", "patch", "head", "options",
    "websocket", "route", "api_route",
}

_MAIN_FUNC_NAMES = {"main", "run", "start", "app", "entrypoint", "handle"}


# ---------------------------------------------------------------------------
# Internal data classes (lightweight, no Pydantic overhead in graph ops)
# ---------------------------------------------------------------------------

class _Node:
    __slots__ = (
        "node_id", "label", "node_type", "module",
        "finding_rule_ids", "is_entry_point", "is_tainted",
        "x", "y",
    )

    def __init__(
        self,
        node_id: str,
        label: str,
        node_type: str,
        module: str = "",
    ) -> None:
        self.node_id        = node_id
        self.label          = label
        self.node_type      = node_type
        self.module         = module
        self.finding_rule_ids: List[str] = []
        self.is_entry_point = False
        self.is_tainted     = False
        self.x              = 0.0
        self.y              = 0.0


class _Edge:
    __slots__ = ("source", "target", "edge_type", "is_tainted")

    def __init__(self, source: str, target: str, edge_type: str) -> None:
        self.source     = source
        self.target     = target
        self.edge_type  = edge_type
        self.is_tainted = False


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------

class _ModuleVisitor(ast.NodeVisitor):
    """
    Walks a single module's AST and extracts:
    - imports (module → module edges)
    - function definitions
    - class definitions + base classes
    - function calls (best-effort)
    """

    def __init__(self, module_id: str, module_label: str) -> None:
        self.module_id    = module_id
        self.module_label = module_label

        self.nodes: List[_Node]              = []
        self.edges: List[_Edge]              = []
        self._scope_stack: List[str]         = [module_id]
        self._func_nodes: Dict[str, _Node]   = {}

    # -- Helpers ---------------------------------------------------------

    def _current_scope(self) -> str:
        return self._scope_stack[-1]

    def _make_node_id(self, name: str, kind: str) -> str:
        return f"{self.module_id}:{kind}:{name}"

    def _add_edge(self, source: str, target: str, edge_type: str) -> None:
        self.edges.append(_Edge(source=source, target=target, edge_type=edge_type))

    # -- Visitors --------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            target_mod = alias.name.split(".")[0]
            self._add_edge(self.module_id, target_mod, _EDGE_IMPORT)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.module:
            target_mod = node.module.split(".")[0]
            self._add_edge(self.module_id, target_mod, _EDGE_IMPORT)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        class_id = self._make_node_id(node.name, "class")
        n = _Node(class_id, node.name, _NODE_TYPE_CLASS, self.module_id)
        self.nodes.append(n)
        self._add_edge(self.module_id, class_id, "contains")

        # Inheritance
        for base in node.bases:
            base_name = ast.unparse(base) if hasattr(ast, "unparse") else _ast_name(base)
            if base_name:
                self._add_edge(class_id, base_name, _EDGE_INHERITS)

        self._scope_stack.append(class_id)
        self.generic_visit(node)
        self._scope_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._handle_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._handle_func(node)

    def _handle_func(self, node: ast.AST) -> None:
        name     = node.name  # type: ignore[attr-defined]
        scope    = self._current_scope()
        func_id  = f"{scope}:func:{name}"
        n        = _Node(func_id, name, _NODE_TYPE_FUNCTION, self.module_id)

        # Detect FastAPI entry points via decorator names
        decorators = getattr(node, "decorator_list", [])
        for dec in decorators:
            dec_name = _decorator_name(dec).lower()
            if any(ep in dec_name for ep in _ENTRY_POINT_DECORATORS):
                n.is_entry_point = True
                break

        if not n.is_entry_point and name.lower() in _MAIN_FUNC_NAMES:
            n.is_entry_point = True

        self.nodes.append(n)
        self._func_nodes[name] = n
        self._add_edge(scope, func_id, "contains")

        self._scope_stack.append(func_id)
        self.generic_visit(node)
        self._scope_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        callee_name = _call_name(node.func)
        if callee_name:
            scope = self._current_scope()
            self._add_edge(scope, callee_name, _EDGE_CALL)
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# AST name helpers
# ---------------------------------------------------------------------------

def _ast_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _ast_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _call_name(node: ast.expr) -> str:
    return _ast_name(node)


def _decorator_name(dec: ast.expr) -> str:
    if isinstance(dec, ast.Call):
        return _ast_name(dec.func)
    return _ast_name(dec)


# ---------------------------------------------------------------------------
# Layout helpers
# ---------------------------------------------------------------------------

def _compute_spring_layout(
    nodes: Dict[str, _Node],
    edges: List[_Edge],
    iterations: int = 50,
) -> None:
    """
    Simple force-directed layout (Fruchterman–Reingold approximation).
    Assigns x/y to each node in-place.  O(V²·iterations) — acceptable for
    typical code graphs (hundreds of nodes).
    """
    nids = list(nodes.keys())
    n    = len(nids)
    if n == 0:
        return

    # Initialise positions on a circle
    for i, nid in enumerate(nids):
        angle       = 2 * math.pi * i / n
        nodes[nid].x = math.cos(angle) * 100
        nodes[nid].y = math.sin(angle) * 100

    if n == 1:
        return

    W = H = 200.0
    area  = W * H
    k     = math.sqrt(area / n)

    pos: Dict[str, List[float]] = {nid: [nodes[nid].x, nodes[nid].y] for nid in nids}

    adj: Set[Tuple[str, str]] = {(e.source, e.target) for e in edges}

    for _ in range(iterations):
        disp: Dict[str, List[float]] = {nid: [0.0, 0.0] for nid in nids}

        # Repulsion
        for i in range(n):
            for j in range(i + 1, n):
                u, v = nids[i], nids[j]
                dx   = pos[u][0] - pos[v][0]
                dy   = pos[u][1] - pos[v][1]
                dist = math.sqrt(dx * dx + dy * dy) or 0.01
                force = (k * k) / dist
                disp[u][0] += (dx / dist) * force
                disp[u][1] += (dy / dist) * force
                disp[v][0] -= (dx / dist) * force
                disp[v][1] -= (dy / dist) * force

        # Attraction
        for e in edges:
            if e.source not in pos or e.target not in pos:
                continue
            dx    = pos[e.source][0] - pos[e.target][0]
            dy    = pos[e.source][1] - pos[e.target][1]
            dist  = math.sqrt(dx * dx + dy * dy) or 0.01
            force = (dist * dist) / k
            disp[e.source][0] -= (dx / dist) * force
            disp[e.source][1] -= (dy / dist) * force
            disp[e.target][0]  += (dx / dist) * force
            disp[e.target][1]  += (dy / dist) * force

        # Apply + clamp
        temp = k * 0.1
        for nid in nids:
            dx   = disp[nid][0]
            dy   = disp[nid][1]
            dm   = math.sqrt(dx * dx + dy * dy) or 0.01
            pos[nid][0] += (dx / dm) * min(dm, temp)
            pos[nid][1] += (dy / dm) * min(dm, temp)

    for nid in nids:
        nodes[nid].x = round(pos[nid][0], 2)
        nodes[nid].y = round(pos[nid][1], 2)


# ---------------------------------------------------------------------------
# DependencyGraph
# ---------------------------------------------------------------------------


class DependencyGraph:
    """
    Builds an AST-based code dependency graph and exposes multiple output
    formats (DOT, JSON, SVG).

    Usage::

        graph = DependencyGraph()
        graph.build("/path/to/project")
        graph.annotate_with_findings(findings)
        svg = graph.to_svg()
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, _Node] = {}
        self._edges: List[_Edge]       = []
        self._built                    = False

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def build(self, directory: str) -> None:
        """
        Parse all .py files under *directory* and construct the graph.

        Extracts:
        - Module nodes for every .py file
        - Function and class nodes
        - Import, call, and inheritance edges
        """
        root = Path(directory).resolve()
        if not root.exists():
            raise FileNotFoundError(f"Directory not found: {root}")

        self._nodes.clear()
        self._edges.clear()

        py_files = sorted(root.rglob("*.py"))
        logger.info("DependencyGraph: scanning %d Python files in %s", len(py_files), root)

        for py_file in py_files:
            self._process_file(py_file, root)

        # Resolve edge targets: map bare names to known node_ids where possible
        self._resolve_edges()

        # Compute layout
        _compute_spring_layout(self._nodes, self._edges)

        self._built = True
        logger.info(
            "DependencyGraph built: %d nodes, %d edges",
            len(self._nodes),
            len(self._edges),
        )

    def _process_file(self, py_file: Path, root: Path) -> None:
        rel      = py_file.relative_to(root)
        mod_id   = str(rel).replace(os.sep, ".").removesuffix(".py")
        mod_label = rel.stem

        source = ""
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", py_file, exc)
            return

        # Always add the module node
        mod_node = _Node(mod_id, mod_label, _NODE_TYPE_MODULE, mod_id)
        self._nodes[mod_id] = mod_node

        try:
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError as exc:
            logger.debug("Syntax error in %s: %s", py_file, exc)
            return

        visitor = _ModuleVisitor(mod_id, mod_label)
        visitor.visit(tree)

        for node in visitor.nodes:
            self._nodes[node.node_id] = node
        self._edges.extend(visitor.edges)

    def _resolve_edges(self) -> None:
        """
        Attempt to resolve raw call targets (bare function/class names) to
        fully-qualified node_ids in the graph.  Unresolvable edges are kept
        as-is (their target simply won't be in _nodes).
        """
        # Build a reverse index: label → [node_id, ...]
        label_index: Dict[str, List[str]] = defaultdict(list)
        for nid, n in self._nodes.items():
            label_index[n.label].append(nid)

        resolved: List[_Edge] = []
        for e in self._edges:
            if e.target not in self._nodes and e.target in label_index:
                candidates = label_index[e.target]
                # Prefer nodes in the same module as the source
                src_module = self._nodes.get(e.source, _Node("", "", "")).module
                same_mod   = [c for c in candidates if self._nodes[c].module == src_module]
                e.target   = same_mod[0] if same_mod else candidates[0]
            resolved.append(e)
        self._edges = resolved

    # ------------------------------------------------------------------
    # Annotation
    # ------------------------------------------------------------------

    def annotate_with_findings(self, findings: Any) -> None:
        """
        Mark nodes as tainted based on findings.

        Matches findings to nodes by file path ↔ module_id and by
        function/class name appearing in the description or context.
        """
        # We accept List[Finding] but avoid hard import to prevent circularity
        for f in findings:
            # Normalise file path to a module-id-like string
            file_key = (
                str(f.file)
                .replace("\\", "/")
                .removesuffix(".py")
                .replace("/", ".")
                .lstrip(".")
            )

            matched = False
            for nid, node in self._nodes.items():
                if file_key and (nid == file_key or nid.endswith(file_key) or file_key.endswith(node.module)):
                    node.is_tainted = True
                    if f.rule_id not in node.finding_rule_ids:
                        node.finding_rule_ids.append(f.rule_id)
                    matched = True

            if not matched:
                # Try substring match on module component
                for nid, node in self._nodes.items():
                    basename = file_key.rsplit(".", 1)[-1] if "." in file_key else file_key
                    if basename and basename in nid:
                        node.is_tainted = True
                        if f.rule_id not in node.finding_rule_ids:
                            node.finding_rule_ids.append(f.rule_id)

        # Mark edges between tainted nodes as tainted
        for e in self._edges:
            src = self._nodes.get(e.source)
            tgt = self._nodes.get(e.target)
            if src and tgt and src.is_tainted and tgt.is_tainted:
                e.is_tainted = True

    # ------------------------------------------------------------------
    # Output: DOT
    # ------------------------------------------------------------------

    def to_dot(self) -> str:
        """Return a Graphviz DOT representation of the graph."""
        lines = [
            "digraph DependencyGraph {",
            '    rankdir="LR";',
            '    node [fontname="Helvetica", fontsize=10];',
            '    edge [fontsize=8];',
            "",
        ]

        for nid, node in self._nodes.items():
            safe_id  = _dot_id(nid)
            color    = _node_color(node)
            shape    = _node_shape(node)
            label    = node.label.replace('"', '\\"')
            tooltip  = " | ".join(node.finding_rule_ids) if node.finding_rule_ids else ""
            tooltip_attr = f' tooltip="{tooltip}"' if tooltip else ""
            lines.append(
                f'    {safe_id} [label="{label}" shape={shape} '
                f'style=filled fillcolor="{color}"{tooltip_attr}];'
            )

        lines.append("")
        for e in self._edges:
            src   = _dot_id(e.source)
            tgt   = _dot_id(e.target)
            style = "solid"
            color = "black"
            if e.is_tainted:
                color = "red"
                style = "bold"
            elif e.edge_type == _EDGE_IMPORT:
                color = "#888888"
                style = "dashed"
            elif e.edge_type == _EDGE_INHERITS:
                color = "#0055AA"
            lines.append(
                f'    {src} -> {tgt} '
                f'[style={style} color="{color}" label="{e.edge_type}"];'
            )

        lines.append("}")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Output: JSON
    # ------------------------------------------------------------------

    def to_json(self) -> dict:
        """
        Return a JSON-serialisable dict suitable for frontend rendering.

        Schema::

            {
                "nodes": [{"id", "label", "type", "x", "y", "tainted",
                           "entry_point", "findings"}, ...],
                "edges": [{"source", "target", "type", "tainted"}, ...]
            }
        """
        nodes_out = []
        for nid, node in self._nodes.items():
            nodes_out.append({
                "id":          nid,
                "label":       node.label,
                "type":        node.node_type,
                "module":      node.module,
                "x":           node.x,
                "y":           node.y,
                "tainted":     node.is_tainted,
                "entry_point": node.is_entry_point,
                "findings":    list(node.finding_rule_ids),
                "risk":        _node_risk(node),
            })

        edges_out = [
            {
                "source":  e.source,
                "target":  e.target,
                "type":    e.edge_type,
                "tainted": e.is_tainted,
            }
            for e in self._edges
        ]

        return {"nodes": nodes_out, "edges": edges_out}

    # ------------------------------------------------------------------
    # Output: SVG
    # ------------------------------------------------------------------

    def to_svg(self) -> str:
        """
        Render an SVG via `dot -Tsvg`.

        Falls back to returning the DOT string if graphviz is not installed.
        """
        dot_bin = shutil.which("dot")
        if not dot_bin:
            logger.debug("graphviz 'dot' not found — returning DOT fallback")
            return self.to_dot()

        dot_src = self.to_dot().encode("utf-8")
        try:
            result = subprocess.run(
                [dot_bin, "-Tsvg"],
                input=dot_src,
                capture_output=True,
                timeout=60,
            )
            if result.returncode == 0:
                return result.stdout.decode("utf-8", errors="replace")
            logger.warning("dot -Tsvg failed: %s", result.stderr.decode())
        except Exception as exc:
            logger.warning("SVG rendering error: %s", exc)
        return self.to_dot()

    # ------------------------------------------------------------------
    # High-risk nodes
    # ------------------------------------------------------------------

    def get_high_risk_nodes(self) -> List[Dict[str, Any]]:
        """
        Return nodes that are both entry points AND have findings attached.
        These represent the highest-risk attack surface.

        Returns list of dicts with keys: id, label, type, findings, risk.
        """
        result = []
        for nid, node in self._nodes.items():
            if node.is_entry_point and node.finding_rule_ids:
                result.append({
                    "id":       nid,
                    "label":    node.label,
                    "type":     node.node_type,
                    "findings": list(node.finding_rule_ids),
                    "risk":     "CRITICAL",
                    "module":   node.module,
                })
        # Also include highly tainted non-entry-point nodes
        for nid, node in self._nodes.items():
            if not node.is_entry_point and node.is_tainted and len(node.finding_rule_ids) >= 2:
                result.append({
                    "id":       nid,
                    "label":    node.label,
                    "type":     node.node_type,
                    "findings": list(node.finding_rule_ids),
                    "risk":     "HIGH",
                    "module":   node.module,
                })
        return result

    # ------------------------------------------------------------------
    # Taint paths
    # ------------------------------------------------------------------

    def get_taint_paths(self) -> List[List[str]]:
        """
        Find shortest paths between source nodes (entry points) and tainted
        sink nodes using BFS over the call/import edges.

        Returns list of paths (each path is a list of node_ids).
        """
        # Build adjacency for BFS
        adj: Dict[str, List[str]] = defaultdict(list)
        for e in self._edges:
            if e.edge_type in (_EDGE_CALL, _EDGE_IMPORT):
                adj[e.source].append(e.target)

        sources = [
            nid for nid, n in self._nodes.items()
            if n.is_entry_point
        ]
        sinks = [
            nid for nid, n in self._nodes.items()
            if n.is_tainted and n.finding_rule_ids and not n.is_entry_point
        ]

        paths: List[List[str]] = []
        for src in sources:
            for sink in sinks:
                if src == sink:
                    continue
                path = self._bfs_path(adj, src, sink)
                if path:
                    paths.append(path)

        return paths

    @staticmethod
    def _bfs_path(
        adj: Dict[str, List[str]],
        start: str,
        end: str,
    ) -> Optional[List[str]]:
        """BFS shortest path; returns None if unreachable."""
        if start == end:
            return [start]
        visited: Set[str] = {start}
        queue: deque[List[str]] = deque([[start]])
        while queue:
            path = queue.popleft()
            node = path[-1]
            for nb in adj.get(node, []):
                if nb == end:
                    return path + [nb]
                if nb not in visited:
                    visited.add(nb)
                    queue.append(path + [nb])
        return None


# ---------------------------------------------------------------------------
# DOT helpers
# ---------------------------------------------------------------------------

def _dot_id(raw: str) -> str:
    """Convert an arbitrary node id to a safe DOT identifier."""
    safe = raw.replace(".", "_").replace("-", "_").replace("/", "_").replace(":", "_").replace(" ", "_")
    # DOT ids must not start with a digit
    if safe and safe[0].isdigit():
        safe = "n_" + safe
    return safe or "unknown"


def _node_color(node: _Node) -> str:
    if node.is_entry_point and node.finding_rule_ids:
        return "#FF4444"   # CRITICAL — red
    if node.is_entry_point:
        return "#FFD700"   # entry point — gold
    if node.is_tainted:
        return "#FF9900"   # tainted — orange
    if node.node_type == _NODE_TYPE_MODULE:
        return "#AED6F1"   # module — light blue
    if node.node_type == _NODE_TYPE_CLASS:
        return "#A9DFBF"   # class — light green
    return "#FDFEFE"        # function — white


def _node_shape(node: _Node) -> str:
    if node.node_type == _NODE_TYPE_MODULE:
        return "box"
    if node.node_type == _NODE_TYPE_CLASS:
        return "ellipse"
    return "rectangle"


def _node_risk(node: _Node) -> str:
    if node.is_entry_point and node.finding_rule_ids:
        return "CRITICAL"
    if node.is_tainted and node.finding_rule_ids:
        return "HIGH"
    if node.is_tainted:
        return "MEDIUM"
    return "LOW"
