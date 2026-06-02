"""
backend/core/cpg/graph.py — Code Property Graph data structures and Python builder.

Provides:
  CPGNodeType  — enum of node kinds
  CPGEdgeType  — enum of edge kinds
  CPGNode      — graph node (statement / expression / function entry)
  CPGEdge      — directed typed edge
  CodePropertyGraph — adjacency-list graph with incremental mutation support
  PythonCPGBuilder  — builds a CPG from Python source files via the ast module
"""
from __future__ import annotations

import ast
import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Node / Edge type enums
# ---------------------------------------------------------------------------

class CPGNodeType(str, Enum):
    # Control-flow graph nodes
    CFG_ENTRY   = "cfg_entry"    # function entry point
    CFG_EXIT    = "cfg_exit"     # function exit / return
    CFG_NODE    = "cfg_node"     # generic statement
    CFG_BRANCH  = "cfg_branch"   # branch point (if / while / for)

    # Data-flow graph nodes
    DFG_DEF       = "dfg_def"       # variable definition
    DFG_USE       = "dfg_use"       # variable use
    DFG_SOURCE    = "dfg_source"    # taint source (user input, request data)
    DFG_SINK      = "dfg_sink"      # taint sink (execute, eval, …)
    DFG_SANITIZER = "dfg_sanitizer" # sanitizer / validator

    # Call-graph nodes
    CG_CALL     = "cg_call"     # call site
    CG_FUNCTION = "cg_function" # function definition node

    # AST nodes
    AST_LITERAL = "ast_literal" # constant / literal
    AST_IMPORT  = "ast_import"  # import statement
    AST_CLASS   = "ast_class"   # class definition


class CPGEdgeType(str, Enum):
    # Control flow
    CFG_NEXT         = "cfg_next"          # sequential next statement
    CFG_BRANCH_TRUE  = "cfg_branch_true"   # branch taken (condition true)
    CFG_BRANCH_FALSE = "cfg_branch_false"  # branch not taken (condition false)
    CFG_RETURN       = "cfg_return"        # return edge

    # Data flow
    DFG_FLOW    = "dfg_flow"    # data flows from definition to use
    DFG_DEF_USE = "dfg_def_use" # reaching definition edge

    # Call graph
    CG_CALL   = "cg_call"   # caller → callee (call site → function entry)
    CG_RETURN = "cg_return" # callee → caller (return site)

    # Program Dependence Graph
    PDG_CONTROL = "pdg_control" # control dependence
    PDG_DATA    = "pdg_data"    # data dependence

    # AST structure
    AST_CHILD = "ast_child" # parent → child in AST
    AST_SCOPE = "ast_scope" # scope containment edge


# ---------------------------------------------------------------------------
# Node / Edge data classes
# ---------------------------------------------------------------------------

@dataclass
class CPGNode:
    """A node in the Code Property Graph."""
    node_id:    str
    node_type:  CPGNodeType
    code:       str                              # source code snippet (≤ 200 chars)
    ast_type:   str                = ""          # Python ast node class name
    file:       str                = ""          # absolute source file path
    line:       int                = 0
    col:        int                = 0
    function:   str                = ""          # enclosing function name
    properties: Dict[str, Any]     = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id":   self.node_id,
            "node_type": self.node_type.value,
            "code":      self.code[:200],
            "ast_type":  self.ast_type,
            "file":      self.file,
            "line":      self.line,
            "function":  self.function,
        }


@dataclass
class CPGEdge:
    """A directed, typed edge in the Code Property Graph."""
    src_id:     str
    dst_id:     str
    edge_type:  CPGEdgeType
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_id":    self.src_id,
            "dst_id":    self.dst_id,
            "edge_type": self.edge_type.value,
        }


# ---------------------------------------------------------------------------
# Code Property Graph
# ---------------------------------------------------------------------------

class CodePropertyGraph:
    """
    Unified Code Property Graph (CFG + DFG + CG + PDG).

    Supports incremental mutation:
      add_node / remove_node / add_edge / remove_edge / invalidate_file

    Traversal:
      reachable()  — BFS reachability
      all_paths()  — DFS enumerate paths
      predecessors / successors — one-hop neighbours

    The ``version`` counter is incremented on every mutation so callers can
    detect stale cached analysis results.
    """

    def __init__(self) -> None:
        self.nodes:       Dict[str, CPGNode]       = {}
        # src_id → list of outgoing edges
        self._adj:        Dict[str, List[CPGEdge]] = defaultdict(list)
        # dst_id → list of incoming edges (reverse)
        self._radj:       Dict[str, List[CPGEdge]] = defaultdict(list)
        # file path → set of node_ids defined in that file
        self._file_nodes: Dict[str, Set[str]]       = defaultdict(set)
        self.version: int = 0

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add_node(self, node: CPGNode) -> None:
        self.nodes[node.node_id] = node
        if node.file:
            self._file_nodes[node.file].add(node.node_id)
        self.version += 1

    def add_edge(self, edge: CPGEdge) -> None:
        self._adj[edge.src_id].append(edge)
        self._radj[edge.dst_id].append(edge)
        self.version += 1

    def remove_node(self, node_id: str) -> bool:
        """Remove node and all its edges. Returns True if node existed."""
        if node_id not in self.nodes:
            return False
        node = self.nodes.pop(node_id)
        if node.file:
            self._file_nodes[node.file].discard(node_id)

        # Drop outgoing edges from this node
        self._adj.pop(node_id, None)
        # Drop incoming edges to this node
        self._radj.pop(node_id, None)

        # Remove this node from other nodes' adjacency lists
        for src_id in list(self._adj):
            before = len(self._adj[src_id])
            self._adj[src_id] = [e for e in self._adj[src_id] if e.dst_id != node_id]
            if len(self._adj[src_id]) != before and not self._adj[src_id]:
                del self._adj[src_id]
        for dst_id in list(self._radj):
            before = len(self._radj[dst_id])
            self._radj[dst_id] = [e for e in self._radj[dst_id] if e.src_id != node_id]
            if len(self._radj[dst_id]) != before and not self._radj[dst_id]:
                del self._radj[dst_id]

        self.version += 1
        return True

    def remove_edge(
        self,
        src_id: str,
        dst_id: str,
        edge_type: Optional[CPGEdgeType] = None,
    ) -> int:
        """Remove matching edges. Returns count of removed edges."""
        removed = 0

        def _matches(e: CPGEdge) -> bool:
            return e.dst_id == dst_id and (edge_type is None or e.edge_type == edge_type)

        if src_id in self._adj:
            before = len(self._adj[src_id])
            self._adj[src_id] = [e for e in self._adj[src_id] if not _matches(e)]
            removed = before - len(self._adj[src_id])

        def _rev_matches(e: CPGEdge) -> bool:
            return e.src_id == src_id and (edge_type is None or e.edge_type == edge_type)

        if dst_id in self._radj:
            self._radj[dst_id] = [e for e in self._radj[dst_id] if not _rev_matches(e)]

        if removed:
            self.version += 1
        return removed

    def invalidate_file(self, filepath: str) -> int:
        """Remove all nodes (and their edges) belonging to filepath.
        Returns the number of nodes removed."""
        node_ids = list(self._file_nodes.get(filepath, set()))
        for nid in node_ids:
            self.remove_node(nid)
        self._file_nodes.pop(filepath, None)
        return len(node_ids)

    # ------------------------------------------------------------------
    # Traversal
    # ------------------------------------------------------------------

    def reachable(
        self,
        start_id: str,
        edge_types: Optional[List[CPGEdgeType]] = None,
        max_depth: int = 30,
    ) -> Set[str]:
        """BFS reachability from start_id.
        Returns set of reachable node_ids (start_id itself excluded)."""
        if start_id not in self.nodes:
            return set()
        type_filter: Optional[Set[CPGEdgeType]] = set(edge_types) if edge_types else None
        visited: Set[str] = set()
        queue: deque[Tuple[str, int]] = deque([(start_id, 0)])
        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for edge in self._adj.get(current, []):
                if type_filter and edge.edge_type not in type_filter:
                    continue
                if edge.dst_id not in visited:
                    visited.add(edge.dst_id)
                    queue.append((edge.dst_id, depth + 1))
        return visited

    def all_paths(
        self,
        src_id: str,
        dst_id: str,
        edge_types: Optional[List[CPGEdgeType]] = None,
        max_depth: int = 30,
        max_paths: int = 10,
    ) -> List[List[str]]:
        """DFS enumerate all simple paths from src_id to dst_id.
        Returns list of paths (each a list of node_ids including both endpoints)."""
        if src_id not in self.nodes or dst_id not in self.nodes:
            return []
        type_filter: Optional[Set[CPGEdgeType]] = set(edge_types) if edge_types else None
        paths: List[List[str]] = []

        def _dfs(current: str, path: List[str], visited: Set[str]) -> None:
            if len(paths) >= max_paths or len(path) > max_depth:
                return
            if current == dst_id and len(path) > 1:
                paths.append(list(path))
                return
            for edge in self._adj.get(current, []):
                if type_filter and edge.edge_type not in type_filter:
                    continue
                nxt = edge.dst_id
                if nxt not in visited:
                    visited.add(nxt)
                    path.append(nxt)
                    _dfs(nxt, path, visited)
                    path.pop()
                    visited.discard(nxt)

        _dfs(src_id, [src_id], {src_id})
        return paths

    def predecessors(
        self,
        node_id: str,
        edge_types: Optional[List[CPGEdgeType]] = None,
    ) -> List[CPGNode]:
        """Return all nodes with an edge pointing to node_id."""
        type_filter: Optional[Set[CPGEdgeType]] = set(edge_types) if edge_types else None
        result: List[CPGNode] = []
        for edge in self._radj.get(node_id, []):
            if type_filter and edge.edge_type not in type_filter:
                continue
            node = self.nodes.get(edge.src_id)
            if node:
                result.append(node)
        return result

    def successors(
        self,
        node_id: str,
        edge_types: Optional[List[CPGEdgeType]] = None,
    ) -> List[CPGNode]:
        """Return all nodes reachable in one step from node_id."""
        type_filter: Optional[Set[CPGEdgeType]] = set(edge_types) if edge_types else None
        result: List[CPGNode] = []
        for edge in self._adj.get(node_id, []):
            if type_filter and edge.edge_type not in type_filter:
                continue
            node = self.nodes.get(edge.dst_id)
            if node:
                result.append(node)
        return result

    # ------------------------------------------------------------------
    # Info / serialisation
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, int]:
        total_edges = sum(len(v) for v in self._adj.values())
        return {
            "nodes":   len(self.nodes),
            "edges":   total_edges,
            "files":   len(self._file_nodes),
            "version": self.version,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [
                e.to_dict()
                for edges in self._adj.values()
                for e in edges
            ],
            "stats": self.stats(),
        }


# ---------------------------------------------------------------------------
# Helpers for the builder
# ---------------------------------------------------------------------------

class _Counter:
    """Thread-unsafe monotonic counter for node IDs (fast, single-process use)."""
    __slots__ = ("_n",)

    def __init__(self) -> None:
        self._n = 0

    def next(self, prefix: str = "n") -> str:
        self._n += 1
        return f"{prefix}{self._n}"


_TAINT_SOURCES = frozenset([
    "request.", "flask.request", "bottle.request",
    "input(", "sys.argv", "os.environ", "os.getenv(",
    "args.", "kwargs.", "form[", "json[", "get_json",
])

_TAINT_SINKS = frozenset([
    "execute(", ".execute(", "eval(", "exec(",
    "os.system(", "subprocess.", "popen(", "Popen(",
    "render_template_string(", "Template(",
    "open(", "pickle.load", "yaml.load(",
])


def _is_source(code: str) -> bool:
    cl = code.lower()
    return any(p in cl for p in _TAINT_SOURCES)


def _is_sink(code: str) -> bool:
    cl = code.lower()
    return any(p in cl for p in _TAINT_SINKS)


def _has_entry_decorator(decorator_list: list) -> bool:
    """Return True if any decorator matches route/endpoint/HTTP-method names."""
    _ENTRY_KW = {"route", "endpoint", "get", "post", "put", "delete", "patch", "view"}
    for dec in decorator_list:
        name = ""
        if isinstance(dec, ast.Name):
            name = dec.id
        elif isinstance(dec, ast.Attribute):
            name = dec.attr
        elif isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Name):
                name = dec.func.id
            elif isinstance(dec.func, ast.Attribute):
                name = dec.func.attr
        if any(kw in name.lower() for kw in _ENTRY_KW):
            return True
    return False


# ---------------------------------------------------------------------------
# Python CPG builder
# ---------------------------------------------------------------------------

class PythonCPGBuilder:
    """
    Builds a CodePropertyGraph from Python source files using the ``ast`` module.

    For each function definition:
    - Creates CFG_ENTRY and CFG_EXIT nodes
    - Chains statements with CFG_NEXT edges
    - Creates CFG_BRANCH nodes for if/while/for with CFG_BRANCH_TRUE / _FALSE edges
    - Detects taint sources (DFG_SOURCE) and sinks (DFG_SINK) by code pattern
    - Creates CG_CALL nodes connected via CG_CALL edge
    - Creates DFG_FLOW edges when a variable is assigned from a previously defined var
    - Second pass: links CG_CALL nodes to their target CFG_ENTRY nodes
    """

    def __init__(self) -> None:
        self._ctr = _Counter()

    def _nid(self) -> str:
        return self._ctr.next()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_file(
        self,
        filepath: str,
        cpg: Optional[CodePropertyGraph] = None,
    ) -> CodePropertyGraph:
        """Parse one Python file and append its CPG to *cpg* (creates new if None)."""
        if cpg is None:
            cpg = CodePropertyGraph()
        try:
            source = Path(filepath).read_text(encoding="utf-8", errors="replace")
            tree   = ast.parse(source, filename=filepath)
        except (SyntaxError, OSError, ValueError):
            return cpg

        lines = source.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Only process top-level and first-level methods (skip deep nesting)
                self._build_function(node, filepath, lines, cpg)

        return cpg

    def build_project(self, path: str) -> CodePropertyGraph:
        """Build CPG for all Python files under *path*."""
        cpg  = CodePropertyGraph()
        root = Path(path)

        if root.is_file():
            return self.build_file(str(root), cpg)

        _SKIP = {"__pycache__", ".git", "node_modules", ".venv", "venv", "dist", "build"}
        for py_file in sorted(root.rglob("*.py")):
            if any(s in py_file.parts for s in _SKIP):
                continue
            self.build_file(str(py_file), cpg)

        self._resolve_cross_file_calls(cpg)
        return cpg

    # ------------------------------------------------------------------
    # Function builder
    # ------------------------------------------------------------------

    def _build_function(
        self,
        func_node: ast.FunctionDef,
        filepath:  str,
        lines:     List[str],
        cpg:       CodePropertyGraph,
    ) -> str:
        """Build CFG/DFG for one function. Returns CFG_ENTRY node_id."""
        func_name  = func_node.name
        is_async   = isinstance(func_node, ast.AsyncFunctionDef)
        is_entry   = _has_entry_decorator(func_node.decorator_list)
        entry_line = func_node.lineno

        # CFG_ENTRY
        entry_id = self._nid()
        cpg.add_node(CPGNode(
            node_id   = entry_id,
            node_type = CPGNodeType.CFG_ENTRY,
            code      = f"def {func_name}(...)",
            ast_type  = "FunctionDef",
            file      = filepath,
            line      = entry_line,
            function  = func_name,
            properties = {
                "func_name": func_name,
                "is_async":  is_async,
                "is_entry":  is_entry,
                "args":      [a.arg for a in func_node.args.args],
            },
        ))

        # CFG_EXIT
        exit_line = getattr(func_node, "end_lineno", entry_line)
        exit_id   = self._nid()
        cpg.add_node(CPGNode(
            node_id   = exit_id,
            node_type = CPGNodeType.CFG_EXIT,
            code      = f"# end {func_name}",
            ast_type  = "Return",
            file      = filepath,
            line      = exit_line,
            function  = func_name,
        ))

        defined_vars: Dict[str, str] = {}   # var_name → node_id of its definition
        prev_ids: List[str]          = [entry_id]

        for stmt in func_node.body:
            stmt_id, exits = self._build_stmt(
                stmt, filepath, lines, func_name, cpg, defined_vars
            )
            if stmt_id:
                for pid in prev_ids:
                    cpg.add_edge(CPGEdge(pid, stmt_id, CPGEdgeType.CFG_NEXT))
                prev_ids = exits if exits else [stmt_id]

        for pid in prev_ids:
            cpg.add_edge(CPGEdge(pid, exit_id, CPGEdgeType.CFG_NEXT))

        return entry_id

    # ------------------------------------------------------------------
    # Statement builder
    # ------------------------------------------------------------------

    def _build_stmt(
        self,
        stmt:         ast.stmt,
        filepath:     str,
        lines:        List[str],
        func_name:    str,
        cpg:          CodePropertyGraph,
        defined_vars: Dict[str, str],
    ) -> Tuple[Optional[str], List[str]]:
        """Build CPG nodes for one statement. Returns (node_id, exit_node_ids)."""
        if isinstance(stmt, (ast.If, ast.While, ast.For)):
            return self._build_branch(stmt, filepath, lines, func_name, cpg, defined_vars)

        # Python 3.10+ match/case (ast.Match is absent on older interpreters)
        _ast_Match = getattr(ast, "Match", None)
        if _ast_Match is not None and isinstance(stmt, _ast_Match):
            return self._build_match(stmt, filepath, lines, func_name, cpg, defined_vars)

        # Extract source code line
        line_no = getattr(stmt, "lineno", 0)
        idx     = line_no - 1
        code    = (lines[idx].strip()[:200] if 0 <= idx < len(lines) else "")
        stmt_type = type(stmt).__name__

        # Choose node type
        if isinstance(stmt, ast.Assign):
            if _is_source(code):
                ntype = CPGNodeType.DFG_SOURCE
            elif _is_sink(code):
                ntype = CPGNodeType.DFG_SINK
            else:
                ntype = CPGNodeType.CFG_NODE
        elif isinstance(stmt, (ast.Return, ast.Raise)):
            ntype = CPGNodeType.CFG_EXIT
        else:
            ntype = CPGNodeType.CFG_NODE

        node_id = self._nid()
        cpg.add_node(CPGNode(
            node_id    = node_id,
            node_type  = ntype,
            code       = code,
            ast_type   = stmt_type,
            file       = filepath,
            line       = line_no,
            function   = func_name,
            properties = {"condition": code},
        ))

        # DFG edges for variable assignments
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    # If RHS is a known variable, add DFG_FLOW
                    if isinstance(stmt.value, ast.Name):
                        src_var = stmt.value.id
                        if src_var in defined_vars:
                            cpg.add_edge(CPGEdge(
                                defined_vars[src_var], node_id, CPGEdgeType.DFG_FLOW
                            ))
                    defined_vars[target.id] = node_id

        # CG_CALL nodes for every Call in this statement
        for child in ast.walk(stmt):
            if not isinstance(child, ast.Call):
                continue
            callee_name = ""
            if isinstance(child.func, ast.Name):
                callee_name = child.func.id
            elif isinstance(child.func, ast.Attribute):
                callee_name = child.func.attr
            if not callee_name:
                continue
            call_id = self._nid()
            call_line = getattr(child, "lineno", line_no)
            cpg.add_node(CPGNode(
                node_id    = call_id,
                node_type  = CPGNodeType.CG_CALL,
                code       = f"{callee_name}(...)",
                ast_type   = "Call",
                file       = filepath,
                line       = call_line,
                function   = func_name,
                properties = {"callee": callee_name},
            ))
            cpg.add_edge(CPGEdge(node_id, call_id, CPGEdgeType.CG_CALL))
            break  # one call node per statement to keep the graph tractable

        # Build sub-graphs for any comprehension / generator expression
        # embedded in this statement (each creates an implicit scope)
        _COMP_TYPES = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        for child in ast.walk(stmt):
            if isinstance(child, _COMP_TYPES):
                self._build_comprehension(
                    child, filepath, lines, func_name, cpg, defined_vars, node_id
                )
                break  # one comprehension sub-graph per statement

        return node_id, [node_id]

    # ------------------------------------------------------------------
    # Branch builder
    # ------------------------------------------------------------------

    def _build_branch(
        self,
        stmt:         ast.stmt,
        filepath:     str,
        lines:        List[str],
        func_name:    str,
        cpg:          CodePropertyGraph,
        defined_vars: Dict[str, str],
    ) -> Tuple[str, List[str]]:
        """Build if / while / for branch node with TRUE/FALSE edge arms."""
        line_no = getattr(stmt, "lineno", 0)
        idx     = line_no - 1
        code    = (lines[idx].strip()[:200] if 0 <= idx < len(lines) else "")

        branch_id = self._nid()
        cpg.add_node(CPGNode(
            node_id    = branch_id,
            node_type  = CPGNodeType.CFG_BRANCH,
            code       = code,
            ast_type   = type(stmt).__name__,
            file       = filepath,
            line       = line_no,
            function   = func_name,
            properties = {"condition": code},
        ))

        exit_ids: List[str] = []

        # True body
        true_prev = [branch_id]
        for body_stmt in (getattr(stmt, "body", None) or []):
            sid, sexits = self._build_stmt(
                body_stmt, filepath, lines, func_name, cpg, defined_vars
            )
            if sid:
                for pid in true_prev:
                    edge_type = (
                        CPGEdgeType.CFG_BRANCH_TRUE if pid == branch_id
                        else CPGEdgeType.CFG_NEXT
                    )
                    cpg.add_edge(CPGEdge(pid, sid, edge_type))
                true_prev = sexits if sexits else [sid]
        exit_ids.extend(true_prev)

        # False / else body
        orelse = getattr(stmt, "orelse", None) or []
        if orelse:
            false_prev = [branch_id]
            for or_stmt in orelse:
                sid, sexits = self._build_stmt(
                    or_stmt, filepath, lines, func_name, cpg, defined_vars
                )
                if sid:
                    for pid in false_prev:
                        edge_type = (
                            CPGEdgeType.CFG_BRANCH_FALSE if pid == branch_id
                            else CPGEdgeType.CFG_NEXT
                        )
                        cpg.add_edge(CPGEdge(pid, sid, edge_type))
                    false_prev = sexits if sexits else [sid]
            exit_ids.extend(false_prev)
        else:
            # No else branch: the branch node itself is a fallthrough exit
            exit_ids.append(branch_id)

        return branch_id, exit_ids

    # ------------------------------------------------------------------
    # Comprehension builder (ListComp / SetComp / DictComp / GeneratorExp)
    # ------------------------------------------------------------------

    def _build_comprehension(
        self,
        comp:         ast.expr,
        filepath:     str,
        lines:        List[str],
        func_name:    str,
        cpg:          CodePropertyGraph,
        defined_vars: Dict[str, str],
        parent_id:    str,
    ) -> Optional[str]:
        """
        Build a CFG sub-graph for a comprehension / generator expression.

        Each comprehension creates an implicit scope (PEP 289).  We model it
        as a CFG_BRANCH node (the implicit loop) connected to the parent
        statement, plus DFG_DEF nodes for each iteration variable.
        Returns the branch node_id (or None on error).
        """
        line_no   = getattr(comp, "lineno", 0)
        idx       = line_no - 1
        comp_type = type(comp).__name__
        code      = lines[idx].strip()[:200] if 0 <= idx < len(lines) else f"<{comp_type}>"

        branch_id = self._nid()
        cpg.add_node(CPGNode(
            node_id    = branch_id,
            node_type  = CPGNodeType.CFG_BRANCH,
            code       = code,
            ast_type   = comp_type,
            file       = filepath,
            line       = line_no,
            function   = func_name,
            properties = {"comprehension_type": comp_type},
        ))
        cpg.add_edge(CPGEdge(parent_id, branch_id, CPGEdgeType.CFG_NEXT))

        for gen in getattr(comp, "generators", []):
            # Resolve the iterable's source code for taint detection
            try:
                iter_code = ast.unparse(gen.iter) if hasattr(ast, "unparse") else ""
            except Exception:
                iter_code = ""

            # Iteration variable definition node
            if isinstance(gen.target, ast.Name):
                var_name = gen.target.id
                iter_id  = self._nid()
                ntype = CPGNodeType.DFG_SOURCE if _is_source(iter_code) else CPGNodeType.DFG_DEF
                cpg.add_node(CPGNode(
                    node_id    = iter_id,
                    node_type  = ntype,
                    code       = f"{var_name} = <iter>",
                    ast_type   = "comprehension",
                    file       = filepath,
                    line       = line_no,
                    function   = func_name,
                    properties = {"var_name": var_name, "is_comp_var": True},
                ))
                cpg.add_edge(CPGEdge(branch_id, iter_id, CPGEdgeType.CFG_BRANCH_TRUE))
                defined_vars[var_name] = iter_id

        return branch_id

    # ------------------------------------------------------------------
    # Match/case builder (Python 3.10+ ast.Match)
    # ------------------------------------------------------------------

    def _build_match(
        self,
        stmt:         ast.stmt,
        filepath:     str,
        lines:        List[str],
        func_name:    str,
        cpg:          CodePropertyGraph,
        defined_vars: Dict[str, str],
    ) -> Tuple[str, List[str]]:
        """
        Build CFG nodes for a match/case statement (Python 3.10+ ast.Match).
        Creates a CFG_BRANCH node for the match subject and arms for each case.
        Returns (match_node_id, exit_node_ids).
        """
        line_no = getattr(stmt, "lineno", 0)
        idx     = line_no - 1
        code    = lines[idx].strip()[:200] if 0 <= idx < len(lines) else "match ..."

        match_id = self._nid()
        cpg.add_node(CPGNode(
            node_id    = match_id,
            node_type  = CPGNodeType.CFG_BRANCH,
            code       = code,
            ast_type   = "Match",
            file       = filepath,
            line       = line_no,
            function   = func_name,
            properties = {"is_match": True},
        ))

        exit_ids:   List[str] = []
        first_case: bool      = True

        for case in (getattr(stmt, "cases", []) or []):
            case_prev = [match_id]
            for body_stmt in (getattr(case, "body", []) or []):
                sid, sexits = self._build_stmt(
                    body_stmt, filepath, lines, func_name, cpg, defined_vars
                )
                if sid:
                    for pid in case_prev:
                        if pid == match_id:
                            etype = (
                                CPGEdgeType.CFG_BRANCH_TRUE
                                if first_case
                                else CPGEdgeType.CFG_BRANCH_FALSE
                            )
                        else:
                            etype = CPGEdgeType.CFG_NEXT
                        cpg.add_edge(CPGEdge(pid, sid, etype))
                    case_prev = sexits if sexits else [sid]
            exit_ids.extend(case_prev)
            first_case = False

        if not exit_ids:
            exit_ids.append(match_id)

        return match_id, exit_ids

    # ------------------------------------------------------------------
    # Cross-file call resolution (second pass)
    # ------------------------------------------------------------------

    def _resolve_cross_file_calls(self, cpg: CodePropertyGraph) -> None:
        """Link CG_CALL nodes to the CFG_ENTRY of their callee (where name matches)."""
        # Build callee_name → CFG_ENTRY node_id map
        func_entries: Dict[str, str] = {}
        for node_id, node in cpg.nodes.items():
            if node.node_type == CPGNodeType.CFG_ENTRY:
                fname = node.properties.get("func_name", "")
                if fname:
                    func_entries[fname] = node_id

        for node_id, node in cpg.nodes.items():
            if node.node_type != CPGNodeType.CG_CALL:
                continue
            callee = node.properties.get("callee", "")
            if not callee or callee not in func_entries:
                continue
            target_id = func_entries[callee]
            # Avoid duplicate edges
            already = any(
                e.dst_id == target_id and e.edge_type == CPGEdgeType.CG_CALL
                for e in cpg._adj.get(node_id, [])
            )
            if not already:
                cpg.add_edge(CPGEdge(node_id, target_id, CPGEdgeType.CG_CALL))
