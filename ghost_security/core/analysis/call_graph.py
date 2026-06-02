"""
Ghost Security Platform — Call Graph Generator
AST-based call graph for Python source trees.
Generates: function nodes, call edges, entrypoints, dead code detection.
"""
from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class FuncNode:
    name:       str
    module:     str
    file:       str
    lineno:     int
    is_async:   bool = False
    calls:      List[str] = field(default_factory=list)   # fully-qualified names called
    called_by:  List[str] = field(default_factory=list)   # who calls this
    is_entry:   bool = False                              # no callers → potential entrypoint
    is_dead:    bool = False                              # never called

    @property
    def qualified_name(self) -> str:
        return f"{self.module}.{self.name}"

    def to_dict(self) -> dict:
        return {
            "name":        self.name,
            "module":      self.module,
            "file":        self.file,
            "lineno":      self.lineno,
            "is_async":    self.is_async,
            "qualified":   self.qualified_name,
            "calls":       self.calls,
            "called_by":   self.called_by,
            "is_entry":    self.is_entry,
            "is_dead":     self.is_dead,
        }


class _FunctionCollector(ast.NodeVisitor):
    """First pass: collect all function definitions."""

    def __init__(self, module: str, filepath: str):
        self.module    = module
        self.filepath  = filepath
        self.functions: List[FuncNode] = []
        self._scope_stack: List[str]   = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter_func(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enter_func(node, is_async=True)

    def _enter_func(self, node, is_async: bool) -> None:
        self._scope_stack.append(node.name)
        fn = FuncNode(
            name      = ".".join(self._scope_stack),
            module    = self.module,
            file      = self.filepath,
            lineno    = node.lineno,
            is_async  = is_async,
        )
        self.functions.append(fn)
        self.generic_visit(node)
        self._scope_stack.pop()

    # also handle class bodies
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()


class _CallCollector(ast.NodeVisitor):
    """Second pass: collect all call expressions within each function."""

    def __init__(self, module: str, known_funcs: Set[str]):
        self.module       = module
        self.known_funcs  = known_funcs
        self.calls: Dict[str, List[str]] = {}  # func_qname → [called_qnames]
        self._scope: List[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter_scope(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enter_scope(node)

    def _enter_scope(self, node) -> None:
        self._scope.append(node.name)
        qname = f"{self.module}.{'.'.join(self._scope)}"
        if qname not in self.calls:
            self.calls[qname] = []
        self.generic_visit(node)
        self._scope.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    def visit_Call(self, node: ast.Call) -> None:
        if not self._scope:
            self.generic_visit(node)
            return
        caller_qname = f"{self.module}.{'.'.join(self._scope)}"
        callee = self._resolve_call(node.func)
        if callee:
            self.calls.setdefault(caller_qname, []).append(callee)
        self.generic_visit(node)

    @staticmethod
    def _resolve_call(func_node) -> Optional[str]:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            # e.g. self.foo, obj.bar
            return func_node.attr
        return None


def _module_name(filepath: str, root: str) -> str:
    """Convert a file path to a dotted module name relative to root."""
    try:
        rel = Path(filepath).relative_to(root)
        parts = list(rel.with_suffix("").parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        return ".".join(parts)
    except ValueError:
        return Path(filepath).stem


class CallGraphGenerator:
    """
    Generate a call graph for a Python project or single file.
    
    Usage:
        gen = CallGraphGenerator()
        graph = gen.build("/path/to/project")
        print(gen.to_json(graph))
    """

    def build(self, path: str) -> dict:
        """
        Build the call graph.
        Returns a dict with nodes, edges, entrypoints, dead_code.
        """
        p = Path(path)
        root = str(p) if p.is_dir() else str(p.parent)
        files = list(p.rglob("*.py")) if p.is_dir() else [p]
        files = [f for f in files if "__pycache__" not in str(f)]

        # Pass 1: collect all function definitions
        all_nodes: Dict[str, FuncNode] = {}
        for f in files:
            module = _module_name(str(f), root)
            try:
                tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue
            collector = _FunctionCollector(module, str(f))
            collector.visit(tree)
            for fn in collector.functions:
                all_nodes[fn.qualified_name] = fn

        known = set(all_nodes.keys())

        # Pass 2: collect calls
        for f in files:
            module = _module_name(str(f), root)
            try:
                tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
            except SyntaxError:
                continue
            caller = _CallCollector(module, known)
            caller.visit(tree)
            for caller_qname, callees in caller.calls.items():
                if caller_qname not in all_nodes:
                    continue
                node = all_nodes[caller_qname]
                for callee in callees:
                    # Try to resolve to a known qualified name
                    resolved = self._resolve(callee, module, known)
                    if resolved:
                        node.calls.append(resolved)
                        all_nodes[resolved].called_by.append(caller_qname)

        # Mark entrypoints and dead code
        for node in all_nodes.values():
            # deduplicate
            node.calls    = list(dict.fromkeys(node.calls))
            node.called_by = list(dict.fromkeys(node.called_by))
            # entrypoint = not called by any known function; typical for main/cli/test
            node.is_entry = len(node.called_by) == 0
            # dead = not called AND not an entrypoint heuristic
            is_test    = "test" in node.name.lower()
            is_main    = node.name in ("main", "__main__", "run")
            is_handler = any(k in node.name.lower() for k in ("handler", "endpoint", "route", "view"))
            node.is_dead = node.is_entry and not is_test and not is_main and not is_handler

        # Build edge list
        edges = []
        for qname, node in all_nodes.items():
            for callee in node.calls:
                edges.append({"from": qname, "to": callee})

        # Top-level stats
        dead_code  = [n for n in all_nodes.values() if n.is_dead]
        entrypoints = [n for n in all_nodes.values() if n.is_entry and not n.is_dead]

        return {
            "nodes":       [n.to_dict() for n in all_nodes.values()],
            "edges":       edges,
            "entrypoints": [n.qualified_name for n in entrypoints],
            "dead_code":   [n.qualified_name for n in dead_code],
            "stats": {
                "total_functions":  len(all_nodes),
                "total_edges":      len(edges),
                "entrypoints":      len(entrypoints),
                "dead_code":        len(dead_code),
                "files_analyzed":   len(files),
            },
        }

    @staticmethod
    def _resolve(callee: str, caller_module: str, known: Set[str]) -> Optional[str]:
        """Try to resolve a bare name to a qualified function name."""
        # Direct qualified match
        if callee in known:
            return callee
        # Same-module match
        candidate = f"{caller_module}.{callee}"
        if candidate in known:
            return candidate
        # Partial suffix match (last module component)
        for qname in known:
            if qname.endswith(f".{callee}"):
                return qname
        return None

    def to_json(self, graph: dict) -> str:
        return json.dumps(graph, indent=2)

    def dot(self, graph: dict) -> str:
        """Export as Graphviz DOT format."""
        lines = ["digraph CallGraph {", "  rankdir=LR;"]
        for edge in graph["edges"]:
            a = edge["from"].replace(".", "_").replace("-", "_")
            b = edge["to"].replace(".", "_").replace("-", "_")
            lines.append(f'  {a} -> {b};')
        lines.append("}")
        return "\n".join(lines)


# ── Incremental Call Graph (Phase 6) ─────────────────────────────────────────

import hashlib as _hashlib
import time as _time


class IncrementalCallGraph:
    """
    Incremental call graph that caches per-file function/call data and only
    re-parses files that have changed (detected by content SHA-256).

    Usage:
        icg = IncrementalCallGraph("/path/to/project")
        graph = icg.build()          # full build
        icg.update_file("auth.py")   # re-parse one file, update edges
        graph = icg.current_graph    # always up-to-date
    """

    def __init__(self, root: str = ".") -> None:
        self.root = str(Path(root).resolve())
        self._gen = CallGraphGenerator()

        # Per-file cache: filepath → {sha, nodes: List[dict], edges: List[dict]}
        self._file_cache: Dict[str, dict] = {}

        # Merged graph (updated incrementally)
        self.current_graph: dict = {
            "nodes": [], "edges": [], "entrypoints": [], "dead_code": [],
            "stats": {},
        }
        self._built = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self) -> dict:
        """Full build: parse all Python files, populate cache, merge graph."""
        root = Path(self.root)
        _SKIP = {"__pycache__", ".git", "node_modules", ".venv", "venv"}
        files = [
            str(f) for f in root.rglob("*.py")
            if not any(s in f.parts for s in _SKIP)
        ]
        for fp in files:
            self._parse_file(fp)
        self._merge()
        self._built = True
        return self.current_graph

    def update_file(self, filepath: str) -> bool:
        """
        Re-parse one file. Only does work if content SHA changed.
        Returns True if the file actually changed and graph was updated.
        """
        fp = str(Path(filepath).resolve())
        new_sha = self._sha(fp)
        cached = self._file_cache.get(fp, {})
        if cached.get("sha") == new_sha:
            return False   # nothing changed
        self._parse_file(fp)
        self._merge()
        return True

    def update_files(self, filepaths: List[str]) -> int:
        """Update multiple files. Returns count of files that actually changed."""
        changed = 0
        for fp in filepaths:
            if self.update_file(fp):
                changed += 1
        return changed

    def remove_file(self, filepath: str) -> bool:
        """Remove a deleted file from the graph."""
        fp = str(Path(filepath).resolve())
        if fp not in self._file_cache:
            return False
        del self._file_cache[fp]
        self._merge()
        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _sha(self, filepath: str) -> str:
        try:
            content = Path(filepath).read_bytes()
            return _hashlib.sha256(content).hexdigest()[:16]
        except OSError:
            return ""

    def _parse_file(self, filepath: str) -> None:
        """Parse one file and store per-file data in cache."""
        sha = self._sha(filepath)
        if not sha:
            return
        root = self.root
        module = _module_name(filepath, root)
        try:
            tree = ast.parse(
                Path(filepath).read_text(encoding="utf-8", errors="replace"),
                filename=filepath,
            )
        except (SyntaxError, OSError):
            self._file_cache[filepath] = {"sha": sha, "nodes": [], "edges": []}
            return

        # Collect function definitions
        collector = _FunctionCollector(module, filepath)
        collector.visit(tree)
        file_nodes: List[dict] = [fn.to_dict() for fn in collector.functions]

        # Collect calls (intra-file resolution only for speed)
        known = {fn.qualified_name for fn in collector.functions}
        caller = _CallCollector(module, known)
        caller.visit(tree)

        file_edges: List[dict] = []
        node_map: Dict[str, FuncNode] = {fn.qualified_name: fn for fn in collector.functions}
        for caller_qname, callees in caller.calls.items():
            if caller_qname not in node_map:
                continue
            for callee in callees:
                resolved = CallGraphGenerator._resolve(callee, module, known)
                if resolved:
                    file_edges.append({"from": caller_qname, "to": resolved})

        self._file_cache[filepath] = {
            "sha": sha, "nodes": file_nodes, "edges": file_edges,
        }

    def _merge(self) -> None:
        """Rebuild merged graph from per-file cache."""
        all_nodes: Dict[str, dict] = {}
        all_edges: List[dict] = []
        called_set: Set[str] = set()

        for data in self._file_cache.values():
            for n in data["nodes"]:
                all_nodes[n["qualified"]] = n
            for e in data["edges"]:
                all_edges.append(e)
                called_set.add(e["to"])

        # Cross-file call resolution
        known = set(all_nodes.keys())
        resolved_edges: List[dict] = []
        for edge in all_edges:
            frm, to = edge["from"], edge["to"]
            if to not in known:
                # Try suffix match
                for q in known:
                    if q.endswith(f".{to}"):
                        to = q
                        break
            if frm in known:
                resolved_edges.append({"from": frm, "to": to})
                called_set.add(to)

        # Mark called_by and entrypoints
        for qname, node in all_nodes.items():
            node["called_by"] = []
            node["is_entry"]  = qname not in called_set
        for edge in resolved_edges:
            if edge["to"] in all_nodes:
                all_nodes[edge["to"]]["called_by"].append(edge["from"])

        entrypoints = [q for q, n in all_nodes.items() if n["is_entry"] and not n.get("is_dead")]
        dead_code   = [
            q for q, n in all_nodes.items()
            if n["is_entry"]
            and not any(k in n["name"].lower() for k in ("test", "main", "handler", "route", "view"))
        ]

        self.current_graph = {
            "nodes":       list(all_nodes.values()),
            "edges":       resolved_edges,
            "entrypoints": entrypoints,
            "dead_code":   dead_code,
            "stats": {
                "total_functions": len(all_nodes),
                "total_edges":     len(resolved_edges),
                "entrypoints":     len(entrypoints),
                "dead_code":       len(dead_code),
                "files_cached":    len(self._file_cache),
            },
        }
