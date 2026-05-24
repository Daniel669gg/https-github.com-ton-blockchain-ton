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
