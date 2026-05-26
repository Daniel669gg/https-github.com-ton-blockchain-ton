"""
Ghost Security — Python AST Taint Tracker
Intraprocedural taint analysis: tracks user-controlled data from sources
to dangerous sinks within a single function body.
"""
from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .source_sink_db import PYTHON_SANITIZERS, PYTHON_SINKS, PYTHON_SOURCES

log = logging.getLogger("ghost.taint_tracker")

# Flatten sink names for quick look-up
_ALL_SINK_NAMES: Set[str] = {
    s for sinks in PYTHON_SINKS.values() for s in sinks
}

# Normalise source list into bare names for AST matching
_SOURCE_NAMES: Set[str] = {s.split(".")[-1] for s in PYTHON_SOURCES}
_SOURCE_ATTRS: Set[str] = set(PYTHON_SOURCES)

# Categorise sinks by their category key
_SINK_CATEGORY: Dict[str, str] = {
    s: cat
    for cat, sinks in PYTHON_SINKS.items()
    for s in sinks
}


@dataclass
class TaintFlow:
    """A single detected taint flow from source to sink."""
    source: str
    sink: str
    category: str
    variable: str
    source_line: int
    sink_line: int
    sanitized: bool = False
    message: str = ""

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "sink": self.sink,
            "category": self.category,
            "variable": self.variable,
            "source_line": self.source_line,
            "sink_line": self.sink_line,
            "sanitized": self.sanitized,
            "message": self.message,
        }


def _node_is_source(node: ast.expr) -> bool:
    """Return True if the AST expression looks like a taint source."""
    # input() call
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in _SOURCE_NAMES:
            return True
        # request.args / request.form / request.json etc.
        if isinstance(node.func, ast.Attribute):
            full = _attr_chain(node.func)
            if full in _SOURCE_ATTRS:
                return True
            # request.args.get(...) etc.
            if any(full.startswith(s) for s in _SOURCE_ATTRS):
                return True
    # sys.argv, os.environ attribute access
    if isinstance(node, ast.Attribute):
        full = _attr_chain(node)
        if full in _SOURCE_ATTRS:
            return True
    # Subscript: request.args["x"]
    if isinstance(node, ast.Subscript):
        return _node_is_source(node.value)
    return False


def _attr_chain(node: ast.expr, parts: Optional[List[str]] = None) -> str:
    """Flatten an Attribute chain to a dotted string, e.g. request.args.get"""
    if parts is None:
        parts = []
    if isinstance(node, ast.Attribute):
        _attr_chain(node.value, parts)
        parts.append(node.attr)
    elif isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(parts)


def _node_is_sanitizer(node: ast.expr) -> bool:
    """Return True if the call is a known sanitizer."""
    if isinstance(node, ast.Call):
        name = _attr_chain(node.func) if isinstance(node.func, ast.Attribute) else (
            node.func.id if isinstance(node.func, ast.Name) else ""
        )
        return name in PYTHON_SANITIZERS or any(s in name for s in PYTHON_SANITIZERS)
    return False


def _call_matches_sink(call: ast.Call) -> Optional[str]:
    """Return sink key if this call is a dangerous sink, else None."""
    name = ""
    if isinstance(call.func, ast.Attribute):
        name = _attr_chain(call.func)
    elif isinstance(call.func, ast.Name):
        name = call.func.id

    # Exact match first
    if name in _SINK_CATEGORY:
        return name

    # Suffix match: "cursor.execute" ends with "execute"
    for sink_name in _ALL_SINK_NAMES:
        if name == sink_name or name.endswith("." + sink_name):
            return sink_name

    return None


class _FunctionTaintVisitor(ast.NodeVisitor):
    """
    Visits a single FunctionDef / AsyncFunctionDef and performs simple
    intraprocedural taint tracking.
    """

    def __init__(self, func_name: str) -> None:
        self.func_name = func_name
        # var_name -> (source_description, lineno, is_tainted, sanitized)
        self.tainted: Dict[str, dict] = {}
        self.flows: List[TaintFlow] = []
        self._processing = False

    # ── assignments ────────────────────────────────────────────────────────────

    def visit_Assign(self, node: ast.Assign) -> None:
        rhs = node.value
        if _node_is_source(rhs):
            src_desc = _describe_source(rhs)
            for target in node.targets:
                for name in _extract_names(target):
                    self.tainted[name] = {
                        "source": src_desc,
                        "line": node.lineno,
                        "sanitized": False,
                    }
        elif _node_is_sanitizer(rhs):
            # Anything that flows through a sanitizer is clean
            for target in node.targets:
                for name in _extract_names(target):
                    if name in self.tainted:
                        self.tainted[name]["sanitized"] = True
        else:
            # Propagate taint through simple expressions
            tainted_rhs = _rhs_uses_tainted(rhs, self.tainted)
            if tainted_rhs:
                for target in node.targets:
                    for name in _extract_names(target):
                        self.tainted[name] = {
                            "source": tainted_rhs["source"],
                            "line": tainted_rhs["line"],
                            "sanitized": tainted_rhs["sanitized"],
                        }
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if isinstance(node.target, ast.Name):
            name = node.target.id
            if _rhs_uses_tainted(node.value, self.tainted):
                # augmented assignment from tainted → still tainted
                if name not in self.tainted:
                    pass  # was clean, becomes partially tainted
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is None:
            return
        if _node_is_source(node.value):
            src_desc = _describe_source(node.value)
            if isinstance(node.target, ast.Name):
                self.tainted[node.target.id] = {
                    "source": src_desc,
                    "line": node.lineno,
                    "sanitized": False,
                }
        self.generic_visit(node)

    # ── sink detection ─────────────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:
        sink_key = _call_matches_sink(node)
        if sink_key:
            self._check_args_for_taint(node, sink_key)
        self.generic_visit(node)

    def _check_args_for_taint(self, call: ast.Call, sink_name: str) -> None:
        all_args: List[ast.expr] = list(call.args) + [
            kw.value for kw in call.keywords
        ]
        for arg in all_args:
            taint_info = _arg_taint_info(arg, self.tainted)
            if taint_info:
                category = _SINK_CATEGORY.get(sink_name, "unknown")
                flow = TaintFlow(
                    source=taint_info["source"],
                    sink=sink_name,
                    category=category,
                    variable=taint_info.get("var", "?"),
                    source_line=taint_info["line"],
                    sink_line=call.lineno,
                    sanitized=taint_info["sanitized"],
                    message=(
                        f"Tainted value from '{taint_info['source']}' "
                        f"reaches '{sink_name}' sink "
                        + ("(SANITIZED)" if taint_info["sanitized"] else "(UNSANITIZED)")
                    ),
                )
                self.flows.append(flow)


# ── helpers ────────────────────────────────────────────────────────────────────

def _extract_names(node: ast.expr) -> List[str]:
    """Extract variable names from an assignment target."""
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        names: List[str] = []
        for elt in node.elts:
            names.extend(_extract_names(elt))
        return names
    return []


def _describe_source(node: ast.expr) -> str:
    """Human-readable description of a source node."""
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute):
            return _attr_chain(node.func)
        if isinstance(node.func, ast.Name):
            return node.func.id
    if isinstance(node, ast.Attribute):
        return _attr_chain(node)
    if isinstance(node, ast.Subscript):
        return _describe_source(node.value)
    return "unknown_source"


def _rhs_uses_tainted(node: ast.expr, tainted: Dict[str, dict]) -> Optional[dict]:
    """
    If `node` directly uses any tainted variable, return its taint info.
    Simple single-level check (not full expression traversal).
    """
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id in tainted:
            return {"var": n.id, **tainted[n.id]}
    return None


def _arg_taint_info(node: ast.expr, tainted: Dict[str, dict]) -> Optional[dict]:
    """Check if an argument (or its sub-expressions) is tainted."""
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id in tainted:
            return {"var": n.id, **tainted[n.id]}
        if _node_is_source(n):
            return {
                "var": "inline",
                "source": _describe_source(n),
                "line": getattr(n, "lineno", 0),
                "sanitized": False,
            }
    return None


class TaintTracker:
    """
    Public API for intraprocedural taint tracking.
    Analyses every function in a Python source file.
    """

    SOURCES: Set[str] = set(PYTHON_SOURCES)
    SINKS: Dict[str, List[str]] = PYTHON_SINKS
    SANITIZERS: Set[str] = PYTHON_SANITIZERS

    def track(self, source_code: str) -> List[dict]:
        """
        Parse *source_code* and return a list of taint flow dicts.
        Each dict has: source, sink, category, variable, source_line,
        sink_line, sanitized, message.
        """
        try:
            tree = ast.parse(source_code)
        except SyntaxError as exc:
            log.warning("TaintTracker: syntax error while parsing: %s", exc)
            return []

        flows: List[dict] = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visitor = _FunctionTaintVisitor(node.name)
                visitor.visit(node)
                for flow in visitor.flows:
                    # Only report unsanitized flows as true vulnerabilities
                    if not flow.sanitized:
                        flows.append(flow.to_dict())

        return flows
