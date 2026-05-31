"""Interprocedural (cross-function, cross-file) taint analysis using call graph + CFG."""
from __future__ import annotations

import ast
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from backend.analysis.callgraph import CallEdge, CallGraphBuilder, FunctionSig
from backend.analysis.dataflow import DefUseAnalyzer

logger = logging.getLogger("tythanai.interprocedural")


# ---------------------------------------------------------------------------
# Taint state
# ---------------------------------------------------------------------------


class TaintState(BaseModel):
    """Carries taint information at a single analysis point."""

    model_config = {"arbitrary_types_allowed": True}

    tainted_vars: Set[str] = Field(default_factory=set)
    # var → rule_id that introduced the taint
    taint_sources: Dict[str, str] = Field(default_factory=dict)
    call_depth: int = 0

    def merge(self, other: "TaintState") -> "TaintState":
        """Return a new TaintState that is the union of self and other."""
        merged_vars = self.tainted_vars | other.tainted_vars
        merged_sources = dict(self.taint_sources)
        for var, rule in other.taint_sources.items():
            if var not in merged_sources:
                merged_sources[var] = rule
        return TaintState(
            tainted_vars=merged_vars,
            taint_sources=merged_sources,
            call_depth=max(self.call_depth, other.call_depth),
        )


# ---------------------------------------------------------------------------
# IP Taint finding
# ---------------------------------------------------------------------------


class IPTaintFinding(BaseModel):
    """A taint flow found by interprocedural analysis."""

    source_file: str
    source_line: int
    source_rule: str
    sink_file: str
    sink_line: int
    sink_rule: str
    # Each step: "file:line:var"
    taint_path: List[str] = Field(default_factory=list)
    confidence: float
    severity: str


# ---------------------------------------------------------------------------
# Source / sink pattern tables
# ---------------------------------------------------------------------------

# Attribute/subscript access patterns that introduce taint.
# Each entry: (chain_prefix_tuple, rule_id)
_SOURCE_ATTR_PATTERNS: List[Tuple[Tuple[str, ...], str]] = [
    (("request", "GET"), "taint/request.GET"),
    (("request", "POST"), "taint/request.POST"),
    (("request", "args"), "taint/request.args"),
    (("request", "form"), "taint/request.form"),
    (("request", "json"), "taint/request.json"),
    (("request", "data"), "taint/request.data"),
    (("os", "environ"), "taint/os.environ"),
    (("sys", "argv"), "taint/sys.argv"),
]

# Call expressions that introduce taint.
# Each entry: (full_chain_tuple, rule_id)
_SOURCE_CALL_PATTERNS: List[Tuple[Tuple[str, ...], str]] = [
    (("input",), "taint/input"),
    (("os", "environ", "get"), "taint/os.environ"),
    (("os", "getenv"), "taint/os.environ"),
]

# Sink call patterns.
# Each entry: (full_chain_tuple, rule_id)
_SINK_CALL_PATTERNS: List[Tuple[Tuple[str, ...], str]] = [
    (("exec",), "sink/exec"),
    (("eval",), "sink/eval"),
    (("os", "system"), "sink/os.system"),
    (("os", "popen"), "sink/os.popen"),
    (("subprocess", "run"), "sink/subprocess"),
    (("subprocess", "call"), "sink/subprocess"),
    (("subprocess", "check_output"), "sink/subprocess"),
    (("subprocess", "check_call"), "sink/subprocess"),
    (("subprocess", "Popen"), "sink/subprocess"),
    (("open",), "sink/open"),
    (("cursor", "execute"), "sink/sql_injection"),
]

# Severity map for sink rules
_SINK_SEVERITY: Dict[str, str] = {
    "sink/exec": "CRITICAL",
    "sink/eval": "CRITICAL",
    "sink/os.system": "CRITICAL",
    "sink/os.popen": "CRITICAL",
    "sink/subprocess": "CRITICAL",
    "sink/sql_injection": "HIGH",
    "sink/open": "HIGH",
}


# ---------------------------------------------------------------------------
# AST helper utilities
# ---------------------------------------------------------------------------


def _attr_chain(node: ast.expr) -> Tuple[str, ...]:
    """Flatten an Attribute chain into a tuple of name parts (left to right)."""
    parts: List[str] = []
    cur: ast.expr = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    parts.reverse()
    return tuple(parts)


def _attr_chain_from_subscript(node: ast.Subscript) -> Tuple[str, ...]:
    """
    Extract the attribute chain from the value of a Subscript node.

    E.g. ``request.GET['key']`` → ``('request', 'GET')``.
    """
    return _attr_chain(node.value)


def _names_in_expr(node: ast.expr) -> Set[str]:
    """Return all Name (Load) references inside an expression subtree.

    Handles BinOp (including %-formatting), Subscript, Attribute, JoinedStr
    (f-strings), and str.format(...) calls so taint propagates through all
    common string-building idioms.
    """
    result: Set[str] = set()
    # ast.walk already recurses into all child nodes, including BinOp left/right,
    # Subscript value/slice, Attribute value, JoinedStr values, and Call args.
    # The original loop was correct for plain Name nodes but missed tainted
    # variable names hidden inside complex sub-expressions because ast.walk
    # DOES visit them — the bug was that Subscript.value could be an Attribute
    # chain (e.g. request.form) rather than a plain Name, so we need to also
    # collect names from the *object being subscripted*.
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
            result.add(n.id)
        # BinOp: recurse into left and right (covers "str" + var and "str" % var)
        elif isinstance(n, ast.BinOp):
            result |= _names_in_expr(n.left)
            result |= _names_in_expr(n.right)
        # Subscript: the object being subscripted carries the taint source
        # e.g. request["field"], request.form["field"], os.environ["KEY"]
        elif isinstance(n, ast.Subscript):
            result |= _names_in_expr(n.value)
        # Attribute: the object the attribute is accessed on
        # e.g. self.email — track 'self' as potentially tainted
        elif isinstance(n, ast.Attribute):
            result |= _names_in_expr(n.value)
        # JoinedStr (f-string): collect names from all formatted values
        elif isinstance(n, ast.JoinedStr):
            for part in n.values:
                if isinstance(part, ast.FormattedValue):
                    result |= _names_in_expr(part.value)
        # str.format() call: "template".format(var) — collect args
        elif isinstance(n, ast.Call):
            if isinstance(n.func, ast.Attribute) and n.func.attr == "format":
                for arg in n.args:
                    result |= _names_in_expr(arg)
                for kw in n.keywords:
                    result |= _names_in_expr(kw.value)
    return result


def _get_param_names(func_node: ast.FunctionDef) -> List[str]:
    """Return positional + keyword parameter names (excluding self/cls)."""
    args = func_node.args
    params: List[str] = (
        [a.arg for a in args.posonlyargs]
        + [a.arg for a in args.args]
        + [a.arg for a in args.kwonlyargs]
    )
    if args.vararg:
        params.append(args.vararg.arg)
    if args.kwarg:
        params.append(args.kwarg.arg)
    return [p for p in params if p not in ("self", "cls")]


# ---------------------------------------------------------------------------
# InterproceduralTaintAnalyzer
# ---------------------------------------------------------------------------


class InterproceduralTaintAnalyzer:
    """
    Perform interprocedural taint analysis across all Python files under
    *project_root*.

    Algorithm:
    1. Discover all .py files and parse their ASTs.
    2. Build the call graph using CallGraphBuilder.
    3. For every function that contains a taint source, seed a TaintState and
       run _propagate_in_function (DFS bounded by max_depth).
    4. Within each function, propagate taint through assignments and check
       each call-site against the sink table.
    5. When a tainted variable is passed as an argument to a callee that
       exists in the project, recursively propagate taint into that callee
       with the corresponding parameters marked as tainted.
    6. Emit one IPTaintFinding per confirmed source→sink path (deduplicated).
    """

    def __init__(self, project_root: str, max_depth: int = 10) -> None:
        self.project_root = project_root
        self.max_depth = max_depth

        # Populated during analyze()
        # "filepath::funcname" → ast.FunctionDef node
        self._func_asts: Dict[str, ast.FunctionDef] = {}
        # filepath → source text
        self._file_sources: Dict[str, str] = {}
        # from CallGraphBuilder
        self._functions_map: Dict[str, FunctionSig] = {}
        self._edges: List[CallEdge] = []
        # func_key → outgoing edges from that caller
        self._caller_index: Dict[str, List[CallEdge]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, entry_points: Optional[List[str]] = None) -> List[IPTaintFinding]:
        """
        Discover all .py files, build the call graph, propagate taint.

        *entry_points*: optional list of file paths to restrict which files
        are used as taint-propagation seeds.  If None, all files are seeded.

        Returns a deduplicated list of :class:`IPTaintFinding`.
        """
        root = Path(self.project_root).resolve()
        if not root.exists():
            logger.warning(
                "InterproceduralTaintAnalyzer: root %s does not exist", root
            )
            return []

        # Load and parse all .py files
        py_files = _collect_py_files(root)
        for fp in py_files:
            try:
                src = Path(fp).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            self._file_sources[fp] = src
            self._parse_func_asts(fp, src)

        # Build the call graph
        builder = CallGraphBuilder()
        self._functions_map, self._edges = builder.build(self.project_root)

        # Build caller index: func_key → [CallEdge]
        for edge in self._edges:
            caller_key = f"{edge.caller_file}::{edge.caller_func}"
            self._caller_index.setdefault(caller_key, []).append(edge)

        findings: List[IPTaintFinding] = []

        # Seed taint from every function that has at least one source
        for func_key, func_node in self._func_asts.items():
            filepath = func_key.rsplit("::", 1)[0]

            # Apply entry-point filter if specified
            if entry_points is not None:
                if not any(ep in filepath for ep in entry_points):
                    continue

            initial_state = self._seed_taint(func_node, filepath)
            if not initial_state.tainted_vars:
                continue

            logger.debug(
                "Seeding taint propagation from %s with vars %s",
                func_key,
                initial_state.tainted_vars,
            )

            new_findings = self._propagate_in_function(
                func_key,
                initial_state,
                visited=set(),
            )
            findings.extend(new_findings)

        # Deduplicate by (source_file, source_line, sink_file, sink_line)
        seen: Set[Tuple[str, int, str, int]] = set()
        unique: List[IPTaintFinding] = []
        for f in findings:
            key = (f.source_file, f.source_line, f.sink_file, f.sink_line)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    # ------------------------------------------------------------------
    # Taint seeding
    # ------------------------------------------------------------------

    def _seed_taint(
        self, func_node: ast.FunctionDef, filepath: str
    ) -> TaintState:
        """
        Walk *func_node* to identify all taint-source assignments and return
        a TaintState pre-populated with those variables.
        """
        state = TaintState()
        for node in ast.walk(func_node):
            if isinstance(node, ast.Assign):
                rule = self._is_source(node.value)
                if rule:
                    for target in node.targets:
                        for n in ast.walk(target):
                            if isinstance(n, ast.Name):
                                state.tainted_vars.add(n.id)
                                state.taint_sources[n.id] = rule
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                rule = self._is_source(node.value)
                if rule and isinstance(node.target, ast.Name):
                    state.tainted_vars.add(node.target.id)
                    state.taint_sources[node.target.id] = rule
        return state

    # ------------------------------------------------------------------
    # DFS taint propagation
    # ------------------------------------------------------------------

    def _propagate_in_function(
        self,
        func_key: str,
        taint_state: TaintState,
        visited: Set[str],
    ) -> List[IPTaintFinding]:
        """
        DFS taint propagation within the function identified by *func_key*.

        For every statement in the function body:
        - Re-seed taint from source patterns (new sources inside the function).
        - Propagate taint through assignment RHS → LHS.
        - Check call-site arguments against the sink table.
        - For outgoing calls to project functions, propagate tainted args into
          the callee's parameters (recursively, depth-limited).

        Returns all IPTaintFindings found during this traversal.
        """
        if taint_state.call_depth >= self.max_depth:
            logger.debug("Depth limit %d reached at %s", self.max_depth, func_key)
            return []

        # Guard against revisiting the same (function × taint-set) combination
        visit_key = (
            f"{func_key}|{','.join(sorted(taint_state.tainted_vars))}"
        )
        if visit_key in visited:
            return []
        visited = visited | {visit_key}

        func_node = self._func_asts.get(func_key)
        if func_node is None:
            return []

        filepath = func_key.rsplit("::", 1)[0]

        # Working copy of the taint state (mutated as we walk statements)
        current = TaintState(
            tainted_vars=set(taint_state.tainted_vars),
            taint_sources=dict(taint_state.taint_sources),
            call_depth=taint_state.call_depth,
        )

        findings: List[IPTaintFinding] = []

        # Walk all nodes in the function body.  ast.walk gives us all nodes in
        # BFS order; we rely on assignments appearing before uses in typical
        # Python code.  This is an over-approximation: it may miss ordering
        # in branches but is sound for the purpose of taint tracking.
        for node in ast.walk(func_node):
            # ── Re-seed from new sources in this function ──────────────
            if isinstance(node, ast.Assign):
                rule = self._is_source(node.value)
                if rule:
                    for target in node.targets:
                        for n in ast.walk(target):
                            if isinstance(n, ast.Name):
                                current.tainted_vars.add(n.id)
                                current.taint_sources[n.id] = rule
                else:
                    # Propagate taint through variable assignments.
                    # _names_in_expr now recurses into BinOp, Subscript, Attribute,
                    # JoinedStr and str.format() so all string-building idioms are
                    # covered (Bugs 1, 2, 3).
                    rhs_names = _names_in_expr(node.value)
                    tainted_rhs = rhs_names & current.tainted_vars
                    if tainted_rhs:
                        prop_rule = next(
                            (current.taint_sources[v] for v in tainted_rhs
                             if v in current.taint_sources),
                            "taint/propagated",
                        )
                        for target in node.targets:
                            for n in ast.walk(target):
                                if isinstance(n, ast.Name):
                                    current.tainted_vars.add(n.id)
                                    current.taint_sources[n.id] = prop_rule
                                # Bug 4: attribute assignment e.g. self.email = tainted
                                # Track the root object ('self') as tainted so that
                                # later uses of self.email propagate the taint.
                                elif isinstance(n, ast.Attribute):
                                    root = n.value
                                    while isinstance(root, ast.Attribute):
                                        root = root.value
                                    if isinstance(root, ast.Name):
                                        current.tainted_vars.add(root.id)
                                        current.taint_sources[root.id] = prop_rule

            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                rule = self._is_source(node.value)
                if rule and isinstance(node.target, ast.Name):
                    current.tainted_vars.add(node.target.id)
                    current.taint_sources[node.target.id] = rule
                elif isinstance(node.target, ast.Name):
                    rhs_names = _names_in_expr(node.value)
                    tainted_rhs = rhs_names & current.tainted_vars
                    if tainted_rhs:
                        prop_rule = next(
                            (current.taint_sources[v] for v in tainted_rhs
                             if v in current.taint_sources),
                            "taint/propagated",
                        )
                        current.tainted_vars.add(node.target.id)
                        current.taint_sources[node.target.id] = prop_rule

            # ── Check call-site sinks and propagate into callees ───────
            if isinstance(node, ast.Call):
                # Check sink
                finding = self._check_sink(node, current, filepath)
                if finding:
                    findings.append(finding)

                # Propagate taint into project callees
                callee_findings = self._propagate_to_callees(
                    func_key, node, current, visited
                )
                findings.extend(callee_findings)

        return findings

    def _propagate_to_callees(
        self,
        caller_key: str,
        call_node: ast.Call,
        current: TaintState,
        visited: Set[str],
    ) -> List[IPTaintFinding]:
        """
        For a call site *call_node* inside *caller_key*, find matching
        call-graph edges and propagate tainted arguments into callees.
        """
        callee_chain = _attr_chain(call_node.func)
        if not callee_chain:
            return []
        callee_name = callee_chain[-1]

        findings: List[IPTaintFinding] = []
        for edge in self._caller_index.get(caller_key, []):
            if edge.callee_func != callee_name:
                continue

            callee_key = f"{edge.callee_file}::{edge.callee_func}"
            callee_node = self._func_asts.get(callee_key)
            if callee_node is None:
                continue

            callee_params = _get_param_names(callee_node)
            new_tainted: Set[str] = set()
            new_sources: Dict[str, str] = {}

            # Positional arguments
            for i, arg in enumerate(call_node.args):
                arg_names = _names_in_expr(arg)
                tainted_arg = arg_names & current.tainted_vars
                if tainted_arg and i < len(callee_params):
                    param = callee_params[i]
                    new_tainted.add(param)
                    for an in tainted_arg:
                        if an in current.taint_sources:
                            new_sources[param] = current.taint_sources[an]
                            break

            # Keyword arguments
            for kw in call_node.keywords:
                if kw.arg is None:
                    continue
                kw_names = _names_in_expr(kw.value)
                tainted_kw = kw_names & current.tainted_vars
                if tainted_kw and kw.arg in callee_params:
                    new_tainted.add(kw.arg)
                    for an in tainted_kw:
                        if an in current.taint_sources:
                            new_sources[kw.arg] = current.taint_sources[an]
                            break

            if new_tainted:
                callee_state = TaintState(
                    tainted_vars=new_tainted,
                    taint_sources=new_sources,
                    call_depth=current.call_depth + 1,
                )
                callee_findings = self._propagate_in_function(
                    callee_key, callee_state, visited=visited
                )
                findings.extend(callee_findings)

        return findings

    # ------------------------------------------------------------------
    # Source detection
    # ------------------------------------------------------------------

    def _is_source(self, node: ast.AST) -> Optional[str]:
        """
        Return the source rule_id if *node* is a recognised taint source,
        otherwise return None.

        Recognised sources:
        - input() call
        - os.getenv(...) / os.environ.get(...)
        - os.environ subscript/attribute access
        - sys.argv subscript/attribute access
        - request.GET / POST / args / form / json / data  (attribute or subscript)
        """
        if not isinstance(node, ast.expr):
            return None

        # ── Call-based sources ─────────────────────────────────────────
        if isinstance(node, ast.Call):
            chain = _attr_chain(node.func)
            for src_chain, rule in _SOURCE_CALL_PATTERNS:
                if chain == src_chain:
                    return rule
            # Also match call chains whose prefix is a known attribute source.
            # Handles flask patterns like request.args.get(...), request.form.get(...)
            # and django patterns like request.GET.get(...).
            if len(chain) >= 2:
                for src_chain, rule in _SOURCE_ATTR_PATTERNS:
                    if tuple(chain[: len(src_chain)]) == src_chain:
                        return rule

        # ── Attribute access sources ───────────────────────────────────
        if isinstance(node, ast.Attribute):
            chain = _attr_chain(node)
            for src_chain, rule in _SOURCE_ATTR_PATTERNS:
                if chain[: len(src_chain)] == src_chain:
                    return rule

        # ── Subscript sources (e.g. request.GET['key'], os.environ['KEY'],
        #    request['key'], request.form['field']) ─────────────────────────
        if isinstance(node, ast.Subscript):
            chain = _attr_chain_from_subscript(node)
            for src_chain, rule in _SOURCE_ATTR_PATTERNS:
                if chain[: len(src_chain)] == src_chain:
                    return rule
            # Also check a plain-Name subscript: request["key"] where
            # _attr_chain produces just ("request",).  We match any single-
            # element chain whose name appears as the first part of a source.
            if len(chain) == 1:
                for src_chain, rule in _SOURCE_ATTR_PATTERNS:
                    if chain[0] == src_chain[0]:
                        return rule

        return None

    # ------------------------------------------------------------------
    # Sink detection
    # ------------------------------------------------------------------

    def _check_sink(
        self,
        call: ast.Call,
        taint_state: TaintState,
        filepath: str,
    ) -> Optional[IPTaintFinding]:
        """
        Check if *call* is a known sink receiving tainted data.

        Returns an :class:`IPTaintFinding` if a violation is found, else None.
        """
        chain = _attr_chain(call.func)

        sink_rule: Optional[str] = None
        for sink_chain, rule in _SINK_CALL_PATTERNS:
            if chain == sink_chain:
                sink_rule = rule
                break
        # Accept any *.execute() call as a SQL sink
        if sink_rule is None and len(chain) >= 1 and chain[-1] == "execute":
            sink_rule = "sink/sql_injection"

        if sink_rule is None:
            return None

        # Collect all Name references used in the call arguments
        all_arg_names: Set[str] = set()
        for arg in call.args:
            all_arg_names |= _names_in_expr(arg)
        for kw in call.keywords:
            all_arg_names |= _names_in_expr(kw.value)

        tainted_args = all_arg_names & taint_state.tainted_vars
        if not tainted_args:
            return None

        lineno: int = getattr(call, "lineno", 0)
        source_var = next(iter(tainted_args))
        source_rule = taint_state.taint_sources.get(source_var, "taint/unknown")

        return IPTaintFinding(
            source_file=filepath,
            source_line=lineno,
            source_rule=source_rule,
            sink_file=filepath,
            sink_line=lineno,
            sink_rule=sink_rule,
            taint_path=[f"{filepath}:{lineno}:{source_var}"],
            confidence=0.85,
            severity=_SINK_SEVERITY.get(sink_rule, "HIGH"),
        )

    # ------------------------------------------------------------------
    # AST loading helpers
    # ------------------------------------------------------------------

    def _parse_func_asts(self, filepath: str, source: str) -> None:
        """Parse *source* and store all FunctionDef nodes in _func_asts."""
        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError as exc:
            logger.warning(
                "interprocedural: parse error in %s: %s", filepath, exc
            )
            return
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                key = f"{filepath}::{node.name}"
                # Last definition wins for duplicate names
                self._func_asts[key] = node  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Module-level file-collection helper
# ---------------------------------------------------------------------------


def _collect_py_files(root: Path) -> List[str]:
    """Return all .py files under *root*, skipping common non-project dirs."""
    skip_dirs = {
        "__pycache__", ".git", ".venv", "venv", "env",
        "node_modules", "site-packages", ".tox", "build", "dist",
    }
    results: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in skip_dirs and not d.startswith(".")
        ]
        for fname in filenames:
            if fname.endswith(".py"):
                results.append(os.path.join(dirpath, fname))
    return sorted(results)


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------


def analyze_project_taint(
    project_root: str,
    max_depth: int = 10,
) -> List[IPTaintFinding]:
    """
    Convenience wrapper: run interprocedural taint analysis on *project_root*.

    Returns a list of :class:`IPTaintFinding` objects.
    """
    analyzer = InterproceduralTaintAnalyzer(project_root, max_depth)
    return analyzer.analyze()
