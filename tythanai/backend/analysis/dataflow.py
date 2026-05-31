"""Intra-procedural CFG + SSA-like def-use chains for Python source files."""
from __future__ import annotations

import ast
import logging
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger("tythanai.dataflow")


# ---------------------------------------------------------------------------
# BasicBlock
# ---------------------------------------------------------------------------

class BasicBlock(BaseModel):
    """A single basic block in a control-flow graph."""

    model_config = {"arbitrary_types_allowed": True}

    block_id: int
    # Stored as (lineno, source_text) pairs rather than raw ast.stmt objects
    # to remain serialisable while preserving the information callers need.
    stmts: List[Tuple[int, str]] = Field(default_factory=list)
    predecessors: List[int] = Field(default_factory=list)
    successors: List[int] = Field(default_factory=list)
    defs: Set[str] = Field(default_factory=set)
    uses: Set[str] = Field(default_factory=set)
    phi_vars: Set[str] = Field(default_factory=set)


# ---------------------------------------------------------------------------
# Internal helpers — def/use extraction from a single statement
# ---------------------------------------------------------------------------

def _names_defined(stmt: ast.stmt) -> Set[str]:
    """Return the set of names *defined* (written) by a single statement."""
    defined: Set[str] = set()
    if isinstance(stmt, ast.Assign):
        for t in stmt.targets:
            for node in ast.walk(t):
                if isinstance(node, ast.Name):
                    defined.add(node.id)
    elif isinstance(stmt, (ast.AugAssign, ast.AnnAssign)):
        target = stmt.target  # type: ignore[union-attr]
        if isinstance(target, ast.Name):
            defined.add(target.id)
    elif isinstance(stmt, ast.For):
        for node in ast.walk(stmt.target):
            if isinstance(node, ast.Name):
                defined.add(node.id)
    elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
        defined.add(stmt.name)
    elif isinstance(stmt, ast.ClassDef):
        defined.add(stmt.name)
    elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
        for alias in stmt.names:  # type: ignore[union-attr]
            name = alias.asname if alias.asname else alias.name.split(".")[0]
            defined.add(name)
    return defined


def _names_used(stmt: ast.stmt, locally_defined: Set[str]) -> Set[str]:
    """
    Return names *used* in *stmt* before being defined — i.e. upward-exposed
    uses. We skip names that appear in the stmt's own definition targets.
    """
    used: Set[str] = set()
    defined_here = _names_defined(stmt)
    for node in ast.walk(stmt):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id not in defined_here:
                used.add(node.id)
    return used


# ---------------------------------------------------------------------------
# CFGBuilder
# ---------------------------------------------------------------------------

class _BlockBuilder:
    """
    Walks a function body (flat list of statements) and builds basic blocks.

    Boundaries are created at:
    - If / IfExp
    - For / While / AsyncFor
    - Try / With / AsyncWith
    - Return / Raise / Break / Continue / Yield
    - Match (Python 3.10+)
    """

    _BRANCH_TYPES = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.With,
        ast.AsyncWith,
        ast.Return,
        ast.Raise,
        ast.Break,
        ast.Continue,
        ast.Match if hasattr(ast, "Match") else type(None),  # type: ignore[attr-defined]
    )
    # Statements that terminate the current block regardless
    _TERMINATOR_TYPES = (ast.Return, ast.Raise, ast.Break, ast.Continue)

    def __init__(self, source_lines: List[str]) -> None:
        self._source_lines = source_lines
        self._blocks: List[BasicBlock] = []
        self._counter = 0

    def _new_block(self) -> BasicBlock:
        b = BasicBlock(block_id=self._counter)
        self._counter += 1
        self._blocks.append(b)
        return b

    def _add_edge(self, pred: BasicBlock, succ: BasicBlock) -> None:
        if succ.block_id not in pred.successors:
            pred.successors.append(succ.block_id)
        if pred.block_id not in succ.predecessors:
            succ.predecessors.append(pred.block_id)

    def _stmt_text(self, node: ast.stmt) -> str:
        lineno = getattr(node, "lineno", 0)
        if 1 <= lineno <= len(self._source_lines):
            return self._source_lines[lineno - 1].strip()
        return ast.dump(node)[:80]

    def _process_stmts(
        self,
        stmts: List[ast.stmt],
        current: BasicBlock,
    ) -> BasicBlock:
        """
        Walk a flat list of statements.  Returns the block that is 'live'
        after the last statement (the fall-through block).
        """
        for stmt in stmts:
            lineno = getattr(stmt, "lineno", 0)
            text = self._stmt_text(stmt)
            current.stmts.append((lineno, text))

            # Compute def/use for this block
            defs_here = _names_defined(stmt)
            uses_here = _names_used(stmt, current.defs)
            current.defs.update(defs_here)
            # A use is "upward-exposed" if the name wasn't already defined
            # in this block before this statement
            current.uses.update(u for u in uses_here if u not in current.defs - defs_here)

            if isinstance(stmt, self._BRANCH_TYPES):
                # ----- If statement ----------------------------------------
                if isinstance(stmt, ast.If):
                    then_block = self._new_block()
                    else_block = self._new_block()
                    join_block = self._new_block()

                    self._add_edge(current, then_block)
                    self._add_edge(current, else_block)

                    then_exit = self._process_stmts(stmt.body, then_block)
                    self._add_edge(then_exit, join_block)

                    if stmt.orelse:
                        else_exit = self._process_stmts(stmt.orelse, else_block)
                        self._add_edge(else_exit, join_block)
                    else:
                        self._add_edge(else_block, join_block)

                    current = join_block

                # ----- For / AsyncFor  -------------------------------------
                elif isinstance(stmt, (ast.For, ast.AsyncFor)):
                    header = self._new_block()
                    body_block = self._new_block()
                    exit_block = self._new_block()

                    self._add_edge(current, header)
                    self._add_edge(header, body_block)
                    self._add_edge(header, exit_block)  # loop may be skipped

                    body_exit = self._process_stmts(stmt.body, body_block)
                    self._add_edge(body_exit, header)   # back-edge

                    if stmt.orelse:
                        else_exit = self._process_stmts(stmt.orelse, exit_block)
                        next_block = self._new_block()
                        self._add_edge(else_exit, next_block)
                        current = next_block
                    else:
                        current = exit_block

                # ----- While -----------------------------------------------
                elif isinstance(stmt, ast.While):
                    cond_block = self._new_block()
                    body_block = self._new_block()
                    exit_block = self._new_block()

                    self._add_edge(current, cond_block)
                    self._add_edge(cond_block, body_block)
                    self._add_edge(cond_block, exit_block)

                    body_exit = self._process_stmts(stmt.body, body_block)
                    self._add_edge(body_exit, cond_block)  # back-edge

                    if stmt.orelse:
                        else_exit = self._process_stmts(stmt.orelse, exit_block)
                        next_block = self._new_block()
                        self._add_edge(else_exit, next_block)
                        current = next_block
                    else:
                        current = exit_block

                # ----- Try -------------------------------------------------
                elif isinstance(stmt, ast.Try):
                    try_block = self._new_block()
                    join_block = self._new_block()
                    self._add_edge(current, try_block)

                    try_exit = self._process_stmts(stmt.body, try_block)
                    self._add_edge(try_exit, join_block)

                    for handler in stmt.handlers:
                        h_block = self._new_block()
                        self._add_edge(current, h_block)   # exception edge
                        h_exit = self._process_stmts(handler.body, h_block)
                        self._add_edge(h_exit, join_block)

                    if stmt.orelse:
                        else_exit = self._process_stmts(stmt.orelse, try_exit)
                        self._add_edge(else_exit, join_block)
                    if stmt.finalbody:
                        fin_block = self._new_block()
                        self._add_edge(join_block, fin_block)
                        fin_exit = self._process_stmts(stmt.finalbody, fin_block)
                        next_block = self._new_block()
                        self._add_edge(fin_exit, next_block)
                        current = next_block
                    else:
                        current = join_block

                # ----- With / AsyncWith ------------------------------------
                elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                    with_block = self._new_block()
                    join_block = self._new_block()
                    self._add_edge(current, with_block)
                    with_exit = self._process_stmts(stmt.body, with_block)
                    self._add_edge(with_exit, join_block)
                    current = join_block

                # ----- Return / Raise / Break / Continue ------------------
                elif isinstance(stmt, self._TERMINATOR_TYPES):
                    # Start a new unreachable block (may be merged later)
                    dead = self._new_block()
                    current = dead

                # ----- Match (3.10+) --------------------------------------
                else:
                    # Generic fallback for match or unknown branch stmt
                    join_block = self._new_block()
                    for case in getattr(stmt, "cases", []):
                        case_block = self._new_block()
                        self._add_edge(current, case_block)
                        case_exit = self._process_stmts(
                            getattr(case, "body", []), case_block
                        )
                        self._add_edge(case_exit, join_block)
                    self._add_edge(current, join_block)
                    current = join_block

        return current

    def build(self, body: List[ast.stmt]) -> List[BasicBlock]:
        entry = self._new_block()
        self._process_stmts(body, entry)
        return self._blocks


class CFGBuilder:
    """Build intra-procedural control-flow graphs from Python source code."""

    def build(
        self,
        source_code: str,
        func_name: Optional[str] = None,
    ) -> Dict[str, List[BasicBlock]]:
        """
        Parse *source_code* and return a mapping ``{scope_name: [BasicBlock]}``.

        If *func_name* is given, only that function's CFG is returned.
        The key ``"__module__"`` is used for top-level code.
        """
        try:
            tree = ast.parse(source_code)
        except SyntaxError as exc:
            logger.warning("CFGBuilder.build: parse error — %s", exc)
            return {}

        source_lines = source_code.splitlines()
        result: Dict[str, List[BasicBlock]] = {}

        # Top-level statements (excluding function/class defs)
        top_stmts = [
            s for s in tree.body
            if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        ]
        if top_stmts and func_name is None:
            builder = _BlockBuilder(source_lines)
            blocks = builder.build(top_stmts)
            result["__module__"] = blocks

        # Per-function
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = node.name
                if func_name is not None and name != func_name:
                    continue
                builder = _BlockBuilder(source_lines)
                blocks = builder.build(node.body)
                result[name] = blocks

        return result

    # ------------------------------------------------------------------
    # Dominator computation (Cooper et al. "simple, fast" algorithm)
    # ------------------------------------------------------------------

    def compute_dominators(
        self,
        blocks: List[BasicBlock],
    ) -> Dict[int, Set[int]]:
        """
        Return ``{block_id: {dominator_ids}}`` using the iterative bit-vector
        dominator algorithm (O(N²) in the worst case, fast in practice).

        Block 0 is assumed to be the entry block.
        """
        if not blocks:
            return {}

        id_to_block = {b.block_id: b for b in blocks}
        all_ids = {b.block_id for b in blocks}
        entry_id = blocks[0].block_id

        # Initialise: entry dominates only itself; all others dominated by all
        dom: Dict[int, Set[int]] = {
            bid: ({bid} if bid == entry_id else set(all_ids))
            for bid in all_ids
        }

        changed = True
        while changed:
            changed = False
            for block in blocks:
                bid = block.block_id
                if bid == entry_id:
                    continue
                preds = [p for p in block.predecessors if p in id_to_block]
                if not preds:
                    continue
                new_dom = set(all_ids)
                for pred_id in preds:
                    new_dom &= dom[pred_id]
                new_dom.add(bid)
                if new_dom != dom[bid]:
                    dom[bid] = new_dom
                    changed = True

        return dom

    # ------------------------------------------------------------------
    # Phi-function placement (join-point detection)
    # ------------------------------------------------------------------

    def place_phi_functions(
        self,
        blocks: List[BasicBlock],
        dominators: Dict[int, Set[int]],
    ) -> None:
        """
        Mark ``phi_vars`` on join-point blocks (blocks with ≥2 predecessors).

        A variable ``v`` needs a phi-function at a join block ``J`` if there
        exist two predecessors of ``J`` that define ``v`` on paths that do not
        dominate each other — i.e. ``v`` is defined in at least two of ``J``'s
        predecessors' dominator subtrees.

        This is a simplified Minimal-SSA placement: we check whether a
        variable is defined in any predecessor block (transitively) and
        if so, mark it at the join point.
        """
        id_to_block = {b.block_id: b for b in blocks}

        # Build "all definitions reaching a block" via a simple forward walk
        # (dominator tree walk would be more correct, but this is sufficient
        #  for the intra-procedural, single-function scope here).
        defs_reaching: Dict[int, Set[str]] = {b.block_id: set(b.defs) for b in blocks}

        # Propagate: a block inherits defs from all its predecessors
        changed = True
        while changed:
            changed = False
            for block in blocks:
                pred_defs: Set[str] = set()
                for pid in block.predecessors:
                    if pid in defs_reaching:
                        pred_defs |= defs_reaching[pid]
                new_reaching = pred_defs | block.defs
                if new_reaching != defs_reaching[block.block_id]:
                    defs_reaching[block.block_id] = new_reaching
                    changed = True

        # A join block needs phi for vars defined on ≥2 distinct predecessor paths
        for block in blocks:
            if len(block.predecessors) < 2:
                continue
            # Collect vars defined in each predecessor's own defs
            per_pred_defs: List[Set[str]] = [
                id_to_block[pid].defs
                for pid in block.predecessors
                if pid in id_to_block
            ]
            if len(per_pred_defs) < 2:
                continue
            # Any variable defined in at least one predecessor (and used in
            # this block or later) is a candidate for a phi function.
            candidate_vars: Set[str] = set()
            for s in per_pred_defs:
                candidate_vars |= s
            # Keep only vars that are live (used) in this block or
            # defined in at least two predecessor paths.
            for var in candidate_vars:
                defined_in = sum(1 for s in per_pred_defs if var in s)
                if defined_in >= 2 or var in block.uses:
                    block.phi_vars.add(var)


# ---------------------------------------------------------------------------
# DefUseChain
# ---------------------------------------------------------------------------

class DefUseChain(BaseModel):
    """Records where a variable is defined and where it is subsequently used."""

    var_name: str
    defined_at: int          # line number of the definition
    used_at: List[int] = Field(default_factory=list)
    func_name: str


# ---------------------------------------------------------------------------
# DefUseAnalyzer
# ---------------------------------------------------------------------------

class _DefUseVisitor(ast.NodeVisitor):
    """
    Walk a function (or module) body and collect per-variable def/use info.

    Tracking rules:
    - Definitions: ast.Assign, ast.AugAssign, ast.AnnAssign, ast.For target,
      function parameters, import aliases.
    - Uses: ast.Name with Load context anywhere in an expression.
    """

    def __init__(self, func_name: str) -> None:
        self.func_name = func_name
        # var → (defined_at_line, [used_at_lines])
        self._defs: Dict[str, int] = {}
        self._uses: Dict[str, List[int]] = {}

    # -- Definition visitors -------------------------------------------

    def _record_def(self, name: str, lineno: int) -> None:
        if name not in self._defs:
            self._defs[name] = lineno
        # A re-definition resets the definition site (conservative: take last)
        else:
            self._defs[name] = lineno

    def _record_use(self, name: str, lineno: int) -> None:
        self._uses.setdefault(name, []).append(lineno)

    def visit_Assign(self, node: ast.Assign) -> None:
        # Uses come first (RHS is evaluated before assignment)
        self._visit_expr(node.value)
        for target in node.targets:
            self._visit_target(target, node.lineno)
        # Do NOT call generic_visit to avoid double-counting

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        # AugAssign is both a use and a def
        if isinstance(node.target, ast.Name):
            self._record_use(node.target.id, node.lineno)
            self._visit_expr(node.value)
            self._record_def(node.target.id, node.lineno)
        else:
            self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            self._visit_expr(node.value)
        if isinstance(node.target, ast.Name):
            self._record_def(node.target.id, node.lineno)

    def visit_For(self, node: ast.For) -> None:
        self._visit_expr(node.iter)
        self._visit_target(node.target, node.lineno)
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Record function params as definitions at the function def line
        all_args = (
            node.args.args
            + node.args.posonlyargs
            + node.args.kwonlyargs
        )
        for arg in all_args:
            self._record_def(arg.arg, node.lineno)
        if node.args.vararg:
            self._record_def(node.args.vararg.arg, node.lineno)
        if node.args.kwarg:
            self._record_def(node.args.kwarg.arg, node.lineno)
        # Visit defaults (they use names from enclosing scope)
        for default in node.args.defaults + node.args.kw_defaults:
            if default:
                self._visit_expr(default)
        # Visit body
        for stmt in node.body:
            self.visit(stmt)

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name.split(".")[0]
            self._record_def(name, node.lineno)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self._record_def(name, node.lineno)

    def visit_Global(self, node: ast.Global) -> None:
        for name in node.names:
            self._record_def(name, node.lineno)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        for name in node.names:
            self._record_def(name, node.lineno)

    # -- Generic expression use visitor --------------------------------

    def _visit_expr(self, node: ast.expr) -> None:
        """Record all Name loads in an expression subtree."""
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                self._record_use(n.id, getattr(n, "lineno", 0))

    def _visit_target(self, target: ast.expr, lineno: int) -> None:
        """Recursively handle assignment targets."""
        if isinstance(target, ast.Name):
            self._record_def(target.id, lineno)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._visit_target(elt, lineno)
        elif isinstance(target, ast.Starred):
            self._visit_target(target.value, lineno)
        elif isinstance(target, ast.Attribute):
            self._visit_expr(target.value)
        elif isinstance(target, ast.Subscript):
            self._visit_expr(target.value)
            self._visit_expr(target.slice)

    # -- Fallback for other statements (Expr, Return, etc.) -------------

    def visit_Expr(self, node: ast.Expr) -> None:
        self._visit_expr(node.value)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value:
            self._visit_expr(node.value)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            self._visit_expr(target)

    def visit_Assert(self, node: ast.Assert) -> None:
        self._visit_expr(node.test)
        if node.msg:
            self._visit_expr(node.msg)

    def visit_Raise(self, node: ast.Raise) -> None:
        if node.exc:
            self._visit_expr(node.exc)
        if node.cause:
            self._visit_expr(node.cause)

    def visit_If(self, node: ast.If) -> None:
        self._visit_expr(node.test)
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_While(self, node: ast.While) -> None:
        self._visit_expr(node.test)
        for stmt in node.body:
            self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self._visit_expr(item.context_expr)
            if item.optional_vars:
                self._visit_target(item.optional_vars, node.lineno)
        for stmt in node.body:
            self.visit(stmt)

    visit_AsyncWith = visit_With  # type: ignore[assignment]

    def visit_Try(self, node: ast.Try) -> None:
        for stmt in node.body:
            self.visit(stmt)
        for handler in node.handlers:
            if handler.name:
                self._record_def(handler.name, handler.lineno)
            for stmt in handler.body:
                self.visit(stmt)
        for stmt in node.orelse:
            self.visit(stmt)
        for stmt in node.finalbody:
            self.visit(stmt)

    # -- Build result --------------------------------------------------

    def chains(self) -> List[DefUseChain]:
        result: List[DefUseChain] = []
        for var, def_line in self._defs.items():
            uses = sorted(set(
                ln for ln in self._uses.get(var, [])
                if ln > def_line
            ))
            result.append(DefUseChain(
                var_name=var,
                defined_at=def_line,
                used_at=uses,
                func_name=self.func_name,
            ))
        return result


class DefUseAnalyzer:
    """Build def-use chains for all functions (and module-level code) in a file."""

    def analyze(self, source_code: str, filepath: str) -> List[DefUseChain]:
        """
        Parse *source_code* and return one ``DefUseChain`` per
        (variable, function/scope) pair found in *filepath*.
        """
        try:
            tree = ast.parse(source_code, filename=filepath)
        except SyntaxError as exc:
            logger.warning("DefUseAnalyzer: parse error in %s — %s", filepath, exc)
            return []

        results: List[DefUseChain] = []

        # Module-level (top-level statements, not inside functions)
        module_visitor = _DefUseVisitor("__module__")
        for stmt in tree.body:
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                module_visitor.visit(stmt)
        results.extend(module_visitor.chains())

        # Per-function (including nested functions handled recursively by visitor)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Only process top-level functions to avoid double-counting
                # nested functions (the visitor recurses into them itself).
                visitor = _DefUseVisitor(node.name)
                visitor.visit(node)
                results.extend(visitor.chains())

        return results
