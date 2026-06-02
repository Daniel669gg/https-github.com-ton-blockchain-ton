"""
backend/core/cpg/ssa.py — Static Single Assignment (SSA) Form

Converts a Python source file (or a CodePropertyGraph) into SSA form:
  - Each variable assignment receives a unique version: x → x@0, x@1, …
  - Φ-nodes are inserted at control-flow join points (nodes with ≥ 2 predecessors)
  - Constant folding: literal assignments immediately resolve to known values

Supports partial / incremental rebuilds:
  - rebuild_function(func_name, cpg) — recompute SSA for one function
  - invalidate_variable(var_name)     — force-drop all versions of a variable

Used by constraints.py for path-feasibility checking:
    ssa.variables["uid"]  → [SSAVariable(name="uid", version=0, …), …]
    ssa.constants["uid@0"] → "admin"
"""
from __future__ import annotations

import ast
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

if TYPE_CHECKING:
    from .graph import CPGEdgeType, CPGNode, CPGNodeType, CodePropertyGraph


# ---------------------------------------------------------------------------
# Dominance-computation helpers — Cooper, Harvey & Kennedy 2001
# "A Simple, Fast Dominance Algorithm"
# ---------------------------------------------------------------------------

def _cfg_post_order(
    entry_id: str,
    cpg: "CodePropertyGraph",
    cfg_edge_types: Set,
) -> List[str]:
    """Return reachable CFG nodes in post-order via iterative DFS."""
    post_order: List[str] = []
    visited: Set[str] = set()
    # Stack entries: (node_id, processed)
    stack: List[Tuple[str, bool]] = [(entry_id, False)]
    while stack:
        node, processed = stack.pop()
        if processed:
            post_order.append(node)
            continue
        if node in visited:
            continue
        visited.add(node)
        stack.append((node, True))
        for edge in reversed(cpg._adj.get(node, [])):
            if edge.edge_type in cfg_edge_types and edge.dst_id not in visited:
                stack.append((edge.dst_id, False))
    return post_order


def _compute_idom(
    entry_id: str,
    rpo: List[str],
    pred_map: Dict[str, List[str]],
) -> Dict[str, str]:
    """
    Compute immediate dominators via the Cooper-Harvey-Kennedy iterative
    algorithm.  Returns idom[n] = immediate dominator of n;
    idom[entry] = entry (fixed point).
    """
    rpo_number: Dict[str, int] = {n: i for i, n in enumerate(rpo)}
    idom: Dict[str, str] = {entry_id: entry_id}

    def _intersect(b1: str, b2: str) -> str:
        while b1 != b2:
            while rpo_number.get(b1, len(rpo)) > rpo_number.get(b2, len(rpo)):
                b1 = idom.get(b1, b1)
            while rpo_number.get(b2, len(rpo)) > rpo_number.get(b1, len(rpo)):
                b2 = idom.get(b2, b2)
        return b1

    changed = True
    while changed:
        changed = False
        for n in rpo[1:]:  # skip entry
            processed = [p for p in pred_map.get(n, []) if p in idom]
            if not processed:
                continue
            new_idom = processed[0]
            for other in processed[1:]:
                new_idom = _intersect(new_idom, other)
            if idom.get(n) != new_idom:
                idom[n] = new_idom
                changed = True

    return idom


def _compute_df(
    rpo: List[str],
    idom: Dict[str, str],
    pred_map: Dict[str, List[str]],
) -> Dict[str, Set[str]]:
    """
    Compute dominance frontier for every node.
    df[n] = { y | ∃ pred p of y: n dominates p, but n ≠ idom(y) }.
    """
    df: Dict[str, Set[str]] = {n: set() for n in rpo}
    rpo_len = len(rpo)

    for y in rpo:
        preds = pred_map.get(y, [])
        if len(preds) < 2:
            continue
        idom_y = idom.get(y, y)
        for p in preds:
            runner = p
            steps = 0
            while runner != idom_y and steps < rpo_len:
                if runner in df:
                    df[runner].add(y)
                prev = runner
                runner = idom.get(runner, runner)
                if runner == prev:  # entry is its own idom → stop
                    break
                steps += 1

    return df


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SSAVariable:
    """One versioned instance of a source variable."""
    name:    str    # original variable name
    version: int    # SSA version (0, 1, 2, …)
    node_id: str    # CPG node where this definition was created
    value:   Any    # constant value if known; None for symbolic / unknown

    @property
    def ssa_name(self) -> str:
        return f"{self.name}@{self.version}"


@dataclass
class PhiNode:
    """SSA φ-node: merges multiple variable versions at a join point."""
    var_name:       str
    node_id:        str               # CPG node at which the phi is placed
    operands:       List[SSAVariable] # incoming versions
    result_version: int               # the version produced by this phi

    @property
    def ssa_name(self) -> str:
        return f"{self.var_name}@{self.result_version}"


# ---------------------------------------------------------------------------
# SSA Form
# ---------------------------------------------------------------------------

class SSAForm:
    """
    SSA representation of a Python code-base.

    Primary interface (consumed by constraints.py):

        ssa.variables["uid"]   → List[SSAVariable]  (all versions, ascending)
        ssa.constants["uid@0"] → Any                (constant value or absent)

    Incremental interface:

        SSAForm.build(cpg)            — full build from a CodePropertyGraph
        SSAForm.build_file(filepath)  — full build from a raw .py file
        ssa.rebuild_function(name, cpg)   — partial rebuild for one function
        ssa.invalidate_variable(name)     — drop all versions of one variable
    """

    def __init__(self) -> None:
        # var_name → list of SSAVariable (all versions, all functions)
        self.variables: Dict[str, List[SSAVariable]] = defaultdict(list)
        # "varname@version" → concrete constant value
        self.constants: Dict[str, Any] = {}
        # node_id → list of PhiNodes placed at that CPG node
        self.phi_nodes: Dict[str, List[PhiNode]] = defaultdict(list)

        # Internal bookkeeping
        # func_name → set of var_names defined within that function
        self._func_vars: Dict[str, Set[str]] = defaultdict(set)
        # var_name → next available version number
        self._version_counter: Dict[str, int] = defaultdict(int)
        # version of this SSA form; incremented on every mutation
        self.version: int = 0

    # ------------------------------------------------------------------
    # Class-level constructors
    # ------------------------------------------------------------------

    @classmethod
    def build(cls, cpg: "CodePropertyGraph") -> "SSAForm":
        """Build a complete SSAForm from a CodePropertyGraph."""
        from .graph import CPGEdgeType, CPGNodeType  # local import avoids circular dep

        ssa = cls()
        cfg_edge_types = {
            CPGEdgeType.CFG_NEXT,
            CPGEdgeType.CFG_BRANCH_TRUE,
            CPGEdgeType.CFG_BRANCH_FALSE,
        }

        # Find all function entry nodes
        entries: Dict[str, str] = {}  # func_name → entry_node_id
        for nid, node in cpg.nodes.items():
            if node.node_type == CPGNodeType.CFG_ENTRY:
                fname = node.properties.get("func_name", "")
                if fname:
                    entries[fname] = nid

        for func_name, entry_id in entries.items():
            ssa._build_function_from_cpg(func_name, entry_id, cpg, cfg_edge_types)

        ssa.version += 1
        return ssa

    @classmethod
    def build_file(cls, filepath: str) -> "SSAForm":
        """Build SSA directly from a Python source file (no CPG required)."""
        ssa = cls()
        try:
            source = Path(filepath).read_text(encoding="utf-8", errors="replace")
            tree   = ast.parse(source, filename=filepath)
        except (SyntaxError, OSError, ValueError):
            return ssa

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ssa._build_function_from_ast(node, filepath)

        ssa.version += 1
        return ssa

    # ------------------------------------------------------------------
    # Incremental rebuild
    # ------------------------------------------------------------------

    def rebuild_function(self, func_name: str, cpg: "CodePropertyGraph") -> None:
        """
        Recompute SSA for a single function.
        Removes all variable versions that were defined within this function,
        then re-processes the function from the CPG.
        """
        from .graph import CPGEdgeType, CPGNodeType

        # Collect node_ids for this function
        func_node_ids: Set[str] = {
            nid for nid, n in cpg.nodes.items() if n.function == func_name
        }

        # Remove all SSAVariables whose defining node belongs to this function
        for var_name in list(self._func_vars.get(func_name, set())):
            kept: List[SSAVariable] = []
            for v in self.variables.get(var_name, []):
                if v.node_id in func_node_ids:
                    self.constants.pop(v.ssa_name, None)
                else:
                    kept.append(v)
            if kept:
                self.variables[var_name] = kept
            else:
                self.variables.pop(var_name, None)

        # Remove phi nodes from function's nodes
        for nid in func_node_ids:
            self.phi_nodes.pop(nid, None)

        self._func_vars.pop(func_name, None)

        # Find entry node and rebuild
        entry_id: Optional[str] = None
        for nid, node in cpg.nodes.items():
            if node.node_type == CPGNodeType.CFG_ENTRY:
                if node.properties.get("func_name") == func_name:
                    entry_id = nid
                    break

        if entry_id:
            cfg_edge_types = {
                CPGEdgeType.CFG_NEXT,
                CPGEdgeType.CFG_BRANCH_TRUE,
                CPGEdgeType.CFG_BRANCH_FALSE,
            }
            self._build_function_from_cpg(func_name, entry_id, cpg, cfg_edge_types)

        self.version += 1

    def invalidate_variable(
        self, var_name: str, func_name: Optional[str] = None
    ) -> None:
        """
        Force-invalidate all SSA versions of *var_name*.
        If *func_name* is supplied only versions from that function are removed
        (best-effort — without a CPG we cannot partition by function here, so
        we clear all versions in that case too).
        """
        for v in self.variables.get(var_name, []):
            self.constants.pop(v.ssa_name, None)
        self.variables.pop(var_name, None)
        self._version_counter.pop(var_name, None)

        if func_name:
            self._func_vars.get(func_name, set()).discard(var_name)

        self.version += 1

    # ------------------------------------------------------------------
    # Internal CPG-based build — proper dominance frontier SSA
    # ------------------------------------------------------------------

    def _build_function_from_cpg(
        self,
        func_name:       str,
        entry_id:        str,
        cpg:             "CodePropertyGraph",
        cfg_edge_types:  Set["CPGEdgeType"],
    ) -> None:
        """
        Build SSA form for one function using the Cooper-Harvey-Kennedy (2001)
        dominance frontier algorithm:

        1. Compute RPO traversal + immediate dominators (idom)
        2. Compute dominance frontier (DF) for every node
        3. Insert phi nodes at the iterated dominance frontier (IDF) of each
           variable's definition sites
        4. Rename variables in pre-order DFS of the dominator tree, filling
           phi-node operands with the correct reaching versions
        """
        # Step 1 — RPO + predecessor map
        post_order = _cfg_post_order(entry_id, cpg, cfg_edge_types)
        if not post_order:
            return
        rpo: List[str]    = list(reversed(post_order))
        rpo_set: Set[str] = set(rpo)

        pred_map: Dict[str, List[str]] = {n: [] for n in rpo}
        for n in rpo:
            for edge in cpg._radj.get(n, []):
                if edge.edge_type in cfg_edge_types and edge.src_id in rpo_set:
                    pred_map[n].append(edge.src_id)

        # Step 2 — idom + dominance frontier
        idom = _compute_idom(entry_id, rpo, pred_map)
        df   = _compute_df(rpo, idom, pred_map)

        # Step 3 — collect definition sites per variable
        var_defs: Dict[str, Set[str]] = defaultdict(set)
        for node_id in rpo:
            node = cpg.nodes.get(node_id)
            if node is None:
                continue
            for var_name, _ in self._extract_assignments(node.code):
                var_defs[var_name].add(node_id)

        # Step 4 — place phi nodes via iterated DF
        phi_node_map: Dict[str, Dict[str, PhiNode]] = {}  # node_id → var → phi
        for var_name, def_nodes in var_defs.items():
            worklist: Set[str] = set(def_nodes)
            placed:   Set[str] = set()
            while worklist:
                n = worklist.pop()
                for y in df.get(n, set()):
                    if y in placed:
                        continue
                    placed.add(y)
                    preds_y = pred_map.get(y, [])
                    phi_ver = self._version_counter[var_name]
                    self._version_counter[var_name] += 1
                    phi = PhiNode(
                        var_name       = var_name,
                        node_id        = y,
                        operands       = [SSAVariable(var_name, -1, p, None) for p in preds_y],
                        result_version = phi_ver,
                    )
                    self.phi_nodes[y].append(phi)
                    phi_node_map.setdefault(y, {})[var_name] = phi
                    if y not in def_nodes:
                        worklist.add(y)

        # Step 5 — dominator-tree children map
        dom_children: Dict[str, List[str]] = defaultdict(list)
        for n in rpo:
            p = idom.get(n)
            if p is not None and p != n:
                dom_children[p].append(n)

        # Step 6 — rename variables in pre-order DFS of dominator tree.
        # Uses an explicit stack to avoid Python recursion-limit issues:
        #   (node_id, is_cleanup, vars_pushed_at_this_node)
        var_stacks: Dict[str, List[int]] = defaultdict(list)
        dfs_stack: List[Tuple[str, bool, List[str]]] = [(entry_id, False, [])]

        while dfs_stack:
            node_id, is_cleanup, vars_to_pop = dfs_stack.pop()

            if is_cleanup:
                for vname in reversed(vars_to_pop):
                    if var_stacks[vname]:
                        var_stacks[vname].pop()
                continue

            pushed: List[str] = []

            # Phi-node outputs count as definitions at the block entry
            for phi in self.phi_nodes.get(node_id, []):
                var_stacks[phi.var_name].append(phi.result_version)
                pushed.append(phi.var_name)
                self.variables[phi.var_name].append(
                    SSAVariable(phi.var_name, phi.result_version, node_id, None)
                )
                self._func_vars[func_name].add(phi.var_name)

            # Regular assignments
            node = cpg.nodes.get(node_id)
            if node is not None:
                for var_name, const_val in self._extract_assignments(node.code):
                    ver = self._version_counter[var_name]
                    self._version_counter[var_name] += 1
                    ssa_var = SSAVariable(var_name, ver, node_id, const_val)
                    self.variables[var_name].append(ssa_var)
                    self._func_vars[func_name].add(var_name)
                    var_stacks[var_name].append(ver)
                    pushed.append(var_name)
                    if const_val is not None:
                        self.constants[ssa_var.ssa_name] = const_val

            # Fill phi-operands for CFG successors
            for edge in cpg._adj.get(node_id, []):
                if edge.edge_type not in cfg_edge_types:
                    continue
                succ_id = edge.dst_id
                if succ_id not in phi_node_map:
                    continue
                for var_name, phi in phi_node_map[succ_id].items():
                    if not var_stacks[var_name]:
                        continue
                    cur_ver = var_stacks[var_name][-1]
                    for i, op in enumerate(phi.operands):
                        if op.node_id == node_id and op.version == -1:
                            phi.operands[i] = SSAVariable(var_name, cur_ver, node_id, None)
                            break

            # Push cleanup marker (runs after all children are processed)
            dfs_stack.append((node_id, True, pushed))
            # Push children in reverse order for correct traversal order
            for child in reversed(dom_children.get(node_id, [])):
                dfs_stack.append((child, False, []))

    # ------------------------------------------------------------------
    # Internal AST-based build (no CPG)
    # ------------------------------------------------------------------

    def _build_function_from_ast(
        self,
        func_node: ast.FunctionDef,
        filepath:  str,
    ) -> None:
        """Walk ast.Assign / ast.AnnAssign nodes inside a function."""
        func_name = func_node.name

        for stmt in ast.walk(func_node):
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        var_name  = target.id
                        const_val = self._eval_constant(stmt.value)
                        self._record(var_name, const_val, func_name,
                                     f"{filepath}:{getattr(stmt, 'lineno', 0)}")

            elif isinstance(stmt, ast.AnnAssign):
                if isinstance(stmt.target, ast.Name) and stmt.value is not None:
                    var_name  = stmt.target.id
                    const_val = self._eval_constant(stmt.value)
                    self._record(var_name, const_val, func_name,
                                 f"{filepath}:{getattr(stmt, 'lineno', 0)}")

            elif isinstance(stmt, (ast.For,)):
                # loop variable
                if isinstance(stmt.target, ast.Name):
                    self._record(stmt.target.id, None, func_name,
                                 f"{filepath}:{getattr(stmt, 'lineno', 0)}")

    def _record(
        self,
        var_name:  str,
        const_val: Any,
        func_name: str,
        node_id:   str,
    ) -> None:
        """Create an SSAVariable entry for one assignment."""
        ver = self._version_counter[var_name]
        self._version_counter[var_name] += 1
        ssa_var = SSAVariable(var_name, ver, node_id, const_val)
        self.variables[var_name].append(ssa_var)
        self._func_vars[func_name].add(var_name)
        if const_val is not None:
            self.constants[ssa_var.ssa_name] = const_val

    # ------------------------------------------------------------------
    # Assignment extraction from code strings
    # ------------------------------------------------------------------

    _ASSIGN_RE     = re.compile(r"^\s*(\w+)\s*=\s*(.+)$")
    _ANN_ASSIGN_RE = re.compile(r"^\s*(\w+)\s*:\s*[\w\[\], ]+\s*=\s*(.+)$")
    _AUGMENT_RE    = re.compile(r"^\s*\w+\s*[+\-*/%&|^]=")

    @classmethod
    def _extract_assignments(cls, code: str) -> List[Tuple[str, Any]]:
        """
        Heuristically extract (var_name, const_val) pairs from a code line.
        Skips augmented assignments (+=, -=, …) to avoid false versioning.
        """
        results: List[Tuple[str, Any]] = []
        if cls._AUGMENT_RE.match(code):
            return results

        for pattern in (cls._ANN_ASSIGN_RE, cls._ASSIGN_RE):
            m = pattern.match(code)
            if m:
                var_name  = m.group(1)
                raw_value = m.group(2).strip().rstrip(")")  # strip trailing )
                const_val = cls._parse_literal(raw_value)
                results.append((var_name, const_val))
                break

        return results

    # ------------------------------------------------------------------
    # Literal parsers
    # ------------------------------------------------------------------

    @staticmethod
    def _eval_constant(node: ast.expr) -> Any:
        """Return the Python value for a constant AST node, or None."""
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            if isinstance(node.operand, ast.Constant):
                return -node.operand.value
        return None

    @staticmethod
    def _parse_literal(raw: str) -> Any:
        """Parse a raw string value to a Python literal, or return None."""
        raw = raw.strip()
        if raw in ("None", "null"):
            return None
        if raw == "True":
            return True
        if raw == "False":
            return False
        try:
            return int(raw)
        except ValueError:
            pass
        try:
            return float(raw)
        except ValueError:
            pass
        if len(raw) >= 2 and raw[0] in ('"', "'") and raw[-1] == raw[0]:
            return raw[1:-1]
        return None

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_latest_version(self, var_name: str) -> Optional[SSAVariable]:
        """Return the highest-versioned SSAVariable for *var_name*."""
        versions = self.variables.get(var_name)
        if not versions:
            return None
        return max(versions, key=lambda v: v.version)

    def get_constant(self, var_name: str) -> Optional[Any]:
        """Return the constant value of the latest version of *var_name*, or None."""
        latest = self.get_latest_version(var_name)
        if latest is None:
            return None
        return self.constants.get(latest.ssa_name)

    def all_versions(self, var_name: str) -> List[SSAVariable]:
        """Return all SSAVariables for *var_name*, sorted by version."""
        return sorted(self.variables.get(var_name, []), key=lambda v: v.version)

    def stats(self) -> Dict[str, Any]:
        return {
            "total_variables": len(self.variables),
            "total_versions":  sum(len(v) for v in self.variables.values()),
            "total_constants": len(self.constants),
            "total_phi_nodes": sum(len(p) for p in self.phi_nodes.values()),
            "ssa_version":     self.version,
        }
