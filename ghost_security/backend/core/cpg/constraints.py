"""
backend/core/cpg/constraints.py — Lightweight path feasibility constraint solver.

Pure Python. No Z3/SMT dependency.

Tracks boolean conditions on CFG paths to detect:
- Infeasible paths (if x > 0 and x < 0 on same path)
- Constant-valued branches (always true/false)
- Taint only on feasible paths (reduces false positives)

Algorithm: interval arithmetic + boolean constraint propagation.
"""

from __future__ import annotations

import math
import re
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .graph import CPGEdgeType, CPGNodeType, CodePropertyGraph
from .ssa import SSAForm


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PathConstraint:
    """A single boolean constraint on an SSA variable at a CFG branch point."""
    variable: str           # SSA var name, e.g. "uid@0"
    operator: str           # "==", "!=", "<", ">", "<=", ">=", "in", "not in", "is", "is not"
    value: Any              # concrete value or None for symbolic
    negated: bool           # True if this constraint is the negated branch
    line: int
    confidence: float       # 0.0–1.0 how confident we are this constraint holds

    def effective_operator(self) -> str:
        """Return the operator as it actually holds (accounting for negation)."""
        if not self.negated:
            return self.operator
        _NEGATIONS: Dict[str, str] = {
            "==": "!=",
            "!=": "==",
            "<":  ">=",
            ">":  "<=",
            "<=": ">",
            ">=": "<",
            "in": "not in",
            "not in": "in",
            "is": "is not",
            "is not": "is",
        }
        return _NEGATIONS.get(self.operator, self.operator)


@dataclass
class Interval:
    """A closed real-valued interval [lo, hi]. Uses math.inf for unbounded ends."""
    lo: float
    hi: float

    # ------------------------------------------------------------------
    # Class-method constructors
    # ------------------------------------------------------------------

    @classmethod
    def unbounded(cls) -> "Interval":
        return cls(lo=-math.inf, hi=math.inf)

    @classmethod
    def point(cls, v: float) -> "Interval":
        return cls(lo=float(v), hi=float(v))

    @classmethod
    def non_negative(cls) -> "Interval":
        """x >= 0"""
        return cls(lo=0.0, hi=math.inf)

    @classmethod
    def positive(cls) -> "Interval":
        """x > 0 (strict — use a tiny epsilon)"""
        return cls(lo=1e-9, hi=math.inf)

    @classmethod
    def negative(cls) -> "Interval":
        """x < 0 (strict)"""
        return cls(lo=-math.inf, hi=-1e-9)

    @classmethod
    def non_positive(cls) -> "Interval":
        """x <= 0"""
        return cls(lo=-math.inf, hi=0.0)

    # ------------------------------------------------------------------
    # Instance methods
    # ------------------------------------------------------------------

    def intersect(self, other: "Interval") -> Optional["Interval"]:
        """Return intersection, or None if empty."""
        new_lo = max(self.lo, other.lo)
        new_hi = min(self.hi, other.hi)
        if new_lo > new_hi:
            return None
        return Interval(lo=new_lo, hi=new_hi)

    def is_empty(self) -> bool:
        return self.lo > self.hi

    def contains(self, v: float) -> bool:
        return self.lo <= v <= self.hi

    def __repr__(self) -> str:
        lo_s = "-inf" if self.lo == -math.inf else str(self.lo)
        hi_s = "+inf" if self.hi == math.inf else str(self.hi)
        return f"[{lo_s}, {hi_s}]"


def _operator_to_interval(op: str, value: Any) -> Optional[Interval]:
    """
    Convert a comparison operator + concrete value to an Interval.
    Returns None if value is not numeric (symbolic constraint, skip interval update).
    """
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None

    _EPS = 1e-9  # small epsilon for strict inequalities

    mapping: Dict[str, Interval] = {
        "==": Interval.point(v),
        "!=": Interval.unbounded(),           # can't represent disjoint easily; skip narrowing
        "<":  Interval(lo=-math.inf, hi=v - _EPS),
        ">":  Interval(lo=v + _EPS,  hi=math.inf),
        "<=": Interval(lo=-math.inf, hi=v),
        ">=": Interval(lo=v,         hi=math.inf),
    }
    return mapping.get(op)


@dataclass
class ConstraintSet:
    """
    A set of path constraints accumulated along a CFG path.
    Maintains:
    - The raw constraints list
    - An interval map per variable (after propagation)
    - A constants map for proven-constant variables
    """
    constraints: List[PathConstraint] = field(default_factory=list)
    intervals: Dict[str, Interval] = field(default_factory=dict)
    constants: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add(self, constraint: PathConstraint) -> None:
        """Add a constraint and update the interval for its variable."""
        self.constraints.append(constraint)
        self._update_interval(constraint)
        self._update_constant(constraint)

    def _update_interval(self, constraint: PathConstraint) -> None:
        """Narrow the variable's interval based on the effective operator."""
        var = constraint.variable
        op = constraint.effective_operator()
        new_interval = _operator_to_interval(op, constraint.value)
        if new_interval is None:
            return

        current = self.intervals.get(var, Interval.unbounded())
        intersected = current.intersect(new_interval)
        if intersected is not None:
            self.intervals[var] = intersected
        else:
            # Contradiction detected — store an empty interval as a marker
            self.intervals[var] = Interval(lo=1.0, hi=-1.0)  # explicitly empty

    def _update_constant(self, constraint: PathConstraint) -> None:
        """If the effective operator is == and value is concrete, record as constant."""
        op = constraint.effective_operator()
        if op == "==" and constraint.value is not None:
            self.constants[constraint.variable] = constraint.value
        elif op == "is" and constraint.value is None:
            # x is None  → constant None
            self.constants[constraint.variable] = None

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def is_feasible(self) -> bool:
        """
        Return False if any variable has an empty (contradictory) interval,
        or if two equality constraints assign different concrete values to the
        same variable.
        """
        for var, interval in self.intervals.items():
            if interval.is_empty():
                return False

        # Check for conflicting equality constraints
        eq_values: Dict[str, Any] = {}
        for c in self.constraints:
            op = c.effective_operator()
            if op == "==" and c.value is not None:
                if c.variable in eq_values and eq_values[c.variable] != c.value:
                    return False
                eq_values[c.variable] = c.value

        # Check "is None" vs "is not None" conflict
        is_none: Dict[str, bool] = {}
        for c in self.constraints:
            op = c.effective_operator()
            if op in ("is", "is not") and c.value is None:
                flag = (op == "is")
                if c.variable in is_none and is_none[c.variable] != flag:
                    return False
                is_none[c.variable] = flag

        return True

    def get_constant(self, var: str) -> Optional[Any]:
        """Return the constant value for *var* if it is proven constant."""
        return self.constants.get(var)

    def restrict_to_feasible(self, var: str) -> Optional[Interval]:
        """Return the current interval for *var*, or unbounded if unconstrained."""
        return self.intervals.get(var, Interval.unbounded())

    def contradicts(self, constraint: PathConstraint) -> bool:
        """
        Return True if adding *constraint* to this set would make it infeasible.
        Uses a temporary clone to avoid mutating self.
        """
        trial = self.clone()
        trial.add(constraint)
        return not trial.is_feasible()

    def clone(self) -> "ConstraintSet":
        """Deep copy of this ConstraintSet."""
        return ConstraintSet(
            constraints=list(self.constraints),
            intervals={k: Interval(v.lo, v.hi) for k, v in self.intervals.items()},
            constants=dict(self.constants),
        )


# ---------------------------------------------------------------------------
# ConstraintSolver
# ---------------------------------------------------------------------------

class ConstraintSolver:
    """
    Extracts path constraints from CPG CFG branches and evaluates feasibility.

    For each CFG branch in the CPG, extracts the condition and records:
    - True branch: condition holds
    - False branch: condition is negated

    Then for each taint path, checks if all branch conditions on the path
    are simultaneously satisfiable.
    """

    # Patterns to extract constraints from branch conditions
    # e.g. "if uid > 0:" → PathConstraint(var="uid", op=">", value=0)
    _COMPARISON_RE = re.compile(
        r'\b(\w+)\s*(==|!=|>=|<=|>|<|is not|is|not in|in)\s*(.+)'
    )
    _NONE_CHECK_RE = re.compile(r'\b(\w+)\s+is\s+(not\s+)?None')
    _TRUTHY_RE = re.compile(r'^(\w+)$')  # bare variable check

    # ---------------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------------

    def extract_constraints_from_cpg(
        self, cpg: CodePropertyGraph, ssa: SSAForm
    ) -> Dict[str, ConstraintSet]:
        """
        Extract constraint sets for each CPG branch node.

        Returns: branch_node_id → ConstraintSet (constraints that hold on that branch)
        """
        branch_constraints: Dict[str, ConstraintSet] = {}

        for node_id, node in cpg.nodes.items():
            # Only process branch/conditional nodes: If, While, For
            if node.ast_type not in ("If", "While", "For", "Compare", "BoolOp"):
                continue
            # Must have at least one branch edge
            adj_edges = cpg._adj.get(node_id, [])
            true_branch_edges = [
                e for e in adj_edges if e.edge_type == CPGEdgeType.CFG_BRANCH_TRUE
            ]
            false_branch_edges = [
                e for e in adj_edges if e.edge_type == CPGEdgeType.CFG_BRANCH_FALSE
            ]
            if not (true_branch_edges or false_branch_edges):
                continue

            # Parse the condition from the node's code
            condition_code = node.properties.get("condition", node.code)
            # Strip common prefixes like "if ", "while "
            for prefix in ("if ", "while ", "elif "):
                if condition_code.startswith(prefix):
                    condition_code = condition_code[len(prefix):]
                    break
            condition_code = condition_code.rstrip(":")

            constraint = self.evaluate_branch_condition(condition_code, ssa)
            if constraint is None:
                continue

            # True branch: constraint holds as-is
            for edge in true_branch_edges:
                cs = branch_constraints.get(edge.dst_id, ConstraintSet())
                cs.add(constraint)
                branch_constraints[edge.dst_id] = cs

            # False branch: constraint is negated
            negated_c = PathConstraint(
                variable=constraint.variable,
                operator=constraint.operator,
                value=constraint.value,
                negated=not constraint.negated,
                line=constraint.line,
                confidence=constraint.confidence,
            )
            for edge in false_branch_edges:
                cs = branch_constraints.get(edge.dst_id, ConstraintSet())
                cs.add(negated_c)
                branch_constraints[edge.dst_id] = cs

        return branch_constraints

    def check_path_feasibility(
        self,
        path_node_ids: List[str],
        cpg: CodePropertyGraph,
        branch_constraints: Dict[str, ConstraintSet],
    ) -> Tuple[bool, float, str]:
        """
        Check if a taint path (list of node IDs) is feasible.

        Accumulates constraints from all branch nodes on the path.
        Contradiction → infeasible.

        Returns: (is_feasible, confidence, explanation)
        """
        if not path_node_ids:
            return True, 1.0, "empty path"

        accumulated = ConstraintSet()
        visited_constraints: List[str] = []

        for node_id in path_node_ids:
            cs = branch_constraints.get(node_id)
            if cs is None:
                continue

            for constraint in cs.constraints:
                if accumulated.contradicts(constraint):
                    reason = (
                        f"Contradiction at node {node_id}: "
                        f"{constraint.variable} {constraint.effective_operator()} "
                        f"{constraint.value!r} conflicts with "
                        f"accumulated interval {accumulated.restrict_to_feasible(constraint.variable)}"
                    )
                    # Confidence reflects how many constraints we'd verified before
                    confidence = min(0.95, 0.5 + 0.1 * len(visited_constraints))
                    return False, confidence, reason
                accumulated.add(constraint)
                visited_constraints.append(
                    f"{constraint.variable} {constraint.effective_operator()} {constraint.value!r}"
                )

        if not accumulated.is_feasible():
            reason = (
                f"Path accumulates contradictory constraints: "
                f"{'; '.join(visited_constraints[-3:])}"
            )
            return False, 0.85, reason

        # Compute aggregate confidence as average of individual constraints
        if accumulated.constraints:
            avg_conf = sum(c.confidence for c in accumulated.constraints) / len(
                accumulated.constraints
            )
        else:
            avg_conf = 1.0

        explanation = (
            f"Path feasible with {len(accumulated.constraints)} constraints; "
            f"intervals: "
            + ", ".join(
                f"{v}={i}" for v, i in list(accumulated.intervals.items())[:5]
            )
        )
        return True, avg_conf, explanation

    def evaluate_branch_condition(
        self, condition_code: str, ssa: SSAForm
    ) -> Optional[PathConstraint]:
        """
        Parse a branch condition string into a PathConstraint.
        e.g. "uid > 0" → PathConstraint(var="uid@0", op=">", value=0)
        Uses SSA form to resolve variable versions.
        """
        if not condition_code or not condition_code.strip():
            return None

        code = condition_code.strip()
        line = 0

        # --- Pattern 1: explicit None checks  "x is None" / "x is not None" ---
        m_none = self._NONE_CHECK_RE.match(code)
        if m_none:
            var_raw = m_none.group(1)
            is_not = bool(m_none.group(2))
            op = "is not" if is_not else "is"
            var_ssa = self._resolve_ssa_var(var_raw, ssa)
            return PathConstraint(
                variable=var_ssa,
                operator=op,
                value=None,
                negated=False,
                line=line,
                confidence=0.9,
            )

        # --- Pattern 2: standard comparisons  "x op value" ---
        m_cmp = self._COMPARISON_RE.match(code)
        if m_cmp:
            var_raw = m_cmp.group(1)
            op = m_cmp.group(2).strip()
            raw_val = m_cmp.group(3).strip()
            var_ssa = self._resolve_ssa_var(var_raw, ssa)
            value = self._parse_value(raw_val)
            return PathConstraint(
                variable=var_ssa,
                operator=op,
                value=value,
                negated=False,
                line=line,
                confidence=0.85,
            )

        # --- Pattern 3: bare truthy check  "if varname:" ---
        m_truthy = self._TRUTHY_RE.match(code)
        if m_truthy:
            var_raw = m_truthy.group(1)
            var_ssa = self._resolve_ssa_var(var_raw, ssa)
            # "if x" is equivalent to "x != None and x != 0 and x != ''"
            # We model as x != 0 for numeric interval purposes
            return PathConstraint(
                variable=var_ssa,
                operator="!=",
                value=None,
                negated=False,
                line=line,
                confidence=0.7,
            )

        # --- Pattern 4: negated check  "not x" ---
        if code.startswith("not "):
            inner = code[4:].strip()
            m_inner = self._TRUTHY_RE.match(inner)
            if m_inner:
                var_raw = m_inner.group(1)
                var_ssa = self._resolve_ssa_var(var_raw, ssa)
                return PathConstraint(
                    variable=var_ssa,
                    operator="==",
                    value=None,
                    negated=False,
                    line=line,
                    confidence=0.7,
                )

        return None

    def propagate_constants(
        self, constraint_set: ConstraintSet, ssa: SSAForm
    ) -> ConstraintSet:
        """
        Use SSA constant information to strengthen constraint sets.
        If SSA says uid@0 = "admin", add equality constraint.
        """
        result = constraint_set.clone()

        for ssa_key, const_val in ssa.constants.items():
            # ssa_key format: "varname@version"
            if const_val is None:
                continue  # None constants are handled separately
            if ssa_key in result.constants:
                continue  # already known

            parts = ssa_key.split("@", 1)
            if len(parts) != 2:
                continue

            constraint = PathConstraint(
                variable=ssa_key,
                operator="==",
                value=const_val,
                negated=False,
                line=0,
                confidence=0.95,
            )
            result.add(constraint)

        return result

    def is_taint_path_feasible(
        self,
        taint_path_hops: List,   # List[TaintHop] from interprocedural.py
        cpg: CodePropertyGraph,
        ssa: SSAForm,
    ) -> Tuple[bool, float, str]:
        """
        Check if an interprocedural taint path is feasible given CPG constraints.
        Main integration point for the verification system.
        Returns: (feasible, confidence, reason)
        """
        if not taint_path_hops:
            return True, 1.0, "no hops to check"

        # Step 1: extract all branch constraints from the CPG
        branch_constraints = self.extract_constraints_from_cpg(cpg, ssa)

        # Step 2: propagate SSA constants into each constraint set
        strengthened: Dict[str, ConstraintSet] = {}
        for node_id, cs in branch_constraints.items():
            strengthened[node_id] = self.propagate_constants(cs, ssa)

        # Step 3: collect node IDs from the taint hops
        path_node_ids: List[str] = []
        for hop in taint_path_hops:
            nid = getattr(hop, "node_id", None)
            if nid:
                path_node_ids.append(nid)

        if not path_node_ids:
            return True, 0.5, "no node IDs in taint hops"

        # Step 4: check feasibility of the accumulated path
        feasible, confidence, explanation = self.check_path_feasibility(
            path_node_ids, cpg, strengthened
        )

        if not feasible:
            reason = f"Taint path infeasible: {explanation}"
            return False, confidence, reason

        # Step 5: sanity check — verify that none of the hops have
        # individually contradictory constraints
        accumulated = ConstraintSet()
        for node_id in path_node_ids:
            cs = strengthened.get(node_id)
            if cs is None:
                continue
            for c in cs.constraints:
                if accumulated.contradicts(c):
                    reason = (
                        f"Late contradiction at hop {node_id}: "
                        f"{c.variable} {c.effective_operator()} {c.value!r}"
                    )
                    return False, 0.8, reason
                accumulated.add(c)

        return (
            True,
            confidence,
            f"Path feasible across {len(taint_path_hops)} hops; {explanation}",
        )

    # ---------------------------------------------------------------------------
    # Internal helpers
    # ---------------------------------------------------------------------------

    def _resolve_ssa_var(self, var_name: str, ssa: SSAForm) -> str:
        """
        Given a plain variable name, return its SSA-versioned name (var@version).
        Uses the highest (most recent) version available in the SSA form.
        Falls back to "var@0" if not found.
        """
        if "@" in var_name:
            return var_name  # already SSA-qualified

        versions = ssa.variables.get(var_name, [])
        if not versions:
            return f"{var_name}@0"
        # Use the highest version (most recent definition)
        latest = max(versions, key=lambda v: v.version)
        return f"{var_name}@{latest.version}"

    @staticmethod
    def _parse_value(raw: str) -> Any:
        """
        Parse a raw string value extracted from a comparison.
        Tries int → float → bool → None → strip-quoted string → leave as str.
        """
        raw = raw.strip()

        if raw == "None":
            return None
        if raw == "True":
            return True
        if raw == "False":
            return False

        # Try int
        try:
            return int(raw)
        except ValueError:
            pass

        # Try float
        try:
            return float(raw)
        except ValueError:
            pass

        # Strip quotes for string literals
        if (
            (raw.startswith('"') and raw.endswith('"')) or
            (raw.startswith("'") and raw.endswith("'"))
        ):
            return raw[1:-1]

        # Leave as-is (symbolic name)
        return raw
