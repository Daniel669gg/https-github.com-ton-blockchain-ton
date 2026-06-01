"""
tests/test_phase1_constraints.py — Tests for the pure-Python constraint solver.
20 tests covering PathConstraint, Interval arithmetic, ConstraintSet, and ConstraintSolver.
"""
import sys
import pathlib
import math

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.cpg.constraints import (
    PathConstraint, Interval, ConstraintSet, ConstraintSolver,
)
from backend.core.cpg.graph import CodePropertyGraph, CPGNode, CPGNodeType, CPGEdge, CPGEdgeType
from backend.core.cpg.ssa import SSAConverter, SSAForm


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _make_constraint(var: str, op: str, val, negated: bool = False) -> PathConstraint:
    return PathConstraint(variable=var, operator=op, value=val,
                          negated=negated, line=1, confidence=0.9)


def _make_cpg() -> CodePropertyGraph:
    return CodePropertyGraph()


# ──────────────────────────────────────────────────────────────────────────────
# Interval arithmetic
# ──────────────────────────────────────────────────────────────────────────────

class TestInterval:
    def test_unbounded_contains_all(self):
        iv = Interval.unbounded()
        assert iv.contains(0)
        assert iv.contains(1e9)
        assert iv.contains(-1e9)
        assert not iv.is_empty()

    def test_point_interval(self):
        iv = Interval.point(5)
        assert iv.contains(5)
        assert not iv.contains(4)
        assert not iv.contains(6)
        assert not iv.is_empty()

    def test_non_negative(self):
        iv = Interval.non_negative()
        assert iv.contains(0)
        assert iv.contains(100)
        assert not iv.contains(-1)

    def test_positive(self):
        iv = Interval.positive()
        assert iv.contains(1)
        assert iv.lo > 0

    def test_negative(self):
        iv = Interval.negative()
        assert iv.contains(-1)
        assert iv.hi < 0

    def test_intersect_non_overlapping_is_empty(self):
        iv1 = Interval(lo=10.0, hi=20.0)
        iv2 = Interval(lo=30.0, hi=40.0)
        result = iv1.intersect(iv2)
        assert result is None or result.is_empty()

    def test_intersect_overlapping(self):
        iv1 = Interval(lo=0.0, hi=10.0)
        iv2 = Interval(lo=5.0, hi=15.0)
        result = iv1.intersect(iv2)
        assert result is not None
        assert not result.is_empty()
        assert result.lo == 5.0
        assert result.hi == 10.0

    def test_intersect_positive_and_negative_empty(self):
        pos = Interval.positive()
        neg = Interval.negative()
        result = pos.intersect(neg)
        assert result is None or result.is_empty()


# ──────────────────────────────────────────────────────────────────────────────
# PathConstraint negation
# ──────────────────────────────────────────────────────────────────────────────

class TestPathConstraint:
    def test_negation_less_becomes_gte(self):
        c = _make_constraint("x", "<", 10, negated=True)
        assert c.effective_operator() == ">="

    def test_negation_eq_becomes_ne(self):
        c = _make_constraint("x", "==", 0, negated=True)
        assert c.effective_operator() == "!="

    def test_no_negation_keeps_operator(self):
        c = _make_constraint("x", ">", 5, negated=False)
        assert c.effective_operator() == ">"

    def test_negation_gt_becomes_lte(self):
        c = _make_constraint("y", ">", 100, negated=True)
        assert c.effective_operator() == "<="


# ──────────────────────────────────────────────────────────────────────────────
# ConstraintSet feasibility
# ──────────────────────────────────────────────────────────────────────────────

class TestConstraintSet:
    def test_empty_set_is_feasible(self):
        cs = ConstraintSet()
        assert cs.is_feasible()

    def test_consistent_constraints_feasible(self):
        cs = ConstraintSet()
        cs.add(_make_constraint("x", ">", 0))
        cs.add(_make_constraint("x", "<", 100))
        assert cs.is_feasible()

    def test_contradictory_gt_and_lt_infeasible(self):
        cs = ConstraintSet()
        cs.add(_make_constraint("x", ">", 10))
        cs.add(_make_constraint("x", "<", 5))
        assert not cs.is_feasible()

    def test_contradicts_detection(self):
        cs = ConstraintSet()
        cs.add(_make_constraint("n", ">", 50))
        new_c = _make_constraint("n", "<", 10)
        assert cs.contradicts(new_c)

    def test_clone_is_independent(self):
        cs = ConstraintSet()
        cs.add(_make_constraint("a", ">", 0))
        clone = cs.clone()
        clone.add(_make_constraint("a", "<", -1))
        # original should still be feasible
        assert cs.is_feasible()
        assert not clone.is_feasible()

    def test_get_constant_after_eq(self):
        cs = ConstraintSet()
        cs.add(_make_constraint("k", "==", 42))
        val = cs.get_constant("k")
        assert val == 42


# ──────────────────────────────────────────────────────────────────────────────
# ConstraintSolver: path feasibility via solver
# ──────────────────────────────────────────────────────────────────────────────

class TestConstraintSolverFeasibility:
    def test_empty_path_is_feasible(self):
        cpg = _make_cpg()
        ssa = SSAConverter().convert(cpg)
        solver = ConstraintSolver()
        is_f, conf, _ = solver.check_path_feasibility([], cpg, {})
        assert is_f
        assert conf > 0

    def test_no_constraints_on_path_is_feasible(self):
        cpg = _make_cpg()
        ssa = SSAConverter().convert(cpg)
        solver = ConstraintSolver()
        is_f, conf, _ = solver.check_path_feasibility(["node1", "node2"], cpg, {})
        assert is_f

    def test_contradictory_constraints_infeasible(self):
        cpg = _make_cpg()
        ssa = SSAConverter().convert(cpg)
        solver = ConstraintSolver()

        cs1 = ConstraintSet()
        cs1.add(_make_constraint("x@0", ">", 100))

        cs2 = ConstraintSet()
        cs2.add(_make_constraint("x@0", "<", 10))

        branch_constraints = {"nodeA": cs1, "nodeB": cs2}
        is_f, conf, reason = solver.check_path_feasibility(
            ["nodeA", "nodeB"], cpg, branch_constraints
        )
        assert not is_f
        assert conf > 0
        assert len(reason) > 0

    def test_consistent_constraints_feasible(self):
        cpg = _make_cpg()
        ssa = SSAConverter().convert(cpg)
        solver = ConstraintSolver()

        cs1 = ConstraintSet()
        cs1.add(_make_constraint("uid@0", ">", 0))

        cs2 = ConstraintSet()
        cs2.add(_make_constraint("uid@0", "<", 1000))

        branch_constraints = {"n1": cs1, "n2": cs2}
        is_f, conf, _ = solver.check_path_feasibility(
            ["n1", "n2"], cpg, branch_constraints
        )
        assert is_f

    def test_is_taint_path_feasible_empty_cpg(self):
        """On an empty CPG with no constraints, taint path should be feasible."""
        cpg = _make_cpg()
        ssa = SSAConverter().convert(cpg)
        solver = ConstraintSolver()
        result = solver.is_taint_path_feasible([], cpg, ssa)
        # Returns (is_feasible, confidence, explanation) or bool
        if isinstance(result, tuple):
            is_f, conf, _ = result
            assert is_f is True
        else:
            assert result is True
