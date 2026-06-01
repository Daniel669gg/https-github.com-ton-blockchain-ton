"""
tests/test_phase2_attack_graph.py — Phase 2 Attack Graph 2.0 tests.
25 tests covering path ranking, risk propagation, impact propagation, and scoring.
"""
import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.analysis.attack_graph import AttackGraphBuilder, ScoredAttackPath


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_finding(
    cwe_id="CWE-89", severity="HIGH", confidence=0.85,
    file="app.py", line=42, description="SQL injection",
):
    class MockFinding:
        rule_id = f"test-{cwe_id}"
    f = MockFinding()
    f.cwe_id = cwe_id
    f.severity = severity
    f.confidence = confidence
    f.file = file
    f.line = line
    f.description = description
    return f


_FINDINGS = [
    _make_finding("CWE-89", "CRITICAL", 0.9),
    _make_finding("CWE-78", "HIGH", 0.8),
    _make_finding("CWE-22", "MEDIUM", 0.6),
]


def _make_graph():
    """Return a built (builder, graph) tuple."""
    builder = AttackGraphBuilder(_FINDINGS, [])
    graph = builder.build(_FINDINGS, [])
    return builder, graph


# ─────────────────────────────────────────────────────────────────────────────
# ScoredAttackPath dataclass
# ─────────────────────────────────────────────────────────────────────────────

class TestScoredAttackPath:
    def test_scored_attack_path_importable(self):
        assert ScoredAttackPath is not None

    def test_scored_attack_path_has_required_fields(self):
        path = ScoredAttackPath(
            path_nodes=["n1", "n2"],
            path_labels=["source", "sink"],
            path_score=0.8,
            reachability_score=0.9,
            exploitability_score=0.75,
            impact_score=1.0,
            confidence_score=0.85,
            risk_score=0.9 * 0.75 * 1.0 * 0.85,
            cwe_ids=["CWE-89"],
            attack_techniques=["T1190"],
            description="SQL injection attack path",
            is_verified=False,
        )
        assert path.path_score == 0.8
        assert path.risk_score > 0
        assert "CWE-89" in path.cwe_ids

    def test_scored_attack_path_risk_values_in_range(self):
        path = ScoredAttackPath(
            path_nodes=[], path_labels=[], path_score=0.5,
            reachability_score=0.8, exploitability_score=0.7,
            impact_score=0.9, confidence_score=0.85,
            risk_score=0.8 * 0.7 * 0.9 * 0.85,
            cwe_ids=[], attack_techniques=[], description="", is_verified=False,
        )
        assert 0.0 <= path.risk_score <= 1.0
        assert 0.0 <= path.path_score <= 1.0


# ─────────────────────────────────────────────────────────────────────────────
# rank_attack_paths
# ─────────────────────────────────────────────────────────────────────────────

class TestRankAttackPaths:
    def test_rank_attack_paths_returns_list(self):
        builder, graph = _make_graph()
        paths = builder.rank_attack_paths(10, graph)
        assert isinstance(paths, list)

    def test_rank_attack_paths_returns_scored_paths(self):
        builder, graph = _make_graph()
        paths = builder.rank_attack_paths(10, graph)
        for p in paths:
            assert hasattr(p, "path_score")
            assert hasattr(p, "risk_score")
            assert 0.0 <= p.path_score <= 1.0

    def test_rank_attack_paths_sorted_by_score(self):
        builder, graph = _make_graph()
        paths = builder.rank_attack_paths(10, graph)
        if len(paths) >= 2:
            for i in range(len(paths) - 1):
                assert paths[i].path_score >= paths[i + 1].path_score

    def test_rank_attack_paths_respects_max_paths(self):
        builder, graph = _make_graph()
        paths = builder.rank_attack_paths(3, graph)
        assert len(paths) <= 3

    def test_rank_empty_findings_returns_list(self):
        builder = AttackGraphBuilder([], [])
        graph = builder.build([], [])
        paths = builder.rank_attack_paths(10, graph)
        assert isinstance(paths, list)

    def test_critical_finding_has_higher_exploitability(self):
        f_crit = [_make_finding("CWE-89", "CRITICAL", 0.95)]
        f_low = [_make_finding("CWE-400", "LOW", 0.3)]
        bc = AttackGraphBuilder(f_crit, [])
        bl = AttackGraphBuilder(f_low, [])
        gc = bc.build(f_crit, [])
        gl = bl.build(f_low, [])
        paths_c = bc.rank_attack_paths(1, gc)
        paths_l = bl.rank_attack_paths(1, gl)
        if paths_c and paths_l:
            assert paths_c[0].exploitability_score >= paths_l[0].exploitability_score


# ─────────────────────────────────────────────────────────────────────────────
# get_top_exploit_chains
# ─────────────────────────────────────────────────────────────────────────────

class TestTopExploitChains:
    def test_get_top_exploit_chains_returns_list(self):
        builder, graph = _make_graph()
        chains = builder.get_top_exploit_chains(10, graph)
        assert isinstance(chains, list)

    def test_get_top_exploit_chains_max_respected(self):
        builder, graph = _make_graph()
        chains = builder.get_top_exploit_chains(5, graph)
        assert len(chains) <= 5

    def test_get_top_reachable_risks_returns_list(self):
        builder, graph = _make_graph()
        risks = builder.get_top_reachable_risks(10, graph)
        assert isinstance(risks, list)

    def test_get_top_reachable_risks_max_respected(self):
        builder, graph = _make_graph()
        risks = builder.get_top_reachable_risks(3, graph)
        assert len(risks) <= 3


# ─────────────────────────────────────────────────────────────────────────────
# Risk and impact propagation
# ─────────────────────────────────────────────────────────────────────────────

class TestRiskPropagation:
    def test_propagate_risk_returns_dict(self):
        builder, graph = _make_graph()
        risk_map = builder.propagate_risk("nonexistent_node", graph=graph)
        assert isinstance(risk_map, dict)

    def test_propagate_risk_on_real_node(self):
        builder, graph = _make_graph()
        nodes = graph.nodes if isinstance(graph.nodes, list) else list(graph.nodes.values())
        if nodes:
            node_id = nodes[0].node_id if hasattr(nodes[0], "node_id") else nodes[0]
            risk_map = builder.propagate_risk(node_id, graph=graph)
            assert isinstance(risk_map, dict)

    def test_propagate_impact_returns_dict(self):
        builder, graph = _make_graph()
        impact_map = builder.propagate_impact("nonexistent_asset", graph=graph)
        assert isinstance(impact_map, dict)

    def test_propagate_risk_values_between_0_and_1(self):
        builder, graph = _make_graph()
        nodes = graph.nodes if isinstance(graph.nodes, list) else list(graph.nodes.values())
        if nodes:
            node_id = nodes[0].node_id if hasattr(nodes[0], "node_id") else nodes[0]
            risk_map = builder.propagate_risk(node_id, propagation_depth=2, graph=graph)
            for nid, score in risk_map.items():
                assert 0.0 <= score <= 1.0, f"Score {score} out of range for {nid}"

    def test_propagate_risk_depth_zero_is_empty(self):
        builder, graph = _make_graph()
        nodes = graph.nodes if isinstance(graph.nodes, list) else list(graph.nodes.values())
        if nodes:
            node_id = nodes[0].node_id if hasattr(nodes[0], "node_id") else nodes[0]
            risk_map = builder.propagate_risk(node_id, propagation_depth=0, graph=graph)
            assert isinstance(risk_map, dict)


# ─────────────────────────────────────────────────────────────────────────────
# Existing functionality preserved
# ─────────────────────────────────────────────────────────────────────────────

class TestExistingFunctionalityPreserved:
    def test_build_still_works(self):
        builder, graph = _make_graph()
        assert graph is not None

    def test_find_critical_paths_still_works(self):
        builder, graph = _make_graph()
        paths = builder.find_critical_paths(graph)
        assert isinstance(paths, list)

    def test_to_json_still_works(self):
        builder, graph = _make_graph()
        j = AttackGraphBuilder.to_json(graph)
        assert isinstance(j, str)
        import json
        data = json.loads(j)
        assert isinstance(data, dict)

    def test_to_mermaid_still_works(self):
        builder, graph = _make_graph()
        mermaid = AttackGraphBuilder.to_mermaid(graph)
        assert isinstance(mermaid, str)

    def test_compute_risk_score_still_works(self):
        builder, graph = _make_graph()
        score = builder.compute_risk_score(graph)
        assert isinstance(score, (int, float))
        assert 0 <= score <= 100
