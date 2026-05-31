"""Tests for enhanced ReachabilityAnalyzer: scoring, matrix, and report generation.

All tests are offline — no HTTP calls are made. Temporary directories are used
to simulate Python project layouts.
"""
from __future__ import annotations

import os
import textwrap

import pytest

from backend.analysis.reachability import (
    ReachabilityAnalyzer,
    score_by_reachability,
)
from backend.core.confidence import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(file: str, rule_id: str = "SQL-001", severity: str = "HIGH") -> Finding:
    return Finding(rule_id=rule_id, file=file, line=1, severity=severity)


# ---------------------------------------------------------------------------
# Test 1 — HTTP route file receives a high matrix score (>= 0.8)
# ---------------------------------------------------------------------------


def test_reachability_matrix_http_route_gets_high_score(tmp_path):
    """A file that contains a Flask HTTP route should have score >= 0.8."""
    views = tmp_path / "views.py"
    views.write_text(
        textwrap.dedent("""\
            from flask import Flask
            app = Flask(__name__)

            @app.route("/api/data")
            def get_data():
                return "ok"
        """),
        encoding="utf-8",
    )

    analyzer = ReachabilityAnalyzer()
    matrix = analyzer.build_reachability_matrix(str(tmp_path))

    assert str(views) in matrix, "views.py should appear in the reachability matrix"
    assert matrix[str(views)] >= 0.8, (
        f"Expected HTTP route score >= 0.8, got {matrix[str(views)]}"
    )


# ---------------------------------------------------------------------------
# Test 2 — CLI entrypoint scores lower than HTTP route
# ---------------------------------------------------------------------------


def test_reachability_matrix_cli_lower_than_http(tmp_path):
    """A CLI command file should receive a lower reachability score than an HTTP route."""
    http_file = tmp_path / "web.py"
    http_file.write_text(
        textwrap.dedent("""\
            from flask import Flask
            app = Flask(__name__)

            @app.route("/health")
            def health():
                return "ok"
        """),
        encoding="utf-8",
    )

    cli_file = tmp_path / "cli.py"
    cli_file.write_text(
        textwrap.dedent("""\
            import click

            @click.command()
            def main():
                pass
        """),
        encoding="utf-8",
    )

    analyzer = ReachabilityAnalyzer()
    matrix = analyzer.build_reachability_matrix(str(tmp_path))

    http_score = matrix.get(str(http_file), 0.0)
    cli_score = matrix.get(str(cli_file), 0.0)

    assert http_score > cli_score, (
        f"HTTP score ({http_score}) should be > CLI score ({cli_score})"
    )


# ---------------------------------------------------------------------------
# Test 3 — Findings in high-reach files score higher than low-reach files
# ---------------------------------------------------------------------------


def test_findings_scored_by_reachability(tmp_path):
    """A finding in a high-reachability file must outscore one in a low-reach file."""
    high_file = tmp_path / "routes.py"
    high_file.write_text(
        textwrap.dedent("""\
            from flask import Flask
            app = Flask(__name__)

            @app.route("/exec")
            def run_cmd():
                import subprocess
                subprocess.call("ls")
        """),
        encoding="utf-8",
    )

    low_file = tmp_path / "helpers.py"
    low_file.write_text("def helper(): pass\n", encoding="utf-8")

    finding_high = _make_finding(str(high_file), rule_id="CMD-INJ")
    finding_low = _make_finding(str(low_file), rule_id="CMD-INJ")

    analyzer = ReachabilityAnalyzer()
    scored = analyzer.score_findings_by_reachability(
        [finding_high, finding_low], str(tmp_path)
    )

    assert len(scored) == 2
    # First entry should be the high-reach finding
    first_finding, first_score = scored[0]
    second_finding, second_score = scored[1]

    assert first_score >= second_score, (
        f"High-reach score ({first_score}) should be >= low-reach score ({second_score})"
    )
    assert first_finding.file == str(high_file), (
        "The highest-scored finding should be in the HTTP route file"
    )


# ---------------------------------------------------------------------------
# Test 4 — Report has required structure keys
# ---------------------------------------------------------------------------


def test_reachability_report_structure(tmp_path):
    """generate_reachability_report should return a dict with all required top-level keys."""
    route_file = tmp_path / "app.py"
    route_file.write_text(
        textwrap.dedent("""\
            from flask import Flask
            app = Flask(__name__)

            @app.route("/ping")
            def ping():
                return "pong"
        """),
        encoding="utf-8",
    )

    findings = [_make_finding(str(route_file))]

    analyzer = ReachabilityAnalyzer()
    report = analyzer.generate_reachability_report(str(tmp_path), findings)

    required_keys = {
        "entrypoints_discovered",
        "reachability_matrix",
        "findings_by_reachability",
        "high_priority_count",
        "medium_priority_count",
        "low_priority_count",
        "fp_reduction_estimate",
    }
    assert required_keys.issubset(report.keys()), (
        f"Missing keys: {required_keys - report.keys()}"
    )

    # Each finding entry must have the three sub-keys
    for entry in report["findings_by_reachability"]:
        assert "finding" in entry
        assert "reachability_score" in entry
        assert "tier" in entry
        assert entry["tier"] in ("HIGH", "MEDIUM", "LOW")


# ---------------------------------------------------------------------------
# Test 5 — Low-reachability findings are captured in the FP estimate
# ---------------------------------------------------------------------------


def test_low_reach_findings_flagged(tmp_path):
    """Low-reachability findings should be reflected in the fp_reduction_estimate string."""
    # Create a project with only a CLI entrypoint (low reach) and an isolated util
    cli_file = tmp_path / "cli.py"
    cli_file.write_text(
        textwrap.dedent("""\
            import click

            @click.command()
            def run():
                pass
        """),
        encoding="utf-8",
    )

    # Isolated utility file — no entrypoint references it
    isolated = tmp_path / "internal_util.py"
    isolated.write_text("def _priv(): pass\n", encoding="utf-8")

    findings = [
        _make_finding(str(isolated), rule_id="LOW-REACH-RULE", severity="LOW"),
    ]

    analyzer = ReachabilityAnalyzer()
    report = analyzer.generate_reachability_report(str(tmp_path), findings)

    fp_estimate = report["fp_reduction_estimate"]
    assert isinstance(fp_estimate, str)
    # The estimate should mention a percentage and the word "low-reachability"
    assert "%" in fp_estimate
    assert "low-reachability" in fp_estimate.lower()

    # All isolated findings should end up in the LOW tier
    assert report["low_priority_count"] >= 1


# ---------------------------------------------------------------------------
# Test 6 — Empty project returns empty matrix
# ---------------------------------------------------------------------------


def test_empty_project_returns_empty_matrix(tmp_path):
    """A directory with no Python files should yield an empty reachability matrix."""
    # tmp_path is empty
    analyzer = ReachabilityAnalyzer()
    matrix = analyzer.build_reachability_matrix(str(tmp_path))

    assert matrix == {}, f"Expected empty matrix, got {matrix}"


def test_nonexistent_project_returns_empty_matrix():
    """A non-existent path should yield an empty reachability matrix without error."""
    analyzer = ReachabilityAnalyzer()
    matrix = analyzer.build_reachability_matrix("/tmp/_does_not_exist_ghost_test_")
    assert matrix == {}
