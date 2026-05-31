"""
tests/test_dataflow_evidence.py
Tests for backend/analysis/dataflow_evidence.py — Data Flow Evidence module.

5 tests covering:
1. test_analyze_single_file        — write a temp py file, analyze → CFGStats populated
2. test_cfg_cyclomatic_complexity  — function with if/else → complexity >= 2
3. test_ssa_chains_collected       — file with assignments → SSAChain entries returned
4. test_to_markdown_has_sections   — markdown output has "## Data Flow" header
5. test_empty_project_no_crash     — analyze empty temp dir → no crash, 0 files
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from backend.analysis.dataflow_evidence import (
    CFGStats,
    DataFlowEvidenceCollector,
    DataFlowEvidenceReport,
    SSAChain,
    generate_dataflow_evidence,
)


# ---------------------------------------------------------------------------
# Helper: write a temporary Python file
# ---------------------------------------------------------------------------

def _write_temp_py(content: str, tmp_dir: str) -> str:
    """Write content to a temp .py file inside tmp_dir and return its path."""
    path = os.path.join(tmp_dir, "sample.py")
    Path(path).write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# 1. test_analyze_single_file
# ---------------------------------------------------------------------------

def test_analyze_single_file():
    """Analyzing a temp dir with a single Python file should populate CFGStats."""
    code = """\
def greet(name):
    message = "Hello, " + name
    return message

def add(a, b):
    return a + b
"""
    with tempfile.TemporaryDirectory() as tmp_dir:
        _write_temp_py(code, tmp_dir)
        collector = DataFlowEvidenceCollector()
        report = collector.analyze_project(tmp_dir)

    assert isinstance(report, DataFlowEvidenceReport)
    assert report.files_analyzed >= 1, "Expected at least 1 file analyzed"
    assert report.functions_analyzed >= 1, "Expected at least 1 function analyzed"
    assert len(report.cfg_stats) >= 1, "Expected at least 1 CFGStats entry"

    # Verify structure of the first stats entry
    stat = report.cfg_stats[0]
    assert isinstance(stat, CFGStats)
    assert stat.function_name in ("greet", "add", "__module__")
    assert stat.block_count >= 1
    assert stat.cyclomatic_complexity >= 1


# ---------------------------------------------------------------------------
# 2. test_cfg_cyclomatic_complexity
# ---------------------------------------------------------------------------

def test_cfg_cyclomatic_complexity():
    """A function with an if/else branch should have cyclomatic complexity >= 2."""
    code = """\
def categorize(x):
    if x > 0:
        return "positive"
    else:
        return "non-positive"
"""
    with tempfile.TemporaryDirectory() as tmp_dir:
        _write_temp_py(code, tmp_dir)
        collector = DataFlowEvidenceCollector()
        report = collector.analyze_project(tmp_dir)

    # Find the categorize function's stats
    categorize_stats = [
        s for s in report.cfg_stats if s.function_name == "categorize"
    ]
    assert categorize_stats, "Expected CFGStats for 'categorize' function"

    stat = categorize_stats[0]
    assert stat.cyclomatic_complexity >= 2, (
        f"Expected cyclomatic_complexity >= 2 for branching function, "
        f"got {stat.cyclomatic_complexity}"
    )
    assert stat.has_branches is True, "Expected has_branches=True for if/else function"


# ---------------------------------------------------------------------------
# 3. test_ssa_chains_collected
# ---------------------------------------------------------------------------

def test_ssa_chains_collected():
    """A file with variable assignments should produce SSAChain entries."""
    code = """\
def process_data(user_input):
    cleaned = user_input.strip()
    result = cleaned.upper()
    prefix = "PROCESSED"
    final = prefix + result
    return final
"""
    with tempfile.TemporaryDirectory() as tmp_dir:
        _write_temp_py(code, tmp_dir)
        collector = DataFlowEvidenceCollector()
        report = collector.analyze_project(tmp_dir)

    assert len(report.ssa_chains) > 0, "Expected at least some SSAChain entries"

    # All chains should have valid structure
    for chain in report.ssa_chains:
        assert isinstance(chain, SSAChain)
        assert isinstance(chain.variable, str) and len(chain.variable) > 0
        assert isinstance(chain.defined_at_line, int)
        assert isinstance(chain.used_at_lines, list)
        assert isinstance(chain.is_tainted, bool)

    # Verify that variable names from the code appear in chains
    chain_vars = {c.variable for c in report.ssa_chains}
    expected_vars = {"cleaned", "result", "prefix", "final"}
    found_vars = expected_vars & chain_vars
    assert len(found_vars) > 0, (
        f"Expected some of {expected_vars} in SSA chains, got vars: {chain_vars}"
    )


# ---------------------------------------------------------------------------
# 4. test_to_markdown_has_sections
# ---------------------------------------------------------------------------

def test_to_markdown_has_sections():
    """to_markdown() output must contain the '## Data Flow' section header."""
    code = """\
def simple():
    x = 1
    return x
"""
    with tempfile.TemporaryDirectory() as tmp_dir:
        _write_temp_py(code, tmp_dir)
        collector = DataFlowEvidenceCollector()
        report = collector.analyze_project(tmp_dir)
        markdown = collector.to_markdown(report)

    assert "## Data Flow Engine Evidence" in markdown, (
        "Markdown output should contain '## Data Flow Engine Evidence' header"
    )
    assert "### Control Flow Graph Statistics" in markdown, (
        "Markdown output should contain '### Control Flow Graph Statistics' section"
    )
    assert "### Interprocedural Taint Paths" in markdown, (
        "Markdown output should contain '### Interprocedural Taint Paths' section"
    )
    assert "|" in markdown, "Markdown output should contain table rows with '|'"


# ---------------------------------------------------------------------------
# 5. test_empty_project_no_crash
# ---------------------------------------------------------------------------

def test_empty_project_no_crash():
    """Analyzing an empty directory should not crash and return 0 files analyzed."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        collector = DataFlowEvidenceCollector()
        report = collector.analyze_project(tmp_dir)

    assert isinstance(report, DataFlowEvidenceReport)
    assert report.files_analyzed == 0, (
        f"Expected 0 files_analyzed for empty dir, got {report.files_analyzed}"
    )
    assert report.functions_analyzed == 0
    assert report.cfg_stats == []
    assert report.ssa_chains == []
    assert report.ip_taint_paths == []

    # Summary should have sensible zero values
    assert report.summary["total_blocks"] == 0
    assert report.summary["total_edges"] == 0

    # Module-level convenience also should not crash
    with tempfile.TemporaryDirectory() as tmp_dir2:
        report2 = generate_dataflow_evidence(tmp_dir2)
    assert report2.files_analyzed == 0
