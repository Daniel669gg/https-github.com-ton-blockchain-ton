"""
backend/analysis/dataflow_evidence.py
Data Flow Engine Evidence Report — proves CFG, SSA, and interprocedural taint work.

Generates a structured report that shows:
- CFG statistics per file/function (block count, edges, cyclomatic complexity)
- SSA def-use chains with actual variable names and line references
- Interprocedural taint paths with file:line references
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from backend.analysis.dataflow import BasicBlock, CFGBuilder, DefUseAnalyzer, DefUseChain
from backend.analysis.interprocedural import InterproceduralTaintAnalyzer, IPTaintFinding

logger = logging.getLogger("tythanai.dataflow_evidence")

# CWE mappings for known sink rule IDs
_SINK_CWE_MAP: Dict[str, str] = {
    "sink/sql_injection": "CWE-89",
    "sink/exec": "CWE-78",
    "sink/eval": "CWE-95",
    "sink/os.system": "CWE-78",
    "sink/os.popen": "CWE-78",
    "sink/subprocess": "CWE-78",
    "sink/open": "CWE-73",
}


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class CFGStats(BaseModel):
    """Control-flow graph statistics for a single function."""

    function_name: str
    file: str
    block_count: int
    edge_count: int
    cyclomatic_complexity: int  # edges - blocks + 2 (McCabe's formula)
    has_loops: bool
    has_exceptions: bool
    has_branches: bool
    phi_variable_count: int     # number of SSA phi nodes across all blocks


class SSAChain(BaseModel):
    """An SSA-like def-use chain for a variable in a function."""

    variable: str
    file: str
    function_name: str
    defined_at_line: int
    used_at_lines: List[int]
    is_tainted: bool
    taint_source: str = ""


class IPTaintPath(BaseModel):
    """An interprocedural taint path from source to sink."""

    source_file: str
    source_line: int
    source_type: str
    hops: List[str]            # ["file:func:line", ...]
    sink_file: str
    sink_line: int
    sink_type: str
    cwe_id: str
    confidence: float


class DataFlowEvidenceReport(BaseModel):
    """Full data flow engine evidence report."""

    timestamp: str
    project_path: str
    files_analyzed: int
    functions_analyzed: int
    cfg_stats: List[CFGStats]
    ssa_chains: List[SSAChain]
    ip_taint_paths: List[IPTaintPath]
    summary: Dict[str, Any]


# ---------------------------------------------------------------------------
# DataFlowEvidenceCollector
# ---------------------------------------------------------------------------


class DataFlowEvidenceCollector:
    """
    Collects evidence that the TythanAI data flow engine is real and working.

    Analyzes a project directory and produces concrete CFG/SSA/taint evidence.
    """

    # Known taint source rule IDs for marking SSA chains as tainted
    _TAINT_SOURCE_RULES = frozenset({
        "taint/request.GET",
        "taint/request.POST",
        "taint/request.args",
        "taint/request.form",
        "taint/request.json",
        "taint/request.data",
        "taint/os.environ",
        "taint/sys.argv",
        "taint/input",
        "taint/propagated",
    })

    def analyze_project(self, project_root: str) -> DataFlowEvidenceReport:
        """
        Analyze a project directory and generate a DataFlowEvidenceReport.

        Steps:
        1. Build CFGs for each .py file → collect CFGStats
        2. Run DefUseAnalyzer → collect SSAChain entries
        3. Run InterproceduralTaintAnalyzer → collect IPTaintPath entries
        4. Assemble summary statistics
        """
        root = Path(project_root).resolve()
        py_files = self._collect_py_files(root)

        cfg_stats_list: List[CFGStats] = []
        ssa_chain_list: List[SSAChain] = []

        cfg_builder = CFGBuilder()
        def_use_analyzer = DefUseAnalyzer()

        for filepath in py_files:
            try:
                source = Path(filepath).read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                logger.warning("Cannot read %s: %s", filepath, exc)
                continue

            # ── CFG analysis ─────────────────────────────────────────────
            try:
                cfg_map = cfg_builder.build(source)
                for func_name, blocks in cfg_map.items():
                    if not blocks:
                        continue
                    # Place phi functions for SSA evidence
                    try:
                        dominators = cfg_builder.compute_dominators(blocks)
                        cfg_builder.place_phi_functions(blocks, dominators)
                    except Exception as exc:
                        logger.debug("Phi placement failed for %s::%s — %s", filepath, func_name, exc)

                    stats = self._cfg_stats_for_function(blocks, func_name, filepath)
                    cfg_stats_list.append(stats)
            except Exception as exc:
                logger.warning("CFG analysis failed for %s: %s", filepath, exc)

            # ── Def-use / SSA analysis ───────────────────────────────────
            try:
                chains = def_use_analyzer.analyze(source, filepath)
                for chain in chains:
                    ssa = SSAChain(
                        variable=chain.var_name,
                        file=filepath,
                        function_name=chain.func_name,
                        defined_at_line=chain.defined_at,
                        used_at_lines=chain.used_at,
                        is_tainted=False,
                        taint_source="",
                    )
                    ssa_chain_list.append(ssa)
            except Exception as exc:
                logger.warning("DefUse analysis failed for %s: %s", filepath, exc)

        # ── Interprocedural taint analysis ───────────────────────────────
        ip_taint_paths: List[IPTaintPath] = []
        try:
            ip_analyzer = InterproceduralTaintAnalyzer(project_root, max_depth=5)
            ip_findings: List[IPTaintFinding] = ip_analyzer.analyze()
            for finding in ip_findings:
                cwe = _SINK_CWE_MAP.get(finding.sink_rule, "CWE-20")
                # Build hops from taint_path entries
                hops = list(finding.taint_path)
                ip_taint_paths.append(
                    IPTaintPath(
                        source_file=finding.source_file,
                        source_line=finding.source_line,
                        source_type=finding.source_rule,
                        hops=hops,
                        sink_file=finding.sink_file,
                        sink_line=finding.sink_line,
                        sink_type=finding.sink_rule,
                        cwe_id=cwe,
                        confidence=finding.confidence,
                    )
                )
        except Exception as exc:
            logger.warning("Interprocedural taint analysis failed: %s", exc)

        # ── Mark tainted variables in SSA chains ─────────────────────────
        # Cross-reference: if a variable appears in an IP taint path, mark it
        tainted_by_file: Dict[str, set] = {}
        for path in ip_taint_paths:
            for hop in path.hops:
                # hop format: "file:line:var"
                parts = hop.rsplit(":", 2)
                if len(parts) == 3:
                    hop_file, hop_line_str, hop_var = parts
                    tainted_by_file.setdefault(hop_file, set()).add(hop_var)

        for ssa in ssa_chain_list:
            tainted_vars = tainted_by_file.get(ssa.file, set())
            if ssa.variable in tainted_vars:
                ssa.is_tainted = True
                # Find taint source
                for path in ip_taint_paths:
                    if path.source_file == ssa.file:
                        ssa.taint_source = path.source_type
                        break

        # ── Summary ──────────────────────────────────────────────────────
        total_blocks = sum(s.block_count for s in cfg_stats_list)
        total_edges = sum(s.edge_count for s in cfg_stats_list)
        avg_complexity = (
            sum(s.cyclomatic_complexity for s in cfg_stats_list) / len(cfg_stats_list)
            if cfg_stats_list else 0.0
        )
        tainted_variables = sum(1 for s in ssa_chain_list if s.is_tainted)
        cross_file_paths = sum(
            1 for p in ip_taint_paths
            if p.source_file != p.sink_file
        )
        max_hop_count = max((len(p.hops) for p in ip_taint_paths), default=0)

        summary: Dict[str, Any] = {
            "total_blocks": total_blocks,
            "total_edges": total_edges,
            "avg_complexity": round(avg_complexity, 2),
            "tainted_variables": tainted_variables,
            "cross_file_paths": cross_file_paths,
            "max_hop_count": max_hop_count,
            "functions_with_loops": sum(1 for s in cfg_stats_list if s.has_loops),
            "functions_with_branches": sum(1 for s in cfg_stats_list if s.has_branches),
            "functions_with_exceptions": sum(1 for s in cfg_stats_list if s.has_exceptions),
            "total_phi_nodes": sum(s.phi_variable_count for s in cfg_stats_list),
            "total_ssa_chains": len(ssa_chain_list),
            "total_ip_taint_paths": len(ip_taint_paths),
        }

        return DataFlowEvidenceReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            project_path=str(project_root),
            files_analyzed=len(py_files),
            functions_analyzed=len(cfg_stats_list),
            cfg_stats=cfg_stats_list,
            ssa_chains=ssa_chain_list,
            ip_taint_paths=ip_taint_paths,
            summary=summary,
        )

    def _cfg_stats_for_function(
        self,
        blocks: List[BasicBlock],
        func_name: str,
        file: str,
    ) -> CFGStats:
        """
        Compute CFG statistics from a list of BasicBlocks.

        Counts:
        - Blocks (total)
        - Edges (by summing len(block.successors) across all blocks)
        - Cyclomatic complexity: number of decision points + 1
          (McCabe's predicate-counting formula; equivalent to E - N + 2 on
          a reduced graph, but robust against the empty join-blocks that
          the CFGBuilder creates for each branch/loop structure).
        - Loops: any block has a back-edge (successor block_id <= current block_id)
        - Exceptions: a join-block's predecessors include a try/except block
        - Branches: any block has >= 2 successors
        - Phi variables: sum of phi_vars across all blocks
        """
        if not blocks:
            return CFGStats(
                function_name=func_name,
                file=file,
                block_count=0,
                edge_count=0,
                cyclomatic_complexity=1,
                has_loops=False,
                has_exceptions=False,
                has_branches=False,
                phi_variable_count=0,
            )

        block_count = len(blocks)
        edge_count = sum(len(b.successors) for b in blocks)

        # Cyclomatic complexity via predicate counting:
        # CC = (number of blocks with >= 2 successors) + 1
        # This is equivalent to M = E - N + 2 on the *reduced* CFG (without
        # dead / empty join blocks) and is robust against the CFGBuilder's
        # extra empty join blocks.
        decision_points = sum(1 for b in blocks if len(b.successors) >= 2)
        cyclomatic_complexity = decision_points + 1

        block_ids = {b.block_id for b in blocks}
        has_loops = False
        has_branches = False
        has_exceptions = False
        phi_variable_count = 0

        for block in blocks:
            # Branches: block has 2+ successors
            if len(block.successors) >= 2:
                has_branches = True

            # Loops: any successor has a lower or equal block_id (back-edge heuristic)
            for succ_id in block.successors:
                if succ_id <= block.block_id and succ_id in block_ids:
                    has_loops = True
                    break

            # Exceptions: blocks with 2+ predecessors where stmts contain try/except keywords
            if len(block.predecessors) >= 2:
                stmt_texts = " ".join(text for _, text in block.stmts)
                if "try" in stmt_texts or "except" in stmt_texts or "finally" in stmt_texts:
                    has_exceptions = True

            # Phi variable count
            phi_variable_count += len(block.phi_vars)

        return CFGStats(
            function_name=func_name,
            file=file,
            block_count=block_count,
            edge_count=edge_count,
            cyclomatic_complexity=cyclomatic_complexity,
            has_loops=has_loops,
            has_exceptions=has_exceptions,
            has_branches=has_branches,
            phi_variable_count=phi_variable_count,
        )

    def to_json(self, report: DataFlowEvidenceReport) -> str:
        """Return the report as formatted JSON."""
        return report.model_dump_json(indent=2)

    def to_markdown(self, report: DataFlowEvidenceReport) -> str:
        """
        Return a markdown report with tables for CFG stats and IP taint paths.
        """
        lines: List[str] = [
            "## Data Flow Engine Evidence",
            "",
            f"**Timestamp:** {report.timestamp}  ",
            f"**Project:** `{report.project_path}`  ",
            f"**Files Analyzed:** {report.files_analyzed}  ",
            f"**Functions Analyzed:** {report.functions_analyzed}",
            "",
            "### Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
        ]
        for key, val in report.summary.items():
            display_key = key.replace("_", " ").title()
            lines.append(f"| {display_key} | {val} |")

        lines.extend([
            "",
            "### Control Flow Graph Statistics",
            "",
            "| Function | File | Blocks | Edges | Complexity | Phi Nodes |",
            "|----------|------|--------|-------|-----------|-----------|",
        ])
        for stat in report.cfg_stats[:50]:  # cap at 50 rows for readability
            short_file = stat.file.replace(str(report.project_path), "").lstrip("/\\")
            lines.append(
                f"| `{stat.function_name}` | `{short_file}` "
                f"| {stat.block_count} | {stat.edge_count} "
                f"| {stat.cyclomatic_complexity} | {stat.phi_variable_count} |"
            )
        if len(report.cfg_stats) > 50:
            lines.append(f"| *(+{len(report.cfg_stats) - 50} more functions)* | | | | | |")

        lines.extend([
            "",
            "### SSA Def-Use Chains (Tainted Variables)",
            "",
            "| Variable | File | Function | Defined At | Used At Lines | Taint Source |",
            "|----------|------|----------|------------|---------------|--------------|",
        ])
        tainted_chains = [s for s in report.ssa_chains if s.is_tainted]
        for chain in tainted_chains[:30]:
            short_file = chain.file.replace(str(report.project_path), "").lstrip("/\\")
            used_lines = ", ".join(str(l) for l in chain.used_at_lines[:5])
            if len(chain.used_at_lines) > 5:
                used_lines += f" (+{len(chain.used_at_lines) - 5})"
            lines.append(
                f"| `{chain.variable}` | `{short_file}` | `{chain.function_name}` "
                f"| {chain.defined_at_line} | {used_lines} | `{chain.taint_source}` |"
            )
        if not tainted_chains:
            lines.append("| *(no tainted variables detected)* | | | | | |")

        lines.extend([
            "",
            "### Interprocedural Taint Paths",
            "",
            "| Source | Hops | Sink | CWE | Confidence |",
            "|--------|------|------|-----|------------|",
        ])
        for path in report.ip_taint_paths[:20]:
            src_short = f"{os.path.basename(path.source_file)}:{path.source_line}"
            sink_short = f"{os.path.basename(path.sink_file)}:{path.sink_line}"
            hop_count = len(path.hops)
            lines.append(
                f"| `{src_short}` ({path.source_type}) "
                f"| {hop_count} hop(s) "
                f"| `{sink_short}` ({path.sink_type}) "
                f"| {path.cwe_id} | {path.confidence:.2f} |"
            )
        if not report.ip_taint_paths:
            lines.append("| *(no interprocedural taint paths detected)* | | | | |")
        elif len(report.ip_taint_paths) > 20:
            lines.append(f"| *(+{len(report.ip_taint_paths) - 20} more paths)* | | | | |")

        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _collect_py_files(root: Path) -> List[str]:
        """Return all .py files under root, skipping common non-project dirs."""
        skip_dirs = {
            "__pycache__", ".git", ".venv", "venv", "env",
            "node_modules", "site-packages", ".tox", "build", "dist",
        }
        results: List[str] = []
        try:
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [
                    d for d in dirnames
                    if d not in skip_dirs and not d.startswith(".")
                ]
                for fname in filenames:
                    if fname.endswith(".py"):
                        results.append(os.path.join(dirpath, fname))
        except OSError as exc:
            logger.warning("File collection failed under %s: %s", root, exc)
        return sorted(results)


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------


def generate_dataflow_evidence(project_root: str) -> DataFlowEvidenceReport:
    """
    Convenience wrapper: run DataFlowEvidenceCollector.analyze_project.
    """
    return DataFlowEvidenceCollector().analyze_project(project_root)
