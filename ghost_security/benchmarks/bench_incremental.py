"""
benchmarks/bench_incremental.py — Real Incremental Analysis Benchmarks (Phase 6, Part 10)

Measures actual timing for:
  1. Full Scan          — all files, no cache
  2. Warm Scan          — all files, full cache (0 re-scanned)
  3. Incremental 1-file — only 1 changed file
  4. Incremental 10-files
  5. Incremental 100-files

Outputs real numbers to stdout + JSON + BenchmarkDashboard table.

Run::
    python -m benchmarks.bench_incremental [--path /repo] [--output results.json]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional

# Add project root to path
_HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_HERE))

from core.analysis.call_graph import IncrementalCallGraph
from core.graph_invalidation import GraphInvalidationManager, SymbolExtractor
from core.incremental import ScanCache
from core.incremental_dashboard import BenchmarkDashboard, BenchmarkResult


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

class IncrementalBenchmark:
    """
    Runs all benchmark scenarios against a real project directory.

    The benchmark uses a temporary cache directory so it doesn't pollute
    the project's own scan cache.
    """

    def __init__(self, project_path: str) -> None:
        self.project_path = str(Path(project_path).resolve())
        self._tmp_dir: Optional[str] = None

    def _make_temp_cache(self) -> str:
        self._tmp_dir = tempfile.mkdtemp(prefix="tythanai_bench_")
        return self._tmp_dir

    def _cleanup(self) -> None:
        if self._tmp_dir and Path(self._tmp_dir).exists():
            shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def _collect_python_files(self) -> List[str]:
        """Return all Python files in the project (excluding pycache)."""
        root  = Path(self.project_path)
        _SKIP = {"__pycache__", ".git", "node_modules", ".venv", "venv",
                 "dist", "build", ".eggs"}
        return [
            str(f) for f in root.rglob("*.py")
            if not any(s in f.parts for s in _SKIP)
        ]

    # ------------------------------------------------------------------
    # Scenario 1: Full Scan (no cache)
    # ------------------------------------------------------------------

    def bench_full_scan(self) -> BenchmarkResult:
        """Scan all Python files with a fresh (empty) cache."""
        cache_dir = os.path.join(self._make_temp_cache(), "full")
        cache = ScanCache(cache_dir)

        files = self._collect_python_files()
        total_findings = 0
        t0 = time.perf_counter()

        for fp in files:
            # Check cache (will always miss on first run)
            cached = cache.get(fp)
            if cached is not None:
                total_findings += len(cached)
                continue
            # Scan the file
            findings = self._scan_file_fast(fp)
            cache.set(fp, findings)
            total_findings += len(findings)

        duration = time.perf_counter() - t0
        return BenchmarkResult(
            label="Full Scan (cold)",
            duration_s=duration,
            files_scanned=len(files),
            files_cached=0,
            findings=total_findings,
            notes=f"{len(files)} files",
        )

    # ------------------------------------------------------------------
    # Scenario 2: Warm Scan (full cache hit)
    # ------------------------------------------------------------------

    def bench_warm_scan(self) -> BenchmarkResult:
        """Scan all files when everything is already cached."""
        cache_dir = os.path.join(tempfile.mkdtemp(prefix="tythanai_bench_warm_"), "warm")
        cache = ScanCache(cache_dir)

        files = self._collect_python_files()

        # Pre-warm the cache
        for fp in files:
            cache.set(fp, self._scan_file_fast(fp))

        total_findings = 0
        t0 = time.perf_counter()

        for fp in files:
            cached = cache.get(fp)
            if cached is not None:
                total_findings += len(cached)

        duration = time.perf_counter() - t0

        shutil.rmtree(os.path.dirname(cache_dir), ignore_errors=True)
        return BenchmarkResult(
            label="Warm Scan (full cache)",
            duration_s=duration,
            files_scanned=0,
            files_cached=len(files),
            findings=total_findings,
            notes="100% cache hit",
        )

    # ------------------------------------------------------------------
    # Scenario 3-5: Incremental N files
    # ------------------------------------------------------------------

    def bench_incremental(self, n_changed: int) -> BenchmarkResult:
        """Simulate scanning n_changed files while the rest are cached."""
        cache_dir = os.path.join(tempfile.mkdtemp(prefix=f"tythanai_bench_inc{n_changed}_"), "inc")
        cache = ScanCache(cache_dir)

        files = self._collect_python_files()
        n_changed = min(n_changed, len(files))
        changed   = files[:n_changed]
        unchanged = files[n_changed:]

        # Pre-warm cache for unchanged files
        for fp in unchanged:
            cache.set(fp, self._scan_file_fast(fp))

        total_findings = 0
        t_graph_total  = 0.0
        t0 = time.perf_counter()

        # Unchanged: cache hit
        for fp in unchanged:
            cached = cache.get(fp)
            if cached is not None:
                total_findings += len(cached)

        # Changed: re-scan + graph impact analysis
        manager = GraphInvalidationManager()
        for fp in changed:
            findings = self._scan_file_fast(fp)
            cache.set(fp, findings)
            total_findings += len(findings)

        # Graph-level impact computation
        t_graph = time.perf_counter()
        try:
            impact = manager.compute_impact(changed)
        except Exception:
            impact = None
        t_graph_total = time.perf_counter() - t_graph

        duration = time.perf_counter() - t0

        shutil.rmtree(os.path.dirname(cache_dir), ignore_errors=True)
        changed_sym_count = 0
        if impact:
            try:
                changed_sym_count = len(impact.directly_changed)
            except Exception:
                pass

        return BenchmarkResult(
            label=f"Incremental ({n_changed} file{'s' if n_changed != 1 else ''})",
            duration_s=duration,
            files_scanned=n_changed,
            files_cached=len(unchanged),
            findings=total_findings,
            graph_time_s=t_graph_total,
            notes=f"{changed_sym_count} symbols impacted",
        )

    # ------------------------------------------------------------------
    # Scenario 6: Call graph incremental build
    # ------------------------------------------------------------------

    def bench_call_graph_incremental(self, n_changed: int = 1) -> BenchmarkResult:
        """Benchmark incremental call graph update vs full rebuild."""
        files = self._collect_python_files()
        if not files:
            return BenchmarkResult("Call Graph Incremental", 0, 0, 0, 0)

        icg = IncrementalCallGraph(self.project_path)

        # Full build
        t0 = time.perf_counter()
        icg.build()
        full_duration = time.perf_counter() - t0

        # Incremental update of n_changed files
        changed = files[:min(n_changed, len(files))]
        t0 = time.perf_counter()
        updated = icg.update_files(changed)
        inc_duration = time.perf_counter() - t0

        nodes = len(icg.current_graph.get("nodes", []))

        return BenchmarkResult(
            label=f"Call Graph ({n_changed}f incremental vs full)",
            duration_s=inc_duration,
            files_scanned=updated,
            files_cached=len(files) - updated,
            findings=0,
            graph_time_s=full_duration,
            notes=(
                f"Full rebuild: {full_duration:.3f}s | "
                f"Incremental: {inc_duration:.3f}s | "
                f"{nodes} nodes | "
                f"speedup: {full_duration / max(inc_duration, 0.0001):.1f}x"
            ),
        )

    # ------------------------------------------------------------------
    # Fast single-file scanner (AST-only, no network, for benchmarking)
    # ------------------------------------------------------------------

    @staticmethod
    def _scan_file_fast(filepath: str) -> List[dict]:
        """
        Fast AST-based scanner for benchmarking purposes.
        Detects obvious patterns without running semgrep/bandit.
        Returns a list of finding dicts.
        """
        import ast
        findings: List[dict] = []
        try:
            source = Path(filepath).read_text(encoding="utf-8", errors="replace")
            tree   = ast.parse(source, filename=filepath)
        except (SyntaxError, OSError):
            return findings

        _SINK_PATTERNS = {
            "eval":    ("CWE-94",  "HIGH",   "Code injection via eval()"),
            "exec":    ("CWE-94",  "HIGH",   "Code injection via exec()"),
            "system":  ("CWE-78",  "HIGH",   "OS command injection via os.system()"),
            "execute": ("CWE-89",  "HIGH",   "Potential SQL injection in execute()"),
            "pickle":  ("CWE-502", "MEDIUM", "Insecure deserialization (pickle)"),
            "loads":   ("CWE-502", "MEDIUM", "Potential insecure deserialization"),
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                callee = ""
                if isinstance(node.func, ast.Name):
                    callee = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    callee = node.func.attr
                if callee in _SINK_PATTERNS:
                    cwe, sev, desc = _SINK_PATTERNS[callee]
                    findings.append({
                        "rule_id":     f"bench.{callee}",
                        "type":        cwe,
                        "severity":    sev,
                        "file":        filepath,
                        "line":        getattr(node, "lineno", 0),
                        "description": desc,
                    })

        return findings

    # ------------------------------------------------------------------
    # Run all benchmarks
    # ------------------------------------------------------------------

    def run_all(self) -> BenchmarkDashboard:
        """Run all benchmark scenarios and return a BenchmarkDashboard."""
        print("Running incremental benchmarks…", flush=True)
        bd = BenchmarkDashboard()

        scenarios = [
            ("Full Scan (cold)",          lambda: self.bench_full_scan()),
            ("Warm Scan (full cache)",    lambda: self.bench_warm_scan()),
            ("Incremental 1 file",        lambda: self.bench_incremental(1)),
            ("Incremental 10 files",      lambda: self.bench_incremental(10)),
            ("Incremental 100 files",     lambda: self.bench_incremental(100)),
            ("Call Graph (1f incr.)",     lambda: self.bench_call_graph_incremental(1)),
        ]

        for label, fn in scenarios:
            print(f"  {label}… ", end="", flush=True)
            try:
                result = fn()
                bd.add(result)
                print(f"{result.duration_s:.3f}s")
            except Exception as exc:
                print(f"ERROR: {exc}")
                bd.add(BenchmarkResult(label, 0, 0, 0, 0, notes=f"ERROR: {exc}"))

        return bd


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="TythanAI Incremental Benchmark")
    parser.add_argument("--path",   default=".", help="Project root to benchmark")
    parser.add_argument("--output", default=None, help="JSON output file")
    args = parser.parse_args()

    bench = IncrementalBenchmark(args.path)
    bd    = bench.run_all()
    bench._cleanup()

    print()
    print(bd.render_text())

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(bd.to_dicts(), fh, indent=2)
        print(f"\nResults saved to {args.output}")


if __name__ == "__main__":
    main()
