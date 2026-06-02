"""
core/incremental_dashboard.py — Incremental Analysis Dashboard (Phase 6, Part 12)

Produces both plain-text and JSON reports from an IncrementalResult.

Displays:
  • Changed files
  • Impacted symbols (directly changed, callers, entry points)
  • Invalidated graph nodes (per graph type)
  • Graph rebuild statistics (timing, counts)
  • Scan cache statistics
  • Benchmark summary when benchmark data is provided
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Dashboard data model
# ---------------------------------------------------------------------------

@dataclass
class DashboardSection:
    title:   str
    rows:    List[Dict[str, Any]] = field(default_factory=list)
    summary: Optional[str]        = None


@dataclass
class IncrementalDashboard:
    """
    Dashboard built from one IncrementalResult.

    Usage::

        db = IncrementalDashboard.from_result(result)
        print(db.render_text())
        db.save_json("/tmp/dashboard.json")
    """

    sections:    List[DashboardSection] = field(default_factory=list)
    generated_at: str = ""
    scan_commit:  str = ""
    total_duration_s: float = 0.0

    # ------------------------------------------------------------------
    # Constructor
    # ------------------------------------------------------------------

    @classmethod
    def from_result(cls, result: Any) -> "IncrementalDashboard":
        """Build a dashboard from an IncrementalResult or equivalent dict."""

        def _get(key: str, default: Any = None) -> Any:
            if isinstance(result, dict):
                return result.get(key, default)
            return getattr(result, key, default)

        db = cls(
            generated_at     = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            scan_commit      = _get("commit", "unknown"),
            total_duration_s = _get("duration_s", 0.0),
        )

        # Section 1: Changed files
        changed_files = _get("changed_files", [])
        scanned_files = set(_get("scanned_files", []))
        cached_files  = set(_get("cached_files", []))

        file_rows = []
        for fp in changed_files:
            status = "scanned" if fp in scanned_files else ("cached" if fp in cached_files else "unknown")
            file_rows.append({"file": fp, "status": status})

        db.sections.append(DashboardSection(
            title   = "Changed Files",
            rows    = file_rows,
            summary = (
                f"{len(changed_files)} changed  |  "
                f"{len(scanned_files)} re-scanned  |  "
                f"{len(cached_files)} from cache"
            ),
        ))

        # Section 2: Impacted symbols
        impact_set = _get("impact_set", {}) or {}
        symbol_rows = []
        for sym in sorted(impact_set.get("directly_changed", [])):
            symbol_rows.append({"symbol": sym, "impact_type": "directly_changed"})
        for sym in sorted(impact_set.get("callers", [])):
            symbol_rows.append({"symbol": sym, "impact_type": "caller"})
        for sym in sorted(impact_set.get("entrypoints", [])):
            symbol_rows.append({"symbol": sym, "impact_type": "entrypoint"})

        n_direct  = len(impact_set.get("directly_changed", []))
        n_callers = len(impact_set.get("callers", []))
        n_entries = len(impact_set.get("entrypoints", []))
        db.sections.append(DashboardSection(
            title   = "Impacted Symbols",
            rows    = symbol_rows,
            summary = (
                f"{n_direct} directly changed  |  "
                f"{n_callers} transitive callers  |  "
                f"{n_entries} entry points affected"
            ),
        ))

        # Section 3: Invalidated graph nodes
        inv_nodes = _get("invalidated_nodes", {}) or {}
        node_rows = []
        for gtype, nids in inv_nodes.items():
            count = len(nids) if isinstance(nids, (list, set)) else int(nids)
            node_rows.append({"graph_type": gtype, "invalidated_count": count})

        total_inv = sum(
            len(v) if isinstance(v, (list, set)) else int(v)
            for v in inv_nodes.values()
        )
        db.sections.append(DashboardSection(
            title   = "Invalidated Graph Nodes",
            rows    = node_rows,
            summary = f"{total_inv} total nodes invalidated across {len(inv_nodes)} graph types",
        ))

        # Section 4: Graph rebuild stats
        rebuild = _get("graph_rebuild_stats", {}) or {}
        per_graph = rebuild.get("per_graph", {})
        rebuild_rows = []
        for gtype, stats in per_graph.items():
            row = {"graph_type": gtype}
            row.update(stats)
            rebuild_rows.append(row)

        db.sections.append(DashboardSection(
            title   = "Graph Rebuild Statistics",
            rows    = rebuild_rows,
            summary = (
                f"Total graph time: {rebuild.get('total_graph_duration_s', 0):.3f}s  |  "
                f"{len(per_graph)} graphs updated"
            ),
        ))

        # Section 5: Cache statistics
        cache_stats = _get("cache_stats", {}) or {}
        db.sections.append(DashboardSection(
            title = "Cache Statistics",
            rows  = [
                {"metric": "entries",  "value": cache_stats.get("entries", 0)},
                {"metric": "size_kb",  "value": cache_stats.get("size_kb", 0)},
                {"metric": "hits",     "value": cache_stats.get("hits", 0)},
                {"metric": "misses",   "value": cache_stats.get("misses", 0)},
                {"metric": "hit_rate", "value": cache_stats.get("hit_rate", 0)},
            ],
            summary = (
                f"Hit rate: {cache_stats.get('hit_rate', 0)*100:.0f}%  |  "
                f"{cache_stats.get('entries', 0)} entries  |  "
                f"{cache_stats.get('size_kb', 0)} KB"
            ),
        ))

        # Section 6: New findings summary
        new_findings = _get("new_findings", []) or []
        sev_counts: Dict[str, int] = {}
        for f in new_findings:
            s = (f.get("severity") or "MEDIUM").upper()
            sev_counts[s] = sev_counts.get(s, 0) + 1

        finding_rows = [
            {"severity": sev, "count": cnt}
            for sev, cnt in sorted(
                sev_counts.items(),
                key=lambda kv: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(kv[0])
                if kv[0] in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else 99,
            )
        ]
        db.sections.append(DashboardSection(
            title   = "New Findings",
            rows    = finding_rows,
            summary = f"{len(new_findings)} new findings in this scan",
        ))

        return db

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def render_text(self, width: int = 70) -> str:
        """Render a formatted plain-text dashboard."""
        lines: List[str] = []
        sep = "─" * width

        lines.append("=" * width)
        lines.append(" INCREMENTAL ANALYSIS DASHBOARD ".center(width))
        lines.append("=" * width)
        lines.append(f"  Commit:      {self.scan_commit}")
        lines.append(f"  Generated:   {self.generated_at}")
        lines.append(f"  Scan time:   {self.total_duration_s:.3f}s")
        lines.append("")

        for section in self.sections:
            lines.append(f"┌─ {section.title} {'─' * max(0, width - len(section.title) - 4)}┐")
            if section.rows:
                # Determine columns
                if section.rows:
                    cols = list(section.rows[0].keys())
                    col_widths = {c: max(len(str(c)), max(len(str(r.get(c, ""))) for r in section.rows))
                                  for c in cols}
                    # Header
                    header = "  " + "  ".join(str(c).ljust(col_widths[c]) for c in cols)
                    lines.append(header)
                    lines.append("  " + "  ".join("-" * col_widths[c] for c in cols))
                    for row in section.rows[:20]:  # cap at 20 rows per section
                        lines.append("  " + "  ".join(str(row.get(c, "")).ljust(col_widths[c]) for c in cols))
                    if len(section.rows) > 20:
                        lines.append(f"  … {len(section.rows) - 20} more rows")
            else:
                lines.append("  (none)")

            if section.summary:
                lines.append(f"│  {section.summary}")
            lines.append(f"└{'─' * (width - 1)}┘")
            lines.append("")

        lines.append(sep)
        return "\n".join(lines)

    def render_json(self, indent: int = 2) -> str:
        """Render as JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_dict(self) -> dict:
        return {
            "generated_at":      self.generated_at,
            "scan_commit":       self.scan_commit,
            "total_duration_s":  self.total_duration_s,
            "sections": [
                {
                    "title":   s.title,
                    "rows":    s.rows,
                    "summary": s.summary,
                }
                for s in self.sections
            ],
        }

    def save_json(self, path: str) -> None:
        """Write JSON dashboard to *path*."""
        from pathlib import Path as _Path
        _Path(path).write_text(self.render_json(), encoding="utf-8")


# ---------------------------------------------------------------------------
# Benchmark report (Part 10 integration)
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkResult:
    label:         str
    duration_s:    float
    files_scanned: int
    files_cached:  int
    findings:      int
    graph_time_s:  float = 0.0
    notes:         str   = ""

    def to_dict(self) -> dict:
        return {
            "label":         self.label,
            "duration_s":    round(self.duration_s, 3),
            "files_scanned": self.files_scanned,
            "files_cached":  self.files_cached,
            "findings":      self.findings,
            "graph_time_s":  round(self.graph_time_s, 3),
            "notes":         self.notes,
        }


class BenchmarkDashboard:
    """
    Aggregates multiple BenchmarkResult objects and renders a comparison table.

    Usage::

        bd = BenchmarkDashboard()
        bd.add(BenchmarkResult("Full Scan",     12.34, 150, 0,   87))
        bd.add(BenchmarkResult("Warm Scan",      0.42, 0,  150,  87))
        bd.add(BenchmarkResult("Incremental 1f", 0.18, 1,  149,   3))
        print(bd.render_text())
    """

    def __init__(self) -> None:
        self._results: List[BenchmarkResult] = []

    def add(self, result: BenchmarkResult) -> None:
        self._results.append(result)

    def render_text(self, width: int = 80) -> str:
        if not self._results:
            return "No benchmark results."

        lines: List[str] = []
        lines.append("=" * width)
        lines.append(" INCREMENTAL SCAN BENCHMARKS ".center(width))
        lines.append("=" * width)

        cols = ["Label", "Duration(s)", "Scanned", "Cached", "Findings", "Graph(s)", "Speedup"]
        col_w = [22, 12, 8, 8, 10, 10, 10]

        header = "  ".join(c.ljust(col_w[i]) for i, c in enumerate(cols))
        lines.append(header)
        lines.append("  ".join("-" * w for w in col_w))

        baseline = self._results[0].duration_s if self._results else 1.0

        for r in self._results:
            speedup = f"{baseline / max(r.duration_s, 0.001):.1f}x"
            row = [
                r.label[:22],
                f"{r.duration_s:.3f}",
                str(r.files_scanned),
                str(r.files_cached),
                str(r.findings),
                f"{r.graph_time_s:.3f}",
                speedup,
            ]
            lines.append("  ".join(v.ljust(col_w[i]) for i, v in enumerate(row)))

        lines.append("=" * width)
        if len(self._results) >= 2:
            last = self._results[-1]
            first = self._results[0]
            speedup_total = first.duration_s / max(last.duration_s, 0.001)
            lines.append(
                f"  Best incremental speedup vs full scan: {speedup_total:.1f}x  "
                f"({first.label} → {last.label})"
            )
        return "\n".join(lines)

    def render_json(self, indent: int = 2) -> str:
        return json.dumps([r.to_dict() for r in self._results], indent=indent)

    def to_dicts(self) -> List[dict]:
        return [r.to_dict() for r in self._results]
