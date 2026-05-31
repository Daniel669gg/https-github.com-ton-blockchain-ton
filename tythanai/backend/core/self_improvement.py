"""
backend/core/self_improvement.py — TythanAI Post-Scan Self-Improvement Engine

Analyzes completed scan results to identify false-positive patterns and generate
concrete improvement actions for future scans.
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("tythanai.self_improvement")

# ---------------------------------------------------------------------------
# Extended schema SQL — call init_extended_schema() once before use
# ---------------------------------------------------------------------------

_EXTENDED_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scan_analyses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT    NOT NULL UNIQUE,
    precision       REAL,
    recall          REAL,
    fp_rate         REAL,
    fp_count        INTEGER DEFAULT 0,
    fn_count        INTEGER DEFAULT 0,
    total_findings  INTEGER DEFAULT 0,
    analysis_json   TEXT,
    created_at      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS fp_feedback (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id             TEXT,
    finding_fingerprint TEXT,
    rule_id             TEXT,
    file                TEXT,
    line                INTEGER,
    verdict             TEXT,
    created_at          TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS improvement_actions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    action_type     TEXT,
    target_rule_id  TEXT,
    reason          TEXT,
    confidence      REAL,
    data_json       TEXT,
    applied         INTEGER DEFAULT 0,
    created_at      TEXT    NOT NULL
);
"""


def init_extended_schema(db: "Database") -> None:  # type: ignore[name-defined]
    """Create extended tables required by SelfImprovementEngine."""
    with db.get_conn() as conn:
        conn.executescript(_EXTENDED_SCHEMA_SQL)
        conn.commit()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ImprovementAction:
    action_type: str       # "increase_threshold" | "decrease_threshold" | "flag_rule" | "add_pattern"
    target_rule_id: str
    reason: str
    confidence: float
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanAnalysis:
    scan_id: str
    total_findings: int
    confirmed_findings: int
    fp_findings: int
    fn_count: int
    fp_rate: float
    precision: float          # confirmed / (confirmed + fp)
    recall: float             # confirmed / (confirmed + fn)
    rule_breakdown: Dict[str, Dict]  # rule_id → {hits, fps, tps}
    recommendations: List[str]
    improvement_actions: List[ImprovementAction]


@dataclass
class FPPatternAnalysis:
    rule_id: str
    total_fps: int
    common_file_patterns: List[str]   # e.g. ["test_", "mock_", ".fixture"]
    common_context_tokens: List[str]  # e.g. ["unittest", "pytest", "mock"]
    suggested_exclusions: List[str]


@dataclass
class ImprovementReport:
    generated_at: str
    scans_analyzed: int
    total_actions: int
    fp_patterns: List[FPPatternAnalysis]
    actions: List[ImprovementAction]
    precision_delta: float   # positive = improvement
    recall_delta: float


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class SelfImprovementEngine:
    """Post-scan self-improvement — analyzes errors and FPs to improve future performance."""

    MIN_SAMPLES_FOR_ANALYSIS: int = 5
    FP_RATE_THRESHOLD: float = 0.30
    HIGH_PRECISION_THRESHOLD: float = 0.95

    # Common file-name fragments that often indicate test/mock context
    _FILE_PATTERN_TOKENS = [
        "test_", "_test", "mock_", "_mock", ".fixture", "spec_", "_spec",
        "conftest", "factories", "fake_", "_fake", "stub_", "_stub",
    ]
    # Context tokens that indicate test frameworks / non-prod code
    _CONTEXT_TOKENS = [
        "unittest", "pytest", "mock", "fixture", "monkeypatch", "MagicMock",
        "patch(", "setUp", "tearDown", "describe(", "it(", "beforeEach",
        "afterEach", "jest", "mocha", "chai",
    ]

    def __init__(
        self,
        db: Optional[Any] = None,
        db_path: str = "data/tythanai.db",
    ) -> None:
        if db is not None:
            self.db = db
        else:
            from backend.core.db import Database
            self.db = Database(db_path)
            self.db.init_schema()
        init_extended_schema(self.db)

    # ------------------------------------------------------------------
    # Core analysis
    # ------------------------------------------------------------------

    def analyze_scan(
        self,
        scan_id: str,
        findings: List[Any],
        fp_fingerprints: List[str] = [],
        fn_count: int = 0,
    ) -> ScanAnalysis:
        """Analyze a completed scan.

        fp_fingerprints — fingerprints of findings the user marked as false positives.
        fn_count        — number of false negatives reported by the user.
        """
        fp_set = set(fp_fingerprints)
        total = len(findings)

        # Classify each finding
        fp_list: List[Any] = []
        tp_list: List[Any] = []
        for f in findings:
            if f.fingerprint() in fp_set:
                fp_list.append(f)
            else:
                tp_list.append(f)

        fp_count = len(fp_list)
        confirmed_count = len(tp_list)
        fp_rate = fp_count / total if total > 0 else 0.0
        precision = confirmed_count / (confirmed_count + fp_count) if (confirmed_count + fp_count) > 0 else 1.0
        recall = confirmed_count / (confirmed_count + fn_count) if (confirmed_count + fn_count) > 0 else 1.0

        # Per-rule breakdown
        rule_breakdown: Dict[str, Dict[str, int]] = defaultdict(lambda: {"hits": 0, "fps": 0, "tps": 0})
        for f in findings:
            rule_breakdown[f.rule_id]["hits"] += 1
            if f.fingerprint() in fp_set:
                rule_breakdown[f.rule_id]["fps"] += 1
            else:
                rule_breakdown[f.rule_id]["tps"] += 1

        # Generate rule-level recommendations and actions
        recommendations: List[str] = []
        actions: List[ImprovementAction] = []
        for rule_id, stats in rule_breakdown.items():
            hits = stats["hits"]
            fps = stats["fps"]
            tps = stats["tps"]
            rule_fp_rate = fps / hits if hits > 0 else 0.0

            if hits >= self.MIN_SAMPLES_FOR_ANALYSIS and rule_fp_rate > self.FP_RATE_THRESHOLD:
                recommendations.append(
                    f"Rule '{rule_id}' has FP rate {rule_fp_rate:.1%} (>{self.FP_RATE_THRESHOLD:.0%})"
                    " — consider raising confidence threshold."
                )
                actions.append(
                    ImprovementAction(
                        action_type="increase_threshold",
                        target_rule_id=rule_id,
                        reason=f"FP rate {rule_fp_rate:.1%} exceeds threshold {self.FP_RATE_THRESHOLD:.0%}",
                        confidence=0.85,
                        data={"fp_rate": rule_fp_rate, "hits": hits, "fps": fps, "delta": 0.05},
                    )
                )
            elif hits >= 10 and rule_fp_rate < (1.0 - self.HIGH_PRECISION_THRESHOLD):
                recommendations.append(
                    f"Rule '{rule_id}' is highly precise — threshold can be lowered slightly."
                )
                actions.append(
                    ImprovementAction(
                        action_type="decrease_threshold",
                        target_rule_id=rule_id,
                        reason=f"FP rate {rule_fp_rate:.1%} very low with {hits} samples",
                        confidence=0.70,
                        data={"fp_rate": rule_fp_rate, "hits": hits, "delta": -0.02},
                    )
                )

        analysis = ScanAnalysis(
            scan_id=scan_id,
            total_findings=total,
            confirmed_findings=confirmed_count,
            fp_findings=fp_count,
            fn_count=fn_count,
            fp_rate=fp_rate,
            precision=precision,
            recall=recall,
            rule_breakdown=dict(rule_breakdown),
            recommendations=recommendations,
            improvement_actions=actions,
        )

        self.save_analysis(analysis)
        return analysis

    # ------------------------------------------------------------------
    # FP pattern analysis
    # ------------------------------------------------------------------

    def analyze_fp_patterns(
        self,
        findings: List[Any],
        fp_fingerprints: List[str],
    ) -> List[FPPatternAnalysis]:
        """Find common patterns in false positive findings."""
        fp_set = set(fp_fingerprints)
        fp_by_rule: Dict[str, List[Any]] = defaultdict(list)
        for f in findings:
            if f.fingerprint() in fp_set:
                fp_by_rule[f.rule_id].append(f)

        results: List[FPPatternAnalysis] = []
        for rule_id, fp_findings in fp_by_rule.items():
            # Count file-name patterns
            file_pattern_counter: Counter = Counter()
            for token in self._FILE_PATTERN_TOKENS:
                for f in fp_findings:
                    import os
                    basename = os.path.basename(f.file).lower()
                    if token.lower() in basename:
                        file_pattern_counter[token] += 1

            # Count context tokens
            ctx_counter: Counter = Counter()
            for token in self._CONTEXT_TOKENS:
                for f in fp_findings:
                    ctx_text = " ".join(f.context_lines).lower()
                    if token.lower() in ctx_text:
                        ctx_counter[token] += 1

            top_file_patterns = [p for p, _ in file_pattern_counter.most_common(5)]
            top_ctx_tokens = [t for t, _ in ctx_counter.most_common(5)]

            # Generate suggested exclusions
            exclusions: List[str] = []
            for pat in top_file_patterns:
                exclusions.append(f"exclude files matching: *{pat}*")
            for tok in top_ctx_tokens:
                exclusions.append(f"exclude context containing: {tok}")

            results.append(
                FPPatternAnalysis(
                    rule_id=rule_id,
                    total_fps=len(fp_findings),
                    common_file_patterns=top_file_patterns,
                    common_context_tokens=top_ctx_tokens,
                    suggested_exclusions=exclusions,
                )
            )

        return results

    # ------------------------------------------------------------------
    # Multi-scan improvement actions
    # ------------------------------------------------------------------

    def generate_improvement_actions(
        self,
        analyses: List[ScanAnalysis],
    ) -> List[ImprovementAction]:
        """Generate concrete improvement actions from multiple scan analyses."""
        # Aggregate per-rule stats across all scans
        rule_hits: Dict[str, int] = defaultdict(int)
        rule_fps: Dict[str, int] = defaultdict(int)
        rule_tps: Dict[str, int] = defaultdict(int)
        rule_scan_count: Dict[str, int] = defaultdict(int)

        for analysis in analyses:
            for rule_id, stats in analysis.rule_breakdown.items():
                rule_hits[rule_id] += stats.get("hits", 0)
                rule_fps[rule_id] += stats.get("fps", 0)
                rule_tps[rule_id] += stats.get("tps", 0)
                rule_scan_count[rule_id] += 1

        actions: List[ImprovementAction] = []
        all_rule_ids = set(rule_hits.keys())

        for rule_id in all_rule_ids:
            hits = rule_hits[rule_id]
            fps = rule_fps[rule_id]
            tps = rule_tps[rule_id]
            fp_rate = fps / hits if hits > 0 else 0.0
            scans = rule_scan_count[rule_id]

            if hits >= self.MIN_SAMPLES_FOR_ANALYSIS and fp_rate > self.FP_RATE_THRESHOLD:
                actions.append(
                    ImprovementAction(
                        action_type="increase_threshold",
                        target_rule_id=rule_id,
                        reason=(
                            f"Aggregate FP rate {fp_rate:.1%} over {hits} findings "
                            f"across {scans} scans exceeds {self.FP_RATE_THRESHOLD:.0%} threshold"
                        ),
                        confidence=0.90,
                        data={"fp_rate": fp_rate, "hits": hits, "fps": fps, "delta": 0.05},
                    )
                )
            elif hits >= 10 and fp_rate == 0.0:
                actions.append(
                    ImprovementAction(
                        action_type="decrease_threshold",
                        target_rule_id=rule_id,
                        reason=f"0% FP rate over {hits} samples — safe to lower threshold",
                        confidence=0.75,
                        data={"fp_rate": 0.0, "hits": hits, "delta": -0.02},
                    )
                )

        # Rules that never triggered across many scans → flag for review
        total_scans = len(analyses)
        if total_scans >= 10:
            for rule_id, scans in rule_scan_count.items():
                if scans == 0 or (scans < 2 and total_scans >= 10):
                    actions.append(
                        ImprovementAction(
                            action_type="flag_rule",
                            target_rule_id=rule_id,
                            reason=f"Rule triggered in only {scans}/{total_scans} scans — may be stale",
                            confidence=0.60,
                            data={"scans_triggered": scans, "total_scans": total_scans},
                        )
                    )

        return actions

    # ------------------------------------------------------------------
    # Full improvement cycle
    # ------------------------------------------------------------------

    def run_improvement_cycle(self, recent_scans: int = 10) -> ImprovementReport:
        """Run full improvement cycle on recent scans. Reads from DB."""
        # Load recent scan_analyses from DB
        with self.db.get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_analyses ORDER BY created_at DESC LIMIT ?",
                (recent_scans,),
            ).fetchall()

        analyses: List[ScanAnalysis] = []
        all_precision: List[float] = []
        all_recall: List[float] = []

        for row in rows:
            row_dict = dict(row)
            raw_json = row_dict.get("analysis_json") or "{}"
            try:
                analysis_data = json.loads(raw_json)
            except json.JSONDecodeError:
                analysis_data = {}

            # Rebuild ScanAnalysis from stored data
            analysis = ScanAnalysis(
                scan_id=row_dict["scan_id"],
                total_findings=row_dict.get("total_findings", 0),
                confirmed_findings=row_dict.get("total_findings", 0) - row_dict.get("fp_count", 0),
                fp_findings=row_dict.get("fp_count", 0),
                fn_count=row_dict.get("fn_count", 0),
                fp_rate=row_dict.get("fp_rate", 0.0),
                precision=row_dict.get("precision", 1.0),
                recall=row_dict.get("recall", 1.0),
                rule_breakdown=analysis_data.get("rule_breakdown", {}),
                recommendations=analysis_data.get("recommendations", []),
                improvement_actions=[],
            )
            analyses.append(analysis)
            all_precision.append(row_dict.get("precision", 1.0))
            all_recall.append(row_dict.get("recall", 1.0))

        # Generate aggregate actions
        actions = self.generate_improvement_actions(analyses)

        # Aggregate FP pattern analysis from stored feedback
        fp_patterns = self._load_fp_patterns_from_db()

        # Compute precision/recall delta (latest vs earliest)
        precision_delta = 0.0
        recall_delta = 0.0
        if len(all_precision) >= 2:
            precision_delta = all_precision[0] - all_precision[-1]
            recall_delta = all_recall[0] - all_recall[-1]

        # Persist actions
        now = datetime.now(timezone.utc).isoformat()
        with self.db.get_conn() as conn:
            for action in actions:
                conn.execute(
                    """
                    INSERT INTO improvement_actions
                        (action_type, target_rule_id, reason, confidence, data_json, created_at)
                    VALUES (?,?,?,?,?,?)
                    """,
                    (
                        action.action_type,
                        action.target_rule_id,
                        action.reason,
                        action.confidence,
                        json.dumps(action.data),
                        now,
                    ),
                )
            conn.commit()

        return ImprovementReport(
            generated_at=now,
            scans_analyzed=len(analyses),
            total_actions=len(actions),
            fp_patterns=fp_patterns,
            actions=actions,
            precision_delta=precision_delta,
            recall_delta=recall_delta,
        )

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def save_analysis(self, analysis: ScanAnalysis) -> None:
        """Persist scan analysis to SQLite for future reference."""
        now = datetime.now(timezone.utc).isoformat()
        analysis_json = json.dumps(
            {
                "rule_breakdown": analysis.rule_breakdown,
                "recommendations": analysis.recommendations,
            }
        )
        with self.db.get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_analyses
                    (scan_id, precision, recall, fp_rate, fp_count, fn_count,
                     total_findings, analysis_json, created_at)
                VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (
                    analysis.scan_id,
                    analysis.precision,
                    analysis.recall,
                    analysis.fp_rate,
                    analysis.fp_findings,
                    analysis.fn_count,
                    analysis.total_findings,
                    analysis_json,
                    now,
                ),
            )
            conn.commit()

    def get_historical_precision(self, rule_id: str, lookback_days: int = 30) -> float:
        """Get average precision for a specific rule over the lookback period."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).isoformat()
        with self.db.get_conn() as conn:
            rows = conn.execute(
                """
                SELECT sa.precision, sa.analysis_json, sa.created_at
                FROM scan_analyses sa
                WHERE sa.created_at >= ?
                ORDER BY sa.created_at DESC
                """,
                (cutoff,),
            ).fetchall()

        if not rows:
            return 1.0

        precisions: List[float] = []
        for row in rows:
            row_dict = dict(row)
            try:
                data = json.loads(row_dict.get("analysis_json") or "{}")
                rule_breakdown = data.get("rule_breakdown", {})
            except json.JSONDecodeError:
                rule_breakdown = {}

            if rule_id in rule_breakdown:
                rb = rule_breakdown[rule_id]
                hits = rb.get("hits", 0)
                fps = rb.get("fps", 0)
                tps = hits - fps
                if (tps + fps) > 0:
                    precisions.append(tps / (tps + fps))

        if not precisions:
            # Fall back to overall scan precision
            overall = [dict(r)["precision"] for r in rows if dict(r).get("precision") is not None]
            return sum(overall) / len(overall) if overall else 1.0

        return sum(precisions) / len(precisions)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_fp_patterns_from_db(self) -> List[FPPatternAnalysis]:
        """Load FP feedback from DB and summarise patterns per rule."""
        with self.db.get_conn() as conn:
            rows = conn.execute(
                "SELECT rule_id, file FROM fp_feedback WHERE verdict='fp'"
            ).fetchall()

        if not rows:
            return []

        by_rule: Dict[str, List[str]] = defaultdict(list)
        for row in rows:
            by_rule[row["rule_id"]].append(row["file"] or "")

        patterns: List[FPPatternAnalysis] = []
        for rule_id, files in by_rule.items():
            file_pattern_counter: Counter = Counter()
            for token in self._FILE_PATTERN_TOKENS:
                for fpath in files:
                    import os
                    basename = os.path.basename(fpath).lower()
                    if token.lower() in basename:
                        file_pattern_counter[token] += 1

            top_patterns = [p for p, _ in file_pattern_counter.most_common(5)]
            exclusions = [f"exclude files matching: *{p}*" for p in top_patterns]

            patterns.append(
                FPPatternAnalysis(
                    rule_id=rule_id,
                    total_fps=len(files),
                    common_file_patterns=top_patterns,
                    common_context_tokens=[],
                    suggested_exclusions=exclusions,
                )
            )
        return patterns
