"""
backend/core/continuous_learning.py — TythanAI Continuous Learning Coordinator

Orchestrates the post-scan learning pipeline:
  scan completed → dataset accumulation → FP/FN feedback → rule evolution → self-improvement
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("tythanai.continuous_learning")

# ---------------------------------------------------------------------------
# Extended schema SQL
# ---------------------------------------------------------------------------

_LEARNING_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS learning_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    TEXT    NOT NULL UNIQUE,
    event_type  TEXT,
    scan_id     TEXT,
    data_json   TEXT,
    processed   INTEGER DEFAULT 0,
    created_at  TEXT    NOT NULL
);
"""


def init_learning_schema(db: Any) -> None:
    """Create learning_events table if it does not exist."""
    with db.get_conn() as conn:
        conn.executescript(_LEARNING_SCHEMA_SQL)
        conn.commit()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class LearningEvent:
    event_id: str
    event_type: str   # "scan_completed" | "feedback_received" | "rule_evolved" | "fp_detected"
    scan_id: str
    data: Dict[str, Any]
    processed: bool = False
    created_at: str = ""


@dataclass
class LearningStats:
    total_events: int
    processed_events: int
    total_scans_learned_from: int
    total_rules_evolved: int
    total_fps_learned: int
    total_confirmed_tps: int
    current_system_precision: float
    current_system_recall: float
    last_learning_cycle: str
    knowledge_entries: int


# ---------------------------------------------------------------------------
# Coordinator
# ---------------------------------------------------------------------------

class ContinuousLearningCoordinator:
    """Orchestrates post-scan learning: updates knowledge, rules, confidence."""

    # Run a full improvement cycle every N scans
    _IMPROVEMENT_CYCLE_INTERVAL = 5

    def __init__(
        self,
        db: Optional[Any] = None,
        db_path: str = "data/tythanai.db",
        dataset_manager: Optional[Any] = None,
        rule_evolution: Optional[Any] = None,
        self_improvement: Optional[Any] = None,
    ) -> None:
        if db is not None:
            self.db = db
        else:
            from backend.core.db import Database
            self.db = Database(db_path)
            self.db.init_schema()

        init_learning_schema(self.db)

        # Lazily instantiate sub-systems if not provided
        if dataset_manager is not None:
            self._dataset_manager = dataset_manager
        else:
            from backend.core.dataset_manager import DatasetManager
            self._dataset_manager = DatasetManager(db=self.db)

        if rule_evolution is not None:
            self._rule_evolution = rule_evolution
        else:
            from backend.core.rule_evolution import RuleEvolutionSystem
            self._rule_evolution = RuleEvolutionSystem(db=self.db)

        if self_improvement is not None:
            self._self_improvement = self_improvement
        else:
            from backend.core.self_improvement import SelfImprovementEngine
            self._self_improvement = SelfImprovementEngine(db=self.db)

    # ------------------------------------------------------------------
    # Post-scan hook
    # ------------------------------------------------------------------

    def after_scan(
        self,
        scan_id: str,
        findings: List[Any],
        scan_path: str = "",
    ) -> LearningEvent:
        """Call after every scan completes. Triggers learning pipeline.

        Steps:
        1. Save the scan episode to scan_history
        2. Queue each finding for the dataset (verdict='needs_review')
        3. Update rule hit counts in generated_rules
        4. Check whether a full improvement cycle is due (every 5 scans)
        5. Emit and persist a 'scan_completed' learning event
        """
        now = datetime.now(timezone.utc).isoformat()

        # 1. Save scan episode
        try:
            self.db.save_scan(scan_id, scan_path or "")
            counts = self._compute_counts(findings)
            self.db.complete_scan(scan_id, counts)
        except Exception as exc:
            logger.warning("after_scan: could not save scan record for %s: %s", scan_id, exc)

        # 2. Queue findings into dataset with 'needs_review' verdict
        queued = 0
        for finding in findings:
            try:
                self._dataset_manager.add_entry(
                    finding=finding,
                    verdict="needs_review",
                    scan_id=scan_id,
                    source_code_snippet="\n".join(getattr(finding, "context_lines", []))[
                        : self._dataset_manager.MAX_SNIPPET_LENGTH
                    ],
                )
                queued += 1
            except Exception as exc:
                logger.debug("Could not queue finding %s: %s", getattr(finding, "rule_id", "?"), exc)

        # 3. Update rule hit counts in generated_rules (increment hit_count)
        rule_ids_seen: set = set()
        for finding in findings:
            rid = getattr(finding, "rule_id", "")
            if rid and rid not in rule_ids_seen:
                rule_ids_seen.add(rid)
                try:
                    existing = self.db.get_generated_rule(rid)
                    if existing:
                        # Increment by upserting with same yaml_content
                        self.db.upsert_generated_rule(
                            rule_id=rid,
                            yaml_content=existing.get("yaml_content", ""),
                            confidence_avg=existing.get("confidence_avg", 0.8),
                            status=existing.get("status", "draft"),
                            output_path=existing.get("output_path", ""),
                        )
                except Exception as exc:
                    logger.debug("Could not update hit count for rule %s: %s", rid, exc)

        # 4. Check if improvement cycle is due
        scan_count = self._count_scans()
        cycle_triggered = False
        if scan_count > 0 and scan_count % self._IMPROVEMENT_CYCLE_INTERVAL == 0:
            try:
                self.trigger_learning_cycle()
                cycle_triggered = True
            except Exception as exc:
                logger.warning("Learning cycle failed after scan %s: %s", scan_id, exc)

        # 5. Persist learning event
        event_id = str(uuid.uuid4())
        event_data = {
            "total_findings": len(findings),
            "queued_to_dataset": queued,
            "scan_path": scan_path,
            "cycle_triggered": cycle_triggered,
        }
        event = LearningEvent(
            event_id=event_id,
            event_type="scan_completed",
            scan_id=scan_id,
            data=event_data,
            processed=False,
            created_at=now,
        )
        self._persist_event(event)
        return event

    # ------------------------------------------------------------------
    # Feedback processing
    # ------------------------------------------------------------------

    def process_feedback(
        self,
        scan_id: str,
        fp_fingerprints: List[str],
        fn_descriptions: List[str] = [],
    ) -> int:
        """Process user feedback (FP/FN reports).

        Returns: number of learning actions taken.
        """
        now = datetime.now(timezone.utc).isoformat()
        actions_taken = 0

        # 1. Record FP feedback for each fingerprint
        with self.db.get_conn() as conn:
            for fp_fp in fp_fingerprints:
                try:
                    conn.execute(
                        """
                        INSERT INTO fp_feedback
                            (scan_id, finding_fingerprint, rule_id, file, line, verdict, created_at)
                        VALUES (?,?,?,?,?,?,?)
                        """,
                        (scan_id, fp_fp, "", "", 0, "fp", now),
                    )
                    actions_taken += 1
                except Exception as exc:
                    logger.debug("Could not record fp_feedback for %s: %s", fp_fp, exc)
            try:
                conn.commit()
            except Exception as exc:
                logger.warning("process_feedback: commit error: %s", exc)

        if not fp_fingerprints:
            return 0

        # 2. Update dataset entries whose fingerprint matches
        with self.db.get_conn() as conn:
            for fp_fp in fp_fingerprints:
                try:
                    conn.execute(
                        """
                        UPDATE dataset_entries
                        SET verdict='false_positive'
                        WHERE finding_fingerprint=? AND scan_id=?
                        """,
                        (fp_fp, scan_id),
                    )
                except Exception as exc:
                    logger.debug("Could not update dataset entry for %s: %s", fp_fp, exc)
            try:
                conn.commit()
            except Exception as exc:
                logger.warning("process_feedback: dataset update commit error: %s", exc)

        # 3. Trigger self-improvement analysis
        try:
            # We only have fingerprints, not full Finding objects, so we pass empty list
            # but supply the fp_fingerprints so the engine records them.
            # For proper analysis we query the dataset for all findings in this scan.
            dataset_entries = self._get_scan_findings_from_dataset(scan_id)
            if dataset_entries:
                self._self_improvement.analyze_scan(
                    scan_id=scan_id + "_feedback",
                    findings=[_EntryAsFinding(e) for e in dataset_entries],
                    fp_fingerprints=fp_fingerprints,
                    fn_count=len(fn_descriptions),
                )
        except Exception as exc:
            logger.warning("process_feedback: self-improvement analysis error: %s", exc)

        # 4. Emit feedback events
        for fp_fp in fp_fingerprints:
            evt = LearningEvent(
                event_id=str(uuid.uuid4()),
                event_type="fp_detected",
                scan_id=scan_id,
                data={"fingerprint": fp_fp},
                processed=False,
                created_at=now,
            )
            self._persist_event(evt)

        # Emit a combined feedback_received event
        feedback_event = LearningEvent(
            event_id=str(uuid.uuid4()),
            event_type="feedback_received",
            scan_id=scan_id,
            data={
                "fp_count": len(fp_fingerprints),
                "fn_count": len(fn_descriptions),
                "fp_fingerprints": fp_fingerprints,
            },
            processed=False,
            created_at=now,
        )
        self._persist_event(feedback_event)

        return actions_taken

    # ------------------------------------------------------------------
    # Learning cycle
    # ------------------------------------------------------------------

    def trigger_learning_cycle(self) -> Dict[str, Any]:
        """Run full learning cycle: improvement + rule evolution + knowledge update."""
        now = datetime.now(timezone.utc).isoformat()
        summary: Dict[str, Any] = {
            "triggered_at": now,
            "improvement_report": None,
            "rule_evolution_stats": None,
            "dataset_stats": None,
            "errors": [],
        }

        # Run self-improvement cycle
        try:
            report = self._self_improvement.run_improvement_cycle(recent_scans=10)
            summary["improvement_report"] = {
                "scans_analyzed": report.scans_analyzed,
                "total_actions": report.total_actions,
                "precision_delta": report.precision_delta,
                "recall_delta": report.recall_delta,
            }
        except Exception as exc:
            logger.warning("trigger_learning_cycle: improvement error: %s", exc)
            summary["errors"].append(f"self_improvement: {exc}")

        # Get rule evolution stats
        try:
            stats = self._rule_evolution.get_stats()
            summary["rule_evolution_stats"] = stats
        except Exception as exc:
            logger.warning("trigger_learning_cycle: rule evolution error: %s", exc)
            summary["errors"].append(f"rule_evolution: {exc}")

        # Get dataset stats
        try:
            ds_stats = self._dataset_manager.get_stats()
            summary["dataset_stats"] = {
                "total_entries": ds_stats.total_entries,
                "true_positives": ds_stats.true_positives,
                "false_positives": ds_stats.false_positives,
                "tp_rate": ds_stats.tp_rate,
                "fp_rate": ds_stats.fp_rate,
            }
        except Exception as exc:
            logger.warning("trigger_learning_cycle: dataset stats error: %s", exc)
            summary["errors"].append(f"dataset_manager: {exc}")

        # Emit cycle event
        cycle_event = LearningEvent(
            event_id=str(uuid.uuid4()),
            event_type="rule_evolved",
            scan_id="",
            data=summary,
            processed=True,
            created_at=now,
        )
        self._persist_event(cycle_event)
        self.mark_event_processed(cycle_event.event_id)

        return summary

    # ------------------------------------------------------------------
    # Stats & events
    # ------------------------------------------------------------------

    def get_stats(self) -> LearningStats:
        """Compute and return overall learning statistics."""
        with self.db.get_conn() as conn:
            total_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM learning_events"
            ).fetchone()
            processed_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM learning_events WHERE processed=1"
            ).fetchone()
            scan_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM learning_events WHERE event_type='scan_completed'"
            ).fetchone()
            fp_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM learning_events WHERE event_type='fp_detected'"
            ).fetchone()
            last_cycle_row = conn.execute(
                """
                SELECT created_at FROM learning_events
                WHERE event_type='rule_evolved'
                ORDER BY created_at DESC LIMIT 1
                """
            ).fetchone()

        total_events = int(total_row["cnt"]) if total_row else 0
        processed_events = int(processed_row["cnt"]) if processed_row else 0
        total_scans = int(scan_row["cnt"]) if scan_row else 0
        total_fps = int(fp_row["cnt"]) if fp_row else 0
        last_cycle = last_cycle_row["created_at"] if last_cycle_row else ""

        # Rule evolution stats
        try:
            evo_stats = self._rule_evolution.get_stats()
            total_rules_evolved = evo_stats.get("active", 0)
        except Exception:
            total_rules_evolved = 0

        # Dataset stats
        try:
            ds = self._dataset_manager.get_stats()
            confirmed_tps = ds.true_positives
            knowledge_entries = ds.total_entries
        except Exception:
            confirmed_tps = 0
            knowledge_entries = 0

        # System precision / recall from recent scan analyses
        precision, recall = self._compute_system_metrics()

        return LearningStats(
            total_events=total_events,
            processed_events=processed_events,
            total_scans_learned_from=total_scans,
            total_rules_evolved=total_rules_evolved,
            total_fps_learned=total_fps,
            total_confirmed_tps=confirmed_tps,
            current_system_precision=precision,
            current_system_recall=recall,
            last_learning_cycle=last_cycle,
            knowledge_entries=knowledge_entries,
        )

    def get_recent_events(self, limit: int = 20) -> List[LearningEvent]:
        """Return the most recent learning events."""
        with self.db.get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM learning_events ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_event(dict(r)) for r in rows]

    def mark_event_processed(self, event_id: str) -> None:
        """Mark a learning event as processed."""
        with self.db.get_conn() as conn:
            conn.execute(
                "UPDATE learning_events SET processed=1 WHERE event_id=?",
                (event_id,),
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _persist_event(self, event: LearningEvent) -> None:
        with self.db.get_conn() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO learning_events
                    (event_id, event_type, scan_id, data_json, processed, created_at)
                VALUES (?,?,?,?,?,?)
                """,
                (
                    event.event_id,
                    event.event_type,
                    event.scan_id,
                    json.dumps(event.data),
                    1 if event.processed else 0,
                    event.created_at,
                ),
            )
            conn.commit()

    @staticmethod
    def _row_to_event(row: Dict[str, Any]) -> LearningEvent:
        try:
            data = json.loads(row.get("data_json") or "{}")
        except json.JSONDecodeError:
            data = {}
        return LearningEvent(
            event_id=row.get("event_id", ""),
            event_type=row.get("event_type", ""),
            scan_id=row.get("scan_id", ""),
            data=data,
            processed=bool(row.get("processed", 0)),
            created_at=row.get("created_at", ""),
        )

    @staticmethod
    def _compute_counts(findings: List[Any]) -> Dict[str, int]:
        """Compute severity counts from a list of findings."""
        counts: Dict[str, int] = {"total": len(findings), "critical": 0, "high": 0}
        for f in findings:
            sev = (getattr(f, "severity", "") or "").upper()
            if sev == "CRITICAL":
                counts["critical"] += 1
            elif sev == "HIGH":
                counts["high"] += 1
        return counts

    def _count_scans(self) -> int:
        """Count total completed scans."""
        with self.db.get_conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM scan_history WHERE completed_at IS NOT NULL"
            ).fetchone()
        return int(row["cnt"]) if row else 0

    def _compute_system_metrics(self) -> tuple[float, float]:
        """Compute system-level precision and recall from recent scan analyses."""
        try:
            with self.db.get_conn() as conn:
                rows = conn.execute(
                    """
                    SELECT precision, recall FROM scan_analyses
                    ORDER BY created_at DESC LIMIT 10
                    """
                ).fetchall()
            if not rows:
                return 1.0, 1.0
            precisions = [float(r["precision"] or 1.0) for r in rows]
            recalls = [float(r["recall"] or 1.0) for r in rows]
            return round(sum(precisions) / len(precisions), 4), round(sum(recalls) / len(recalls), 4)
        except Exception:
            return 1.0, 1.0

    def _get_scan_findings_from_dataset(self, scan_id: str) -> List[Any]:
        """Retrieve dataset entries for a scan_id."""
        try:
            with self.db.get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM dataset_entries WHERE scan_id=?", (scan_id,)
                ).fetchall()
            from backend.core.dataset_manager import DatasetManager
            return [DatasetManager._row_to_entry(dict(r)) for r in rows]
        except Exception:
            return []


# ---------------------------------------------------------------------------
# Adapter: DatasetEntry → minimal Finding-like object for self-improvement
# ---------------------------------------------------------------------------

class _EntryAsFinding:
    """Thin wrapper around DatasetEntry to satisfy the Finding interface."""

    def __init__(self, entry: Any) -> None:
        self._entry = entry
        self.rule_id = entry.rule_id
        self.file = entry.file
        self.line = entry.line
        self.severity = entry.severity
        self.confidence = entry.confidence
        self.cwe_id = entry.cwe_id
        self.description = entry.description
        self.context_lines: List[str] = []

    def fingerprint(self) -> str:
        return self._entry.finding_fingerprint or ""
