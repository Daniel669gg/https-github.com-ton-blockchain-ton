"""
backend/core/dataset_manager.py — TythanAI Training Dataset Accumulation System

Accumulates confirmed findings for training/evaluation of future models.
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("tythanai.dataset_manager")

# ---------------------------------------------------------------------------
# Extended schema SQL
# ---------------------------------------------------------------------------

_DATASET_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS dataset_entries (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id                TEXT    NOT NULL UNIQUE,
    finding_fingerprint     TEXT,
    rule_id                 TEXT,
    file                    TEXT,
    line                    INTEGER,
    severity                TEXT,
    cwe_id                  TEXT,
    description             TEXT,
    source_code_snippet     TEXT,
    verdict                 TEXT,
    confidence              REAL,
    re_verification_result  TEXT,
    scan_id                 TEXT,
    created_at              TEXT    NOT NULL
);
"""

_ALLOWED_VERDICTS = {"true_positive", "false_positive", "needs_review"}


def init_dataset_schema(db: Any) -> None:
    """Create dataset_entries table if it does not exist."""
    with db.get_conn() as conn:
        conn.executescript(_DATASET_SCHEMA_SQL)
        conn.commit()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DatasetEntry:
    entry_id: str
    finding_fingerprint: str
    rule_id: str
    file: str
    line: int
    severity: str
    cwe_id: str
    description: str
    source_code_snippet: str   # max 500 chars
    verdict: str               # "true_positive" | "false_positive" | "needs_review"
    confidence: float
    re_verification_result: Optional[str]
    scan_id: str
    created_at: str


@dataclass
class DatasetStats:
    total_entries: int
    true_positives: int
    false_positives: int
    needs_review: int
    by_severity: Dict[str, int]
    by_rule_id: Dict[str, int]
    by_cwe: Dict[str, int]
    tp_rate: float
    fp_rate: float
    coverage_rules: int   # unique rule_ids


# ---------------------------------------------------------------------------
# Dataset Manager
# ---------------------------------------------------------------------------

class DatasetManager:
    """Accumulates confirmed finding dataset for training/evaluation."""

    MAX_SNIPPET_LENGTH: int = 500

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
        init_dataset_schema(self.db)

    # ------------------------------------------------------------------
    # Add / Update
    # ------------------------------------------------------------------

    def add_entry(
        self,
        finding: Any,
        verdict: str,
        scan_id: str = "",
        source_code_snippet: str = "",
    ) -> DatasetEntry:
        """Add a finding to the dataset.

        verdict must be one of: 'true_positive', 'false_positive', 'needs_review'
        Raises ValueError for invalid verdicts.
        """
        if verdict not in _ALLOWED_VERDICTS:
            raise ValueError(
                f"Invalid verdict '{verdict}'. Allowed: {sorted(_ALLOWED_VERDICTS)}"
            )

        snippet = (source_code_snippet or "")[: self.MAX_SNIPPET_LENGTH]
        now = datetime.now(timezone.utc).isoformat()
        entry_id = str(uuid.uuid4())

        fingerprint = finding.fingerprint() if hasattr(finding, "fingerprint") else ""

        entry = DatasetEntry(
            entry_id=entry_id,
            finding_fingerprint=fingerprint,
            rule_id=getattr(finding, "rule_id", ""),
            file=getattr(finding, "file", ""),
            line=int(getattr(finding, "line", 0)),
            severity=getattr(finding, "severity", "MEDIUM"),
            cwe_id=getattr(finding, "cwe_id", ""),
            description=getattr(finding, "description", ""),
            source_code_snippet=snippet,
            verdict=verdict,
            confidence=float(getattr(finding, "confidence", 0.0)),
            re_verification_result=None,
            scan_id=scan_id,
            created_at=now,
        )

        with self.db.get_conn() as conn:
            conn.execute(
                """
                INSERT INTO dataset_entries
                    (entry_id, finding_fingerprint, rule_id, file, line, severity,
                     cwe_id, description, source_code_snippet, verdict, confidence,
                     re_verification_result, scan_id, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    entry.entry_id,
                    entry.finding_fingerprint,
                    entry.rule_id,
                    entry.file,
                    entry.line,
                    entry.severity,
                    entry.cwe_id,
                    entry.description,
                    entry.source_code_snippet,
                    entry.verdict,
                    entry.confidence,
                    entry.re_verification_result,
                    entry.scan_id,
                    entry.created_at,
                ),
            )
            conn.commit()

        logger.debug("Added dataset entry %s (verdict=%s, rule=%s)", entry_id, verdict, entry.rule_id)
        return entry

    def update_verification(self, entry_id: str, re_verification_result: str) -> None:
        """Update re-verification result for an existing entry."""
        with self.db.get_conn() as conn:
            conn.execute(
                "UPDATE dataset_entries SET re_verification_result=? WHERE entry_id=?",
                (re_verification_result, entry_id),
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Retrieve
    # ------------------------------------------------------------------

    def get_entry(self, entry_id: str) -> Optional[DatasetEntry]:
        """Fetch a single entry by its ID."""
        with self.db.get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM dataset_entries WHERE entry_id=?", (entry_id,)
            ).fetchone()
        if row is None:
            return None
        return self._row_to_entry(dict(row))

    def get_by_rule(self, rule_id: str) -> List[DatasetEntry]:
        """Return all entries for a given rule_id."""
        with self.db.get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM dataset_entries WHERE rule_id=? ORDER BY created_at DESC",
                (rule_id,),
            ).fetchall()
        return [self._row_to_entry(dict(r)) for r in rows]

    def filter_confirmed(self, min_confidence: float = 0.0) -> List[DatasetEntry]:
        """Return only true_positive and false_positive entries (exclude needs_review)."""
        with self.db.get_conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM dataset_entries
                WHERE verdict IN ('true_positive', 'false_positive')
                  AND confidence >= ?
                ORDER BY created_at DESC
                """,
                (min_confidence,),
            ).fetchall()
        return [self._row_to_entry(dict(r)) for r in rows]

    def get_entries_for_training(
        self,
        min_confidence: float = 0.8,
        exclude_needs_review: bool = True,
    ) -> List[DatasetEntry]:
        """Get high-quality entries suitable for model training."""
        if exclude_needs_review:
            verdict_clause = "AND verdict IN ('true_positive', 'false_positive')"
        else:
            verdict_clause = ""

        sql = f"""
            SELECT * FROM dataset_entries
            WHERE confidence >= ?
              {verdict_clause}
            ORDER BY confidence DESC, created_at DESC
        """
        with self.db.get_conn() as conn:
            rows = conn.execute(sql, (min_confidence,)).fetchall()
        return [self._row_to_entry(dict(r)) for r in rows]

    # ------------------------------------------------------------------
    # Export / Import
    # ------------------------------------------------------------------

    def export_jsonl(self, output_path: str) -> int:
        """Export dataset to JSONL format. Returns number of entries written."""
        with self.db.get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM dataset_entries ORDER BY created_at ASC"
            ).fetchall()

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        count = 0
        with output.open("w", encoding="utf-8") as fh:
            for row in rows:
                entry = self._row_to_entry(dict(row))
                fh.write(json.dumps(self._entry_to_dict(entry), ensure_ascii=False) + "\n")
                count += 1

        logger.info("Exported %d entries to JSONL: %s", count, output_path)
        return count

    def export_json(self, output_path: str) -> int:
        """Export dataset to JSON format. Returns number of entries written."""
        with self.db.get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM dataset_entries ORDER BY created_at ASC"
            ).fetchall()

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        entries = [self._entry_to_dict(self._row_to_entry(dict(r))) for r in rows]
        with output.open("w", encoding="utf-8") as fh:
            json.dump(entries, fh, indent=2, ensure_ascii=False)

        count = len(entries)
        logger.info("Exported %d entries to JSON: %s", count, output_path)
        return count

    def import_jsonl(self, input_path: str) -> int:
        """Import entries from JSONL. Skips duplicates. Returns count imported."""
        path = Path(input_path)
        if not path.exists():
            raise FileNotFoundError(f"JSONL file not found: {input_path}")

        count = 0
        with path.open("r", encoding="utf-8") as fh:
            for line_num, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.warning("Skipping malformed JSON on line %d: %s", line_num, exc)
                    continue

                verdict = data.get("verdict", "needs_review")
                if verdict not in _ALLOWED_VERDICTS:
                    verdict = "needs_review"

                entry_id = data.get("entry_id") or str(uuid.uuid4())
                now = datetime.now(timezone.utc).isoformat()

                try:
                    with self.db.get_conn() as conn:
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO dataset_entries
                                (entry_id, finding_fingerprint, rule_id, file, line, severity,
                                 cwe_id, description, source_code_snippet, verdict, confidence,
                                 re_verification_result, scan_id, created_at)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                            """,
                            (
                                entry_id,
                                data.get("finding_fingerprint", ""),
                                data.get("rule_id", ""),
                                data.get("file", ""),
                                int(data.get("line", 0)),
                                data.get("severity", "MEDIUM"),
                                data.get("cwe_id", ""),
                                data.get("description", ""),
                                (data.get("source_code_snippet", "") or "")[: self.MAX_SNIPPET_LENGTH],
                                verdict,
                                float(data.get("confidence", 0.0)),
                                data.get("re_verification_result"),
                                data.get("scan_id", ""),
                                data.get("created_at", now),
                            ),
                        )
                        conn.commit()
                    count += 1
                except Exception as exc:
                    logger.warning("Failed to import entry on line %d: %s", line_num, exc)

        logger.info("Imported %d entries from %s", count, input_path)
        return count

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> DatasetStats:
        """Compute dataset statistics."""
        with self.db.get_conn() as conn:
            total_row = conn.execute("SELECT COUNT(*) AS cnt FROM dataset_entries").fetchone()
            total = int(total_row["cnt"]) if total_row else 0

            verdict_rows = conn.execute(
                "SELECT verdict, COUNT(*) AS cnt FROM dataset_entries GROUP BY verdict"
            ).fetchall()

            sev_rows = conn.execute(
                "SELECT severity, COUNT(*) AS cnt FROM dataset_entries GROUP BY severity"
            ).fetchall()

            rule_rows = conn.execute(
                "SELECT rule_id, COUNT(*) AS cnt FROM dataset_entries GROUP BY rule_id"
            ).fetchall()

            cwe_rows = conn.execute(
                "SELECT cwe_id, COUNT(*) AS cnt FROM dataset_entries GROUP BY cwe_id"
            ).fetchall()

            unique_rules_row = conn.execute(
                "SELECT COUNT(DISTINCT rule_id) AS cnt FROM dataset_entries"
            ).fetchone()

        verdict_counts: Dict[str, int] = {}
        for row in verdict_rows:
            verdict_counts[row["verdict"]] = int(row["cnt"])

        tp = verdict_counts.get("true_positive", 0)
        fp = verdict_counts.get("false_positive", 0)
        nr = verdict_counts.get("needs_review", 0)
        confirmed = tp + fp

        tp_rate = tp / confirmed if confirmed > 0 else 0.0
        fp_rate = fp / confirmed if confirmed > 0 else 0.0

        by_severity = {row["severity"]: int(row["cnt"]) for row in sev_rows}
        by_rule_id = {row["rule_id"]: int(row["cnt"]) for row in rule_rows}
        by_cwe = {(row["cwe_id"] or ""): int(row["cnt"]) for row in cwe_rows}
        coverage_rules = int(unique_rules_row["cnt"]) if unique_rules_row else 0

        return DatasetStats(
            total_entries=total,
            true_positives=tp,
            false_positives=fp,
            needs_review=nr,
            by_severity=by_severity,
            by_rule_id=by_rule_id,
            by_cwe=by_cwe,
            tp_rate=round(tp_rate, 4),
            fp_rate=round(fp_rate, 4),
            coverage_rules=coverage_rules,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_entry(row: Dict[str, Any]) -> DatasetEntry:
        return DatasetEntry(
            entry_id=row.get("entry_id", ""),
            finding_fingerprint=row.get("finding_fingerprint", ""),
            rule_id=row.get("rule_id", ""),
            file=row.get("file", ""),
            line=int(row.get("line", 0)),
            severity=row.get("severity", "MEDIUM"),
            cwe_id=row.get("cwe_id", ""),
            description=row.get("description", ""),
            source_code_snippet=row.get("source_code_snippet", ""),
            verdict=row.get("verdict", "needs_review"),
            confidence=float(row.get("confidence", 0.0)),
            re_verification_result=row.get("re_verification_result"),
            scan_id=row.get("scan_id", ""),
            created_at=row.get("created_at", ""),
        )

    @staticmethod
    def _entry_to_dict(entry: DatasetEntry) -> Dict[str, Any]:
        return {
            "entry_id": entry.entry_id,
            "finding_fingerprint": entry.finding_fingerprint,
            "rule_id": entry.rule_id,
            "file": entry.file,
            "line": entry.line,
            "severity": entry.severity,
            "cwe_id": entry.cwe_id,
            "description": entry.description,
            "source_code_snippet": entry.source_code_snippet,
            "verdict": entry.verdict,
            "confidence": entry.confidence,
            "re_verification_result": entry.re_verification_result,
            "scan_id": entry.scan_id,
            "created_at": entry.created_at,
        }
