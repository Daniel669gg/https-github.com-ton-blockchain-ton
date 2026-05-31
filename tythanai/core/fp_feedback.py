"""
TythanAI Platform — FP Feedback Loop
Система обучения на разметке пользователя.

Когда пользователь помечает finding как FP:
  1. Сохраняем fingerprint + контекст в БД
  2. Обновляем embedding в vector store
  3. При следующих сканах — похожие findings получают penalty
  4. После N подтверждений — finding автоматически фильтруется

Self-improving: чем больше разметки, тем точнее фильтрация.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_DB_PATH = Path("./data/fp_feedback.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS fp_reports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint   TEXT NOT NULL,
    rule_id       TEXT,
    finding_type  TEXT,
    cwe           TEXT,
    file_pattern  TEXT,
    context_hash  TEXT,
    reporter      TEXT DEFAULT 'user',
    confirmed_at  REAL,
    reason        TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS fp_stats (
    fingerprint   TEXT PRIMARY KEY,
    rule_id       TEXT,
    finding_type  TEXT,
    report_count  INTEGER DEFAULT 0,
    last_seen     REAL,
    auto_suppress BOOLEAN DEFAULT 0,
    confidence_penalty REAL DEFAULT 0.0
);

CREATE INDEX IF NOT EXISTS idx_fp_fingerprint ON fp_reports(fingerprint);
CREATE INDEX IF NOT EXISTS idx_fp_rule ON fp_reports(rule_id);
CREATE INDEX IF NOT EXISTS idx_fp_type ON fp_reports(finding_type);
"""

_AUTO_SUPPRESS_THRESHOLD = 3   # N confirmed FPs → auto-suppress
_PENALTY_PER_REPORT      = 0.15  # confidence penalty per FP report


def _fp_fingerprint(finding: dict) -> str:
    """Stable fingerprint for a finding (same rule + file pattern + context)."""
    file_stem = Path(finding.get("file", "")).stem
    key = "|".join([
        str(finding.get("rule_id") or finding.get("id") or finding.get("type") or ""),
        file_stem,
        str(finding.get("cwe") or ""),
        _context_hash(finding),
    ])
    return hashlib.sha1(key.encode()).hexdigest()[:20]


def _context_hash(finding: dict) -> str:
    """Hash of the code context — normalised to be pattern-independent."""
    ctx = finding.get("evidence") or finding.get("context") or finding.get("code_snippet") or ""
    # Normalise: remove variable names, keep structure
    import re
    ctx = re.sub(r'\b[a-z_][a-z_0-9]{2,}\b', 'VAR', ctx.lower())
    ctx = re.sub(r'\s+', ' ', ctx)
    return hashlib.sha1(ctx.encode()).hexdigest()[:12]


class FPFeedbackStore:
    """SQLite store for FP reports and statistics."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        path = Path(db_path or _DB_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = str(path)
        self._init()

    def _init(self) -> None:
        with self._conn() as c:
            c.executescript(_SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def report_fp(
        self,
        finding: dict,
        reason: str = "",
        reporter: str = "user",
    ) -> dict:
        """Mark a finding as false positive."""
        fp  = _fp_fingerprint(finding)
        rid = finding.get("rule_id") or finding.get("id") or finding.get("type") or ""
        ftype = finding.get("type") or ""

        with self._conn() as c:
            c.execute(
                "INSERT INTO fp_reports(fingerprint,rule_id,finding_type,cwe,file_pattern,"
                "context_hash,reporter,confirmed_at,reason) VALUES(?,?,?,?,?,?,?,?,?)",
                (fp, rid, ftype, finding.get("cwe",""),
                 Path(finding.get("file","")).suffix,
                 _context_hash(finding), reporter, time.time(), reason),
            )
            count = c.execute(
                "SELECT COUNT(*) FROM fp_reports WHERE fingerprint=?", (fp,)
            ).fetchone()[0]
            penalty  = min(1.0, count * _PENALTY_PER_REPORT)
            suppress = count >= _AUTO_SUPPRESS_THRESHOLD
            c.execute("""
                INSERT INTO fp_stats(fingerprint,rule_id,finding_type,report_count,last_seen,auto_suppress,confidence_penalty)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    report_count=report_count+1,
                    last_seen=excluded.last_seen,
                    auto_suppress=excluded.auto_suppress,
                    confidence_penalty=excluded.confidence_penalty
            """, (fp, rid, ftype, count, time.time(), suppress, penalty))

        return {
            "fingerprint":        fp,
            "report_count":       count,
            "confidence_penalty": penalty,
            "auto_suppress":      suppress,
            "message": (
                f"Auto-suppressed after {count} reports"
                if suppress else
                f"FP recorded ({count}/{_AUTO_SUPPRESS_THRESHOLD} for auto-suppress)"
            ),
        }

    def get_penalty(self, finding: dict) -> Tuple[float, bool]:
        """
        Returns (confidence_penalty, auto_suppress) for a finding.
        Call this during scan to adjust confidence before presenting results.
        """
        fp = _fp_fingerprint(finding)
        with self._conn() as c:
            row = c.execute(
                "SELECT confidence_penalty, auto_suppress FROM fp_stats WHERE fingerprint=?",
                (fp,),
            ).fetchone()
        if row:
            return float(row["confidence_penalty"]), bool(row["auto_suppress"])
        return 0.0, False

    def filter_findings(
        self,
        findings: List[dict],
        apply_penalty: bool = True,
    ) -> Tuple[List[dict], List[dict]]:
        """
        Filter findings using FP feedback.
        Returns (kept_findings, suppressed_findings).
        """
        kept: List[dict] = []
        suppressed: List[dict] = []
        for f in findings:
            penalty, suppress = self.get_penalty(f)
            if suppress:
                f = dict(f)
                f["_fp_suppressed"] = True
                f["_fp_reason"]     = "auto-suppressed by user feedback"
                suppressed.append(f)
                continue
            if apply_penalty and penalty > 0:
                f = dict(f)
                orig = float(f.get("confidence", 0.8))
                f["confidence"]     = max(0.0, round(orig - penalty, 3))
                f["_fp_penalty"]    = penalty
            kept.append(f)
        return kept, suppressed

    def top_fp_rules(self, limit: int = 10) -> List[dict]:
        """Rules with most FP reports — useful for tuning."""
        with self._conn() as c:
            rows = c.execute("""
                SELECT rule_id, finding_type, SUM(report_count) as total,
                       COUNT(*) as unique_patterns
                FROM fp_stats GROUP BY rule_id
                ORDER BY total DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        with self._conn() as c:
            total   = c.execute("SELECT COUNT(*) FROM fp_reports").fetchone()[0]
            suppressed = c.execute(
                "SELECT COUNT(*) FROM fp_stats WHERE auto_suppress=1"
            ).fetchone()[0]
            rules   = c.execute("SELECT COUNT(DISTINCT rule_id) FROM fp_stats").fetchone()[0]
        return {
            "total_fp_reports": total,
            "auto_suppressed":  suppressed,
            "affected_rules":   rules,
            "threshold":        _AUTO_SUPPRESS_THRESHOLD,
        }

    def reset_fingerprint(self, finding: dict) -> bool:
        """Un-suppress a previously marked FP (user correction)."""
        fp = _fp_fingerprint(finding)
        with self._conn() as c:
            c.execute("DELETE FROM fp_reports WHERE fingerprint=?", (fp,))
            c.execute("DELETE FROM fp_stats  WHERE fingerprint=?", (fp,))
        return True


# Module singleton
FP_STORE = FPFeedbackStore()
