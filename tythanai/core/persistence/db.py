"""
TythanAI Platform — SQLite Persistence Layer
Таблицы: scans, findings, packages
Фичи:
  • История всех сканов с метриками
  • Diff "новые с прошлого раза" и "исчезли"
  • Тренд risk-score за N дней
  • TOP-10 повторяющихся CWE
  • Поиск по findings
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, List, Optional, Tuple


_DEFAULT_DB = Path(__file__).parent.parent / "data" / "tythanai.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    mode        TEXT NOT NULL DEFAULT 'all',
    started_at  REAL NOT NULL,
    finished_at REAL,
    total_findings INTEGER DEFAULT 0,
    critical    INTEGER DEFAULT 0,
    high        INTEGER DEFAULT 0,
    medium      INTEGER DEFAULT 0,
    low         INTEGER DEFAULT 0,
    risk_score  REAL DEFAULT 0.0,
    risk_level  TEXT DEFAULT 'UNKNOWN',
    meta        TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS findings (
    id            TEXT PRIMARY KEY,
    scan_id       TEXT NOT NULL REFERENCES scans(id),
    rule_id       TEXT,
    type          TEXT,
    severity      TEXT,
    cwe           TEXT,
    owasp         TEXT,
    file          TEXT,
    line          INTEGER,
    message       TEXT,
    description   TEXT,
    evidence      TEXT,
    confidence    REAL DEFAULT 0.8,
    priority      TEXT,
    fingerprint   TEXT,
    first_seen_at REAL,
    last_seen_at  REAL,
    occurrences   INTEGER DEFAULT 1,
    raw           TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_findings_scan  ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_fp    ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_sev   ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_cwe   ON findings(cwe);
CREATE INDEX IF NOT EXISTS idx_scans_target   ON scans(target);
CREATE INDEX IF NOT EXISTS idx_scans_started  ON scans(started_at);
"""


def _fingerprint(f: dict) -> str:
    key = "|".join([
        str(f.get("rule_id") or f.get("id") or f.get("type") or ""),
        str(f.get("file") or ""),
        str(f.get("line") or ""),
    ])
    return hashlib.sha1(key.encode()).hexdigest()[:20]


def _finding_id(scan_id: str, fp: str) -> str:
    return hashlib.sha1(f"{scan_id}:{fp}".encode()).hexdigest()[:24]


class GhostDB:
    """
    Центральное хранилище результатов TythanAI.
    Потокобезопасен (check_same_thread=False + WAL mode).
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        path = Path(db_path or _DEFAULT_DB)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = str(path)
        self._init()

    # ── Init ──────────────────────────────────────────────────────────────────

    def _init(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")

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

    # ── Scan lifecycle ─────────────────────────────────────────────────────────

    def begin_scan(self, scan_id: str, target: str, mode: str = "all") -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO scans(id,target,mode,started_at) VALUES(?,?,?,?)",
                (scan_id, target, mode, time.time()),
            )

    def finish_scan(self, scan_id: str, findings: List[dict], meta: dict = None) -> dict:
        """Сохраняет findings, вычисляет метрики, возвращает summary."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        now    = time.time()

        with self._conn() as conn:
            for raw in findings:
                f   = dict(raw)
                fp  = f.get("fingerprint") or _fingerprint(f)
                fid = _finding_id(scan_id, fp)
                sev = (f.get("severity") or "MEDIUM").upper()
                counts[sev] = counts.get(sev, 0) + 1

                conn.execute("""
                    INSERT OR REPLACE INTO findings
                    (id,scan_id,rule_id,type,severity,cwe,owasp,
                     file,line,message,description,evidence,
                     confidence,priority,fingerprint,
                     first_seen_at,last_seen_at,occurrences,raw)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,
                        COALESCE((SELECT first_seen_at FROM findings WHERE fingerprint=? LIMIT 1),?),
                        ?,
                        COALESCE((SELECT occurrences FROM findings WHERE fingerprint=? LIMIT 1),0)+1,
                        ?)
                """, (
                    fid, scan_id,
                    f.get("rule_id") or f.get("id"),
                    f.get("type"),
                    sev,
                    f.get("cwe"), f.get("owasp"),
                    f.get("file"), f.get("line"),
                    f.get("message") or f.get("description"),
                    f.get("description"),
                    f.get("evidence"),
                    f.get("confidence", 0.8),
                    f.get("priority"),
                    fp,
                    fp, now,   # first_seen fallback
                    now,       # last_seen
                    fp,        # occurrences subquery
                    json.dumps(f),
                ))

            risk_score = min(
                counts.get("CRITICAL", 0) * 25 +
                counts.get("HIGH", 0) * 15 +
                counts.get("MEDIUM", 0) * 8 +
                counts.get("LOW", 0) * 3, 100
            )
            risk_level = (
                "CRITICAL" if risk_score >= 75 else
                "HIGH"     if risk_score >= 50 else
                "MEDIUM"   if risk_score >= 25 else "LOW"
            )

            conn.execute("""
                UPDATE scans SET
                    finished_at=?, total_findings=?,
                    critical=?, high=?, medium=?, low=?,
                    risk_score=?, risk_level=?, meta=?
                WHERE id=?
            """, (
                now, len(findings),
                counts.get("CRITICAL", 0), counts.get("HIGH", 0),
                counts.get("MEDIUM", 0),   counts.get("LOW", 0),
                risk_score, risk_level,
                json.dumps(meta or {}),
                scan_id,
            ))

        return {
            "scan_id":    scan_id,
            "findings":   len(findings),
            "severity_counts": counts,
            "risk_score": risk_score,
            "risk_level": risk_level,
        }

    # ── Diff ("новые с прошлого раза") ────────────────────────────────────────

    def diff_with_previous(self, scan_id: str) -> dict:
        """
        Сравнивает текущий скан с предыдущим сканом того же target.
        Возвращает: new, fixed, recurring findings.
        """
        with self._conn() as conn:
            # Найти target текущего скана
            row = conn.execute(
                "SELECT target FROM scans WHERE id=?", (scan_id,)
            ).fetchone()
            if not row:
                return {"error": "scan not found"}
            target = row["target"]

            # Предыдущий скан того же target
            prev = conn.execute("""
                SELECT id FROM scans
                WHERE target=? AND id!=? AND finished_at IS NOT NULL
                ORDER BY started_at DESC LIMIT 1
            """, (target, scan_id)).fetchone()

            if not prev:
                return {
                    "status":    "first_scan",
                    "new":       [],
                    "fixed":     [],
                    "recurring": [],
                }

            prev_id = prev["id"]

            # Fingerprints в каждом скане
            curr_fps = {
                r["fingerprint"]: dict(r)
                for r in conn.execute(
                    "SELECT * FROM findings WHERE scan_id=?", (scan_id,)
                )
            }
            prev_fps = {
                r["fingerprint"]: dict(r)
                for r in conn.execute(
                    "SELECT * FROM findings WHERE scan_id=?", (prev_id,)
                )
            }

            new       = [v for fp, v in curr_fps.items() if fp not in prev_fps]
            fixed     = [v for fp, v in prev_fps.items() if fp not in curr_fps]
            recurring = [v for fp, v in curr_fps.items() if fp in prev_fps]

        return {
            "compared_with": prev_id,
            "new":       new,
            "fixed":     fixed,
            "recurring": recurring,
            "summary": {
                "new_count":       len(new),
                "fixed_count":     len(fixed),
                "recurring_count": len(recurring),
            },
        }

    # ── Тренд risk-score ───────────────────────────────────────────────────────

    def risk_trend(self, target: str, days: int = 30) -> List[dict]:
        since = time.time() - days * 86400
        with self._conn() as conn:
            rows = conn.execute("""
                SELECT id, started_at, risk_score, risk_level,
                       total_findings, critical, high
                FROM scans
                WHERE target=? AND started_at>=? AND finished_at IS NOT NULL
                ORDER BY started_at ASC
            """, (target, since)).fetchall()
        return [dict(r) for r in rows]

    # ── TOP CWE ───────────────────────────────────────────────────────────────

    def top_cwes(self, limit: int = 10, target: Optional[str] = None) -> List[dict]:
        with self._conn() as conn:
            if target:
                rows = conn.execute("""
                    SELECT f.cwe, COUNT(*) as cnt, MAX(f.severity) as max_sev
                    FROM findings f JOIN scans s ON f.scan_id=s.id
                    WHERE s.target=? AND f.cwe IS NOT NULL AND f.cwe!=''
                    GROUP BY f.cwe ORDER BY cnt DESC LIMIT ?
                """, (target, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT cwe, COUNT(*) as cnt, MAX(severity) as max_sev
                    FROM findings
                    WHERE cwe IS NOT NULL AND cwe!=''
                    GROUP BY cwe ORDER BY cnt DESC LIMIT ?
                """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ── История сканов ─────────────────────────────────────────────────────────

    def list_scans(
        self,
        target: Optional[str] = None,
        limit: int = 20,
    ) -> List[dict]:
        with self._conn() as conn:
            if target:
                rows = conn.execute("""
                    SELECT * FROM scans WHERE target=?
                    ORDER BY started_at DESC LIMIT ?
                """, (target, limit)).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?",
                    (limit,)
                ).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id: str) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE id=?", (scan_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_findings(self, scan_id: str) -> List[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id=? ORDER BY severity",
                (scan_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Поиск ─────────────────────────────────────────────────────────────────

    def search_findings(
        self,
        query:    str,
        severity: Optional[str] = None,
        cwe:      Optional[str] = None,
        limit:    int = 50,
    ) -> List[dict]:
        filters = ["(message LIKE ? OR description LIKE ? OR type LIKE ?)"]
        params  = [f"%{query}%", f"%{query}%", f"%{query}%"]
        if severity:
            filters.append("severity=?"); params.append(severity.upper())
        if cwe:
            filters.append("cwe=?");      params.append(cwe)
        params.append(limit)
        sql = f"SELECT * FROM findings WHERE {' AND '.join(filters)} ORDER BY severity LIMIT ?"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ── Статистика ────────────────────────────────────────────────────────────

    def global_stats(self) -> dict:
        with self._conn() as conn:
            total_scans    = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            targets        = conn.execute("SELECT COUNT(DISTINCT target) FROM scans").fetchone()[0]
            worst          = conn.execute("""
                SELECT target, MAX(risk_score) as risk_score, risk_level
                FROM scans WHERE finished_at IS NOT NULL
                GROUP BY target ORDER BY risk_score DESC LIMIT 5
            """).fetchall()
        return {
            "total_scans":    total_scans,
            "total_findings": total_findings,
            "unique_targets": targets,
            "worst_targets":  [dict(r) for r in worst],
        }

    def delete_scan(self, scan_id: str) -> bool:
        with self._conn() as conn:
            conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
            n = conn.execute("DELETE FROM scans WHERE id=?", (scan_id,)).rowcount
        return n > 0


# Singleton
_DB: Optional[GhostDB] = None

def get_db(path: Optional[str] = None) -> GhostDB:
    global _DB
    if _DB is None:
        _DB = GhostDB(path)
    return _DB
