"""SQLite database helper — initialize tables, CRUD operations."""
from __future__ import annotations

import logging
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

logger = logging.getLogger("tythanai.db")

# ---------------------------------------------------------------------------
# Lazy import — Finding is defined in backend.core.confidence but we need
# to tolerate circular-import scenarios, so we import inline where needed.
# ---------------------------------------------------------------------------


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS agent_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT    NOT NULL,
    timestamp   TEXT    NOT NULL,
    step_number INTEGER NOT NULL,
    reasoning   TEXT,
    action      TEXT,
    observation TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT    NOT NULL,
    rule_id     TEXT    NOT NULL,
    file        TEXT    NOT NULL,
    line        INTEGER,
    severity    TEXT,
    confidence  REAL,
    cwe_id      TEXT,
    description TEXT,
    created_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT    NOT NULL UNIQUE,
    path            TEXT    NOT NULL,
    started_at      TEXT    NOT NULL,
    completed_at    TEXT,
    total_findings  INTEGER DEFAULT 0,
    critical_count  INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS generated_rules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id        TEXT    NOT NULL UNIQUE,
    yaml_content   TEXT    NOT NULL,
    created_at     TEXT    NOT NULL,
    hit_count      INTEGER DEFAULT 1,
    status         TEXT    DEFAULT 'draft',
    confidence_avg REAL,
    output_path    TEXT    DEFAULT ''
);

CREATE TABLE IF NOT EXISTS attack_chains (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    chain_id    TEXT NOT NULL,
    finding_ids TEXT,
    severity    TEXT,
    narrative   TEXT,
    created_at  TEXT NOT NULL
);
"""


class Database:
    """Thin wrapper around a SQLite connection with schema management."""

    def __init__(self, db_path: str = "data/tythanai.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        logger.debug("Database path: %s", self.db_path.resolve())

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def init_schema(self) -> None:
        """Create all tables if they do not already exist."""
        with self.get_conn() as conn:
            conn.executescript(_SCHEMA_SQL)
            conn.commit()
        logger.info("Database schema initialised at %s", self.db_path)

    # ------------------------------------------------------------------
    # Connection context manager
    # ------------------------------------------------------------------

    @contextmanager
    def get_conn(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def save_finding(self, scan_id: str, finding: Any) -> int:
        """Persist a Finding and return its row id."""
        from datetime import datetime, timezone

        sql = """
            INSERT INTO findings
                (scan_id, rule_id, file, line, severity, confidence,
                 cwe_id, description, created_at)
            VALUES (?,?,?,?,?,?,?,?,?)
        """
        now = datetime.now(timezone.utc).isoformat()
        params = (
            scan_id,
            finding.rule_id,
            finding.file,
            finding.line,
            finding.severity,
            finding.confidence,
            getattr(finding, "cwe_id", ""),
            getattr(finding, "description", ""),
            now,
        )
        with self.get_conn() as conn:
            cur = conn.execute(sql, params)
            conn.commit()
            return cur.lastrowid  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    def save_scan(self, scan_id: str, path: str) -> None:
        """Insert a new scan_history row (started state)."""
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat()
        sql = """
            INSERT OR IGNORE INTO scan_history
                (scan_id, path, started_at)
            VALUES (?,?,?)
        """
        with self.get_conn() as conn:
            conn.execute(sql, (scan_id, path, now))
            conn.commit()

    def complete_scan(self, scan_id: str, counts: Dict[str, int]) -> None:
        """Mark a scan as completed with finding counts."""
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat()
        sql = """
            UPDATE scan_history
            SET completed_at   = ?,
                total_findings = ?,
                critical_count = ?,
                high_count     = ?
            WHERE scan_id = ?
        """
        with self.get_conn() as conn:
            conn.execute(
                sql,
                (
                    now,
                    counts.get("total", 0),
                    counts.get("critical", 0),
                    counts.get("high", 0),
                    scan_id,
                ),
            )
            conn.commit()

    def get_scan_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Return the most recent scan records."""
        sql = """
            SELECT * FROM scan_history
            ORDER BY started_at DESC
            LIMIT ?
        """
        with self.get_conn() as conn:
            rows = conn.execute(sql, (limit,)).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Generated rules helpers
    # ------------------------------------------------------------------

    def upsert_generated_rule(
        self,
        rule_id: str,
        yaml_content: str,
        confidence_avg: float,
        status: str = "draft",
        output_path: str = "",
    ) -> int:
        """Insert or update a generated_rules row; returns new hit_count."""
        sql_select = "SELECT id, hit_count FROM generated_rules WHERE rule_id = ?"
        sql_insert = """
            INSERT INTO generated_rules
                (rule_id, yaml_content, created_at, hit_count, status, confidence_avg, output_path)
            VALUES (?,?,?,1,?,?,?)
        """
        sql_update = """
            UPDATE generated_rules
            SET hit_count      = hit_count + 1,
                yaml_content   = ?,
                confidence_avg = ?,
                status         = ?,
                output_path    = ?
            WHERE rule_id = ?
        """
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat()
        with self.get_conn() as conn:
            row = conn.execute(sql_select, (rule_id,)).fetchone()
            if row is None:
                conn.execute(sql_insert, (rule_id, yaml_content, now, status, confidence_avg, output_path))
                hit_count = 1
            else:
                conn.execute(sql_update, (yaml_content, confidence_avg, status, output_path, rule_id))
                hit_count = row["hit_count"] + 1
            conn.commit()
        return hit_count

    def get_generated_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        sql = "SELECT * FROM generated_rules WHERE rule_id = ?"
        with self.get_conn() as conn:
            row = conn.execute(sql, (rule_id,)).fetchone()
        return dict(row) if row else None

    def list_generated_rules(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        if status:
            sql = "SELECT * FROM generated_rules WHERE status = ? ORDER BY created_at DESC"
            params: tuple = (status,)
        else:
            sql = "SELECT * FROM generated_rules ORDER BY created_at DESC"
            params = ()
        with self.get_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
