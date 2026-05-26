"""
Ghost Security Cloud — Usage Tracker
Records per-org scan and API call events to SQLite for billing.
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class UsageTracker:
    """Record and query billing usage events per organisation."""

    def __init__(self, db_path: str = "~/.ghost/cloud.db") -> None:
        self._db_path = Path(db_path).expanduser()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ── Private helpers ────────────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS usage_events (
                    event_id      TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    event_type    TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at    TEXT NOT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ue_org_type_date "
                "ON usage_events(org_id, event_type, created_at)"
            )

    def _insert_event(self, org_id: str, event_type: str, metadata: dict) -> str:
        event_id = str(uuid.uuid4())
        created_at = _now_iso()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO usage_events (event_id, org_id, event_type, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (event_id, org_id, event_type, json.dumps(metadata), created_at),
            )
        return event_id

    # ── Public API ─────────────────────────────────────────────────────────────

    def record_scan(
        self,
        org_id: str,
        scanner: str,
        files_scanned: int,
        findings: int,
    ) -> str:
        """Record a completed scan event. Returns the event_id."""
        return self._insert_event(
            org_id,
            "scan",
            {
                "scanner": scanner,
                "files_scanned": files_scanned,
                "findings": findings,
            },
        )

    def record_api_call(self, org_id: str, endpoint: str, status_code: int) -> str:
        """Record an API call event. Returns the event_id."""
        return self._insert_event(
            org_id,
            "api_call",
            {"endpoint": endpoint, "status_code": status_code},
        )

    def get_monthly_usage(self, org_id: str, year: int, month: int) -> dict:
        """
        Aggregate usage for *org_id* in the given year/month.
        Returns: {scans, files_scanned, api_calls, findings, year, month}
        """
        month_prefix = f"{year:04d}-{month:02d}"

        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT event_type, metadata_json
                FROM   usage_events
                WHERE  org_id = ?
                  AND  substr(created_at, 1, 7) = ?
                """,
                (org_id, month_prefix),
            ).fetchall()

        scans = 0
        files_scanned = 0
        api_calls = 0
        findings = 0

        for row in rows:
            meta = json.loads(row["metadata_json"])
            if row["event_type"] == "scan":
                scans += 1
                files_scanned += meta.get("files_scanned", 0)
                findings += meta.get("findings", 0)
            elif row["event_type"] == "api_call":
                api_calls += 1

        return {
            "org_id": org_id,
            "year": year,
            "month": month,
            "scans": scans,
            "files_scanned": files_scanned,
            "api_calls": api_calls,
            "findings": findings,
        }

    def get_usage_report(self, org_id: str) -> dict:
        """
        Return current month usage plus the previous 3 months.
        Keys: current_month, history (list of monthly dicts).
        """
        now = datetime.now(timezone.utc)
        current = self.get_monthly_usage(org_id, now.year, now.month)

        history = []
        year, month = now.year, now.month
        for _ in range(3):
            month -= 1
            if month == 0:
                month = 12
                year -= 1
            history.append(self.get_monthly_usage(org_id, year, month))

        return {
            "org_id": org_id,
            "current_month": current,
            "history": history,
        }
