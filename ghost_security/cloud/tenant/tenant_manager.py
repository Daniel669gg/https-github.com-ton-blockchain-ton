"""
Ghost Security Cloud — Tenant Manager
Multi-tenant management with plan quota enforcement backed by SQLite.
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Plan definitions ───────────────────────────────────────────────────────────
PLANS: dict = {
    "free": {
        "price_usd": 0,
        "scans_per_month": 100,
        "max_repos": 1,
        "description": "Free tier",
    },
    "developer": {
        "price_usd": 49,
        "scans_per_month": 1_000,
        "max_repos": 5,
        "description": "Developer plan",
    },
    "team": {
        "price_usd": 299,
        "scans_per_month": 10_000,
        "max_repos": 50,
        "description": "Team plan",
    },
    "enterprise": {
        "price_usd": None,  # custom
        "scans_per_month": None,  # unlimited
        "max_repos": None,  # unlimited
        "description": "Enterprise — unlimited",
    },
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _current_month() -> str:
    """Return YYYY-MM string for the current month."""
    now = datetime.now(timezone.utc)
    return f"{now.year:04d}-{now.month:02d}"


class TenantManager:
    """Create, manage, and query Ghost Security tenants."""

    def __init__(self, db_path: str = "~/.ghost/cloud.db") -> None:
        self._db_path = Path(db_path).expanduser()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ── Private helpers ────────────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tenants (
                    org_id        TEXT PRIMARY KEY,
                    name          TEXT NOT NULL,
                    plan          TEXT NOT NULL DEFAULT 'free',
                    created_at    TEXT NOT NULL,
                    settings_json TEXT NOT NULL DEFAULT '{}'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS usage_events (
                    event_id      TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    event_type    TEXT NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at    TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_usage_org_month ON usage_events(org_id, created_at)")

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        if "settings_json" in d:
            d["settings"] = json.loads(d.pop("settings_json"))
        return d

    # ── Public API ─────────────────────────────────────────────────────────────

    def create_tenant(self, name: str, plan: str = "free") -> dict:
        """
        Create a new tenant.
        Returns a tenant dict including a freshly generated org_id (UUID4).
        Raises ValueError for unknown plans.
        """
        if plan not in PLANS:
            raise ValueError(f"Unknown plan {plan!r}. Valid: {list(PLANS)}")

        org_id = str(uuid.uuid4())
        created_at = _now_iso()

        with self._conn() as conn:
            conn.execute(
                "INSERT INTO tenants (org_id, name, plan, created_at) VALUES (?, ?, ?, ?)",
                (org_id, name, plan, created_at),
            )

        return {
            "org_id": org_id,
            "name": name,
            "plan": plan,
            "created_at": created_at,
            "settings": {},
        }

    def get_tenant(self, org_id: str) -> Optional[dict]:
        """Return tenant dict or None if not found."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM tenants WHERE org_id = ?", (org_id,)
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def update_tenant(self, org_id: str, **kwargs) -> bool:
        """
        Update mutable fields (name, plan, settings_json).
        Returns True if the tenant was found and updated.
        """
        allowed = {"name", "plan", "settings_json"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False

        # Validate plan if changing
        if "plan" in updates and updates["plan"] not in PLANS:
            raise ValueError(f"Unknown plan {updates['plan']!r}")

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [org_id]

        with self._conn() as conn:
            cursor = conn.execute(
                f"UPDATE tenants SET {set_clause} WHERE org_id = ?", values
            )
        return cursor.rowcount > 0

    def delete_tenant(self, org_id: str) -> bool:
        """Hard-delete a tenant. Returns True if deleted."""
        with self._conn() as conn:
            cursor = conn.execute("DELETE FROM tenants WHERE org_id = ?", (org_id,))
        return cursor.rowcount > 0

    def list_tenants(self) -> list:
        """Return all tenants ordered by creation date descending."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM tenants ORDER BY created_at DESC"
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def check_quota(self, org_id: str, resource: str) -> bool:
        """
        Return True if the tenant is within its plan limits for *resource*.
        Supported resources: 'scans', 'repos'.
        """
        tenant = self.get_tenant(org_id)
        if tenant is None:
            return False

        plan_limits = PLANS.get(tenant["plan"], PLANS["free"])

        if resource == "scans":
            limit = plan_limits["scans_per_month"]
            if limit is None:
                return True  # unlimited
            usage = self.get_usage(org_id)
            return usage.get("scans", 0) < limit

        if resource == "repos":
            limit = plan_limits["max_repos"]
            if limit is None:
                return True
            # Count distinct repos from usage events this month
            month = _current_month()
            with self._conn() as conn:
                count = conn.execute(
                    """
                    SELECT COUNT(DISTINCT json_extract(metadata_json, '$.path')) AS cnt
                    FROM   usage_events
                    WHERE  org_id = ?
                      AND  event_type = 'scan'
                      AND  substr(created_at, 1, 7) = ?
                    """,
                    (org_id, month),
                ).fetchone()["cnt"]
            return count < limit

        # Unknown resource — default to allowed
        return True

    def get_usage(self, org_id: str, month: Optional[str] = None) -> dict:
        """
        Return usage for *org_id* in the given *month* (YYYY-MM).
        Defaults to the current calendar month.
        """
        if month is None:
            month = _current_month()

        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT event_type, metadata_json
                FROM   usage_events
                WHERE  org_id = ?
                  AND  substr(created_at, 1, 7) = ?
                """,
                (org_id, month),
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
            "month": month,
            "org_id": org_id,
            "scans": scans,
            "files_scanned": files_scanned,
            "api_calls": api_calls,
            "findings": findings,
        }
