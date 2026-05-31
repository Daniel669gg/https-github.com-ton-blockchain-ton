"""
TythanAI Platform — Customer Pilot System
Управление пробными периодами для enterprise acquisition.

Lifecycle:
  lead → trial_started → active → converted | churned

Трекинг:
  • Количество сканов за период
  • Находки по severity
  • Feature adoption (какие эндпоинты используются)
  • Time-to-first-scan (онбординг-метрика)
  • Engagement score
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

_DB = Path("./data/pilots.db")

_SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS pilots (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    company_name    TEXT NOT NULL,
    contact_email   TEXT NOT NULL,
    contact_name    TEXT DEFAULT '',
    plan            TEXT DEFAULT 'trial',
    status          TEXT DEFAULT 'active',
    started_at      REAL NOT NULL,
    trial_ends_at   REAL NOT NULL,
    converted_at    REAL,
    churned_at      REAL,
    trial_days      INTEGER DEFAULT 14,
    seats           INTEGER DEFAULT 5,
    notes           TEXT DEFAULT '',
    source          TEXT DEFAULT 'inbound'
);

CREATE TABLE IF NOT EXISTS pilot_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pilot_id    TEXT NOT NULL REFERENCES pilots(id),
    event_type  TEXT NOT NULL,
    payload     TEXT DEFAULT '{}',
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS pilot_usage (
    pilot_id        TEXT NOT NULL,
    date            TEXT NOT NULL,
    scans_count     INTEGER DEFAULT 0,
    findings_total  INTEGER DEFAULT 0,
    critical_count  INTEGER DEFAULT 0,
    api_calls       INTEGER DEFAULT 0,
    active_users    INTEGER DEFAULT 0,
    features_used   TEXT DEFAULT '[]',
    PRIMARY KEY (pilot_id, date)
);

CREATE INDEX IF NOT EXISTS idx_pilots_org    ON pilots(org_id);
CREATE INDEX IF NOT EXISTS idx_pilots_status ON pilots(status);
CREATE INDEX IF NOT EXISTS idx_events_pilot  ON pilot_events(pilot_id);
CREATE INDEX IF NOT EXISTS idx_usage_pilot   ON pilot_usage(pilot_id);
"""


@dataclass
class PilotRecord:
    id:             str
    org_id:         str
    company_name:   str
    contact_email:  str
    contact_name:   str
    plan:           str
    status:         str
    started_at:     float
    trial_ends_at:  float
    converted_at:   Optional[float]
    churned_at:     Optional[float]
    trial_days:     int
    seats:          int
    notes:          str
    source:         str

    @property
    def days_remaining(self) -> int:
        return max(0, int((self.trial_ends_at - time.time()) / 86400))

    @property
    def is_expired(self) -> bool:
        return time.time() > self.trial_ends_at and self.status == "active"

    @property
    def days_active(self) -> int:
        end = self.converted_at or self.churned_at or time.time()
        return int((end - self.started_at) / 86400)

    def to_dict(self) -> dict:
        return {
            "id":            self.id,
            "org_id":        self.org_id,
            "company_name":  self.company_name,
            "contact_email": self.contact_email,
            "status":        self.status,
            "plan":          self.plan,
            "days_remaining":self.days_remaining,
            "days_active":   self.days_active,
            "is_expired":    self.is_expired,
            "trial_ends_at": self.trial_ends_at,
            "converted_at":  self.converted_at,
            "seats":         self.seats,
            "source":        self.source,
            "notes":         self.notes,
        }


class PilotManager:
    """Full lifecycle management for customer pilots / trials."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        path = Path(db_path or _DB)
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

    # ── Create / Manage ────────────────────────────────────────────────────────

    def create_pilot(
        self,
        org_id:        str,
        company_name:  str,
        contact_email: str,
        contact_name:  str = "",
        trial_days:    int = 14,
        seats:         int = 5,
        plan:          str = "trial",
        source:        str = "inbound",
        notes:         str = "",
    ) -> PilotRecord:
        pid  = secrets.token_hex(8)
        now  = time.time()
        ends = now + trial_days * 86400
        with self._conn() as c:
            c.execute("""
                INSERT INTO pilots
                (id,org_id,company_name,contact_email,contact_name,plan,
                 status,started_at,trial_ends_at,trial_days,seats,source,notes)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (pid, org_id, company_name, contact_email, contact_name,
                  plan, "active", now, ends, trial_days, seats, source, notes))
        self._event(pid, "pilot_created", {"company": company_name, "trial_days": trial_days})
        return self.get(pid)

    def convert(self, pilot_id: str, plan: str = "pro", notes: str = "") -> Optional[PilotRecord]:
        """Mark pilot as converted to paying customer."""
        now = time.time()
        with self._conn() as c:
            c.execute(
                "UPDATE pilots SET status='converted', converted_at=?, plan=?, notes=? WHERE id=?",
                (now, plan, notes, pilot_id),
            )
        self._event(pilot_id, "converted", {"plan": plan, "notes": notes})
        return self.get(pilot_id)

    def churn(self, pilot_id: str, reason: str = "") -> Optional[PilotRecord]:
        """Mark pilot as churned."""
        with self._conn() as c:
            c.execute(
                "UPDATE pilots SET status='churned', churned_at=? WHERE id=?",
                (time.time(), pilot_id),
            )
        self._event(pilot_id, "churned", {"reason": reason})
        return self.get(pilot_id)

    def extend(self, pilot_id: str, extra_days: int) -> Optional[PilotRecord]:
        """Extend trial period."""
        with self._conn() as c:
            c.execute(
                "UPDATE pilots SET trial_ends_at=trial_ends_at+?, trial_days=trial_days+? WHERE id=?",
                (extra_days * 86400, extra_days, pilot_id),
            )
        self._event(pilot_id, "trial_extended", {"extra_days": extra_days})
        return self.get(pilot_id)

    # ── Usage Tracking ─────────────────────────────────────────────────────────

    def record_scan(self, pilot_id: str, findings: int, critical: int) -> None:
        """Record a scan event for usage analytics."""
        date = time.strftime("%Y-%m-%d")
        with self._conn() as c:
            c.execute("""
                INSERT INTO pilot_usage (pilot_id,date,scans_count,findings_total,critical_count,api_calls)
                VALUES(?,?,1,?,?,1)
                ON CONFLICT(pilot_id,date) DO UPDATE SET
                    scans_count=scans_count+1,
                    findings_total=findings_total+excluded.findings_total,
                    critical_count=critical_count+excluded.critical_count,
                    api_calls=api_calls+1
            """, (pilot_id, date, findings, critical))
        self._event(pilot_id, "scan_completed",
                    {"findings": findings, "critical": critical})

    def record_feature(self, pilot_id: str, feature: str) -> None:
        """Track which features the pilot is using."""
        date = time.strftime("%Y-%m-%d")
        with self._conn() as c:
            row = c.execute(
                "SELECT features_used FROM pilot_usage WHERE pilot_id=? AND date=?",
                (pilot_id, date),
            ).fetchone()
            if row:
                used = json.loads(row["features_used"] or "[]")
                if feature not in used:
                    used.append(feature)
                    c.execute(
                        "UPDATE pilot_usage SET features_used=?,api_calls=api_calls+1 WHERE pilot_id=? AND date=?",
                        (json.dumps(used), pilot_id, date),
                    )
            else:
                c.execute(
                    "INSERT OR IGNORE INTO pilot_usage(pilot_id,date,features_used,api_calls) VALUES(?,?,?,1)",
                    (pilot_id, date, json.dumps([feature])),
                )

    # ── Queries ────────────────────────────────────────────────────────────────

    def get(self, pilot_id: str) -> Optional[PilotRecord]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM pilots WHERE id=?", (pilot_id,)).fetchone()
        return self._row_to_rec(dict(row)) if row else None

    def get_by_org(self, org_id: str) -> Optional[PilotRecord]:
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM pilots WHERE org_id=? ORDER BY started_at DESC LIMIT 1",
                (org_id,),
            ).fetchone()
        return self._row_to_rec(dict(row)) if row else None

    def list(self, status: Optional[str] = None, limit: int = 100) -> List[PilotRecord]:
        with self._conn() as c:
            if status:
                rows = c.execute(
                    "SELECT * FROM pilots WHERE status=? ORDER BY started_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = c.execute(
                    "SELECT * FROM pilots ORDER BY started_at DESC LIMIT ?", (limit,)
                ).fetchall()
        return [self._row_to_rec(dict(r)) for r in rows]

    def expiring_soon(self, days: int = 3) -> List[PilotRecord]:
        """Pilots expiring in next N days — useful for sending renewal emails."""
        cutoff = time.time() + days * 86400
        with self._conn() as c:
            rows = c.execute("""
                SELECT * FROM pilots
                WHERE status='active' AND trial_ends_at < ? AND trial_ends_at > ?
                ORDER BY trial_ends_at ASC
            """, (cutoff, time.time())).fetchall()
        return [self._row_to_rec(dict(r)) for r in rows]

    def usage_summary(self, pilot_id: str) -> dict:
        """Aggregate usage stats for a pilot."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM pilot_usage WHERE pilot_id=? ORDER BY date",
                (pilot_id,),
            ).fetchall()
        if not rows:
            return {
                "pilot_id": pilot_id, "scans": 0, "findings": 0,
                "days_active": 0, "days_with_activity": 0,
                "features_used": [], "feature_count": 0,
                "critical": 0, "engagement_score": "minimal",
            }

        total_scans    = sum(r["scans_count"]    for r in rows)
        total_findings = sum(r["findings_total"] for r in rows)
        total_critical = sum(r["critical_count"] for r in rows)
        all_features: set = set()
        for r in rows:
            all_features |= set(json.loads(r["features_used"] or "[]"))

        return {
            "pilot_id":       pilot_id,
            "scans":          total_scans,
            "findings":       total_findings,
            "critical":       total_critical,
            "days_with_activity": len(rows),
            "features_used":  sorted(all_features),
            "feature_count":  len(all_features),
            "engagement_score": self._engagement(total_scans, len(all_features), len(rows)),
        }

    def stats(self) -> dict:
        """Summary stats for all pilots — for investor/sales dashboards."""
        with self._conn() as c:
            total     = c.execute("SELECT COUNT(*) FROM pilots").fetchone()[0]
            active    = c.execute("SELECT COUNT(*) FROM pilots WHERE status='active'").fetchone()[0]
            converted = c.execute("SELECT COUNT(*) FROM pilots WHERE status='converted'").fetchone()[0]
            churned   = c.execute("SELECT COUNT(*) FROM pilots WHERE status='churned'").fetchone()[0]
        return {
            "total":           total,
            "active":          active,
            "converted":       converted,
            "churned":         churned,
            "conversion_rate": round(converted / max(total, 1) * 100, 1),
            "expiring_soon":   len(self.expiring_soon()),
        }

    # ── Internal ───────────────────────────────────────────────────────────────

    def _event(self, pilot_id: str, event_type: str, payload: dict) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO pilot_events(pilot_id,event_type,payload,created_at) VALUES(?,?,?,?)",
                (pilot_id, event_type, json.dumps(payload), time.time()),
            )

    @staticmethod
    def _engagement(scans: int, features: int, active_days: int) -> str:
        score = scans * 2 + features * 5 + active_days * 3
        if score >= 50: return "high"
        if score >= 20: return "medium"
        if score >= 5:  return "low"
        return "minimal"

    @staticmethod
    def _row_to_rec(r: dict) -> PilotRecord:
        return PilotRecord(
            id=r["id"], org_id=r["org_id"], company_name=r["company_name"],
            contact_email=r["contact_email"], contact_name=r.get("contact_name",""),
            plan=r["plan"], status=r["status"],
            started_at=r["started_at"], trial_ends_at=r["trial_ends_at"],
            converted_at=r.get("converted_at"), churned_at=r.get("churned_at"),
            trial_days=r["trial_days"], seats=r["seats"],
            notes=r.get("notes",""), source=r.get("source","inbound"),
        )


PILOTS = PilotManager()
