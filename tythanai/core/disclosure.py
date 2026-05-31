"""
TythanAI Platform — Responsible Disclosure Workflow
Полный lifecycle от находки до публичного CVE:
  1. Draft — создаём внутренний отчёт
  2. Validate — проверяем через PoC
  3. Report   — отправляем вендору / Immunefi
  4. Track    — отслеживаем ответ (SLA: 90 дней)
  5. Fix      — вендор подтверждает фикс
  6. Disclose — публикуем после фикса

База данных в SQLite. Уведомления при просрочке SLA.
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


_DB_PATH = Path("./data/disclosures.db")
_DEFAULT_SLA_DAYS = 90  # стандарт отрасли

_SCHEMA = """
CREATE TABLE IF NOT EXISTS disclosures (
    id            TEXT PRIMARY KEY,
    title         TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'draft',
    severity      TEXT NOT NULL DEFAULT 'HIGH',
    target        TEXT NOT NULL DEFAULT '',
    program       TEXT NOT NULL DEFAULT '',
    program_url   TEXT DEFAULT '',
    findings      TEXT DEFAULT '[]',
    poc_notes     TEXT DEFAULT '',
    reporter_name TEXT DEFAULT '',
    reporter_email TEXT DEFAULT '',
    created_at    REAL,
    reported_at   REAL,
    vendor_ack_at REAL,
    fixed_at      REAL,
    disclosed_at  REAL,
    sla_deadline  REAL,
    bounty_amount REAL DEFAULT 0,
    cve_id        TEXT DEFAULT '',
    notes         TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_disc_status ON disclosures(status);
CREATE INDEX IF NOT EXISTS idx_disc_sla    ON disclosures(sla_deadline);
"""

_STATUSES = ["draft","validated","reported","acknowledged","fixed","disclosed","declined"]

_STATUS_DESCRIPTIONS = {
    "draft":        "Finding documented internally, not yet sent",
    "validated":    "PoC confirmed, ready to submit",
    "reported":     "Sent to vendor/program, awaiting response",
    "acknowledged": "Vendor confirmed receipt and triaged",
    "fixed":        "Vendor has deployed a fix",
    "disclosed":    "Published publicly (CVE assigned or post written)",
    "declined":     "Out of scope or not accepted by program",
}


@dataclass
class DisclosureRecord:
    id:             str
    title:          str
    status:         str
    severity:       str
    target:         str
    program:        str
    program_url:    str
    findings:       List[dict]
    poc_notes:      str
    reporter_name:  str
    reporter_email: str
    created_at:     float
    reported_at:    Optional[float]
    vendor_ack_at:  Optional[float]
    fixed_at:       Optional[float]
    disclosed_at:   Optional[float]
    sla_deadline:   Optional[float]
    bounty_amount:  float
    cve_id:         str
    notes:          str

    @property
    def days_since_report(self) -> Optional[int]:
        if self.reported_at:
            return int((time.time() - self.reported_at) / 86400)
        return None

    @property
    def sla_remaining_days(self) -> Optional[int]:
        if self.sla_deadline:
            return max(0, int((self.sla_deadline - time.time()) / 86400))
        return None

    @property
    def is_overdue(self) -> bool:
        return bool(self.sla_deadline and time.time() > self.sla_deadline
                    and self.status not in ("fixed","disclosed","declined"))

    def to_dict(self) -> dict:
        return {
            "id":              self.id,
            "title":           self.title,
            "status":          self.status,
            "status_desc":     _STATUS_DESCRIPTIONS.get(self.status,""),
            "severity":        self.severity,
            "target":          self.target,
            "program":         self.program,
            "program_url":     self.program_url,
            "findings_count":  len(self.findings),
            "poc_notes":       self.poc_notes,
            "reporter_name":   self.reporter_name,
            "created_at":      self.created_at,
            "reported_at":     self.reported_at,
            "vendor_ack_at":   self.vendor_ack_at,
            "fixed_at":        self.fixed_at,
            "disclosed_at":    self.disclosed_at,
            "sla_deadline":    self.sla_deadline,
            "days_since_report": self.days_since_report,
            "sla_remaining":   self.sla_remaining_days,
            "is_overdue":      self.is_overdue,
            "bounty_amount":   self.bounty_amount,
            "cve_id":          self.cve_id,
            "notes":           self.notes,
        }


class DisclosureTracker:
    """Full lifecycle tracker for responsible disclosure."""

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

    # ── CRUD ───────────────────────────────────────────────────────────────────

    def create(
        self,
        title:         str,
        severity:      str,
        target:        str,
        findings:      List[dict],
        program:       str = "",
        program_url:   str = "",
        poc_notes:     str = "",
        reporter_name: str = "",
        reporter_email: str = "",
        sla_days:      int = _DEFAULT_SLA_DAYS,
    ) -> DisclosureRecord:
        did = secrets.token_hex(8)
        now = time.time()
        with self._conn() as c:
            c.execute("""
                INSERT INTO disclosures
                (id,title,status,severity,target,program,program_url,
                 findings,poc_notes,reporter_name,reporter_email,created_at,notes)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'')
            """, (did,"draft",title,severity,target,program,program_url,
                  json.dumps(findings),poc_notes,reporter_name,reporter_email,now))
        # wait is wrong above — positional mismatch, let me redo
        with self._conn() as c:
            c.execute("DELETE FROM disclosures WHERE id=?", (did,))
            c.execute("""
                INSERT INTO disclosures
                (id,status,title,severity,target,program,program_url,
                 findings,poc_notes,reporter_name,reporter_email,created_at,notes)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'')
            """, (did,"draft",title,severity,target,program,program_url,
                  json.dumps(findings),poc_notes,reporter_name,reporter_email,now))
        return self.get(did)

    def advance(self, did: str, new_status: str, **kwargs) -> Optional[DisclosureRecord]:
        """Move disclosure to next status, recording timestamps."""
        if new_status not in _STATUSES:
            return None
        now = time.time()
        updates = {"status": new_status}
        if new_status == "reported":
            updates["reported_at"] = now
            updates["sla_deadline"] = now + _DEFAULT_SLA_DAYS * 86400
        elif new_status == "acknowledged":
            updates["vendor_ack_at"] = now
        elif new_status == "fixed":
            updates["fixed_at"] = now
        elif new_status == "disclosed":
            updates["disclosed_at"] = now
        updates.update(kwargs)

        set_clause = ", ".join(f"{k}=?" for k in updates)
        values     = list(updates.values()) + [did]
        with self._conn() as c:
            c.execute(f"UPDATE disclosures SET {set_clause} WHERE id=?", values)
        return self.get(did)

    def update(self, did: str, **fields) -> Optional[DisclosureRecord]:
        allowed = {"cve_id","bounty_amount","notes","poc_notes","program_url","program"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get(did)
        set_clause = ", ".join(f"{k}=?" for k in updates)
        with self._conn() as c:
            c.execute(f"UPDATE disclosures SET {set_clause} WHERE id=?",
                      list(updates.values()) + [did])
        return self.get(did)

    def get(self, did: str) -> Optional[DisclosureRecord]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM disclosures WHERE id=?", (did,)).fetchone()
        if not row:
            return None
        return self._row_to_record(dict(row))

    def list(self, status: Optional[str] = None) -> List[DisclosureRecord]:
        with self._conn() as c:
            if status:
                rows = c.execute("SELECT * FROM disclosures WHERE status=? ORDER BY created_at DESC", (status,)).fetchall()
            else:
                rows = c.execute("SELECT * FROM disclosures ORDER BY created_at DESC").fetchall()
        return [self._row_to_record(dict(r)) for r in rows]

    def overdue(self) -> List[DisclosureRecord]:
        now = time.time()
        with self._conn() as c:
            rows = c.execute("""
                SELECT * FROM disclosures
                WHERE sla_deadline < ? AND status NOT IN ('fixed','disclosed','declined')
                ORDER BY sla_deadline ASC
            """, (now,)).fetchall()
        return [self._row_to_record(dict(r)) for r in rows]

    # ── Report generation ──────────────────────────────────────────────────────

    def generate_submission(self, did: str) -> str:
        """Generate a ready-to-submit vulnerability report (Markdown)."""
        rec = self.get(did)
        if not rec:
            return "Disclosure not found"
        date    = time.strftime("%Y-%m-%d", time.gmtime(rec.created_at))
        icon    = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(rec.severity,"⚪")
        lines = [
            f"# {icon} {rec.title}",
            f"**Severity:** {rec.severity}  ",
            f"**Target:** {rec.target}  ",
            f"**Date:** {date}  ",
            f"**Reporter:** {rec.reporter_name or 'TythanAI'}",
            "",
            "## Summary",
            "",
            f"A **{rec.severity.lower()} severity** vulnerability was identified in {rec.target}.",
            "",
            "## Vulnerability Details",
            "",
        ]
        for i, f in enumerate(rec.findings, 1):
            msg = f.get("message") or f.get("description","")
            cwe = f.get("cwe","")
            sev = f.get("severity","")
            lines += [
                f"### Finding {i}: {msg[:60]}",
                f"- **Severity:** {sev}",
                f"- **CWE:** {cwe}",
                f"- **File:** `{f.get('file','')}:{f.get('line','')}`",
                f"- **Evidence:** `{(f.get('evidence','') or '')[:100]}`",
                "",
            ]
        if rec.poc_notes:
            lines += ["## Proof of Concept", "", rec.poc_notes, ""]
        lines += [
            "## Impact",
            "",
            "This vulnerability could be exploited by an attacker to:",
            f"- [Describe specific impact based on finding type]",
            "",
            "## Remediation",
            "",
            "Recommended fixes for each finding are provided above.",
            "",
            "## Timeline",
            "",
            f"- {date}: Vulnerability discovered via TythanAI static analysis",
            f"- {date}: Internal validation completed",
            "",
            "## Disclosure Policy",
            "",
            f"This report follows responsible disclosure with a {_DEFAULT_SLA_DAYS}-day remediation window.",
            "",
            "---",
            "*Discovered and reported by TythanAI Platform*",
        ]
        return "\n".join(lines)

    def stats(self) -> dict:
        all_d = self.list()
        by_status: dict = {}
        for d in all_d:
            by_status[d.status] = by_status.get(d.status,0)+1
        total_bounty = sum(d.bounty_amount for d in all_d)
        return {
            "total":        len(all_d),
            "by_status":    by_status,
            "overdue":      len(self.overdue()),
            "total_bounty": total_bounty,
            "cve_count":    sum(1 for d in all_d if d.cve_id),
        }

    @staticmethod
    def _row_to_record(row: dict) -> DisclosureRecord:
        return DisclosureRecord(
            id=row["id"], title=row["title"], status=row["status"],
            severity=row["severity"], target=row["target"],
            program=row["program"], program_url=row.get("program_url",""),
            findings=json.loads(row.get("findings","[]") or "[]"),
            poc_notes=row.get("poc_notes",""),
            reporter_name=row.get("reporter_name",""),
            reporter_email=row.get("reporter_email",""),
            created_at=row["created_at"],
            reported_at=row.get("reported_at"),
            vendor_ack_at=row.get("vendor_ack_at"),
            fixed_at=row.get("fixed_at"),
            disclosed_at=row.get("disclosed_at"),
            sla_deadline=row.get("sla_deadline"),
            bounty_amount=float(row.get("bounty_amount",0) or 0),
            cve_id=row.get("cve_id",""),
            notes=row.get("notes",""),
        )


DISCLOSURE_TRACKER = DisclosureTracker()
