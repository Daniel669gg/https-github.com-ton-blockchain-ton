"""
Ghost Security Platform — SLA Tracker
Enterprise SLA compliance tracking for security findings.

Security teams have SLA requirements:
  CRITICAL: fix within 1 day
  HIGH:     fix within 7 days
  MEDIUM:   fix within 30 days
  LOW:      fix within 90 days
  INFO:     fix within 365 days

Supports PCI-DSS, SOC 2, and custom policies.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional


# ── SQLite schema ──────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sla_findings (
    finding_id   TEXT PRIMARY KEY,
    rule_id      TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT 'MEDIUM',
    file         TEXT NOT NULL DEFAULT '',
    line         INTEGER NOT NULL DEFAULT 0,
    opened_at    REAL NOT NULL,
    deadline     REAL NOT NULL,
    resolved_at  REAL,
    status       TEXT NOT NULL DEFAULT 'open'
);
CREATE INDEX IF NOT EXISTS idx_sla_status   ON sla_findings(status);
CREATE INDEX IF NOT EXISTS idx_sla_severity ON sla_findings(severity);
CREATE INDEX IF NOT EXISTS idx_sla_deadline ON sla_findings(deadline);
"""

# ── SLA Policy ─────────────────────────────────────────────────────────────────

@dataclass
class SLAPolicy:
    """Maps severity levels to maximum days-to-fix thresholds."""
    name: str
    thresholds: Dict[str, int]  # severity → days to fix

    @classmethod
    def default(cls) -> "SLAPolicy":
        return cls(
            name="default",
            thresholds={
                "CRITICAL": 1,
                "HIGH":     7,
                "MEDIUM":   30,
                "LOW":      90,
                "INFO":     365,
            },
        )

    @classmethod
    def pci_dss(cls) -> "SLAPolicy":
        """
        PCI-DSS 4.0 requirements:
          - CRITICAL within 1 day
          - HIGH within 7 days
          - MEDIUM within 30 days
          - LOW within 90 days
        """
        return cls(
            name="PCI-DSS",
            thresholds={
                "CRITICAL": 1,
                "HIGH":     7,
                "MEDIUM":   30,
                "LOW":      90,
                "INFO":     180,
            },
        )

    @classmethod
    def soc2(cls) -> "SLAPolicy":
        """
        SOC 2 standard thresholds aligned with CC7.1-CC7.5 control requirements.
          - CRITICAL within 1 day
          - HIGH within 7 days
          - MEDIUM within 30 days
          - LOW within 90 days
          - INFO within 365 days
        """
        return cls(
            name="SOC2",
            thresholds={
                "CRITICAL": 1,
                "HIGH":     7,
                "MEDIUM":   30,
                "LOW":      90,
                "INFO":     365,
            },
        )

    def days_for(self, severity: str) -> int:
        """Return the SLA threshold in days for the given severity. Defaults to 30."""
        return self.thresholds.get(severity.upper(), 30)


# ── SLA Status ─────────────────────────────────────────────────────────────────

@dataclass
class SLAStatus:
    finding_id:    str
    rule_id:       str
    severity:      str
    file:          str
    opened_at:     float   # unix timestamp
    deadline:      float   # unix timestamp
    days_remaining: int    # negative = overdue
    is_overdue:    bool
    status:        str     # "on_track" / "at_risk" / "overdue" / "resolved"


# ── SLA Tracker ────────────────────────────────────────────────────────────────

# "at_risk" window: <= this many days remaining → at_risk
_AT_RISK_DAYS = 2


class SLATracker:
    """
    SQLite-backed SLA compliance tracker.

    Usage::

        tracker = SLATracker(policy=SLAPolicy.pci_dss())
        fid = tracker.open_finding({"rule_id": "SQL-001", "severity": "HIGH",
                                    "file": "app.py", "line": 42})
        status = tracker.get_status(fid)
        print(tracker.report("md"))
    """

    def __init__(
        self,
        db_path: str = "~/.ghost/sla.db",
        policy: Optional[SLAPolicy] = None,
    ) -> None:
        path = Path(db_path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path   = str(path)
        self._policy = policy or SLAPolicy.default()
        self._init_db()

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._conn()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _make_finding_id(finding: dict) -> str:
        """Deterministic SHA-256 ID from rule_id + file + line."""
        key = f"{finding.get('rule_id','')}{finding.get('file','')}{finding.get('line',0)}"
        return hashlib.sha256(key.encode()).hexdigest()[:32]

    def _compute_status(
        self,
        deadline: float,
        resolved_at: Optional[float],
    ) -> tuple[int, bool, str]:
        """Returns (days_remaining, is_overdue, status_string)."""
        if resolved_at is not None:
            return 0, False, "resolved"
        now = time.time()
        secs_remaining = deadline - now
        days_remaining = int(math.ceil(secs_remaining / 86400))
        is_overdue = days_remaining < 0
        if is_overdue:
            status_str = "overdue"
        elif days_remaining <= _AT_RISK_DAYS:
            status_str = "at_risk"
        else:
            status_str = "on_track"
        return days_remaining, is_overdue, status_str

    def _row_to_status(self, row: sqlite3.Row) -> SLAStatus:
        days_remaining, is_overdue, status_str = self._compute_status(
            row["deadline"], row["resolved_at"]
        )
        return SLAStatus(
            finding_id=row["finding_id"],
            rule_id=row["rule_id"],
            severity=row["severity"],
            file=row["file"],
            opened_at=row["opened_at"],
            deadline=row["deadline"],
            days_remaining=days_remaining,
            is_overdue=is_overdue,
            status=status_str,
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    def open_finding(self, finding: dict) -> str:
        """
        Register a new finding for SLA tracking.

        Returns the finding_id (SHA-256 of rule_id+file+line).
        Idempotent — if already open, returns the existing ID unchanged.
        """
        fid      = self._make_finding_id(finding)
        severity = finding.get("severity", "MEDIUM").upper()
        days     = self._policy.days_for(severity)
        now      = time.time()
        deadline = now + days * 86400

        conn = self._conn()
        try:
            existing = conn.execute(
                "SELECT finding_id FROM sla_findings WHERE finding_id=?", (fid,)
            ).fetchone()
            if existing:
                return fid

            conn.execute(
                """
                INSERT INTO sla_findings
                  (finding_id, rule_id, severity, file, line, opened_at, deadline, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'open')
                """,
                (
                    fid,
                    finding.get("rule_id", ""),
                    severity,
                    finding.get("file", ""),
                    int(finding.get("line", 0)),
                    now,
                    deadline,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return fid

    def resolve_finding(self, finding_id: str) -> bool:
        """
        Mark a finding as resolved.

        Returns True if found and updated, False if not found.
        """
        conn = self._conn()
        try:
            cur = conn.execute(
                "UPDATE sla_findings SET resolved_at=?, status='resolved' WHERE finding_id=?",
                (time.time(), finding_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def get_status(self, finding_id: str) -> Optional[SLAStatus]:
        """Get SLA status for a specific finding. Returns None if not found."""
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM sla_findings WHERE finding_id=?", (finding_id,)
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return self._row_to_status(row)

    def check_all(self) -> List[SLAStatus]:
        """Return SLA status for all open findings (not resolved)."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM sla_findings WHERE resolved_at IS NULL ORDER BY deadline ASC"
            ).fetchall()
        finally:
            conn.close()
        return [self._row_to_status(r) for r in rows]

    def overdue(self) -> List[SLAStatus]:
        """Return only overdue findings (deadline passed, not resolved)."""
        now = time.time()
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM sla_findings WHERE resolved_at IS NULL AND deadline < ? ORDER BY deadline ASC",
                (now,),
            ).fetchall()
        finally:
            conn.close()
        return [self._row_to_status(r) for r in rows]

    def summary(self) -> dict:
        """
        Returns aggregate counts and an SLA score.

        sla_score: 0-100 (100 = all findings on track, 0 = all overdue).
        Resolved findings are excluded from the score calculation.
        """
        statuses = self.check_all()
        total     = len(statuses)
        on_track  = sum(1 for s in statuses if s.status == "on_track")
        at_risk   = sum(1 for s in statuses if s.status == "at_risk")
        overdue_n = sum(1 for s in statuses if s.status == "overdue")

        if total == 0:
            sla_score = 100.0
        else:
            sla_score = round((on_track / total) * 100, 1)

        return {
            "total":     total,
            "on_track":  on_track,
            "at_risk":   at_risk,
            "overdue":   overdue_n,
            "sla_score": sla_score,
        }

    def track_batch(self, findings: List[dict]) -> dict:
        """
        Open SLA for all findings in the list.

        Returns a summary dict with total count and status breakdown.
        """
        ids = [self.open_finding(f) for f in findings]
        result = self.summary()
        result["registered"] = len(ids)
        return result

    # ── Reporting ──────────────────────────────────────────────────────────────

    def report(self, fmt: str = "table") -> str:
        """
        Generate an SLA compliance report.

        fmt="table"  → colored ASCII table
        fmt="json"   → JSON string
        fmt="md"     → Markdown report with SLA compliance score
        """
        statuses = self.check_all()
        summ     = self.summary()

        if fmt == "json":
            data = {
                "policy":   self._policy.name,
                "summary":  summ,
                "findings": [
                    {
                        "finding_id":    s.finding_id,
                        "rule_id":       s.rule_id,
                        "severity":      s.severity,
                        "file":          s.file,
                        "opened_at":     s.opened_at,
                        "deadline":      s.deadline,
                        "days_remaining": s.days_remaining,
                        "is_overdue":    s.is_overdue,
                        "status":        s.status,
                    }
                    for s in statuses
                ],
            }
            return json.dumps(data, indent=2)

        if fmt == "md":
            lines = [
                f"# SLA Compliance Report — {self._policy.name} Policy",
                "",
                f"**SLA Score:** {summ['sla_score']}/100",
                "",
                f"| Metric | Count |",
                f"|--------|-------|",
                f"| Total open findings | {summ['total']} |",
                f"| On track | {summ['on_track']} |",
                f"| At risk | {summ['at_risk']} |",
                f"| Overdue | {summ['overdue']} |",
                "",
            ]
            if statuses:
                lines += [
                    "## Findings",
                    "",
                    "| ID | Severity | Rule | File | Status | Days Remaining |",
                    "|----|----------|------|------|--------|----------------|",
                ]
                for s in statuses:
                    short_id = s.finding_id[:8]
                    short_file = Path(s.file).name if s.file else ""
                    lines.append(
                        f"| {short_id} | {s.severity} | {s.rule_id} | {short_file} | {s.status} | {s.days_remaining} |"
                    )
            return "\n".join(lines)

        # Default: ASCII table
        _SEV_W = 10
        _STATUS_W = 10
        _FILE_W = 30
        _RULE_W = 20

        RESET  = "\033[0m"
        RED    = "\033[31m"
        ORANGE = "\033[33m"
        GREEN  = "\033[32m"
        BOLD   = "\033[1m"
        DIM    = "\033[2m"

        def sev_color(s: str) -> str:
            return {"CRITICAL": "\033[1;31m", "HIGH": "\033[31m",
                    "MEDIUM": "\033[33m", "LOW": "\033[34m"}.get(s, "")

        def status_color(s: str) -> str:
            return {"overdue": RED, "at_risk": ORANGE, "on_track": GREEN}.get(s, "")

        header = (
            f"{BOLD}{'SEV':<{_SEV_W}}{'STATUS':<{_STATUS_W}}"
            f"{'DAYS':>6}  {'RULE':<{_RULE_W}}{'FILE':<{_FILE_W}}{RESET}"
        )
        separator = "-" * 80
        rows = [header, separator]
        for s in statuses:
            sc = sev_color(s.severity)
            stc = status_color(s.status)
            short_file = Path(s.file).name if s.file else ""
            rows.append(
                f"{sc}{s.severity:<{_SEV_W}}{RESET}"
                f"{stc}{s.status:<{_STATUS_W}}{RESET}"
                f"{s.days_remaining:>6}  "
                f"{DIM}{s.rule_id[:_RULE_W-1]:<{_RULE_W}}{RESET}"
                f"{short_file[:_FILE_W-1]:<{_FILE_W}}"
            )
        rows.append(separator)
        rows.append(
            f"\n{BOLD}SLA Score: {summ['sla_score']}/100{RESET}  "
            f"Total: {summ['total']}  "
            f"{GREEN}On-track: {summ['on_track']}{RESET}  "
            f"{ORANGE}At-risk: {summ['at_risk']}{RESET}  "
            f"{RED}Overdue: {summ['overdue']}{RESET}"
        )
        return "\n".join(rows)
