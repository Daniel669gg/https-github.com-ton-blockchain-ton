"""
Ghost Security Platform — SOC2 Audit Log
Immutable structured event trail for compliance.

Covers SOC2 CC6 (Logical Access), CC7 (System Operations),
CC8 (Change Management) control requirements.

Events logged:
  auth.login / auth.logout / auth.fail
  scan.started / scan.completed / scan.failed
  finding.viewed / finding.suppressed / finding.exported
  api_key.created / api_key.revoked
  user.created / user.role_changed / user.deleted
  rule.loaded / rule.validated
  report.generated / report.exported
  config.changed
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


_DB_PATH    = Path("./data/audit.db")
_CHAIN_KEY  = os.getenv("AUDIT_CHAIN_KEY", "ghost_audit_v1").encode()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    TEXT UNIQUE NOT NULL,
    timestamp   REAL NOT NULL,
    event_type  TEXT NOT NULL,
    actor_id    TEXT NOT NULL DEFAULT 'system',
    actor_email TEXT NOT NULL DEFAULT '',
    org_id      TEXT NOT NULL DEFAULT '',
    resource    TEXT DEFAULT '',
    action      TEXT NOT NULL,
    outcome     TEXT NOT NULL DEFAULT 'success',
    metadata    TEXT DEFAULT '{}',
    ip_address  TEXT DEFAULT '',
    user_agent  TEXT DEFAULT '',
    chain_hash  TEXT NOT NULL,
    prev_hash   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_time  ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_type  ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_org   ON audit_events(org_id);
"""


@dataclass
class AuditEvent:
    event_type:  str           # auth.login, scan.started, etc.
    action:      str           # human-readable description
    outcome:     str = "success"   # success | failure | error
    actor_id:    str = "system"
    actor_email: str = ""
    org_id:      str = ""
    resource:    str = ""          # what resource was acted upon
    metadata:    Dict[str, Any] = field(default_factory=dict)
    ip_address:  str = ""
    user_agent:  str = ""


class AuditLogger:
    """
    Append-only audit log with hash chain integrity verification.
    Each event includes a hash of the previous event — tampering
    breaks the chain and is detectable.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        path = Path(db_path or _DB_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = str(path)
        self._lock = threading.Lock()
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

    # ── Logging ────────────────────────────────────────────────────────────────

    def log(self, event: AuditEvent) -> str:
        """Append an event to the audit log. Returns event_id."""
        import secrets
        event_id = secrets.token_hex(12)
        now      = time.time()

        with self._lock:
            prev_hash = self._last_chain_hash()
            payload   = json.dumps({
                "event_id":   event_id,
                "timestamp":  now,
                "event_type": event.event_type,
                "actor_id":   event.actor_id,
                "action":     event.action,
                "outcome":    event.outcome,
                "metadata":   event.metadata,
                "prev_hash":  prev_hash,
            }, sort_keys=True)
            chain_hash = hmac.new(_CHAIN_KEY, payload.encode(), "sha256").hexdigest()

            with self._conn() as c:
                c.execute("""
                    INSERT INTO audit_events
                    (event_id, timestamp, event_type, actor_id, actor_email, org_id,
                     resource, action, outcome, metadata, ip_address, user_agent,
                     chain_hash, prev_hash)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    event_id, now, event.event_type,
                    event.actor_id, event.actor_email, event.org_id,
                    event.resource, event.action, event.outcome,
                    json.dumps(event.metadata),
                    event.ip_address, event.user_agent,
                    chain_hash, prev_hash,
                ))
        return event_id

    def _last_chain_hash(self) -> str:
        try:
            with self._conn() as c:
                row = c.execute(
                    "SELECT chain_hash FROM audit_events ORDER BY id DESC LIMIT 1"
                ).fetchone()
            return row["chain_hash"] if row else ""
        except Exception:
            return ""

    # ── Convenience methods ────────────────────────────────────────────────────

    def auth_login(self, user_id: str, email: str, org_id: str, ip: str = "", success: bool = True) -> None:
        self.log(AuditEvent(
            event_type  = "auth.login",
            action      = f"User {'logged in' if success else 'login failed'}",
            outcome     = "success" if success else "failure",
            actor_id    = user_id,
            actor_email = email,
            org_id      = org_id,
            ip_address  = ip,
        ))

    def scan_started(self, actor_id: str, org_id: str, target: str, mode: str) -> None:
        self.log(AuditEvent(
            event_type = "scan.started",
            action     = f"Security scan started: {mode} on {target}",
            actor_id   = actor_id,
            org_id     = org_id,
            resource   = target,
            metadata   = {"mode": mode, "target": target},
        ))

    def scan_completed(self, actor_id: str, org_id: str, target: str,
                       findings: int, risk_level: str) -> None:
        self.log(AuditEvent(
            event_type = "scan.completed",
            action     = f"Scan completed: {findings} findings ({risk_level} risk)",
            actor_id   = actor_id,
            org_id     = org_id,
            resource   = target,
            metadata   = {"findings": findings, "risk_level": risk_level},
        ))

    def finding_suppressed(self, actor_id: str, org_id: str,
                           finding_type: str, reason: str) -> None:
        self.log(AuditEvent(
            event_type = "finding.suppressed",
            action     = f"Finding marked as FP: {finding_type}",
            actor_id   = actor_id,
            org_id     = org_id,
            resource   = finding_type,
            metadata   = {"reason": reason},
        ))

    def api_key_created(self, actor_id: str, org_id: str, key_name: str) -> None:
        self.log(AuditEvent(
            event_type = "api_key.created",
            action     = f"API key created: {key_name}",
            actor_id   = actor_id,
            org_id     = org_id,
            metadata   = {"key_name": key_name},
        ))

    def report_exported(self, actor_id: str, org_id: str,
                        report_type: str, findings_count: int) -> None:
        self.log(AuditEvent(
            event_type = "report.exported",
            action     = f"Report exported: {report_type} ({findings_count} findings)",
            actor_id   = actor_id,
            org_id     = org_id,
            metadata   = {"report_type": report_type, "findings": findings_count},
        ))

    def config_changed(self, actor_id: str, org_id: str, key: str, new_value: str) -> None:
        self.log(AuditEvent(
            event_type = "config.changed",
            action     = f"Configuration updated: {key}",
            actor_id   = actor_id,
            org_id     = org_id,
            metadata   = {"key": key, "new_value": str(new_value)[:200]},
        ))

    # ── Query ──────────────────────────────────────────────────────────────────

    def query(
        self,
        org_id:     Optional[str]   = None,
        event_type: Optional[str]   = None,
        actor_id:   Optional[str]   = None,
        since:      Optional[float] = None,
        until:      Optional[float] = None,
        limit:      int = 100,
    ) -> List[dict]:
        filters = []
        params  = []
        if org_id:
            filters.append("org_id=?"); params.append(org_id)
        if event_type:
            filters.append("event_type LIKE ?"); params.append(f"{event_type}%")
        if actor_id:
            filters.append("actor_id=?"); params.append(actor_id)
        if since:
            filters.append("timestamp>=?"); params.append(since)
        if until:
            filters.append("timestamp<=?"); params.append(until)
        params.append(limit)
        where = " WHERE " + " AND ".join(filters) if filters else ""
        sql   = f"SELECT * FROM audit_events{where} ORDER BY timestamp DESC LIMIT ?"
        with self._conn() as c:
            rows = c.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ── Integrity verification ─────────────────────────────────────────────────

    def verify_integrity(self) -> dict:
        """
        Verify the hash chain hasn't been tampered with.
        Returns {valid, checked, broken_at} dict.
        """
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM audit_events ORDER BY id ASC"
            ).fetchall()

        checked = 0
        prev_hash = ""
        for row in rows:
            payload = json.dumps({
                "event_id":   row["event_id"],
                "timestamp":  row["timestamp"],
                "event_type": row["event_type"],
                "actor_id":   row["actor_id"],
                "action":     row["action"],
                "outcome":    row["outcome"],
                "metadata":   json.loads(row["metadata"] or "{}"),
                "prev_hash":  prev_hash,
            }, sort_keys=True)
            expected = hmac.new(_CHAIN_KEY, payload.encode(), "sha256").hexdigest()
            if not hmac.compare_digest(expected, row["chain_hash"]):
                return {
                    "valid":      False,
                    "checked":    checked,
                    "broken_at":  row["event_id"],
                    "message":    f"Chain integrity broken at event {row['event_id']}",
                }
            prev_hash = row["chain_hash"]
            checked += 1

        return {"valid": True, "checked": checked, "message": "Audit log integrity verified"}

    def tail(self, n: int = 50) -> List[dict]:
        """Return the last N audit events, most-recent first."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (n,)
            ).fetchall()
        return [dict(r) for r in rows]

    def export_csv(self, output_path: str) -> str:
        """
        Export the full audit log to a CSV file.

        Returns the absolute path of the written file.
        """
        import csv as _csv

        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM audit_events ORDER BY id ASC"
            ).fetchall()

        out = str(Path(output_path).expanduser().resolve())
        Path(out).parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "id", "event_id", "timestamp", "event_type",
            "actor_id", "actor_email", "org_id", "resource",
            "action", "outcome", "metadata", "ip_address",
            "user_agent", "chain_hash", "prev_hash",
        ]
        with open(out, "w", newline="", encoding="utf-8") as fh:
            writer = _csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(dict(row))

        return out

    def stats(self) -> dict:
        """
        Return aggregate statistics:
          - total_events
          - failures
          - by_type   (event_type → count)
          - by_user   (actor_id  → count)
          - last_24h  (count of events in past 24 hours)
        """
        since_24h = time.time() - 86400
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            by_type = dict(c.execute(
                "SELECT event_type, COUNT(*) FROM audit_events GROUP BY event_type"
            ).fetchall())
            by_user = dict(c.execute(
                "SELECT actor_id, COUNT(*) FROM audit_events GROUP BY actor_id"
            ).fetchall())
            failures = c.execute(
                "SELECT COUNT(*) FROM audit_events WHERE outcome='failure'"
            ).fetchone()[0]
            last_24h = c.execute(
                "SELECT COUNT(*) FROM audit_events WHERE timestamp >= ?", (since_24h,)
            ).fetchone()[0]
        return {
            "total_events": total,
            "failures":     failures,
            "by_type":      by_type,
            "by_user":      by_user,
            "last_24h":     last_24h,
        }


# Singleton
AUDIT = AuditLogger()
