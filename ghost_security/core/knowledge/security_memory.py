"""
Ghost Security — Security Memory System
Persistent knowledge base: previous findings, recurring patterns,
org knowledge, CVE context. SQLite-backed, no external deps.
"""
import json, sqlite3, time, hashlib, re
from pathlib import Path
from typing import Dict, List, Optional

DB_PATH = Path(__file__).parent.parent.parent / "data" / "security_memory.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    finding_id  TEXT,
    severity    TEXT,
    category    TEXT,
    source      TEXT,
    file        TEXT,
    description TEXT,
    cwe         TEXT,
    target      TEXT,
    first_seen  REAL,
    last_seen   REAL,
    occurrences INTEGER DEFAULT 1,
    resolved    INTEGER DEFAULT 0,
    notes       TEXT,
    raw_json    TEXT
);
CREATE INDEX IF NOT EXISTS idx_severity  ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_cwe       ON findings(cwe);
CREATE INDEX IF NOT EXISTS idx_target    ON findings(target);

CREATE TABLE IF NOT EXISTS patterns (
    id          TEXT PRIMARY KEY,
    pattern     TEXT,
    category    TEXT,
    occurrence  INTEGER DEFAULT 1,
    first_seen  REAL,
    last_seen   REAL,
    targets     TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    session_id  TEXT PRIMARY KEY,
    target      TEXT,
    audit_type  TEXT,
    timestamp   REAL,
    duration_s  REAL,
    risk_score  INTEGER,
    risk_level  TEXT,
    total_findings INTEGER,
    severity_counts TEXT
);

CREATE TABLE IF NOT EXISTS knowledge (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    category    TEXT,
    updated_at  REAL
);
"""

class SecurityMemory:
    """
    Persistent security knowledge base.
    - Stores all findings across scans
    - Detects recurring patterns / repeat vulnerabilities
    - Tracks remediation status
    - Provides org-level risk trends
    """

    def __init__(self, db_path: Optional[Path] = None):
        self._db = db_path or DB_PATH
        self._db.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ── Findings CRUD ─────────────────────────────────────────────────────────

    def store_finding(self, finding: Dict, target: str, session_id: str = "") -> str:
        """Store or update a finding. Returns finding memory ID."""
        fid = self._finding_hash(finding, target)
        with self._connect() as conn:
            existing = conn.execute("SELECT occurrences FROM findings WHERE id=?", (fid,)).fetchone()
            if existing:
                conn.execute(
                    "UPDATE findings SET last_seen=?, occurrences=occurrences+1 WHERE id=?",
                    (time.time(), fid)
                )
            else:
                conn.execute("""INSERT INTO findings
                    (id,finding_id,severity,category,source,file,description,cwe,
                     target,first_seen,last_seen,raw_json)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (fid, finding.get("id","?"), finding.get("severity","INFO"),
                     finding.get("category",""), finding.get("source",""),
                     finding.get("file",""), finding.get("description","")[:500],
                     finding.get("cwe",""), target,
                     time.time(), time.time(), json.dumps(finding)))
        return fid

    def store_scan(self, report: Dict) -> None:
        """Record a completed scan session."""
        counts = report.get("severity_counts", {})
        with self._connect() as conn:
            conn.execute("""INSERT OR REPLACE INTO scans
                (session_id,target,audit_type,timestamp,duration_s,risk_score,
                 risk_level,total_findings,severity_counts)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (report.get("session_id", str(int(time.time()))),
                 report.get("target",""), report.get("audit_type","full"),
                 time.time(), report.get("duration_s",0),
                 report.get("risk_score",0), report.get("risk_level","LOW"),
                 report.get("total_findings",0), json.dumps(counts)))

    def store_all_findings(self, findings: List[Dict], target: str) -> int:
        count = 0
        for f in findings:
            self.store_finding(f, target)
            count += 1
        self._update_patterns(findings, target)
        return count

    def mark_resolved(self, finding_id: str, notes: str = "") -> bool:
        with self._connect() as conn:
            c = conn.execute(
                "UPDATE findings SET resolved=1,notes=? WHERE finding_id=?",
                (notes, finding_id)
            )
            return c.rowcount > 0

    # ── Queries ───────────────────────────────────────────────────────────────

    def recurring_findings(self, min_occurrences: int = 2) -> List[Dict]:
        """Return findings that appear repeatedly across scans."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT finding_id, severity, cwe, description, target,
                       occurrences, first_seen, last_seen
                FROM findings WHERE occurrences >= ? AND resolved=0
                ORDER BY occurrences DESC, severity ASC
            """, (min_occurrences,)).fetchall()
        return [{"finding_id":r[0],"severity":r[1],"cwe":r[2],
                 "description":r[3][:100],"target":r[4],
                 "occurrences":r[5],"first_seen":r[6],"last_seen":r[7]}
                for r in rows]

    def risk_trend(self, days: int = 30) -> List[Dict]:
        """Return daily risk scores for the last N days."""
        since = time.time() - days * 86400
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT date(timestamp,'unixepoch') as day,
                       AVG(risk_score) as avg_risk,
                       SUM(total_findings) as total_findings
                FROM scans WHERE timestamp > ?
                GROUP BY day ORDER BY day
            """, (since,)).fetchall()
        return [{"date":r[0],"avg_risk":round(r[1],1),"total_findings":r[2]} for r in rows]

    def top_cwes(self, limit: int = 10) -> List[Dict]:
        """Most common CWEs across all findings."""
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT cwe, COUNT(*) as count, MAX(severity) as max_severity
                FROM findings WHERE cwe != '' AND resolved=0
                GROUP BY cwe ORDER BY count DESC LIMIT ?
            """, (limit,)).fetchall()
        return [{"cwe":r[0],"count":r[1],"max_severity":r[2]} for r in rows]

    def unresolved_by_severity(self) -> Dict:
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT severity, COUNT(*) FROM findings
                WHERE resolved=0 GROUP BY severity
            """).fetchall()
        return {r[0]: r[1] for r in rows}

    def search(self, query: str, limit: int = 20) -> List[Dict]:
        like = f"%{query}%"
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT finding_id, severity, cwe, description, file, target, last_seen
                FROM findings WHERE description LIKE ? OR cwe LIKE ? OR file LIKE ?
                ORDER BY last_seen DESC LIMIT ?
            """, (like, like, like, limit)).fetchall()
        return [{"finding_id":r[0],"severity":r[1],"cwe":r[2],
                 "description":r[3][:120],"file":r[4],"target":r[5],"last_seen":r[6]}
                for r in rows]

    def summary(self) -> Dict:
        with self._connect() as conn:
            total_f  = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            unres    = conn.execute("SELECT COUNT(*) FROM findings WHERE resolved=0").fetchone()[0]
            total_s  = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            patterns = conn.execute("SELECT COUNT(*) FROM patterns").fetchone()[0]
        return {"total_findings_ever":total_f,"unresolved":unres,
                "total_scans":total_s,"known_patterns":patterns}

    # ── Knowledge base (arbitrary key-value) ──────────────────────────────────

    def remember(self, key: str, value: str, category: str = "general") -> None:
        with self._connect() as conn:
            conn.execute("""INSERT OR REPLACE INTO knowledge (key,value,category,updated_at)
                VALUES (?,?,?,?)""", (key, value, category, time.time()))

    def recall(self, key: str) -> Optional[str]:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM knowledge WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    # ── Internal ──────────────────────────────────────────────────────────────

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self._db))

    def _update_patterns(self, findings: List[Dict], target: str):
        pat_counts: Dict[str, int] = {}
        for f in findings:
            cat = f.get("category","unknown")
            pat_counts[cat] = pat_counts.get(cat, 0) + 1
        with self._connect() as conn:
            for cat, cnt in pat_counts.items():
                pid = hashlib.md5(cat.encode()).hexdigest()[:12]
                existing = conn.execute("SELECT targets FROM patterns WHERE id=?", (pid,)).fetchone()
                if existing:
                    targets = json.loads(existing[0] or "[]")
                    if target not in targets: targets.append(target)
                    conn.execute("UPDATE patterns SET occurrence=occurrence+?, last_seen=?, targets=? WHERE id=?",
                                 (cnt, time.time(), json.dumps(targets), pid))
                else:
                    conn.execute("INSERT INTO patterns (id,pattern,category,occurrence,first_seen,last_seen,targets) VALUES (?,?,?,?,?,?,?)",
                                 (pid, cat, cat, cnt, time.time(), time.time(), json.dumps([target])))

    @staticmethod
    def _finding_hash(finding: Dict, target: str) -> str:
        key = f"{finding.get('id','')}{finding.get('cwe','')}{finding.get('file','')}{target}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

# Singleton
MEMORY = SecurityMemory()
