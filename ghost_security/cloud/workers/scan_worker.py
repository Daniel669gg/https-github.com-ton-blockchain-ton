"""
Ghost Security Cloud — Async Scan Worker
Processes jobs from a SQLite-backed queue.  Calls existing Ghost scanners.
"""

import asyncio
import importlib
import json
import logging
import sqlite3
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

_STATUS_PENDING = "pending"
_STATUS_RUNNING = "running"
_STATUS_COMPLETED = "completed"
_STATUS_FAILED = "failed"

# Map scanner names to module paths + class names in the existing codebase
_SCANNER_REGISTRY: dict = {
    "owasp": ("scanners.owasp_scanner", "OWASPScanner"),
    "dependency": ("scanners.dependency_scanner", "DependencyScanner"),
    "iac": ("scanners.iac_scanner", "IACScanner"),
    "secrets": ("scanners.secret_scanner.scanner", "SecretScanner"),
    "container": ("scanners.container_scanner", "ContainerScanner"),
    "semgrep": ("scanners.semgrep_scanner.runner", "SemgrepScanner"),
    "supply_chain": ("scanners.supply_chain_scanner", "SupplyChainScanner"),
    "js": ("scanners.js_analyzer", "JSAnalyzer"),
    "java": ("scanners.java_scanner", "JavaScanner"),
    "go": ("scanners.go_scanner", "GoScanner"),
    "openapi": ("scanners.openapi_scanner", "OpenAPIScanner"),
    "graphql": ("scanners.graphql_scanner", "GraphQLScanner"),
    "jwt": ("scanners.jwt_scanner", "JWTScanner"),
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanWorker:
    """Pull jobs from the scan queue and execute Ghost Security scanners."""

    def __init__(self, worker_id: str, db_path: str = "~/.ghost/cloud.db") -> None:
        self.worker_id = worker_id
        self._db_path = Path(db_path).expanduser()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ── Private helpers ────────────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    job_id       TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    status       TEXT NOT NULL DEFAULT 'pending',
                    priority     INTEGER NOT NULL DEFAULT 5,
                    path         TEXT NOT NULL,
                    scanner      TEXT NOT NULL,
                    options_json TEXT NOT NULL DEFAULT '{}',
                    created_at   TEXT NOT NULL,
                    started_at   TEXT,
                    completed_at TEXT,
                    worker_id    TEXT,
                    result_json  TEXT
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_jobs_status_pri "
                "ON scan_jobs(status, priority, created_at)"
            )

    def _update_job(self, job_id: str, **fields) -> None:
        if not fields:
            return
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [job_id]
        with self._conn() as conn:
            conn.execute(
                f"UPDATE scan_jobs SET {set_clause} WHERE job_id = ?", values
            )

    # ── Scanner invocation ─────────────────────────────────────────────────────

    def _run_scanner(self, scanner_name: str, path: str, options: dict) -> dict:
        """
        Import and invoke the appropriate Ghost scanner.
        Returns a dict with at least: {findings: list, files_scanned: int}.
        Falls back gracefully if the scanner module is unavailable.
        """
        entry = _SCANNER_REGISTRY.get(scanner_name.lower())
        if entry is None:
            return {
                "error": f"Unknown scanner: {scanner_name!r}",
                "findings": [],
                "files_scanned": 0,
            }

        module_path, class_name = entry
        try:
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)
        except (ImportError, AttributeError) as exc:
            log.warning("Scanner %r not available: %s", scanner_name, exc)
            return {
                "error": f"Scanner {scanner_name!r} unavailable: {exc}",
                "findings": [],
                "files_scanned": 0,
            }

        try:
            scanner = cls(**options) if options else cls()
            target = Path(path)
            # Discover files
            if target.is_file():
                files = [target]
            else:
                files = list(target.rglob("*"))
                files = [f for f in files if f.is_file()]

            # Most scanners expose scan(path) returning a list of findings
            if hasattr(scanner, "scan"):
                raw = scanner.scan(path)
            elif hasattr(scanner, "scan_file"):
                raw = []
                for f in files:
                    raw.extend(scanner.scan_file(str(f)))
            else:
                return {
                    "error": f"Scanner {class_name!r} has no scan() method",
                    "findings": [],
                    "files_scanned": len(files),
                }

            # Normalise findings to list of dicts
            findings = []
            for item in (raw or []):
                if isinstance(item, dict):
                    findings.append(item)
                elif hasattr(item, "__dict__"):
                    findings.append(vars(item))
                else:
                    findings.append({"raw": str(item)})

            return {
                "findings": findings,
                "files_scanned": len(files),
                "scanner": scanner_name,
            }

        except Exception as exc:
            log.error("Scanner %r raised: %s\n%s", scanner_name, exc, traceback.format_exc())
            return {
                "error": str(exc),
                "findings": [],
                "files_scanned": 0,
            }

    # ── Public API ─────────────────────────────────────────────────────────────

    def enqueue_job(
        self,
        org_id: str,
        path: str,
        scanner: str,
        options: Optional[dict] = None,
        priority: int = 5,
    ) -> str:
        """
        Add a new scan job to the queue. Returns job_id.
        Lower priority value = higher priority (like Unix nice).
        """
        job_id = str(uuid.uuid4())
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO scan_jobs
                    (job_id, org_id, status, priority, path, scanner, options_json, created_at)
                VALUES (?, ?, 'pending', ?, ?, ?, ?, ?)
                """,
                (job_id, org_id, priority, path, scanner,
                 json.dumps(options or {}), _now_iso()),
            )
        return job_id

    def claim_job(self) -> Optional[dict]:
        """
        Atomically claim the next pending job ordered by priority then created_at.
        Returns the job dict or None if the queue is empty.
        """
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT * FROM scan_jobs
                WHERE  status = 'pending'
                ORDER  BY priority ASC, created_at ASC
                LIMIT  1
                """,
            ).fetchone()

            if row is None:
                return None

            job_id = row["job_id"]
            conn.execute(
                """
                UPDATE scan_jobs
                SET    status = 'running', started_at = ?, worker_id = ?
                WHERE  job_id = ? AND status = 'pending'
                """,
                (_now_iso(), self.worker_id, job_id),
            )

        # Re-fetch to confirm we won the race
        with self._conn() as conn:
            confirmed = conn.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ? AND worker_id = ? AND status = 'running'",
                (job_id, self.worker_id),
            ).fetchone()

        if confirmed is None:
            return None

        return dict(confirmed)

    def process_scan_job(self, job: dict) -> dict:
        """
        Execute *job* and persist results. Returns the completed job dict.
        job keys required: job_id, org_id, path, scanner, options_json (or options).
        """
        job_id = job["job_id"]
        scanner_name = job["scanner"]
        path = job["path"]

        options_raw = job.get("options_json") or job.get("options") or "{}"
        if isinstance(options_raw, str):
            options = json.loads(options_raw)
        else:
            options = options_raw

        log.info("Worker %s processing job %s (scanner=%s, path=%s)",
                 self.worker_id, job_id, scanner_name, path)

        self._update_job(job_id, status=_STATUS_RUNNING, started_at=_now_iso())

        try:
            result = self._run_scanner(scanner_name, path, options)
            self._update_job(
                job_id,
                status=_STATUS_COMPLETED,
                completed_at=_now_iso(),
                result_json=json.dumps(result),
            )
            result["status"] = _STATUS_COMPLETED
            result["job_id"] = job_id
            return result

        except Exception as exc:
            error_result = {"error": str(exc), "findings": [], "files_scanned": 0}
            self._update_job(
                job_id,
                status=_STATUS_FAILED,
                completed_at=_now_iso(),
                result_json=json.dumps(error_result),
            )
            error_result["status"] = _STATUS_FAILED
            error_result["job_id"] = job_id
            return error_result

    def get_job(self, job_id: str) -> Optional[dict]:
        """Return current state of a job by ID, or None."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scan_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return dict(row) if row else None

    async def run_forever(self, poll_interval: float = 2.0) -> None:
        """
        Async event loop: continuously poll for and process pending jobs.
        Runs until cancelled.
        """
        log.info("ScanWorker %s started, polling every %.1fs", self.worker_id, poll_interval)
        while True:
            try:
                job = self.claim_job()
                if job:
                    # Run the (potentially blocking) scanner in a thread pool
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, self.process_scan_job, job)
                else:
                    await asyncio.sleep(poll_interval)
            except asyncio.CancelledError:
                log.info("ScanWorker %s shutting down", self.worker_id)
                return
            except Exception as exc:
                log.error("ScanWorker %s unexpected error: %s", self.worker_id, exc)
                await asyncio.sleep(poll_interval)
