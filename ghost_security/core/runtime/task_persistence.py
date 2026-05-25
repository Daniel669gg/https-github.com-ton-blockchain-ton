"""
Ghost Security Platform — Task Persistence
SQLite-backed durable store for scan task state.
Survives process restart; thread-safe via a module-level lock.

Usage:
    from core.runtime.task_persistence import TaskStore
    store = TaskStore()                          # default ~/.ghost/tasks.db
    store = TaskStore(db_path="/tmp/test.db")   # custom path
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

_DEFAULT_DB = Path.home() / ".ghost" / "tasks.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    task_id     TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    state       TEXT NOT NULL DEFAULT 'pending',
    payload     TEXT NOT NULL DEFAULT '{}',
    result      TEXT,
    error       TEXT,
    created_at  REAL NOT NULL,
    finished_at REAL
);

CREATE INDEX IF NOT EXISTS idx_tasks_state      ON tasks(state);
CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks(created_at);
"""


class TaskStore:
    """
    Thread-safe SQLite-backed persistence for runtime tasks.

    Columns
    -------
    task_id     : str   — unique identifier (UUID hex or similar)
    name        : str   — human-readable task name
    state       : str   — pending | running | retrying | succeeded | failed |
                          cancelled | timeout
    payload     : dict  — JSON-serialised input arguments
    result      : Any   — JSON-serialised return value (None until finished)
    error       : str   — error message if the task failed (None otherwise)
    created_at  : float — Unix epoch when the task was first saved
    finished_at : float — Unix epoch when the task reached a terminal state
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        path = Path(db_path) if db_path else _DEFAULT_DB
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = str(path)
        self._lock = threading.Lock()
        self._init_db()

    # ── Private helpers ──────────────────────────────────────────────────────

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")

    @contextmanager
    def _conn(self):
        """Yield a committed connection; rolls back on error."""
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

    @staticmethod
    def _encode(value: Any) -> Optional[str]:
        """Serialize a Python value to a JSON string (None stays None)."""
        if value is None:
            return None
        return json.dumps(value, default=str)

    @staticmethod
    def _decode(text: Optional[str]) -> Any:
        """Deserialize a JSON string back to Python (None stays None)."""
        if text is None:
            return None
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["payload"] = TaskStore._decode(d.get("payload"))
        d["result"]  = TaskStore._decode(d.get("result"))
        return d

    # ── Public API ────────────────────────────────────────────────────────────

    def save_task(
        self,
        task_id:     str,
        name:        str,
        state:       str,
        payload:     Any             = None,
        result:      Any             = None,
        error:       Optional[str]   = None,
        created_at:  Optional[float] = None,
        finished_at: Optional[float] = None,
    ) -> None:
        """
        Insert or replace a task record.

        Parameters
        ----------
        task_id     : unique key; existing rows are fully replaced (UPSERT).
        name        : human-readable label.
        state       : lifecycle state string.
        payload     : arbitrary dict/list/scalar — JSON-serialised internally.
        result      : terminal result value — JSON-serialised internally.
        error       : error message string (None for non-error states).
        created_at  : creation epoch; defaults to now if omitted.
        finished_at : completion epoch; None while task is in-flight.
        """
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO tasks
                        (task_id, name, state, payload, result,
                         error, created_at, finished_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        task_id,
                        name,
                        state,
                        self._encode(payload if payload is not None else {}),
                        self._encode(result),
                        error,
                        created_at if created_at is not None else time.time(),
                        finished_at,
                    ),
                )

    def load_task(self, task_id: str) -> Optional[dict]:
        """
        Return the task record as a plain dict, or None if not found.

        The ``payload`` and ``result`` fields are deserialized from JSON.
        """
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
                ).fetchone()
        return self._row_to_dict(row) if row else None

    def list_tasks(
        self,
        state: Optional[str] = None,
        limit: int = 100,
    ) -> List[dict]:
        """
        Return up to *limit* task records, newest first.

        Parameters
        ----------
        state : if provided, filter to tasks in exactly this state.
        limit : maximum number of rows to return (default 100).
        """
        with self._lock:
            with self._conn() as conn:
                if state is not None:
                    rows = conn.execute(
                        """
                        SELECT * FROM tasks
                        WHERE state = ?
                        ORDER BY created_at DESC
                        LIMIT ?
                        """,
                        (state, limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """
                        SELECT * FROM tasks
                        ORDER BY created_at DESC
                        LIMIT ?
                        """,
                        (limit,),
                    ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def update_state(
        self,
        task_id:     str,
        state:       str,
        result:      Any           = None,
        error:       Optional[str] = None,
        finished_at: Optional[float] = None,
    ) -> bool:
        """
        Update mutable fields of an existing task.

        Returns True if the row was found and updated, False otherwise.
        """
        with self._lock:
            with self._conn() as conn:
                rowcount = conn.execute(
                    """
                    UPDATE tasks
                    SET state = ?,
                        result = ?,
                        error = ?,
                        finished_at = ?
                    WHERE task_id = ?
                    """,
                    (
                        state,
                        self._encode(result),
                        error,
                        finished_at,
                        task_id,
                    ),
                ).rowcount
        return rowcount > 0

    def cleanup_old(self, days: int = 30) -> int:
        """
        Delete task records whose ``created_at`` is older than *days* days.

        Returns the number of rows deleted.
        """
        cutoff = time.time() - days * 86400
        with self._lock:
            with self._conn() as conn:
                rowcount = conn.execute(
                    "DELETE FROM tasks WHERE created_at < ?", (cutoff,)
                ).rowcount
        return rowcount

    def stats(self) -> Dict[str, int]:
        """
        Return a dict mapping each distinct state to its row count.

        Example::

            {
                "pending":   3,
                "running":   1,
                "succeeded": 42,
                "failed":    2,
            }
        """
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT state, COUNT(*) AS cnt FROM tasks GROUP BY state"
                ).fetchall()
        return {row["state"]: row["cnt"] for row in rows}

    def delete_task(self, task_id: str) -> bool:
        """Delete a single task record.  Returns True if it existed."""
        with self._lock:
            with self._conn() as conn:
                rowcount = conn.execute(
                    "DELETE FROM tasks WHERE task_id = ?", (task_id,)
                ).rowcount
        return rowcount > 0
