"""
TythanAI Platform v13 — SQLite-backed Inference Cache
Caches LLM responses keyed on a SHA-256 hash of (model, prompt) with TTL eviction.
Only uses stdlib: sqlite3, hashlib, pathlib, time, logging.
"""
from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# DDL executed on first open
_SCHEMA = """
CREATE TABLE IF NOT EXISTS inference_cache (
    prompt_hash  TEXT    PRIMARY KEY,
    response     TEXT    NOT NULL,
    created_at   REAL    NOT NULL,
    hit_count    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS cache_stats (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    total_gets   INTEGER NOT NULL DEFAULT 0,
    total_hits   INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO cache_stats (id, total_gets, total_hits) VALUES (1, 0, 0);
"""


class InferenceCache:
    """
    SQLite-backed LLM inference cache with TTL-based expiration.

    Thread-safety: each call opens and closes a connection from the pool,
    so concurrent access from multiple threads is safe under SQLite's WAL mode.
    """

    def __init__(
        self,
        db_path: str = "~/.ghost/inference_cache.db",
        ttl_days: int = 7,
    ) -> None:
        self.db_path = Path(os.path.expanduser(db_path))
        self.ttl_seconds: float = ttl_days * 86_400.0
        self._ensure_db()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _ensure_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def hash_prompt(model: str, prompt: str) -> str:
        """SHA-256 digest of (model + prompt), returned as a hex string."""
        payload = f"{model}\x00{prompt}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def get(self, prompt_hash: str) -> Optional[str]:
        """
        Return the cached response for *prompt_hash* if it exists and has not
        expired.  Returns ``None`` on a cache miss or an expired entry.
        """
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                "UPDATE cache_stats SET total_gets = total_gets + 1 WHERE id = 1"
            )
            row = conn.execute(
                "SELECT response, created_at FROM inference_cache WHERE prompt_hash = ?",
                (prompt_hash,),
            ).fetchone()

            if row is None:
                return None

            response, created_at = row

            # TTL check
            if now - created_at > self.ttl_seconds:
                conn.execute(
                    "DELETE FROM inference_cache WHERE prompt_hash = ?", (prompt_hash,)
                )
                logger.debug("Cache miss (expired): %s", prompt_hash[:12])
                return None

            # Hit — increment counters
            conn.execute(
                """UPDATE inference_cache
                   SET hit_count = hit_count + 1
                   WHERE prompt_hash = ?""",
                (prompt_hash,),
            )
            conn.execute(
                "UPDATE cache_stats SET total_hits = total_hits + 1 WHERE id = 1"
            )
            logger.debug("Cache hit: %s", prompt_hash[:12])
            return response

    def set(self, prompt_hash: str, response: str) -> None:
        """Store (or update) a cached response."""
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO inference_cache (prompt_hash, response, created_at, hit_count)
                   VALUES (?, ?, ?, 0)
                   ON CONFLICT(prompt_hash) DO UPDATE SET
                       response   = excluded.response,
                       created_at = excluded.created_at,
                       hit_count  = 0""",
                (prompt_hash, response, now),
            )
        logger.debug("Cache set: %s (%d chars)", prompt_hash[:12], len(response))

    def evict_expired(self) -> int:
        """
        Delete all entries older than the configured TTL.
        Returns the number of rows deleted.
        """
        cutoff = time.time() - self.ttl_seconds
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM inference_cache WHERE created_at < ?", (cutoff,)
            )
            deleted = cur.rowcount
        if deleted:
            logger.info("Evicted %d expired cache entries", deleted)
        return deleted

    def stats(self) -> dict:
        """
        Return a dict with:
        - ``hit_rate``      (float 0–1) — fraction of gets that were hits
        - ``total_entries`` (int)       — current live entries in cache
        - ``size_bytes``    (int)       — size of the SQLite file on disk
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT total_gets, total_hits FROM cache_stats WHERE id = 1"
            ).fetchone()
            total_gets, total_hits = (row or (0, 0))

            total_entries = conn.execute(
                "SELECT COUNT(*) FROM inference_cache"
            ).fetchone()[0]

        hit_rate = (total_hits / total_gets) if total_gets > 0 else 0.0
        size_bytes = self.db_path.stat().st_size if self.db_path.exists() else 0

        return {
            "hit_rate": round(hit_rate, 4),
            "total_entries": total_entries,
            "size_bytes": size_bytes,
            "total_gets": total_gets,
            "total_hits": total_hits,
        }
