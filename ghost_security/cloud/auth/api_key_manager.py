"""
Ghost Security Cloud — API Key Manager
Manages creation, validation, rotation, and revocation of API keys.
Keys are stored as SHA-256 hashes; plaintext is returned only once at creation.
"""

import hashlib
import os
import secrets
import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class APIKeyManager:
    """Manage lifecycle of Ghost Security API keys per organisation."""

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
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_id      TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    key_hash    TEXT NOT NULL UNIQUE,
                    name        TEXT NOT NULL,
                    scopes_json TEXT NOT NULL DEFAULT '[]',
                    created_at  TEXT NOT NULL,
                    expires_at  TEXT,
                    revoked     INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_org ON api_keys(org_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)")

    @staticmethod
    def _generate_key() -> str:
        """Return a new key in the format ghst_<32 hex chars>."""
        return "ghst_" + secrets.token_hex(16)  # 16 bytes → 32 hex chars

    # ── Public API ─────────────────────────────────────────────────────────────

    def create_key(self, org_id: str, name: str, scopes: list) -> dict:
        """
        Create a new API key for *org_id*.

        Returns dict with keys: key, key_id, created_at, scopes.
        The ``key`` field is the plaintext value — it is NOT stored; save it now.
        """
        plaintext = self._generate_key()
        key_id = secrets.token_hex(8)
        key_hash = _sha256(plaintext)
        created_at = _now_iso()

        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO api_keys
                    (key_id, org_id, key_hash, name, scopes_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (key_id, org_id, key_hash, name, json.dumps(scopes), created_at),
            )

        return {
            "key": plaintext,
            "key_id": key_id,
            "created_at": created_at,
            "scopes": scopes,
            "name": name,
        }

    def validate_key(self, key: str) -> Optional[dict]:
        """
        Validate *key* and return its metadata, or None if invalid/expired/revoked.

        Returned dict contains: org_id, key_id, scopes, name.
        """
        if not key or not key.startswith("ghst_"):
            return None

        key_hash = _sha256(key)
        now = _now_iso()

        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT key_id, org_id, scopes_json, name, expires_at, revoked
                FROM   api_keys
                WHERE  key_hash = ?
                """,
                (key_hash,),
            ).fetchone()

        if row is None:
            return None
        if row["revoked"]:
            return None
        if row["expires_at"] and row["expires_at"] < now:
            return None

        return {
            "key_id": row["key_id"],
            "org_id": row["org_id"],
            "scopes": json.loads(row["scopes_json"]),
            "name": row["name"],
        }

    def revoke_key(self, key_id: str, org_id: str) -> bool:
        """
        Revoke the key identified by *key_id* that belongs to *org_id*.
        Returns True if a row was updated, False otherwise.
        """
        with self._conn() as conn:
            cursor = conn.execute(
                "UPDATE api_keys SET revoked = 1 WHERE key_id = ? AND org_id = ?",
                (key_id, org_id),
            )
        return cursor.rowcount > 0

    def list_keys(self, org_id: str) -> list:
        """
        Return all non-revoked keys for *org_id* (without the plaintext key).
        """
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT key_id, name, scopes_json, created_at, expires_at, revoked
                FROM   api_keys
                WHERE  org_id = ?
                ORDER  BY created_at DESC
                """,
                (org_id,),
            ).fetchall()

        return [
            {
                "key_id": r["key_id"],
                "name": r["name"],
                "scopes": json.loads(r["scopes_json"]),
                "created_at": r["created_at"],
                "expires_at": r["expires_at"],
                "revoked": bool(r["revoked"]),
            }
            for r in rows
        ]

    def rotate_key(self, key_id: str, org_id: str) -> dict:
        """
        Create a new key with the same name/scopes as *key_id*, then revoke the old one.
        Returns the new key dict (same shape as create_key).
        Raises ValueError if the old key does not exist or does not belong to *org_id*.
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT name, scopes_json FROM api_keys WHERE key_id = ? AND org_id = ?",
                (key_id, org_id),
            ).fetchone()

        if row is None:
            raise ValueError(f"Key {key_id!r} not found for org {org_id!r}")

        new_key = self.create_key(
            org_id=org_id,
            name=row["name"],
            scopes=json.loads(row["scopes_json"]),
        )
        self.revoke_key(key_id, org_id)
        new_key["rotated_from"] = key_id
        return new_key
