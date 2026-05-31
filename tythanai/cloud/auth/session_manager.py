"""
TythanAI Cloud — Session Manager
HMAC-signed sessions stored in SQLite; no external JWT library required.

Token format (dot-separated, URL-safe base64):
  <header_b64>.<payload_b64>.<signature_b64>

where signature = HMAC-SHA256(secret_key, header_b64 + "." + payload_b64)
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


_SESSION_TTL_HOURS = 24


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(s: str) -> bytes:
    # Add back stripped padding
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class SessionManager:
    """Create and validate HMAC-signed sessions backed by SQLite."""

    def __init__(self, secret_key: Optional[str] = None, db_path: str = "~/.ghost/cloud.db") -> None:
        self._secret = (secret_key or secrets.token_hex(32)).encode()
        self._db_path = Path(db_path).expanduser()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ── Private helpers ────────────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id    TEXT NOT NULL,
                    org_id     TEXT NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    metadata   TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked    INTEGER NOT NULL DEFAULT 0
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_hash ON sessions(token_hash)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")

    def _sign(self, header_b64: str, payload_b64: str) -> str:
        message = f"{header_b64}.{payload_b64}".encode()
        sig = hmac.new(self._secret, message, hashlib.sha256).digest()
        return _b64_encode(sig)

    def _build_token(self, payload: dict) -> str:
        header = {"alg": "HS256", "typ": "GHOST"}
        header_b64 = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())
        sig_b64 = self._sign(header_b64, payload_b64)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def _parse_token(self, token: str) -> Optional[dict]:
        """Parse and verify signature; return payload dict or None."""
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, provided_sig = parts
        expected_sig = self._sign(header_b64, payload_b64)
        if not hmac.compare_digest(expected_sig, provided_sig):
            return None
        try:
            return json.loads(_b64_decode(payload_b64))
        except Exception:
            return None

    # ── Public API ─────────────────────────────────────────────────────────────

    def create_session(self, user_id: str, org_id: str, metadata: Optional[dict] = None) -> str:
        """
        Create a signed session token for *user_id* / *org_id*.
        Returns the token string; also persists a hash in SQLite.
        """
        session_id = secrets.token_hex(16)
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(hours=_SESSION_TTL_HOURS)).isoformat()
        meta = metadata or {}

        payload = {
            "sid": session_id,
            "sub": user_id,
            "org": org_id,
            "iat": now.isoformat(),
            "exp": expires_at,
        }
        token = self._build_token(payload)
        token_hash = _sha256(token)

        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO sessions
                    (session_id, user_id, org_id, token_hash, metadata, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, user_id, org_id, token_hash,
                 json.dumps(meta), now.isoformat(), expires_at),
            )
        return token

    def validate_session(self, token: str) -> Optional[dict]:
        """
        Validate *token* signature + expiry + revocation status.
        Returns session data dict or None.
        """
        payload = self._parse_token(token)
        if payload is None:
            return None

        now = _now_iso()
        if payload.get("exp", "") < now:
            return None

        token_hash = _sha256(token)
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT session_id, user_id, org_id, metadata, expires_at, revoked
                FROM   sessions
                WHERE  token_hash = ?
                """,
                (token_hash,),
            ).fetchone()

        if row is None or row["revoked"]:
            return None
        if row["expires_at"] < now:
            return None

        return {
            "session_id": row["session_id"],
            "user_id": row["user_id"],
            "org_id": row["org_id"],
            "metadata": json.loads(row["metadata"]),
            "expires_at": row["expires_at"],
        }

    def revoke_session(self, token: str) -> None:
        """Mark *token*'s session as revoked."""
        token_hash = _sha256(token)
        with self._conn() as conn:
            conn.execute(
                "UPDATE sessions SET revoked = 1 WHERE token_hash = ?",
                (token_hash,),
            )

    def refresh_session(self, token: str) -> Optional[str]:
        """
        Extend an existing valid session by another 24 hours.
        Returns the new token, or None if the original is invalid/revoked.
        """
        session_data = self.validate_session(token)
        if session_data is None:
            return None

        # Revoke the old token
        self.revoke_session(token)

        # Issue a fresh token with the same user/org/metadata
        return self.create_session(
            user_id=session_data["user_id"],
            org_id=session_data["org_id"],
            metadata=session_data["metadata"],
        )
