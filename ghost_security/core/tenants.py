"""
Ghost Security Platform — Multi-Tenant SaaS Layer
Organization → Projects → Users → API Keys → Scans

Модель:
  Organization: компания (план: free/pro/enterprise)
  Project: репозиторий/продукт
  User: член организации (roles: owner/admin/member/viewer)
  APIKey: для программного доступа (CI/CD)

JWT auth + API key auth. Изоляция данных по org_id.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

_DB_PATH = Path("./data/tenants.db")
_JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_hex(32))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS organizations (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    slug        TEXT UNIQUE NOT NULL,
    plan        TEXT DEFAULT 'free',
    created_at  REAL,
    settings    TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS projects (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES organizations(id),
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL,
    repo_url    TEXT DEFAULT '',
    created_at  REAL,
    UNIQUE(org_id, slug)
);
CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES organizations(id),
    email       TEXT UNIQUE NOT NULL,
    name        TEXT DEFAULT '',
    role        TEXT DEFAULT 'member',
    password_hash TEXT NOT NULL,
    created_at  REAL,
    last_seen   REAL
);
CREATE TABLE IF NOT EXISTS api_keys (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    project_id  TEXT,
    user_id     TEXT,
    key_hash    TEXT UNIQUE NOT NULL,
    name        TEXT DEFAULT '',
    created_at  REAL,
    last_used   REAL,
    revoked     BOOLEAN DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scan_quotas (
    org_id       TEXT PRIMARY KEY,
    scans_this_month INTEGER DEFAULT 0,
    reset_at     REAL,
    plan_limit   INTEGER DEFAULT 50
);
CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);
CREATE INDEX IF NOT EXISTS idx_projects_org ON projects(org_id);
CREATE INDEX IF NOT EXISTS idx_apikeys_org ON api_keys(org_id);
"""

_PLAN_LIMITS = {
    "free":       {"scans_per_month": 50,   "projects": 1,   "users": 1},
    "pro":        {"scans_per_month": 1000,  "projects": 10,  "users": 10},
    "enterprise": {"scans_per_month": 99999, "projects": 999, "users": 999},
}

_ROLE_PERMISSIONS = {
    "owner":  {"read", "write", "admin", "billing", "delete"},
    "admin":  {"read", "write", "admin"},
    "member": {"read", "write"},
    "viewer": {"read"},
}


def _hash_password(password: str) -> str:
    import hashlib
    salt = secrets.token_hex(16)
    h    = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"{salt}:{h.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split(":", 1)
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return hmac.compare_digest(check.hex(), h)
    except Exception:
        return False


def _make_jwt(payload: dict, secret: str = _JWT_SECRET) -> str:
    import base64, json
    header  = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    body    = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig_b   = hmac.new(secret.encode(), f"{header}.{body}".encode(), "sha256").digest()
    sig     = base64.urlsafe_b64encode(sig_b).rstrip(b"=").decode()
    return f"{header}.{body}.{sig}"


def _verify_jwt(token: str, secret: str = _JWT_SECRET) -> Optional[dict]:
    try:
        import base64
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig = parts
        expected = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), f"{header}.{body}".encode(), "sha256").digest()
        ).rstrip(b"=").decode()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(body + "=="))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


@dataclass
class AuthContext:
    org_id:     str
    user_id:    str
    role:       str
    project_id: Optional[str] = None

    def can(self, permission: str) -> bool:
        return permission in _ROLE_PERMISSIONS.get(self.role, set())

    def require(self, permission: str) -> None:
        if not self.can(permission):
            raise PermissionError(f"Role '{self.role}' lacks permission '{permission}'")


class TenantManager:
    """Multi-tenant data layer."""

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

    # ── Organizations ──────────────────────────────────────────────

    def create_org(self, name: str, slug: str, plan: str = "free") -> dict:
        org_id = secrets.token_hex(8)
        with self._conn() as c:
            c.execute(
                "INSERT INTO organizations(id,name,slug,plan,created_at) VALUES(?,?,?,?,?)",
                (org_id, name, slug, plan, time.time()),
            )
            c.execute(
                "INSERT INTO scan_quotas(org_id,reset_at,plan_limit) VALUES(?,?,?)",
                (org_id, time.time() + 2592000,
                 _PLAN_LIMITS[plan]["scans_per_month"]),
            )
        return {"id": org_id, "name": name, "slug": slug, "plan": plan}

    def get_org(self, org_id: str) -> Optional[dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM organizations WHERE id=?", (org_id,)).fetchone()
        return dict(row) if row else None

    def get_org_by_slug(self, slug: str) -> Optional[dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM organizations WHERE slug=?", (slug,)).fetchone()
        return dict(row) if row else None

    # ── Users ──────────────────────────────────────────────────────

    def create_user(
        self, org_id: str, email: str, password: str,
        name: str = "", role: str = "member",
    ) -> dict:
        uid = secrets.token_hex(8)
        with self._conn() as c:
            c.execute(
                "INSERT INTO users(id,org_id,email,name,role,password_hash,created_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (uid, org_id, email, name, role, _hash_password(password), time.time()),
            )
        return {"id": uid, "org_id": org_id, "email": email, "role": role}

    def authenticate(self, email: str, password: str) -> Optional[dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not row or not _verify_password(password, row["password_hash"]):
            return None
        with self._conn() as c:
            c.execute("UPDATE users SET last_seen=? WHERE id=?", (time.time(), row["id"]))
        user = dict(row)
        user.pop("password_hash", None)
        return user

    def issue_token(self, user: dict, expires_in: int = 86400) -> str:
        return _make_jwt({
            "sub":     user["id"],
            "org":     user["org_id"],
            "role":    user["role"],
            "email":   user["email"],
            "exp":     time.time() + expires_in,
        })

    def verify_token(self, token: str) -> Optional[AuthContext]:
        payload = _verify_jwt(token)
        if not payload:
            return None
        return AuthContext(
            org_id  = payload["org"],
            user_id = payload["sub"],
            role    = payload["role"],
        )

    # ── Projects ───────────────────────────────────────────────────

    def create_project(self, org_id: str, name: str, slug: str, repo_url: str = "") -> dict:
        pid = secrets.token_hex(8)
        with self._conn() as c:
            c.execute(
                "INSERT INTO projects(id,org_id,name,slug,repo_url,created_at) VALUES(?,?,?,?,?,?)",
                (pid, org_id, name, slug, repo_url, time.time()),
            )
        return {"id": pid, "org_id": org_id, "name": name, "slug": slug}

    def list_projects(self, org_id: str) -> List[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM projects WHERE org_id=?", (org_id,)).fetchall()
        return [dict(r) for r in rows]

    # ── API Keys ───────────────────────────────────────────────────

    def create_api_key(
        self, org_id: str, name: str,
        project_id: Optional[str] = None,
        user_id:    Optional[str] = None,
    ) -> dict:
        raw_key = f"ghost_{secrets.token_urlsafe(32)}"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        kid      = secrets.token_hex(8)
        with self._conn() as c:
            c.execute(
                "INSERT INTO api_keys(id,org_id,project_id,user_id,key_hash,name,created_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (kid, org_id, project_id, user_id, key_hash, name, time.time()),
            )
        return {"id": kid, "key": raw_key, "name": name,
                "note": "Save this key — it won't be shown again"}

    def verify_api_key(self, raw_key: str) -> Optional[AuthContext]:
        if not raw_key.startswith("ghost_"):
            return None
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM api_keys WHERE key_hash=? AND revoked=0", (key_hash,)
            ).fetchone()
        if not row:
            return None
        with self._conn() as c:
            c.execute("UPDATE api_keys SET last_used=? WHERE id=?", (time.time(), row["id"]))
        # Get org role for API key (default: member)
        return AuthContext(
            org_id     = row["org_id"],
            user_id    = row["user_id"] or "",
            role       = "member",
            project_id = row["project_id"],
        )

    def revoke_api_key(self, key_id: str, org_id: str) -> bool:
        with self._conn() as c:
            n = c.execute(
                "UPDATE api_keys SET revoked=1 WHERE id=? AND org_id=?",
                (key_id, org_id),
            ).rowcount
        return n > 0

    # ── Quota ──────────────────────────────────────────────────────

    def check_quota(self, org_id: str) -> dict:
        with self._conn() as c:
            row = c.execute("SELECT * FROM scan_quotas WHERE org_id=?", (org_id,)).fetchone()
        if not row:
            return {"allowed": True, "remaining": 50}
        now = time.time()
        if now > row["reset_at"]:
            with self._conn() as c:
                c.execute(
                    "UPDATE scan_quotas SET scans_this_month=0, reset_at=? WHERE org_id=?",
                    (now + 2592000, org_id),
                )
            used = 0
        else:
            used = row["scans_this_month"]
        limit     = row["plan_limit"]
        remaining = max(0, limit - used)
        return {"allowed": remaining > 0, "used": used, "limit": limit, "remaining": remaining}

    def increment_quota(self, org_id: str) -> None:
        with self._conn() as c:
            c.execute(
                "UPDATE scan_quotas SET scans_this_month=scans_this_month+1 WHERE org_id=?",
                (org_id,),
            )

    # ── Auth middleware helper ─────────────────────────────────────

    def resolve_auth(self, authorization: str) -> Optional[AuthContext]:
        """
        Resolves auth from Authorization header.
        Supports: 'Bearer <jwt>' and 'Bearer ghost_<api_key>'
        """
        if not authorization or not authorization.startswith("Bearer "):
            return None
        token = authorization[7:].strip()
        if token.startswith("ghost_"):
            return self.verify_api_key(token)
        return self.verify_token(token)


# Singleton
TENANTS = TenantManager()
