-- Ghost Security Cloud — Initial Schema
-- Compatible with PostgreSQL and SQLite.
-- Run once on a fresh database.
-- ──────────────────────────────────────────────────────────────────────────────

-- ── tenants ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenants (
    org_id        TEXT        PRIMARY KEY,
    name          TEXT        NOT NULL,
    plan          TEXT        NOT NULL DEFAULT 'free',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),  -- PostgreSQL; SQLite uses CURRENT_TIMESTAMP
    settings_json TEXT        NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_tenants_plan ON tenants(plan);

-- ── api_keys ──────────────────────────────────────────────────────────────────
-- Plaintext keys are NEVER stored; only the SHA-256 hash is persisted.
CREATE TABLE IF NOT EXISTS api_keys (
    key_id      TEXT        PRIMARY KEY,
    org_id      TEXT        NOT NULL REFERENCES tenants(org_id) ON DELETE CASCADE,
    key_hash    TEXT        NOT NULL UNIQUE,
    name        TEXT        NOT NULL,
    scopes_json TEXT        NOT NULL DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ,
    revoked     BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_api_keys_org     ON api_keys(org_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash    ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_revoked ON api_keys(revoked) WHERE NOT revoked;

-- ── sessions ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT        PRIMARY KEY,
    user_id    TEXT        NOT NULL,
    org_id     TEXT        NOT NULL REFERENCES tenants(org_id) ON DELETE CASCADE,
    token_hash TEXT        NOT NULL UNIQUE,
    metadata   TEXT        NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked    BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_org     ON sessions(org_id);
CREATE INDEX IF NOT EXISTS idx_sessions_hash    ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry  ON sessions(expires_at);

-- ── usage_events ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS usage_events (
    event_id      TEXT        PRIMARY KEY,
    org_id        TEXT        NOT NULL REFERENCES tenants(org_id) ON DELETE CASCADE,
    event_type    TEXT        NOT NULL,              -- 'scan' | 'api_call' | ...
    metadata_json TEXT        NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_usage_org_type ON usage_events(org_id, event_type);
CREATE INDEX IF NOT EXISTS idx_usage_created  ON usage_events(created_at);

-- ── scan_jobs ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id       TEXT        PRIMARY KEY,
    org_id       TEXT        NOT NULL REFERENCES tenants(org_id) ON DELETE CASCADE,
    status       TEXT        NOT NULL DEFAULT 'pending',  -- pending|running|completed|failed
    priority     INTEGER     NOT NULL DEFAULT 5,
    path         TEXT        NOT NULL,
    scanner      TEXT        NOT NULL,
    options_json TEXT        NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at   TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    worker_id    TEXT,
    result_json  TEXT
);

CREATE INDEX IF NOT EXISTS idx_jobs_status_pri ON scan_jobs(status, priority, created_at);
CREATE INDEX IF NOT EXISTS idx_jobs_org        ON scan_jobs(org_id);
CREATE INDEX IF NOT EXISTS idx_jobs_worker     ON scan_jobs(worker_id) WHERE worker_id IS NOT NULL;
