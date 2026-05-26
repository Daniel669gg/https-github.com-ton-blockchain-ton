-- Ghost Security Cloud — Row-Level Security (PostgreSQL only)
-- Enforces tenant isolation: each database session can only see rows
-- belonging to the organisation stored in the session-local setting
-- app.current_org_id (set by the application connection pool).
--
-- Usage from application code:
--   SET LOCAL app.current_org_id = '<org_id>';
-- ──────────────────────────────────────────────────────────────────────────────

-- ── Dedicated application role ────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ghost_app') THEN
        CREATE ROLE ghost_app LOGIN;
    END IF;
END;
$$;

-- ── scan_jobs: RLS ────────────────────────────────────────────────────────────
ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_jobs FORCE ROW LEVEL SECURITY;

-- Drop policy if it exists so this script is idempotent
DROP POLICY IF EXISTS scan_jobs_tenant_isolation ON scan_jobs;

CREATE POLICY scan_jobs_tenant_isolation ON scan_jobs
    USING (org_id = current_setting('app.current_org_id', TRUE))
    WITH CHECK (org_id = current_setting('app.current_org_id', TRUE));

-- ── usage_events: RLS ─────────────────────────────────────────────────────────
ALTER TABLE usage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS usage_events_tenant_isolation ON usage_events;

CREATE POLICY usage_events_tenant_isolation ON usage_events
    USING (org_id = current_setting('app.current_org_id', TRUE))
    WITH CHECK (org_id = current_setting('app.current_org_id', TRUE));

-- ── api_keys: RLS ─────────────────────────────────────────────────────────────
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS api_keys_tenant_isolation ON api_keys;

CREATE POLICY api_keys_tenant_isolation ON api_keys
    USING (org_id = current_setting('app.current_org_id', TRUE))
    WITH CHECK (org_id = current_setting('app.current_org_id', TRUE));

-- ── sessions: RLS ─────────────────────────────────────────────────────────────
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS sessions_tenant_isolation ON sessions;

CREATE POLICY sessions_tenant_isolation ON sessions
    USING (org_id = current_setting('app.current_org_id', TRUE))
    WITH CHECK (org_id = current_setting('app.current_org_id', TRUE));

-- ── Grants to ghost_app role ──────────────────────────────────────────────────
-- The application connects as ghost_app; superuser bypasses RLS so we
-- grant only the minimum necessary privileges here.

GRANT SELECT, INSERT, UPDATE, DELETE ON scan_jobs     TO ghost_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON usage_events  TO ghost_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON api_keys      TO ghost_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON sessions      TO ghost_app;
GRANT SELECT                          ON tenants       TO ghost_app;

-- tenants is managed by an admin role; ghost_app can read but not write
-- (tenant provisioning goes through a privileged admin path).
