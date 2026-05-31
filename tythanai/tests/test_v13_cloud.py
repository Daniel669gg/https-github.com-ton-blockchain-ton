"""Tests for v13 cloud SaaS modules."""
import sys
import pathlib
import pytest
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))


class TestAPIKeyManager:
    @pytest.fixture
    def manager(self, tmp_path):
        from cloud.auth.api_key_manager import APIKeyManager
        return APIKeyManager(db_path=str(tmp_path / "cloud.db"))

    def test_import(self, manager):
        assert manager is not None

    def test_create_key(self, manager):
        result = manager.create_key("org-123", "my-key", ["scan:read"])
        assert "key" in result
        assert result["key"].startswith("ghst_")
        assert len(result["key"]) > 10

    def test_validate_key(self, manager):
        result = manager.create_key("org-abc", "test", ["scan:read"])
        key = result["key"]
        validated = manager.validate_key(key)
        assert validated is not None
        assert validated["org_id"] == "org-abc"

    def test_invalid_key_returns_none(self, manager):
        result = manager.validate_key("ghst_fakekeythatdoesnotexist")
        assert result is None

    def test_revoke_key(self, manager):
        result = manager.create_key("org-xyz", "revoke-me", [])
        key_id = result["key_id"]
        success = manager.revoke_key(key_id, "org-xyz")
        assert success is True
        validated = manager.validate_key(result["key"])
        assert validated is None

    def test_list_keys(self, manager):
        manager.create_key("org-list", "key1", [])
        manager.create_key("org-list", "key2", [])
        keys = manager.list_keys("org-list")
        assert len(keys) >= 2

    def test_key_uniqueness(self, manager):
        r1 = manager.create_key("org-u", "k1", [])
        r2 = manager.create_key("org-u", "k2", [])
        assert r1["key"] != r2["key"]


class TestSessionManager:
    @pytest.fixture
    def sm(self, tmp_path):
        from cloud.auth.session_manager import SessionManager
        return SessionManager(db_path=str(tmp_path / "sessions.db"))

    def test_import(self, sm):
        assert sm is not None

    def test_create_session(self, sm):
        token = sm.create_session("user-1", "org-1")
        assert isinstance(token, str)
        assert len(token) > 0

    def test_validate_session(self, sm):
        token = sm.create_session("user-2", "org-2")
        data = sm.validate_session(token)
        assert data is not None
        assert data["user_id"] == "user-2"
        assert data["org_id"] == "org-2"

    def test_invalid_token_returns_none(self, sm):
        result = sm.validate_session("invalid.token.here")
        assert result is None

    def test_revoke_session(self, sm):
        token = sm.create_session("user-3", "org-3")
        sm.revoke_session(token)
        result = sm.validate_session(token)
        assert result is None


class TestTenantManager:
    @pytest.fixture
    def tm(self, tmp_path):
        from cloud.tenant.tenant_manager import TenantManager
        return TenantManager(db_path=str(tmp_path / "tenants.db"))

    def test_import(self, tm):
        assert tm is not None

    def test_create_tenant(self, tm):
        tenant = tm.create_tenant("Acme Corp", plan="free")
        assert "org_id" in tenant
        assert tenant["name"] == "Acme Corp"
        assert tenant["plan"] == "free"

    def test_get_tenant(self, tm):
        tenant = tm.create_tenant("Test Org")
        got = tm.get_tenant(tenant["org_id"])
        assert got is not None
        assert got["name"] == "Test Org"

    def test_update_tenant(self, tm):
        tenant = tm.create_tenant("Update Me")
        success = tm.update_tenant(tenant["org_id"], plan="developer")
        assert success is True
        got = tm.get_tenant(tenant["org_id"])
        assert got["plan"] == "developer"

    def test_delete_tenant(self, tm):
        tenant = tm.create_tenant("Delete Me")
        success = tm.delete_tenant(tenant["org_id"])
        assert success is True
        got = tm.get_tenant(tenant["org_id"])
        assert got is None

    def test_list_tenants(self, tm):
        tm.create_tenant("T1")
        tm.create_tenant("T2")
        tenants = tm.list_tenants()
        assert len(tenants) >= 2

    def test_check_quota_free_plan(self, tm):
        tenant = tm.create_tenant("Quota Test", plan="free")
        allowed = tm.check_quota(tenant["org_id"], "scan")
        assert isinstance(allowed, bool)


class TestUsageTracker:
    @pytest.fixture
    def tracker(self, tmp_path):
        from cloud.billing.usage_tracker import UsageTracker
        return UsageTracker(db_path=str(tmp_path / "usage.db"))

    def test_import(self, tracker):
        assert tracker is not None

    def test_record_scan(self, tracker):
        tracker.record_scan("org-1", "owasp", files_scanned=10, findings=5)

    def test_get_monthly_usage(self, tracker):
        tracker.record_scan("org-2", "ton", files_scanned=5, findings=2)
        usage = tracker.get_monthly_usage("org-2", 2026, 5)
        assert isinstance(usage, dict)
        assert "scans" in usage

    def test_record_api_call(self, tracker):
        tracker.record_api_call("org-3", "/api/scan", 200)

    def test_usage_report(self, tracker):
        tracker.record_scan("org-4", "owasp", 1, 0)
        report = tracker.get_usage_report("org-4")
        assert isinstance(report, dict)
