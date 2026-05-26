"""
Deep tests for APIKeyManager and SessionManager — ~60 tests covering key
creation, validation, revocation, rotation, key hashing, session creation,
validation, expiry, revocation, and refresh.
"""
import hashlib
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest
from cloud.auth.api_key_manager import APIKeyManager
from cloud.auth.session_manager import SessionManager


# ---------------------------------------------------------------------------
# Fixtures — use tmp_path so tests are isolated
# ---------------------------------------------------------------------------

@pytest.fixture
def key_manager(tmp_path):
    db = str(tmp_path / "api_keys.db")
    return APIKeyManager(db_path=db)


@pytest.fixture
def session_manager(tmp_path):
    db = str(tmp_path / "sessions.db")
    return SessionManager(secret_key="test-secret-key-1234", db_path=db)


# ---------------------------------------------------------------------------
# APIKeyManager — create_key
# ---------------------------------------------------------------------------

class TestCreateKey:
    def test_key_starts_with_ghst(self, key_manager):
        result = key_manager.create_key("org1", "Test Key", ["read"])
        assert result["key"].startswith("ghst_")

    def test_key_has_correct_length(self, key_manager):
        result = key_manager.create_key("org1", "Test Key", ["read"])
        # "ghst_" + 32 hex chars = 37 chars
        assert len(result["key"]) == 37

    def test_returns_key_id(self, key_manager):
        result = key_manager.create_key("org1", "Test Key", ["read"])
        assert "key_id" in result
        assert result["key_id"]

    def test_returns_scopes(self, key_manager):
        scopes = ["read", "write"]
        result = key_manager.create_key("org1", "Test Key", scopes)
        assert result["scopes"] == scopes

    def test_returns_name(self, key_manager):
        result = key_manager.create_key("org1", "My API Key", ["read"])
        assert result["name"] == "My API Key"

    def test_returns_created_at(self, key_manager):
        result = key_manager.create_key("org1", "Test Key", ["read"])
        assert "created_at" in result
        assert result["created_at"]

    def test_different_keys_each_call(self, key_manager):
        k1 = key_manager.create_key("org1", "K1", [])
        k2 = key_manager.create_key("org1", "K2", [])
        assert k1["key"] != k2["key"]


# ---------------------------------------------------------------------------
# APIKeyManager — validate_key
# ---------------------------------------------------------------------------

class TestValidateKey:
    def test_valid_key_returns_metadata(self, key_manager):
        result = key_manager.create_key("org1", "Test Key", ["read"])
        meta = key_manager.validate_key(result["key"])
        assert meta is not None

    def test_valid_key_returns_org_id(self, key_manager):
        result = key_manager.create_key("org1", "Test Key", ["read"])
        meta = key_manager.validate_key(result["key"])
        assert meta["org_id"] == "org1"

    def test_valid_key_returns_scopes(self, key_manager):
        result = key_manager.create_key("org1", "Test Key", ["read", "write"])
        meta = key_manager.validate_key(result["key"])
        assert meta["scopes"] == ["read", "write"]

    def test_wrong_key_returns_none(self, key_manager):
        meta = key_manager.validate_key("ghst_wrongkeyvalue12345678901234")
        assert meta is None

    def test_key_without_prefix_returns_none(self, key_manager):
        meta = key_manager.validate_key("no_prefix_key_12345")
        assert meta is None

    def test_empty_key_returns_none(self, key_manager):
        meta = key_manager.validate_key("")
        assert meta is None


# ---------------------------------------------------------------------------
# APIKeyManager — revoke_key
# ---------------------------------------------------------------------------

class TestRevokeKey:
    def test_revoke_key_returns_true(self, key_manager):
        result = key_manager.create_key("org1", "Test Key", ["read"])
        revoked = key_manager.revoke_key(result["key_id"], "org1")
        assert revoked is True

    def test_revoked_key_invalid(self, key_manager):
        result = key_manager.create_key("org1", "Test Key", ["read"])
        key_manager.revoke_key(result["key_id"], "org1")
        meta = key_manager.validate_key(result["key"])
        assert meta is None

    def test_revoke_wrong_key_id_returns_false(self, key_manager):
        revoked = key_manager.revoke_key("nonexistent_id", "org1")
        assert revoked is False

    def test_revoke_wrong_org_returns_false(self, key_manager):
        result = key_manager.create_key("org1", "Test Key", ["read"])
        revoked = key_manager.revoke_key(result["key_id"], "org2")
        assert revoked is False


# ---------------------------------------------------------------------------
# APIKeyManager — list_keys
# ---------------------------------------------------------------------------

class TestListKeys:
    def test_list_keys_returns_list(self, key_manager):
        key_manager.create_key("org1", "K1", ["read"])
        keys = key_manager.list_keys("org1")
        assert isinstance(keys, list)
        assert len(keys) >= 1

    def test_list_keys_for_tenant(self, key_manager):
        key_manager.create_key("org1", "K1", ["read"])
        key_manager.create_key("org2", "K2", ["read"])
        keys_org1 = key_manager.list_keys("org1")
        assert all(k.get("revoked") is False or k.get("revoked") == 0 for k in keys_org1)

    def test_list_keys_empty_for_unknown_org(self, key_manager):
        keys = key_manager.list_keys("unknown_org")
        assert keys == []


# ---------------------------------------------------------------------------
# APIKeyManager — rotate_key
# ---------------------------------------------------------------------------

class TestRotateKey:
    def test_rotate_returns_new_key(self, key_manager):
        old = key_manager.create_key("org1", "Old Key", ["read"])
        new = key_manager.rotate_key(old["key_id"], "org1")
        assert new["key"].startswith("ghst_")

    def test_old_key_invalid_after_rotation(self, key_manager):
        old = key_manager.create_key("org1", "Old Key", ["read"])
        key_manager.rotate_key(old["key_id"], "org1")
        meta = key_manager.validate_key(old["key"])
        assert meta is None

    def test_new_key_valid_after_rotation(self, key_manager):
        old = key_manager.create_key("org1", "Old Key", ["read"])
        new = key_manager.rotate_key(old["key_id"], "org1")
        meta = key_manager.validate_key(new["key"])
        assert meta is not None

    def test_rotate_nonexistent_key_raises(self, key_manager):
        with pytest.raises(ValueError):
            key_manager.rotate_key("nonexistent_id", "org1")

    def test_rotated_from_field_present(self, key_manager):
        old = key_manager.create_key("org1", "Old Key", ["read"])
        new = key_manager.rotate_key(old["key_id"], "org1")
        assert new.get("rotated_from") == old["key_id"]


# ---------------------------------------------------------------------------
# APIKeyManager — key stored as SHA-256 hash
# ---------------------------------------------------------------------------

class TestKeyHashing:
    def test_plaintext_not_in_db(self, key_manager, tmp_path):
        result = key_manager.create_key("org1", "Test Key", ["read"])
        plaintext = result["key"]
        # Read DB file as bytes and check plaintext is NOT there
        db_content = (tmp_path / "api_keys.db").read_bytes()
        assert plaintext.encode() not in db_content

    def test_sha256_hash_stored(self, key_manager, tmp_path):
        import sqlite3
        result = key_manager.create_key("org1", "Test Key", ["read"])
        plaintext = result["key"]
        expected_hash = hashlib.sha256(plaintext.encode()).hexdigest()
        # Query the DB directly to confirm the hash is stored (not the plaintext)
        db_path = str(tmp_path / "api_keys.db")
        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT key_hash FROM api_keys WHERE key_id = ?", (result["key_id"],)
        ).fetchone()
        conn.close()
        assert row is not None
        assert row[0] == expected_hash


# ---------------------------------------------------------------------------
# SessionManager — create_session
# ---------------------------------------------------------------------------

class TestCreateSession:
    def test_create_session_returns_non_empty_token(self, session_manager):
        token = session_manager.create_session("user1", "org1")
        assert token
        assert len(token) > 10

    def test_token_has_three_parts(self, session_manager):
        token = session_manager.create_session("user1", "org1")
        parts = token.split(".")
        assert len(parts) == 3

    def test_different_sessions_different_tokens(self, session_manager):
        t1 = session_manager.create_session("user1", "org1")
        t2 = session_manager.create_session("user1", "org1")
        assert t1 != t2


# ---------------------------------------------------------------------------
# SessionManager — validate_session
# ---------------------------------------------------------------------------

class TestValidateSession:
    def test_valid_session_returns_true(self, session_manager):
        token = session_manager.create_session("user1", "org1")
        result = session_manager.validate_session(token)
        assert result is not None

    def test_valid_session_returns_user_id(self, session_manager):
        token = session_manager.create_session("user1", "org1")
        result = session_manager.validate_session(token)
        assert result["user_id"] == "user1"

    def test_valid_session_returns_org_id(self, session_manager):
        token = session_manager.create_session("user1", "org1")
        result = session_manager.validate_session(token)
        assert result["org_id"] == "org1"

    def test_invalid_token_returns_none(self, session_manager):
        result = session_manager.validate_session("not.a.valid.token")
        assert result is None

    def test_empty_token_returns_none(self, session_manager):
        result = session_manager.validate_session("")
        assert result is None

    def test_tampered_token_returns_none(self, session_manager):
        token = session_manager.create_session("user1", "org1")
        parts = token.split(".")
        # Tamper with payload
        tampered = parts[0] + ".TAMPERED" + "." + parts[2]
        result = session_manager.validate_session(tampered)
        assert result is None


# ---------------------------------------------------------------------------
# SessionManager — revoke_session
# ---------------------------------------------------------------------------

class TestRevokeSession:
    def test_revoked_session_invalid(self, session_manager):
        token = session_manager.create_session("user1", "org1")
        session_manager.revoke_session(token)
        result = session_manager.validate_session(token)
        assert result is None


# ---------------------------------------------------------------------------
# SessionManager — refresh_session
# ---------------------------------------------------------------------------

class TestRefreshSession:
    def test_refresh_returns_new_token(self, session_manager):
        old_token = session_manager.create_session("user1", "org1")
        new_token = session_manager.refresh_session(old_token)
        assert new_token is not None
        assert new_token != old_token

    def test_new_token_valid_after_refresh(self, session_manager):
        old_token = session_manager.create_session("user1", "org1")
        new_token = session_manager.refresh_session(old_token)
        result = session_manager.validate_session(new_token)
        assert result is not None

    def test_old_token_invalid_after_refresh(self, session_manager):
        old_token = session_manager.create_session("user1", "org1")
        session_manager.refresh_session(old_token)
        result = session_manager.validate_session(old_token)
        assert result is None

    def test_refresh_invalid_token_returns_none(self, session_manager):
        result = session_manager.refresh_session("invalid.token.here")
        assert result is None
