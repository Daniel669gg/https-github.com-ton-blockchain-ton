"""
Deep tests for InferenceCache — ~40 tests covering hash_prompt, set/get,
TTL expiry, stats, evict_expired, and concurrent access.
"""
import pathlib
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest
from runtime.providers.inference_cache import InferenceCache


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def cache(tmp_path):
    db = str(tmp_path / "test_cache.db")
    return InferenceCache(db_path=db, ttl_days=7)


@pytest.fixture
def short_ttl_cache(tmp_path):
    db = str(tmp_path / "short_cache.db")
    # ttl_days=0 means ttl_seconds=0 — everything expires immediately
    return InferenceCache(db_path=db, ttl_days=0)


# ---------------------------------------------------------------------------
# hash_prompt
# ---------------------------------------------------------------------------

class TestHashPrompt:
    def test_same_model_prompt_same_hash(self):
        h1 = InferenceCache.hash_prompt("gpt-4", "hello world")
        h2 = InferenceCache.hash_prompt("gpt-4", "hello world")
        assert h1 == h2

    def test_different_model_different_hash(self):
        h1 = InferenceCache.hash_prompt("gpt-4", "hello world")
        h2 = InferenceCache.hash_prompt("gpt-3.5", "hello world")
        assert h1 != h2

    def test_different_prompt_different_hash(self):
        h1 = InferenceCache.hash_prompt("gpt-4", "hello world")
        h2 = InferenceCache.hash_prompt("gpt-4", "goodbye world")
        assert h1 != h2

    def test_hash_is_hex_string(self):
        h = InferenceCache.hash_prompt("model", "prompt")
        # SHA-256 = 64 hex chars
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_empty_prompt_has_hash(self):
        h = InferenceCache.hash_prompt("model", "")
        assert len(h) == 64

    def test_empty_model_different_from_nonempty(self):
        h1 = InferenceCache.hash_prompt("", "prompt")
        h2 = InferenceCache.hash_prompt("model", "prompt")
        assert h1 != h2


# ---------------------------------------------------------------------------
# set then get
# ---------------------------------------------------------------------------

class TestSetGet:
    def test_set_then_get_returns_same_value(self, cache):
        h = InferenceCache.hash_prompt("gpt-4", "test prompt")
        cache.set(h, "test response")
        result = cache.get(h)
        assert result == "test response"

    def test_get_missing_returns_none(self, cache):
        h = InferenceCache.hash_prompt("gpt-4", "nonexistent prompt")
        result = cache.get(h)
        assert result is None

    def test_set_overwrites_existing(self, cache):
        h = InferenceCache.hash_prompt("model", "prompt")
        cache.set(h, "first response")
        cache.set(h, "second response")
        result = cache.get(h)
        assert result == "second response"

    def test_multiple_keys_independent(self, cache):
        h1 = InferenceCache.hash_prompt("model", "prompt1")
        h2 = InferenceCache.hash_prompt("model", "prompt2")
        cache.set(h1, "response1")
        cache.set(h2, "response2")
        assert cache.get(h1) == "response1"
        assert cache.get(h2) == "response2"

    def test_large_response_stored(self, cache):
        h = InferenceCache.hash_prompt("model", "big")
        big_response = "x" * 10000
        cache.set(h, big_response)
        assert cache.get(h) == big_response


# ---------------------------------------------------------------------------
# TTL expiry
# ---------------------------------------------------------------------------

class TestTTLExpiry:
    def test_zero_ttl_expires_immediately(self, short_ttl_cache):
        h = InferenceCache.hash_prompt("model", "test")
        short_ttl_cache.set(h, "response")
        # With ttl_days=0, ttl_seconds=0, so created_at <= cutoff
        result = short_ttl_cache.get(h)
        # Either None (expired) or "response" (within same second)
        # We do a brief sleep to ensure expiry
        time.sleep(0.01)
        result = short_ttl_cache.get(h)
        assert result is None

    def test_non_expired_entry_accessible(self, cache):
        h = InferenceCache.hash_prompt("model", "valid")
        cache.set(h, "valid response")
        result = cache.get(h)
        assert result == "valid response"


# ---------------------------------------------------------------------------
# evict_expired
# ---------------------------------------------------------------------------

class TestEvictExpired:
    def test_evict_expired_removes_old_entries(self, short_ttl_cache):
        h = InferenceCache.hash_prompt("model", "old")
        short_ttl_cache.set(h, "old response")
        time.sleep(0.01)
        deleted = short_ttl_cache.evict_expired()
        assert deleted >= 1

    def test_evict_expired_returns_count(self, short_ttl_cache):
        h1 = InferenceCache.hash_prompt("model", "a")
        h2 = InferenceCache.hash_prompt("model", "b")
        short_ttl_cache.set(h1, "r1")
        short_ttl_cache.set(h2, "r2")
        time.sleep(0.01)
        deleted = short_ttl_cache.evict_expired()
        assert deleted == 2

    def test_evict_returns_zero_when_no_expired(self, cache):
        h = InferenceCache.hash_prompt("model", "fresh")
        cache.set(h, "fresh response")
        deleted = cache.evict_expired()
        assert deleted == 0


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------

class TestStats:
    def test_stats_returns_dict(self, cache):
        stats = cache.stats()
        assert isinstance(stats, dict)

    def test_stats_has_required_keys(self, cache):
        stats = cache.stats()
        for key in ("hit_rate", "total_entries"):
            assert key in stats, f"Missing key: {key}"

    def test_total_entries_increments(self, cache):
        h = InferenceCache.hash_prompt("model", "x")
        cache.set(h, "response")
        stats = cache.stats()
        assert stats["total_entries"] >= 1

    def test_hit_rate_zero_with_no_gets(self, cache):
        stats = cache.stats()
        assert stats["hit_rate"] == 0.0

    def test_hit_rate_updates_on_hit(self, cache):
        h = InferenceCache.hash_prompt("model", "cached")
        cache.set(h, "response")
        cache.get(h)  # hit
        stats = cache.stats()
        assert stats["hit_rate"] > 0.0

    def test_hit_rate_zero_on_miss(self, cache):
        h_miss = InferenceCache.hash_prompt("model", "not cached")
        cache.get(h_miss)  # miss
        stats = cache.stats()
        assert stats["hit_rate"] == 0.0


# ---------------------------------------------------------------------------
# Concurrent access
# ---------------------------------------------------------------------------

class TestConcurrentAccess:
    def test_concurrent_reads_no_crash(self, cache):
        h = InferenceCache.hash_prompt("model", "shared")
        cache.set(h, "shared response")
        errors = []

        def _read():
            try:
                for _ in range(10):
                    cache.get(h)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_read) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []

    def test_concurrent_writes_no_crash(self, cache):
        errors = []

        def _write(i):
            try:
                h = InferenceCache.hash_prompt("model", f"prompt_{i}")
                cache.set(h, f"response_{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_write, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
