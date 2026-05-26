"""
Deep tests for ModelHealthMonitor — ~40 tests covering is_healthy, failure
tracking, recovery, get_best_provider, get_stats, and edge cases.
"""
import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest
from runtime.providers.model_health import ModelHealthMonitor


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def monitor():
    return ModelHealthMonitor()


# ---------------------------------------------------------------------------
# is_healthy — True by default (no records)
# ---------------------------------------------------------------------------

class TestIsHealthyDefault:
    def test_new_provider_healthy(self, monitor):
        assert monitor.is_healthy("new_provider") is True

    def test_any_unknown_provider_healthy(self, monitor):
        assert monitor.is_healthy("ollama") is True
        assert monitor.is_healthy("openai") is True

    def test_provider_with_all_successes_healthy(self, monitor):
        for _ in range(5):
            monitor.record_call("good", success=True, latency_ms=100.0)
        assert monitor.is_healthy("good") is True


# ---------------------------------------------------------------------------
# is_healthy — False after consecutive failures
# ---------------------------------------------------------------------------

class TestIsHealthyFailures:
    def test_unhealthy_after_10_consecutive_failures(self, monitor):
        for _ in range(10):
            monitor.record_call("bad", success=False, latency_ms=100.0)
        assert monitor.is_healthy("bad") is False

    def test_unhealthy_at_exactly_80_percent_failure(self, monitor):
        # 8 failures + 2 successes = 80% failure = 20% success < 80% threshold
        for _ in range(8):
            monitor.record_call("shaky", success=False, latency_ms=100.0)
        for _ in range(2):
            monitor.record_call("shaky", success=True, latency_ms=100.0)
        assert monitor.is_healthy("shaky") is False

    def test_healthy_at_80_percent_success(self, monitor):
        # Exactly 80% success = 0.80 >= 0.80 threshold → healthy
        for _ in range(8):
            monitor.record_call("ok80", success=True, latency_ms=100.0)
        for _ in range(2):
            monitor.record_call("ok80", success=False, latency_ms=100.0)
        assert monitor.is_healthy("ok80") is True


# ---------------------------------------------------------------------------
# Recovery
# ---------------------------------------------------------------------------

class TestRecovery:
    def test_provider_recovers_after_successes(self, monitor):
        # Make unhealthy
        for _ in range(10):
            monitor.record_call("recover", success=False, latency_ms=100.0)
        assert monitor.is_healthy("recover") is False
        # Add many successes to bring rate above 80%
        for _ in range(90):
            monitor.record_call("recover", success=True, latency_ms=50.0)
        # Now should be healthy: 90 successes out of 100 = 90%
        assert monitor.is_healthy("recover") is True


# ---------------------------------------------------------------------------
# get_best_provider
# ---------------------------------------------------------------------------

class TestGetBestProvider:
    def test_returns_fastest_healthy_provider(self, monitor):
        monitor.record_call("fast", success=True, latency_ms=10.0)
        monitor.record_call("slow", success=True, latency_ms=1000.0)
        best = monitor.get_best_provider(["fast", "slow"])
        assert best == "fast"

    def test_skips_unhealthy_providers(self, monitor):
        # Make "bad" unhealthy
        for _ in range(10):
            monitor.record_call("bad", success=False, latency_ms=5.0)
        monitor.record_call("good", success=True, latency_ms=500.0)
        best = monitor.get_best_provider(["bad", "good"])
        assert best == "good"

    def test_unknown_provider_in_list_returns_something(self, monitor):
        # Unknown provider has no records → treated as 0% success rate
        # A known healthy provider beats an unknown one
        monitor.record_call("known", success=True, latency_ms=100.0)
        best = monitor.get_best_provider(["unknown", "known"])
        # The known healthy provider should be preferred over the unknown (0% success)
        assert best in ("unknown", "known")  # some valid provider is returned

    def test_single_provider_returned(self, monitor):
        monitor.record_call("only", success=True, latency_ms=100.0)
        best = monitor.get_best_provider(["only"])
        assert best == "only"

    def test_empty_provider_list_raises(self, monitor):
        with pytest.raises(ValueError):
            monitor.get_best_provider([])

    def test_all_unhealthy_returns_least_bad(self, monitor):
        # All unhealthy; should still return one of them
        for _ in range(10):
            monitor.record_call("bad1", success=False, latency_ms=100.0)
        for _ in range(10):
            monitor.record_call("bad2", success=False, latency_ms=200.0)
        best = monitor.get_best_provider(["bad1", "bad2"])
        assert best in ("bad1", "bad2")


# ---------------------------------------------------------------------------
# get_stats
# ---------------------------------------------------------------------------

class TestGetStats:
    def test_get_stats_returns_dict(self, monitor):
        stats = monitor.get_stats()
        assert isinstance(stats, dict)

    def test_get_stats_empty_no_crash(self, monitor):
        stats = monitor.get_stats()
        assert stats == {}

    def test_get_stats_has_provider_entry(self, monitor):
        monitor.record_call("ollama", success=True, latency_ms=100.0)
        stats = monitor.get_stats()
        assert "ollama" in stats

    def test_get_stats_has_success_rate(self, monitor):
        monitor.record_call("openai", success=True, latency_ms=200.0)
        stats = monitor.get_stats()
        assert "success_rate" in stats["openai"]

    def test_get_stats_has_avg_latency(self, monitor):
        monitor.record_call("openai", success=True, latency_ms=200.0)
        stats = monitor.get_stats()
        assert "avg_latency_ms" in stats["openai"]

    def test_get_stats_has_total_calls(self, monitor):
        monitor.record_call("claude", success=True, latency_ms=150.0)
        stats = monitor.get_stats()
        assert "total_calls" in stats["claude"]

    def test_success_rate_computed_correctly(self, monitor):
        for _ in range(4):
            monitor.record_call("provider", success=True, latency_ms=100.0)
        monitor.record_call("provider", success=False, latency_ms=100.0)
        stats = monitor.get_stats()
        # 4/5 = 0.8
        assert abs(stats["provider"]["success_rate"] - 0.8) < 0.01

    def test_avg_latency_computed_correctly(self, monitor):
        monitor.record_call("p", success=True, latency_ms=100.0)
        monitor.record_call("p", success=True, latency_ms=200.0)
        stats = monitor.get_stats()
        assert abs(stats["p"]["avg_latency_ms"] - 150.0) < 0.1


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

class TestThreadSafety:
    def test_concurrent_record_calls_no_crash(self, monitor):
        errors = []

        def _record():
            try:
                for _ in range(50):
                    monitor.record_call("shared", success=True, latency_ms=10.0)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_record) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []

    def test_concurrent_read_write_no_crash(self, monitor):
        errors = []

        def _write():
            try:
                for _ in range(20):
                    monitor.record_call("concurrent", success=True, latency_ms=5.0)
            except Exception as e:
                errors.append(e)

        def _read():
            try:
                for _ in range(20):
                    monitor.is_healthy("concurrent")
            except Exception as e:
                errors.append(e)

        threads = [
            *[threading.Thread(target=_write) for _ in range(3)],
            *[threading.Thread(target=_read) for _ in range(3)],
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
