"""
Deep tests for CircuitBreaker — ~50 tests covering state transitions,
OPEN/HALF_OPEN/CLOSED states, failure rate, window expiry, async calls,
thread safety, and CircuitBreakerRegistry operations.
"""
import asyncio
import pathlib
import sys
import threading
import time

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest
from runtime.circuit_breaker import (
    CBState,
    CircuitBreaker,
    CircuitBreakerError,
    CircuitBreakerRegistry,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_cb(
    name="test",
    failure_threshold=0.5,
    window_seconds=60.0,
    min_calls=5,
    open_duration=300.0,
):
    return CircuitBreaker(
        name=name,
        failure_threshold=failure_threshold,
        window_seconds=window_seconds,
        min_calls=min_calls,
        open_duration=open_duration,
    )


def fail_func():
    raise IOError("simulated failure")


def ok_func():
    return "ok"


def trigger_failures(cb, count):
    for _ in range(count):
        try:
            cb.call(fail_func)
        except Exception:
            pass


def trigger_successes(cb, count):
    for _ in range(count):
        cb.call(ok_func)


# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------

class TestInitialState:
    def test_starts_closed(self):
        cb = make_cb()
        assert cb.get_state().state == CBState.CLOSED

    def test_failure_rate_zero_initially(self):
        cb = make_cb()
        assert cb.get_state().failure_rate == 0.0

    def test_total_calls_zero_initially(self):
        cb = make_cb()
        assert cb.get_state().total_calls == 0


# ---------------------------------------------------------------------------
# CLOSED → OPEN transition
# ---------------------------------------------------------------------------

class TestClosedToOpen:
    def test_opens_after_failure_threshold(self):
        cb = make_cb(failure_threshold=0.5, min_calls=5)
        # 5 failures out of 5 calls = 100% failure rate > 50%
        trigger_failures(cb, 5)
        assert cb.get_state().state == CBState.OPEN

    def test_not_open_below_min_calls(self):
        cb = make_cb(failure_threshold=0.5, min_calls=5)
        trigger_failures(cb, 3)  # Only 3 calls < min_calls=5
        assert cb.get_state().state == CBState.CLOSED

    def test_not_open_below_threshold(self):
        cb = make_cb(failure_threshold=0.5, min_calls=4)
        # 2 successes, 1 failure = 33% failure rate < 50%
        trigger_successes(cb, 2)
        trigger_failures(cb, 1)
        assert cb.get_state().state == CBState.CLOSED

    def test_opened_at_set_when_opened(self):
        cb = make_cb(failure_threshold=0.5, min_calls=5)
        trigger_failures(cb, 5)
        assert cb.get_state().opened_at > 0.0


# ---------------------------------------------------------------------------
# OPEN state behavior
# ---------------------------------------------------------------------------

class TestOpenState:
    def test_open_rejects_calls(self):
        cb = make_cb(failure_threshold=0.5, min_calls=5)
        trigger_failures(cb, 5)
        assert cb.get_state().state == CBState.OPEN
        with pytest.raises(CircuitBreakerError):
            cb.call(ok_func)

    def test_circuit_breaker_error_message_contains_name(self):
        cb = make_cb(name="my_scanner", failure_threshold=0.5, min_calls=5)
        trigger_failures(cb, 5)
        try:
            cb.call(ok_func)
        except CircuitBreakerError as e:
            assert "my_scanner" in str(e)


# ---------------------------------------------------------------------------
# HALF_OPEN state behavior
# ---------------------------------------------------------------------------

class TestHalfOpenState:
    def _force_half_open(self):
        cb = make_cb(
            failure_threshold=0.5,
            min_calls=5,
            open_duration=0.001,  # tiny duration so it transitions quickly
        )
        trigger_failures(cb, 5)
        time.sleep(0.01)  # Wait for open_duration to elapse
        return cb

    def test_half_open_allows_probe(self):
        cb = self._force_half_open()
        # call() triggers OPEN→HALF_OPEN transition internally; probe executes
        result = cb.call(ok_func)
        assert result == "ok"
        # After successful probe the circuit closes
        assert cb.get_state().state == CBState.CLOSED

    def test_half_open_to_closed_on_success(self):
        cb = self._force_half_open()
        cb.call(ok_func)
        assert cb.get_state().state == CBState.CLOSED

    def test_half_open_to_open_on_failure(self):
        cb = self._force_half_open()
        try:
            cb.call(fail_func)
        except Exception:
            pass
        assert cb.get_state().state == CBState.OPEN

    def test_half_open_rejects_second_probe(self):
        cb = self._force_half_open()
        # First probe in-flight (simulated by a pending call that doesn't complete)
        # We set probe_in_flight manually via internal state for the test
        cb._probe_in_flight = True
        with pytest.raises(CircuitBreakerError):
            cb.call(ok_func)
        cb._probe_in_flight = False


# ---------------------------------------------------------------------------
# reset()
# ---------------------------------------------------------------------------

class TestReset:
    def test_reset_returns_to_closed(self):
        cb = make_cb(failure_threshold=0.5, min_calls=5)
        trigger_failures(cb, 5)
        assert cb.get_state().state == CBState.OPEN
        cb.reset()
        assert cb.get_state().state == CBState.CLOSED

    def test_reset_clears_events(self):
        cb = make_cb(failure_threshold=0.5, min_calls=5)
        trigger_failures(cb, 5)
        cb.reset()
        assert cb.get_state().failure_rate == 0.0

    def test_reset_clears_opened_at(self):
        cb = make_cb(failure_threshold=0.5, min_calls=5)
        trigger_failures(cb, 5)
        cb.reset()
        assert cb.get_state().opened_at == 0.0


# ---------------------------------------------------------------------------
# Failure rate calculation
# ---------------------------------------------------------------------------

class TestFailureRate:
    def test_failure_rate_all_failed(self):
        cb = make_cb(min_calls=3)
        trigger_failures(cb, 3)
        # Depending on whether circuit opened, check failure rate
        stats = cb.get_state()
        assert stats.total_failures == 3

    def test_failure_rate_none_failed(self):
        cb = make_cb()
        trigger_successes(cb, 5)
        assert cb.get_state().failure_rate == 0.0

    def test_counters_update(self):
        cb = make_cb()
        cb.call(ok_func)
        trigger_failures(cb, 1)
        stats = cb.get_state()
        assert stats.total_calls >= 2
        assert stats.total_successes >= 1
        assert stats.total_failures >= 1


# ---------------------------------------------------------------------------
# Window expiry
# ---------------------------------------------------------------------------

class TestWindowExpiry:
    def test_old_events_expire(self):
        cb = make_cb(window_seconds=0.01, min_calls=5)
        trigger_failures(cb, 3)
        time.sleep(0.05)  # Let events expire
        # Force expire check via get_state()
        stats = cb.get_state()
        # After expiry failure_rate should be 0 since events are gone
        assert stats.failure_rate == 0.0


# ---------------------------------------------------------------------------
# Async call
# ---------------------------------------------------------------------------

class TestAsyncCall:
    def test_async_call_success(self):
        cb = make_cb()

        async def _good():
            return "async_ok"

        result = asyncio.run(cb.async_call(_good))
        assert result == "async_ok"

    def test_async_call_records_success(self):
        cb = make_cb()

        async def _good():
            return "ok"

        asyncio.run(cb.async_call(_good))
        assert cb.get_state().total_successes == 1

    def test_async_call_records_failure(self):
        cb = make_cb()

        async def _bad():
            raise IOError("fail")

        try:
            asyncio.run(cb.async_call(_bad))
        except Exception:
            pass
        assert cb.get_state().total_failures == 1


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

class TestThreadSafety:
    def test_concurrent_calls_no_crash(self):
        cb = make_cb(min_calls=100)
        errors = []

        def _work():
            try:
                cb.call(ok_func)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_work) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # No unexpected errors (CircuitBreakerError is okay if circuit opened)
        non_cb_errors = [e for e in errors if not isinstance(e, CircuitBreakerError)]
        assert non_cb_errors == []


# ---------------------------------------------------------------------------
# CircuitBreakerRegistry
# ---------------------------------------------------------------------------

class TestCircuitBreakerRegistry:
    def setup_method(self):
        # Use a fresh registry for each test
        self.registry = CircuitBreakerRegistry()

    def test_get_returns_circuit_breaker(self):
        cb = self.registry.get("scanner_a")
        assert isinstance(cb, CircuitBreaker)

    def test_get_same_name_returns_same_instance(self):
        cb1 = self.registry.get("scanner_b")
        cb2 = self.registry.get("scanner_b")
        assert cb1 is cb2

    def test_get_different_names_different_instances(self):
        cb1 = self.registry.get("scanner_c")
        cb2 = self.registry.get("scanner_d")
        assert cb1 is not cb2

    def test_all_states_returns_dict(self):
        self.registry.get("scanner_e")
        states = self.registry.all_states()
        assert isinstance(states, dict)
        assert "scanner_e" in states

    def test_all_states_has_expected_keys(self):
        self.registry.get("scanner_f")
        states = self.registry.all_states()
        entry = states["scanner_f"]
        for key in ("state", "failure_rate", "total_calls"):
            assert key in entry

    def test_reset_all_resets_all_breakers(self):
        cb = self.registry.get("scanner_g", min_calls=5)
        trigger_failures(cb, 5)
        assert cb.get_state().state == CBState.OPEN
        self.registry.reset_all()
        assert cb.get_state().state == CBState.CLOSED


# ---------------------------------------------------------------------------
# Additional circuit breaker behavior tests
# ---------------------------------------------------------------------------

class TestAdditionalBehavior:
    def test_consecutive_failures_tracked(self):
        cb = make_cb(min_calls=100)
        trigger_failures(cb, 3)
        assert cb.get_state().consecutive_failures == 3

    def test_success_resets_consecutive_failures(self):
        cb = make_cb(min_calls=100)
        trigger_failures(cb, 3)
        cb.call(ok_func)
        assert cb.get_state().consecutive_failures == 0

    def test_last_failure_time_recorded(self):
        cb = make_cb(min_calls=100)
        before = time.time()
        trigger_failures(cb, 1)
        after = time.time()
        lft = cb.get_state().last_failure_time
        assert before <= lft <= after

    def test_last_failure_zero_initially(self):
        cb = make_cb()
        assert cb.get_state().last_failure_time == 0.0

    def test_circuit_stays_closed_under_threshold(self):
        cb = make_cb(failure_threshold=0.6, min_calls=10)
        # 4 failures + 7 successes = 36% failure rate < 60%
        trigger_failures(cb, 4)
        trigger_successes(cb, 7)
        assert cb.get_state().state == CBState.CLOSED

    def test_total_successes_count(self):
        cb = make_cb()
        trigger_successes(cb, 5)
        assert cb.get_state().total_successes == 5

    def test_call_returns_function_result(self):
        cb = make_cb()
        result = cb.call(lambda: 42)
        assert result == 42

    def test_call_propagates_exception(self):
        cb = make_cb(min_calls=100)

        def _fail():
            raise ValueError("test error")

        with pytest.raises(ValueError, match="test error"):
            cb.call(_fail)

    def test_multiple_open_reopen_cycles(self):
        cb = make_cb(
            failure_threshold=0.5,
            min_calls=5,
            open_duration=0.001,
        )
        for _ in range(3):
            trigger_failures(cb, 5)
            assert cb.get_state().state == CBState.OPEN
            time.sleep(0.01)
            # Trigger HALF_OPEN → CLOSED
            cb.call(ok_func)
            assert cb.get_state().state == CBState.CLOSED

    def test_registry_remove(self):
        registry = CircuitBreakerRegistry()
        registry.get("to_remove")
        registry.remove("to_remove")
        states = registry.all_states()
        assert "to_remove" not in states

    def test_registry_remove_nonexistent_no_error(self):
        registry = CircuitBreakerRegistry()
        registry.remove("nonexistent")  # Should not raise

    def test_get_state_is_dataclass(self):
        cb = make_cb()
        state = cb.get_state()
        assert hasattr(state, "state")
        assert hasattr(state, "failure_rate")
        assert hasattr(state, "total_calls")

    def test_async_call_failure_opens_circuit(self):
        cb = make_cb(failure_threshold=0.5, min_calls=5)

        async def _bad():
            raise IOError("async failure")

        async def _run():
            for _ in range(5):
                try:
                    await cb.async_call(_bad)
                except Exception:
                    pass

        asyncio.run(_run())
        assert cb.get_state().state == CBState.OPEN
