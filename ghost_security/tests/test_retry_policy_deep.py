"""
Deep tests for RetryPolicy — ~50 tests covering max_retries=0, exponential
backoff, jitter, max_delay cap, retryable/non-retryable exceptions,
RetryExhausted, async execute, and success-on-first/second call.
"""
import asyncio
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest
from runtime.retry_policy import RetryExhausted, RetryPolicy, RETRYABLE, NON_RETRYABLE


# ---------------------------------------------------------------------------
# max_retries=0 — no retry
# ---------------------------------------------------------------------------

class TestMaxRetriesZero:
    def test_no_retry_on_zero(self):
        call_count = [0]

        def _fail():
            call_count[0] += 1
            raise IOError("fail")

        policy = RetryPolicy(max_retries=0, base_delay=0.001, jitter=False)
        with pytest.raises(RetryExhausted):
            policy.execute_sync(_fail)
        assert call_count[0] == 1

    def test_success_on_first_call_no_retry(self):
        call_count = [0]

        def _ok():
            call_count[0] += 1
            return "done"

        policy = RetryPolicy(max_retries=0, base_delay=0.001, jitter=False)
        result = policy.execute_sync(_ok)
        assert result == "done"
        assert call_count[0] == 1


# ---------------------------------------------------------------------------
# Exponential backoff
# ---------------------------------------------------------------------------

class TestExponentialBackoff:
    def test_delays_double_each_retry(self):
        policy = RetryPolicy(max_retries=0, base_delay=0.001, jitter=False)
        # attempt 0 → delay = 0.001 * 2^0 = 0.001
        assert policy._compute_delay(0) == 0.001
        # attempt 1 → delay = 0.001 * 2^1 = 0.002
        assert policy._compute_delay(1) == 0.002
        # attempt 2 → delay = 0.001 * 2^2 = 0.004
        assert policy._compute_delay(2) == 0.004

    def test_base_delay_used_for_first_retry(self):
        policy = RetryPolicy(max_retries=3, base_delay=0.005, jitter=False)
        assert policy._compute_delay(0) == 0.005

    def test_delay_without_jitter_is_deterministic(self):
        policy = RetryPolicy(max_retries=3, base_delay=0.01, jitter=False)
        d1 = policy._compute_delay(0)
        d2 = policy._compute_delay(0)
        assert d1 == d2


# ---------------------------------------------------------------------------
# Jitter
# ---------------------------------------------------------------------------

class TestJitter:
    def test_jitter_adds_randomness(self):
        policy = RetryPolicy(max_retries=3, base_delay=0.001, jitter=True)
        delays = [policy._compute_delay(0) for _ in range(20)]
        # With jitter, not all delays should be identical
        assert len(set(delays)) > 1

    def test_jitter_delay_at_least_base(self):
        policy = RetryPolicy(max_retries=3, base_delay=0.001, jitter=True)
        for _ in range(10):
            d = policy._compute_delay(0)
            assert d >= 0.001  # base delay minimum


# ---------------------------------------------------------------------------
# max_delay cap
# ---------------------------------------------------------------------------

class TestMaxDelayCap:
    def test_delay_capped_at_max_delay(self):
        policy = RetryPolicy(
            max_retries=10, base_delay=0.001, max_delay=0.01, jitter=False
        )
        # At attempt 10, 0.001 * 2^10 = 1.024, but max is 0.01
        d = policy._compute_delay(10)
        assert d <= 0.01

    def test_max_delay_not_exceeded_with_jitter(self):
        policy = RetryPolicy(
            max_retries=10, base_delay=0.001, max_delay=0.02, jitter=True
        )
        for _ in range(20):
            d = policy._compute_delay(10)
            # jitter adds up to base_delay, so max is max_delay + base_delay
            assert d <= 0.02 + 0.001 + 0.001  # small tolerance


# ---------------------------------------------------------------------------
# Retries on transient errors
# ---------------------------------------------------------------------------

class TestRetryableErrors:
    def test_retries_on_ioerror(self):
        call_count = [0]

        def _fail():
            call_count[0] += 1
            raise IOError("io")

        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        with pytest.raises(RetryExhausted):
            policy.execute_sync(_fail)
        assert call_count[0] == 3  # 1 initial + 2 retries

    def test_retries_on_timeout_error(self):
        call_count = [0]

        def _fail():
            call_count[0] += 1
            raise TimeoutError("timeout")

        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        with pytest.raises(RetryExhausted):
            policy.execute_sync(_fail)
        assert call_count[0] == 3

    def test_retries_on_connection_error(self):
        call_count = [0]

        def _fail():
            call_count[0] += 1
            raise ConnectionError("conn")

        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        with pytest.raises(RetryExhausted):
            policy.execute_sync(_fail)
        assert call_count[0] == 3

    def test_retries_on_oserror(self):
        call_count = [0]

        def _fail():
            call_count[0] += 1
            raise OSError("os")

        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        with pytest.raises(RetryExhausted):
            policy.execute_sync(_fail)
        assert call_count[0] == 3


# ---------------------------------------------------------------------------
# No retry on non-retryable errors
# ---------------------------------------------------------------------------

class TestNonRetryableErrors:
    def test_no_retry_on_value_error(self):
        call_count = [0]

        def _fail():
            call_count[0] += 1
            raise ValueError("bad value")

        policy = RetryPolicy(max_retries=3, base_delay=0.001, jitter=False)
        with pytest.raises(ValueError):
            policy.execute_sync(_fail)
        assert call_count[0] == 1

    def test_no_retry_on_type_error(self):
        call_count = [0]

        def _fail():
            call_count[0] += 1
            raise TypeError("bad type")

        policy = RetryPolicy(max_retries=3, base_delay=0.001, jitter=False)
        with pytest.raises(TypeError):
            policy.execute_sync(_fail)
        assert call_count[0] == 1

    def test_no_retry_on_attribute_error(self):
        call_count = [0]

        def _fail():
            call_count[0] += 1
            raise AttributeError("bad attr")

        policy = RetryPolicy(max_retries=3, base_delay=0.001, jitter=False)
        with pytest.raises(AttributeError):
            policy.execute_sync(_fail)
        assert call_count[0] == 1

    def test_no_retry_on_permission_error(self):
        call_count = [0]

        def _fail():
            call_count[0] += 1
            raise PermissionError("no perm")

        policy = RetryPolicy(max_retries=3, base_delay=0.001, jitter=False)
        with pytest.raises(PermissionError):
            policy.execute_sync(_fail)
        assert call_count[0] == 1


# ---------------------------------------------------------------------------
# RetryExhausted
# ---------------------------------------------------------------------------

class TestRetryExhausted:
    def test_retry_exhausted_raised_after_max_retries(self):
        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)

        def _fail():
            raise IOError("io")

        with pytest.raises(RetryExhausted):
            policy.execute_sync(_fail)

    def test_retry_exhausted_has_attempts(self):
        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)

        def _fail():
            raise IOError("io")

        try:
            policy.execute_sync(_fail)
        except RetryExhausted as e:
            assert e.attempts == 3

    def test_retry_exhausted_has_last_exc(self):
        policy = RetryPolicy(max_retries=1, base_delay=0.001, jitter=False)

        def _fail():
            raise IOError("specific message")

        try:
            policy.execute_sync(_fail)
        except RetryExhausted as e:
            assert isinstance(e.last_exc, IOError)


# ---------------------------------------------------------------------------
# Async execute
# ---------------------------------------------------------------------------

class TestAsyncExecute:
    def test_async_success_first_call(self):
        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        call_count = [0]

        async def _good():
            call_count[0] += 1
            return "async_ok"

        result = asyncio.run(policy.execute(_good))
        assert result == "async_ok"
        assert call_count[0] == 1

    def test_async_retries_on_ioerror(self):
        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        call_count = [0]

        async def _fail():
            call_count[0] += 1
            raise IOError("async io")

        with pytest.raises(RetryExhausted):
            asyncio.run(policy.execute(_fail))
        assert call_count[0] == 3

    def test_async_no_retry_on_value_error(self):
        policy = RetryPolicy(max_retries=3, base_delay=0.001, jitter=False)
        call_count = [0]

        async def _fail():
            call_count[0] += 1
            raise ValueError("bad")

        with pytest.raises(ValueError):
            asyncio.run(policy.execute(_fail))
        assert call_count[0] == 1


# ---------------------------------------------------------------------------
# Success on second call
# ---------------------------------------------------------------------------

class TestSuccessOnRetry:
    def test_success_on_second_call(self):
        call_count = [0]

        def _sometimes_fail():
            call_count[0] += 1
            if call_count[0] < 2:
                raise IOError("first attempt fails")
            return "recovered"

        policy = RetryPolicy(max_retries=3, base_delay=0.001, jitter=False)
        result = policy.execute_sync(_sometimes_fail)
        assert result == "recovered"
        assert call_count[0] == 2

    def test_no_retry_on_success(self):
        call_count = [0]

        def _ok():
            call_count[0] += 1
            return "done"

        policy = RetryPolicy(max_retries=3, base_delay=0.001, jitter=False)
        policy.execute_sync(_ok)
        assert call_count[0] == 1


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class TestValidation:
    def test_negative_max_retries_raises(self):
        with pytest.raises(ValueError):
            RetryPolicy(max_retries=-1, base_delay=0.001)

    def test_zero_base_delay_raises(self):
        with pytest.raises(ValueError):
            RetryPolicy(max_retries=1, base_delay=0.0)

    def test_max_delay_less_than_base_raises(self):
        with pytest.raises(ValueError):
            RetryPolicy(max_retries=1, base_delay=1.0, max_delay=0.5)


# ---------------------------------------------------------------------------
# Additional retry tests
# ---------------------------------------------------------------------------

class TestAdditionalRetryBehavior:
    def test_retry_exhausted_message_contains_attempts(self):
        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)

        def _fail():
            raise IOError("fail")

        try:
            policy.execute_sync(_fail)
        except RetryExhausted as e:
            assert "3" in str(e)

    def test_brokenPipeError_is_retryable(self):
        call_count = [0]

        def _fail():
            call_count[0] += 1
            raise BrokenPipeError("pipe")

        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)
        with pytest.raises(RetryExhausted):
            policy.execute_sync(_fail)
        assert call_count[0] == 3

    def test_connection_refused_is_retryable(self):
        call_count = [0]

        def _fail():
            call_count[0] += 1
            raise ConnectionRefusedError("refused")

        policy = RetryPolicy(max_retries=1, base_delay=0.001, jitter=False)
        with pytest.raises(RetryExhausted):
            policy.execute_sync(_fail)
        assert call_count[0] == 2

    def test_name_error_not_retried(self):
        call_count = [0]

        def _fail():
            call_count[0] += 1
            raise NameError("undefined")

        policy = RetryPolicy(max_retries=3, base_delay=0.001, jitter=False)
        with pytest.raises(NameError):
            policy.execute_sync(_fail)
        assert call_count[0] == 1

    def test_not_implemented_error_not_retried(self):
        call_count = [0]

        def _fail():
            call_count[0] += 1
            raise NotImplementedError("not impl")

        policy = RetryPolicy(max_retries=3, base_delay=0.001, jitter=False)
        with pytest.raises(NotImplementedError):
            policy.execute_sync(_fail)
        assert call_count[0] == 1

    def test_custom_retryable_exceptions(self):
        call_count = [0]

        def _fail():
            call_count[0] += 1
            raise RuntimeError("custom")

        policy = RetryPolicy(
            max_retries=2,
            base_delay=0.001,
            jitter=False,
            retryable=(RuntimeError,),
        )
        with pytest.raises(RetryExhausted):
            policy.execute_sync(_fail)
        assert call_count[0] == 3

    def test_decorator_sync_function(self):
        call_count = [0]
        policy = RetryPolicy(max_retries=2, base_delay=0.001, jitter=False)

        @policy
        def _sometimes_fail():
            call_count[0] += 1
            if call_count[0] < 2:
                raise IOError("first")
            return "ok"

        result = _sometimes_fail()
        assert result == "ok"
        assert call_count[0] == 2

    def test_max_retries_one(self):
        call_count = [0]

        def _fail():
            call_count[0] += 1
            raise IOError("fail")

        policy = RetryPolicy(max_retries=1, base_delay=0.001, jitter=False)
        with pytest.raises(RetryExhausted):
            policy.execute_sync(_fail)
        assert call_count[0] == 2  # 1 initial + 1 retry

    def test_jitter_stays_non_negative(self):
        policy = RetryPolicy(max_retries=3, base_delay=0.001, jitter=True)
        for attempt in range(5):
            d = policy._compute_delay(attempt)
            assert d >= 0.0

    def test_async_success_on_second_attempt(self):
        call_count = [0]
        policy = RetryPolicy(max_retries=3, base_delay=0.001, jitter=False)

        async def _sometimes_fail():
            call_count[0] += 1
            if call_count[0] < 2:
                raise IOError("first")
            return "recovered"

        result = asyncio.run(policy.execute(_sometimes_fail))
        assert result == "recovered"
        assert call_count[0] == 2

    def test_sync_func_via_async_execute(self):
        policy = RetryPolicy(max_retries=1, base_delay=0.001, jitter=False)
        call_count = [0]

        def _sync_ok():
            call_count[0] += 1
            return "sync"

        result = asyncio.run(policy.execute(_sync_ok))
        assert result == "sync"
        assert call_count[0] == 1
