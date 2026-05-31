"""
TythanAI — Retry Policy with Exponential Back-off + Jitter

Provides both async (execute) and sync (execute_sync) variants.

Retries on transient errors:  IOError, TimeoutError, ConnectionError
Does NOT retry on code bugs:  ValueError, TypeError, AttributeError
"""
from __future__ import annotations

import asyncio
import functools
import logging
import random
import time
from typing import Any, Callable, Optional, Set, Tuple, Type

log = logging.getLogger("ghost.retry_policy")

# ─── Error classification ──────────────────────────────────────────────────────

#: Exceptions that indicate a transient infrastructure problem → worth retrying.
RETRYABLE: Tuple[Type[Exception], ...] = (
    IOError,
    TimeoutError,
    ConnectionError,
    ConnectionRefusedError,
    ConnectionResetError,
    ConnectionAbortedError,
    BrokenPipeError,
    OSError,
    asyncio.TimeoutError,
)

#: Exceptions that indicate a programming error → never retry.
NON_RETRYABLE: Tuple[Type[Exception], ...] = (
    ValueError,
    TypeError,
    AttributeError,
    NameError,
    NotImplementedError,
    PermissionError,
    KeyboardInterrupt,
    SystemExit,
)


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, NON_RETRYABLE):
        return False
    return isinstance(exc, RETRYABLE)


# ─── RetryPolicy ─────────────────────────────────────────────────────────────


class RetryExhausted(Exception):
    """Raised when all retry attempts are exhausted."""

    def __init__(self, attempts: int, last_exc: BaseException) -> None:
        self.attempts = attempts
        self.last_exc = last_exc
        super().__init__(
            f"All {attempts} retry attempt(s) exhausted. "
            f"Last error: {type(last_exc).__name__}: {last_exc}"
        )


class RetryPolicy:
    """
    Configurable retry policy with exponential back-off and optional jitter.

    Parameters
    ----------
    max_retries:  Maximum number of *re*tries (total attempts = max_retries + 1).
    base_delay:   Initial delay in seconds before first retry.
    max_delay:    Cap on computed delay.
    jitter:       If True, add uniform random jitter in [0, base_delay).
    retryable:    Override which exception types trigger a retry.
    """

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        jitter: bool = True,
        retryable: Optional[Tuple[Type[Exception], ...]] = None,
    ) -> None:
        if max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if base_delay <= 0:
            raise ValueError("base_delay must be > 0")
        if max_delay < base_delay:
            raise ValueError("max_delay must be >= base_delay")

        self.max_retries = max_retries
        self.base_delay  = base_delay
        self.max_delay   = max_delay
        self.jitter      = jitter
        self._retryable  = retryable or RETRYABLE

    # ── Async execute ──────────────────────────────────────────────────────────

    async def execute(
        self,
        func: Callable,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """
        Call *func* (async or sync) with retry logic.

        If *func* is a coroutine function it is awaited; otherwise it is called
        synchronously inside the event loop (blocking — use execute_sync for
        CPU-heavy sync work).
        """
        last_exc: Optional[BaseException] = None

        for attempt in range(self.max_retries + 1):
            try:
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)

            except BaseException as exc:
                last_exc = exc

                if isinstance(exc, NON_RETRYABLE):
                    log.debug(
                        "RetryPolicy: non-retryable %s — aborting immediately.",
                        type(exc).__name__,
                    )
                    raise

                if not isinstance(exc, self._retryable):
                    log.debug(
                        "RetryPolicy: %s not in retryable set — aborting.",
                        type(exc).__name__,
                    )
                    raise

                if attempt >= self.max_retries:
                    break

                delay = self._compute_delay(attempt)
                log.warning(
                    "RetryPolicy: attempt %d/%d failed (%s: %s). "
                    "Retrying in %.2fs.",
                    attempt + 1, self.max_retries + 1,
                    type(exc).__name__, exc, delay,
                )
                await asyncio.sleep(delay)

        assert last_exc is not None
        raise RetryExhausted(attempts=self.max_retries + 1, last_exc=last_exc)

    # ── Sync execute ───────────────────────────────────────────────────────────

    def execute_sync(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """
        Synchronous version.  Blocks the calling thread between retries.
        """
        last_exc: Optional[BaseException] = None

        for attempt in range(self.max_retries + 1):
            try:
                return func(*args, **kwargs)

            except BaseException as exc:
                last_exc = exc

                if isinstance(exc, NON_RETRYABLE):
                    raise

                if not isinstance(exc, self._retryable):
                    raise

                if attempt >= self.max_retries:
                    break

                delay = self._compute_delay(attempt)
                log.warning(
                    "RetryPolicy(sync): attempt %d/%d failed (%s: %s). "
                    "Retrying in %.2fs.",
                    attempt + 1, self.max_retries + 1,
                    type(exc).__name__, exc, delay,
                )
                time.sleep(delay)

        assert last_exc is not None
        raise RetryExhausted(attempts=self.max_retries + 1, last_exc=last_exc)

    # ── Decorator ─────────────────────────────────────────────────────────────

    def __call__(self, func: Callable) -> Callable:
        """Use RetryPolicy as a decorator on sync or async functions."""
        if asyncio.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                return await self.execute(func, *args, **kwargs)
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                return self.execute_sync(func, *args, **kwargs)
            return sync_wrapper

    # ── Internal ───────────────────────────────────────────────────────────────

    def _compute_delay(self, attempt: int) -> float:
        """Exponential back-off: base * 2^attempt, capped at max_delay."""
        delay = min(self.base_delay * (2.0 ** attempt), self.max_delay)
        if self.jitter:
            delay += random.uniform(0, self.base_delay)
        return delay


# ─── Convenience factory ──────────────────────────────────────────────────────

def default_retry(*, max_retries: int = 3) -> RetryPolicy:
    """Return a RetryPolicy with sensible defaults for Ghost scanners."""
    return RetryPolicy(
        max_retries=max_retries,
        base_delay=1.0,
        max_delay=60.0,
        jitter=True,
    )
