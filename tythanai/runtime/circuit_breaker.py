"""
TythanAI — Circuit Breaker
Implements the circuit breaker pattern per scanner to prevent cascading
failures and enable self-healing through automatic state transitions.

States:
  CLOSED    → Normal operation.  Failures are counted.
  OPEN      → All calls fail fast.  After cool-down enters HALF_OPEN.
  HALF_OPEN → One probe call allowed.  Success → CLOSED; failure → OPEN.
"""
from __future__ import annotations

import asyncio
import collections
import logging
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Deque, Dict, Optional, Tuple

log = logging.getLogger("ghost.circuit_breaker")


class CBState(str, Enum):
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"


@dataclass
class _Event:
    ts: float
    success: bool


@dataclass
class CircuitBreakerStats:
    state: CBState
    failure_rate: float        # 0.0 – 1.0 over the last window
    total_calls: int
    total_failures: int
    total_successes: int
    consecutive_failures: int
    last_failure_time: float   # epoch seconds, 0.0 if never
    opened_at: float           # epoch seconds, 0.0 if not open


class CircuitBreakerError(Exception):
    """Raised when a call is rejected because the circuit is open."""


class CircuitBreaker:
    """
    Thread-safe circuit breaker for a named resource.

    Parameters
    ----------
    name:              Identifier (e.g. scanner name).
    failure_threshold: Failure rate (0-1) above which the circuit opens.
    window_seconds:    Rolling window for failure-rate calculation.
    min_calls:         Minimum calls in window before rate is evaluated.
    open_duration:     Seconds to stay OPEN before trying HALF_OPEN.
    """

    def __init__(
        self,
        name: str,
        failure_threshold: float = 0.5,
        window_seconds: float = 60.0,
        min_calls: int = 5,
        open_duration: float = 300.0,   # 5 minutes
    ) -> None:
        self.name               = name
        self._threshold         = failure_threshold
        self._window            = window_seconds
        self._min_calls         = min_calls
        self._open_duration     = open_duration

        self._state             = CBState.CLOSED
        self._events: Deque[_Event] = collections.deque()
        self._lock              = threading.Lock()
        self._opened_at: float  = 0.0
        self._total_calls: int  = 0
        self._total_failures: int = 0
        self._total_successes: int = 0
        self._consecutive_fails: int = 0
        self._last_failure: float    = 0.0
        # In HALF_OPEN we allow only one probe at a time
        self._probe_in_flight: bool  = False

    # ── Public API ─────────────────────────────────────────────────────────────

    def call(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """Execute *func* through the circuit breaker (sync version)."""
        self._before_call()
        try:
            result = func(*args, **kwargs)
            self._record_success()
            return result
        except Exception:
            self._record_failure()
            raise

    async def async_call(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """Execute an async *func* through the circuit breaker."""
        self._before_call()
        try:
            result = await func(*args, **kwargs)
            self._record_success()
            return result
        except Exception:
            self._record_failure()
            raise

    def get_state(self) -> CircuitBreakerStats:
        with self._lock:
            self._expire_events()
            rate = self._failure_rate()
            return CircuitBreakerStats(
                state=self._state,
                failure_rate=rate,
                total_calls=self._total_calls,
                total_failures=self._total_failures,
                total_successes=self._total_successes,
                consecutive_failures=self._consecutive_fails,
                last_failure_time=self._last_failure,
                opened_at=self._opened_at,
            )

    def reset(self) -> None:
        """Manually reset to CLOSED state (for testing / admin override)."""
        with self._lock:
            self._state = CBState.CLOSED
            self._events.clear()
            self._opened_at = 0.0
            self._consecutive_fails = 0
            self._probe_in_flight = False
        log.info("CircuitBreaker[%s] manually reset to CLOSED", self.name)

    # ── State machine ──────────────────────────────────────────────────────────

    def _before_call(self) -> None:
        with self._lock:
            self._maybe_transition()
            if self._state == CBState.OPEN:
                raise CircuitBreakerError(
                    f"Circuit breaker '{self.name}' is OPEN — calls rejected."
                )
            if self._state == CBState.HALF_OPEN:
                if self._probe_in_flight:
                    raise CircuitBreakerError(
                        f"Circuit breaker '{self.name}' is HALF_OPEN — probe already in flight."
                    )
                self._probe_in_flight = True
            self._total_calls += 1

    def _record_success(self) -> None:
        with self._lock:
            now = time.time()
            self._events.append(_Event(now, True))
            self._total_successes += 1
            self._consecutive_fails = 0
            if self._state == CBState.HALF_OPEN:
                self._probe_in_flight = False
                self._transition(CBState.CLOSED)

    def _record_failure(self) -> None:
        with self._lock:
            now = time.time()
            self._events.append(_Event(now, False))
            self._total_failures += 1
            self._consecutive_fails += 1
            self._last_failure = now
            if self._state == CBState.HALF_OPEN:
                self._probe_in_flight = False
                self._transition(CBState.OPEN)
            elif self._state == CBState.CLOSED:
                self._expire_events()
                if (
                    len(self._events) >= self._min_calls
                    and self._failure_rate() > self._threshold
                ):
                    self._transition(CBState.OPEN)

    def _maybe_transition(self) -> None:
        """Check whether OPEN → HALF_OPEN transition is due."""
        if (
            self._state == CBState.OPEN
            and time.time() - self._opened_at >= self._open_duration
        ):
            self._transition(CBState.HALF_OPEN)

    def _transition(self, new_state: CBState) -> None:
        old = self._state
        self._state = new_state
        if new_state == CBState.OPEN:
            self._opened_at = time.time()
            self._events.clear()
        elif new_state == CBState.CLOSED:
            self._opened_at = 0.0
            self._events.clear()
            self._consecutive_fails = 0
        log.info(
            "CircuitBreaker[%s] %s → %s  (failures=%d)",
            self.name, old, new_state, self._consecutive_fails,
        )

    def _expire_events(self) -> None:
        cutoff = time.time() - self._window
        while self._events and self._events[0].ts < cutoff:
            self._events.popleft()

    def _failure_rate(self) -> float:
        if not self._events:
            return 0.0
        failures = sum(1 for e in self._events if not e.success)
        return failures / len(self._events)


# ─── Registry ─────────────────────────────────────────────────────────────────


class CircuitBreakerRegistry:
    """
    Singleton registry managing per-scanner circuit breakers.

    Usage::

        registry = CircuitBreakerRegistry.instance()
        cb = registry.get("semgrep_scanner")
        result = cb.call(some_function, arg1)
    """

    _instance: Optional[CircuitBreakerRegistry] = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self) -> None:
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._rlock = threading.Lock()

    @classmethod
    def instance(cls) -> CircuitBreakerRegistry:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def get(
        self,
        name: str,
        failure_threshold: float = 0.5,
        window_seconds: float = 60.0,
        min_calls: int = 5,
        open_duration: float = 300.0,
    ) -> CircuitBreaker:
        """Return (creating if necessary) a circuit breaker for *name*."""
        with self._rlock:
            if name not in self._breakers:
                self._breakers[name] = CircuitBreaker(
                    name=name,
                    failure_threshold=failure_threshold,
                    window_seconds=window_seconds,
                    min_calls=min_calls,
                    open_duration=open_duration,
                )
            return self._breakers[name]

    def all_states(self) -> Dict[str, dict]:
        """Return a dict of {name: state_dict} for every managed breaker."""
        with self._rlock:
            return {
                name: {
                    "state": cb.get_state().state,
                    "failure_rate": round(cb.get_state().failure_rate, 3),
                    "total_calls": cb.get_state().total_calls,
                    "consecutive_failures": cb.get_state().consecutive_failures,
                }
                for name, cb in self._breakers.items()
            }

    def reset_all(self) -> None:
        with self._rlock:
            for cb in self._breakers.values():
                cb.reset()

    def remove(self, name: str) -> None:
        with self._rlock:
            self._breakers.pop(name, None)
