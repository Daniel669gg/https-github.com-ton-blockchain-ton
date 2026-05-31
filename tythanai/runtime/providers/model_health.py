"""
TythanAI Platform v13 — Model Health Monitor
Tracks per-provider LLM call success/failure and latency using an in-memory
circular buffer (last 100 calls per provider).  No external dependencies.
"""
from __future__ import annotations

import collections
import logging
import threading
import time
from typing import Deque, NamedTuple

logger = logging.getLogger(__name__)

_BUFFER_SIZE = 100          # calls per provider to retain
_MIN_HEALTHY_RATE = 0.80    # success rate below which a provider is unhealthy


class _CallRecord(NamedTuple):
    success: bool
    latency_ms: float
    ts: float  # epoch seconds


class _ProviderStats:
    """Circular buffer of the last N call records for one provider."""

    def __init__(self, max_size: int = _BUFFER_SIZE) -> None:
        self._buf: Deque[_CallRecord] = collections.deque(maxlen=max_size)
        self._lock = threading.Lock()

    def record(self, success: bool, latency_ms: float) -> None:
        with self._lock:
            self._buf.append(_CallRecord(success=success, latency_ms=latency_ms, ts=time.time()))

    def snapshot(self) -> list[_CallRecord]:
        with self._lock:
            return list(self._buf)


class ModelHealthMonitor:
    """
    Thread-safe monitor for multiple LLM providers.

    Usage::

        monitor = ModelHealthMonitor()
        monitor.record_call("ollama", success=True, latency_ms=342.5)
        print(monitor.is_healthy("ollama"))        # True
        print(monitor.get_best_provider(["ollama", "openai"]))
        print(monitor.get_stats())
    """

    def __init__(self) -> None:
        self._providers: dict[str, _ProviderStats] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _ensure(self, provider: str) -> _ProviderStats:
        with self._lock:
            if provider not in self._providers:
                self._providers[provider] = _ProviderStats()
            return self._providers[provider]

    def _compute_stats(self, records: list[_CallRecord]) -> dict:
        """Compute aggregate stats from a list of records."""
        if not records:
            return {
                "total_calls": 0,
                "success_rate": 0.0,
                "avg_latency_ms": 0.0,
            }
        total = len(records)
        successes = sum(1 for r in records if r.success)
        avg_latency = sum(r.latency_ms for r in records) / total
        return {
            "total_calls": total,
            "success_rate": round(successes / total, 4),
            "avg_latency_ms": round(avg_latency, 2),
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_call(self, provider: str, success: bool, latency_ms: float) -> None:
        """
        Record a single LLM call outcome.

        Args:
            provider:   Provider name, e.g. ``"ollama"`` or ``"openai"``.
            success:    Whether the call completed successfully.
            latency_ms: Wall-clock latency of the call in milliseconds.
        """
        self._ensure(provider).record(success=success, latency_ms=latency_ms)
        logger.debug(
            "Health recorded: provider=%s success=%s latency=%.1fms",
            provider,
            success,
            latency_ms,
        )

    def is_healthy(self, provider: str) -> bool:
        """
        Return True if the provider's success rate over the last 100 calls
        exceeds 80 %.  A provider with zero recorded calls is considered
        *optimistically healthy* (True).
        """
        stats = self._ensure(provider)
        records = stats.snapshot()
        if not records:
            return True  # no data → assume healthy
        computed = self._compute_stats(records)
        return computed["success_rate"] >= _MIN_HEALTHY_RATE

    def get_best_provider(self, providers: list) -> str:
        """
        Return the healthiest provider from *providers*.

        Selection criteria (in order):
        1.  Healthy providers (success rate ≥ 80 %) are preferred over unhealthy.
        2.  Among equals, the one with the lowest average latency wins.
        3.  If no providers are given, raises ``ValueError``.

        Unknown providers (no call history) are treated as fully healthy with
        latency 0, making them the first choice (optimistic onboarding).
        """
        if not providers:
            raise ValueError("providers list must not be empty")

        def _sort_key(p: str) -> tuple:
            records = self._ensure(p).snapshot()
            stats = self._compute_stats(records)
            is_healthy = 1 if stats["success_rate"] >= _MIN_HEALTHY_RATE else 0
            # Sort: healthy first (desc), then lowest latency (asc)
            return (-is_healthy, stats["avg_latency_ms"])

        return sorted(providers, key=_sort_key)[0]

    def get_stats(self) -> dict:
        """
        Return per-provider stats dict:

        .. code-block:: python

            {
                "ollama": {
                    "total_calls": 47,
                    "success_rate": 0.9574,
                    "avg_latency_ms": 312.4,
                },
                ...
            }
        """
        with self._lock:
            provider_names = list(self._providers.keys())

        result = {}
        for name in provider_names:
            stats = self._providers[name]
            result[name] = self._compute_stats(stats.snapshot())
        return result
