"""
TythanAI Platform v13 — Prometheus Metrics (text-format, no client library)
Implements counters, gauges, and histograms in the Prometheus text exposition format.
No prometheus_client required — the format is rendered manually.
"""
from __future__ import annotations

import threading
import time
import logging
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Default histogram buckets (seconds)
_DEFAULT_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]


# ---------------------------------------------------------------------------
# Internal metric primitives
# ---------------------------------------------------------------------------


def _label_str(labels: Optional[dict]) -> str:
    """Render a labels dict as a Prometheus label set string, e.g. '{a="x",b="y"}'."""
    if not labels:
        return ""
    parts = [f'{k}="{v}"' for k, v in sorted(labels.items())]
    return "{" + ",".join(parts) + "}"


def _label_key(labels: Optional[dict]) -> tuple:
    if not labels:
        return ()
    return tuple(sorted(labels.items()))


class _Counter:
    def __init__(self, name: str, help_text: str) -> None:
        self.name = name
        self.help_text = help_text
        self._values: Dict[tuple, float] = defaultdict(float)
        self._lock = threading.Lock()

    def increment(self, labels: Optional[dict], value: float = 1.0) -> None:
        key = _label_key(labels)
        with self._lock:
            self._values[key] += value

    def render(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} counter",
        ]
        with self._lock:
            for key, val in self._values.items():
                ldict = dict(key) if key else None
                lines.append(f"{self.name}{_label_str(ldict)} {val}")
        return "\n".join(lines)


class _Gauge:
    def __init__(self, name: str, help_text: str) -> None:
        self.name = name
        self.help_text = help_text
        self._values: Dict[tuple, float] = {}
        self._lock = threading.Lock()

    def set(self, labels: Optional[dict], value: float) -> None:
        key = _label_key(labels)
        with self._lock:
            self._values[key] = value

    def render(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} gauge",
        ]
        with self._lock:
            for key, val in self._values.items():
                ldict = dict(key) if key else None
                lines.append(f"{self.name}{_label_str(ldict)} {val}")
        return "\n".join(lines)


class _Histogram:
    def __init__(
        self,
        name: str,
        help_text: str,
        buckets: Optional[List[float]] = None,
    ) -> None:
        self.name = name
        self.help_text = help_text
        self.buckets = sorted(buckets or _DEFAULT_BUCKETS)
        # Per label-set: { "count": int, "sum": float, buckets: [int,...] }
        self._data: Dict[tuple, dict] = {}
        self._lock = threading.Lock()

    def observe(self, labels: Optional[dict], value: float) -> None:
        key = _label_key(labels)
        with self._lock:
            if key not in self._data:
                self._data[key] = {
                    "count": 0,
                    "sum": 0.0,
                    "buckets": [0] * len(self.buckets),
                }
            entry = self._data[key]
            entry["count"] += 1
            entry["sum"] += value
            for i, bound in enumerate(self.buckets):
                if value <= bound:
                    entry["buckets"][i] += 1

    def render(self) -> str:
        lines = [
            f"# HELP {self.name} {self.help_text}",
            f"# TYPE {self.name} histogram",
        ]
        with self._lock:
            for key, entry in self._data.items():
                ldict = dict(key) if key else {}
                # entry["buckets"][i] already stores the cumulative count
                # (observe increments all bounds >= value), so output directly.
                for i, bound in enumerate(self.buckets):
                    bucket_labels = dict(ldict)
                    bucket_labels["le"] = str(bound)
                    lines.append(
                        f"{self.name}_bucket{_label_str(bucket_labels)} {entry['buckets'][i]}"
                    )
                # +Inf bucket = total count of all observations
                inf_labels = dict(ldict)
                inf_labels["le"] = "+Inf"
                lines.append(
                    f"{self.name}_bucket{_label_str(inf_labels)} {entry['count']}"
                )
                lines.append(
                    f"{self.name}_sum{_label_str(ldict if ldict else None)} {entry['sum']}"
                )
                lines.append(
                    f"{self.name}_count{_label_str(ldict if ldict else None)} {entry['count']}"
                )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class _Registry:
    """Holds all registered metrics and renders them."""

    def __init__(self) -> None:
        self._metrics: Dict[str, object] = {}
        self._lock = threading.Lock()

    def register(self, metric: object) -> None:
        with self._lock:
            self._metrics[metric.name] = metric  # type: ignore[attr-defined]

    def get_or_none(self, name: str) -> Optional[object]:
        with self._lock:
            return self._metrics.get(name)

    def render_all(self) -> str:
        with self._lock:
            metrics = list(self._metrics.values())
        parts = []
        for m in metrics:
            parts.append(m.render())  # type: ignore[attr-defined]
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# PrometheusMetrics — main public class
# ---------------------------------------------------------------------------


class PrometheusMetrics:
    """
    Manual Prometheus text-format metrics for TythanAI v13.

    Pre-defined metrics follow the Ghost platform naming convention.
    Additional ad-hoc metrics can be created via ``increment()``, ``gauge()``,
    and ``histogram()`` on any name.

    All operations are thread-safe.
    """

    def __init__(self) -> None:
        self._registry = _Registry()
        self._start_ts = time.time()
        self._lock = threading.Lock()

        # ── Pre-defined metrics ─────────────────────────────────────────
        self._define_counter(
            "ghost_scans_total",
            "Total number of security scans",
        )
        self._define_histogram(
            "ghost_scan_duration_seconds",
            "Duration of security scans in seconds",
        )
        self._define_counter(
            "ghost_findings_total",
            "Total security findings by severity and rule",
        )
        self._define_counter(
            "ghost_llm_calls_total",
            "Total LLM provider calls",
        )
        self._define_counter(
            "ghost_llm_tokens_total",
            "Total LLM tokens processed",
        )
        self._define_gauge(
            "ghost_queue_depth",
            "Current depth of processing queues",
        )
        self._define_gauge(
            "ghost_worker_active",
            "Number of active workers per pool",
        )
        self._define_counter(
            "ghost_errors_total",
            "Total errors by component and type",
        )

    # ------------------------------------------------------------------
    # Internal factory helpers
    # ------------------------------------------------------------------

    def _define_counter(self, name: str, help_text: str) -> _Counter:
        c = _Counter(name, help_text)
        self._registry.register(c)
        return c

    def _define_gauge(self, name: str, help_text: str) -> _Gauge:
        g = _Gauge(name, help_text)
        self._registry.register(g)
        return g

    def _define_histogram(
        self,
        name: str,
        help_text: str,
        buckets: Optional[List[float]] = None,
    ) -> _Histogram:
        h = _Histogram(name, help_text, buckets)
        self._registry.register(h)
        return h

    def _get_or_create_counter(self, name: str) -> _Counter:
        existing = self._registry.get_or_none(name)
        if existing is not None:
            if not isinstance(existing, _Counter):
                raise TypeError(f"Metric {name!r} is not a counter")
            return existing
        return self._define_counter(name, f"Auto-created counter {name}")

    def _get_or_create_gauge(self, name: str) -> _Gauge:
        existing = self._registry.get_or_none(name)
        if existing is not None:
            if not isinstance(existing, _Gauge):
                raise TypeError(f"Metric {name!r} is not a gauge")
            return existing
        return self._define_gauge(name, f"Auto-created gauge {name}")

    def _get_or_create_histogram(
        self, name: str, buckets: Optional[List[float]] = None
    ) -> _Histogram:
        existing = self._registry.get_or_none(name)
        if existing is not None:
            if not isinstance(existing, _Histogram):
                raise TypeError(f"Metric {name!r} is not a histogram")
            return existing
        return self._define_histogram(name, f"Auto-created histogram {name}", buckets)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def increment(
        self,
        name: str,
        labels: Optional[dict] = None,
        value: float = 1.0,
    ) -> None:
        """Increment a counter by *value* (default 1.0)."""
        self._get_or_create_counter(name).increment(labels, value)

    def gauge(
        self,
        name: str,
        value: float,
        labels: Optional[dict] = None,
    ) -> None:
        """Set a gauge to *value*."""
        self._get_or_create_gauge(name).set(labels, value)

    def histogram(
        self,
        name: str,
        value: float,
        labels: Optional[dict] = None,
        buckets: Optional[List[float]] = None,
    ) -> None:
        """Record an observation in a histogram."""
        self._get_or_create_histogram(name, buckets).observe(labels, value)

    def render(self) -> str:
        """
        Render all metrics in Prometheus text exposition format.
        Suitable for serving on a ``/metrics`` HTTP endpoint.
        """
        header = (
            f"# TythanAI Platform v13 — Metrics\n"
            f"# Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
            f"ghost_uptime_seconds {time.time() - self._start_ts:.3f}\n"
        )
        return header + self._registry.render_all()
