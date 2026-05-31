"""
backend/telemetry/prometheus.py — Prometheus metrics for TythanAI.

Exposes metrics via /metrics endpoint (prometheus_client).
Falls back gracefully if prometheus_client is not installed.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable, Optional

logger = logging.getLogger("tythanai.prometheus")

# ─────────────────────────────────────────────────────────────────────────────
# Optional prometheus_client import
# ─────────────────────────────────────────────────────────────────────────────

try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        Summary,
        generate_latest,
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        REGISTRY,
    )
    _PROM_AVAILABLE = True
except ImportError:
    _PROM_AVAILABLE = False
    logger.info("prometheus_client not installed — metrics disabled")

    # Stub classes that silently swallow all calls
    class _Stub:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass
        def __call__(self, *a: Any, **kw: Any) -> "_Stub":
            return self
        def labels(self, **kw: Any) -> "_Stub":
            return self
        def inc(self, amount: float = 1) -> None:
            pass
        def dec(self, amount: float = 1) -> None:
            pass
        def set(self, value: float) -> None:
            pass
        def observe(self, amount: float) -> None:
            pass
        def time(self) -> Any:
            import contextlib
            return contextlib.nullcontext()

    Counter   = _Stub  # type: ignore[misc, assignment]
    Gauge     = _Stub  # type: ignore[misc, assignment]
    Histogram = _Stub  # type: ignore[misc, assignment]
    Summary   = _Stub  # type: ignore[misc, assignment]
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"

    def generate_latest() -> bytes:  # type: ignore[misc]
        return b"# prometheus_client not installed\n"


# ─────────────────────────────────────────────────────────────────────────────
# Metric definitions
# ─────────────────────────────────────────────────────────────────────────────

scans_total = Counter(
    "ghost_scans_total",
    "Total number of scans initiated",
    ["scanner", "status"],   # scanner=taint|supply_chain|git_secrets|…, status=ok|error
)

findings_by_severity = Counter(
    "ghost_findings_total",
    "Total findings emitted, labelled by severity and rule category",
    ["severity", "category"],   # severity=CRITICAL/HIGH/MEDIUM/LOW/INFO, category=taint|auth|…
)

scan_duration_seconds = Histogram(
    "ghost_scan_duration_seconds",
    "Wall-clock time for each scan phase",
    ["scanner"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0),
)

agent_iterations = Gauge(
    "ghost_agent_iterations_current",
    "Number of ReAct agent iterations in the most recent run",
)

false_positive_rate = Gauge(
    "ghost_false_positive_rate",
    "Estimated false-positive rate from the last benchmark run",
    ["module"],
)

active_scans = Gauge(
    "ghost_active_scans",
    "Number of scans currently in progress",
)

pipeline_stage_duration = Histogram(
    "ghost_pipeline_stage_duration_seconds",
    "Duration of each defensive lifecycle pipeline stage",
    ["stage"],
    buckets=(0.05, 0.1, 0.5, 1.0, 5.0, 15.0, 60.0),
)

findings_suppressed_total = Counter(
    "ghost_findings_suppressed_total",
    "Findings removed by confidence filter or suppression markers",
    ["reason"],   # reason=low_confidence|suppressed|test_file
)

rules_generated_total = Counter(
    "ghost_rules_generated_total",
    "Auto-generated Semgrep rules produced",
    ["status"],   # status=draft|stable
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

class _TimerContext:
    """Context manager that records elapsed time into a Histogram label."""

    def __init__(self, histogram: Any, label: str) -> None:
        self._histogram = histogram
        self._label = label
        self._start = 0.0

    def __enter__(self) -> "_TimerContext":
        self._start = time.monotonic()
        return self

    def __exit__(self, *_: Any) -> None:
        elapsed = time.monotonic() - self._start
        try:
            self._histogram.labels(scanner=self._label).observe(elapsed)
        except Exception:
            pass


def record_scan(scanner: str, status: str = "ok") -> None:
    """Increment scan counter for the given scanner name."""
    try:
        scans_total.labels(scanner=scanner, status=status).inc()
    except Exception:
        pass


def record_findings(findings: list, category: str = "unknown") -> None:
    """Batch-record finding counts broken down by severity."""
    from collections import Counter as _Counter
    sev_counts = _Counter(f.severity for f in findings)
    for sev, count in sev_counts.items():
        try:
            findings_by_severity.labels(
                severity=sev.upper(), category=category
            ).inc(count)
        except Exception:
            pass


def scan_timer(scanner: str) -> _TimerContext:
    """Return a context manager that times the block and records into scan_duration_seconds."""
    return _TimerContext(scan_duration_seconds, scanner)


def metrics_response() -> tuple:
    """Return (body_bytes, content_type) for the /metrics endpoint."""
    return generate_latest(), CONTENT_TYPE_LATEST
