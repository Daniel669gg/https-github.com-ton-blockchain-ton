"""
TythanAI Platform — Prometheus Metrics
Exposes runtime, scan, finding, and agent metrics in Prometheus text format.
Compatible with prometheus_client (optional) and plain text fallback.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional


class Counter:
    """Thread-safe monotonically increasing counter."""
    def __init__(self, name: str, help_text: str, labels: List[str] = None) -> None:
        self.name   = name
        self.help   = help_text
        self.labels = labels or []
        self._values: Dict[tuple, float] = defaultdict(float)
        self._lock  = threading.Lock()

    def inc(self, amount: float = 1.0, **label_values) -> None:
        key = tuple(label_values.get(l, "") for l in self.labels)
        with self._lock:
            self._values[key] += amount

    def get(self, **label_values) -> float:
        key = tuple(label_values.get(l, "") for l in self.labels)
        with self._lock:
            return self._values[key]

    def render(self) -> str:
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} counter"]
        with self._lock:
            items = list(self._values.items())
        for key, val in items:
            label_str = ",".join(f'{l}="{v}"' for l, v in zip(self.labels, key)) if self.labels else ""
            metric_name = f"{self.name}{'{' + label_str + '}' if label_str else ''}"
            lines.append(f"{metric_name} {val}")
        return "\n".join(lines)


class Gauge:
    """Thread-safe gauge (can go up and down)."""
    def __init__(self, name: str, help_text: str, labels: List[str] = None) -> None:
        self.name   = name
        self.help   = help_text
        self.labels = labels or []
        self._values: Dict[tuple, float] = defaultdict(float)
        self._lock  = threading.Lock()

    def set(self, value: float, **label_values) -> None:
        key = tuple(label_values.get(l, "") for l in self.labels)
        with self._lock:
            self._values[key] = value

    def inc(self, amount: float = 1.0, **label_values) -> None:
        key = tuple(label_values.get(l, "") for l in self.labels)
        with self._lock:
            self._values[key] += amount

    def dec(self, amount: float = 1.0, **label_values) -> None:
        self.inc(-amount, **label_values)

    def get(self, **label_values) -> float:
        key = tuple(label_values.get(l, "") for l in self.labels)
        with self._lock:
            return self._values.get(key, 0.0)

    def render(self) -> str:
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} gauge"]
        with self._lock:
            items = list(self._values.items())
        for key, val in items:
            label_str = ",".join(f'{l}="{v}"' for l, v in zip(self.labels, key)) if self.labels else ""
            metric_name = f"{self.name}{'{' + label_str + '}' if label_str else ''}"
            lines.append(f"{metric_name} {val}")
        return "\n".join(lines)


class Histogram:
    """Thread-safe histogram with fixed buckets."""
    DEFAULT_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

    def __init__(self, name: str, help_text: str, buckets=None) -> None:
        self.name    = name
        self.help    = help_text
        self.buckets = buckets or self.DEFAULT_BUCKETS
        self._counts = defaultdict(int)   # bucket_le → count
        self._sum    = 0.0
        self._total  = 0
        self._lock   = threading.Lock()

    def observe(self, value: float) -> None:
        with self._lock:
            self._sum   += value
            self._total += 1
            for b in self.buckets:
                if value <= b:
                    self._counts[b] += 1

    def render(self) -> str:
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} histogram"]
        with self._lock:
            for b in self.buckets:
                lines.append(f'{self.name}_bucket{{le="{b}"}} {self._counts[b]}')
            lines.append(f'{self.name}_bucket{{le="+Inf"}} {self._total}')
            lines.append(f"{self.name}_sum {self._sum}")
            lines.append(f"{self.name}_count {self._total}")
        return "\n".join(lines)


class MetricsRegistry:
    """Central registry for all TythanAI metrics."""

    def __init__(self) -> None:
        self._metrics: List[Any] = []

        # ── Runtime metrics ──────────────────────────────────────────────────
        self.tasks_submitted   = self._reg(Counter("ghost_tasks_submitted_total",   "Total tasks submitted to supervisor"))
        self.tasks_succeeded   = self._reg(Counter("ghost_tasks_succeeded_total",   "Total tasks succeeded"))
        self.tasks_failed      = self._reg(Counter("ghost_tasks_failed_total",      "Total tasks permanently failed"))
        self.tasks_retried     = self._reg(Counter("ghost_tasks_retried_total",     "Total task retry attempts"))
        self.tasks_active      = self._reg(Gauge  ("ghost_tasks_active",            "Currently running tasks"))
        self.queue_depth       = self._reg(Gauge  ("ghost_queue_depth",             "Tasks in supervisor queue"))
        self.task_duration     = self._reg(Histogram("ghost_task_duration_seconds", "Task execution duration"))

        # ── Scan metrics ─────────────────────────────────────────────────────
        self.scans_started     = self._reg(Counter("ghost_scans_started_total",     "Total scans started",  ["scanner"]))
        self.scans_completed   = self._reg(Counter("ghost_scans_completed_total",   "Total scans completed",["scanner"]))
        self.scans_failed      = self._reg(Counter("ghost_scans_failed_total",      "Total scans failed",   ["scanner"]))
        self.scan_duration     = self._reg(Histogram("ghost_scan_duration_seconds", "Scan wall-clock time"))
        self.findings_total    = self._reg(Counter("ghost_findings_total",          "Total findings emitted", ["severity", "scanner"]))
        self.findings_active   = self._reg(Gauge  ("ghost_findings_active",         "Non-FP findings after triage"))

        # ── Agent metrics ────────────────────────────────────────────────────
        self.agent_calls       = self._reg(Counter("ghost_agent_calls_total",       "Agent invocations",  ["agent"]))
        self.agent_errors      = self._reg(Counter("ghost_agent_errors_total",      "Agent errors",       ["agent"]))
        self.agent_latency     = self._reg(Histogram("ghost_agent_latency_seconds", "Agent call latency"))

        # ── LLM metrics ──────────────────────────────────────────────────────
        self.llm_calls         = self._reg(Counter("ghost_llm_calls_total",         "LLM inference calls",  ["model", "backend"]))
        self.llm_errors        = self._reg(Counter("ghost_llm_errors_total",        "LLM inference errors", ["backend"]))
        self.llm_latency       = self._reg(Histogram("ghost_llm_latency_seconds",   "LLM inference latency"))

        # ── Health metrics ───────────────────────────────────────────────────
        self.service_up        = self._reg(Gauge  ("ghost_service_up",              "Service health (1=up)", ["service"]))
        self.api_requests      = self._reg(Counter("ghost_api_requests_total",      "API HTTP requests",    ["method", "path", "status"]))
        self.api_latency       = self._reg(Histogram("ghost_api_latency_seconds",   "API response latency"))

        # Meta
        self._start_time       = time.time()

    def _reg(self, m):
        self._metrics.append(m)
        return m

    def render_text(self) -> str:
        """Render all metrics in Prometheus text exposition format."""
        parts = []
        for m in self._metrics:
            parts.append(m.render())
        # uptime gauge
        uptime = time.time() - self._start_time
        parts.append(f"# HELP ghost_uptime_seconds Platform uptime\n# TYPE ghost_uptime_seconds gauge\nghost_uptime_seconds {uptime:.2f}")
        return "\n\n".join(parts) + "\n"

    def snapshot(self) -> dict:
        """Return a dict snapshot for /api/health or dashboard."""
        return {
            "tasks_submitted":  self.tasks_submitted.get(),
            "tasks_succeeded":  self.tasks_succeeded.get(),
            "tasks_failed":     self.tasks_failed.get(),
            "tasks_active":     self.tasks_active.get(),
            "queue_depth":      self.queue_depth.get(),
            "scans_started":    self.scans_started.get(),
            "scans_completed":  self.scans_completed.get(),
            "findings_active":  self.findings_active.get(),
            "llm_calls":        self.llm_calls.get(),
            "uptime_seconds":   round(time.time() - self._start_time, 1),
        }


# ── Module-level singleton ─────────────────────────────────────────────────────
METRICS = MetricsRegistry()
