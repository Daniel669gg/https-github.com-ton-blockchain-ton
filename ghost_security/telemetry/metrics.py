"""
Ghost Security Platform — Telemetry Stack
Prometheus метрики + OpenTelemetry трейсы + Grafana dashboard.

Метрики:
  ghost_scans_total          — счётчик сканов
  ghost_findings_total       — счётчик находок по severity
  ghost_scan_duration_seconds — гистограмма времени сканирования
  ghost_api_requests_total   — счётчик API запросов
  ghost_llm_calls_total      — счётчик LLM вызовов по провайдеру
  ghost_llm_cost_usd_total   — суммарная стоимость LLM
  ghost_memory_entries       — размер векторной памяти

Использование:
  from telemetry.metrics import METRICS
  METRICS.scan_started("all", "/path/to/target")
  METRICS.finding_recorded("CRITICAL", "TON", "ton_analyzer")
  METRICS.scan_finished("all", 12.5, 42)
"""
from __future__ import annotations

import time
import threading
from contextlib import contextmanager
from typing import Callable, Dict, Optional


# ══════════════════════════════════════════════════════════════════════════════
# PROMETHEUS METRICS
# ══════════════════════════════════════════════════════════════════════════════

class _Counter:
    """Thread-safe counter."""
    def __init__(self, name: str, help: str, labels: list = None):
        self.name   = name
        self.help   = help
        self.labels = labels or []
        self._values: Dict[tuple, float] = {}
        self._lock  = threading.Lock()

    def inc(self, amount: float = 1.0, **label_vals) -> None:
        key = tuple(label_vals.get(l, "") for l in self.labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def collect(self) -> str:
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} counter"]
        with self._lock:
            for key, val in self._values.items():
                label_str = ",".join(
                    f'{l}="{v}"' for l, v in zip(self.labels, key)
                )
                suffix = f"{{{label_str}}}" if label_str else ""
                lines.append(f"{self.name}{suffix} {val}")
        return "\n".join(lines)


class _Histogram:
    """Thread-safe histogram with fixed buckets."""
    _BUCKETS = [0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, float("inf")]

    def __init__(self, name: str, help: str, labels: list = None):
        self.name   = name
        self.help   = help
        self.labels = labels or []
        self._data: Dict[tuple, dict] = {}
        self._lock  = threading.Lock()

    def observe(self, value: float, **label_vals) -> None:
        key = tuple(label_vals.get(l, "") for l in self.labels)
        with self._lock:
            if key not in self._data:
                self._data[key] = {"count": 0, "sum": 0.0,
                                   "buckets": {b: 0 for b in self._BUCKETS}}
            d = self._data[key]
            d["count"] += 1
            d["sum"]   += value
            for b in self._BUCKETS:
                if value <= b:
                    d["buckets"][b] += 1

    def collect(self) -> str:
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} histogram"]
        with self._lock:
            for key, d in self._data.items():
                label_str = ",".join(f'{l}="{v}"' for l, v in zip(self.labels, key))
                pfx = f"{{{label_str}}}" if label_str else ""
                for b, cnt in d["buckets"].items():
                    le = "+Inf" if b == float("inf") else str(b)
                    lines.append(f'{self.name}_bucket{{{label_str + "," if label_str else ""}le="{le}"}} {cnt}')
                lines.append(f"{self.name}_sum{pfx} {d['sum']}")
                lines.append(f"{self.name}_count{pfx} {d['count']}")
        return "\n".join(lines)


class _Gauge:
    """Thread-safe gauge."""
    def __init__(self, name: str, help: str, labels: list = None):
        self.name   = name
        self.help   = help
        self.labels = labels or []
        self._values: Dict[tuple, float] = {}
        self._lock   = threading.Lock()

    def set(self, value: float, **label_vals) -> None:
        key = tuple(label_vals.get(l, "") for l in self.labels)
        with self._lock:
            self._values[key] = value

    def inc(self, amount: float = 1.0, **label_vals) -> None:
        key = tuple(label_vals.get(l, "") for l in self.labels)
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def collect(self) -> str:
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} gauge"]
        with self._lock:
            for key, val in self._values.items():
                label_str = ",".join(f'{l}="{v}"' for l, v in zip(self.labels, key))
                suffix = f"{{{label_str}}}" if label_str else ""
                lines.append(f"{self.name}{suffix} {val}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# METRICS REGISTRY
# ══════════════════════════════════════════════════════════════════════════════

class MetricsRegistry:
    """Ghost Security Prometheus метрики."""

    def __init__(self) -> None:
        # Scan metrics
        self.scans_total = _Counter(
            "ghost_scans_total",
            "Total number of security scans",
            labels=["mode", "status"],
        )
        self.scan_duration = _Histogram(
            "ghost_scan_duration_seconds",
            "Time spent on security scans",
            labels=["mode"],
        )
        self.findings_total = _Counter(
            "ghost_findings_total",
            "Total findings by severity and scanner",
            labels=["severity", "category", "scanner"],
        )

        # API metrics
        self.api_requests = _Counter(
            "ghost_api_requests_total",
            "Total API requests",
            labels=["method", "endpoint", "status"],
        )
        self.api_latency = _Histogram(
            "ghost_api_latency_seconds",
            "API request latency",
            labels=["endpoint"],
        )

        # LLM metrics
        self.llm_calls = _Counter(
            "ghost_llm_calls_total",
            "Total LLM provider calls",
            labels=["provider", "model", "task", "status"],
        )
        self.llm_cost = _Counter(
            "ghost_llm_cost_usd_total",
            "Total LLM cost in USD",
            labels=["provider"],
        )
        self.llm_latency = _Histogram(
            "ghost_llm_latency_seconds",
            "LLM call latency",
            labels=["provider", "task"],
        )

        # Memory metrics
        self.memory_entries = _Gauge(
            "ghost_memory_entries_total",
            "Entries in vector memory",
            labels=["collection", "backend"],
        )
        self.memory_searches = _Counter(
            "ghost_memory_searches_total",
            "Vector memory searches",
            labels=["collection"],
        )

        # Runtime metrics
        self.supervisor_tasks = _Gauge(
            "ghost_supervisor_tasks",
            "Active supervisor tasks by state",
            labels=["state"],
        )

        self._all = [
            self.scans_total, self.scan_duration, self.findings_total,
            self.api_requests, self.api_latency,
            self.llm_calls, self.llm_cost, self.llm_latency,
            self.memory_entries, self.memory_searches,
            self.supervisor_tasks,
        ]
        self._start_time = time.time()

    # ── Helper methods ────────────────────────────────────────────────────────

    def scan_started(self, mode: str, target: str = "") -> float:
        """Call at scan start. Returns start timestamp."""
        self.scans_total.inc(mode=mode, status="started")
        return time.time()

    def scan_finished(self, mode: str, duration_s: float, findings_count: int, status: str = "success") -> None:
        self.scans_total.inc(mode=mode, status=status)
        self.scan_duration.observe(duration_s, mode=mode)

    def finding_recorded(self, severity: str, category: str, scanner: str) -> None:
        self.findings_total.inc(severity=severity, category=category, scanner=scanner)

    def findings_batch(self, findings: list) -> None:
        for f in findings:
            self.finding_recorded(
                f.get("severity", "MEDIUM"),
                f.get("category", "unknown"),
                f.get("source", f.get("scanner", "unknown")),
            )

    def llm_call(self, provider: str, model: str, task: str,
                 latency_ms: int, cost_usd: float, ok: bool) -> None:
        self.llm_calls.inc(provider=provider, model=model, task=task,
                           status="ok" if ok else "error")
        self.llm_latency.observe(latency_ms / 1000, provider=provider, task=task)
        if cost_usd > 0:
            self.llm_cost.inc(cost_usd, provider=provider)

    def api_call(self, method: str, endpoint: str, status: int, latency_s: float) -> None:
        self.api_requests.inc(method=method, endpoint=endpoint, status=str(status))
        self.api_latency.observe(latency_s, endpoint=endpoint)

    @contextmanager
    def time_scan(self, mode: str):
        """Context manager для измерения скана."""
        t0 = time.time()
        try:
            yield
        finally:
            self.scan_duration.observe(time.time() - t0, mode=mode)

    # ── Prometheus export ─────────────────────────────────────────────────────

    def export(self) -> str:
        """Генерирует Prometheus-compatible /metrics текст."""
        parts = [
            f"# Ghost Security Platform Metrics",
            f"# Generated at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
            "",
            f"ghost_uptime_seconds {time.time() - self._start_time:.1f}",
            "",
        ]
        for metric in self._all:
            parts.append(metric.collect())
            parts.append("")
        return "\n".join(parts)


# ══════════════════════════════════════════════════════════════════════════════
# OPENTELEMETRY TRACING
# ══════════════════════════════════════════════════════════════════════════════

class OTelTracer:
    """
    OpenTelemetry трейсинг.
    Если opentelemetry установлен — использует его.
    Fallback — lightweight JSONL трейс в файл.
    """

    def __init__(self, service_name: str = "ghost-security") -> None:
        self._service = service_name
        self._otel    = False
        self._spans:  list = []
        self._lock    = threading.Lock()
        self._trace_file = "./data/traces.jsonl"
        self._init_otel()

    def _init_otel(self) -> None:
        try:
            from opentelemetry import trace
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import (
                BatchSpanProcessor, ConsoleSpanExporter
            )
            import os
            provider = TracerProvider()
            endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
            if endpoint:
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
                provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
            else:
                provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer(self._service)
            self._otel = True
        except ImportError:
            self._otel = False

    @contextmanager
    def span(self, name: str, attributes: dict = None):
        """Context manager for a trace span."""
        if self._otel:
            from opentelemetry import trace
            with self._tracer.start_as_current_span(name) as s:
                if attributes:
                    for k, v in attributes.items():
                        s.set_attribute(k, str(v))
                yield s
        else:
            # Lightweight fallback
            t0 = time.time()
            span_id = {"id": None, "name": name, "attrs": attributes or {}}
            yield span_id
            record = {
                "trace_id":   id(span_id),
                "span":       name,
                "service":    self._service,
                "start":      t0,
                "duration_ms": int((time.time() - t0) * 1000),
                "attributes": attributes or {},
            }
            with self._lock:
                self._spans.append(record)
            # Flush to file periodically
            if len(self._spans) % 10 == 0:
                self._flush()

    def _flush(self) -> None:
        import os, json
        os.makedirs(os.path.dirname(self._trace_file), exist_ok=True)
        with open(self._trace_file, "a") as f:
            with self._lock:
                for s in self._spans:
                    f.write(json.dumps(s) + "\n")
                self._spans.clear()

    def recent_traces(self, limit: int = 50) -> list:
        with self._lock:
            return list(self._spans[-limit:])


# ══════════════════════════════════════════════════════════════════════════════
# GRAFANA DASHBOARD JSON
# ══════════════════════════════════════════════════════════════════════════════

GRAFANA_DASHBOARD = {
    "title": "Ghost Security Platform",
    "uid":   "ghost-security-main",
    "tags":  ["ghost", "security", "appsec"],
    "time":  {"from": "now-24h", "to": "now"},
    "refresh": "30s",
    "panels": [
        {
            "id": 1, "type": "stat", "title": "Total Scans (24h)",
            "targets": [{"expr": "sum(increase(ghost_scans_total[24h]))"}],
            "gridPos": {"h": 4, "w": 4, "x": 0, "y": 0},
        },
        {
            "id": 2, "type": "stat", "title": "Critical Findings",
            "targets": [{"expr": 'sum(ghost_findings_total{severity="CRITICAL"})'}],
            "fieldConfig": {"defaults": {"color": {"fixedColor": "red", "mode": "fixed"}}},
            "gridPos": {"h": 4, "w": 4, "x": 4, "y": 0},
        },
        {
            "id": 3, "type": "stat", "title": "LLM Cost Today ($)",
            "targets": [{"expr": "sum(increase(ghost_llm_cost_usd_total[24h]))"}],
            "gridPos": {"h": 4, "w": 4, "x": 8, "y": 0},
        },
        {
            "id": 4, "type": "timeseries", "title": "Scans per Hour",
            "targets": [{"expr": "rate(ghost_scans_total[1h])", "legendFormat": "{{mode}}"}],
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 4},
        },
        {
            "id": 5, "type": "bargauge", "title": "Findings by Severity",
            "targets": [{"expr": "sum by(severity)(ghost_findings_total)", "legendFormat": "{{severity}}"}],
            "gridPos": {"h": 8, "w": 6, "x": 12, "y": 4},
        },
        {
            "id": 6, "type": "timeseries", "title": "Scan Duration p95",
            "targets": [{"expr": "histogram_quantile(0.95, rate(ghost_scan_duration_seconds_bucket[5m]))", "legendFormat": "p95"}],
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 12},
        },
        {
            "id": 7, "type": "piechart", "title": "LLM Usage by Provider",
            "targets": [{"expr": "sum by(provider)(ghost_llm_calls_total)", "legendFormat": "{{provider}}"}],
            "gridPos": {"h": 8, "w": 6, "x": 12, "y": 12},
        },
        {
            "id": 8, "type": "table", "title": "API Latency p99",
            "targets": [{"expr": "histogram_quantile(0.99, rate(ghost_api_latency_seconds_bucket[5m]))", "legendFormat": "{{endpoint}}"}],
            "gridPos": {"h": 8, "w": 12, "x": 0, "y": 20},
        },
    ],
}


def save_grafana_dashboard(path: str = "./infra/grafana/ghost_dashboard.json") -> str:
    import json, os
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump({"dashboard": GRAFANA_DASHBOARD, "overwrite": True}, f, indent=2)
    return path


# ── Singletons ────────────────────────────────────────────────────────────────
METRICS = MetricsRegistry()
TRACER  = OTelTracer("ghost-security")
