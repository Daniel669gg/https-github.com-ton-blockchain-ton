"""
TythanAI Platform — Execution Trace Engine
Async-safe execution spans with trace IDs, timing, metadata, and JSONL export.
Used by all subsystems for distributed tracing and audit trails.
"""
from __future__ import annotations

import json
import time
import uuid
import asyncio
import threading
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# ── Span dataclass ────────────────────────────────────────────────────────────

@dataclass
class Span:
    trace_id:   str
    span_id:    str
    parent_id:  Optional[str]
    name:       str
    component:  str
    started_at: float           = field(default_factory=time.time)
    ended_at:   float           = 0.0
    status:     str             = "running"   # running | ok | error
    metadata:   Dict[str, Any]  = field(default_factory=dict)
    error:      str             = ""

    @property
    def duration_ms(self) -> float:
        if self.ended_at:
            return round((self.ended_at - self.started_at) * 1000, 2)
        return 0.0

    def finish(self, status: str = "ok", error: str = "") -> None:
        self.ended_at = time.time()
        self.status   = status
        self.error    = error

    def to_dict(self) -> dict:
        return {
            "trace_id":    self.trace_id,
            "span_id":     self.span_id,
            "parent_id":   self.parent_id,
            "name":        self.name,
            "component":   self.component,
            "started_at":  round(self.started_at, 4),
            "ended_at":    round(self.ended_at, 4),
            "duration_ms": self.duration_ms,
            "status":      self.status,
            "metadata":    self.metadata,
            "error":       self.error,
        }


# ── TraceLogger ───────────────────────────────────────────────────────────────

class TraceLogger:
    """
    Structured execution tracer.
    Writes JSONL records and maintains an in-memory ring buffer (last 2000 spans).
    Thread-safe; async-context-manager-compatible.
    """

    MAX_BUFFER = 2000

    def __init__(self, path: str = "ghost_trace.jsonl", component: str = "ghost") -> None:
        self.path      = Path(path)
        self.component = component
        self._buf:  List[Span]        = []
        self._lock: threading.Lock    = threading.Lock()

    # ── Low-level span lifecycle ──────────────────────────────────────────────

    def start_span(
        self,
        name: str,
        trace_id: Optional[str] = None,
        parent_id: Optional[str] = None,
        component: Optional[str] = None,
        **metadata,
    ) -> Span:
        span = Span(
            trace_id  = trace_id  or uuid.uuid4().hex[:16],
            span_id   = uuid.uuid4().hex[:12],
            parent_id = parent_id,
            name      = name,
            component = component or self.component,
            metadata  = metadata,
        )
        with self._lock:
            self._buf.append(span)
            if len(self._buf) > self.MAX_BUFFER:
                self._buf = self._buf[-self.MAX_BUFFER:]
        return span

    def end_span(self, span: Span, status: str = "ok", error: str = "") -> None:
        span.finish(status=status, error=error)
        self._write(span)

    def _write(self, span: Span) -> None:
        try:
            with self.path.open("a") as fh:
                fh.write(json.dumps(span.to_dict()) + "\n")
        except Exception:
            pass  # never let tracing break the main path

    # ── Convenience: simple step log (backward-compat) ────────────────────────

    def log(self, step: str, agent: str, status: str, data: Optional[dict] = None) -> None:
        span = self.start_span(
            name=step, component=agent,
            **(data or {}),
        )
        span.finish(status=status)
        self._write(span)

    # ── Sync context manager ──────────────────────────────────────────────────

    @contextmanager
    def span(
        self,
        name: str,
        trace_id: Optional[str] = None,
        parent_id: Optional[str] = None,
        **metadata,
    ):
        s = self.start_span(name, trace_id=trace_id, parent_id=parent_id, **metadata)
        try:
            yield s
            self.end_span(s, status="ok")
        except Exception as exc:
            self.end_span(s, status="error", error=str(exc))
            raise

    # ── Async context manager ─────────────────────────────────────────────────

    @asynccontextmanager
    async def async_span(
        self,
        name: str,
        trace_id: Optional[str] = None,
        parent_id: Optional[str] = None,
        **metadata,
    ):
        s = self.start_span(name, trace_id=trace_id, parent_id=parent_id, **metadata)
        try:
            yield s
            self.end_span(s, status="ok")
        except Exception as exc:
            self.end_span(s, status="error", error=str(exc))
            raise

    # ── Diagnostics ───────────────────────────────────────────────────────────

    def recent(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return [s.to_dict() for s in self._buf[-limit:]]

    def stats(self) -> dict:
        with self._lock:
            spans = list(self._buf)
        total = len(spans)
        ok    = sum(1 for s in spans if s.status == "ok")
        err   = sum(1 for s in spans if s.status == "error")
        durations = [s.duration_ms for s in spans if s.ended_at]
        avg_ms = round(sum(durations) / len(durations), 2) if durations else 0.0
        return {
            "total_spans": total,
            "ok":          ok,
            "errors":      err,
            "avg_duration_ms": avg_ms,
        }


# ── Module-level singleton ─────────────────────────────────────────────────────
TRACER = TraceLogger(path="ghost_trace.jsonl", component="ghost.runtime")
