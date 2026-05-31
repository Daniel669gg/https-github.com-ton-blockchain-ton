"""
TythanAI Platform v13 — Lightweight Distributed Tracing
Implements W3C-compatible trace/span model without any OpenTelemetry dependency.
Uses thread-local storage for the active trace context.
"""
from __future__ import annotations

import threading
import time
import uuid
import logging
from contextlib import contextmanager
from typing import Generator, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Thread-local storage for active trace ID
# ---------------------------------------------------------------------------
_thread_local = threading.local()


def _get_trace_id() -> Optional[str]:
    return getattr(_thread_local, "trace_id", None)


def _set_trace_id(trace_id: Optional[str]) -> None:
    _thread_local.trace_id = trace_id


# ---------------------------------------------------------------------------
# TraceContext — primitive span operations
# ---------------------------------------------------------------------------


class TraceContext:
    """
    Stateless helper that provides factory and lifecycle methods for traces
    and spans.  Spans are recorded in the parent ``Tracer`` singleton.

    Most callers should use the ``Tracer`` singleton and its context manager::

        with tracer.span("my-operation") as span:
            do_work()
    """

    @staticmethod
    def new_trace() -> str:
        """Generate and return a new UUID4 trace ID."""
        return str(uuid.uuid4())

    @staticmethod
    def new_span(trace_id: str, operation: str) -> dict:
        """
        Create and return a span dict.

        The span is *open* (no end time yet).  Call ``finish_span`` to close it.
        """
        span_id = str(uuid.uuid4())[:16].replace("-", "")
        return {
            "trace_id": trace_id,
            "span_id": span_id,
            "operation": operation,
            "start_time": time.perf_counter(),
            "start_epoch": time.time(),
            "end_time": None,
            "duration_ms": None,
            "attributes": {},
            "status": "ok",
        }

    @staticmethod
    def finish_span(span: dict) -> None:
        """Record the end time and duration on an open span (mutates in place)."""
        end = time.perf_counter()
        span["end_time"] = end
        span["duration_ms"] = round((end - span["start_time"]) * 1000, 3)

    @staticmethod
    def get_current_trace_id() -> Optional[str]:
        """Return the active trace ID from thread-local storage, or None."""
        return _get_trace_id()


# ---------------------------------------------------------------------------
# Tracer — singleton with span storage and context manager
# ---------------------------------------------------------------------------


class Tracer:
    """
    Singleton distributed tracer for TythanAI v13.

    Provides a context manager for creating spans, stores completed spans in
    memory, and exposes them via ``export_spans()``.

    Usage::

        tracer = Tracer.get_instance()

        with tracer.span("parse-findings") as span:
            span["attributes"]["finding_count"] = 42

        spans = tracer.export_spans()
    """

    _instance: Optional["Tracer"] = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        self._spans: List[dict] = []
        self._lock = threading.Lock()
        self._tc = TraceContext()

    @classmethod
    def get_instance(cls) -> "Tracer":
        """Return the process-wide singleton instance."""
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
        return cls._instance

    # ------------------------------------------------------------------
    # Span management
    # ------------------------------------------------------------------

    def new_trace(self) -> str:
        """Generate a new trace ID and store it in thread-local storage."""
        trace_id = self._tc.new_trace()
        _set_trace_id(trace_id)
        return trace_id

    def get_current_trace_id(self) -> Optional[str]:
        return _get_trace_id()

    @contextmanager
    def span(
        self,
        operation: str,
        trace_id: Optional[str] = None,
    ) -> Generator[dict, None, None]:
        """
        Context manager that creates a span, makes it available as the context
        variable, and records it on exit.

        If *trace_id* is omitted the current thread-local trace ID is used; if
        none exists a new trace is started automatically.

        Example::

            with tracer.span("scan-file") as s:
                s["attributes"]["path"] = "/src/main.py"
        """
        if trace_id is None:
            trace_id = _get_trace_id() or self.new_trace()

        prev_trace_id = _get_trace_id()
        _set_trace_id(trace_id)

        span = self._tc.new_span(trace_id, operation)
        logger.debug("Span start: trace=%s op=%s", trace_id[:8], operation)

        try:
            yield span
        except Exception as exc:
            span["status"] = "error"
            span["error"] = str(exc)
            raise
        finally:
            self._tc.finish_span(span)
            with self._lock:
                self._spans.append(span)
            _set_trace_id(prev_trace_id)
            logger.debug(
                "Span end: trace=%s op=%s duration=%.1fms",
                trace_id[:8],
                operation,
                span.get("duration_ms", 0),
            )

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_spans(self, clear: bool = False) -> List[dict]:
        """
        Return all recorded spans (shallow copies).

        Args:
            clear: If True, clear the internal span buffer after returning.
        """
        with self._lock:
            result = [dict(s) for s in self._spans]
            if clear:
                self._spans.clear()
        return result


# ---------------------------------------------------------------------------
# Module-level singleton convenience
# ---------------------------------------------------------------------------
tracer = Tracer.get_instance()
