"""
Ghost Security Platform — Structured Logger
JSON-formatted log records with trace_id, component, and timing context.
Drop-in addition to Python logging — configure once, use everywhere.
"""
from __future__ import annotations

import json
import logging
import sys
import time
import traceback
import uuid
from contextvars import ContextVar
from typing import Any, Optional

# Active trace context propagated through async call stacks
_trace_id: ContextVar[str] = ContextVar("trace_id", default="")
_component: ContextVar[str] = ContextVar("component", default="ghost")


def set_trace(trace_id: str, component: str = "ghost") -> None:
    _trace_id.set(trace_id)
    _component.set(component)


def new_trace(component: str = "ghost") -> str:
    tid = uuid.uuid4().hex[:16]
    set_trace(tid, component)
    return tid


def current_trace() -> str:
    return _trace_id.get()


class _JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        doc: dict[str, Any] = {
            "ts":        round(record.created, 3),
            "level":     record.levelname,
            "component": _component.get() or record.name,
            "trace_id":  _trace_id.get() or None,
            "msg":       record.getMessage(),
            "logger":    record.name,
            "loc":       f"{record.filename}:{record.lineno}",
        }
        if record.exc_info:
            doc["exc"] = traceback.format_exception(*record.exc_info)
        # any extras passed via extra={}
        for k, v in record.__dict__.items():
            if k.startswith("ctx_"):
                doc[k[4:]] = v
        return json.dumps(doc)


def configure(
    level: str = "INFO",
    json_output: bool = True,
    stream=sys.stdout,
) -> None:
    """
    Call once at startup (e.g. in main / server startup).
    Sets the root logger to JSON output at the specified level.
    """
    handler = logging.StreamHandler(stream)
    handler.setFormatter(_JSONFormatter() if json_output else logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
    ))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


class StructuredLogger:
    """
    Thin wrapper that emits structured log records with consistent fields.

    Usage:
        log = StructuredLogger("ghost.scanner")
        log.info("scan started", path="/tmp/target", rules=42)
    """

    def __init__(self, name: str) -> None:
        self._log = logging.getLogger(name)

    def _emit(self, level: int, msg: str, **ctx) -> None:
        if self._log.isEnabledFor(level):
            extra = {f"ctx_{k}": v for k, v in ctx.items()}
            self._log.log(level, msg, extra=extra, stacklevel=3)

    def debug(self, msg: str, **ctx) -> None:   self._emit(logging.DEBUG,   msg, **ctx)
    def info(self,  msg: str, **ctx) -> None:   self._emit(logging.INFO,    msg, **ctx)
    def warning(self, msg: str, **ctx) -> None: self._emit(logging.WARNING, msg, **ctx)
    def error(self, msg: str, **ctx) -> None:   self._emit(logging.ERROR,   msg, **ctx)
    def critical(self, msg: str, **ctx) -> None:self._emit(logging.CRITICAL,msg, **ctx)

    def timed(self, operation: str):
        """Context manager that logs duration of a block."""
        return _TimedBlock(self, operation)


class _TimedBlock:
    def __init__(self, logger: StructuredLogger, operation: str) -> None:
        self._log       = logger
        self._operation = operation
        self._start     = 0.0

    def __enter__(self):
        self._start = time.perf_counter()
        self._log.debug(f"{self._operation} started")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = round(time.perf_counter() - self._start, 4)
        if exc_type:
            self._log.error(
                f"{self._operation} failed",
                duration_s=elapsed, exc=str(exc_val),
            )
        else:
            self._log.info(f"{self._operation} completed", duration_s=elapsed)
        return False  # don't suppress exceptions


# Convenience: get a component logger
def get_logger(name: str) -> StructuredLogger:
    return StructuredLogger(name)
