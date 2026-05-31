"""
backend/telemetry/otel.py — OpenTelemetry tracing for TythanAI.

Provides span-based tracing for scan pipeline stages and ReAct agent cycles.
Falls back gracefully if opentelemetry packages are not installed.
"""
from __future__ import annotations

import contextlib
import logging
import time
from typing import Any, Generator, Optional

logger = logging.getLogger("tythanai.otel")

# ─────────────────────────────────────────────────────────────────────────────
# Optional OTel imports
# ─────────────────────────────────────────────────────────────────────────────

try:
    from opentelemetry import trace as _otel_trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
    from opentelemetry.sdk.resources import Resource, SERVICE_NAME

    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False
    logger.info("opentelemetry SDK not installed — tracing disabled")


# ─────────────────────────────────────────────────────────────────────────────
# Provider setup
# ─────────────────────────────────────────────────────────────────────────────

_tracer: Any = None
_provider: Any = None


def setup_tracing(
    service_name: str = "sentinelops-ghost",
    otlp_endpoint: Optional[str] = None,
    console: bool = False,
) -> None:
    """
    Initialize the OTel TracerProvider.

    Call once at application start-up.  safe to call multiple times (no-op).

    Args:
        service_name:   Reported service name in traces.
        otlp_endpoint:  gRPC OTLP collector endpoint, e.g. "http://localhost:4317".
                        If None, no OTLP exporter is registered.
        console:        If True, also emit spans to stdout (useful for dev/debug).
    """
    global _tracer, _provider

    if _tracer is not None:
        return  # already set up

    if not _OTEL_AVAILABLE:
        logger.debug("OTel not available — skipping tracing setup")
        return

    resource = Resource.create({SERVICE_NAME: service_name})
    provider = TracerProvider(resource=resource)

    if console:
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    if otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            logger.info("OTel OTLP exporter registered at %s", otlp_endpoint)
        except ImportError:
            logger.warning(
                "opentelemetry-exporter-otlp-proto-grpc not installed — "
                "OTLP export disabled"
            )

    _otel_trace.set_tracer_provider(provider)
    _provider = provider
    _tracer = _otel_trace.get_tracer(service_name)
    logger.info("OTel tracing initialised for service '%s'", service_name)


def get_tracer() -> Any:
    """Return the configured tracer (or a no-op stub if OTel is unavailable)."""
    global _tracer
    if _tracer is None and _OTEL_AVAILABLE:
        setup_tracing()
    return _tracer


# ─────────────────────────────────────────────────────────────────────────────
# Span context managers
# ─────────────────────────────────────────────────────────────────────────────

@contextlib.contextmanager
def span(name: str, attributes: Optional[dict] = None) -> Generator[Any, None, None]:
    """
    Context manager that wraps a code block in an OTel span.

    Usage::

        with otel.span("taint-analysis", {"path": filepath}):
            findings = analyzer.analyze_file(filepath)

    If OTel is not configured the context manager is a no-op.
    """
    tracer = get_tracer()
    if tracer is None:
        yield None
        return

    with tracer.start_as_current_span(name) as current_span:
        if attributes and current_span is not None:
            try:
                for key, value in attributes.items():
                    current_span.set_attribute(key, str(value))
            except Exception:
                pass
        start = time.monotonic()
        try:
            yield current_span
        except Exception as exc:
            if current_span is not None:
                try:
                    current_span.record_exception(exc)
                    current_span.set_status(
                        _otel_trace.StatusCode.ERROR, str(exc)
                    )
                except Exception:
                    pass
            raise
        finally:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            if current_span is not None:
                try:
                    current_span.set_attribute("duration_ms", elapsed_ms)
                except Exception:
                    pass


@contextlib.contextmanager
def pipeline_span(stage: str, path: str = "") -> Generator[Any, None, None]:
    """Span for a single defensive lifecycle pipeline stage."""
    attrs = {"stage": stage}
    if path:
        attrs["target_path"] = path
    with span(f"pipeline.{stage}", attrs) as s:
        yield s


@contextlib.contextmanager
def agent_span(session_id: str, iteration: int) -> Generator[Any, None, None]:
    """Span for a single ReAct agent iteration."""
    with span(
        f"agent.iteration",
        {"session_id": session_id, "iteration": iteration},
    ) as s:
        yield s


def shutdown_tracing() -> None:
    """Flush and shut down the tracer provider.  Call at application exit."""
    global _provider
    if _provider is not None and _OTEL_AVAILABLE:
        try:
            _provider.shutdown()
        except Exception:
            pass
        _provider = None
