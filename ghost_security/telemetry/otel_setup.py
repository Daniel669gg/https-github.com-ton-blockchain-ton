"""
Ghost Security Platform v13 — OpenTelemetry Setup
Configures OTel TracerProvider with OTLP export when opentelemetry is installed;
falls back silently to the local TraceContext implementation when it is not.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_otel_available: bool = False
_tracer_provider = None

# ---------------------------------------------------------------------------
# Fallback tracer accessor (lazy to avoid circular imports)
# ---------------------------------------------------------------------------

_fallback_tracer = None


def _get_fallback_tracer():
    global _fallback_tracer
    if _fallback_tracer is None:
        try:
            from ghost_security.telemetry.trace_context import tracer as _t
            _fallback_tracer = _t
        except ImportError:
            from telemetry.trace_context import tracer as _t  # type: ignore[no-redef]
            _fallback_tracer = _t
    return _fallback_tracer


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def setup_telemetry(
    service_name: str,
    otlp_endpoint: Optional[str] = None,
) -> bool:
    """
    Initialise the tracing backend.

    Attempts to configure OpenTelemetry with an OTLP gRPC exporter.
    If ``opentelemetry`` packages are not installed, silently falls back to
    the Ghost Security built-in ``TraceContext`` tracer.

    Args:
        service_name:   Logical name of this service (e.g. ``"ghost-scanner"``).
        otlp_endpoint:  OTLP collector URL, e.g. ``"http://localhost:4317"``.
                        If ``None``, the ``OTEL_EXPORTER_OTLP_ENDPOINT``
                        environment variable is consulted, then defaults to
                        ``"http://localhost:4317"``.

    Returns:
        ``True`` if OpenTelemetry was configured successfully.
        ``False`` if the fallback ``TraceContext`` is being used.
    """
    global _otel_available, _tracer_provider

    endpoint = (
        otlp_endpoint
        or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
    )

    try:
        from opentelemetry import trace as otel_trace
        from opentelemetry.sdk.trace import TracerProvider

        # Resource — try modern API first, then legacy
        try:
            from opentelemetry.sdk.resources import Resource, SERVICE_NAME
            resource = Resource(attributes={SERVICE_NAME: service_name})
        except (ImportError, TypeError):
            try:
                from opentelemetry.sdk.resources import Resource
                resource = Resource.create({"service.name": service_name})
            except Exception:
                resource = None  # type: ignore[assignment]

        provider_kwargs = {}
        if resource is not None:
            provider_kwargs["resource"] = resource
        provider = TracerProvider(**provider_kwargs)

        # Try OTLP exporter; fall back to console if not installed
        try:
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )
            exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
            provider.add_span_processor(BatchSpanProcessor(exporter))
            logger.info(
                "OpenTelemetry configured: service=%s endpoint=%s",
                service_name,
                endpoint,
            )
        except ImportError:
            try:
                from opentelemetry.sdk.trace.export import (
                    SimpleSpanProcessor,
                    ConsoleSpanExporter,
                )
                provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
                logger.info(
                    "OpenTelemetry configured with ConsoleSpanExporter "
                    "(OTLP exporter not installed); service=%s",
                    service_name,
                )
            except ImportError:
                logger.info(
                    "OpenTelemetry SDK incomplete; no span exporter attached. service=%s",
                    service_name,
                )

        otel_trace.set_tracer_provider(provider)
        _tracer_provider = provider
        _otel_available = True
        return True

    except ImportError:
        logger.info(
            "opentelemetry not installed; using Ghost Security TraceContext fallback "
            "(service=%s)",
            service_name,
        )
        _otel_available = False
        return False


def get_tracer(name: str):
    """
    Return a tracer for *name*.

    If OpenTelemetry has been configured (``setup_telemetry`` returned ``True``)
    this returns an OTel tracer.  Otherwise it returns the Ghost Security
    built-in ``Tracer`` singleton so callers get a consistent interface
    regardless of the OTel installation status.

    Both the OTel tracer and the fallback ``Tracer`` support the same
    context-manager interface::

        t = get_tracer("ghost.scanner")
        with t.span("scan") as span:
            ...
    """
    if _otel_available:
        try:
            from opentelemetry import trace as otel_trace
            return otel_trace.get_tracer(name)
        except Exception:
            pass
    return _get_fallback_tracer()


def is_otel_enabled() -> bool:
    """Return True if OpenTelemetry is active, False if using the built-in fallback."""
    return _otel_available
