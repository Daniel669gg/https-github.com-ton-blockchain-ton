"""
Ghost Security Platform — /metrics Prometheus endpoint
Mount this router on the FastAPI app to expose metrics.
"""
try:
    from fastapi import APIRouter
    from fastapi.responses import PlainTextResponse
except ImportError:  # pragma: no cover
    APIRouter = object
    PlainTextResponse = object
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.metrics.prometheus_metrics import METRICS

router = APIRouter(tags=["Metrics"])


@router.get("/metrics", response_class=PlainTextResponse, include_in_schema=False)
async def prometheus_metrics():
    """Prometheus text exposition endpoint. Scrape at /metrics."""
    return PlainTextResponse(METRICS.render_text(), media_type="text/plain; version=0.0.4")


@router.get("/api/metrics/snapshot")
async def metrics_snapshot():
    """JSON snapshot of key platform metrics for the dashboard."""
    return METRICS.snapshot()
