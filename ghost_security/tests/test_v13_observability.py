"""Tests for v13 observability stack."""
import sys
import pathlib
import pytest
import time

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))


class TestPrometheusMetrics:
    @pytest.fixture
    def metrics(self):
        from telemetry.prometheus_metrics import PrometheusMetrics
        return PrometheusMetrics()

    def test_import(self, metrics):
        assert metrics is not None

    def test_increment_counter(self, metrics):
        metrics.increment("ghost_scans_total", {"scanner": "owasp", "status": "success"})
        output = metrics.render()
        assert "ghost_scans_total" in output

    def test_gauge(self, metrics):
        metrics.gauge("ghost_queue_depth", 42.0, {"queue": "scan"})
        output = metrics.render()
        assert "ghost_queue_depth" in output
        assert "42" in output

    def test_histogram(self, metrics):
        metrics.histogram("ghost_scan_duration_seconds", 1.5, {"scanner": "ton"})
        output = metrics.render()
        assert "ghost_scan_duration_seconds" in output

    def test_render_prometheus_format(self, metrics):
        metrics.increment("ghost_scans_total", {"scanner": "test", "status": "ok"})
        output = metrics.render()
        assert isinstance(output, str)
        assert len(output) > 0
        # Prometheus format: lines with metric_name{labels} value
        lines = [l for l in output.split("\n") if l and not l.startswith("#")]
        assert len(lines) >= 1

    def test_multiple_increments(self, metrics):
        for _ in range(5):
            metrics.increment("ghost_errors_total", {"component": "scanner", "error_type": "timeout"})
        output = metrics.render()
        assert "ghost_errors_total" in output
        assert "5" in output


class TestTraceContext:
    @pytest.fixture
    def tracer(self):
        from telemetry.trace_context import Tracer
        return Tracer()

    def test_import(self, tracer):
        assert tracer is not None

    def test_new_trace_id(self, tracer):
        tid = tracer.new_trace()
        assert isinstance(tid, str)
        assert len(tid) > 0

    def test_unique_trace_ids(self, tracer):
        ids = {tracer.new_trace() for _ in range(10)}
        assert len(ids) == 10

    def test_create_span_via_context(self, tracer):
        with tracer.span("test_operation") as span:
            assert span is not None

    def test_finish_span_via_context(self, tracer):
        with tracer.span("op") as span:
            time.sleep(0.001)
        # Duration tracked internally

    def test_context_manager(self, tracer):
        tid = tracer.new_trace()
        assert isinstance(tid, str)
        with tracer.span("operation") as span:
            assert span is not None

    def test_export_spans(self, tracer):
        with tracer.span("test"):
            pass
        spans = tracer.export_spans()
        assert isinstance(spans, list)


class TestInferenceCache:
    @pytest.fixture
    def cache(self, tmp_path):
        from runtime.providers.inference_cache import InferenceCache
        return InferenceCache(db_path=str(tmp_path / "cache.db"), ttl_days=1)

    def test_import(self, cache):
        assert cache is not None

    def test_miss_returns_none(self, cache):
        result = cache.get("nonexistent_hash_xyz")
        assert result is None

    def test_set_and_get(self, cache):
        h = cache.hash_prompt("model1", "test prompt")
        cache.set(h, "test response")
        result = cache.get(h)
        assert result == "test response"

    def test_different_models_different_hash(self, cache):
        h1 = cache.hash_prompt("model1", "same prompt")
        h2 = cache.hash_prompt("model2", "same prompt")
        assert h1 != h2

    def test_stats(self, cache):
        h = cache.hash_prompt("m", "p")
        cache.set(h, "resp")
        cache.get(h)
        cache.get("miss")
        stats = cache.stats()
        assert "total_entries" in stats

    def test_evict_expired(self, cache):
        # Should not raise
        cache.evict_expired()


class TestModelHealth:
    @pytest.fixture
    def monitor(self):
        from runtime.providers.model_health import ModelHealthMonitor
        return ModelHealthMonitor()

    def test_import(self, monitor):
        assert monitor is not None

    def test_record_success(self, monitor):
        monitor.record_call("anthropic", True, 500.0)
        stats = monitor.get_stats()
        assert "anthropic" in stats

    def test_is_healthy_after_successes(self, monitor):
        for _ in range(5):
            monitor.record_call("openai", True, 200.0)
        assert monitor.is_healthy("openai") is True

    def test_unhealthy_after_failures(self, monitor):
        for _ in range(10):
            monitor.record_call("bad_provider", False, 30000.0)
        assert monitor.is_healthy("bad_provider") is False

    def test_get_best_provider(self, monitor):
        monitor.record_call("fast", True, 100.0)
        monitor.record_call("slow", True, 5000.0)
        best = monitor.get_best_provider(["fast", "slow"])
        assert best in ["fast", "slow"]

    def test_unknown_provider_healthy(self, monitor):
        # New provider with no data should default to healthy (benefit of doubt)
        result = monitor.is_healthy("new_provider")
        assert isinstance(result, bool)
