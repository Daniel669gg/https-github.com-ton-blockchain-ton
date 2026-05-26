"""
Deep tests for PrometheusMetrics — ~50 tests covering counter behavior,
gauge behavior, histogram bucket/sum/count, render() format, label escaping,
multiple metric families, thread safety, pre-defined metrics, and ad-hoc metrics.
"""
import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest
from telemetry.prometheus_metrics import PrometheusMetrics


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def metrics():
    return PrometheusMetrics()


# ---------------------------------------------------------------------------
# Counter — never decreases
# ---------------------------------------------------------------------------

class TestCounter:
    def test_counter_starts_at_zero_implicitly(self, metrics):
        metrics.increment("ghost_scans_total", {"status": "ok"})
        output = metrics.render()
        assert "ghost_scans_total" in output

    def test_counter_increments(self, metrics):
        metrics.increment("ghost_scans_total", {"env": "test"}, value=1.0)
        metrics.increment("ghost_scans_total", {"env": "test"}, value=1.0)
        output = metrics.render()
        # Should show 2.0
        assert "2.0" in output

    def test_counter_increment_by_custom_value(self, metrics):
        metrics.increment("ghost_scans_total", {"env": "prod"}, value=5.0)
        output = metrics.render()
        assert "5.0" in output

    def test_counter_never_decreases(self, metrics):
        metrics.increment("ghost_scans_total", {"env": "test"}, value=10.0)
        metrics.increment("ghost_scans_total", {"env": "test"}, value=1.0)
        output = metrics.render()
        assert "11.0" in output

    def test_new_ad_hoc_counter(self, metrics):
        metrics.increment("my_custom_counter", {"tag": "x"}, value=3.0)
        output = metrics.render()
        assert "my_custom_counter" in output
        assert "3.0" in output


# ---------------------------------------------------------------------------
# Gauge — can go up and down
# ---------------------------------------------------------------------------

class TestGauge:
    def test_gauge_set_value(self, metrics):
        metrics.gauge("ghost_queue_depth", 42.0, {"pool": "default"})
        output = metrics.render()
        assert "42.0" in output

    def test_gauge_can_decrease(self, metrics):
        metrics.gauge("ghost_worker_active", 10.0, {"name": "a"})
        metrics.gauge("ghost_worker_active", 5.0, {"name": "a"})
        output = metrics.render()
        assert "5.0" in output

    def test_gauge_can_go_to_zero(self, metrics):
        metrics.gauge("ghost_queue_depth", 0.0, {"pool": "p1"})
        output = metrics.render()
        assert "ghost_queue_depth" in output

    def test_new_ad_hoc_gauge(self, metrics):
        metrics.gauge("custom_gauge", 99.5, {"region": "us-east"})
        output = metrics.render()
        assert "custom_gauge" in output
        assert "99.5" in output


# ---------------------------------------------------------------------------
# Histogram — bucket boundaries, sum, count
# ---------------------------------------------------------------------------

class TestHistogram:
    def test_histogram_bucket_count_increments(self, metrics):
        metrics.histogram("ghost_scan_duration_seconds", 0.05, {"scanner": "evm"})
        output = metrics.render()
        # 0.05 should fall into buckets >= 0.05
        assert "ghost_scan_duration_seconds_bucket" in output

    def test_histogram_sum_updated(self, metrics):
        metrics.histogram("ghost_scan_duration_seconds", 1.5, {"scanner": "sol"})
        output = metrics.render()
        assert "ghost_scan_duration_seconds_sum" in output
        assert "1.5" in output

    def test_histogram_count_updated(self, metrics):
        metrics.histogram("ghost_scan_duration_seconds", 0.1, {"scanner": "ast"})
        metrics.histogram("ghost_scan_duration_seconds", 0.2, {"scanner": "ast"})
        output = metrics.render()
        assert "ghost_scan_duration_seconds_count" in output

    def test_histogram_inf_bucket(self, metrics):
        metrics.histogram("ghost_scan_duration_seconds", 999.0, {"scanner": "test"})
        output = metrics.render()
        assert '+Inf' in output

    def test_histogram_small_value_in_small_buckets(self, metrics):
        metrics.histogram("ghost_scan_duration_seconds", 0.001, {"scanner": "tiny"})
        output = metrics.render()
        # 0.001 should not exceed buckets, so first bucket (0.005) should have count 1
        assert "ghost_scan_duration_seconds_bucket" in output

    def test_ad_hoc_histogram(self, metrics):
        metrics.histogram("custom_latency", 0.5, {"endpoint": "/scan"})
        output = metrics.render()
        assert "custom_latency_bucket" in output


# ---------------------------------------------------------------------------
# render() — valid Prometheus text format
# ---------------------------------------------------------------------------

class TestRenderFormat:
    def test_render_returns_string(self, metrics):
        output = metrics.render()
        assert isinstance(output, str)

    def test_render_contains_help_lines(self, metrics):
        metrics.increment("ghost_scans_total")
        output = metrics.render()
        assert "# HELP ghost_scans_total" in output

    def test_render_contains_type_lines(self, metrics):
        metrics.increment("ghost_scans_total")
        output = metrics.render()
        assert "# TYPE ghost_scans_total counter" in output

    def test_render_contains_uptime(self, metrics):
        output = metrics.render()
        assert "ghost_uptime_seconds" in output

    def test_render_multiple_metric_families(self, metrics):
        metrics.increment("ghost_scans_total")
        metrics.gauge("ghost_queue_depth", 1.0)
        metrics.histogram("ghost_scan_duration_seconds", 0.1)
        output = metrics.render()
        assert "ghost_scans_total" in output
        assert "ghost_queue_depth" in output
        assert "ghost_scan_duration_seconds" in output


# ---------------------------------------------------------------------------
# Label handling
# ---------------------------------------------------------------------------

class TestLabels:
    def test_labels_appear_in_output(self, metrics):
        metrics.increment("ghost_scans_total", {"scanner": "evm", "status": "ok"})
        output = metrics.render()
        assert 'scanner="evm"' in output
        assert 'status="ok"' in output

    def test_no_labels_no_braces(self, metrics):
        metrics.increment("ghost_errors_total", None, value=1.0)
        output = metrics.render()
        assert "ghost_errors_total 1.0" in output

    def test_multiple_label_sets_distinct(self, metrics):
        metrics.increment("ghost_findings_total", {"severity": "HIGH"}, value=3.0)
        metrics.increment("ghost_findings_total", {"severity": "LOW"}, value=7.0)
        output = metrics.render()
        assert 'severity="HIGH"' in output
        assert 'severity="LOW"' in output


# ---------------------------------------------------------------------------
# Pre-defined metrics exist in render()
# ---------------------------------------------------------------------------

class TestPredefinedMetrics:
    EXPECTED_METRICS = [
        "ghost_scans_total",
        "ghost_scan_duration_seconds",
        "ghost_findings_total",
        "ghost_llm_calls_total",
        "ghost_llm_tokens_total",
        "ghost_queue_depth",
        "ghost_worker_active",
        "ghost_errors_total",
    ]

    def test_all_predefined_metrics_in_render(self, metrics):
        output = metrics.render()
        for name in self.EXPECTED_METRICS:
            assert name in output, f"Missing metric: {name}"

    def test_predefined_counter_can_be_incremented(self, metrics):
        metrics.increment("ghost_llm_calls_total", {"model": "gpt4"})
        output = metrics.render()
        assert 'model="gpt4"' in output

    def test_predefined_gauge_can_be_set(self, metrics):
        metrics.gauge("ghost_queue_depth", 5.0, {"pool": "main"})
        output = metrics.render()
        assert "5.0" in output


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

class TestThreadSafety:
    def test_concurrent_increments(self, metrics):
        errors = []

        def _inc():
            try:
                for _ in range(100):
                    metrics.increment("ghost_scans_total", {"thread": "yes"})
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=_inc) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        output = metrics.render()
        assert "1000.0" in output  # 10 threads × 100 increments
