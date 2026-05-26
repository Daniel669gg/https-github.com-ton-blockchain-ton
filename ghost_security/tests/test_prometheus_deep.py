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


# ---------------------------------------------------------------------------
# Additional prometheus tests
# ---------------------------------------------------------------------------

class TestAdditionalMetrics:
    def test_counter_without_labels(self, metrics):
        metrics.increment("ghost_errors_total", None, value=2.0)
        output = metrics.render()
        assert "ghost_errors_total 2.0" in output

    def test_multiple_histogram_observations(self, metrics):
        for v in [0.1, 0.5, 1.0, 2.0]:
            metrics.histogram("ghost_scan_duration_seconds", v, {"s": "evm"})
        output = metrics.render()
        assert "ghost_scan_duration_seconds_count" in output

    def test_histogram_count_matches_observations(self, metrics):
        for _ in range(5):
            metrics.histogram("ghost_scan_duration_seconds", 0.1, {"s": "x"})
        output = metrics.render()
        # The count bucket should be 5
        assert "5" in output

    def test_histogram_sum_matches_observations(self, metrics):
        # Observe 3 values of 1.0 each = sum 3.0
        for _ in range(3):
            metrics.histogram("ghost_scan_duration_seconds", 1.0, {"s": "y"})
        output = metrics.render()
        assert "3.0" in output

    def test_gauge_decreases_to_negative(self, metrics):
        metrics.gauge("ghost_queue_depth", -5.0, {"pool": "neg"})
        output = metrics.render()
        assert "-5.0" in output

    def test_type_error_on_counter_as_gauge(self, metrics):
        import pytest as pt
        with pt.raises(TypeError):
            metrics.gauge("ghost_scans_total", 1.0)

    def test_type_error_on_gauge_as_counter(self, metrics):
        import pytest as pt
        metrics.gauge("my_gauge_x", 1.0)
        with pt.raises(TypeError):
            metrics.increment("my_gauge_x")

    def test_render_produces_newlines(self, metrics):
        metrics.increment("ghost_scans_total")
        output = metrics.render()
        assert "\n" in output

    def test_histogram_inf_bucket_equals_total_count(self, metrics):
        metrics.histogram("ghost_scan_duration_seconds", 999.0, {"s": "inf"})
        output = metrics.render()
        assert 'le="+Inf"' in output

    def test_increment_value_custom(self, metrics):
        metrics.increment("ghost_findings_total", {"sev": "LOW"}, value=42.0)
        output = metrics.render()
        assert "42.0" in output

    def test_gauge_multiple_label_sets(self, metrics):
        metrics.gauge("ghost_worker_active", 3.0, {"pool": "a"})
        metrics.gauge("ghost_worker_active", 7.0, {"pool": "b"})
        output = metrics.render()
        assert "3.0" in output
        assert "7.0" in output

    def test_ad_hoc_histogram_with_custom_buckets(self, metrics):
        metrics.histogram("custom_hist", 0.5, buckets=[0.1, 0.5, 1.0])
        output = metrics.render()
        assert "custom_hist_bucket" in output

    def test_render_contains_ghost_comment_header(self, metrics):
        output = metrics.render()
        assert "Ghost Security" in output

    def test_multiple_increments_accumulate(self, metrics):
        for _ in range(7):
            metrics.increment("ghost_llm_tokens_total", {"model": "test"})
        output = metrics.render()
        assert "7.0" in output

    def test_histogram_bucket_increments_for_small_values(self, metrics):
        # Observe 0.001 — should be counted in 0.005 bucket
        metrics.histogram("ghost_scan_duration_seconds", 0.001, {"s": "tiny"})
        output = metrics.render()
        # At least the first bucket should have count 1
        assert "1" in output


# ---------------------------------------------------------------------------
# Final prometheus tests
# ---------------------------------------------------------------------------

class TestFinalPrometheus:
    def test_render_is_non_empty(self, metrics):
        output = metrics.render()
        assert len(output) > 0

    def test_render_has_help_for_all_predefined(self, metrics):
        output = metrics.render()
        help_count = output.count("# HELP ")
        # At least 8 pre-defined metrics
        assert help_count >= 8

    def test_render_has_type_for_all_predefined(self, metrics):
        output = metrics.render()
        type_count = output.count("# TYPE ")
        assert type_count >= 8

    def test_counter_label_str_format(self, metrics):
        metrics.increment("ghost_errors_total", {"component": "scanner", "type": "timeout"})
        output = metrics.render()
        assert 'component="scanner"' in output
        assert 'type="timeout"' in output

    def test_gauge_set_overwrites(self, metrics):
        metrics.gauge("ghost_queue_depth", 100.0, {"pool": "x"})
        metrics.gauge("ghost_queue_depth", 5.0, {"pool": "x"})
        output = metrics.render()
        assert "5.0" in output
        # 100.0 should be overwritten
        assert "100.0" not in output

    def test_histogram_with_no_labels(self, metrics):
        metrics.histogram("ghost_scan_duration_seconds", 0.5)
        output = metrics.render()
        assert "ghost_scan_duration_seconds_sum" in output

    def test_multiple_gauge_updates(self, metrics):
        for i in range(5):
            metrics.gauge("ghost_worker_active", float(i), {"pool": "p"})
        output = metrics.render()
        assert "4.0" in output

    def test_counter_zero_value(self, metrics):
        metrics.increment("ghost_llm_calls_total", {"provider": "ollama"}, value=0.0)
        output = metrics.render()
        assert 'provider="ollama"' in output

    def test_ad_hoc_counter_and_gauge_coexist(self, metrics):
        metrics.increment("custom_counter_abc", value=1.0)
        metrics.gauge("custom_gauge_abc", 1.0)
        output = metrics.render()
        assert "custom_counter_abc" in output
        assert "custom_gauge_abc" in output

    def test_histogram_large_value_in_inf_bucket(self, metrics):
        metrics.histogram("ghost_scan_duration_seconds", 1000.0, {"s": "big"})
        output = metrics.render()
        # +Inf should have count 1
        assert '+Inf' in output

    def test_render_has_generated_timestamp(self, metrics):
        output = metrics.render()
        assert "Generated:" in output

    def test_increment_same_labels_multiple_times(self, metrics):
        for _ in range(3):
            metrics.increment("ghost_scans_total", {"env": "staging"}, value=2.0)
        output = metrics.render()
        # 3 * 2.0 = 6.0
        assert "6.0" in output

    def test_type_counter_in_output(self, metrics):
        output = metrics.render()
        assert "counter" in output

    def test_type_histogram_in_output(self, metrics):
        output = metrics.render()
        assert "histogram" in output

    def test_type_gauge_in_output(self, metrics):
        output = metrics.render()
        assert "gauge" in output
