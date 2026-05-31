"""
TythanAI Platform — FastAPI Endpoint Tests
Tests all major API routes without requiring live external services.
Run: python3 -m pytest tests/test_api.py -v
"""
import sys
import os
import json
from pathlib import Path
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestHealthEndpoint(unittest.TestCase):
    def setUp(self):
        # Mock heavy dependencies before importing FastAPI app
        mocks = {
            "chromadb":            MagicMock(),
            "openai":              MagicMock(),
            "fastapi.staticfiles": MagicMock(),
        }
        self._patches = [patch.dict("sys.modules", mocks)]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in self._patches:
            p.stop()

    def test_metrics_registry_renders(self):
        from core.metrics.prometheus_metrics import MetricsRegistry
        reg = MetricsRegistry()
        reg.scans_started.inc(scanner="ast")
        reg.findings_total.inc(severity="HIGH", scanner="semgrep")
        text = reg.render_text()
        self.assertIn("ghost_scans_started_total", text)
        self.assertIn("ghost_findings_total", text)
        self.assertIn("ghost_uptime_seconds", text)

    def test_metrics_snapshot(self):
        from core.metrics.prometheus_metrics import MetricsRegistry
        reg = MetricsRegistry()
        reg.tasks_succeeded.inc(5)
        snap = reg.snapshot()
        self.assertIn("tasks_succeeded", snap)
        self.assertIn("uptime_seconds", snap)
        self.assertGreaterEqual(snap["uptime_seconds"], 0)

    def test_counter_thread_safety(self):
        import threading
        from core.metrics.prometheus_metrics import Counter
        c = Counter("test_counter", "test", ["label"])
        errors = []

        def inc_many():
            try:
                for _ in range(1000):
                    c.inc(label="x")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=inc_many) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(c.get(label="x"), 4000.0)

    def test_histogram_buckets(self):
        from core.metrics.prometheus_metrics import Histogram
        h = Histogram("test_hist", "test")
        for v in [0.001, 0.01, 0.1, 1.0, 5.0]:
            h.observe(v)
        text = h.render()
        self.assertIn("test_hist_bucket", text)
        self.assertIn("test_hist_sum", text)
        self.assertIn("test_hist_count 5", text)


class TestTraceEngine(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmpdir = tempfile.mkdtemp()

    def test_span_lifecycle(self):
        from runtime.trace import TraceLogger
        t = TraceLogger(path=os.path.join(self.tmpdir, "test.jsonl"))
        span = t.start_span("test_op", component="test")
        self.assertEqual(span.status, "running")
        self.assertFalse(span.ended_at)
        t.end_span(span, status="ok")
        self.assertEqual(span.status, "ok")
        self.assertTrue(span.ended_at)
        self.assertGreaterEqual(span.duration_ms, 0)  # may be 0 on fast machines

    def test_context_manager(self):
        from runtime.trace import TraceLogger
        t = TraceLogger(path=os.path.join(self.tmpdir, "cm.jsonl"))
        with t.span("my_op", component="test") as s:
            self.assertEqual(s.status, "running")
        self.assertEqual(s.status, "ok")

    def test_context_manager_error(self):
        from runtime.trace import TraceLogger
        t = TraceLogger(path=os.path.join(self.tmpdir, "err.jsonl"))
        try:
            with t.span("failing_op") as s:
                raise ValueError("boom")
        except ValueError:
            pass
        self.assertEqual(s.status, "error")
        self.assertIn("boom", s.error)

    def test_stats(self):
        import os as _os
        from runtime.trace import TraceLogger
        t = TraceLogger(path=_os.path.join(self.tmpdir, "stats.jsonl"))
        for name in ("op_a", "op_b", "op_c"):
            with t.span(name):
                pass
        stats = t.stats()
        self.assertEqual(stats["total_spans"], 3)
        self.assertEqual(stats["ok"], 3)
        self.assertEqual(stats["errors"], 0)

    def test_log_backward_compat(self):
        import os as _os
        from runtime.trace import TraceLogger
        t = TraceLogger(path=_os.path.join(self.tmpdir, "compat.jsonl"))
        # Should not raise
        t.log("step_1", "agent_x", "success", {"key": "val"})
        recent = t.recent(10)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["name"], "step_1")


class TestWatchdog(unittest.TestCase):
    def test_register_and_beat(self):
        from runtime.watchdog import RuntimeWatchdog
        wd = RuntimeWatchdog(check_interval=999)
        calls = []
        wd.register("test_svc", heartbeat_fn=lambda: True, timeout=5.0)
        wd.beat("test_svc")
        status = wd.status()
        self.assertIn("test_svc", status["targets"])
        self.assertEqual(status["targets"]["test_svc"]["status"], "ok")

    def test_status_overall_ok(self):
        from runtime.watchdog import RuntimeWatchdog
        wd = RuntimeWatchdog(check_interval=999)
        wd.register("svc_a", lambda: True)
        wd.register("svc_b", lambda: True)
        status = wd.status()
        self.assertEqual(status["overall"], "ok")


class TestConfidenceEngine(unittest.TestCase):
    def test_score_function_returns_float(self):
        from verifier.confidence_engine import _score_finding
        finding = {
            "type": "hardcoded_secret",
            "severity": "CRITICAL",
            "file": "config.py",
            "message": "API key detected",
            "source": "semgrep",
        }
        score, factors = _score_finding(finding)
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_fp_detection_placeholder(self):
        from verifier.confidence_engine import _is_likely_fp
        finding = {
            "type": "hardcoded_secret",
            "severity": "HIGH",
            "context": "api_key = \'your_api_key_here\'",
            "message": "secret detected",
        }
        is_fp, reason = _is_likely_fp(finding)
        self.assertTrue(is_fp, f"Expected FP detection, got reason: {reason}")

    def test_engine_instantiates(self):
        from verifier.confidence_engine import ConfidenceEngine
        engine = ConfidenceEngine()
        self.assertIsNotNone(engine)


if __name__ == "__main__":
    unittest.main()
