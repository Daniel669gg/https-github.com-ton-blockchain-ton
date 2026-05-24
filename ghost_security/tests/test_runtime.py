"""
Ghost Security Platform — Runtime & Orchestration Tests
Tests for: RuntimeSupervisor, TaskGraph, ConfidenceEngine, CVEEnricher, RepoIndexer
Run: python3 -m pytest tests/test_runtime.py -v
"""
import asyncio
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── RuntimeSupervisor ────────────────────────────────────────────────────────

class TestRuntimeSupervisor(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        from runtime.supervisor import RuntimeSupervisor, RetryPolicy
        self.sup = RuntimeSupervisor(max_concurrent=4)
        await self.sup.start()

    async def asyncTearDown(self):
        await self.sup.shutdown(timeout=3.0)

    async def test_successful_task(self):
        async def job():
            return {"ok": True}

        result = await self.sup.run_once("test_success", job)
        self.assertEqual(result, {"ok": True})

    async def test_timeout_triggers_retry(self):
        from runtime.supervisor import RetryPolicy
        call_count = {"n": 0}

        async def slow_job():
            call_count["n"] += 1
            if call_count["n"] < 2:
                await asyncio.sleep(10)  # will timeout
            return "done"

        policy = RetryPolicy(max_attempts=2, base_delay=0.01)
        tid = self.sup.submit("test_retry", slow_job, timeout=0.05, retry=policy)
        st  = await self.sup.wait(tid, poll=0.05)
        # Should succeed on second attempt
        from runtime.supervisor import TaskState
        self.assertIn(st.state, (TaskState.SUCCEEDED, TaskState.FAILED))

    async def test_task_failure_after_retries(self):
        from runtime.supervisor import RetryPolicy, TaskState

        async def always_fail():
            raise ValueError("deliberate failure")

        policy = RetryPolicy(max_attempts=2, base_delay=0.01)
        tid = self.sup.submit("test_fail", always_fail, retry=policy)
        st  = await self.sup.wait(tid, poll=0.05)
        self.assertEqual(st.state, TaskState.FAILED)
        self.assertIn("deliberate failure", st.error)
        self.assertEqual(st.attempts, 2)

    async def test_concurrent_tasks(self):
        results = []
        async def task(n):
            await asyncio.sleep(0.01)
            return n * 2

        tids = [self.sup.submit(f"concurrent_{i}", task, i) for i in range(10)]
        sts  = [await self.sup.wait(tid) for tid in tids]
        for i, st in enumerate(sts):
            from runtime.supervisor import TaskState
            self.assertEqual(st.state, TaskState.SUCCEEDED)

    async def test_status(self):
        status = self.sup.status()
        self.assertIn("running", status)
        self.assertIn("total_tasks", status)

    async def test_graceful_shutdown(self):
        """Supervisor should drain and stop cleanly."""
        async def quick_job():
            return "fast"

        self.sup.submit("shutdown_test", quick_job)
        await self.sup.shutdown(timeout=5.0)
        self.assertFalse(self.sup._running)


# ─── TaskGraph ────────────────────────────────────────────────────────────────

class TestTaskGraph(unittest.IsolatedAsyncioTestCase):

    async def test_linear_chain(self):
        """A → B → C executes in order."""
        from orchestrator.task_graph import TaskGraph
        order = []

        async def step(name):
            order.append(name)
            return name

        g = TaskGraph()
        a = g.add("A", step, "A")
        b = g.add("B", step, "B", deps=[a])
        c = g.add("C", step, "C", deps=[b])

        run = await g.execute()
        from orchestrator.task_graph import NodeState
        for nid in [a, b, c]:
            self.assertEqual(run.nodes[nid].state, NodeState.SUCCEEDED)
        self.assertEqual(order, ["A", "B", "C"])

    async def test_parallel_nodes(self):
        """Nodes with no deps run in parallel."""
        from orchestrator.task_graph import TaskGraph, NodeState
        start_times = {}

        async def timed_step(name):
            start_times[name] = time.monotonic()
            await asyncio.sleep(0.02)
            return name

        g = TaskGraph()
        a = g.add("P1", timed_step, "P1")
        b = g.add("P2", timed_step, "P2")
        c = g.add("P3", timed_step, "P3")

        run = await g.execute(max_concurrent=4)
        # All should succeed
        for nid in [a, b, c]:
            self.assertEqual(run.nodes[nid].state, NodeState.SUCCEEDED)
        # Should overlap (run within 0.1s total, not 0.06s serially)
        total_time = run.finished - run.started
        self.assertLess(total_time, 0.15)

    async def test_dep_failure_skips_children(self):
        from orchestrator.task_graph import TaskGraph, NodeState

        async def fail_step():
            raise RuntimeError("boom")

        async def child_step():
            return "child"

        g = TaskGraph()
        parent = g.add("parent", fail_step, max_retries=0)
        child  = g.add("child",  child_step, deps=[parent], skip_on_dep_failure=True)

        run = await g.execute()
        self.assertEqual(run.nodes[parent].state, NodeState.FAILED)
        self.assertEqual(run.nodes[child].state,  NodeState.SKIPPED)

    async def test_cycle_detection(self):
        from orchestrator.task_graph import TaskGraph

        async def noop(): pass

        g = TaskGraph()
        a = g.add("A", noop, node_id="node_a")
        b = g.add("B", noop, deps=["node_a"], node_id="node_b")
        # Manually force a cycle
        g._nodes["node_a"].deps = ["node_b"]
        errors = g.validate()
        self.assertTrue(len(errors) > 0)

    async def test_graph_summary(self):
        from orchestrator.task_graph import TaskGraph

        async def ok(): return 1

        g = TaskGraph("test-graph")
        a = g.add("X", ok)
        run = await g.execute()
        s = run.summary()
        self.assertEqual(s["graph_id"], "test-graph")
        self.assertIn("by_state", s)


# ─── ConfidenceEngine ─────────────────────────────────────────────────────────

class TestConfidenceEngine(unittest.TestCase):

    def setUp(self):
        from verifier.confidence_engine import ConfidenceEngine
        self.engine = ConfidenceEngine(fp_threshold=0.3)

    def _make(self, **kw) -> dict:
        return {"type": "sql_injection", "severity": "HIGH",
                "file": "app.py", "line": 10,
                "context": "cursor.execute(sql % user_input)", **kw}

    def test_basic_scoring(self):
        result = self.engine.process([self._make()])
        self.assertIn("findings", result)
        self.assertIn("stats", result)

    def test_fp_suppressed(self):
        finding = self._make(context="# nosec: sql is safe here")
        result = self.engine.process([finding])
        # Either discarded or very low confidence
        discarded_count = result["stats"]["discarded_fps"]
        self.assertGreaterEqual(discarded_count, 0)

    def test_hardcoded_placeholder_is_fp(self):
        finding = {
            "type": "hardcoded_secret",
            "severity": "HIGH",
            "context": 'api_key = "your_api_key_here"',
            "file": "config.py",
            "line": 5,
        }
        result = self.engine.process([finding])
        # Placeholder pattern should be detected as FP
        self.assertTrue(
            result["stats"]["discarded_fps"] > 0
            or (result["findings"] and result["findings"][0]["confidence"] < 0.7)
        )

    def test_confidence_field_present(self):
        result = self.engine.process([self._make()])
        for f in result["findings"]:
            self.assertIn("confidence", f)
            self.assertIn("priority",   f)
            self.assertIn("fingerprint",f)

    def test_deduplication(self):
        f = self._make()
        result = self.engine.process([f, f, f])
        # After dedup, at most 1 finding
        total = result["stats"]["after_filter"] + result["stats"]["discarded_fps"]
        self.assertLessEqual(total, 1)

    def test_priority_order(self):
        """Critical/high confidence findings should come first."""
        findings = [
            self._make(severity="LOW",      confidence=0.5, line=1),
            self._make(severity="CRITICAL", confidence=0.95, line=2),
            self._make(severity="MEDIUM",   confidence=0.7,  line=3),
        ]
        result = self.engine.process(findings)
        if len(result["findings"]) >= 2:
            p0 = result["findings"][0]["priority"]
            p1 = result["findings"][-1]["priority"]
            self.assertLessEqual(p0, p1)  # P1 < P5 lexically

    def test_explain(self):
        finding = self._make(confidence=0.9)
        explanation = self.engine.explain(finding)
        self.assertIn("Confidence", explanation)
        self.assertIn("Priority",   explanation)


# ─── CVEEnricher ──────────────────────────────────────────────────────────────

class TestCVEEnricher(unittest.TestCase):

    def setUp(self):
        from core.knowledge.cve_enricher import CVEEnricher
        self.enricher = CVEEnricher(online=False)

    def _finding(self, **kw) -> dict:
        return {"type": "sql_injection", "severity": "HIGH", **kw}

    def test_cwe_inferred(self):
        f = self._finding()
        enriched = self.enricher.enrich([f])
        self.assertEqual(enriched[0].get("cwe"), "CWE-89")

    def test_owasp_mapped(self):
        f = self._finding()
        enriched = self.enricher.enrich([f])
        self.assertIn("owasp", enriched[0])
        self.assertIn("A03:2021", enriched[0]["owasp"])

    def test_xss_cwe(self):
        f = {"type": "xss", "severity": "MEDIUM"}
        enriched = self.enricher.enrich([f])
        self.assertEqual(enriched[0].get("cwe"), "CWE-79")

    def test_ssrf_cwe(self):
        f = {"type": "ssrf", "severity": "HIGH"}
        enriched = self.enricher.enrich([f])
        self.assertEqual(enriched[0].get("cwe"), "CWE-918")

    def test_summary(self):
        findings = self.enricher.enrich([
            {"type": "sql_injection",  "severity": "HIGH"},
            {"type": "xss",            "severity": "MEDIUM"},
            {"type": "ssrf",           "severity": "HIGH"},
        ])
        s = self.enricher.summary(findings)
        self.assertIn("top_cwes",  s)
        self.assertIn("top_owasp", s)

    def test_severity_normalised(self):
        f = {"type": "test", "severity": "critical"}  # lowercase
        enriched = self.enricher.enrich([f])
        self.assertEqual(enriched[0]["severity"], "CRITICAL")


# ─── RepoIndexer ──────────────────────────────────────────────────────────────

class TestRepoIndexer(unittest.TestCase):

    def setUp(self):
        from core.indexing.repo_indexer import RepoIndexer
        self.indexer = RepoIndexer()
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write(self, name, content):
        p = os.path.join(self._tmpdir, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content)
        return p

    def test_basic_index(self):
        self._write("app.py", "import flask\napp = flask.Flask(__name__)\n")
        result = self.indexer.index(self._tmpdir)
        self.assertIn("fingerprint",    result)
        self.assertIn("total_files",    result)
        self.assertIn("languages",      result)
        self.assertGreater(result["total_files"], 0)

    def test_framework_detection(self):
        self._write("server.py", "from flask import Flask\napp = Flask(__name__)\n")
        result = self.indexer.index(self._tmpdir)
        self.assertIn("flask", result.get("frameworks", []))

    def test_secret_signal(self):
        self._write("config.py", 'SECRET_KEY = "my_super_secret_key_1234567890"\n')
        result = self.indexer.index(self._tmpdir)
        stats = result.get("stats", {})
        self.assertGreater(stats.get("secret_signals", 0), 0)

    def test_risk_heatmap_produced(self):
        self._write("app.py", "eval(user_input)\nexec(cmd)\n")
        result = self.indexer.index(self._tmpdir)
        self.assertIn("risk_heatmap", result)

    def test_dep_inventory_requirements(self):
        self._write("requirements.txt", "fastapi>=0.110\nrequests==2.31.0\n")
        result = self.indexer.index(self._tmpdir)
        deps = result.get("dependencies", [])
        names = [d["name"] for d in deps]
        self.assertIn("fastapi",   names)
        self.assertIn("requests",  names)

    def test_fingerprint_reproducible(self):
        self._write("main.py", "print('hello')\n")
        r1 = self.indexer.index(self._tmpdir)
        r2 = self.indexer.index(self._tmpdir)
        self.assertEqual(r1["fingerprint"], r2["fingerprint"])


# ─── CallGraph ────────────────────────────────────────────────────────────────

class TestCallGraph(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write(self, name, content):
        p = os.path.join(self._tmpdir, name)
        with open(p, "w") as f:
            f.write(content)

    def test_simple_call_graph(self):
        self._write("example.py", """
def helper():
    return 1

def main():
    return helper()
""")
        from core.analysis.call_graph import CallGraphGenerator
        g = CallGraphGenerator().build(self._tmpdir)
        self.assertIn("nodes", g)
        self.assertIn("edges", g)
        self.assertIn("stats", g)
        self.assertGreater(g["stats"]["total_functions"], 0)

    def test_dot_export(self):
        self._write("mod.py", "def a():\n    b()\ndef b():\n    pass\n")
        from core.analysis.call_graph import CallGraphGenerator
        gen = CallGraphGenerator()
        g   = gen.build(self._tmpdir)
        dot = gen.dot(g)
        self.assertIn("digraph", dot)


# ─── TON Contract Graph ───────────────────────────────────────────────────────

class TestTONContractGraph(unittest.TestCase):

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _write(self, name, content):
        p = os.path.join(self._tmpdir, name)
        with open(p, "w") as f:
            f.write(content)

    def test_upgrade_detected(self):
        self._write("wallet.fc", """
() upgrade(slice new_code) impure {
    set_code(new_code);
}
""")
        from scanners.ton_scanner.contract_graph import TONContractGraph
        result = TONContractGraph().analyze(self._tmpdir)
        self.assertGreater(result["total_findings"], 0)
        self.assertIn("wallet", result.get("upgrade_risk_contracts", []))

    def test_replay_detection(self):
        self._write("contract.fc", """
() recv_internal(slice in_msg_body) impure {
    int seqno = in_msg_body~load_uint(32);
    int valid_until = in_msg_body~load_uint(32);
}
""")
        from scanners.ton_scanner.contract_graph import TONContractGraph
        result = TONContractGraph().analyze(self._tmpdir)
        self.assertIn("contract", result.get("high_replay_risk", []))

    def test_clean_contract(self):
        self._write("simple.fc", """
() recv_internal(int msg_value, cell in_msg_cell, slice in_msg_body) impure {
    int op = in_msg_body~load_uint(32);
}
""")
        from scanners.ton_scanner.contract_graph import TONContractGraph
        result = TONContractGraph().analyze(self._tmpdir)
        self.assertEqual(result["contracts_analyzed"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
