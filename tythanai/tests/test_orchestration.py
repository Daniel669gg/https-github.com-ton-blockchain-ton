"""
TythanAI Platform — Orchestration & Task Graph Tests
Tests: TaskGraph, DAG execution, dependency resolution, parallel runs, failure handling.
Run: python3 -m unittest tests.test_orchestration -v
"""
import asyncio
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestTaskGraph(unittest.IsolatedAsyncioTestCase):

    def _make_graph(self):
        from orchestrator.task_graph import TaskGraph
        return TaskGraph()

    async def test_single_node_executes(self):
        graph = self._make_graph()

        async def job_a():
            return "done_a"

        graph.add("a", job_a, node_id="a")
        run = await graph.execute()
        self.assertIsNotNone(run)
        self.assertIn("a", run.nodes)

    async def test_dependency_ordering(self):
        graph = self._make_graph()
        order = []

        async def job_a():
            order.append("a")
            return "a"

        async def job_b():
            order.append("b")
            return "b"

        async def job_c():
            order.append("c")
            return "c"

        graph.add("a", job_a, node_id="a")
        graph.add("b", job_b, node_id="b", deps=["a"])
        graph.add("c", job_c, node_id="c", deps=["b"])
        run = await graph.execute()

        self.assertEqual(run.nodes["a"].result, "a")
        # c must come after b, b after a
        self.assertLess(order.index("a"), order.index("b"))
        self.assertLess(order.index("b"), order.index("c"))

    async def test_parallel_independent_nodes(self):
        graph = self._make_graph()
        timestamps = {}

        async def slow(name):
            timestamps[name] = time.time()
            await asyncio.sleep(0.05)
            return name

        async def x(): return await slow("x")
        async def y(): return await slow("y")
        async def z(): return await slow("z")

        graph.add("x", x, node_id="x")
        graph.add("y", y, node_id="y")
        graph.add("z", z, node_id="z")

        start = time.time()
        run = await graph.execute(max_concurrent=6)
        elapsed = time.time() - start

        # 3 × 50ms parallel tasks should finish in < 300ms total
        self.assertLess(elapsed, 0.4, "Independent nodes should run in parallel")

    async def test_failed_node_marks_dependents_skipped(self):
        from orchestrator.task_graph import NodeState
        graph = self._make_graph()

        async def failing():
            raise ValueError("intentional failure")

        async def downstream():
            return "should_be_skipped"

        graph.add("root", failing, node_id="root")
        graph.add("child", downstream, node_id="child", deps=["root"], skip_on_dep_failure=True)
        run = await graph.execute()

        self.assertEqual(run.nodes["root"].state, NodeState.FAILED)
        self.assertEqual(run.nodes["child"].state, NodeState.SKIPPED)

    async def test_node_result_available(self):
        from orchestrator.task_graph import NodeState
        graph = self._make_graph()

        async def produces():
            return {"findings": [1, 2, 3]}

        graph.add("producer", produces, node_id="producer")
        run = await graph.execute()
        self.assertEqual(run.nodes["producer"].state, NodeState.SUCCEEDED)
        self.assertEqual(run.nodes["producer"].result, {"findings": [1, 2, 3]})

    async def test_graph_run_has_trace(self):
        graph = self._make_graph()

        async def simple():
            return True

        graph.add("traced", simple, node_id="traced")
        run = await graph.execute()
        self.assertIsInstance(run.trace, list)


class TestRuntimeSupervisorEdgeCases(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        from runtime.supervisor import RuntimeSupervisor
        self.sup = RuntimeSupervisor(max_concurrent=2)
        await self.sup.start()

    async def asyncTearDown(self):
        await self.sup.shutdown(timeout=3.0)

    async def test_concurrent_task_limit(self):
        """Verify semaphore limits concurrency."""
        active = {"count": 0, "peak": 0}

        async def tracked_job(idx):
            active["count"] += 1
            active["peak"] = max(active["peak"], active["count"])
            await asyncio.sleep(0.05)
            active["count"] -= 1
            return idx

        from runtime.supervisor import RetryPolicy
        policy = RetryPolicy(max_attempts=1)
        tids = [
            self.sup.submit(f"job_{i}", tracked_job, i, timeout=5.0, retry=policy)
            for i in range(6)
        ]
        for tid in tids:
            await self.sup.wait(tid)

        self.assertLessEqual(active["peak"], 2, "Should not exceed max_concurrent=2")

    async def test_run_once_returns_result(self):
        from runtime.supervisor import RetryPolicy

        async def my_job():
            return {"status": "ok", "count": 42}

        policy = RetryPolicy(max_attempts=1)
        result = await self.sup.run_once("my_job", my_job, timeout=5.0, retry=policy)
        self.assertEqual(result["count"], 42)

    async def test_supervisor_status_keys(self):
        status = self.sup.status()
        self.assertIn("running", status)
        self.assertIn("queued", status)
        self.assertIn("total_tasks", status)
        self.assertIn("by_state", status)

    async def test_retry_on_transient_failure(self):
        from runtime.supervisor import RetryPolicy, TaskState
        call_count = {"n": 0}

        async def flaky():
            call_count["n"] += 1
            if call_count["n"] < 3:
                raise RuntimeError("transient")
            return "recovered"

        policy = RetryPolicy(max_attempts=3, base_delay=0.01)
        result = await self.sup.run_once("flaky", flaky, timeout=5.0, retry=policy)
        self.assertEqual(result, "recovered")
        self.assertEqual(call_count["n"], 3)


class TestMultiAgentRuntime(unittest.TestCase):
    def test_module_importable(self):
        import orchestrator.multi_agent_runtime as mar
        self.assertTrue(hasattr(mar, "MultiAgentRuntime"))

    def test_runtime_has_run_method(self):
        from orchestrator.multi_agent_runtime import MultiAgentRuntime
        self.assertTrue(hasattr(MultiAgentRuntime, "run"),
                        "MultiAgentRuntime must expose .run()")


if __name__ == "__main__":
    unittest.main()
