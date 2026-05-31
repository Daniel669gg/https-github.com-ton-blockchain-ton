"""
TythanAI Platform — Runtime Hardening Tests
Stress and isolation tests for:
  - TaskStore (SQLite-backed task persistence)
  - ExecutionIsolator (subprocess-based scanner isolation)
  - RuntimeSupervisor (stress: 20 concurrent tasks, crash recovery, deadlock detection)

Run:
    python3 -m pytest tests/test_runtime_hardening.py -v
    python3 -m unittest tests.test_runtime_hardening -v
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time
import unittest

# Ensure the project root is on the path when running tests directly.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ─── TaskStore (task persistence) ─────────────────────────────────────────────

class TestTaskPersistence(unittest.TestCase):
    """SQLite-backed task persistence — unit tests."""

    def setUp(self):
        from core.runtime.task_persistence import TaskStore
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._tmp.close()
        self.store = TaskStore(db_path=self._tmp.name)

    def tearDown(self):
        try:
            os.unlink(self._tmp.name)
        except OSError:
            pass

    # ── DB auto-creation ──────────────────────────────────────────────────────

    def test_db_autocreated_on_new_path(self):
        """TaskStore creates the DB file (and parent dirs) when they do not exist."""
        from core.runtime.task_persistence import TaskStore
        with tempfile.TemporaryDirectory() as td:
            db_path = os.path.join(td, "nested", "subdir", "tasks.db")
            store = TaskStore(db_path=db_path)
            # The file must now exist and be a valid SQLite DB.
            self.assertTrue(os.path.isfile(db_path))
            # Prove it is queryable.
            self.assertEqual(store.list_tasks(), [])

    # ── save_task / load_task ─────────────────────────────────────────────────

    def test_save_and_load_roundtrip(self):
        """A saved task can be retrieved by task_id."""
        self.store.save_task(
            task_id="abc123",
            name="scan_repo",
            state="pending",
            payload={"path": "/tmp/repo", "depth": 3},
        )
        task = self.store.load_task("abc123")
        self.assertIsNotNone(task)
        self.assertEqual(task["task_id"], "abc123")
        self.assertEqual(task["name"], "scan_repo")
        self.assertEqual(task["state"], "pending")

    def test_load_nonexistent_returns_none(self):
        """load_task returns None for an unknown task_id."""
        result = self.store.load_task("does_not_exist")
        self.assertIsNone(result)

    def test_save_overwrites_existing_task(self):
        """Saving twice with the same task_id replaces the row (UPSERT)."""
        self.store.save_task("dup", "first_name", "pending")
        self.store.save_task("dup", "second_name", "succeeded", result={"ok": True})
        task = self.store.load_task("dup")
        self.assertEqual(task["name"], "second_name")
        self.assertEqual(task["state"], "succeeded")

    def test_save_with_result_and_error(self):
        """Result and error fields are persisted and retrieved correctly."""
        self.store.save_task(
            "t_err",
            "failing_scan",
            "failed",
            error="Connection refused",
            finished_at=time.time(),
        )
        task = self.store.load_task("t_err")
        self.assertEqual(task["error"], "Connection refused")
        self.assertIsNotNone(task["finished_at"])

    def test_timestamps_default_to_now(self):
        """created_at is set automatically when omitted."""
        before = time.time()
        self.store.save_task("ts_check", "ts_task", "pending")
        after = time.time()
        task = self.store.load_task("ts_check")
        self.assertGreaterEqual(task["created_at"], before)
        self.assertLessEqual(task["created_at"], after)

    # ── JSON serialisation roundtrip ──────────────────────────────────────────

    def test_payload_json_roundtrip_nested(self):
        """Nested dict/list payload survives JSON serialisation."""
        payload = {
            "targets": ["host1", "host2"],
            "options": {"deep": True, "level": 5},
            "meta": None,
        }
        self.store.save_task("json1", "json_test", "pending", payload=payload)
        task = self.store.load_task("json1")
        self.assertEqual(task["payload"], payload)

    def test_result_json_roundtrip(self):
        """Result with nested structure survives JSON serialisation."""
        result = {
            "findings": [{"type": "sqli", "severity": "HIGH", "line": 42}],
            "scanned_files": 128,
            "duration_ms": 450,
        }
        self.store.save_task(
            "json2", "json_result", "succeeded",
            result=result, finished_at=time.time(),
        )
        task = self.store.load_task("json2")
        self.assertEqual(task["result"], result)

    def test_payload_list_roundtrip(self):
        """List-valued payload survives JSON serialisation."""
        payload = [1, "two", {"three": 3}]
        self.store.save_task("list_pay", "list_payload_task", "pending", payload=payload)
        task = self.store.load_task("list_pay")
        self.assertEqual(task["payload"], payload)

    def test_null_payload_stored_as_empty_dict(self):
        """When payload is omitted, the row stores an empty dict."""
        self.store.save_task("null_pay", "null_payload_task", "pending")
        task = self.store.load_task("null_pay")
        # The schema defaults to '{}', so the decoded value must be dict-like.
        self.assertIsInstance(task["payload"], dict)

    # ── list_tasks ────────────────────────────────────────────────────────────

    def test_list_tasks_all(self):
        """list_tasks() returns all saved tasks."""
        for i in range(5):
            self.store.save_task(f"list_{i}", f"task_{i}", "pending")
        tasks = self.store.list_tasks()
        self.assertEqual(len(tasks), 5)

    def test_list_tasks_filtered_by_state(self):
        """list_tasks(state=...) returns only tasks in that state."""
        self.store.save_task("s1", "s1", "succeeded")
        self.store.save_task("s2", "s2", "succeeded")
        self.store.save_task("f1", "f1", "failed")
        succeeded = self.store.list_tasks(state="succeeded")
        failed    = self.store.list_tasks(state="failed")
        self.assertEqual(len(succeeded), 2)
        self.assertEqual(len(failed), 1)
        self.assertTrue(all(t["state"] == "succeeded" for t in succeeded))

    def test_list_tasks_limit(self):
        """list_tasks(limit=N) returns at most N rows."""
        for i in range(10):
            self.store.save_task(f"lim_{i}", f"lim_{i}", "pending")
        tasks = self.store.list_tasks(limit=3)
        self.assertLessEqual(len(tasks), 3)

    def test_list_tasks_empty_store(self):
        """list_tasks() on an empty store returns an empty list."""
        self.assertEqual(self.store.list_tasks(), [])

    def test_list_tasks_newest_first(self):
        """list_tasks() orders results newest-first (by created_at DESC)."""
        t0 = time.time()
        self.store.save_task("old_task", "old", "pending", created_at=t0 - 100)
        self.store.save_task("new_task", "new", "pending", created_at=t0)
        tasks = self.store.list_tasks()
        self.assertEqual(tasks[0]["task_id"], "new_task")

    # ── cleanup_old ───────────────────────────────────────────────────────────

    def test_cleanup_old_removes_stale_rows(self):
        """cleanup_old(days=1) removes rows older than 1 day; leaves recent rows."""
        old_ts   = time.time() - 2 * 86400   # 2 days ago  → should be deleted
        fresh_ts = time.time()                # just now    → should survive
        self.store.save_task("stale", "stale_task", "succeeded", created_at=old_ts)
        self.store.save_task("fresh", "fresh_task", "pending",   created_at=fresh_ts)
        deleted = self.store.cleanup_old(days=1)
        # The 2-day-old row should be gone; the row created right now must remain.
        self.assertGreaterEqual(deleted, 1)
        self.assertIsNone(self.store.load_task("stale"))
        self.assertIsNotNone(self.store.load_task("fresh"))

    def test_cleanup_old_thirty_days_default(self):
        """cleanup_old(days=30) leaves recently-created rows intact."""
        self.store.save_task("recent", "recent_task", "succeeded")
        deleted = self.store.cleanup_old(days=30)
        self.assertEqual(deleted, 0)
        self.assertIsNotNone(self.store.load_task("recent"))

    def test_cleanup_old_returns_count(self):
        """cleanup_old returns the integer number of rows deleted."""
        old_ts = time.time() - 3600  # 1 hour ago
        self.store.save_task("o1", "o1", "succeeded", created_at=old_ts)
        self.store.save_task("o2", "o2", "failed",    created_at=old_ts)
        deleted = self.store.cleanup_old(days=0)
        self.assertEqual(deleted, 2)

    # ── stats ─────────────────────────────────────────────────────────────────

    def test_stats_empty_store(self):
        """stats() on an empty store returns an empty dict."""
        self.assertEqual(self.store.stats(), {})

    def test_stats_counts_by_state(self):
        """stats() returns per-state counts."""
        self.store.save_task("st1", "t1", "succeeded")
        self.store.save_task("st2", "t2", "succeeded")
        self.store.save_task("st3", "t3", "failed")
        self.store.save_task("st4", "t4", "pending")
        s = self.store.stats()
        self.assertEqual(s.get("succeeded"), 2)
        self.assertEqual(s.get("failed"), 1)
        self.assertEqual(s.get("pending"), 1)

    def test_stats_all_states(self):
        """stats() handles all canonical task states without error."""
        states = ["pending", "running", "retrying", "succeeded", "failed", "cancelled", "timeout"]
        for i, state in enumerate(states):
            self.store.save_task(f"s{i}", f"task_{state}", state)
        s = self.store.stats()
        for state in states:
            self.assertIn(state, s)
            self.assertEqual(s[state], 1)

    # ── thread-safety ─────────────────────────────────────────────────────────

    def test_concurrent_writes_are_safe(self):
        """Multiple threads writing simultaneously must not corrupt the DB."""
        import threading

        errors: list = []

        def writer(idx: int) -> None:
            try:
                for j in range(10):
                    self.store.save_task(
                        f"thr_{idx}_{j}",
                        f"thr_task_{idx}_{j}",
                        "pending",
                        payload={"idx": idx, "j": j},
                    )
            except Exception as exc:
                errors.append(str(exc))

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], msg=f"Thread errors: {errors}")
        # 8 threads × 10 writes = 80 rows
        tasks = self.store.list_tasks(limit=200)
        self.assertEqual(len(tasks), 80)


# ─── ExecutionIsolator ────────────────────────────────────────────────────────

class TestExecutionIsolator(unittest.IsolatedAsyncioTestCase):
    """Subprocess-isolation tests for ExecutionIsolator."""

    def setUp(self):
        from runtime.execution_isolator import ExecutionIsolator, ResourceLimits
        self.ExecutionIsolator = ExecutionIsolator
        self.ResourceLimits    = ResourceLimits
        self.iso = ExecutionIsolator()

    # ── ResourceLimits dataclass ──────────────────────────────────────────────

    def test_resource_limits_defaults(self):
        """ResourceLimits has expected default values."""
        limits = self.ResourceLimits()
        self.assertEqual(limits.max_memory_mb, 512)
        self.assertEqual(limits.timeout, 120.0)

    def test_resource_limits_custom(self):
        """ResourceLimits accepts custom values."""
        limits = self.ResourceLimits(max_memory_mb=256, timeout=30.0)
        self.assertEqual(limits.max_memory_mb, 256)
        self.assertEqual(limits.timeout, 30.0)

    # ── run_isolated (sync) ───────────────────────────────────────────────────

    def test_run_isolated_success(self):
        """run_isolated returns success=True and the function's return value."""
        result = self.iso.run_isolated("os.getenv", {"key": "HOME"}, timeout=10.0)
        self.assertTrue(result["success"])
        self.assertIn("result", result)
        self.assertIn("duration", result)
        self.assertIsInstance(result["duration"], float)
        self.assertGreaterEqual(result["duration"], 0.0)

    def test_run_isolated_returns_none_for_missing_env(self):
        """run_isolated correctly passes back a None return value."""
        result = self.iso.run_isolated(
            "os.getenv", {"key": "_GHOST_TEST_VAR_NOT_SET_XYZ"}, timeout=10.0
        )
        self.assertTrue(result["success"])
        self.assertIsNone(result["result"])

    def test_run_isolated_json_roundtrip(self):
        """run_isolated returns JSON-serialisable values correctly."""
        result = self.iso.run_isolated("json.dumps", {"obj": {"a": 1, "b": [2, 3]}}, timeout=10.0)
        self.assertTrue(result["success"])
        # json.dumps returns a string; parse it back to verify structure.
        parsed = json.loads(result["result"])
        self.assertEqual(parsed["a"], 1)
        self.assertEqual(parsed["b"], [2, 3])

    def test_run_isolated_error_handling(self):
        """run_isolated returns success=False and an error message on ImportError."""
        result = self.iso.run_isolated(
            "totally_nonexistent_module_xyz.some_fn", {}, timeout=10.0
        )
        self.assertFalse(result["success"])
        self.assertIn("error", result)
        self.assertIsInstance(result["error"], str)
        self.assertGreater(len(result["error"]), 0)

    def test_run_isolated_bad_fn_path_error(self):
        """run_isolated returns success=False for a bad dotted path."""
        result = self.iso.run_isolated(
            "os.totally_nonexistent_function_abc", {}, timeout=10.0
        )
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    def test_run_isolated_timeout_enforced(self):
        """run_isolated kills the subprocess and returns success=False on timeout."""
        # _ghost_spin is guaranteed not to exist, so this will fail immediately;
        # use a Python one-liner via the operator module as a proxy for timeout.
        # We test true timeout by using a very tight timeout on a subprocess that
        # definitely takes longer to start than the limit.
        result = self.iso.run_isolated("os.getenv", {"key": "HOME"}, timeout=0.0001)
        # Either times out (expected) or fails for another reason; must not succeed.
        # On an extremely fast system a 0.0001s timeout is effectively 0 — the
        # subprocess cannot possibly finish in time.
        self.assertFalse(result["success"])
        self.assertIn("duration", result)

    def test_run_isolated_duration_is_measured(self):
        """duration field reflects real elapsed time."""
        result = self.iso.run_isolated("os.getenv", {"key": "HOME"}, timeout=10.0)
        # We only require it to be a non-negative float, not an exact value.
        self.assertIsInstance(result["duration"], float)
        self.assertGreaterEqual(result["duration"], 0.0)

    def test_run_isolated_uses_limits_timeout_as_default(self):
        """When timeout is omitted, it falls back to ResourceLimits.timeout."""
        limits = self.ResourceLimits(timeout=10.0)
        iso = self.ExecutionIsolator(limits=limits)
        result = iso.run_isolated("os.getenv", {"key": "HOME"})
        self.assertTrue(result["success"])

    # ── run_isolated_async ────────────────────────────────────────────────────

    async def test_run_isolated_async_success(self):
        """run_isolated_async returns the same shape as the sync version."""
        result = await self.iso.run_isolated_async("os.getenv", {"key": "HOME"}, timeout=10.0)
        self.assertTrue(result["success"])
        self.assertIn("result", result)
        self.assertIn("duration", result)
        self.assertIsInstance(result["duration"], float)

    async def test_run_isolated_async_json_result(self):
        """Async path correctly deserialises the subprocess JSON output."""
        result = await self.iso.run_isolated_async(
            "json.dumps", {"obj": {"x": 99}}, timeout=10.0
        )
        self.assertTrue(result["success"])
        self.assertEqual(json.loads(result["result"]), {"x": 99})

    async def test_run_isolated_async_error(self):
        """run_isolated_async propagates subprocess errors correctly."""
        result = await self.iso.run_isolated_async(
            "ghost_not_a_real_module.fn", {}, timeout=10.0
        )
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    async def test_run_isolated_async_timeout_enforced(self):
        """run_isolated_async kills the subprocess on timeout."""
        result = await self.iso.run_isolated_async(
            "os.getenv", {"key": "HOME"}, timeout=0.0001
        )
        self.assertFalse(result["success"])
        self.assertIn("duration", result)

    async def test_run_isolated_async_parallel(self):
        """Multiple concurrent async calls all complete independently."""
        coros = [
            self.iso.run_isolated_async("os.getenv", {"key": "HOME"}, timeout=10.0)
            for _ in range(5)
        ]
        results = await asyncio.gather(*coros)
        self.assertEqual(len(results), 5)
        for r in results:
            self.assertTrue(r["success"], msg=f"Unexpected failure: {r}")

    # ── result dict shape contract ────────────────────────────────────────────

    def test_success_result_has_required_keys(self):
        """Success dict always has 'success', 'result', 'duration'."""
        r = self.iso.run_isolated("os.getenv", {"key": "HOME"}, timeout=10.0)
        self.assertIn("success", r)
        self.assertIn("result",  r)
        self.assertIn("duration", r)

    def test_failure_result_has_required_keys(self):
        """Failure dict always has 'success', 'error', 'duration'."""
        r = self.iso.run_isolated("no_module.fn", {}, timeout=10.0)
        self.assertIn("success",  r)
        self.assertIn("error",    r)
        self.assertIn("duration", r)
        self.assertFalse(r["success"])


# ─── RuntimeSupervisor stress tests ───────────────────────────────────────────

class TestSupervisorStress(unittest.IsolatedAsyncioTestCase):
    """Stress and reliability tests for RuntimeSupervisor."""

    async def asyncSetUp(self):
        from runtime.supervisor import RuntimeSupervisor, RetryPolicy
        # Fast retries for stress tests; single attempt where crashes are expected.
        self.RetryPolicy = RetryPolicy
        self.sup = RuntimeSupervisor(
            max_concurrent=4,
            default_retry=RetryPolicy(max_attempts=1, base_delay=0.001),
        )
        await self.sup.start()

    async def asyncTearDown(self):
        await self.sup.shutdown(timeout=10.0)

    # ── 20 concurrent tasks ───────────────────────────────────────────────────

    async def test_concurrent_20_tasks(self):
        """Submit 20 tasks concurrently; all must complete successfully."""
        from runtime.supervisor import TaskState

        results_bag: dict[int, int] = {}

        async def compute(n: int) -> int:
            await asyncio.sleep(0.005)
            return n * 2

        # Submit all 20 before awaiting any.
        tids = [self.sup.submit(f"c20_{i}", compute, i) for i in range(20)]

        # Await completion of every task concurrently to avoid serial bottleneck.
        supervised_tasks = await asyncio.gather(
            *[self.sup.wait(tid, poll=0.02) for tid in tids]
        )

        succeeded = [t for t in supervised_tasks if t.state == TaskState.SUCCEEDED]
        self.assertEqual(
            len(succeeded), 20,
            msg=f"Expected 20 successes; got {len(succeeded)}. "
                f"Failed: {[t.error for t in supervised_tasks if t.state != TaskState.SUCCEEDED]}",
        )
        # Verify the arithmetic is correct for each.
        for st in succeeded:
            # The argument N is embedded in the task name "c20_<N>".
            n = int(st.name.split("_")[-1])
            self.assertEqual(st.result, n * 2)

    async def test_concurrent_20_tasks_all_complete(self):
        """All 20 tasks reach a terminal state (no tasks stuck in PENDING/RUNNING)."""
        from runtime.supervisor import TaskState
        _TERMINAL = {TaskState.SUCCEEDED, TaskState.FAILED, TaskState.CANCELLED, TaskState.TIMEOUT}

        async def noop(i: int) -> str:
            await asyncio.sleep(0.001)
            return f"done_{i}"

        tids = [self.sup.submit(f"noop_{i}", noop, i) for i in range(20)]
        sts = await asyncio.gather(*[self.sup.wait(tid, poll=0.02) for tid in tids])

        non_terminal = [t for t in sts if t.state not in _TERMINAL]
        self.assertEqual(non_terminal, [])

    # ── crash recovery ────────────────────────────────────────────────────────

    async def test_supervisor_recovers_after_worker_crash(self):
        """
        A task that raises an unhandled exception must not stop the supervisor.
        Subsequent tasks submitted after the crash must succeed.
        """
        from runtime.supervisor import TaskState

        async def crashing_job():
            raise RuntimeError("deliberate crash in worker")

        async def healthy_job(x: int) -> int:
            return x + 1

        # First: crash one task.
        crash_policy = self.RetryPolicy(max_attempts=1, base_delay=0.001)
        tid_crash = self.sup.submit("crash_task", crashing_job, retry=crash_policy)
        st_crash  = await self.sup.wait(tid_crash, poll=0.02)
        self.assertEqual(st_crash.state, TaskState.FAILED)
        self.assertIn("deliberate crash", st_crash.error)

        # Supervisor must still be running.
        self.assertTrue(self.sup._running)

        # Submit 5 healthy tasks after the crash; all must succeed.
        tids = [self.sup.submit(f"post_crash_{i}", healthy_job, i) for i in range(5)]
        sts  = await asyncio.gather(*[self.sup.wait(tid, poll=0.02) for tid in tids])
        for i, st in enumerate(sts):
            self.assertEqual(st.state, TaskState.SUCCEEDED, msg=f"post-crash task {i} failed: {st.error}")
            self.assertEqual(st.result, i + 1)

    async def test_supervisor_recovers_after_multiple_crashes(self):
        """Multiple crashing tasks in succession do not degrade the supervisor."""
        from runtime.supervisor import TaskState

        crash_policy = self.RetryPolicy(max_attempts=1, base_delay=0.001)

        async def always_crash(msg: str):
            raise ValueError(msg)

        async def ok_job() -> bool:
            return True

        crash_tids = [
            self.sup.submit(f"mc_{i}", always_crash, f"crash_{i}", retry=crash_policy)
            for i in range(6)
        ]
        ok_tid = self.sup.submit("after_crashes", ok_job)

        crash_sts = await asyncio.gather(*[self.sup.wait(t, poll=0.02) for t in crash_tids])
        ok_st     = await self.sup.wait(ok_tid, poll=0.02)

        for st in crash_sts:
            self.assertEqual(st.state, TaskState.FAILED)
        self.assertEqual(ok_st.state, TaskState.SUCCEEDED)
        self.assertTrue(ok_st.result)
        self.assertTrue(self.sup._running)

    # ── no-deadlock under saturation ──────────────────────────────────────────

    async def test_no_deadlock_under_saturation(self):
        """
        Filling the queue to max_concurrent*3 (= 12) must fully drain without
        deadlock or tasks stuck in PENDING indefinitely.
        """
        from runtime.supervisor import TaskState

        n = self.sup._max_concurrent * 3  # 12

        async def payload(i: int) -> int:
            await asyncio.sleep(0.005)
            return i

        tids = [self.sup.submit(f"sat_{i}", payload, i) for i in range(n)]

        # Wait for all; generous timeout to avoid false positives on slow CI.
        sts = await asyncio.gather(
            *[self.sup.wait(tid, poll=0.02) for tid in tids],
            return_exceptions=False,
        )

        failed = [t for t in sts if t.state != TaskState.SUCCEEDED]
        self.assertEqual(
            failed, [],
            msg=f"Some tasks did not succeed: {[(t.name, t.state, t.error) for t in failed]}",
        )

    async def test_no_deadlock_rapid_sequential_flood(self):
        """
        Repeatedly flooding the queue in waves must drain each wave without
        stalling.  Three waves of max_concurrent*2 tasks each.
        """
        from runtime.supervisor import TaskState

        wave_size = self.sup._max_concurrent * 2  # 8

        async def quick(i: int) -> int:
            await asyncio.sleep(0.002)
            return i

        for wave in range(3):
            tids = [self.sup.submit(f"w{wave}_{i}", quick, i) for i in range(wave_size)]
            sts  = await asyncio.gather(*[self.sup.wait(tid, poll=0.02) for tid in tids])
            failed = [t for t in sts if t.state != TaskState.SUCCEEDED]
            self.assertEqual(failed, [], msg=f"Wave {wave} had failures: {failed}")

    # ── supervisor status contract ────────────────────────────────────────────

    async def test_status_reflects_running(self):
        """status() reports running=True while the supervisor is active."""
        s = self.sup.status()
        self.assertTrue(s["running"])
        self.assertIn("total_tasks", s)
        self.assertIn("by_state",    s)
        self.assertIn("workers",     s)

    async def test_status_after_tasks_complete(self):
        """After tasks complete, status shows them under 'succeeded' state."""
        from runtime.supervisor import TaskState

        async def fast() -> int:
            return 42

        tid = self.sup.submit("status_check", fast)
        await self.sup.wait(tid, poll=0.02)

        s = self.sup.status()
        self.assertGreaterEqual(s.get("total_tasks", 0), 1)
        by_state = s.get("by_state", {})
        self.assertGreaterEqual(by_state.get(TaskState.SUCCEEDED, 0), 1)

    async def test_list_tasks_by_state(self):
        """list_tasks(state=SUCCEEDED) returns only succeeded tasks."""
        from runtime.supervisor import TaskState

        async def job() -> str:
            return "result"

        tids = [self.sup.submit(f"lt_{i}", job) for i in range(4)]
        await asyncio.gather(*[self.sup.wait(t, poll=0.02) for t in tids])

        all_tasks       = self.sup.list_tasks()
        succeeded_tasks = self.sup.list_tasks(state=TaskState.SUCCEEDED)

        self.assertGreaterEqual(len(all_tasks), 4)
        self.assertGreaterEqual(len(succeeded_tasks), 4)
        for t in succeeded_tasks:
            self.assertEqual(t["state"], TaskState.SUCCEEDED)

    # ── retry integration ─────────────────────────────────────────────────────

    async def test_task_exhausts_retries_then_fails(self):
        """A task that always fails must reach FAILED after max_attempts."""
        from runtime.supervisor import TaskState

        async def always_fail():
            raise RuntimeError("always fails")

        policy = self.RetryPolicy(max_attempts=3, base_delay=0.001)
        tid = self.sup.submit("retry_exhaust", always_fail, retry=policy)
        st  = await self.sup.wait(tid, poll=0.02)

        self.assertEqual(st.state, TaskState.FAILED)
        self.assertEqual(st.attempts, 3)
        self.assertIn("always fails", st.error)

    async def test_task_succeeds_on_second_attempt(self):
        """A task that fails once then succeeds must land in SUCCEEDED state."""
        from runtime.supervisor import TaskState

        call_counter = {"n": 0}

        async def flaky() -> str:
            call_counter["n"] += 1
            if call_counter["n"] < 2:
                raise RuntimeError("transient error")
            return "recovered"

        policy = self.RetryPolicy(max_attempts=2, base_delay=0.001)
        tid = self.sup.submit("flaky_task", flaky, retry=policy)
        st  = await self.sup.wait(tid, poll=0.02)

        self.assertEqual(st.state, TaskState.SUCCEEDED)
        self.assertEqual(st.result, "recovered")
        self.assertEqual(st.attempts, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
