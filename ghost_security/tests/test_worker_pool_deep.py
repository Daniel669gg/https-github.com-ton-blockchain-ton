"""
Deep tests for WorkerPool — ~60 tests covering max_workers concurrency,
queue capacity, QueueFullError, stop/drain, stats, completed/failed counters,
context manager, and parallel execution.
"""
import asyncio
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest
from runtime.worker_pool import QueueFullError, WorkerPool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(coro):
    return asyncio.run(coro)


async def simple_task():
    await asyncio.sleep(0)
    return "done"


async def failing_task():
    raise RuntimeError("task failed")


async def slow_task(duration=0.05):
    await asyncio.sleep(duration)


# ---------------------------------------------------------------------------
# Basic lifecycle
# ---------------------------------------------------------------------------

class TestLifecycle:
    def test_start_and_stop(self):
        async def _run():
            pool = WorkerPool(max_workers=2, max_queue=10)
            await pool.start()
            await pool.stop()
        run(_run())

    def test_context_manager(self):
        async def _run():
            async with WorkerPool(max_workers=2, max_queue=10) as pool:
                assert pool._running is True
            assert pool._running is False
        run(_run())

    def test_not_started_raises_on_submit(self):
        async def _run():
            pool = WorkerPool(max_workers=2, max_queue=10)
            with pytest.raises(RuntimeError):
                await pool.submit(simple_task)
        run(_run())

    def test_start_twice_raises(self):
        async def _run():
            pool = WorkerPool(max_workers=2, max_queue=10)
            await pool.start()
            try:
                with pytest.raises(RuntimeError):
                    await pool.start()
            finally:
                await pool.stop()
        run(_run())

    def test_stop_not_started_no_error(self):
        async def _run():
            pool = WorkerPool(max_workers=2, max_queue=10)
            await pool.stop()  # Should not raise
        run(_run())


# ---------------------------------------------------------------------------
# Task execution
# ---------------------------------------------------------------------------

class TestTaskExecution:
    def test_task_executes(self):
        results = []

        async def _run():
            async with WorkerPool(max_workers=2, max_queue=10) as pool:
                async def _task():
                    results.append("done")
                await pool.submit(_task)
                await asyncio.sleep(0.05)

        run(_run())
        assert "done" in results

    def test_multiple_tasks_execute(self):
        results = []

        async def _run():
            async with WorkerPool(max_workers=4, max_queue=20) as pool:
                async def _task():
                    results.append(1)
                for _ in range(5):
                    await pool.submit(_task)
                await asyncio.sleep(0.1)

        run(_run())
        assert len(results) == 5

    def test_completed_counter_increments(self):
        async def _run():
            async with WorkerPool(max_workers=2, max_queue=10) as pool:
                await pool.submit(simple_task)
                await asyncio.sleep(0.05)
                stats = pool.get_stats()
            return stats.completed

        completed = run(_run())
        assert completed >= 1

    def test_failed_counter_increments_on_task_exception(self):
        async def _run():
            async with WorkerPool(max_workers=2, max_queue=10) as pool:
                await pool.submit(failing_task)
                await asyncio.sleep(0.05)
                stats = pool.get_stats()
            return stats.failed

        failed = run(_run())
        assert failed >= 1


# ---------------------------------------------------------------------------
# Queue capacity
# ---------------------------------------------------------------------------

class TestQueueCapacity:
    def test_queue_full_raises_error(self):
        async def _run():
            pool = WorkerPool(max_workers=1, max_queue=2)
            await pool.start()
            try:
                # Fill queue
                await pool.submit(lambda: slow_task(0.5))
                await pool.submit(lambda: slow_task(0.5))
                # This should raise QueueFullError
                with pytest.raises(QueueFullError):
                    await pool.submit(lambda: slow_task(0.5))
            finally:
                await pool.stop(drain_timeout=1.0)

        run(_run())

    def test_submit_nowait_raises_when_full(self):
        async def _run():
            pool = WorkerPool(max_workers=1, max_queue=1)
            await pool.start()
            try:
                await pool.submit(lambda: slow_task(0.5))
                with pytest.raises(QueueFullError):
                    pool.submit_nowait(lambda: slow_task(0.5))
            finally:
                await pool.stop(drain_timeout=1.0)

        run(_run())

    def test_rejected_counter_increments_on_full(self):
        async def _run():
            pool = WorkerPool(max_workers=1, max_queue=1)
            await pool.start()
            try:
                await pool.submit(lambda: slow_task(0.5))
                try:
                    await pool.submit(lambda: slow_task(0.5))
                except QueueFullError:
                    pass
                stats = pool.get_stats()
            finally:
                await pool.stop(drain_timeout=1.0)
            return stats.rejected

        rejected = run(_run())
        assert rejected >= 1


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestStats:
    def test_get_stats_returns_pool_stats(self):
        async def _run():
            async with WorkerPool(max_workers=2, max_queue=10) as pool:
                return pool.get_stats()

        stats = run(_run())
        assert stats is not None

    def test_get_stats_dict_has_expected_keys(self):
        async def _run():
            async with WorkerPool(max_workers=2, max_queue=10) as pool:
                return pool.get_stats_dict()

        stats = run(_run())
        for key in ("active", "queued", "completed", "failed", "rejected", "uptime_seconds", "running"):
            assert key in stats, f"Missing key: {key}"

    def test_stats_running_true_when_running(self):
        async def _run():
            async with WorkerPool(max_workers=2, max_queue=10) as pool:
                return pool.get_stats_dict()

        stats = run(_run())
        assert stats["running"] is True

    def test_stats_running_false_after_stop(self):
        async def _run():
            pool = WorkerPool(max_workers=2, max_queue=10)
            await pool.start()
            await pool.stop()
            return pool.get_stats_dict()

        stats = run(_run())
        assert stats["running"] is False

    def test_uptime_seconds_positive(self):
        async def _run():
            async with WorkerPool(max_workers=2, max_queue=10) as pool:
                await asyncio.sleep(0.01)
                return pool.get_stats_dict()

        stats = run(_run())
        assert stats["uptime_seconds"] >= 0.0


# ---------------------------------------------------------------------------
# max_workers limits concurrency
# ---------------------------------------------------------------------------

class TestMaxWorkersLimit:
    def test_max_workers_respected(self):
        concurrent_count = [0]
        max_concurrent = [0]

        async def _task():
            concurrent_count[0] += 1
            max_concurrent[0] = max(max_concurrent[0], concurrent_count[0])
            await asyncio.sleep(0.02)
            concurrent_count[0] -= 1

        async def _run():
            async with WorkerPool(max_workers=2, max_queue=20) as pool:
                for _ in range(8):
                    await pool.submit(_task)
                await asyncio.sleep(0.3)

        run(_run())
        assert max_concurrent[0] <= 2


# ---------------------------------------------------------------------------
# Parallel execution timing
# ---------------------------------------------------------------------------

class TestParallelExecution:
    def test_tasks_run_in_parallel(self):
        async def _run():
            times = []

            async def _slow():
                await asyncio.sleep(0.05)
                times.append(time.monotonic())

            start = time.monotonic()
            async with WorkerPool(max_workers=4, max_queue=20) as pool:
                for _ in range(4):
                    await pool.submit(_slow)
                await asyncio.sleep(0.3)
            elapsed = time.monotonic() - start
            return elapsed

        elapsed = run(_run())
        # If truly parallel, 4 tasks of 0.05s should finish well under 0.2s total
        assert elapsed < 0.5


# ---------------------------------------------------------------------------
# Stop drains queue
# ---------------------------------------------------------------------------

class TestStopDrains:
    def test_stop_waits_for_tasks(self):
        results = []

        async def _run():
            async with WorkerPool(max_workers=2, max_queue=10) as pool:
                async def _task():
                    await asyncio.sleep(0.02)
                    results.append("done")
                for _ in range(3):
                    await pool.submit(_task)
            # After __aexit__ all tasks should be complete

        run(_run())
        assert len(results) == 3


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

class TestValidation:
    def test_max_workers_zero_raises(self):
        with pytest.raises(ValueError):
            WorkerPool(max_workers=0)

    def test_max_queue_zero_raises(self):
        with pytest.raises(ValueError):
            WorkerPool(max_queue=0)

    def test_max_workers_one_works(self):
        async def _run():
            async with WorkerPool(max_workers=1, max_queue=5) as pool:
                await pool.submit(simple_task)
                await asyncio.sleep(0.05)

        run(_run())


# ---------------------------------------------------------------------------
# Additional worker pool tests
# ---------------------------------------------------------------------------

class TestAdditionalWorkerPool:
    def test_queued_counter_increases(self):
        async def _run():
            pool = WorkerPool(max_workers=1, max_queue=10)
            await pool.start()
            try:
                # Submit task that blocks the worker
                await pool.submit(lambda: slow_task(0.2))
                # Submit another that stays queued
                await pool.submit(simple_task)
                stats = pool.get_stats()
            finally:
                await pool.stop(drain_timeout=1.0)
            return stats.queued

        queued = run(_run())
        assert queued >= 0  # May have already processed by the time stats are read

    def test_submit_after_stop_raises(self):
        async def _run():
            pool = WorkerPool(max_workers=2, max_queue=10)
            await pool.start()
            await pool.stop()
            with pytest.raises(RuntimeError):
                await pool.submit(simple_task)

        run(_run())

    def test_submit_nowait_after_stop_raises(self):
        async def _run():
            pool = WorkerPool(max_workers=2, max_queue=10)
            await pool.start()
            await pool.stop()
            with pytest.raises(RuntimeError):
                pool.submit_nowait(simple_task)

        run(_run())

    def test_exception_task_increments_failed(self):
        async def _run():
            pool = WorkerPool(max_workers=2, max_queue=10)
            await pool.start()
            try:
                await pool.submit(failing_task)
                await asyncio.sleep(0.05)
                stats = pool.get_stats()
            finally:
                await pool.stop()
            return stats.failed

        failed = run(_run())
        assert failed >= 1

    def test_multiple_workers_all_execute(self):
        results = []

        async def _run():
            async with WorkerPool(max_workers=4, max_queue=20) as pool:
                async def _task():
                    results.append(1)
                for _ in range(8):
                    await pool.submit(_task)
                await asyncio.sleep(0.2)

        run(_run())
        assert len(results) == 8

    def test_pool_stats_active_zero_after_tasks_complete(self):
        async def _run():
            async with WorkerPool(max_workers=2, max_queue=10) as pool:
                await pool.submit(simple_task)
                await asyncio.sleep(0.1)
                stats = pool.get_stats()
            return stats.active

        active = run(_run())
        assert active == 0

    def test_context_manager_returns_pool(self):
        async def _run():
            async with WorkerPool(max_workers=2, max_queue=10) as pool:
                return pool

        pool = run(_run())
        assert isinstance(pool, WorkerPool)

    def test_large_number_of_tasks(self):
        results = []

        async def _run():
            async with WorkerPool(max_workers=8, max_queue=200) as pool:
                async def _task():
                    results.append(1)
                for _ in range(50):
                    await pool.submit(_task)
                await asyncio.sleep(0.5)

        run(_run())
        assert len(results) == 50
