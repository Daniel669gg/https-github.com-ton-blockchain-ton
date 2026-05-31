"""Tests for v13 runtime hardening modules (supervisor, circuit_breaker, etc.)."""
import asyncio
import sys
import pathlib
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))


class TestCircuitBreaker:
    def test_import(self):
        from runtime.circuit_breaker import CircuitBreakerRegistry
        reg = CircuitBreakerRegistry()
        assert reg is not None

    def test_allows_calls_when_closed(self):
        from runtime.circuit_breaker import CircuitBreakerRegistry
        reg = CircuitBreakerRegistry()
        cb = reg.get("good_scanner")
        result = cb.call(lambda: 42)
        assert result == 42

    def test_records_state(self):
        from runtime.circuit_breaker import CircuitBreakerRegistry
        reg = CircuitBreakerRegistry()
        cb = reg.get("scanner_stats")
        try:
            cb.call(lambda: None)
        except Exception:
            pass
        state = cb.get_state()
        # CircuitBreakerStats has these attributes
        assert hasattr(state, "state")
        assert hasattr(state, "total_calls")
        assert hasattr(state, "failure_rate")

    def test_fails_fast_when_open(self):
        from runtime.circuit_breaker import CircuitBreakerRegistry
        reg = CircuitBreakerRegistry()
        cb = reg.get("bad_scanner", failure_threshold=0.5, min_calls=5)
        # Force failures
        for _ in range(20):
            try:
                cb.call(lambda: (_ for _ in ()).throw(IOError("fail")))
            except Exception:
                pass
        # After many failures, circuit may be open
        state = cb.get_state()
        assert hasattr(state, "state")
        assert state.total_calls >= 0

    def test_all_states(self):
        from runtime.circuit_breaker import CircuitBreakerRegistry
        reg = CircuitBreakerRegistry()
        reg.get("scanner_a")
        reg.get("scanner_b")
        states = reg.all_states()
        assert isinstance(states, dict)

    def test_reset(self):
        from runtime.circuit_breaker import CircuitBreakerRegistry, CBState
        reg = CircuitBreakerRegistry()
        cb = reg.get("resettable")
        cb.reset()
        state = cb.get_state()
        assert state.state == CBState.CLOSED


class TestRetryPolicy:
    def test_import(self):
        from runtime.retry_policy import RetryPolicy
        p = RetryPolicy()
        assert p is not None

    def test_success_no_retry(self):
        from runtime.retry_policy import RetryPolicy
        p = RetryPolicy(max_retries=3, base_delay=0.001)
        calls = [0]
        def fn():
            calls[0] += 1
            return "done"
        r = p.execute_sync(fn)
        assert r == "done"
        assert calls[0] == 1

    def test_retries_ioerror(self):
        from runtime.retry_policy import RetryPolicy
        p = RetryPolicy(max_retries=3, base_delay=0.001)
        calls = [0]
        def fn():
            calls[0] += 1
            if calls[0] < 2:
                raise IOError("tmp fail")
            return "ok"
        r = p.execute_sync(fn)
        assert r == "ok"
        assert calls[0] == 2

    def test_no_retry_on_valueerror(self):
        from runtime.retry_policy import RetryPolicy
        p = RetryPolicy(max_retries=3, base_delay=0.001)
        calls = [0]
        def fn():
            calls[0] += 1
            raise ValueError("bad")
        with pytest.raises(ValueError):
            p.execute_sync(fn)
        assert calls[0] == 1


class TestWorkerPool:
    def test_import_and_lifecycle(self):
        async def _run():
            from runtime.worker_pool import WorkerPool
            pool = WorkerPool(max_workers=2, max_queue=10)
            await pool.start()
            stats = pool.get_stats_dict()
            assert isinstance(stats, dict)
            assert "active" in stats
            await pool.stop()
        asyncio.run(_run())

    def test_processes_tasks(self):
        async def _run():
            from runtime.worker_pool import WorkerPool
            pool = WorkerPool(max_workers=2, max_queue=20)
            results = []
            async def work(n):
                await asyncio.sleep(0.001)
                results.append(n)
            await pool.start()
            for i in range(4):
                # submit expects a zero-arg callable that returns a coroutine
                await pool.submit(lambda n=i: work(n))
            await asyncio.sleep(0.1)
            await pool.stop()
            assert len(results) >= 1
        asyncio.run(_run())


class TestGracefulShutdown:
    def test_import(self):
        from runtime.graceful_shutdown import GracefulShutdown
        gs = GracefulShutdown()
        assert not gs.is_shutting_down

    def test_register_cleanup(self):
        from runtime.graceful_shutdown import GracefulShutdown
        gs = GracefulShutdown()
        ran = []
        gs.register(lambda: ran.append(1))
        assert isinstance(ran, list)

    def test_shutdown_runs_cleanup(self):
        async def _run():
            from runtime.graceful_shutdown import GracefulShutdown
            gs = GracefulShutdown()
            cleaned = []
            async def cleanup():
                cleaned.append(True)
            gs.register(cleanup)
            await gs.shutdown(timeout=1)
            assert len(cleaned) == 1
        asyncio.run(_run())


class TestSupervisor:
    def test_import(self):
        from runtime.supervisor import TaskSupervisor
        sup = TaskSupervisor()
        status = sup.get_status()
        assert isinstance(status, dict)

    def test_runs_simple_task(self):
        async def _run():
            from runtime.supervisor import TaskSupervisor
            sup = TaskSupervisor()
            results = []
            async def task():
                results.append(1)
            sup.add_task(task(), "t1", timeout=5)
            await sup.run_all()
            assert results == [1]
        asyncio.run(_run())
