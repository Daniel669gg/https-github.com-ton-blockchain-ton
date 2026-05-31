"""
TythanAI — Async Worker Pool with Backpressure

Provides a bounded pool of asyncio workers that process submitted coroutines
from a shared queue.  When the queue is full, submit() raises immediately
(backpressure) rather than silently growing memory without bound.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, List, Optional

log = logging.getLogger("ghost.worker_pool")

# Type alias for a coroutine factory: a zero-argument callable that returns a coro
_TaskFactory = Callable[[], Coroutine[Any, Any, Any]]


@dataclass
class PoolStats:
    active: int
    queued: int
    completed: int
    failed: int
    rejected: int
    uptime_seconds: float


class QueueFullError(Exception):
    """Raised by WorkerPool.submit() when the task queue is at capacity."""


class WorkerPool:
    """
    Async worker pool with configurable concurrency and queue depth.

    Parameters
    ----------
    max_workers: Maximum number of concurrently executing tasks.
    max_queue:   Maximum tasks allowed to wait in the queue.
                 submit() raises QueueFullError if this is exceeded.

    Lifecycle::

        pool = WorkerPool(max_workers=8, max_queue=100)
        await pool.start()
        await pool.submit(my_coroutine_factory)
        await pool.stop()
    """

    def __init__(self, max_workers: int = 8, max_queue: int = 100) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be >= 1")
        if max_queue < 1:
            raise ValueError("max_queue must be >= 1")

        self._max_workers = max_workers
        self._max_queue   = max_queue

        # asyncio primitives — initialised in start()
        self._queue:   Optional[asyncio.Queue] = None
        self._sem:     Optional[asyncio.Semaphore] = None
        self._workers: List[asyncio.Task] = []

        # State
        self._running    = False
        self._started_at: float = 0.0

        # Stats (protected by asyncio single-thread assumption)
        self._active    = 0
        self._completed = 0
        self._failed    = 0
        self._rejected  = 0

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Initialise the pool and spawn worker coroutines."""
        if self._running:
            raise RuntimeError("WorkerPool is already running.")

        self._queue   = asyncio.Queue(maxsize=self._max_queue)
        self._sem     = asyncio.Semaphore(self._max_workers)
        self._running = True
        self._started_at = time.time()

        for i in range(self._max_workers):
            task = asyncio.create_task(
                self._worker(i),
                name=f"ghost-worker-{i}",
            )
            self._workers.append(task)

        log.info(
            "WorkerPool started (max_workers=%d, max_queue=%d)",
            self._max_workers, self._max_queue,
        )

    async def stop(self, drain_timeout: float = 30.0) -> None:
        """
        Stop accepting new tasks and wait for in-flight work to complete.

        Parameters
        ----------
        drain_timeout: Seconds to wait for queued tasks to finish before
                       cancelling workers.
        """
        if not self._running:
            return

        self._running = False
        log.info("WorkerPool stopping — draining queue (timeout=%.1fs)...", drain_timeout)

        # Signal workers to exit by pushing sentinel None values
        assert self._queue is not None
        for _ in self._workers:
            await self._queue.put(None)  # type: ignore[arg-type]

        try:
            await asyncio.wait_for(
                asyncio.gather(*self._workers, return_exceptions=True),
                timeout=drain_timeout,
            )
        except asyncio.TimeoutError:
            log.warning("WorkerPool: drain timed out — cancelling workers")
            for w in self._workers:
                w.cancel()
            await asyncio.gather(*self._workers, return_exceptions=True)

        self._workers.clear()
        log.info(
            "WorkerPool stopped (completed=%d, failed=%d, rejected=%d)",
            self._completed, self._failed, self._rejected,
        )

    # ── Task submission ────────────────────────────────────────────────────────

    async def submit(self, task_coro: _TaskFactory) -> None:
        """
        Add a coroutine factory to the work queue.

        Parameters
        ----------
        task_coro: A zero-argument callable that returns a coroutine.
                   Called by the worker just before execution.

        Raises
        ------
        QueueFullError: If the queue has reached max_queue capacity.
        RuntimeError:   If the pool has not been started.
        """
        if not self._running:
            raise RuntimeError("WorkerPool is not running — call start() first.")

        assert self._queue is not None
        if self._queue.qsize() >= self._max_queue:
            self._rejected += 1
            raise QueueFullError(
                f"WorkerPool queue is full ({self._max_queue} tasks) — backpressure."
            )

        await self._queue.put(task_coro)
        log.debug("WorkerPool: task submitted (queued=%d)", self._queue.qsize())

    def submit_nowait(self, task_coro: _TaskFactory) -> None:
        """
        Non-async submit.  Raises QueueFullError immediately if queue is full.
        """
        if not self._running:
            raise RuntimeError("WorkerPool is not running — call start() first.")

        assert self._queue is not None
        if self._queue.qsize() >= self._max_queue:
            self._rejected += 1
            raise QueueFullError(
                f"WorkerPool queue is full ({self._max_queue} tasks) — backpressure."
            )
        self._queue.put_nowait(task_coro)

    # ── Stats ──────────────────────────────────────────────────────────────────

    def get_stats(self) -> PoolStats:
        """Return a snapshot of current pool statistics."""
        queued = self._queue.qsize() if self._queue else 0
        uptime = time.time() - self._started_at if self._started_at else 0.0
        return PoolStats(
            active=self._active,
            queued=queued,
            completed=self._completed,
            failed=self._failed,
            rejected=self._rejected,
            uptime_seconds=round(uptime, 2),
        )

    def get_stats_dict(self) -> dict:
        s = self.get_stats()
        return {
            "active": s.active,
            "queued": s.queued,
            "completed": s.completed,
            "failed": s.failed,
            "rejected": s.rejected,
            "uptime_seconds": s.uptime_seconds,
            "running": self._running,
        }

    # ── Internal worker ────────────────────────────────────────────────────────

    async def _worker(self, worker_id: int) -> None:
        log.debug("WorkerPool: worker-%d started", worker_id)
        assert self._queue is not None
        assert self._sem is not None

        while True:
            try:
                item = await self._queue.get()
            except asyncio.CancelledError:
                log.debug("WorkerPool: worker-%d cancelled", worker_id)
                return

            # None is the stop sentinel
            if item is None:
                self._queue.task_done()
                log.debug("WorkerPool: worker-%d received stop sentinel", worker_id)
                return

            task_factory: _TaskFactory = item
            async with self._sem:
                self._active += 1
                try:
                    coro = task_factory()
                    await coro
                    self._completed += 1
                except asyncio.CancelledError:
                    log.debug("WorkerPool: worker-%d task was cancelled", worker_id)
                    self._failed += 1
                except Exception as exc:
                    self._failed += 1
                    log.error(
                        "WorkerPool: worker-%d task raised %s: %s",
                        worker_id, type(exc).__name__, exc,
                    )
                finally:
                    self._active -= 1

            self._queue.task_done()

    # ── Context manager ────────────────────────────────────────────────────────

    async def __aenter__(self) -> WorkerPool:
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.stop()
