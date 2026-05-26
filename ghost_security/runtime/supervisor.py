"""
Ghost Security Platform — Runtime Supervisor
Task supervision with retries, timeouts, cancellation, graceful shutdown,
structured logging and health diagnostics.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional

log = logging.getLogger("ghost.supervisor")


class TaskState(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    RETRYING  = "retrying"
    SUCCEEDED = "succeeded"
    FAILED    = "failed"
    CANCELLED = "cancelled"
    TIMEOUT   = "timeout"


@dataclass
class RetryPolicy:
    max_attempts: int = 3
    base_delay:   float = 1.0        # seconds
    backoff:      float = 2.0        # exponential multiplier
    max_delay:    float = 30.0
    jitter:       float = 0.1        # ±10 % random jitter

    def delay_for(self, attempt: int) -> float:
        import random
        raw = min(self.base_delay * (self.backoff ** attempt), self.max_delay)
        return raw * (1 + random.uniform(-self.jitter, self.jitter))


@dataclass
class SupervisedTask:
    task_id:     str
    name:        str
    coro_fn:     Callable[..., Coroutine]
    args:        tuple        = field(default_factory=tuple)
    kwargs:      dict         = field(default_factory=dict)
    timeout:     Optional[float] = 60.0    # seconds; None = no limit
    retry:       RetryPolicy  = field(default_factory=RetryPolicy)
    state:       TaskState    = TaskState.PENDING
    result:      Any          = None
    error:       str          = ""
    attempts:    int          = 0
    started_at:  float        = 0.0
    finished_at: float        = 0.0
    _handle:     Optional[asyncio.Task] = field(default=None, repr=False)

    @property
    def duration(self) -> float:
        if self.started_at and self.finished_at:
            return round(self.finished_at - self.started_at, 3)
        return 0.0

    def to_dict(self) -> dict:
        return {
            "task_id":  self.task_id,
            "name":     self.name,
            "state":    self.state,
            "attempts": self.attempts,
            "duration": self.duration,
            "error":    self.error,
        }


class RuntimeSupervisor:
    """
    Async task supervisor.
    Manages a pool of coroutines with:
      • per-task timeouts
      • exponential-backoff retries
      • cancellation via cancel_token
      • graceful shutdown (drains queue, awaits running tasks)
      • structured diagnostics
    """

    def __init__(
        self,
        max_concurrent: int = 8,
        default_retry: Optional[RetryPolicy] = None,
    ) -> None:
        self._max_concurrent  = max_concurrent
        self._default_retry   = default_retry or RetryPolicy()
        self._tasks: Dict[str, SupervisedTask] = {}
        self._queue:  asyncio.Queue  = asyncio.Queue()
        self._sem:    asyncio.Semaphore | None = None
        self._workers: List[asyncio.Task] = []
        self._shutdown_event: asyncio.Event = asyncio.Event()
        self._running = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        self._sem = asyncio.Semaphore(self._max_concurrent)
        self._shutdown_event.clear()
        self._running = True
        for i in range(self._max_concurrent):
            w = asyncio.create_task(self._worker(i), name=f"supervisor-worker-{i}")
            self._workers.append(w)
        log.info("RuntimeSupervisor started (concurrency=%d)", self._max_concurrent)

    async def shutdown(self, timeout: float = 15.0) -> None:
        """Graceful shutdown: stop accepting work, drain queue, await tasks."""
        self._running = False
        self._shutdown_event.set()

        # drain workers
        try:
            await asyncio.wait_for(
                asyncio.gather(*self._workers, return_exceptions=True),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            log.warning("Supervisor shutdown timed out; cancelling workers")
            for w in self._workers:
                w.cancel()

        # cancel any still-running supervised tasks
        for st in self._tasks.values():
            if st._handle and not st._handle.done():
                st._handle.cancel()
                st.state = TaskState.CANCELLED
                st.finished_at = time.time()

        log.info("RuntimeSupervisor stopped")

    # ── Task submission ────────────────────────────────────────────────────────

    def submit(
        self,
        name: str,
        coro_fn: Callable[..., Coroutine],
        *args,
        timeout: Optional[float] = 60.0,
        retry: Optional[RetryPolicy] = None,
        **kwargs,
    ) -> str:
        task_id = uuid.uuid4().hex[:12]
        st = SupervisedTask(
            task_id=task_id,
            name=name,
            coro_fn=coro_fn,
            args=args,
            kwargs=kwargs,
            timeout=timeout,
            retry=retry or self._default_retry,
        )
        self._tasks[task_id] = st
        self._queue.put_nowait(st)
        log.debug("Submitted task %s (%s)", task_id, name)
        return task_id

    async def wait(self, task_id: str, poll: float = 0.2) -> SupervisedTask:
        """Await completion of a specific task."""
        st = self._tasks[task_id]
        while st.state in (TaskState.PENDING, TaskState.RUNNING, TaskState.RETRYING):
            await asyncio.sleep(poll)
        return st

    async def run_once(
        self,
        name: str,
        coro_fn: Callable[..., Coroutine],
        *args,
        timeout: Optional[float] = 60.0,
        retry: Optional[RetryPolicy] = None,
        **kwargs,
    ) -> Any:
        """Submit + wait, return result or raise on failure."""
        tid = self.submit(name, coro_fn, *args, timeout=timeout, retry=retry, **kwargs)
        st  = await self.wait(tid)
        if st.state == TaskState.SUCCEEDED:
            return st.result
        raise RuntimeError(f"Task '{name}' failed: {st.error}")

    # ── Internal worker ────────────────────────────────────────────────────────

    async def _worker(self, worker_id: int) -> None:
        while not self._shutdown_event.is_set():
            try:
                st: SupervisedTask = await asyncio.wait_for(
                    self._queue.get(), timeout=1.0
                )
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                return

            async with self._sem:  # type: ignore[arg-type]
                await self._execute(st)
            self._queue.task_done()

    async def _execute(self, st: SupervisedTask) -> None:
        policy = st.retry
        for attempt in range(policy.max_attempts):
            st.attempts = attempt + 1
            st.state    = TaskState.RUNNING if attempt == 0 else TaskState.RETRYING
            st.started_at = time.time()

            try:
                coro = st.coro_fn(*st.args, **st.kwargs)
                if st.timeout:
                    result = await asyncio.wait_for(coro, timeout=st.timeout)
                else:
                    result = await coro

                st.result      = result
                st.state       = TaskState.SUCCEEDED
                st.finished_at = time.time()
                log.info(
                    "Task %s (%s) succeeded in %.2fs (attempt %d/%d)",
                    st.task_id, st.name, st.duration, st.attempts, policy.max_attempts,
                )
                return

            except asyncio.TimeoutError:
                st.error = f"Timeout after {st.timeout}s"
                st.state = TaskState.TIMEOUT
                log.warning("Task %s timed out (attempt %d/%d)", st.task_id, st.attempts, policy.max_attempts)

            except asyncio.CancelledError:
                st.state       = TaskState.CANCELLED
                st.finished_at = time.time()
                log.info("Task %s cancelled", st.task_id)
                return

            except Exception as exc:
                st.error = str(exc)
                log.warning(
                    "Task %s error (attempt %d/%d): %s",
                    st.task_id, st.attempts, policy.max_attempts, exc,
                )

            # decide retry
            if attempt < policy.max_attempts - 1:
                delay = policy.delay_for(attempt)
                log.debug("Task %s retrying in %.1fs", st.task_id, delay)
                await asyncio.sleep(delay)
            else:
                st.state       = TaskState.FAILED
                st.finished_at = time.time()
                log.error(
                    "Task %s (%s) permanently failed after %d attempts: %s",
                    st.task_id, st.name, st.attempts, st.error,
                )

    # ── Diagnostics ───────────────────────────────────────────────────────────

    def status(self) -> dict:
        counts: Dict[str, int] = {}
        for st in self._tasks.values():
            counts[st.state] = counts.get(st.state, 0) + 1
        return {
            "running":    self._running,
            "queued":     self._queue.qsize(),
            "total_tasks": len(self._tasks),
            "by_state":   counts,
            "workers":    self._max_concurrent,
        }

    def get_task(self, task_id: str) -> Optional[SupervisedTask]:
        return self._tasks.get(task_id)

    def list_tasks(self, state: Optional[TaskState] = None) -> List[dict]:
        tasks = self._tasks.values()
        if state:
            tasks = [t for t in tasks if t.state == state]
        return [t.to_dict() for t in tasks]


# Module-level singleton — import and use directly
SUPERVISOR = RuntimeSupervisor()


class TaskSupervisor:
    """Simplified facade over RuntimeSupervisor for v13 compatibility."""

    def __init__(self) -> None:
        self._tasks: list = []
        self._results: dict = {}

    def add_task(self, coro: "Coroutine", name: str, timeout: float = 300) -> None:
        self._tasks.append((name, coro, timeout))

    async def run_all(self) -> None:
        for name, coro, timeout in self._tasks:
            try:
                await asyncio.wait_for(coro, timeout=timeout)
                self._results[name] = "succeeded"
            except asyncio.TimeoutError:
                self._results[name] = "timeout"
            except Exception as exc:
                self._results[name] = f"failed: {exc}"
        self._tasks.clear()

    def get_status(self) -> dict:
        return dict(self._results)
