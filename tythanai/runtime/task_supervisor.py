"""
TythanAI — Task Supervisor (v13)

Production-grade asyncio task supervisor with:
  - Per-task timeout enforcement
  - Automatic restart with exponential back-off (up to 3 attempts)
  - Graceful shutdown with configurable drain timeout
  - Structured status reporting

Class: TaskSupervisor
"""
from __future__ import annotations

import asyncio
import logging
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional

log = logging.getLogger("ghost.task_supervisor")


class TaskStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    SUCCEEDED = "succeeded"
    FAILED    = "failed"
    RETRYING  = "retrying"
    CANCELLED = "cancelled"
    TIMEOUT   = "timeout"


@dataclass
class _ManagedTask:
    name:      str
    coro_fn:   Callable[[], Coroutine[Any, Any, Any]]
    timeout:   Optional[float]          # seconds; None = unlimited
    status:    TaskStatus = TaskStatus.PENDING
    attempts:  int        = 0
    last_error: str       = ""
    started_at: float     = 0.0
    finished_at: float    = 0.0
    _handle:   Optional[asyncio.Task] = field(default=None, repr=False)

    def to_dict(self) -> dict:
        return {
            "name":       self.name,
            "status":     self.status,
            "attempts":   self.attempts,
            "last_error": self.last_error,
            "duration":   round(self.finished_at - self.started_at, 3)
                          if self.started_at and self.finished_at else 0.0,
        }


_MAX_RESTARTS  = 3
_BACKOFF_BASE  = 2.0   # seconds
_BACKOFF_MAX   = 30.0  # seconds cap


def _backoff(attempt: int) -> float:
    """Exponential back-off capped at _BACKOFF_MAX."""
    return min(_BACKOFF_BASE ** attempt, _BACKOFF_MAX)


class TaskSupervisor:
    """
    Manages a collection of named, supervised async tasks.

    Usage::

        supervisor = TaskSupervisor()
        supervisor.add_task(scanner_coro, name="semgrep", timeout=300)
        await supervisor.run_all()
        print(supervisor.get_status())
    """

    def __init__(self) -> None:
        self._tasks: Dict[str, _ManagedTask] = {}
        self._shutdown_event = asyncio.Event()

    # ── Task registration ──────────────────────────────────────────────────────

    def add_task(
        self,
        coro: Callable[[], Coroutine[Any, Any, Any]],
        name: str,
        timeout: Optional[float] = 300,
    ) -> None:
        """
        Register a supervised task.

        Parameters
        ----------
        coro:    Zero-argument callable returning a coroutine.
        name:    Unique human-readable identifier.
        timeout: Per-attempt timeout in seconds (None = no limit).
        """
        if name in self._tasks:
            raise ValueError(f"Task '{name}' is already registered.")
        self._tasks[name] = _ManagedTask(name=name, coro_fn=coro, timeout=timeout)
        log.debug("TaskSupervisor: registered task '%s' (timeout=%s)", name, timeout)

    # ── Run all ────────────────────────────────────────────────────────────────

    async def run_all(self) -> None:
        """
        Launch all registered tasks concurrently and wait for them to finish.

        Each task is supervised independently:
        - On timeout: task is cancelled, status set to TIMEOUT, no restart.
        - On exception: up to _MAX_RESTARTS restarts with backoff.
        - On success: status set to SUCCEEDED.
        """
        if not self._tasks:
            log.warning("TaskSupervisor.run_all(): no tasks registered.")
            return

        supervisors = [
            asyncio.create_task(self._supervise(mt), name=f"sup-{mt.name}")
            for mt in self._tasks.values()
        ]
        await asyncio.gather(*supervisors, return_exceptions=True)

    # ── Graceful shutdown ──────────────────────────────────────────────────────

    async def shutdown(self, timeout: float = 30.0) -> None:
        """
        Signal all running tasks to stop and wait up to *timeout* seconds.
        Tasks still running after the deadline are cancelled.
        """
        self._shutdown_event.set()
        running_handles = [
            mt._handle
            for mt in self._tasks.values()
            if mt._handle is not None and not mt._handle.done()
        ]
        if not running_handles:
            return

        log.info(
            "TaskSupervisor: shutdown — waiting up to %.1fs for %d task(s)",
            timeout, len(running_handles),
        )
        try:
            await asyncio.wait_for(
                asyncio.gather(*running_handles, return_exceptions=True),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            log.warning(
                "TaskSupervisor: shutdown timeout — force-cancelling %d task(s)",
                len(running_handles),
            )
            for h in running_handles:
                if not h.done():
                    h.cancel()
            await asyncio.gather(*running_handles, return_exceptions=True)

        for mt in self._tasks.values():
            if mt.status == TaskStatus.RUNNING:
                mt.status = TaskStatus.CANCELLED
                mt.finished_at = time.time()

        log.info("TaskSupervisor: shutdown complete")

    # ── Status ─────────────────────────────────────────────────────────────────

    def get_status(self) -> Dict[str, dict]:
        """
        Return a dict of {task_name: status_dict} for all managed tasks.
        """
        return {name: mt.to_dict() for name, mt in self._tasks.items()}

    # ── Internal supervision loop ──────────────────────────────────────────────

    async def _supervise(self, mt: _ManagedTask) -> None:
        """Run a single managed task with restart-on-failure logic."""
        for attempt in range(_MAX_RESTARTS + 1):
            if self._shutdown_event.is_set():
                mt.status = TaskStatus.CANCELLED
                return

            mt.attempts   = attempt + 1
            mt.status     = TaskStatus.RUNNING if attempt == 0 else TaskStatus.RETRYING
            mt.started_at = time.time()

            if attempt > 0:
                delay = _backoff(attempt - 1)
                log.info(
                    "TaskSupervisor: restarting '%s' (attempt %d/%d) in %.1fs",
                    mt.name, attempt + 1, _MAX_RESTARTS + 1, delay,
                )
                await asyncio.sleep(delay)

            try:
                coro = mt.coro_fn()
                if mt.timeout is not None:
                    handle = asyncio.create_task(coro, name=mt.name)
                    mt._handle = handle
                    await asyncio.wait_for(
                        asyncio.shield(handle), timeout=mt.timeout
                    )
                else:
                    handle = asyncio.create_task(coro, name=mt.name)
                    mt._handle = handle
                    await handle

                mt.status      = TaskStatus.SUCCEEDED
                mt.finished_at = time.time()
                log.info(
                    "TaskSupervisor: task '%s' succeeded (attempt %d)",
                    mt.name, mt.attempts,
                )
                return

            except asyncio.TimeoutError:
                mt.last_error  = f"Timed out after {mt.timeout}s"
                mt.status      = TaskStatus.TIMEOUT
                mt.finished_at = time.time()
                log.warning(
                    "TaskSupervisor: task '%s' timed out (attempt %d) — not restarting",
                    mt.name, mt.attempts,
                )
                if mt._handle and not mt._handle.done():
                    mt._handle.cancel()
                return  # timeouts are not restarted

            except asyncio.CancelledError:
                mt.status      = TaskStatus.CANCELLED
                mt.finished_at = time.time()
                log.info("TaskSupervisor: task '%s' was cancelled", mt.name)
                return

            except Exception as exc:
                mt.last_error  = f"{type(exc).__name__}: {exc}"
                mt.finished_at = time.time()

                if attempt < _MAX_RESTARTS:
                    log.warning(
                        "TaskSupervisor: task '%s' failed (attempt %d/%d): %s — will retry",
                        mt.name, mt.attempts, _MAX_RESTARTS + 1, exc,
                    )
                    continue
                else:
                    mt.status = TaskStatus.FAILED
                    log.error(
                        "TaskSupervisor: task '%s' permanently failed after %d attempts: %s",
                        mt.name, mt.attempts, exc,
                    )
