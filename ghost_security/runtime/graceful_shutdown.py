"""
Ghost Security — Graceful Shutdown Handler

Provides signal-aware async shutdown coordination using asyncio.Event.
Cleanup callbacks are executed in reverse registration order (LIFO),
mirroring typical resource teardown patterns.
"""
from __future__ import annotations

import asyncio
import logging
import signal
import sys
import time
from typing import Any, Callable, Coroutine, List, Optional, Union

log = logging.getLogger("ghost.graceful_shutdown")

# Type aliases
_CleanupFn = Union[
    Callable[[], None],
    Callable[[], Coroutine[Any, Any, None]],
]


class GracefulShutdown:
    """
    Coordinates orderly shutdown of the Ghost platform.

    Usage::

        gs = GracefulShutdown()
        gs.setup_signals()
        gs.register(my_cleanup)

        # In the main async entrypoint:
        await gs.wait_for_shutdown()
        await gs.shutdown(timeout=30)
    """

    def __init__(self) -> None:
        self._event: asyncio.Event = asyncio.Event()
        self._callbacks: List[_CleanupFn] = []
        self._shutdown_started = False
        self._shutdown_complete = False
        self._started_at: float = 0.0

    # ── Registration ───────────────────────────────────────────────────────────

    def register(self, cleanup_func: _CleanupFn) -> None:
        """
        Register a cleanup callback.  Callbacks are called in reverse
        (LIFO) order during shutdown.

        *cleanup_func* may be a plain function or a coroutine function.
        """
        self._callbacks.append(cleanup_func)
        log.debug("GracefulShutdown: registered cleanup '%s'", _name(cleanup_func))

    # ── Signal setup ───────────────────────────────────────────────────────────

    def setup_signals(self) -> None:
        """
        Register SIGTERM and SIGINT handlers that trigger the shutdown event.
        Must be called from the main thread after an event loop is running.
        """
        if sys.platform == "win32":
            # Windows: only SIGINT via signal module
            signal.signal(signal.SIGINT, self._sync_handler)
            log.info("GracefulShutdown: registered SIGINT handler (Windows)")
        else:
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(
                    sig,
                    lambda s=sig: asyncio.create_task(self._signal_handler(s)),
                )
            log.info("GracefulShutdown: registered SIGTERM + SIGINT handlers")

    # ── Shutdown coordination ──────────────────────────────────────────────────

    @property
    def is_shutting_down(self) -> bool:
        """True once the shutdown sequence has been initiated."""
        return self._shutdown_started

    def trigger(self) -> None:
        """
        Programmatically trigger the shutdown (non-signal path).
        Thread-safe; may be called from any thread.
        """
        if not self._event.is_set():
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.call_soon_threadsafe(self._event.set)
                else:
                    self._event.set()
            except RuntimeError:
                # No running event loop — set directly (pre-start scenario)
                self._event.set()
            log.info("GracefulShutdown: shutdown triggered programmatically")

    async def wait_for_shutdown(self) -> None:
        """
        Coroutine that blocks until the shutdown event is set.
        Intended for the main task to await before starting cleanup.
        """
        await self._event.wait()

    async def shutdown(self, timeout: float = 30.0) -> None:
        """
        Execute all registered cleanup callbacks in LIFO order.

        Each callback is given at most *timeout* / n seconds (shared budget).
        If a callback exceeds its slot, it is cancelled and a warning is logged.
        After all callbacks run (or timeout), any remaining asyncio tasks that
        are not the current task are cancelled.

        Parameters
        ----------
        timeout: Total seconds allocated across all cleanup callbacks.
        """
        if self._shutdown_started:
            log.warning("GracefulShutdown.shutdown() called more than once — ignoring.")
            return

        self._shutdown_started = True
        self._started_at = time.time()
        self._event.set()  # ensure event is set in case triggered programmatically

        log.info(
            "GracefulShutdown: starting cleanup (%d callback(s), timeout=%.1fs)",
            len(self._callbacks), timeout,
        )

        callbacks = list(reversed(self._callbacks))
        per_cb_timeout = (timeout / len(callbacks)) if callbacks else timeout

        for cb in callbacks:
            cb_name = _name(cb)
            try:
                if asyncio.iscoroutinefunction(cb):
                    await asyncio.wait_for(cb(), timeout=per_cb_timeout)
                else:
                    # Run sync callback in executor so it doesn't block the loop
                    loop = asyncio.get_event_loop()
                    await asyncio.wait_for(
                        loop.run_in_executor(None, cb),
                        timeout=per_cb_timeout,
                    )
                log.debug("GracefulShutdown: cleanup '%s' completed", cb_name)
            except asyncio.TimeoutError:
                log.warning(
                    "GracefulShutdown: cleanup '%s' timed out (%.1fs) — skipping.",
                    cb_name, per_cb_timeout,
                )
            except Exception as exc:
                log.error(
                    "GracefulShutdown: cleanup '%s' raised %s: %s",
                    cb_name, type(exc).__name__, exc,
                )

        # Cancel remaining tasks (other than this one)
        await self._cancel_remaining_tasks()

        elapsed = time.time() - self._started_at
        self._shutdown_complete = True
        log.info("GracefulShutdown: complete (elapsed=%.2fs)", elapsed)

    # ── Internal ───────────────────────────────────────────────────────────────

    async def _signal_handler(self, sig: signal.Signals) -> None:
        log.info("GracefulShutdown: received signal %s", sig.name)
        self._event.set()

    def _sync_handler(self, signum: int, frame: Any) -> None:
        log.info("GracefulShutdown: received signal %d", signum)
        self.trigger()

    @staticmethod
    async def _cancel_remaining_tasks() -> None:
        current = asyncio.current_task()
        tasks = [
            t for t in asyncio.all_tasks()
            if t is not current and not t.done()
        ]
        if not tasks:
            return
        log.info(
            "GracefulShutdown: cancelling %d remaining task(s)", len(tasks)
        )
        for t in tasks:
            t.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for t, res in zip(tasks, results):
            if isinstance(res, Exception) and not isinstance(res, asyncio.CancelledError):
                log.warning(
                    "GracefulShutdown: task '%s' raised on cancel: %s", t.get_name(), res
                )


def _name(fn: _CleanupFn) -> str:
    return getattr(fn, "__qualname__", None) or getattr(fn, "__name__", None) or repr(fn)


# ─── Module-level singleton ───────────────────────────────────────────────────

_DEFAULT_HANDLER: Optional[GracefulShutdown] = None


def get_shutdown_handler() -> GracefulShutdown:
    """Return the process-level singleton GracefulShutdown instance."""
    global _DEFAULT_HANDLER
    if _DEFAULT_HANDLER is None:
        _DEFAULT_HANDLER = GracefulShutdown()
    return _DEFAULT_HANDLER
