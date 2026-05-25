"""
Ghost Security Platform — Scan Event Bus
In-process publish/subscribe event bus for scan lifecycle events.
Used internally to decouple scan engines from WebSocket broadcasting,
metrics collection, and audit logging.
"""
import asyncio
import threading
import time
import uuid
from typing import Callable, Dict, List, Optional


class ScanEventBus:
    """
    In-process event bus for scan lifecycle events.

    Supports both synchronous and async publishers and subscribers.
    Thread-safe; all internal state is protected by a lock.

    Typical event_types:
        "scan_started", "finding", "scan_progress", "scan_completed", "error"
    """

    def __init__(self):
        self._handlers: Dict[str, Callable[[dict], None]] = {}
        self._lock = threading.Lock()

    # ── Subscribe / Unsubscribe ───────────────────────────────────────────────

    def subscribe(self, handler: Callable[[dict], None]) -> str:
        """
        Register *handler* to receive every published event.

        Parameters
        ----------
        handler : callable
            A function (or coroutine function) that accepts a single ``dict``
            argument containing the event payload.

        Returns
        -------
        str
            A unique subscription ID that can be passed to :meth:`unsubscribe`.
        """
        sub_id = str(uuid.uuid4())
        with self._lock:
            self._handlers[sub_id] = handler
        return sub_id

    def unsubscribe(self, sub_id: str) -> None:
        """
        Remove the subscription identified by *sub_id*.

        Silently ignores unknown IDs so callers don't need to track whether
        they already unsubscribed.
        """
        with self._lock:
            self._handlers.pop(sub_id, None)

    # ── Publish (sync) ───────────────────────────────────────────────────────

    def publish(self, event_type: str, scan_id: str, data: dict) -> dict:
        """
        Build and dispatch a scan event synchronously.

        All registered handlers are called in the calling thread.
        Exceptions raised by individual handlers are swallowed so that one
        failing handler cannot block the others.

        Parameters
        ----------
        event_type : str
            One of ``"scan_started"``, ``"finding"``, ``"scan_progress"``,
            ``"scan_completed"``, or ``"error"``.
        scan_id : str
            Unique identifier for the scan session.
        data : dict
            Arbitrary payload attached to the event.

        Returns
        -------
        dict
            The assembled event dict that was dispatched.
        """
        event = {
            "event_type": event_type,
            "scan_id": scan_id,
            "data": data,
            "timestamp": time.time(),
        }
        with self._lock:
            handlers = list(self._handlers.values())
        for handler in handlers:
            try:
                handler(event)
            except Exception:
                pass
        return event

    # ── Publish (async) ──────────────────────────────────────────────────────

    async def publish_async(self, event_type: str, scan_id: str, data: dict) -> dict:
        """
        Build and dispatch a scan event asynchronously.

        Synchronous handlers are called via :func:`asyncio.get_event_loop`'s
        thread executor so they never block the event loop.  Coroutine
        handlers are awaited directly.

        Parameters
        ----------
        event_type : str
            One of ``"scan_started"``, ``"finding"``, ``"scan_progress"``,
            ``"scan_completed"``, or ``"error"``.
        scan_id : str
            Unique identifier for the scan session.
        data : dict
            Arbitrary payload attached to the event.

        Returns
        -------
        dict
            The assembled event dict that was dispatched.
        """
        event = {
            "event_type": event_type,
            "scan_id": scan_id,
            "data": data,
            "timestamp": time.time(),
        }
        with self._lock:
            handlers = list(self._handlers.values())

        loop = asyncio.get_event_loop()
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    await loop.run_in_executor(None, handler, event)
            except Exception:
                pass
        return event

    # ── Introspection ────────────────────────────────────────────────────────

    def subscriber_count(self) -> int:
        """Return the number of currently registered subscribers."""
        with self._lock:
            return len(self._handlers)

    def subscriber_ids(self) -> List[str]:
        """Return a snapshot list of active subscription IDs."""
        with self._lock:
            return list(self._handlers.keys())


# Module-level singleton — import and use directly:
#
#   from core.telemetry.scan_event_bus import scan_bus
#   sub_id = scan_bus.subscribe(my_handler)
#   scan_bus.publish("scan_started", scan_id="abc123", data={"path": "/repo"})
#   scan_bus.unsubscribe(sub_id)
scan_bus = ScanEventBus()
