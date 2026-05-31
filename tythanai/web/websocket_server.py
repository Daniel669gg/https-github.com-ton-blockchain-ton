"""
TythanAI Platform — WebSocket / SSE Event Broadcaster
Phase 8: Real-time scan event streaming to dashboard clients.

Architecture
------------
ScanEventBus (singleton) manages connected clients and broadcasts
finding events.  Two transports are supported:

  1. WebSocket   — preferred; clients connect to /ws/scan
  2. SSE fallback — GET /api/dashboard/live  (EventSource-compatible)

The server integrates with the FastAPI app in api/server.py via
``register_ws_routes(app)``.  Scanners call
``broadcast_finding(finding_dict)`` from any thread — it is
thread-safe.

Usage in api/server.py
-----------------------
    from web.websocket_server import register_ws_routes, broadcast_finding
    register_ws_routes(app)
    ...
    # inside a scanner or background task:
    broadcast_finding({"severity": "HIGH", "message": "..."})
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import threading
from typing import Any, Dict, Optional, Set

logger = logging.getLogger("tythanai.ws")

# ---------------------------------------------------------------------------
# Transport shim — detect whether websockets-capable server is available.
# FastAPI + uvicorn (starlette) ships WebSocket support natively.
# ---------------------------------------------------------------------------
try:
    from fastapi import WebSocket, WebSocketDisconnect
    from starlette.websockets import WebSocketState
    _HAS_FASTAPI_WS = True
except ImportError:
    _HAS_FASTAPI_WS = False
    WebSocket = None  # type: ignore
    WebSocketDisconnect = Exception  # type: ignore

try:
    from fastapi import FastAPI, Request
    from fastapi.responses import StreamingResponse
    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False
    FastAPI = None  # type: ignore


# ══════════════════════════════════════════════════════════════════════════════
# Internal event queue — the bridge between sync scanners and async event loop
# ══════════════════════════════════════════════════════════════════════════════

class _EventQueue:
    """Thread-safe bridge between sync producers and async consumers."""

    def __init__(self) -> None:
        self._lock: threading.Lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._async_queue: Optional[asyncio.Queue] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        with self._lock:
            self._loop = loop
            self._async_queue = asyncio.Queue()

    def put_nowait_threadsafe(self, item: Any) -> None:
        """Call from *any* thread to enqueue an event."""
        with self._lock:
            if self._loop and self._async_queue:
                try:
                    self._loop.call_soon_threadsafe(self._async_queue.put_nowait, item)
                except RuntimeError:
                    pass  # loop may be closed

    async def get(self, timeout: float = 30.0) -> Optional[Any]:
        if self._async_queue is None:
            await asyncio.sleep(timeout)
            return None
        try:
            return await asyncio.wait_for(self._async_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None


# ══════════════════════════════════════════════════════════════════════════════
# ScanEventBus — singleton broadcast hub
# ══════════════════════════════════════════════════════════════════════════════

class ScanEventBus:
    """
    Singleton event bus.  Scanners call ``broadcast_finding()`` from
    sync threads.  Async WebSocket / SSE handlers subscribe and receive
    events.

    Public API
    ----------
    subscribe(client_id, queue)     — register an async queue
    unsubscribe(client_id)          — remove a client
    broadcast(event_dict)           — send to all clients (async, call from loop)
    broadcast_finding(finding)      — thread-safe helper for sync callers
    """

    def __init__(self) -> None:
        self._lock: threading.Lock = threading.Lock()
        self._clients: Dict[str, asyncio.Queue] = {}  # client_id → queue
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._event_queue: _EventQueue = _EventQueue()
        self._stats: Dict[str, int] = {
            "total_broadcasts": 0,
            "total_clients_ever": 0,
        }
        self._dispatch_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Called once when the FastAPI event loop starts."""
        with self._lock:
            self._loop = loop
        self._event_queue.set_loop(loop)

    async def start_dispatch(self) -> None:
        """Start background dispatcher coroutine (run in async context)."""
        self._dispatch_task = asyncio.create_task(self._dispatch_loop())

    async def stop(self) -> None:
        if self._dispatch_task:
            self._dispatch_task.cancel()
            try:
                await self._dispatch_task
            except asyncio.CancelledError:
                pass

    # ------------------------------------------------------------------
    # Client management
    # ------------------------------------------------------------------

    def subscribe(self, client_id: str, queue: asyncio.Queue) -> None:
        with self._lock:
            self._clients[client_id] = queue
            self._stats["total_clients_ever"] += 1
        logger.debug("ScanEventBus: client %s subscribed (%d active)", client_id, self.client_count)

    def unsubscribe(self, client_id: str) -> None:
        with self._lock:
            self._clients.pop(client_id, None)
        logger.debug("ScanEventBus: client %s unsubscribed (%d active)", client_id, self.client_count)

    @property
    def client_count(self) -> int:
        with self._lock:
            return len(self._clients)

    # ------------------------------------------------------------------
    # Broadcasting
    # ------------------------------------------------------------------

    async def broadcast(self, event_dict: Dict[str, Any]) -> int:
        """
        Send *event_dict* to all subscribed clients.
        Must be called from within the async event loop.
        Returns number of clients reached.
        """
        payload = json.dumps(event_dict, default=str)
        with self._lock:
            clients = dict(self._clients)

        dead: Set[str] = set()
        for cid, queue in clients.items():
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                dead.add(cid)
            except Exception:
                dead.add(cid)

        for cid in dead:
            self.unsubscribe(cid)

        with self._lock:
            self._stats["total_broadcasts"] += 1

        return len(clients) - len(dead)

    def broadcast_finding(self, finding: Dict[str, Any]) -> None:
        """
        Thread-safe helper.  Enqueue a finding from any thread or sync
        scanner.  The async dispatcher delivers it to all WS/SSE clients.
        """
        event = {
            "event": "finding",
            "data":  finding,
            "ts":    time.time(),
        }
        self._event_queue.put_nowait_threadsafe(event)

    def broadcast_event(self, event_type: str, data: Any) -> None:
        """Thread-safe generic event broadcast."""
        self._event_queue.put_nowait_threadsafe({
            "event": event_type,
            "data":  data,
            "ts":    time.time(),
        })

    async def _dispatch_loop(self) -> None:
        """Async task: drain _event_queue and broadcast to clients."""
        while True:
            try:
                msg = await self._event_queue.get(timeout=30.0)
                if msg is not None:
                    await self.broadcast(msg)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception("ScanEventBus dispatch error: %s", exc)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                **self._stats,
                "active_clients": len(self._clients),
            }


# ── Singleton instance ────────────────────────────────────────────────────────
EVENT_BUS: ScanEventBus = ScanEventBus()


# ══════════════════════════════════════════════════════════════════════════════
# Public helper — call from scanners
# ══════════════════════════════════════════════════════════════════════════════

def broadcast_finding(finding: Dict[str, Any]) -> None:
    """
    Thread-safe.  Call from any scanner thread to push a finding to
    all connected dashboard clients.

    Example::

        from web.websocket_server import broadcast_finding
        broadcast_finding({"severity": "HIGH", "message": "...", "file": "..."})
    """
    EVENT_BUS.broadcast_finding(finding)


def broadcast_event(event_type: str, data: Any = None) -> None:
    """Thread-safe generic event broadcast (scan_start, scan_complete, etc.)."""
    EVENT_BUS.broadcast_event(event_type, data or {})


# ══════════════════════════════════════════════════════════════════════════════
# FastAPI route registration
# ══════════════════════════════════════════════════════════════════════════════

def register_ws_routes(app: Any) -> None:
    """
    Attach WebSocket and SSE routes to a FastAPI *app*.

    Routes added
    ------------
    GET  /ws/scan           — WebSocket endpoint
    GET  /api/dashboard/live — SSE fallback endpoint
    GET  /api/ws/status      — bus stats (health check)
    """
    if not _HAS_FASTAPI:
        logger.warning("FastAPI not available — WebSocket routes not registered")
        return

    # ------------------------------------------------------------------
    # Lifecycle hooks — initialise event loop binding
    # ------------------------------------------------------------------

    @app.on_event("startup")
    async def _ws_startup() -> None:
        loop = asyncio.get_running_loop()
        EVENT_BUS.set_loop(loop)
        await EVENT_BUS.start_dispatch()
        logger.info("ScanEventBus started")

    @app.on_event("shutdown")
    async def _ws_shutdown() -> None:
        await EVENT_BUS.stop()
        logger.info("ScanEventBus stopped")

    # ------------------------------------------------------------------
    # WebSocket endpoint
    # ------------------------------------------------------------------

    if _HAS_FASTAPI_WS:
        import uuid

        @app.websocket("/ws/scan")
        async def ws_scan(websocket: WebSocket) -> None:
            await websocket.accept()
            client_id = str(uuid.uuid4())
            queue: asyncio.Queue = asyncio.Queue(maxsize=256)
            EVENT_BUS.subscribe(client_id, queue)
            logger.info("WS client connected: %s", client_id)

            # Send welcome
            try:
                await websocket.send_text(json.dumps({
                    "event": "connected",
                    "data":  {"client_id": client_id, "transport": "websocket"},
                    "ts":    time.time(),
                }))
            except Exception:
                EVENT_BUS.unsubscribe(client_id)
                return

            # Receive loop (runs in a background task so we can also drain queue)
            recv_task = asyncio.create_task(_ws_receive(websocket))

            try:
                while True:
                    # Wait for queued message
                    try:
                        payload = await asyncio.wait_for(queue.get(), timeout=25.0)
                        if websocket.client_state == WebSocketState.DISCONNECTED:
                            break
                        await websocket.send_text(payload)
                    except asyncio.TimeoutError:
                        # Send ping to keep connection alive
                        try:
                            await websocket.send_text(json.dumps({
                                "event": "ping",
                                "data":  {"ts": time.time()},
                            }))
                        except Exception:
                            break
                    except (WebSocketDisconnect, Exception):
                        break
            finally:
                recv_task.cancel()
                EVENT_BUS.unsubscribe(client_id)
                logger.info("WS client disconnected: %s", client_id)

        async def _ws_receive(ws: WebSocket) -> None:
            """Drain incoming WebSocket messages (ping/pong, commands)."""
            try:
                while True:
                    msg = await ws.receive_text()
                    try:
                        data = json.loads(msg)
                        logger.debug("WS recv from client: %s", data)
                    except Exception:
                        pass
            except Exception:
                pass

    # ------------------------------------------------------------------
    # SSE fallback endpoint
    # ------------------------------------------------------------------

    import uuid as _uuid

    @app.get("/api/dashboard/live")
    async def sse_live(request: "Request") -> "StreamingResponse":  # type: ignore[name-defined]
        client_id = str(_uuid.uuid4())
        queue: asyncio.Queue = asyncio.Queue(maxsize=256)
        EVENT_BUS.subscribe(client_id, queue)
        logger.info("SSE client connected: %s", client_id)

        async def generator():
            try:
                # Initial connected event
                yield "data: " + json.dumps({
                    "event": "connected",
                    "data":  {"client_id": client_id, "transport": "sse"},
                    "ts":    time.time(),
                }) + "\n\n"

                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        payload = await asyncio.wait_for(queue.get(), timeout=25.0)
                        yield "data: " + payload + "\n\n"
                    except asyncio.TimeoutError:
                        # Keep-alive comment
                        yield ": ping\n\n"
            except asyncio.CancelledError:
                pass
            finally:
                EVENT_BUS.unsubscribe(client_id)
                logger.info("SSE client disconnected: %s", client_id)

        return StreamingResponse(
            generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    # ------------------------------------------------------------------
    # Status endpoint
    # ------------------------------------------------------------------

    @app.get("/api/ws/status")
    async def ws_status() -> Dict[str, Any]:
        return {
            "status":  "ok",
            "bus":     EVENT_BUS.stats(),
            "transports": {
                "websocket": _HAS_FASTAPI_WS,
                "sse":       True,
            },
        }
