"""
Ghost Security Platform — Runtime Watchdog
Heartbeat monitoring, hung-task detection, and automatic worker recovery.
Runs as a background daemon thread; zero external dependencies.
"""
from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

log = logging.getLogger("ghost.watchdog")


@dataclass
class WatchdogTarget:
    name:      str
    heartbeat_fn: Callable[[], bool]   # returns True if healthy
    interval:  float = 30.0            # seconds between checks
    timeout:   float = 60.0            # max silence before alert
    recover_fn: Optional[Callable] = None

    last_beat:  float = field(default_factory=time.time)
    failures:   int   = 0
    status:     str   = "ok"


class RuntimeWatchdog:
    """
    Background watchdog that monitors registered subsystems.
    On silence > timeout it calls recover_fn (if provided) and logs CRITICAL.
    """

    def __init__(self, check_interval: float = 10.0) -> None:
        self._targets: Dict[str, WatchdogTarget] = {}
        self._check_interval = check_interval
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._lock    = threading.Lock()
        self._alerts: List[dict] = []

    def register(
        self,
        name: str,
        heartbeat_fn: Callable[[], bool],
        interval: float = 30.0,
        timeout: float  = 60.0,
        recover_fn: Optional[Callable] = None,
    ) -> None:
        with self._lock:
            self._targets[name] = WatchdogTarget(
                name=name, heartbeat_fn=heartbeat_fn,
                interval=interval, timeout=timeout,
                recover_fn=recover_fn,
            )
        log.info("Watchdog registered target: %s (timeout=%.0fs)", name, timeout)

    def beat(self, name: str) -> None:
        """Call from a subsystem to signal it is still alive."""
        with self._lock:
            t = self._targets.get(name)
            if t:
                t.last_beat = time.time()
                t.failures  = 0
                t.status    = "ok"

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True, name="ghost-watchdog")
        self._thread.start()
        log.info("RuntimeWatchdog started (check_interval=%.0fs)", self._check_interval)

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        while self._running:
            self._tick()
            time.sleep(self._check_interval)

    def _tick(self) -> None:
        now = time.time()
        with self._lock:
            targets = list(self._targets.values())

        for t in targets:
            # Only check at configured interval
            if now - t.last_beat < t.interval:
                continue
            try:
                healthy = t.heartbeat_fn()
            except Exception as exc:
                healthy = False
                log.warning("Watchdog probe error for %s: %s", t.name, exc)

            if healthy:
                t.last_beat = now
                t.failures  = 0
                t.status    = "ok"
            else:
                silence = now - t.last_beat
                t.failures += 1
                if silence > t.timeout:
                    t.status = "dead"
                    alert = {"ts": now, "target": t.name, "silence_s": round(silence, 1), "failures": t.failures}
                    self._alerts.append(alert)
                    log.critical("WATCHDOG ALERT: %s silent for %.0fs — attempting recovery", t.name, silence)
                    if t.recover_fn:
                        try:
                            t.recover_fn()
                            log.info("Watchdog recovery called for %s", t.name)
                        except Exception as exc:
                            log.error("Watchdog recovery failed for %s: %s", t.name, exc)
                else:
                    t.status = "degraded"
                    log.warning("Watchdog: %s degraded (silence=%.0fs, failures=%d)", t.name, silence, t.failures)

    def status(self) -> dict:
        with self._lock:
            targets = {n: {"status": t.status, "failures": t.failures} for n, t in self._targets.items()}
        overall = "ok"
        if any(v["status"] == "dead" for v in targets.values()):
            overall = "critical"
        elif any(v["status"] == "degraded" for v in targets.values()):
            overall = "degraded"
        return {"overall": overall, "targets": targets, "alert_count": len(self._alerts)}

    def recent_alerts(self, limit: int = 20) -> List[dict]:
        return self._alerts[-limit:]


# Module-level singleton
WATCHDOG = RuntimeWatchdog(check_interval=15.0)
