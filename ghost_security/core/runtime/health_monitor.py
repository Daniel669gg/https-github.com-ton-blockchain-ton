"""
Ghost Security — Health Monitor
Real-time health tracking for all platform subsystems.
"""
import time, threading
from typing import Dict, List, Optional, Callable

class HealthStatus:
    OK      = "ok"
    DEGRADED= "degraded"
    DOWN    = "down"
    UNKNOWN = "unknown"

class ServiceHealth:
    def __init__(self, name: str):
        self.name       = name
        self.status     = HealthStatus.UNKNOWN
        self.last_check = 0.0
        self.latency_ms = 0.0
        self.error      = ""
        self.checks_ok  = 0
        self.checks_fail= 0

    def to_dict(self):
        uptime = self.checks_ok/(self.checks_ok+self.checks_fail)*100 if (self.checks_ok+self.checks_fail) else 0
        return {"name":self.name,"status":self.status,
                "last_check":self.last_check,"latency_ms":round(self.latency_ms,1),
                "uptime_pct":round(uptime,1),"error":self.error}

class HealthMonitor:
    """Tracks and exposes health of all Ghost Security subsystems."""

    def __init__(self, interval: int = 30):
        self._services: Dict[str, ServiceHealth] = {}
        self._probes:   Dict[str, Callable]      = {}
        self._interval  = interval
        self._lock      = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._running   = False

    def register(self, name: str, probe: Optional[Callable] = None, status: str = HealthStatus.UNKNOWN):
        with self._lock:
            svc = ServiceHealth(name)
            svc.status = status
            self._services[name] = svc
            if probe: self._probes[name] = probe

    def check(self, name: str) -> ServiceHealth:
        svc = self._services.get(name)
        probe = self._probes.get(name)
        if not svc: return ServiceHealth(name)
        if probe:
            t0 = time.time()
            try:
                ok = probe()
                svc.latency_ms = (time.time()-t0)*1000
                svc.status = HealthStatus.OK if ok else HealthStatus.DEGRADED
                svc.checks_ok += 1; svc.error = ""
            except Exception as e:
                svc.status = HealthStatus.DOWN; svc.error = str(e)[:80]
                svc.checks_fail += 1
            svc.last_check = time.time()
        return svc

    def check_all(self) -> Dict:
        with self._lock:
            names = list(self._services.keys())
        results = {n: self.check(n).to_dict() for n in names}
        statuses = [r["status"] for r in results.values()]
        overall = (HealthStatus.OK if all(s==HealthStatus.OK for s in statuses)
                   else HealthStatus.DEGRADED if HealthStatus.DOWN not in statuses
                   else HealthStatus.DOWN)
        return {"overall":overall,"services":results,"timestamp":time.time()}

    def start_background(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self): self._running = False

    def _loop(self):
        while self._running:
            try: self.check_all()
            except Exception: pass
            time.sleep(self._interval)

    def report(self) -> Dict:
        return self.check_all()

MONITOR = HealthMonitor(interval=60)
MONITOR.register("ton_analyzer", probe=lambda: True, status=HealthStatus.OK)
MONITOR.register("task_queue",   probe=lambda: True, status=HealthStatus.OK)
MONITOR.register("report_gen",   probe=lambda: True, status=HealthStatus.OK)
MONITOR.register("llm_backend",  status=HealthStatus.UNKNOWN)
