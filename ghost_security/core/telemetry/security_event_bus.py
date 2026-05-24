"""
Ghost Security — Security Event Bus
In-process event bus for audit trail, metrics, and alerting.
"""
import threading, time, collections
from typing import Any, Callable, Dict, List, Optional

class SecurityEvent:
    SCAN_STARTED    = "scan.started"
    SCAN_COMPLETED  = "scan.completed"
    FINDING_ADDED   = "finding.added"
    FINDING_DEBATED = "finding.debated"
    REPORT_GENERATED= "report.generated"
    AGENT_STARTED   = "agent.started"
    AGENT_DONE      = "agent.done"
    HEALTH_DEGRADED = "health.degraded"
    ERROR           = "error"

class Event:
    def __init__(self, event_type: str, source: str, payload: Dict):
        self.event_type = event_type
        self.source     = source
        self.payload    = payload
        self.timestamp  = time.time()
        self.id         = f"{event_type}_{int(self.timestamp*1000)}"

    def to_dict(self):
        return {"id":self.id,"type":self.event_type,"source":self.source,
                "payload":self.payload,"timestamp":self.timestamp}

class SecurityEventBus:
    """
    In-memory event bus. Supports publish, subscribe, and event replay.
    Thread-safe. Keeps last 1000 events for audit trail.
    """
    MAX_EVENTS = 1000

    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._history: collections.deque = collections.deque(maxlen=self.MAX_EVENTS)
        self._lock = threading.Lock()
        self._counts: Dict[str, int] = {}

    def subscribe(self, event_type: str, handler: Callable):
        with self._lock:
            self._subscribers.setdefault(event_type, []).append(handler)
            self._subscribers.setdefault("*", [])  # wildcard

    def publish(self, event_type: str, source: str = "platform", payload: Dict = None) -> Event:
        ev = Event(event_type, source, payload or {})
        with self._lock:
            self._history.append(ev)
            self._counts[event_type] = self._counts.get(event_type, 0) + 1
            handlers = list(self._subscribers.get(event_type, []) +
                            self._subscribers.get("*", []))
        for h in handlers:
            try: h(ev)
            except Exception: pass
        return ev

    def history(self, event_type: Optional[str] = None, limit: int = 50) -> List[Dict]:
        with self._lock:
            evs = list(self._history)
        if event_type:
            evs = [e for e in evs if e.event_type == event_type]
        return [e.to_dict() for e in evs[-limit:]]

    def stats(self) -> Dict:
        with self._lock:
            return {"total_events":len(self._history),"counts":dict(self._counts)}

BUS = SecurityEventBus()
