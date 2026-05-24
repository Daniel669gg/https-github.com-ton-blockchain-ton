"""
Ghost Security — Async Priority Task Queue
Thread-safe, priority-aware queue for parallel scan workloads.
"""
import heapq, threading, time, uuid, asyncio
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional

class Priority(IntEnum):
    CRITICAL = 0; HIGH = 1; MEDIUM = 2; LOW = 3

@dataclass(order=True)
class Task:
    priority:   int
    created_at: float         = field(compare=True)
    task_id:    str           = field(compare=False, default_factory=lambda: str(uuid.uuid4())[:8])
    name:       str           = field(compare=False, default="task")
    payload:    Dict          = field(compare=False, default_factory=dict)
    result:     Optional[Any] = field(compare=False, default=None)
    error:      Optional[str] = field(compare=False, default=None)
    status:     str           = field(compare=False, default="pending")
    started_at: float         = field(compare=False, default=0.0)
    done_at:    float         = field(compare=False, default=0.0)

    @property
    def duration(self): return round(self.done_at - self.started_at, 3) if self.done_at else 0.0

class AsyncTaskQueue:
    def __init__(self, max_workers: int = 4):
        self._heap:   List[Task] = []
        self._lock    = threading.Lock()
        self._tasks:  Dict[str, Task] = {}
        self._events: Dict[str, threading.Event] = {}
        self._active  = 0
        self._stats   = {"submitted":0,"completed":0,"failed":0,"cancelled":0}

    def submit(self, name: str, payload: Dict, priority: Priority = Priority.MEDIUM) -> str:
        t = Task(priority=int(priority), created_at=time.time(), name=name, payload=payload)
        with self._lock:
            heapq.heappush(self._heap, t)
            self._tasks[t.task_id] = t
            self._events[t.task_id] = threading.Event()
            self._stats["submitted"] += 1
        return t.task_id

    def next_task(self) -> Optional[Task]:
        with self._lock:
            while self._heap:
                t = heapq.heappop(self._heap)
                if t.status == "pending":
                    t.status = "running"; t.started_at = time.time(); self._active += 1; return t
        return None

    def complete(self, task_id: str, result: Any = None, error: Optional[str] = None):
        with self._lock:
            t = self._tasks.get(task_id)
            if not t: return
            t.done_at = time.time()
            if error:   t.status="failed";    t.error=error;  self._stats["failed"]+=1
            else:       t.status="completed"; t.result=result; self._stats["completed"]+=1
            self._active -= 1; self._events[task_id].set()

    def cancel(self, task_id: str) -> bool:
        with self._lock:
            t = self._tasks.get(task_id)
            if t and t.status=="pending":
                t.status="cancelled"; self._stats["cancelled"]+=1
                self._events[task_id].set(); return True
        return False

    def wait(self, task_id: str, timeout: float = 120.0) -> Optional[Task]:
        ev = self._events.get(task_id)
        if ev: ev.wait(timeout=timeout)
        return self._tasks.get(task_id)

    def status(self) -> Dict:
        with self._lock:
            pending = sum(1 for t in self._tasks.values() if t.status=="pending")
            return {"pending":pending,"active":self._active,"stats":dict(self._stats)}

    async def run_async(self, fn: Callable, name: str, payload: Dict,
                        priority: Priority = Priority.MEDIUM) -> Task:
        tid = self.submit(name, payload, priority)
        t = self._tasks[tid]; t.status="running"; t.started_at=time.time()
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, lambda: fn(payload))
            self.complete(tid, result=result)
        except Exception as e:
            self.complete(tid, error=str(e))
        return self._tasks[tid]

QUEUE = AsyncTaskQueue()
