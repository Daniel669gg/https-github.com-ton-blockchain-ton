"""
TythanAI Platform — Rate Limiter (no framework dependency)
Pure Python sliding-window rate limiter, testable without FastAPI.
"""
from __future__ import annotations

import json, os, time, threading
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, Tuple

@dataclass
class RateLimit:
    requests: int
    window:   int   # seconds

_LIMITS: Dict[str, RateLimit] = {
    "default":   RateLimit(100, 60),
    "scan":      RateLimit(20,  60),
    "auth":      RateLimit(10,  60),
    "ai":        RateLimit(30,  60),
    "report":    RateLimit(10,  60),
    "benchmark": RateLimit(2,  300),
}

class RateLimiter:
    def __init__(self):
        self._windows: Dict[str, deque] = defaultdict(deque)
        self._lock    = threading.Lock()
        self._redis   = None
        redis_url = os.getenv("REDIS_URL","")
        if redis_url:
            try:
                import redis as _r
                self._redis = _r.from_url(redis_url, socket_timeout=1)
                self._redis.ping()
            except Exception:
                self._redis = None

    def _tier(self, path: str) -> str:
        if "/scan" in path:    return "scan"
        if "/auth" in path:    return "auth"
        if "/llm" in path or "/copilot" in path: return "ai"
        if "/report" in path or "/compliance" in path: return "report"
        if "/benchmark" in path: return "benchmark"
        return "default"

    def check(self, key: str, path: str) -> Tuple[bool, int, int]:
        """Returns (allowed, remaining, retry_after_seconds)."""
        lim  = _LIMITS.get(self._tier(path), _LIMITS["default"])
        wkey = f"rl:{key}:{self._tier(path)}"
        now  = time.time()
        with self._lock:
            dq = self._windows[wkey]
            while dq and dq[0] < now - lim.window:
                dq.popleft()
            if len(dq) >= lim.requests:
                retry = int(dq[0] + lim.window - now) + 1
                return False, 0, retry
            dq.append(now)
            return True, lim.requests - len(dq), 0

    def reset(self, key: str, path: str = "/") -> None:
        wkey = f"rl:{key}:{self._tier(path)}"
        with self._lock:
            self._windows.pop(wkey, None)

    def status(self) -> dict:
        return {
            "backend": "redis" if self._redis else "memory",
            "limits": {k: {"requests": v.requests, "window": v.window}
                       for k, v in _LIMITS.items()},
        }

RATE_LIMITER = RateLimiter()
