"""
Ghost Security Platform — Structured Logger (no framework dependency)
Pure Python JSON logger, testable standalone.
"""
from __future__ import annotations

import json, os, time, threading
from typing import Optional

class StructuredLogger:
    def __init__(self, service: str = "ghost-security"):
        self._service = service
        self._lock    = threading.Lock()
        self._level   = os.getenv("GHOST_LOG_LEVEL", "INFO")
        self._levels  = {"DEBUG":0,"INFO":1,"WARNING":2,"ERROR":3}
        self._file    = os.getenv("GHOST_LOG_FILE","")

    def _emit(self, level: str, event: str, **ctx) -> None:
        if self._levels.get(level,1) < self._levels.get(self._level,1):
            return
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "level": level, "service": self._service, "event": event,
            **{k: v for k, v in ctx.items() if v is not None},
        }
        line = json.dumps(rec, ensure_ascii=False)
        with self._lock:
            if self._file:
                try:
                    with open(self._file, "a") as f: f.write(line + "\n")
                except Exception: pass
            else:
                print(line, flush=True)

    def info(self, ev, **c):    self._emit("INFO",    ev, **c)
    def warning(self, ev, **c): self._emit("WARNING", ev, **c)
    def error(self, ev, **c):   self._emit("ERROR",   ev, **c)
    def debug(self, ev, **c):   self._emit("DEBUG",   ev, **c)

    def request_log(self, req: dict, resp: dict) -> None:
        lvl = "WARNING" if resp.get("status", 200) >= 400 else "INFO"
        self._emit(lvl, "http_request", **req, **resp)

LOG = StructuredLogger()
