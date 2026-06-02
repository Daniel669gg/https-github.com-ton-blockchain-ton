"""
Ghost Security Platform — Production Middleware (FastAPI adapter)
Wraps core rate limiter / logger into FastAPI middleware.
FastAPI imports are lazy — core modules work without FastAPI.
"""
from __future__ import annotations
import os, time, traceback, uuid
from typing import Optional

from core.security.rate_limiter    import RATE_LIMITER
from core.security.structured_logger import LOG


# ---------------------------------------------------------------------------
# FastAPI dependency functions (used with Depends())
# ---------------------------------------------------------------------------
# We import FastAPI types lazily so that core modules remain importable
# without FastAPI installed (unit tests, CLI usage).
try:
    from fastapi import HTTPException as _HTTPException, Request as _Request
    from fastapi.security.utils import get_authorization_scheme_param as _scheme_param
    _FASTAPI_AVAILABLE = True
except ImportError:
    _HTTPException = Exception  # type: ignore[misc,assignment]
    _Request = None             # type: ignore[assignment,misc]
    _FASTAPI_AVAILABLE = False


async def verify_api_key(request: Optional[_Request] = None) -> bool:  # type: ignore[valid-type]
    """FastAPI dependency: validate API key from Authorization header.

    When API_KEY_REQUIRED env var is unset or empty, all requests pass
    (development / self-hosted mode).  In production set API_KEY_REQUIRED=1
    and provide valid keys via API_KEYS (comma-separated).
    """
    if not os.getenv("API_KEY_REQUIRED", "").strip():
        return True
    if not _FASTAPI_AVAILABLE or request is None:
        return True

    auth_header: str = request.headers.get("Authorization", "")
    scheme, token = _scheme_param(auth_header)
    if scheme.lower() != "bearer" or not token:
        raise _HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    valid_keys = {k.strip() for k in os.getenv("API_KEYS", "").split(",") if k.strip()}
    if valid_keys and token not in valid_keys:
        raise _HTTPException(status_code=403, detail="Invalid API key")
    return True


async def rate_limit(request: Optional[_Request] = None) -> bool:  # type: ignore[valid-type]
    """FastAPI dependency: per-route rate limit check (complements global middleware)."""
    if not _FASTAPI_AVAILABLE or request is None:
        return True

    auth: str = request.headers.get("authorization", "")
    key = auth[7:27] if auth.startswith("Bearer ") else (
        request.client.host if request.client else "anon"
    )
    allowed, remaining, retry = RATE_LIMITER.check(key, request.url.path)
    if not allowed:
        raise _HTTPException(
            status_code=429,
            detail={"error": "rate_limit_exceeded", "retry_after": retry},
            headers={"Retry-After": str(retry), "X-RateLimit-Remaining": "0"},
        )
    return True


def register_middleware(app) -> None:
    """Register all production middleware on a FastAPI app."""
    from fastapi.responses import JSONResponse
    from starlette.middleware.base import BaseHTTPMiddleware

    class _RateLimitMW(BaseHTTPMiddleware):
        _SKIP = {"/health","/metrics","/docs","/openapi.json","/redoc","/ping"}
        async def dispatch(self, request, call_next):
            if request.url.path in self._SKIP:
                return await call_next(request)
            auth = request.headers.get("authorization","")
            key  = auth[7:27] if auth.startswith("Bearer ") else (
                request.client.host if request.client else "anon")
            allowed, remaining, retry = RATE_LIMITER.check(key, request.url.path)
            if not allowed:
                LOG.warning("rate_limited", key=key[:16], path=request.url.path)
                return JSONResponse(
                    status_code=429,
                    content={"error":"rate_limit_exceeded","retry_after":retry},
                    headers={"Retry-After":str(retry),"X-RateLimit-Remaining":"0"},
                )
            resp = await call_next(request)
            resp.headers["X-RateLimit-Remaining"] = str(remaining)
            return resp

    class _RequestIDMW(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())[:16]
            request.state.request_id = rid
            request.state.start_time = time.time()
            resp = await call_next(request)
            resp.headers["X-Request-ID"] = rid
            return resp

    class _LoggerMW(BaseHTTPMiddleware):
        _SKIP = {"/metrics","/health","/ping"}
        async def dispatch(self, request, call_next):
            if request.url.path in self._SKIP:
                return await call_next(request)
            t0  = time.time()
            rid = getattr(request.state, "request_id", "-")
            try:
                resp = await call_next(request)
            except Exception as exc:
                LOG.error("request_error", request_id=rid, path=request.url.path, error=str(exc))
                raise
            ms = int((time.time()-t0)*1000)
            LOG.request_log(
                {"request_id":rid,"method":request.method,"path":request.url.path,
                 "ip": request.client.host if request.client else "-"},
                {"status":resp.status_code,"latency_ms":ms},
            )
            resp.headers["X-Response-Time"] = f"{ms}ms"
            return resp

    class _SecHeadersMW(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            resp = await call_next(request)
            resp.headers.update({
                "X-Content-Type-Options":    "nosniff",
                "X-Frame-Options":           "DENY",
                "X-XSS-Protection":          "1; mode=block",
                "Referrer-Policy":           "strict-origin-when-cross-origin",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            })
            return resp

    async def _global_exc_handler(request, exc):
        rid = getattr(request.state, "request_id", str(uuid.uuid4())[:8])
        LOG.error("unhandled_exception", request_id=rid, path=request.url.path,
                  error=str(exc), tb=traceback.format_exc()[-400:])
        if os.getenv("SENTRY_DSN"):
            try:
                import sentry_sdk; sentry_sdk.capture_exception(exc)
            except Exception: pass
        return JSONResponse(status_code=500, content={
            "error": "internal_server_error",
            "message": "Unexpected error. Our team has been notified.",
            "request_id": rid,
        })

    app.add_middleware(_SecHeadersMW)
    app.add_middleware(_LoggerMW)
    app.add_middleware(_RequestIDMW)
    app.add_middleware(_RateLimitMW)
    app.add_exception_handler(Exception, _global_exc_handler)


async def deep_health_check() -> dict:
    """Deep health check of all dependencies."""
    import time
    checks: dict = {}
    overall = True

    def _chk(name, fn):
        nonlocal overall
        t0 = time.time()
        try:
            detail = fn() or {}
            ok = detail.pop("_ok", True) if isinstance(detail, dict) else True
            checks[name] = {"ok": ok, "latency_ms": int((time.time()-t0)*1000), **detail}
            if not ok: overall = False
        except Exception as e:
            checks[name] = {"ok": False, "error": str(e)[:100]}
            overall = False

    _chk("database",      lambda: (__import__("core.persistence.db", fromlist=["get_db"]).get_db().list_scans(limit=1), {})[1])
    _chk("rate_limiter",  lambda: RATE_LIMITER.status())
    _chk("disk",          lambda: __import__("shutil").disk_usage("/") and {"_ok": True})
    _chk("audit_log",     lambda: __import__("core.audit_log", fromlist=["AUDIT"]).AUDIT.verify_integrity())

    return {
        "ok": overall,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "version": "10.0.0",
        "checks": checks,
    }
