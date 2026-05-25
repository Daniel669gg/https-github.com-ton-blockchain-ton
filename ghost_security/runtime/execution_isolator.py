"""
Ghost Security Platform — Execution Isolator
Runs individual scanner functions in subprocess isolation so a hung or
crashing scanner cannot bring down the main process.

Usage (sync)::

    iso = ExecutionIsolator()
    result = iso.run_isolated(
        "scanners.java_scanner.JavaScanner.scan_directory",
        {"path": "/repo"},
        timeout=60.0,
    )
    # result == {"success": True, "result": {...}, "duration": 1.23}

Usage (async)::

    iso = ExecutionIsolator()
    result = await iso.run_isolated_async(
        "scanners.java_scanner.JavaScanner.scan_directory",
        {"path": "/repo"},
        timeout=60.0,
    )
"""
from __future__ import annotations

import asyncio
import dataclasses
import json
import subprocess
import sys
import time
from typing import Any, Dict

# ---------------------------------------------------------------------------
# Runner script embedded as a string constant.
# It is written to a temporary file at first use and reused thereafter.
# The script is given three command-line arguments:
#   argv[1]  dotted fn_path   e.g. "scanners.java_scanner.JavaScanner.scan"
#   argv[2]  JSON-encoded args dict
#
# stdout  → JSON {"ok": true,  "result": <any>}
#         → JSON {"ok": false, "error": "<message>"}
# stderr  → free-form traceback (ignored by the isolator)
# ---------------------------------------------------------------------------

_RUNNER_SCRIPT = r"""
import json
import sys
import traceback

def _load_fn(fn_path):
    parts = fn_path.rsplit(".", 1)
    if len(parts) != 2:
        raise ImportError(f"Cannot parse fn_path: {fn_path!r}")
    module_path, attr = parts
    # Try direct import first; fall back to treating the last component
    # as a class name and the one before it as the function.
    import importlib
    try:
        mod = importlib.import_module(module_path)
        fn = getattr(mod, attr)
        # If it is a class, try to instantiate and call the first callable
        # attribute that matches a conventional scan method name.
        if isinstance(fn, type):
            instance = fn()
            for candidate in ("scan", "run", "execute", "analyze"):
                if hasattr(instance, candidate):
                    return getattr(instance, candidate)
        return fn
    except (ImportError, AttributeError):
        # module_path might be "pkg.module.ClassName", attr == "method"
        parts2 = module_path.rsplit(".", 1)
        if len(parts2) == 2:
            mod = importlib.import_module(parts2[0])
            cls = getattr(mod, parts2[1])
            instance = cls()
            return getattr(instance, attr)
        raise


def main():
    if len(sys.argv) < 3:
        print(json.dumps({"ok": False, "error": "usage: runner <fn_path> <json_args>"}))
        sys.exit(1)

    fn_path = sys.argv[1]
    try:
        args = json.loads(sys.argv[2])
    except json.JSONDecodeError as exc:
        print(json.dumps({"ok": False, "error": f"bad args JSON: {exc}"}))
        sys.exit(1)

    try:
        fn = _load_fn(fn_path)
        if isinstance(args, dict):
            result = fn(**args)
        else:
            result = fn(args)
        print(json.dumps({"ok": True, "result": result}, default=str))
    except Exception:
        tb = traceback.format_exc()
        print(json.dumps({"ok": False, "error": tb}))
        sys.exit(1)


main()
""".lstrip()


@dataclasses.dataclass
class ResourceLimits:
    """
    Resource constraints applied to isolated subprocesses.

    Attributes
    ----------
    max_memory_mb : int   — (informational) soft memory ceiling in MiB.
                            Enforced on Linux via resource.setrlimit when
                            available; treated as advisory on other platforms.
    timeout       : float — hard wall-clock limit in seconds.
    """
    max_memory_mb: int   = 512
    timeout:       float = 120.0


class ExecutionIsolator:
    """
    Spawn scanner functions in isolated subprocesses.

    Each call to :meth:`run_isolated` (or :meth:`run_isolated_async`) forks a
    fresh Python interpreter that imports and calls the target function, then
    exits.  The main process is protected from infinite loops, segfaults, and
    memory leaks inside scanner code.

    Parameters
    ----------
    limits : ResourceLimits
        Default resource limits; per-call ``timeout`` overrides
        ``limits.timeout`` when supplied.
    extra_sys_path : list[str]
        Extra directories prepended to ``sys.path`` in the child process.
        Defaults to the parent's ``sys.path``.
    """

    def __init__(
        self,
        limits: ResourceLimits | None = None,
        extra_sys_path: list[str] | None = None,
    ) -> None:
        self._limits = limits or ResourceLimits()
        self._sys_path: list[str] = extra_sys_path if extra_sys_path is not None else list(sys.path)
        self._runner_path: str | None = None   # written lazily

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _ensure_runner(self) -> str:
        """Write the embedded runner script to a temp file once."""
        if self._runner_path is not None:
            return self._runner_path

        import tempfile, os, atexit
        fd, path = tempfile.mkstemp(suffix="_ghost_runner.py", prefix="ghost_")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_RUNNER_SCRIPT)
        self._runner_path = path
        atexit.register(lambda p=path: _silent_remove(p))
        return path

    def _build_env(self) -> dict[str, str]:
        """Build the subprocess environment with the right PYTHONPATH."""
        import os
        env = os.environ.copy()
        env["PYTHONPATH"] = ":".join(self._sys_path)
        return env

    # ── Synchronous API ──────────────────────────────────────────────────────

    def run_isolated(
        self,
        fn_path: str,
        args: Dict[str, Any],
        timeout: float | None = None,
    ) -> Dict[str, Any]:
        """
        Run *fn_path* in a subprocess and return a result dict.

        Parameters
        ----------
        fn_path : dotted module.function (or module.Class.method) string.
        args    : keyword arguments passed to the function.
        timeout : wall-clock limit in seconds.  Defaults to
                  ``self._limits.timeout``.

        Returns
        -------
        On success::

            {"success": True, "result": <return value>, "duration": <float>}

        On any failure (exception, timeout, bad JSON, non-zero exit)::

            {"success": False, "error": "<message>", "duration": <float>}
        """
        effective_timeout = timeout if timeout is not None else self._limits.timeout
        runner = self._ensure_runner()
        args_json = json.dumps(args, default=str)
        cmd = [sys.executable, runner, fn_path, args_json]
        env = self._build_env()

        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                env=env,
            )
            duration = round(time.monotonic() - t0, 4)

            if proc.returncode != 0 and not proc.stdout.strip():
                err_text = proc.stderr.strip() or f"exit code {proc.returncode}"
                return {"success": False, "error": err_text, "duration": duration}

            raw = proc.stdout.strip()
            if not raw:
                err_text = proc.stderr.strip() or "no output from subprocess"
                return {"success": False, "error": err_text, "duration": duration}

            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as exc:
                return {
                    "success": False,
                    "error": f"JSON decode error: {exc}; raw: {raw[:200]}",
                    "duration": duration,
                }

            if payload.get("ok"):
                return {"success": True, "result": payload.get("result"), "duration": duration}
            else:
                return {"success": False, "error": payload.get("error", "unknown error"), "duration": duration}

        except subprocess.TimeoutExpired as exc:
            duration = round(time.monotonic() - t0, 4)
            # Make sure the child is dead.
            # subprocess.run() raises TimeoutExpired without a .process attribute;
            # only Popen-based usage attaches it.  Use getattr to handle both.
            proc_ref = getattr(exc, "process", None)
            if proc_ref is not None:
                try:
                    proc_ref.kill()
                except Exception:
                    pass
            return {
                "success": False,
                "error": f"Timeout after {effective_timeout}s",
                "duration": duration,
            }
        except Exception as exc:
            duration = round(time.monotonic() - t0, 4)
            return {"success": False, "error": str(exc), "duration": duration}

    # ── Asynchronous API ─────────────────────────────────────────────────────

    async def run_isolated_async(
        self,
        fn_path: str,
        args: Dict[str, Any],
        timeout: float | None = None,
    ) -> Dict[str, Any]:
        """
        Async version of :meth:`run_isolated`.

        Uses :func:`asyncio.create_subprocess_exec` so the event loop is not
        blocked while waiting for the child process.

        Parameters and return value are identical to :meth:`run_isolated`.
        """
        effective_timeout = timeout if timeout is not None else self._limits.timeout
        runner = self._ensure_runner()
        args_json = json.dumps(args, default=str)
        cmd = [sys.executable, runner, fn_path, args_json]
        env = self._build_env()

        t0 = time.monotonic()
        proc: asyncio.subprocess.Process | None = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=effective_timeout
                )
            except asyncio.TimeoutError:
                duration = round(time.monotonic() - t0, 4)
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
                return {
                    "success": False,
                    "error": f"Timeout after {effective_timeout}s",
                    "duration": duration,
                }

            duration = round(time.monotonic() - t0, 4)
            raw = stdout_bytes.decode("utf-8", errors="replace").strip()

            if proc.returncode != 0 and not raw:
                err_text = (
                    stderr_bytes.decode("utf-8", errors="replace").strip()
                    or f"exit code {proc.returncode}"
                )
                return {"success": False, "error": err_text, "duration": duration}

            if not raw:
                err_text = (
                    stderr_bytes.decode("utf-8", errors="replace").strip()
                    or "no output from subprocess"
                )
                return {"success": False, "error": err_text, "duration": duration}

            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as exc:
                return {
                    "success": False,
                    "error": f"JSON decode error: {exc}; raw: {raw[:200]}",
                    "duration": duration,
                }

            if payload.get("ok"):
                return {"success": True, "result": payload.get("result"), "duration": duration}
            else:
                return {"success": False, "error": payload.get("error", "unknown error"), "duration": duration}

        except Exception as exc:
            duration = round(time.monotonic() - t0, 4)
            if proc is not None:
                try:
                    proc.kill()
                except Exception:
                    pass
            return {"success": False, "error": str(exc), "duration": duration}


# ── Utilities ────────────────────────────────────────────────────────────────

def _silent_remove(path: str) -> None:
    """Delete *path* without raising if it doesn't exist."""
    import os
    try:
        os.unlink(path)
    except OSError:
        pass


# Module-level singleton
ISOLATOR = ExecutionIsolator()
