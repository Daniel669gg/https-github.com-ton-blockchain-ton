"""
Ghost Security Platform v13 — Ollama Provider v2
Improved Ollama integration with caching, health checks, streaming, and a
model fallback chain.  Uses only stdlib (urllib) for HTTP — no requests/httpx.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from typing import Generator, Optional

from ghost_security.runtime.providers.inference_cache import InferenceCache

logger = logging.getLogger(__name__)

# Fallback chain when the requested model is unavailable
_FALLBACK_CHAIN = [
    "qwen2.5-coder:7b",
    "llama3.2:3b",
    "mistral:7b",
]


def _http_post(url: str, payload: dict, timeout: int) -> dict:
    """POST JSON to *url* and return the parsed response dict."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_get(url: str, timeout: int) -> dict:
    """GET *url* and return the parsed response dict."""
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _http_post_stream(url: str, payload: dict, timeout: int) -> Generator[str, None, None]:
    """
    POST JSON to *url* and stream NDJSON lines back.
    Yields the ``response`` field from each non-empty line.
    """
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        for raw_line in resp:
            line = raw_line.decode("utf-8").strip()
            if not line:
                continue
            try:
                chunk = json.loads(line)
            except json.JSONDecodeError:
                continue
            token = chunk.get("response", "")
            if token:
                yield token
            if chunk.get("done"):
                break


class OllamaProviderV2:
    """
    Improved Ollama provider for Ghost Security v13.

    Features:
    - ``InferenceCache`` integration (SQLite, TTL-based)
    - Health checking and model availability
    - Automatic fallback to a known-good model when the requested one is absent
    - Streaming generation (yields tokens)
    - Pure-stdlib HTTP via ``urllib``
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        timeout: int = 60,
        cache: Optional[InferenceCache] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._cache = cache or InferenceCache()

    # ------------------------------------------------------------------
    # Availability / discovery
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if Ollama is running and reachable (checks /api/tags)."""
        try:
            _http_get(f"{self.base_url}/api/tags", timeout=5)
            return True
        except Exception:
            return False

    def list_models(self) -> list[str]:
        """Return a list of model names available in this Ollama instance."""
        try:
            data = _http_get(f"{self.base_url}/api/tags", timeout=self.timeout)
        except Exception as exc:
            logger.warning("list_models failed: %s", exc)
            return []
        models_data = data.get("models") or []
        return [m.get("name", "") for m in models_data if m.get("name")]

    # ------------------------------------------------------------------
    # Model resolution
    # ------------------------------------------------------------------

    def _resolve_model(self, requested: str) -> str:
        """
        Return *requested* if it is available, otherwise walk the fallback
        chain and return the first match.  If nothing matches, return the
        first item in the fallback chain as a last resort.
        """
        available = self.list_models()
        if not available:
            # Ollama may not be running or may have no models yet;
            # return the requested model and let the actual call fail naturally.
            return requested

        # Exact or prefix match
        def _matches(name: str, candidate: str) -> bool:
            return candidate == name or candidate.startswith(name.split(":")[0] + ":")

        if any(_matches(requested, a) for a in available):
            return requested

        logger.warning("Model %r not available; trying fallback chain.", requested)
        for fallback in _FALLBACK_CHAIN:
            if any(_matches(fallback, a) for a in available):
                logger.info("Using fallback model: %s", fallback)
                return fallback

        # Nothing matched — return first fallback so we fail gracefully
        logger.warning("No fallback model found; defaulting to %s", _FALLBACK_CHAIN[0])
        return _FALLBACK_CHAIN[0]

    # ------------------------------------------------------------------
    # Generation
    # ------------------------------------------------------------------

    def generate(
        self,
        model: str,
        prompt: str,
        stream: bool = False,
    ):
        """
        Generate a response from Ollama.

        Args:
            model:  Model name (e.g. ``"qwen2.5-coder:7b"``).
            prompt: The prompt text.
            stream: If ``True``, returns a generator yielding string chunks.
                    If ``False`` (default), returns the full response string.

        When ``stream=False``, the response is cached and served from cache on
        subsequent identical calls.
        """
        resolved = self._resolve_model(model)

        if not stream:
            # Check cache
            prompt_hash = self._cache.hash_prompt(resolved, prompt)
            cached = self._cache.get(prompt_hash)
            if cached is not None:
                logger.debug("Inference cache hit for model=%s", resolved)
                return cached

            # Live call
            response = self._generate_sync(resolved, prompt)

            # Store in cache
            self._cache.set(prompt_hash, response)
            return response

        # Streaming — no cache (caller consumes a generator)
        return self._generate_stream(resolved, prompt)

    def _generate_sync(self, model: str, prompt: str) -> str:
        """Blocking generation; returns the full response text."""
        url = f"{self.base_url}/api/generate"
        payload = {"model": model, "prompt": prompt, "stream": False}
        try:
            data = _http_post(url, payload, timeout=self.timeout)
        except urllib.error.URLError as exc:
            logger.error("Ollama generate error: %s", exc)
            raise RuntimeError(f"Ollama unavailable: {exc}") from exc
        return data.get("response", "")

    def _generate_stream(self, model: str, prompt: str) -> Generator[str, None, None]:
        """Generator that yields response chunks from Ollama's streaming API."""
        url = f"{self.base_url}/api/generate"
        payload = {"model": model, "prompt": prompt, "stream": True}
        yield from _http_post_stream(url, payload, timeout=self.timeout)

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def health_check(self) -> dict:
        """
        Return a health summary dict:

        .. code-block:: python

            {
                "status": "ok" | "unavailable",
                "models": ["qwen2.5-coder:7b", ...],
                "response_time_ms": 142.3,
            }

        Unlike ``list_models()`` (which swallows errors), this method propagates
        connectivity failures into the ``"unavailable"`` status path.
        """
        t0 = time.perf_counter()
        try:
            # Use the raw HTTP helper directly so we see connection errors.
            data = _http_get(f"{self.base_url}/api/tags", timeout=self.timeout)
            response_time_ms = (time.perf_counter() - t0) * 1000
            models_data = data.get("models") or []
            models = [m.get("name", "") for m in models_data if m.get("name")]
            return {
                "status": "ok",
                "models": models,
                "response_time_ms": round(response_time_ms, 2),
            }
        except Exception as exc:
            response_time_ms = (time.perf_counter() - t0) * 1000
            logger.warning("Ollama health check failed: %s", exc)
            return {
                "status": "unavailable",
                "models": [],
                "response_time_ms": round(response_time_ms, 2),
                "error": str(exc),
            }
