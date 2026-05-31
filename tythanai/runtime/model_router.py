"""
TythanAI — Model Router v2.2
Routes tasks to the best available model:
  1. Task-specific Ollama model (if running locally)
  2. Configured OpenAI-compatible endpoint
  3. Graceful fallback with explanation
"""
import sys
import urllib.request
import urllib.error
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.config import OPENAI_API_KEY, OPENAI_BASE_URL, LLM_MODEL, LLM_FAST_MODEL


# Task → preferred local Ollama model → fallback cloud model
ROUTES = {
    "planning":  {"ollama": "deepseek-r1",       "cloud": LLM_MODEL},
    "coding":    {"ollama": "deepseek-coder-v2",  "cloud": LLM_MODEL},
    "critique":  {"ollama": "qwen3",              "cloud": LLM_FAST_MODEL},
    "security":  {"ollama": "qwen3",              "cloud": LLM_MODEL},
    "ton":       {"ollama": "deepseek-coder-v2",  "cloud": LLM_MODEL},
    "report":    {"ollama": "qwen3",              "cloud": LLM_FAST_MODEL},
    "default":   {"ollama": "deepseek-r1",        "cloud": LLM_MODEL},
}


class ModelRouter:
    """
    Routes each task type to the most appropriate available model.
    Detects Ollama availability once at startup and caches the result.
    """

    def __init__(self):
        self._ollama_ok: bool | None = None   # None = not yet checked
        self._ollama_models: list[str] = []

    # ── Public API ────────────────────────────────────────────────────────────

    def route(self, task_type: str) -> str:
        """Return the model name string to use for this task."""
        entry = ROUTES.get(task_type, ROUTES["default"])
        if self._ollama_available():
            preferred = entry["ollama"]
            if preferred in self._ollama_models or not self._ollama_models:
                return preferred
        return entry["cloud"]

    def get_client(self, task_type: str):
        """Return a configured OpenAI client pointed at the right backend."""
        from openai import OpenAI
        model = self.route(task_type)
        if self._ollama_available() and ROUTES.get(task_type, {}).get("ollama") in (self._ollama_models or [model]):
            return OpenAI(api_key="ollama", base_url="http://localhost:11434/v1"), model
        if OPENAI_API_KEY:
            return OpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL), model
        raise RuntimeError(
            "No LLM available. Set OPENAI_API_KEY in .env or start Ollama locally."
        )

    def status(self) -> dict:
        """Return current routing status (useful for /health endpoint)."""
        ollama = self._ollama_available()
        return {
            "ollama_available": ollama,
            "ollama_models": self._ollama_models if ollama else [],
            "cloud_available": bool(OPENAI_API_KEY),
            "active_backend": "ollama" if ollama else ("cloud" if OPENAI_API_KEY else "none"),
            "routes": {k: self.route(k) for k in ROUTES},
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _ollama_available(self) -> bool:
        if self._ollama_ok is not None:
            return self._ollama_ok
        try:
            req = urllib.request.Request(
                "http://localhost:11434/api/tags",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read())
                self._ollama_models = [m["name"] for m in data.get("models", [])]
                self._ollama_ok = True
        except Exception:
            self._ollama_ok = False
        return self._ollama_ok
