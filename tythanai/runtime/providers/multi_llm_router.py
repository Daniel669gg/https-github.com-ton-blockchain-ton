"""
TythanAI Platform — Multi-LLM Router
Маршрутизация между провайдерами: Claude, OpenAI, Gemini, Ollama.
Фичи:
  • Task-based routing (security / coding / report / fast)
  • Consensus engine — N провайдеров голосуют, побеждает большинство
  • Fallback chains — если провайдер упал, автоматически следующий
  • Cost tracking — считаем токены и стоимость
  • Response arbitration — выбираем лучший ответ из нескольких
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# ══════════════════════════════════════════════════════════════════════════════
# ПРОВАЙДЕРЫ
# ══════════════════════════════════════════════════════════════════════════════

class Provider(str, Enum):
    CLAUDE  = "claude"
    OPENAI  = "openai"
    GEMINI  = "gemini"
    OLLAMA  = "ollama"


@dataclass
class LLMResponse:
    text:       str
    provider:   Provider
    model:      str
    tokens_in:  int   = 0
    tokens_out: int   = 0
    latency_ms: int   = 0
    cost_usd:   float = 0.0
    error:      str   = ""

    @property
    def ok(self) -> bool:
        return bool(self.text) and not self.error


# ── Pricing (USD per 1M tokens, as of 2025) ───────────────────────────────────
_PRICING: Dict[str, Tuple[float, float]] = {  # (input, output) per 1M tokens
    "claude-sonnet-4-6":        (3.00,  15.00),
    "claude-haiku-4-5":         (0.25,   1.25),
    "gpt-4o":                   (2.50,  10.00),
    "gpt-4o-mini":              (0.15,   0.60),
    "gemini-1.5-pro":           (1.25,   5.00),
    "gemini-1.5-flash":         (0.075,  0.30),
    "gemini-2.0-flash":         (0.10,   0.40),
    "deepseek-r1":              (0.0,    0.0),  # local
    "qwen3":                    (0.0,    0.0),  # local
}

def _calc_cost(model: str, tokens_in: int, tokens_out: int) -> float:
    inp, out = _PRICING.get(model, (0.0, 0.0))
    return round((tokens_in * inp + tokens_out * out) / 1_000_000, 6)


# ══════════════════════════════════════════════════════════════════════════════
# CLAUDE ADAPTER
# ══════════════════════════════════════════════════════════════════════════════

class ClaudeAdapter:
    """Anthropic Claude via official API."""

    _DEFAULT_MODEL = "claude-sonnet-4-6"
    _FAST_MODEL    = "claude-haiku-4-5"

    def __init__(self) -> None:
        self.api_key  = os.getenv("ANTHROPIC_API_KEY", "")
        self.base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")

    def is_available(self) -> bool:
        return bool(self.api_key)

    def call(
        self,
        prompt: str,
        system: str = "",
        model: str  = "",
        max_tokens: int = 2048,
        temperature: float = 0.1,
    ) -> LLMResponse:
        if not self.is_available():
            return LLMResponse("", Provider.CLAUDE, model, error="No ANTHROPIC_API_KEY")

        import urllib.request
        model = model or self._DEFAULT_MODEL
        t0    = time.time()

        messages = [{"role": "user", "content": prompt}]
        body: Dict[str, Any] = {
            "model":      model,
            "max_tokens": max_tokens,
            "messages":   messages,
        }
        if system:
            body["system"] = system

        req = urllib.request.Request(
            f"{self.base_url}/v1/messages",
            data    = json.dumps(body).encode(),
            headers = {
                "x-api-key":         self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            },
            method = "POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read())
            text   = data["content"][0]["text"]
            usage  = data.get("usage", {})
            tin    = usage.get("input_tokens",  0)
            tout   = usage.get("output_tokens", 0)
            return LLMResponse(
                text       = text,
                provider   = Provider.CLAUDE,
                model      = model,
                tokens_in  = tin,
                tokens_out = tout,
                latency_ms = int((time.time() - t0) * 1000),
                cost_usd   = _calc_cost(model, tin, tout),
            )
        except Exception as e:
            return LLMResponse("", Provider.CLAUDE, model, error=str(e))


# ══════════════════════════════════════════════════════════════════════════════
# OPENAI ADAPTER
# ══════════════════════════════════════════════════════════════════════════════

class OpenAIAdapter:
    """OpenAI / any OpenAI-compatible endpoint."""

    _DEFAULT_MODEL = "gpt-4o-mini"

    def __init__(self) -> None:
        self.api_key  = os.getenv("OPENAI_API_KEY", "")
        self.base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")

    def is_available(self) -> bool:
        return bool(self.api_key)

    def call(
        self,
        prompt: str,
        system: str    = "",
        model: str     = "",
        max_tokens: int = 2048,
        temperature: float = 0.1,
    ) -> LLMResponse:
        if not self.is_available():
            return LLMResponse("", Provider.OPENAI, model, error="No OPENAI_API_KEY")

        import urllib.request
        model    = model or self._DEFAULT_MODEL
        t0       = time.time()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data    = json.dumps({
                "model": model, "messages": messages,
                "max_tokens": max_tokens, "temperature": temperature,
            }).encode(),
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type":  "application/json",
            },
            method = "POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read())
            text  = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})
            tin   = usage.get("prompt_tokens",     0)
            tout  = usage.get("completion_tokens",  0)
            return LLMResponse(
                text       = text,
                provider   = Provider.OPENAI,
                model      = model,
                tokens_in  = tin,
                tokens_out = tout,
                latency_ms = int((time.time() - t0) * 1000),
                cost_usd   = _calc_cost(model, tin, tout),
            )
        except Exception as e:
            return LLMResponse("", Provider.OPENAI, model, error=str(e))


# ══════════════════════════════════════════════════════════════════════════════
# GEMINI ADAPTER
# ══════════════════════════════════════════════════════════════════════════════

class GeminiAdapter:
    """Google Gemini via Generative Language API."""

    _DEFAULT_MODEL = "gemini-1.5-flash"

    def __init__(self) -> None:
        self.api_key = os.getenv("GEMINI_API_KEY", os.getenv("GOOGLE_API_KEY", ""))

    def is_available(self) -> bool:
        return bool(self.api_key)

    def call(
        self,
        prompt: str,
        system: str    = "",
        model: str     = "",
        max_tokens: int = 2048,
        temperature: float = 0.1,
    ) -> LLMResponse:
        if not self.is_available():
            return LLMResponse("", Provider.GEMINI, model, error="No GEMINI_API_KEY")

        import urllib.request
        model = model or self._DEFAULT_MODEL
        t0    = time.time()

        # Combine system + user if system provided
        full_prompt = f"{system}\n\n{prompt}" if system else prompt
        body = {
            "contents": [{"parts": [{"text": full_prompt}]}],
            "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens},
        }
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent?key={self.api_key}"
        )
        req = urllib.request.Request(
            url,
            data    = json.dumps(body).encode(),
            headers = {"Content-Type": "application/json"},
            method  = "POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read())
            text = data["candidates"][0]["content"]["parts"][0]["text"]
            # Gemini doesn't always return token counts
            meta = data.get("usageMetadata", {})
            tin  = meta.get("promptTokenCount",     0)
            tout = meta.get("candidatesTokenCount", 0)
            return LLMResponse(
                text       = text,
                provider   = Provider.GEMINI,
                model      = model,
                tokens_in  = tin,
                tokens_out = tout,
                latency_ms = int((time.time() - t0) * 1000),
                cost_usd   = _calc_cost(model, tin, tout),
            )
        except Exception as e:
            return LLMResponse("", Provider.GEMINI, model, error=str(e))


# ══════════════════════════════════════════════════════════════════════════════
# OLLAMA ADAPTER
# ══════════════════════════════════════════════════════════════════════════════

class OllamaLocalAdapter:
    """Local Ollama models."""

    _DEFAULT_MODEL = "qwen3"

    def __init__(self) -> None:
        self.base_url     = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self._model_cache: Optional[List[str]] = None
        self._cache_ts: float = 0.0

    def is_available(self) -> bool:
        return bool(self.available_models())

    def available_models(self) -> List[str]:
        if time.time() - self._cache_ts < 60 and self._model_cache is not None:
            return self._model_cache
        import urllib.request
        try:
            with urllib.request.urlopen(
                f"{self.base_url}/api/tags", timeout=3
            ) as r:
                data = json.loads(r.read())
            self._model_cache = [m["name"].split(":")[0] for m in data.get("models", [])]
            self._cache_ts    = time.time()
        except Exception:
            self._model_cache = []
        return self._model_cache

    def call(
        self,
        prompt: str,
        system: str    = "",
        model: str     = "",
        max_tokens: int = 2048,
        temperature: float = 0.1,
    ) -> LLMResponse:
        avail = self.available_models()
        model = model or (avail[0] if avail else self._DEFAULT_MODEL)
        if not avail:
            return LLMResponse("", Provider.OLLAMA, model, error="Ollama not running")

        import urllib.request
        t0       = time.time()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data    = json.dumps({
                "model": model, "messages": messages, "stream": False,
                "options": {"temperature": temperature, "num_predict": max_tokens},
            }).encode(),
            headers = {"Content-Type": "application/json"},
            method  = "POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                data = json.loads(r.read())
            text = data.get("message", {}).get("content", "")
            return LLMResponse(
                text       = text,
                provider   = Provider.OLLAMA,
                model      = model,
                latency_ms = int((time.time() - t0) * 1000),
                cost_usd   = 0.0,
            )
        except Exception as e:
            return LLMResponse("", Provider.OLLAMA, model, error=str(e))


# ══════════════════════════════════════════════════════════════════════════════
# ROUTING TABLE
# ══════════════════════════════════════════════════════════════════════════════

# task → ordered list of (provider, model)
_ROUTING_TABLE: Dict[str, List[Tuple[str, str]]] = {
    "security": [
        (Provider.CLAUDE,  "claude-sonnet-4-6"),
        (Provider.OPENAI,  "gpt-4o"),
        (Provider.GEMINI,  "gemini-1.5-pro"),
        (Provider.OLLAMA,  "deepseek-r1"),
    ],
    "coding": [
        (Provider.CLAUDE,  "claude-sonnet-4-6"),
        (Provider.OPENAI,  "gpt-4o"),
        (Provider.OLLAMA,  "deepseek-coder-v2"),
        (Provider.GEMINI,  "gemini-1.5-flash"),
    ],
    "fast": [
        (Provider.CLAUDE,  "claude-haiku-4-5"),
        (Provider.OPENAI,  "gpt-4o-mini"),
        (Provider.GEMINI,  "gemini-2.0-flash"),
        (Provider.OLLAMA,  "qwen3"),
    ],
    "report": [
        (Provider.OPENAI,  "gpt-4o"),
        (Provider.CLAUDE,  "claude-sonnet-4-6"),
        (Provider.GEMINI,  "gemini-1.5-pro"),
        (Provider.OLLAMA,  "llama3.2"),
    ],
    "ton": [
        (Provider.CLAUDE,  "claude-sonnet-4-6"),
        (Provider.OPENAI,  "gpt-4o"),
        (Provider.OLLAMA,  "deepseek-coder-v2"),
        (Provider.GEMINI,  "gemini-1.5-pro"),
    ],
    "remediation": [
        (Provider.CLAUDE,  "claude-sonnet-4-6"),
        (Provider.OPENAI,  "gpt-4o"),
        (Provider.OLLAMA,  "deepseek-r1"),
        (Provider.GEMINI,  "gemini-1.5-pro"),
    ],
    "default": [
        (Provider.CLAUDE,  "claude-haiku-4-5"),
        (Provider.OPENAI,  "gpt-4o-mini"),
        (Provider.GEMINI,  "gemini-1.5-flash"),
        (Provider.OLLAMA,  "qwen3"),
    ],
}


# ══════════════════════════════════════════════════════════════════════════════
# CONSENSUS ENGINE
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ConsensusResult:
    winner:     LLMResponse
    all_responses: List[LLMResponse]
    agreement:  float   = 0.0  # 0–1, how much responses agree
    method:     str     = "majority"

    def to_dict(self) -> dict:
        return {
            "winner_provider": self.winner.provider,
            "winner_model":    self.winner.model,
            "agreement":       self.agreement,
            "method":          self.method,
            "responses":       len(self.all_responses),
            "text":            self.winner.text,
        }


class ConsensusEngine:
    """
    Запрашивает N провайдеров, выбирает лучший ответ.
    Стратегии: longest (самый подробный), fastest, cheapest, vote (NLP similarity).
    """

    def run(
        self,
        responses: List[LLMResponse],
        strategy: str = "longest",
    ) -> ConsensusResult:
        ok = [r for r in responses if r.ok]
        if not ok:
            # Все упали — возвращаем пустой
            fallback = responses[0] if responses else LLMResponse("", Provider.OLLAMA, "", error="all_failed")
            return ConsensusResult(fallback, responses, agreement=0.0, method="fallback")

        if strategy == "fastest":
            winner = min(ok, key=lambda r: r.latency_ms)
        elif strategy == "cheapest":
            winner = min(ok, key=lambda r: r.cost_usd)
        elif strategy == "vote":
            winner = self._vote(ok)
        else:  # longest — самый подробный ответ
            winner = max(ok, key=lambda r: len(r.text))

        agreement = self._agreement(ok)
        return ConsensusResult(winner, responses, agreement=agreement, method=strategy)

    @staticmethod
    def _vote(responses: List[LLMResponse]) -> LLMResponse:
        """Выбирает ответ с наибольшим overlap слов с остальными."""
        if len(responses) == 1:
            return responses[0]
        scores = []
        for r in responses:
            words_r = set(r.text.lower().split())
            overlap = sum(
                len(words_r & set(other.text.lower().split()))
                for other in responses if other is not r
            )
            scores.append((overlap, r))
        return max(scores, key=lambda x: x[0])[1]

    @staticmethod
    def _agreement(responses: List[LLMResponse]) -> float:
        if len(responses) < 2:
            return 1.0
        # Jaccard overlap между всеми парами
        pairs, total = 0, 0.0
        for i in range(len(responses)):
            for j in range(i + 1, len(responses)):
                a = set(responses[i].text.lower().split())
                b = set(responses[j].text.lower().split())
                union = a | b
                total += len(a & b) / len(union) if union else 0
                pairs += 1
        return round(total / pairs, 3) if pairs else 0.0


# ══════════════════════════════════════════════════════════════════════════════
# MAIN ROUTER
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class CostTracker:
    total_cost_usd: float = 0.0
    total_calls:    int   = 0
    by_provider:    Dict[str, float] = field(default_factory=dict)

    def record(self, resp: LLMResponse) -> None:
        self.total_cost_usd += resp.cost_usd
        self.total_calls    += 1
        key = f"{resp.provider}/{resp.model}"
        self.by_provider[key] = self.by_provider.get(key, 0.0) + resp.cost_usd

    def summary(self) -> dict:
        return {
            "total_calls":    self.total_calls,
            "total_cost_usd": round(self.total_cost_usd, 6),
            "by_provider":    {k: round(v, 6) for k, v in self.by_provider.items()},
        }


class MultiLLMRouter:
    """
    Центральный маршрутизатор.

    Использование:
        router = MultiLLMRouter()
        resp   = router.call("security", "Analyse this code...", system="You are a security expert")
        # или с консенсусом:
        result = router.consensus("security", "...", providers=["claude","openai","ollama"])
    """

    def __init__(self) -> None:
        self._claude  = ClaudeAdapter()
        self._openai  = OpenAIAdapter()
        self._gemini  = GeminiAdapter()
        self._ollama  = OllamaLocalAdapter()
        self._consensus = ConsensusEngine()
        self.costs    = CostTracker()

        self._adapters: Dict[str, Any] = {
            Provider.CLAUDE: self._claude,
            Provider.OPENAI: self._openai,
            Provider.GEMINI: self._gemini,
            Provider.OLLAMA: self._ollama,
        }

    # ── Single call with fallback chain ───────────────────────────────────────

    def call(
        self,
        task: str,
        prompt: str,
        system: str      = "",
        max_tokens: int  = 2048,
        temperature: float = 0.1,
        force_provider: Optional[str] = None,
    ) -> LLMResponse:
        """
        Вызывает первый доступный провайдер из цепочки для данного task.
        При ошибке — автоматически следующий.
        """
        chain = _ROUTING_TABLE.get(task, _ROUTING_TABLE["default"])

        if force_provider:
            adapter = self._adapters.get(force_provider)
            if adapter:
                resp = adapter.call(prompt, system=system, max_tokens=max_tokens, temperature=temperature)
                self.costs.record(resp)
                return resp

        for provider, model in chain:
            adapter = self._adapters.get(provider)
            if not adapter or not adapter.is_available():
                continue
            resp = adapter.call(prompt, system=system, model=model,
                                max_tokens=max_tokens, temperature=temperature)
            self.costs.record(resp)
            if resp.ok:
                return resp
            # Логируем ошибку и пробуем следующий
            import logging
            logging.getLogger("ghost.router").warning(
                "Provider %s/%s failed: %s — trying next", provider, model, resp.error
            )

        return LLMResponse("", Provider.OLLAMA, "", error="all_providers_failed")

    # ── Consensus call ────────────────────────────────────────────────────────

    def consensus(
        self,
        task: str,
        prompt: str,
        system: str       = "",
        providers: Optional[List[str]] = None,
        strategy: str     = "longest",
        max_tokens: int   = 2048,
    ) -> ConsensusResult:
        """
        Вызывает несколько провайдеров параллельно и выбирает лучший ответ.
        Используй для высокоставочных решений (critical vuln analysis).
        """
        chain = _ROUTING_TABLE.get(task, _ROUTING_TABLE["default"])
        targets = [(p, m) for p, m in chain
                   if (providers is None or p in providers)
                   and self._adapters.get(p, None)
                   and self._adapters[p].is_available()][:3]  # max 3 провайдера

        if not targets:
            resp = self.call(task, prompt, system, max_tokens)
            return ConsensusResult(resp, [resp], agreement=1.0, method="single")

        responses: List[LLMResponse] = []
        for provider, model in targets:
            r = self._adapters[provider].call(
                prompt, system=system, model=model, max_tokens=max_tokens
            )
            self.costs.record(r)
            responses.append(r)

        return self._consensus.run(responses, strategy=strategy)

    # ── Async wrappers ────────────────────────────────────────────────────────

    async def acall(self, task: str, prompt: str, **kwargs) -> LLMResponse:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.call(task, prompt, **kwargs))

    async def aconsensus(self, task: str, prompt: str, **kwargs) -> ConsensusResult:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.consensus(task, prompt, **kwargs))

    # ── Status ────────────────────────────────────────────────────────────────

    def status(self) -> dict:
        return {
            "providers": {
                "claude":  {"available": self._claude.is_available(), "key_set": bool(self._claude.api_key)},
                "openai":  {"available": self._openai.is_available(), "key_set": bool(self._openai.api_key)},
                "gemini":  {"available": self._gemini.is_available(), "key_set": bool(self._gemini.api_key)},
                "ollama":  {"available": self._ollama.is_available(), "models": self._ollama.available_models()},
            },
            "costs": self.costs.summary(),
            "routing_tasks": list(_ROUTING_TABLE.keys()),
        }


# Singleton
ROUTER = MultiLLMRouter()
