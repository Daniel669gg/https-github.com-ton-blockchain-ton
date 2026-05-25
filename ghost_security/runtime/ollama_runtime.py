"""
Ghost Security Platform — Ollama Production Runtime
Multi-model local AI:
  • Model health-check & availability cache
  • Task-type routing (planning / coding / security / report)
  • Fallback chain: ollama → openai → offline stub
  • Reasoning pipeline with chain-of-thought
  • Remediation generation
  • Findings summarisation
  • Secure code explanation
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ── Model catalogue ────────────────────────────────────────────────────────────
@dataclass
class ModelProfile:
    name:     str
    tasks:    List[str]    # task types this model is good at
    ctx_len:  int = 8192
    fast:     bool = False # prefer for low-latency tasks


_CATALOGUE: List[ModelProfile] = [
    ModelProfile("deepseek-r1",         ["planning", "reasoning", "security"],        ctx_len=32768),
    ModelProfile("deepseek-coder-v2",   ["coding",   "ton",   "solidity"],            ctx_len=16384),
    ModelProfile("qwen3",               ["critique", "report","summarise"],           ctx_len=8192,  fast=True),
    ModelProfile("qwen2.5-coder",       ["coding",   "fix",   "explain"],             ctx_len=8192),
    ModelProfile("llama3.2",            ["summarise","report","remediation"],         ctx_len=8192,  fast=True),
    ModelProfile("phi4-mini",           ["critique", "triage"],                       ctx_len=4096,  fast=True),
    ModelProfile("mistral",             ["security", "explain","remediation"],        ctx_len=8192),
    ModelProfile("codellama",           ["coding",   "fix",   "explain"],             ctx_len=8192),
]

_TASK_PREFERENCE: Dict[str, List[str]] = {
    "planning":    ["deepseek-r1", "llama3.2", "qwen3"],
    "reasoning":   ["deepseek-r1", "llama3.2", "mistral"],
    "security":    ["deepseek-r1", "qwen3", "mistral"],
    "coding":      ["deepseek-coder-v2", "qwen2.5-coder", "codellama"],
    "ton":         ["deepseek-coder-v2", "qwen2.5-coder"],
    "solidity":    ["deepseek-coder-v2", "qwen2.5-coder"],
    "fix":         ["qwen2.5-coder", "deepseek-coder-v2", "codellama"],
    "explain":     ["qwen2.5-coder", "mistral", "llama3.2"],
    "remediation": ["mistral", "llama3.2", "qwen3"],
    "critique":    ["qwen3", "phi4-mini", "llama3.2"],
    "report":      ["qwen3", "llama3.2", "mistral"],
    "summarise":   ["llama3.2", "qwen3", "phi4-mini"],
    "triage":      ["phi4-mini", "qwen3", "llama3.2"],
    "default":     ["deepseek-r1", "qwen3", "mistral"],
}

_OLLAMA_BASE = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
_OPENAI_KEY  = os.getenv("OPENAI_API_KEY", "")
_OPENAI_BASE = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
_CLOUD_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")


# ── Low-level Ollama client ────────────────────────────────────────────────────

def _ollama_list() -> List[str]:
    """Return list of locally available model names."""
    try:
        req = urllib.request.Request(f"{_OLLAMA_BASE}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=3) as r:
            data = json.loads(r.read())
        return [m["name"].split(":")[0] for m in data.get("models", [])]
    except Exception:
        return []


def _ollama_generate(
    model: str,
    prompt: str,
    system: str = "",
    temperature: float = 0.1,
    max_tokens: int = 2048,
    stream: bool = False,
) -> str:
    """Call ollama /api/chat endpoint. Returns full response text."""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    payload = json.dumps({
        "model":   model,
        "messages": messages,
        "stream":  stream,
        "options": {"temperature": temperature, "num_predict": max_tokens},
    }).encode()

    req = urllib.request.Request(
        f"{_OLLAMA_BASE}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.loads(r.read())
        return data.get("message", {}).get("content", "")
    except Exception as exc:
        raise RuntimeError(f"Ollama call failed ({model}): {exc}")


def _openai_generate(prompt: str, system: str, model: str, max_tokens: int = 2048) -> str:
    """Fallback to OpenAI-compatible cloud endpoint."""
    if not _OPENAI_KEY:
        return ""
    from openai import OpenAI
    client = OpenAI(api_key=_OPENAI_KEY, base_url=_OPENAI_BASE)
    msgs = []
    if system:
        msgs.append({"role": "system", "content": system})
    msgs.append({"role": "user", "content": prompt})
    resp = client.chat.completions.create(
        model=model, messages=msgs, max_tokens=max_tokens, temperature=0.1
    )
    return resp.choices[0].message.content or ""


# ── Router ────────────────────────────────────────────────────────────────────

class OllamaRouter:
    """
    Routes each task to the best available local model.
    Falls back to cloud if Ollama is unavailable.
    """

    _CACHE_TTL = 60  # seconds

    def __init__(self) -> None:
        self._available:   List[str] = []
        self._last_check:  float     = 0.0

    def available_models(self) -> List[str]:
        now = time.time()
        if now - self._last_check > self._CACHE_TTL:
            self._available  = _ollama_list()
            self._last_check = now
        return self._available

    def is_online(self) -> bool:
        return len(self.available_models()) > 0

    def pick_model(self, task: str) -> Tuple[str, str]:
        """
        Returns (backend, model_name).
        backend = "ollama" | "openai" | "none"
        """
        available = set(self.available_models())
        for candidate in _TASK_PREFERENCE.get(task, _TASK_PREFERENCE["default"]):
            if candidate in available:
                return "ollama", candidate
        # fallback to cloud
        if _OPENAI_KEY:
            return "openai", _CLOUD_MODEL
        return "none", ""

    def call(
        self,
        task: str,
        prompt: str,
        system: str = "",
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ) -> Tuple[str, str]:
        """
        Call the best available backend.
        Returns (response_text, model_used).
        """
        backend, model = self.pick_model(task)
        if backend == "ollama":
            try:
                text = _ollama_generate(model, prompt, system, temperature, max_tokens)
                return text, model
            except Exception:
                # fallback
                if _OPENAI_KEY:
                    return _openai_generate(prompt, system, _CLOUD_MODEL, max_tokens), _CLOUD_MODEL
        elif backend == "openai":
            return _openai_generate(prompt, system, model, max_tokens), model
        return "", "none"

    def status(self) -> dict:
        avail = self.available_models()
        return {
            "ollama_online":  self.is_online(),
            "ollama_base":    _OLLAMA_BASE,
            "available_models": avail,
            "cloud_available": bool(_OPENAI_KEY),
            "cloud_model":    _CLOUD_MODEL,
            "routing": {
                task: list(self.pick_model(task))
                for task in ("security", "coding", "reasoning", "report", "triage")
            },
        }


# ── High-level AI pipelines ────────────────────────────────────────────────────

_SYS_SECURITY = (
    "You are a senior AppSec engineer specialising in vulnerability analysis. "
    "Be precise, concise, and actionable. Output only the requested content."
)

_SYS_CODING = (
    "You are an expert software engineer. "
    "Write clear, secure, idiomatic code with minimal boilerplate."
)

_SYS_REPORT = (
    "You are a security report writer. "
    "Summarise findings clearly for both technical and management audiences."
)


class OllamaSecurityAI:
    """
    High-level security AI powered by Ollama (local) or OpenAI (cloud).
    All methods return plain strings — no external dependencies.
    """

    def __init__(self) -> None:
        self._router = OllamaRouter()

    # ── Reasoning pipeline ─────────────────────────────────────────────────────

    def reason(self, question: str, context: str = "") -> str:
        """Multi-step chain-of-thought reasoning for security questions."""
        prompt = (
            f"Context:\n{context}\n\n" if context else ""
        ) + f"""Security question: {question}

Think through this step-by-step:
1. What is the vulnerability / risk?
2. What is the attack vector and impact?
3. What is the likelihood of exploitation?
4. What is the recommended fix?

Answer:"""
        text, _ = self._router.call("reasoning", prompt, system=_SYS_SECURITY, max_tokens=1500)
        return text or self._offline_reason(question)

    # ── Remediation generation ─────────────────────────────────────────────────

    def generate_remediation(self, finding: dict, code_context: str = "") -> str:
        """Generate a concrete code fix for a security finding."""
        sev   = finding.get("severity", "MEDIUM")
        ftype = finding.get("type") or finding.get("rule_id") or "finding"
        msg   = finding.get("message") or finding.get("description") or ftype
        code_block = (
            "Vulnerable code:\n```\n" + code_context + "\n```\n"
            if code_context else ""
        )
        prompt = (
            f"Security finding:\n"
            f"Type:     {ftype}\n"
            f"Severity: {sev}\n"
            f"Message:  {msg}\n"
            f"CWE:      {finding.get('cwe', 'unknown')}\n"
            f"OWASP:    {finding.get('owasp', 'unknown')}\n\n"
            f"{code_block}"
            "Provide:\n"
            "1. Root cause (1-2 sentences)\n"
            "2. Fixed code (complete, runnable)\n"
            "3. Testing advice (how to verify the fix)"
        )
        text, _ = self._router.call("remediation", prompt, system=_SYS_CODING, max_tokens=1500)
        return text or self._offline_remediation(finding)

    # ── Secure code explanation ────────────────────────────────────────────────

    def explain_finding(self, finding: dict) -> str:
        """Plain-language explanation of a finding for devs."""
        ftype = finding.get("type") or "security issue"
        msg   = finding.get("message") or ""
        cwe   = finding.get("cwe", "")
        prompt = f"""Explain this security finding to a developer in plain language:

Type:    {ftype}
Message: {msg}
CWE:     {cwe}
File:    {finding.get('file', '')} line {finding.get('line', '')}

Include: what it is, why it matters, how it could be exploited (briefly), and the fix."""
        text, _ = self._router.call("explain", prompt, system=_SYS_SECURITY, max_tokens=800)
        return text or f"Security finding: {ftype} — {msg}"

    # ── Findings summarisation ─────────────────────────────────────────────────

    def summarise_findings(self, findings: List[dict], target: str = "") -> str:
        """Generate an executive summary of a scan's findings."""
        if not findings:
            return "No findings to summarise."

        counts: dict = {}
        for f in findings:
            s = f.get("severity", "MEDIUM")
            counts[s] = counts.get(s, 0) + 1

        top = sorted(findings, key=lambda f: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(f.get("severity", "LOW"), 4)
        ))[:5]
        top_list = "\n".join(
            f"- [{f.get('severity')}] {f.get('message') or f.get('type')} ({f.get('file', '')}:{f.get('line', '')})"
            for f in top
        )
        prompt = f"""Summarise these security scan results for a technical lead:

Target: {target or 'repository'}
Findings: {json.dumps(counts)}
Top findings:
{top_list}

Write a 3-paragraph executive summary covering:
1. Overall risk posture
2. Critical/high priority findings
3. Recommended immediate actions"""
        text, _ = self._router.call("summarise", prompt, system=_SYS_REPORT, max_tokens=600)
        return text or self._offline_summary(counts, target)

    # ── Threat model ───────────────────────────────────────────────────────────

    def threat_model(self, findings: List[dict], asset: str = "Application") -> str:
        """STRIDE-based threat model from a list of findings."""
        types = list({f.get("type") or "unknown" for f in findings})[:15]
        prompt = f"""Produce a STRIDE threat model for: {asset}

Detected vulnerability types: {', '.join(types)}

For each STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege):
- Is it relevant given the findings?
- What is the key threat?
- Mitigation recommendation

Be concise. Use a table or bullet structure."""
        text, _ = self._router.call("security", prompt, system=_SYS_SECURITY, max_tokens=1200)
        return text or "STRIDE analysis requires AI connectivity."

    # ── Offline fallbacks ──────────────────────────────────────────────────────

    @staticmethod
    def _offline_reason(question: str) -> str:
        return (
            f"[Offline] Cannot process AI reasoning without Ollama or OpenAI. "
            f"Question: {question[:200]}"
        )

    @staticmethod
    def _offline_remediation(finding: dict) -> str:
        ftype = finding.get("type") or "unknown"
        sev   = finding.get("severity", "MEDIUM")
        return (
            f"[Offline remediation — AI not available]\n"
            f"Finding: {ftype} ({sev})\n"
            f"Refer to OWASP {finding.get('owasp', '')} and CWE {finding.get('cwe', '')} "
            f"for remediation guidance."
        )

    @staticmethod
    def _offline_summary(counts: dict, target: str) -> str:
        total = sum(counts.values())
        crits = counts.get("CRITICAL", 0)
        highs = counts.get("HIGH", 0)
        return (
            f"Scan of '{target}' found {total} issue(s): "
            f"{crits} CRITICAL, {highs} HIGH. "
            f"AI summarisation requires Ollama or OpenAI connectivity."
        )

    def status(self) -> dict:
        return self._router.status()


# Module-level singleton
OLLAMA_AI = OllamaSecurityAI()
