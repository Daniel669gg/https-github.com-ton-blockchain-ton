"""
Ghost Security — LLM Security Copilot
AI-powered assistant for explaining findings, suggesting fixes,
answering security questions, and rewriting code securely.
Works with OpenAI, Ollama (DeepSeek, Qwen), or any compatible endpoint.
"""
import json
from pathlib import Path
from typing import Dict, Iterator, List, Optional
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

SYSTEM_PROMPT = """You are Ghost Security Copilot — an expert application security engineer.
You help developers understand security vulnerabilities and write safer code.

Your capabilities:
- Explain security vulnerabilities in plain language
- Suggest concrete, language-specific code fixes
- Answer security questions with precise technical detail
- Review code for security issues
- Explain CVEs, CWEs, and attack patterns

Guidelines:
- Be concrete: show actual code, not just concepts
- Be brief: 2-4 sentences for explanations, code blocks for fixes
- Reference CWE/OWASP where relevant
- Never produce offensive tools or exploits
- Always recommend responsible disclosure for real vulnerabilities
"""


class SecurityCopilot:
    """
    Conversational security assistant with streaming support.
    Maintains conversation history for multi-turn sessions.
    """

    def __init__(self):
        self._client = None
        self._model  = "gpt-4o-mini"
        self._history: List[Dict] = []
        self._init_client()

    # ── Public API ────────────────────────────────────────────────────────────

    def explain_finding(self, finding: Dict) -> str:
        """Plain-language explanation of a security finding."""
        prompt = (
            f"Explain this security finding in plain language for a developer:\n"
            f"{json.dumps(finding, indent=2)[:1500]}\n\n"
            "Keep it under 100 words. Focus on: what it is, why it's dangerous, "
            "and one concrete example of exploitation."
        )
        return self.ask(prompt, use_history=False)

    def suggest_fix(self, finding: Dict, code_context: str = "") -> str:
        """Generate a concrete code fix for a finding."""
        ctx = f"\n\nCode context:\n```\n{code_context[:800]}\n```" if code_context else ""
        prompt = (
            f"Generate a concrete code fix for this security finding:\n"
            f"{json.dumps({'id':finding.get('id'),'severity':finding.get('severity'),'description':finding.get('description'),'evidence':finding.get('evidence'),'cwe':finding.get('cwe')}, indent=2)}"
            f"{ctx}\n\nProvide: 1) the fixed code snippet, 2) a one-line explanation of the change."
        )
        return self.ask(prompt, use_history=False)

    def review_code(self, code: str, language: str = "python") -> str:
        """Security review of a code snippet."""
        prompt = (
            f"Perform a security review of this {language} code. "
            f"List only real security issues (not style issues). "
            f"Format: [SEVERITY] Issue description\n\n"
            f"```{language}\n{code[:2000]}\n```"
        )
        return self.ask(prompt, use_history=False)

    def rewrite_secure(self, code: str, language: str = "python") -> str:
        """Rewrite code to be security-hardened."""
        prompt = (
            f"Rewrite this {language} code to be security-hardened. "
            f"Fix all security issues. Add inline comments explaining each fix.\n\n"
            f"```{language}\n{code[:1500]}\n```\n\n"
            "Return only the rewritten code block."
        )
        return self.ask(prompt, use_history=False)

    def ask(self, question: str, use_history: bool = True) -> str:
        """General security question answering with optional history."""
        if not self._client:
            return self._offline_response(question)

        messages = [{"role":"system","content":SYSTEM_PROMPT}]
        if use_history:
            messages.extend(self._history[-8:])  # last 4 turns
        messages.append({"role":"user","content":question})

        try:
            resp = self._client.chat.completions.create(
                model=self._model, max_tokens=600, temperature=0.2,
                messages=messages,
            )
            answer = resp.choices[0].message.content.strip()
            if use_history:
                self._history.append({"role":"user","content":question})
                self._history.append({"role":"assistant","content":answer})
            return answer
        except Exception as e:
            return f"[Copilot unavailable: {e}]"

    def stream(self, question: str) -> Iterator[str]:
        """Stream response token by token (for real-time UI)."""
        if not self._client:
            yield self._offline_response(question); return
        try:
            stream = self._client.chat.completions.create(
                model=self._model, max_tokens=600, temperature=0.2, stream=True,
                messages=[{"role":"system","content":SYSTEM_PROMPT},
                          {"role":"user","content":question}],
            )
            for chunk in stream:
                delta = chunk.choices[0].delta.content or ""
                if delta: yield delta
        except Exception as e:
            yield f"[Stream error: {e}]"

    def clear_history(self): self._history.clear()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _init_client(self):
        try:
            from config.config import OPENAI_API_KEY, OPENAI_BASE_URL, LLM_FAST_MODEL
            if OPENAI_API_KEY:
                from openai import OpenAI
                self._client = OpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL)
                self._model  = LLM_FAST_MODEL
        except Exception:
            pass

    @staticmethod
    def _offline_response(question: str) -> str:
        q = question.lower()
        if "explain" in q or "what is" in q:
            return ("No LLM configured. Set OPENAI_API_KEY in .env or start Ollama.\n"
                    "Run: python3 ghost_cli.py llm-status")
        if "fix" in q or "remediat" in q:
            return "Auto-remediation requires an LLM. See .env.example for configuration."
        return "Security Copilot requires an LLM backend. See README.md → Quick Start."
