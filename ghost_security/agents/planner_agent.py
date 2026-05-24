"""
Ghost Security Platform — Planner Agent
Generates structured audit plans. LLM-powered with deterministic fallback.
"""
import json
from pathlib import Path
from typing import List

DEFAULT_PLANS = {
    "full": [
        "Enumerate files and understand project structure",
        "Run secret detection scan (credentials, API keys, tokens)",
        "Run AST security analysis (injection, unsafe calls, weak crypto)",
        "Run Semgrep with security rulesets",
        "Run TON/smart contract analyzer if .fc/.tact files present",
        "Perform deep analysis of highest-severity findings",
        "Verify and deduplicate findings across scanners",
        "Score risk and generate executive summary",
        "Save final report (JSON + HTML + Markdown)",
    ],
    "quick": [
        "Identify target type",
        "Run secret detection scan",
        "Run AST security analysis",
        "Deduplicate and report findings",
    ],
    "ton": [
        "Identify .fc / .func / .tact / .fift files",
        "Run TON static analyzer (access control, replay, randomness, gas griefing)",
        "Check for Jetton standard compliance issues",
        "Verify bounce message handling",
        "Run context rules (impure, recv_external signature check)",
        "Score contract risk and generate audit report",
    ],
    "secrets": [
        "Run secret detection scan (hardcoded credentials, API keys, private keys)",
        "Validate entropy of suspicious strings",
        "Report and recommend rotation of exposed secrets",
    ],
    "code": [
        "Run AST security analysis",
        "Run Semgrep with OWASP and security rulesets",
        "Deep-dive highest severity AST findings",
        "Report with CWE classification and remediation steps",
    ],
}


class PlannerAgent:
    def __init__(self):
        self._llm = None
        try:
            import sys; sys.path.insert(0, str(Path(__file__).parent.parent))
            from config.config import OPENAI_API_KEY, OPENAI_BASE_URL, LLM_FAST_MODEL
            if OPENAI_API_KEY:
                from openai import OpenAI
                self._llm = OpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL)
                self._model = LLM_FAST_MODEL
        except Exception:
            pass

    async def plan(self, task: str, audit_type: str = "full") -> List[str]:
        if self._llm:
            try:
                return await self._plan_with_llm(task, audit_type)
            except Exception:
                pass
        return self._default_plan(task, audit_type)

    async def _plan_with_llm(self, task: str, audit_type: str) -> List[str]:
        import asyncio
        loop = asyncio.get_event_loop()
        resp = await loop.run_in_executor(None, lambda: self._llm.chat.completions.create(
            model=self._model, max_tokens=400, temperature=0.2,
            messages=[
                {"role": "system", "content": (
                    "You are a senior security auditor. Given a target and audit type, "
                    "produce an ordered list of 6-12 audit steps. "
                    "Output ONLY a JSON array of strings. No preamble."
                )},
                {"role": "user", "content": f"Target: {task}\nAudit type: {audit_type}"},
            ],
        ))
        text = resp.choices[0].message.content.strip().replace("```json", "").replace("```", "").strip()
        steps = json.loads(text)
        if isinstance(steps, list) and all(isinstance(s, str) for s in steps):
            return steps
        raise ValueError("Unexpected LLM plan format")

    def _default_plan(self, task: str, audit_type: str) -> List[str]:
        plan = list(DEFAULT_PLANS.get(audit_type, DEFAULT_PLANS["full"]))
        if any(kw in task.lower() for kw in ["ton", ".fc", ".func", ".tact", "smart contract"]):
            if "Run TON" not in " ".join(plan):
                plan.insert(3, "Run TON static analyzer (FunC / Tact vulnerability rules)")
        return plan
