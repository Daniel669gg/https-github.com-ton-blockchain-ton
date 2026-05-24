"""
Ghost Security Platform — Critic Agent
Reviews findings for quality and accuracy. LLM-powered with heuristic fallback.
"""
import json
from pathlib import Path
from typing import Dict


class CriticAgent:
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

    async def review(self, output: Dict) -> Dict:
        if self._llm:
            try:
                return await self._llm_review(output)
            except Exception:
                pass
        return self._heuristic_review(output)

    async def _llm_review(self, output: Dict) -> Dict:
        import asyncio
        prompt = (
            "You are a senior security auditor. Review these findings for quality.\n"
            "Findings:\n" + json.dumps(output, indent=2)[:3000] + "\n\n"
            "Return JSON only: {\"quality_score\": 0.0-1.0, \"issues\": [], \"recommendation\": \"accepted|revise|reject\"}"
        )
        loop = asyncio.get_event_loop()
        resp = await loop.run_in_executor(None, lambda: self._llm.chat.completions.create(
            model=self._model, max_tokens=400, temperature=0.1,
            messages=[{"role": "user", "content": prompt}],
        ))
        text = resp.choices[0].message.content.strip().replace("```json", "").replace("```", "")
        return json.loads(text)

    def _heuristic_review(self, output: Dict) -> Dict:
        findings = output.get("findings", [])
        issues, score = [], 1.0
        for i, f in enumerate(findings):
            if not f.get("evidence"):
                issues.append(f"Finding #{i+1} missing evidence"); score -= 0.05
            if not f.get("recommendation"):
                issues.append(f"Finding #{i+1} missing recommendation"); score -= 0.02
            if not f.get("file") and f.get("severity") in ("CRITICAL", "HIGH"):
                issues.append(f"Finding #{i+1} high severity without file reference"); score -= 0.08
        crits = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        if crits > 10:
            issues.append(f"Unusually high critical count ({crits}) — verify for false positives"); score -= 0.1
        score = max(0.0, round(score, 2))
        return {"quality_score": score, "issues": issues,
                "recommendation": "accepted" if score >= 0.75 else "revise" if score >= 0.5 else "reject"}
