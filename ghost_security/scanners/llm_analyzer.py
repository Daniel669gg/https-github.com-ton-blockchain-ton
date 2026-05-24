"""
Ghost Security — LLM Deep Analyzer
Enriches static findings with: AI explanation, confidence score,
CVSS vector, exploitability note, and code-level remediation patch.
Works with OpenAI, Ollama, or any OpenAI-compatible endpoint.
Falls back gracefully when no LLM is configured.
"""
import json
import re
import time
from pathlib import Path
from typing import Dict, List, Optional
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from config.config import OPENAI_API_KEY, OPENAI_BASE_URL, LLM_MODEL


ENRICH_PROMPT = """\
You are a senior application security engineer reviewing a static analysis finding.
Enrich it with structured analysis. Return ONLY valid JSON — no markdown, no prose.

Finding:
{finding}

Respond with exactly this JSON schema:
{{
  "confidence": <int 0-100>,
  "confidence_reason": "<one sentence why>",
  "cvss_vector": "<CVSS:3.1/AV:.../...>",
  "cvss_score": <float 0.0-10.0>,
  "exploitability": "<none|low|medium|high|critical>",
  "exploit_scenario": "<1-2 sentence realistic attack scenario, or 'N/A'>",
  "deeper_explanation": "<2-3 sentences technical explanation>",
  "code_fix": "<concrete corrected code snippet, or 'N/A'>",
  "false_positive_risk": "<low|medium|high>",
  "references": ["<CWE/OWASP/CVE link>"]
}}
"""


class LLMAnalyzer:
    """
    Enriches static findings with LLM-powered deep analysis.
    Processes only HIGH and CRITICAL findings by default to control cost.
    """

    def __init__(self, min_severity: str = "HIGH", max_findings: int = 20):
        self._client = None
        self._model = LLM_MODEL
        self._min_severity = min_severity
        self._max_findings = max_findings
        self._severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self._min_idx = self._severity_order.get(min_severity, 1)

        if OPENAI_API_KEY:
            try:
                from openai import OpenAI
                self._client = OpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL)
            except Exception:
                pass

    def enrich_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Enrich a list of findings in place.
        Returns the same list with 'llm_analysis' fields added where applicable.
        """
        if not self._client:
            return self._add_fallback_scores(findings)

        # Only enrich findings at or above min_severity threshold
        candidates = [
            f for f in findings
            if self._severity_order.get(f.get("severity", "INFO"), 99) <= self._min_idx
        ][:self._max_findings]

        enriched_ids = set()
        for finding in candidates:
            fid = id(finding)
            if fid in enriched_ids:
                continue
            enriched_ids.add(fid)
            try:
                analysis = self._enrich_one(finding)
                finding["llm_analysis"] = analysis
                finding["confidence"] = analysis.get("confidence", 75)
                finding["cvss_score"] = analysis.get("cvss_score", 0.0)
                finding["cvss_vector"] = analysis.get("cvss_vector", "")
                finding["exploit_scenario"] = analysis.get("exploit_scenario", "N/A")
                finding["code_fix"] = analysis.get("code_fix", "N/A")
                finding["false_positive_risk"] = analysis.get("false_positive_risk", "medium")
            except Exception as e:
                finding["llm_analysis"] = {"error": str(e)}
                finding["confidence"] = 60

        # Add lightweight fallback scores to the rest
        return self._add_fallback_scores(findings, skip_enriched=True)

    def _enrich_one(self, finding: Dict) -> Dict:
        prompt = ENRICH_PROMPT.format(finding=json.dumps(finding, indent=2)[:2000])
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=600,
            temperature=0.1,
        )
        text = resp.choices[0].message.content.strip()
        text = re.sub(r"```(?:json)?|```", "", text).strip()
        return json.loads(text)

    def _add_fallback_scores(self, findings: List[Dict], skip_enriched: bool = False) -> List[Dict]:
        """Add heuristic confidence/CVSS scores to findings without LLM enrichment."""
        sev_cvss = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 1.0}
        sev_conf = {"CRITICAL": 85,  "HIGH": 75,  "MEDIUM": 65,  "LOW": 55,  "INFO": 40}
        for f in findings:
            if skip_enriched and "llm_analysis" in f:
                continue
            sev = f.get("severity", "INFO")
            if "confidence" not in f:
                f["confidence"] = sev_conf.get(sev, 50)
            if "cvss_score" not in f:
                f["cvss_score"] = sev_cvss.get(sev, 0.0)
            if "false_positive_risk" not in f:
                # Findings with evidence are less likely FP
                f["false_positive_risk"] = "low" if f.get("evidence") else "medium"
        return findings


class CVSSCalculator:
    """
    Calculate CVSS v3.1 base score from a structured finding.
    Maps CWE categories to approximate CVSS metrics.
    """

    # CWE → (AV, AC, PR, UI, S, C, I, A)
    CWE_METRICS = {
        "CWE-78":  ("N", "L", "N", "N", "C", "H", "H", "H"),   # Command injection
        "CWE-79":  ("N", "L", "N", "R", "C", "L", "L", "N"),   # XSS
        "CWE-89":  ("N", "L", "N", "N", "U", "H", "H", "N"),   # SQLi
        "CWE-95":  ("N", "L", "N", "N", "C", "H", "H", "H"),   # Code injection
        "CWE-502": ("N", "L", "N", "N", "U", "H", "H", "H"),   # Deserialization
        "CWE-22":  ("N", "L", "N", "N", "U", "H", "H", "N"),   # Path traversal
        "CWE-284": ("N", "L", "N", "N", "U", "H", "H", "N"),   # Access control
        "CWE-287": ("N", "L", "N", "N", "U", "H", "H", "N"),   # Auth bypass
        "CWE-294": ("N", "H", "N", "N", "U", "H", "H", "N"),   # Replay
        "CWE-338": ("N", "H", "N", "N", "U", "H", "N", "N"),   # Weak random
        "CWE-400": ("N", "L", "N", "N", "U", "N", "N", "H"),   # DoS
        "CWE-798": ("N", "L", "N", "N", "U", "H", "H", "N"),   # Hardcoded creds
        "CWE-327": ("N", "H", "N", "N", "U", "L", "N", "N"),   # Weak crypto
        "CWE-362": ("N", "H", "H", "N", "U", "H", "H", "N"),   # Race condition
        "CWE-611": ("N", "L", "N", "N", "C", "H", "L", "N"),   # XXE
    }

    SCORE_TABLE = {
        # Approximate lookup for common vectors (simplified)
        ("N","L","N","N","C","H","H","H"): (10.0, "Critical"),
        ("N","L","N","N","U","H","H","H"): (9.8,  "Critical"),
        ("N","L","N","N","U","H","H","N"): (9.1,  "Critical"),
        ("N","L","N","N","C","H","L","N"): (8.6,  "High"),
        ("N","L","N","N","C","L","L","N"): (6.1,  "Medium"),
        ("N","H","N","N","U","H","H","N"): (7.5,  "High"),
        ("N","H","H","N","U","H","H","N"): (7.0,  "High"),
        ("N","H","N","N","U","H","N","N"): (5.9,  "Medium"),
        ("N","L","N","N","U","N","N","H"): (7.5,  "High"),
        ("N","H","N","N","U","L","N","N"): (3.7,  "Low"),
        ("N","L","N","R","C","L","L","N"): (6.1,  "Medium"),
        ("N","H","N","N","U","N","N","N"): (0.0,  "None"),
    }

    @classmethod
    def score_from_cwe(cls, cwe: str) -> Dict:
        metrics = cls.CWE_METRICS.get(cwe)
        if not metrics:
            return {"score": 0.0, "rating": "Unknown", "vector": ""}
        score, rating = cls.SCORE_TABLE.get(metrics, (5.0, "Medium"))
        av, ac, pr, ui, s, c, i, a = metrics
        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        return {"score": score, "rating": rating, "vector": vector}
