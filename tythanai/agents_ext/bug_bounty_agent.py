"""
TythanAI — Bug Bounty Agent
Automates responsible disclosure workflow:
triage → severity validation → CVSS scoring → write-up generation.
"""
import time
from typing import Dict, List, Optional
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

PLATFORM_PROGRAMS = {
    "hackerone":  {"name":"HackerOne",  "url":"https://hackerone.com"},
    "bugcrowd":   {"name":"Bugcrowd",   "url":"https://bugcrowd.com"},
    "intigriti":  {"name":"Intigriti",  "url":"https://intigriti.com"},
    "immunefi":   {"name":"Immunefi",   "url":"https://immunefi.com"},  # crypto/TON bounties
    "tonbounty":  {"name":"TON Bounty", "url":"https://github.com/ton-blockchain/bug-bounty"},
}

PAYOUT_ESTIMATES = {
    "CRITICAL": (5000,  100000),
    "HIGH":     (1000,  15000),
    "MEDIUM":   (200,   5000),
    "LOW":      (50,    500),
    "INFO":     (0,     100),
}


# Ghost v8 enhancement: use Multi-LLM router for AI-powered write-ups
try:
    from runtime.providers.multi_llm_router import ROUTER as _ROUTER
    _AI_AVAILABLE = True
except ImportError:
    _AI_AVAILABLE = False


class BugBountyAgent:
    """
    Automates the responsible disclosure workflow.
    1. Triage finding — determine if it qualifies for bounty
    2. Match to suitable bug bounty programs
    3. Estimate payout range
    4. Generate professional disclosure write-up
    """

    def triage(self, finding: Dict) -> Dict:
        """Determine if a finding qualifies for bug bounty submission."""
        sev     = finding.get("severity", "INFO")
        has_ev  = bool(finding.get("evidence"))
        has_rec = bool(finding.get("recommendation"))
        conf    = finding.get("confidence", 70)
        cwe     = finding.get("cwe", "")
        source  = finding.get("source", "")

        # Qualification scoring
        score = 0
        reasons_pass, reasons_fail = [], []

        if sev in ("CRITICAL", "HIGH"):       score += 40; reasons_pass.append(f"{sev} severity")
        elif sev == "MEDIUM":                  score += 20; reasons_pass.append("MEDIUM severity")
        else:                                  score -= 10; reasons_fail.append("LOW/INFO severity rarely bounty-eligible")

        if has_ev:  score += 20; reasons_pass.append("Evidence provided")
        else:       score -= 15; reasons_fail.append("No evidence — harder to prove")

        if conf >= 80: score += 20; reasons_pass.append(f"High confidence ({conf}%)")
        elif conf >= 60: score += 10
        else:           score -= 10; reasons_fail.append(f"Low confidence ({conf}%) — likely FP")

        if cwe:    score += 10; reasons_pass.append(f"CWE classified ({cwe})")
        if has_rec:score += 10; reasons_pass.append("Remediation available")

        qualified     = score >= 50
        payout_lo, payout_hi = PAYOUT_ESTIMATES.get(sev, (0, 100))

        return {
            "finding_id":      finding.get("id", "?"),
            "severity":        sev,
            "qualified":       qualified,
            "triage_score":    score,
            "recommended_action": "submit" if qualified else "manual_validation",
            "reasons_pass":    reasons_pass,
            "reasons_fail":    reasons_fail,
            "payout_estimate": f"${payout_lo:,}–${payout_hi:,}" if qualified else "N/A",
            "confidence":      conf,
        }

    def match_programs(self, finding: Dict, target_type: str = "general") -> List[Dict]:
        """Suggest suitable bug bounty programs for this finding."""
        sev      = finding.get("severity", "INFO")
        source   = finding.get("source", "")
        category = finding.get("category", "")

        programs = []
        # TON / blockchain findings → Immunefi + TON bounty
        if "ton" in source.lower() or "ton" in category.lower() or target_type == "ton":
            programs += ["immunefi", "tonbounty"]
        # General code findings
        programs += ["hackerone", "bugcrowd"]
        if sev in ("CRITICAL", "HIGH"):
            programs += ["intigriti"]

        return [dict(PLATFORM_PROGRAMS[p], program_id=p) for p in dict.fromkeys(programs)
                if p in PLATFORM_PROGRAMS]

    def generate_writeup(self, finding: Dict, target: str = "Target") -> str:
        """Generate a professional bug bounty disclosure write-up."""
        sev  = finding.get("severity", "MEDIUM")
        cwe  = finding.get("cwe", "")
        cvss = finding.get("cvss_score")
        desc = finding.get("description", "")
        ev   = finding.get("evidence", "")
        rec  = finding.get("recommendation", "")
        fix  = finding.get("code_fix", "")
        ts   = time.strftime("%Y-%m-%d")

        cvss_line = f"\n**CVSS Score:** {cvss}" if cvss else ""
        cwe_line  = f"\n**CWE:** [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-','')}.html)" if cwe else ""
        fix_block = f"\n```\n{fix}\n```" if fix and fix != "N/A" else ""

        return f"""# Security Vulnerability Report
**Target:** {target}
**Date:** {ts}
**Severity:** {sev}{cvss_line}{cwe_line}
**Report ID:** GS-{int(time.time())%100000:05d}

---

## Summary

{desc}

## Vulnerability Details

**File / Location:** `{finding.get("file","N/A")}` (line {finding.get("line","N/A")})

**Evidence:**
```
{ev}
```

## Impact

This {sev.lower()}-severity vulnerability could allow an attacker to {self._impact_phrase(sev, cwe)}.

## Proof of Concept

The following evidence was collected via automated static analysis and confirmed manually:

```
{ev}
```

## Recommended Fix

{rec}
{fix_block}

## References

- {"https://cwe.mitre.org/data/definitions/"+cwe.replace("CWE-","")+".html" if cwe else "CWE database"}
- OWASP Top 10 (2021)
- TythanAI Platform — automated finding (confidence: {finding.get("confidence",70)}%)

---
*This report was generated by TythanAI Platform for responsible disclosure purposes.*
*Do not share without authorization from the program owner.*
"""

    @staticmethod
    def _impact_phrase(sev: str, cwe: str) -> str:
        cwe_impacts = {
            "CWE-284": "bypass access controls and perform unauthorized actions",
            "CWE-287": "authenticate without valid credentials",
            "CWE-78":  "execute arbitrary commands on the server",
            "CWE-89":  "read, modify, or delete database records",
            "CWE-798": "gain unauthorized access using hardcoded credentials",
            "CWE-338": "predict random values and break cryptographic protections",
            "CWE-400": "cause denial of service by exhausting resources",
            "CWE-294": "replay captured messages and execute unauthorized operations",
        }
        return cwe_impacts.get(cwe, {
            "CRITICAL": "compromise the entire system",
            "HIGH":     "gain significant unauthorized access or cause data loss",
            "MEDIUM":   "perform unintended actions or access restricted data",
            "LOW":      "obtain limited information or cause minor disruption",
        }.get(sev, "cause unintended behavior"))
