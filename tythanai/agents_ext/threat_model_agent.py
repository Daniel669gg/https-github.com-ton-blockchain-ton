"""
TythanAI — Threat Model Agent
STRIDE-based threat modeling for static analysis findings.
Produces threat model report linked to findings.
"""
from typing import Dict, List

# STRIDE: Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege
STRIDE = {
    "S": "Spoofing Identity",
    "T": "Tampering with Data",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}

# CWE → STRIDE mapping
CWE_TO_STRIDE = {
    "CWE-287": ["S"],       # auth bypass → spoofing
    "CWE-284": ["E","S"],   # access control → elevation + spoofing
    "CWE-78":  ["T","E"],   # command injection → tamper + elevate
    "CWE-89":  ["T","I"],   # SQLi → tamper + info
    "CWE-22":  ["I","T"],   # path traversal → info + tamper
    "CWE-798": ["S","I"],   # hardcoded creds → spoof + info
    "CWE-338": ["S"],       # weak random → spoofing
    "CWE-400": ["D"],       # DoS → denial
    "CWE-294": ["S","R"],   # replay → spoof + repudiation
    "CWE-502": ["T","E"],   # deserialization → tamper + elevate
    "CWE-611": ["I"],       # XXE → info disclosure
    "CWE-362": ["T"],       # race condition → tamper
    "CWE-190": ["T","D"],   # overflow → tamper + DoS
    "CWE-369": ["D"],       # division by zero → DoS
    "CWE-691": ["T"],       # control flow → tamper
}

LIKELIHOOD = {"CRITICAL":5,"HIGH":4,"MEDIUM":3,"LOW":2,"INFO":1}
IMPACT_MAP  = {"CRITICAL":5,"HIGH":4,"MEDIUM":3,"LOW":2,"INFO":1}

class ThreatModelAgent:
    """
    Maps findings to STRIDE threat categories.
    Produces DREAD-style risk ratings and a STRIDE coverage matrix.
    """

    def analyze(self, asset: str, findings: List[Dict]) -> Dict:
        threats = []
        stride_coverage = {k: [] for k in STRIDE}

        for f in findings:
            cwe     = f.get("cwe", "")
            sev     = f.get("severity", "INFO")
            categories = CWE_TO_STRIDE.get(cwe, ["T"])  # default: tampering

            for cat in categories:
                likelihood = LIKELIHOOD.get(sev, 1)
                impact     = IMPACT_MAP.get(sev, 1)
                risk_score = likelihood * impact  # max 25

                threat = {
                    "asset":       asset,
                    "threat_cat":  cat,
                    "threat_name": STRIDE[cat],
                    "finding_id":  f.get("id","?"),
                    "cwe":         cwe,
                    "severity":    sev,
                    "likelihood":  likelihood,
                    "impact":      impact,
                    "risk_score":  risk_score,
                    "risk_level":  "Critical" if risk_score>=20 else "High" if risk_score>=12
                                   else "Medium" if risk_score>=6 else "Low",
                    "mitigations": self._mitigations(cat, cwe),
                }
                threats.append(threat)
                stride_coverage[cat].append(f.get("id","?"))

        # Compute STRIDE coverage summary
        coverage_summary = {
            STRIDE[k]: {"count":len(v), "finding_ids":v[:5]}
            for k, v in stride_coverage.items()
        }

        # Top risks
        threats.sort(key=lambda t: t["risk_score"], reverse=True)
        top_risks = threats[:10]

        overall_risk = sum(t["risk_score"] for t in threats)
        max_risk     = len(findings) * 25 if findings else 1
        risk_pct     = round(overall_risk / max_risk * 100) if max_risk else 0

        return {
            "asset":            asset,
            "total_threats":    len(threats),
            "overall_risk_pct": risk_pct,
            "risk_level":       "Critical" if risk_pct>=80 else "High" if risk_pct>=60
                                else "Medium" if risk_pct>=40 else "Low",
            "stride_coverage":  coverage_summary,
            "top_risks":        top_risks,
            "all_threats":      threats,
        }

    @staticmethod
    def _mitigations(cat: str, cwe: str) -> List[str]:
        base = {
            "S": ["Implement multi-factor authentication","Validate all identity claims","Use signed tokens"],
            "T": ["Validate all inputs","Use parameterised queries","Implement integrity checks"],
            "R": ["Implement comprehensive audit logging","Use non-repudiation mechanisms"],
            "I": ["Encrypt data at rest and in transit","Apply least-privilege access control"],
            "D": ["Implement rate limiting","Add resource caps","Use circuit breakers"],
            "E": ["Enforce least-privilege","Validate authorisation on every request"],
        }.get(cat, ["Review and harden the affected component"])
        return base
