"""
TythanAI — Decision Engine
Routes audit decisions to the right action: escalate, report, defer, or close.
"""
from typing import Dict, List

SEVERITY_SCORE = {"CRITICAL":100,"HIGH":75,"MEDIUM":50,"LOW":25,"INFO":5}

class Action:
    ESCALATE        = "escalate"       # critical — needs immediate attention
    REPORT          = "report"         # confirmed — include in report
    REQUEST_REVIEW  = "request_review" # uncertain — needs human review
    DEFER           = "defer"          # low priority — log for later
    CLOSE_FP        = "close_fp"       # false positive — close

class DecisionEngine:
    """
    Routes each finding to the correct workflow action based on:
    severity, confidence score, consensus verdict, and platform policy.
    """

    def __init__(self, escalate_threshold: int = 80, fp_threshold: int = 30):
        self.escalate_threshold = escalate_threshold  # confidence above this → escalate if CRIT/HIGH
        self.fp_threshold       = fp_threshold         # confidence below this → likely FP

    def decide(self, finding: Dict, consensus: Dict = None) -> Dict:
        sev      = finding.get("severity", "INFO")
        conf     = finding.get("confidence", 70)
        verdict  = (consensus or {}).get("verdict", "confirm")
        score    = SEVERITY_SCORE.get(sev, 5)

        # False positive path
        if verdict == "reject" or conf < self.fp_threshold:
            action = Action.CLOSE_FP
            rationale = f"Low confidence ({conf}%) or rejected by consensus"
        # Critical/High confirmed → escalate immediately
        elif score >= 75 and conf >= self.escalate_threshold and verdict != "downgrade":
            action = Action.ESCALATE
            rationale = f"{sev} severity with {conf}% confidence"
        # Uncertain → human review
        elif conf < 55 or verdict == "downgrade":
            action = Action.REQUEST_REVIEW
            rationale = f"Confidence {conf}% below threshold or downgraded severity"
        # Low findings → defer
        elif score <= 25:
            action = Action.DEFER
            rationale = "Low severity; scheduled for next review cycle"
        else:
            action = Action.REPORT
            rationale = f"Confirmed {sev} finding with {conf}% confidence"

        return {
            "finding_id": finding.get("id","?"),
            "action":     action,
            "rationale":  rationale,
            "priority":   self._priority(action),
            "severity":   (consensus or {}).get("final_severity", sev),
        }

    def batch(self, findings: List[Dict], consensuses: List[Dict] = None) -> List[Dict]:
        consensuses = consensuses or [{}]*len(findings)
        decisions = [self.decide(f, c) for f, c in zip(findings, consensuses)]
        # Sort: escalate first, then report, then review, then defer, then close_fp
        order = {Action.ESCALATE:0, Action.REPORT:1, Action.REQUEST_REVIEW:2,
                 Action.DEFER:3, Action.CLOSE_FP:4}
        return sorted(decisions, key=lambda d: order.get(d["action"],5))

    def summary(self, decisions: List[Dict]) -> Dict:
        counts = {}
        for d in decisions:
            counts[d["action"]] = counts.get(d["action"],0)+1
        return {"total":len(decisions),"breakdown":counts}

    @staticmethod
    def _priority(action: str) -> int:
        return {Action.ESCALATE:1, Action.REPORT:2, Action.REQUEST_REVIEW:3,
                Action.DEFER:4, Action.CLOSE_FP:5}.get(action, 3)
