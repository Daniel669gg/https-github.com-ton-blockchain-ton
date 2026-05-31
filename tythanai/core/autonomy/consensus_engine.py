"""
TythanAI — Consensus Engine
Multi-agent voting system for finding validation.
Reduces false positives by requiring quorum before confirming a finding.
"""
import math
from typing import Any, Dict, List, Optional

class Vote:
    CONFIRM   = "confirm"
    REJECT    = "reject"
    DOWNGRADE = "downgrade"
    ESCALATE  = "escalate"

class ConsensusEngine:
    """
    Weighted voting across multiple agents.
    Default quorum: 60% weighted confidence required to confirm.
    """

    # Agent trust weights (can be tuned based on historical accuracy)
    DEFAULT_WEIGHTS = {
        "ton_analyzer":    1.0,
        "ast_scanner":     1.0,
        "secret_detector": 1.0,
        "llm_analyzer":    0.8,
        "critic_agent":    0.9,
        "security_agent":  1.0,
        "default":         0.7,
    }

    DOWNGRADE_MAP = {"CRITICAL":"HIGH","HIGH":"MEDIUM","MEDIUM":"LOW","LOW":"INFO"}

    def __init__(self, quorum: float = 0.6):
        self.quorum  = quorum
        self.weights = dict(self.DEFAULT_WEIGHTS)
        self.history: List[Dict] = []

    def vote(self, finding: Dict, agent_votes: List[Dict]) -> Dict:
        """
        agent_votes: [{"agent": str, "vote": Vote, "confidence": 0-100, "reason": str}]
        Returns consensus decision with final severity and confidence.
        """
        if not agent_votes:
            return self._result(finding, Vote.CONFIRM, 50, "No votes — auto-confirm", [])

        total_weight  = 0.0
        confirm_w     = 0.0
        reject_w      = 0.0
        downgrade_w   = 0.0
        escalate_w    = 0.0
        weighted_conf = 0.0

        for av in agent_votes:
            agent  = av.get("agent", "default")
            vote   = av.get("vote", Vote.CONFIRM)
            conf   = av.get("confidence", 70) / 100.0
            weight = self.weights.get(agent, self.weights["default"])
            w      = weight * conf

            total_weight  += weight
            weighted_conf += w
            if   vote == Vote.CONFIRM:   confirm_w   += w
            elif vote == Vote.REJECT:    reject_w    += w
            elif vote == Vote.DOWNGRADE: downgrade_w += w
            elif vote == Vote.ESCALATE:  escalate_w  += w

        if total_weight == 0:
            return self._result(finding, Vote.CONFIRM, 50, "Zero weight", agent_votes)

        # Normalise
        norm       = weighted_conf / total_weight
        final_conf = round(norm * 100)
        reject_r   = reject_w   / total_weight
        downgrade_r= downgrade_w / total_weight
        escalate_r = escalate_w  / total_weight
        confirm_r  = confirm_w   / total_weight

        # Decision logic
        if reject_r >= self.quorum:
            verdict = Vote.REJECT; new_sev = None
        elif escalate_r >= self.quorum:
            verdict = Vote.ESCALATE; new_sev = finding.get("severity")
        elif downgrade_r >= self.quorum:
            verdict = Vote.DOWNGRADE
            new_sev = self.DOWNGRADE_MAP.get(finding.get("severity","INFO"), "INFO")
        elif confirm_r >= self.quorum:
            verdict = Vote.CONFIRM; new_sev = finding.get("severity")
        else:
            # Plurality
            scores = {Vote.CONFIRM:confirm_r, Vote.REJECT:reject_r,
                      Vote.DOWNGRADE:downgrade_r, Vote.ESCALATE:escalate_r}
            verdict = max(scores, key=scores.get)
            new_sev = (self.DOWNGRADE_MAP.get(finding.get("severity","INFO"))
                       if verdict==Vote.DOWNGRADE else finding.get("severity"))

        result = self._result(finding, verdict, final_conf,
                              f"confirm={confirm_r:.0%} reject={reject_r:.0%} "
                              f"downgrade={downgrade_r:.0%}", agent_votes, new_sev)
        self.history.append(result)
        return result

    def batch(self, findings: List[Dict],
              votes_per_finding: List[List[Dict]]) -> List[Dict]:
        return [self.vote(f, v) for f, v in zip(findings, votes_per_finding)]

    def calibrate(self, agent: str, accuracy: float):
        """Update agent weight based on measured accuracy (0-1)."""
        self.weights[agent] = round(max(0.1, min(1.5, accuracy * 1.5)), 2)

    @staticmethod
    def _result(finding, verdict, confidence, reason, votes, new_sev=None):
        return {
            "finding_id": finding.get("id","?"),
            "original_severity": finding.get("severity"),
            "final_severity": new_sev or finding.get("severity"),
            "verdict": verdict,
            "confidence": confidence,
            "reason": reason,
            "vote_count": len(votes),
        }
