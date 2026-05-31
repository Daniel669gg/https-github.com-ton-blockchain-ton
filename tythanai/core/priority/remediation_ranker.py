"""
TythanAI — Remediation Priority Ranker
Scores findings by exploitability, business impact, fix effort, and CVSS-like vectors.
Generates sprint-ready prioritized remediation plans.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ── Scoring weights ────────────────────────────────────────────────────────────
_SEVERITY_BASE = {"critical": 10.0, "high": 7.5, "medium": 4.5, "low": 2.0, "info": 0.5}
_CONFIDENCE_MULT = {"confirmed": 1.0, "high": 0.9, "medium": 0.7, "low": 0.5, "tentative": 0.3}
_EFFORT_DAYS = {"trivial": 0.25, "low": 1.0, "medium": 3.0, "high": 7.0, "complex": 14.0}

# CWE → estimated fix effort
_CWE_EFFORT: Dict[str, str] = {
    "CWE-798": "low",      # hardcoded credential → replace with env var
    "CWE-89":  "medium",   # SQL injection → parameterize queries
    "CWE-79":  "medium",   # XSS → escape output
    "CWE-78":  "medium",   # Command injection → allowlist
    "CWE-22":  "medium",   # Path traversal → sanitize
    "CWE-287": "high",     # Broken auth → redesign flow
    "CWE-284": "high",     # Access control → RBAC redesign
    "CWE-400": "high",     # Resource exhaustion → rate limit + limits
    "CWE-502": "high",     # Deserialization → replace
    "CWE-20":  "low",      # Input validation → add validators
    "CWE-200": "low",      # Info disclosure → remove debug output
    "CWE-312": "medium",   # Cleartext storage → encrypt
}

# Tag boost: if finding has these tags it gets an extra score boost
_TAG_BOOST: Dict[str, float] = {
    "auth":          2.5,
    "authentication": 2.5,
    "rce":           3.0,
    "remote_code_execution": 3.0,
    "sqli":          2.0,
    "sql_injection": 2.0,
    "secret":        2.0,
    "hardcoded":     1.5,
    "reentrancy":    2.5,
    "access_control": 2.0,
    "privilege_escalation": 2.5,
    "public_facing": 1.5,
}


@dataclass
class ScoredFinding:
    finding_id:   str
    rule_id:      str
    title:        str
    file:         str
    line:         int
    severity:     str
    confidence:   str
    cwe:          str
    score:        float
    effort:       str
    effort_days:  float
    priority_rank: int = 0
    roi_score:    float = 0.0  # score / effort_days
    tags:         List[str] = field(default_factory=list)
    sprint:       int = 1

    def to_dict(self) -> dict:
        return {
            "priority_rank": self.priority_rank,
            "finding_id":    self.finding_id,
            "rule_id":       self.rule_id,
            "title":         self.title,
            "file":          self.file,
            "line":          self.line,
            "severity":      self.severity,
            "score":         round(self.score, 2),
            "effort":        self.effort,
            "effort_days":   self.effort_days,
            "roi_score":     round(self.roi_score, 2),
            "sprint":        self.sprint,
        }


@dataclass
class SprintPlan:
    sprints: Dict[int, List[ScoredFinding]] = field(default_factory=dict)
    total_effort_days: float = 0.0
    sprint_capacity_days: float = 5.0

    def summary(self) -> dict:
        return {
            "total_findings":     sum(len(v) for v in self.sprints.values()),
            "total_sprints":      len(self.sprints),
            "total_effort_days":  round(self.total_effort_days, 1),
            "sprint_capacity":    self.sprint_capacity_days,
            "sprints": {
                str(k): {
                    "findings": len(v),
                    "effort_days": round(sum(f.effort_days for f in v), 1),
                }
                for k, v in self.sprints.items()
            },
        }


class RemediationRanker:
    """
    Scores and ranks security findings by risk-adjusted priority.
    Generates sprint plans based on effort estimates and team capacity.
    """

    def __init__(self, sprint_capacity_days: float = 5.0):
        self.sprint_capacity_days = sprint_capacity_days

    def score_finding(self, finding: dict) -> ScoredFinding:
        severity   = finding.get("severity", "medium").lower()
        confidence = finding.get("confidence", "medium").lower()
        cwe        = finding.get("cwe", "")
        tags       = finding.get("tags", [])
        rule_id    = finding.get("rule_id", "UNKNOWN")

        base = _SEVERITY_BASE.get(severity, 4.5)
        conf_mult = _CONFIDENCE_MULT.get(confidence, 0.7)

        # Tag boosts
        tag_boost = sum(_TAG_BOOST.get(t.lower(), 0.0) for t in tags)
        tag_boost += sum(_TAG_BOOST.get(t.lower(), 0.0) for t in rule_id.lower().split("-"))

        score = (base * conf_mult) + tag_boost

        # Effort estimation
        effort = _CWE_EFFORT.get(cwe, self._estimate_effort_by_severity(severity))
        effort_days = _EFFORT_DAYS[effort]

        roi = score / effort_days if effort_days > 0 else score

        return ScoredFinding(
            finding_id   = finding.get("id", f"{rule_id}:{finding.get('file','')}:{finding.get('line',0)}"),
            rule_id      = rule_id,
            title        = finding.get("title", finding.get("message", "Unknown")),
            file         = finding.get("file", ""),
            line         = finding.get("line", 0),
            severity     = severity,
            confidence   = confidence,
            cwe          = cwe,
            score        = score,
            effort       = effort,
            effort_days  = effort_days,
            roi_score    = roi,
            tags         = tags,
        )

    def _estimate_effort_by_severity(self, severity: str) -> str:
        return {"critical": "high", "high": "medium", "medium": "low", "low": "trivial", "info": "trivial"}.get(severity, "low")

    def rank(self, findings: List[dict]) -> List[ScoredFinding]:
        """Score and rank all findings. Returns sorted by (severity_weight DESC, roi DESC)."""
        scored = [self.score_finding(f) for f in findings]
        scored.sort(key=lambda s: (-s.score, -s.roi_score))
        for i, s in enumerate(scored, start=1):
            s.priority_rank = i
        return scored

    def generate_sprint_plan(self, findings: List[dict]) -> SprintPlan:
        """Distribute ranked findings across sprints based on capacity."""
        ranked = self.rank(findings)
        plan = SprintPlan(sprint_capacity_days=self.sprint_capacity_days)

        current_sprint = 1
        current_load   = 0.0

        for finding in ranked:
            finding.sprint = current_sprint
            plan.sprints.setdefault(current_sprint, []).append(finding)
            current_load          += finding.effort_days
            plan.total_effort_days += finding.effort_days

            if current_load >= self.sprint_capacity_days:
                current_sprint += 1
                current_load    = 0.0

        return plan

    def estimate_fix_effort(self, findings: List[dict]) -> dict:
        """Return total and per-severity effort estimates."""
        scored = [self.score_finding(f) for f in findings]
        by_sev: Dict[str, float] = {}
        total = 0.0
        for s in scored:
            by_sev[s.severity] = by_sev.get(s.severity, 0.0) + s.effort_days
            total += s.effort_days
        return {
            "total_days":   round(total, 1),
            "by_severity":  {k: round(v, 1) for k, v in by_sev.items()},
            "total_sprints": math.ceil(total / self.sprint_capacity_days) if total else 0,
        }

    def generate_report(self, findings: List[dict], fmt: str = "text") -> str:
        ranked = self.rank(findings)
        plan   = self.generate_sprint_plan(findings)

        if fmt == "json":
            return json.dumps({
                "ranked_findings": [f.to_dict() for f in ranked],
                "sprint_plan":     plan.summary(),
            }, indent=2)

        lines = [
            "╔══════════════════════════════════════════════════════════════╗",
            "║     REMEDIATION PRIORITY REPORT — TythanAI               ║",
            "╚══════════════════════════════════════════════════════════════╝",
            f"\nTotal findings: {len(ranked)}   "
            f"Est. effort: {round(plan.total_effort_days,1)} days   "
            f"Sprints needed: {len(plan.sprints)}",
            "\n── Top 10 Priority Findings ──",
        ]
        for f in ranked[:10]:
            lines.append(f"  #{f.priority_rank:>3}  [{f.severity.upper():<8}] {f.rule_id:<30}  Score:{f.score:>5.1f}  Effort:{f.effort_days}d  ROI:{f.roi_score:.1f}")
            lines.append(f"        {f.file}:{f.line}")

        lines.append("\n── Sprint Plan ──")
        for sprint_num, sprint_findings in sorted(plan.sprints.items()):
            effort = sum(sf.effort_days for sf in sprint_findings)
            lines.append(f"  Sprint {sprint_num}: {len(sprint_findings)} findings, {effort:.1f} days")
            for sf in sprint_findings[:3]:
                lines.append(f"    - [{sf.severity}] {sf.title[:60]}")
            if len(sprint_findings) > 3:
                lines.append(f"    ... and {len(sprint_findings)-3} more")

        return "\n".join(lines)


import math
