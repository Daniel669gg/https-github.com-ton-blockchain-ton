"""Vulnerability Prioritizer — SSVC-inspired scoring combining EPSS + KEV + Reachability + Exploit."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.vuln_prioritizer")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class SSVCDecision(str, Enum):
    IMMEDIATE = "immediate"         # Patch within 24h
    OUT_OF_CYCLE = "out_of_cycle"   # Patch within 1 week
    SCHEDULED = "scheduled"         # Next patch cycle
    DEFER = "defer"                 # Monitor, no immediate action


class VulnPriority(BaseModel):
    cve_id: str
    finding_rule_id: str
    ssvc_decision: SSVCDecision
    priority_score: float               # 0.0-100.0
    signals: Dict[str, float]           # {epss: 0.45, kev: 1.0, reachability: 0.85, ...}
    explanation: str
    recommended_action: str
    sla_days: int                       # 1, 7, 30, or 90


class PrioritizationReport(BaseModel):
    timestamp: str
    total_findings: int
    immediate: List[VulnPriority] = Field(default_factory=list)
    out_of_cycle: List[VulnPriority] = Field(default_factory=list)
    scheduled: List[VulnPriority] = Field(default_factory=list)
    defer: List[VulnPriority] = Field(default_factory=list)
    summary: str


# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

_SEVERITY_TO_IMPACT: Dict[str, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.2,
    "INFO": 0.05,
    "UNKNOWN": 0.1,
}

_SEVERITY_DEFAULT_REACH: Dict[str, float] = {
    "CRITICAL": 0.8,
    "HIGH": 0.6,
    "MEDIUM": 0.4,
    "LOW": 0.2,
    "INFO": 0.1,
    "UNKNOWN": 0.2,
}

_DECISION_SLA: Dict[SSVCDecision, int] = {
    SSVCDecision.IMMEDIATE: 1,
    SSVCDecision.OUT_OF_CYCLE: 7,
    SSVCDecision.SCHEDULED: 30,
    SSVCDecision.DEFER: 90,
}

_DECISION_ACTION: Dict[SSVCDecision, str] = {
    SSVCDecision.IMMEDIATE: (
        "Apply patch or mitigation immediately. Escalate to security on-call. "
        "Consider taking the affected component offline until patched."
    ),
    SSVCDecision.OUT_OF_CYCLE: (
        "Schedule an out-of-cycle patch deployment within 7 days. "
        "Apply compensating controls (WAF rules, network restrictions) in the interim."
    ),
    SSVCDecision.SCHEDULED: (
        "Include in next scheduled patch cycle (within 30 days). "
        "Monitor for exploitation attempts."
    ),
    SSVCDecision.DEFER: (
        "Log and monitor. Re-evaluate if exploitation signal changes. "
        "Low risk — defer to 90-day review cadence."
    ),
}


# ---------------------------------------------------------------------------
# Prioritizer
# ---------------------------------------------------------------------------


class VulnPrioritizer:
    """SSVC-inspired vulnerability prioritizer combining multiple intelligence signals."""

    def prioritize(
        self,
        findings: List[Finding],
        cve_records: Optional[Dict[str, Any]] = None,
        reachability_scores: Optional[Dict[str, float]] = None,
    ) -> PrioritizationReport:
        """
        Compute an SSVC-inspired decision for each finding.

        Parameters
        ----------
        findings:
            List of Finding objects to prioritize.
        cve_records:
            Optional dict mapping CVE ID → CVERecord dict with keys such as
            ``is_kev`` and ``epss_score``.
        reachability_scores:
            Optional dict mapping file path → reachability score (0.0–1.0).

        Returns
        -------
        PrioritizationReport sorted by priority_score descending within each bucket.
        """
        cve_records = cve_records or {}
        reachability_scores = reachability_scores or {}

        priorities: List[VulnPriority] = []

        for finding in findings:
            vp = self._prioritize_one(finding, cve_records, reachability_scores)
            priorities.append(vp)

        # Sort overall by priority_score desc
        priorities.sort(key=lambda v: v.priority_score, reverse=True)

        immediate = [v for v in priorities if v.ssvc_decision == SSVCDecision.IMMEDIATE]
        out_of_cycle = [
            v for v in priorities if v.ssvc_decision == SSVCDecision.OUT_OF_CYCLE
        ]
        scheduled = [v for v in priorities if v.ssvc_decision == SSVCDecision.SCHEDULED]
        defer = [v for v in priorities if v.ssvc_decision == SSVCDecision.DEFER]

        total = len(priorities)
        summary = (
            f"{total} findings assessed: "
            f"{len(immediate)} IMMEDIATE, "
            f"{len(out_of_cycle)} OUT-OF-CYCLE, "
            f"{len(scheduled)} SCHEDULED, "
            f"{len(defer)} DEFER. "
            f"SSVC-inspired model (EPSS × 0.4 + Reachability × 0.3 + Impact × 0.3)."
        )

        return PrioritizationReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_findings=total,
            immediate=immediate,
            out_of_cycle=out_of_cycle,
            scheduled=scheduled,
            defer=defer,
            summary=summary,
        )

    # ------------------------------------------------------------------
    # Single-finding logic
    # ------------------------------------------------------------------

    def _prioritize_one(
        self,
        finding: Finding,
        cve_records: Dict[str, Any],
        reachability_scores: Dict[str, float],
    ) -> VulnPriority:
        """Compute the SSVC decision and priority score for a single finding."""
        # ── 1. Look up CVE metadata ────────────────────────────────────────────
        cve_id = getattr(finding, "cve_id", "") or ""
        cve_meta: Dict[str, Any] = {}
        if cve_id and cve_id in cve_records:
            raw = cve_records[cve_id]
            cve_meta = raw if isinstance(raw, dict) else (raw.model_dump() if hasattr(raw, "model_dump") else {})

        is_kev: bool = bool(cve_meta.get("is_kev", False))
        epss_score: float = float(cve_meta.get("epss_score", 0.0))

        # ── 2. Exploitation signal (0.0–1.0) ──────────────────────────────────
        if is_kev:
            exploitation = 1.0
        elif epss_score > 0.5:
            exploitation = 0.8
        elif epss_score > 0.1:
            exploitation = 0.5
        else:
            exploitation = 0.1

        # ── 3. Reachability signal (0.0–1.0) ──────────────────────────────────
        reachability: float = reachability_scores.get(
            finding.file,
            _SEVERITY_DEFAULT_REACH.get(finding.severity, 0.2),
        )

        # ── 4. Impact signal (0.0–1.0) ────────────────────────────────────────
        impact: float = _SEVERITY_TO_IMPACT.get(finding.severity, 0.1)

        # ── 5. SSVC decision tree ──────────────────────────────────────────────
        # Exploitation thresholds: HIGH = 0.8+, MEDIUM = 0.5+
        exploitation_high = exploitation >= 0.8
        reachability_high = reachability >= 0.7
        impact_high = impact >= 0.8

        if exploitation_high and reachability_high:
            decision = SSVCDecision.IMMEDIATE
        elif exploitation_high or (reachability_high and impact_high):
            decision = SSVCDecision.OUT_OF_CYCLE
        elif impact >= 0.5:
            decision = SSVCDecision.SCHEDULED
        else:
            decision = SSVCDecision.DEFER

        # ── 6. Priority score (0–100) ──────────────────────────────────────────
        priority_score = round(
            (exploitation * 0.4 + reachability * 0.3 + impact * 0.3) * 100, 2
        )

        # ── 7. Explanation ─────────────────────────────────────────────────────
        explanation_parts = [
            f"Exploitation={exploitation:.2f} (KEV={'yes' if is_kev else 'no'}, EPSS={epss_score:.3f})",
            f"Reachability={reachability:.2f}",
            f"Impact={impact:.2f} (severity={finding.severity})",
            f"Decision={decision.value.upper()}",
        ]
        explanation = "; ".join(explanation_parts)

        return VulnPriority(
            cve_id=cve_id or f"rule:{finding.rule_id}",
            finding_rule_id=finding.rule_id,
            ssvc_decision=decision,
            priority_score=priority_score,
            signals={
                "exploitation": exploitation,
                "epss": epss_score,
                "kev": 1.0 if is_kev else 0.0,
                "reachability": reachability,
                "impact": impact,
            },
            explanation=explanation,
            recommended_action=_DECISION_ACTION[decision],
            sla_days=_DECISION_SLA[decision],
        )

    # ------------------------------------------------------------------
    # Markdown report
    # ------------------------------------------------------------------

    def to_markdown(self, report: PrioritizationReport) -> str:
        """Render *report* as a Markdown table."""
        lines: List[str] = [
            f"# Vulnerability Prioritization Report",
            f"",
            f"**Generated:** {report.timestamp}  ",
            f"**Total findings:** {report.total_findings}  ",
            f"**Summary:** {report.summary}",
            f"",
            f"## Findings by Priority",
            f"",
            f"| CVE / Rule | Finding Rule | Decision | Score | SLA (days) | Explanation |",
            f"|------------|--------------|----------|-------|------------|-------------|",
        ]

        all_priorities = (
            report.immediate
            + report.out_of_cycle
            + report.scheduled
            + report.defer
        )

        for vp in all_priorities:
            cve_col = vp.cve_id or "—"
            lines.append(
                f"| {cve_col} "
                f"| {vp.finding_rule_id} "
                f"| {vp.ssvc_decision.value.upper()} "
                f"| {vp.priority_score:.1f} "
                f"| {vp.sla_days} "
                f"| {vp.explanation} |"
            )

        lines.append("")
        lines.append("## Bucket Summary")
        lines.append("")
        lines.append(
            f"| Bucket | Count |\n"
            f"|--------|-------|\n"
            f"| IMMEDIATE | {len(report.immediate)} |\n"
            f"| OUT_OF_CYCLE | {len(report.out_of_cycle)} |\n"
            f"| SCHEDULED | {len(report.scheduled)} |\n"
            f"| DEFER | {len(report.defer)} |"
        )

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------


def prioritize_vulnerabilities(
    findings: List[Finding],
    cve_records: Optional[Dict[str, Any]] = None,
    reachability_scores: Optional[Dict[str, float]] = None,
) -> PrioritizationReport:
    """Prioritize *findings* using SSVC-inspired multi-signal scoring."""
    return VulnPrioritizer().prioritize(findings, cve_records, reachability_scores)
