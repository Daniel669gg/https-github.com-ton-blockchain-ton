"""
TythanAI Phase 9 — Enterprise Risk Scorer

Produces a single enterprise-level risk score from all security signals.
Combines: SAST + Dependency + DAST + Cloud + IAM + K8s + Container + Business Impact.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from backend.cloud_security.business_impact import BusinessImpactScore
    from backend.cloud_security.cloud_correlation import ExploitChain

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class EnterpriseRiskClass(str, Enum):
    CATASTROPHIC = "CATASTROPHIC"   # Score ≥ 90
    CRITICAL     = "CRITICAL"       # Score ≥ 70
    HIGH         = "HIGH"           # Score ≥ 50
    MEDIUM       = "MEDIUM"         # Score ≥ 30
    LOW          = "LOW"            # Score < 30


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class LayerScore:
    layer: str
    score: int           # 0–100
    findings_count: int
    critical_count: int
    weight: float        # contribution weight to enterprise score


@dataclass
class EnterpriseRiskReport:
    enterprise_score: int                  # 0–100 weighted composite
    risk_class: EnterpriseRiskClass
    layer_scores: List[LayerScore]
    critical_chains: int                   # number of critical exploit chains
    total_findings: int
    top_risks: List[Dict[str, Any]]        # top 10 findings by business impact
    layers_with_critical: List[str]        # which layers have critical findings
    recommended_priorities: List[str]      # prioritized remediation actions

    def to_dict(self) -> Dict[str, Any]:
        return {
            "enterprise_score": self.enterprise_score,
            "risk_class": self.risk_class.value,
            "layer_scores": [
                {
                    "layer": ls.layer,
                    "score": ls.score,
                    "findings_count": ls.findings_count,
                    "critical_count": ls.critical_count,
                    "weight": ls.weight,
                }
                for ls in self.layer_scores
            ],
            "critical_chains": self.critical_chains,
            "total_findings": self.total_findings,
            "top_risks": self.top_risks,
            "layers_with_critical": self.layers_with_critical,
            "recommended_priorities": self.recommended_priorities,
        }


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------


class EnterpriseRiskScorer:
    """
    Combines all security layer scores into a single enterprise risk metric.

    Weights (must sum to 1.0):
      code:        0.20   (SAST findings)
      dependency:  0.15   (CVE/SCA)
      dast:        0.15   (Runtime-confirmed)
      cloud:       0.25   (Cloud misconfigs — highest weight)
      iam:         0.15   (IAM/access risks)
      container:   0.10   (Container/K8s risks)
    """

    WEIGHTS: Dict[str, float] = {
        "code":       0.20,
        "dependency": 0.15,
        "dast":       0.15,
        "cloud":      0.25,
        "iam":        0.15,
        "container":  0.10,
    }

    # Per-layer remediation advice templates
    _LAYER_ADVICE: Dict[str, str] = {
        "code": (
            "Patch SAST critical findings — injection vulnerabilities and authentication bypasses"
        ),
        "dependency": (
            "Update vulnerable dependencies — apply CVE patches and pin transitive packages"
        ),
        "dast": (
            "Remediate runtime-confirmed vulnerabilities — address all DAST-flagged endpoints immediately"
        ),
        "cloud": (
            "Fix critical cloud misconfigurations — public storage buckets and open security groups"
        ),
        "iam": (
            "Remediate overprivileged IAM roles — revoke wildcard permissions and add least-privilege policies"
        ),
        "container": (
            "Harden container and K8s configuration — remove privileged containers and restrict RBAC"
        ),
    }

    def score(
        self,
        sast_findings: Optional[List[Dict]] = None,
        cve_findings: Optional[List[Dict]] = None,
        dast_findings: Optional[List[Dict]] = None,
        cloud_findings: Optional[List[Dict]] = None,
        iam_findings: Optional[List[Dict]] = None,
        k8s_findings: Optional[List[Dict]] = None,
        container_findings: Optional[List[Dict]] = None,
        exploit_chains: Optional[List["ExploitChain"]] = None,
        business_impacts: Optional[List["BusinessImpactScore"]] = None,
    ) -> EnterpriseRiskReport:
        """
        Compute a full enterprise risk report.

        Steps
        -----
        1. Score each layer with _score_layer().
        2. Weighted average of layer scores.
        3. Apply exploit chain multiplier.
        4. Apply business impact multiplier.
        5. Cap at 100.
        6. Generate recommended priorities.
        """
        # Merge K8s into container bucket for scoring purposes
        combined_container: List[Dict] = list(container_findings or []) + list(k8s_findings or [])

        layer_input: Dict[str, List[Dict]] = {
            "code":       list(sast_findings or []),
            "dependency": list(cve_findings or []),
            "dast":       list(dast_findings or []),
            "cloud":      list(cloud_findings or []),
            "iam":        list(iam_findings or []),
            "container":  combined_container,
        }

        # --- 1. Score each layer ---
        layer_scores: List[LayerScore] = []
        for layer_name, findings in layer_input.items():
            layer_scores.append(self._score_layer(findings, layer_name))

        # --- 2. Weighted average ---
        weighted_sum = sum(ls.score * ls.weight for ls in layer_scores)
        # weighted_sum is already on 0–100 scale since each score ≤ 100 and weights sum to 1.0
        raw_score = weighted_sum

        # --- 3. Chain multiplier ---
        chain_mult = self._chain_multiplier(list(exploit_chains or []))
        raw_score *= chain_mult

        # --- 4. Business impact multiplier ---
        if business_impacts:
            # Use the top score as signal: if top impact ≥ 80, add 10% boost
            top_impact = max((b.score for b in business_impacts), default=0)
            if top_impact >= 90:
                raw_score *= 1.15
            elif top_impact >= 70:
                raw_score *= 1.10
            elif top_impact >= 50:
                raw_score *= 1.05

        # --- 5. Cap ---
        enterprise_score = min(100, int(round(raw_score)))

        # --- Supporting metrics ---
        critical_chains = sum(
            1
            for c in (exploit_chains or [])
            if getattr(c, "chain_severity", "") == "CRITICAL" and getattr(c, "layers_count", lambda: 0)() >= 3
        )

        total_findings = sum(ls.findings_count for ls in layer_scores)

        layers_with_critical = [
            ls.layer for ls in layer_scores if ls.critical_count > 0
        ]

        # Top 10 findings by business impact
        top_risks: List[Dict[str, Any]] = []
        if business_impacts:
            sorted_impacts = sorted(business_impacts, key=lambda b: b.score, reverse=True)
            for bi in sorted_impacts[:10]:
                top_risks.append(bi.to_dict())
        else:
            # Fall back: collect top critical/high findings from all layers
            all_findings: List[Dict] = []
            for findings in layer_input.values():
                all_findings.extend(findings)
            sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            all_findings.sort(
                key=lambda f: sev_order.get(str(f.get("severity", "LOW")).upper(), 0),
                reverse=True,
            )
            for f in all_findings[:10]:
                top_risks.append({
                    "severity": f.get("severity", "LOW"),
                    "label": f.get("title", f.get("rule_id", f.get("id", "unknown"))),
                    "resource": f.get("resource", f.get("file", "")),
                    "description": f.get("description", ""),
                })

        # --- 6. Generate priorities ---
        # Build a partial report without priorities first, then fill in
        report = EnterpriseRiskReport(
            enterprise_score=enterprise_score,
            risk_class=self._classify(enterprise_score),
            layer_scores=layer_scores,
            critical_chains=critical_chains,
            total_findings=total_findings,
            top_risks=top_risks,
            layers_with_critical=layers_with_critical,
            recommended_priorities=[],   # filled below
        )
        report.recommended_priorities = self._generate_priorities(report)

        return report

    # ------------------------------------------------------------------
    # Layer scorer
    # ------------------------------------------------------------------

    def _score_layer(self, findings: List[Dict], layer_name: str) -> LayerScore:
        """Score a single layer from its finding list."""
        if not findings:
            return LayerScore(
                layer=layer_name,
                score=0,
                findings_count=0,
                critical_count=0,
                weight=self.WEIGHTS.get(layer_name, 0.0),
            )

        severity_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = str(f.get("severity", "LOW")).upper()
            if sev not in severity_counts:
                sev = "LOW"
            severity_counts[sev] += 1

        raw = (
            severity_counts["CRITICAL"] * 25
            + severity_counts["HIGH"]     * 10
            + severity_counts["MEDIUM"]   * 3
            + severity_counts["LOW"]      * 1
        )
        score = min(100, raw)

        return LayerScore(
            layer=layer_name,
            score=score,
            findings_count=len(findings),
            critical_count=severity_counts["CRITICAL"],
            weight=self.WEIGHTS.get(layer_name, 0.0),
        )

    # ------------------------------------------------------------------
    # Chain multiplier
    # ------------------------------------------------------------------

    def _chain_multiplier(self, chains: List["ExploitChain"]) -> float:
        """Return 1.2 if any chain is CRITICAL with ≥3 layers, else 1.0."""
        for chain in chains:
            sev = getattr(chain, "chain_severity", "")
            n_layers = getattr(chain, "layers_count", lambda: 0)()
            if sev == "CRITICAL" and n_layers >= 3:
                return 1.2
        return 1.0

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def _classify(self, score: int) -> EnterpriseRiskClass:
        if score >= 90:
            return EnterpriseRiskClass.CATASTROPHIC
        if score >= 70:
            return EnterpriseRiskClass.CRITICAL
        if score >= 50:
            return EnterpriseRiskClass.HIGH
        if score >= 30:
            return EnterpriseRiskClass.MEDIUM
        return EnterpriseRiskClass.LOW

    # ------------------------------------------------------------------
    # Priority generation
    # ------------------------------------------------------------------

    def _generate_priorities(self, report: EnterpriseRiskReport) -> List[str]:
        """Generate up to 5 prioritized remediation actions.

        Logic:
        - Sort layers by score descending.
        - Take the top-scoring layers and emit specific advice.
        - If there are critical exploit chains, add a chain-specific action.
        - If score is catastrophic, add an incident response item.
        """
        priorities: List[str] = []

        # Sort layers by score descending
        sorted_layers = sorted(report.layer_scores, key=lambda ls: ls.score, reverse=True)

        # Emit advice for the top layers that actually have findings
        for ls in sorted_layers:
            if len(priorities) >= 5:
                break
            if ls.score == 0 or ls.findings_count == 0:
                continue
            advice = self._LAYER_ADVICE.get(ls.layer)
            if advice:
                # Personalise with counts
                crit_note = f" ({ls.critical_count} critical)" if ls.critical_count > 0 else ""
                priorities.append(f"{advice}{crit_note}")

        # Critical chain action
        if report.critical_chains > 0 and len(priorities) < 5:
            priorities.append(
                f"Break {report.critical_chains} confirmed critical exploit chain(s) — "
                "isolate affected workloads and revoke compromised credentials immediately"
            )

        # Catastrophic/Critical overall score — add incident response
        if report.risk_class in (EnterpriseRiskClass.CATASTROPHIC, EnterpriseRiskClass.CRITICAL):
            if len(priorities) < 5:
                priorities.append(
                    "Initiate incident response procedure — enterprise risk level is "
                    f"{report.risk_class.value}; escalate to security leadership"
                )

        # Fallback if nothing was added (all layers scored 0)
        if not priorities:
            priorities.append(
                "No significant findings detected — maintain current security posture and schedule periodic reviews"
            )

        return priorities[:5]
