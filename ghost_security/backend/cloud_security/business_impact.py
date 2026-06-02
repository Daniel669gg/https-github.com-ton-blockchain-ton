"""
TythanAI Phase 9 — Business Impact Scorer

Scores the real-world business impact of security findings.
Combines: asset criticality + cloud exposure + privilege level + reachability + economic value.

Scale: 0–100 (like CVSS but business-oriented)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from backend.cloud_security.cloud_correlation import ExploitChain

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AssetCriticality(str, Enum):
    PRODUCTION_CRITICAL = "production_critical"  # Directly impacts revenue
    PRODUCTION          = "production"           # Production but not critical path
    STAGING             = "staging"              # Pre-production
    DEVELOPMENT         = "development"          # Dev/test environment
    UNKNOWN             = "unknown"


class CloudExposure(str, Enum):
    PUBLIC_INTERNET = "public_internet"   # Directly reachable from internet
    VPC_EXPOSED     = "vpc_exposed"       # Exposed within VPC but not internet
    INTERNAL_ONLY   = "internal_only"     # Internal network only
    PRIVATE         = "private"           # Private subnet, no exposure


class PrivilegeLevel(str, Enum):
    ROOT_ADMIN  = "root_admin"    # AWS root, cluster-admin, etc.
    ELEVATED    = "elevated"      # Admin role, admin group
    STANDARD    = "standard"      # Normal user/service account
    READ_ONLY   = "read_only"     # Read-only access


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class BusinessImpactScore:
    score: int                        # 0–100
    impact_class: str                 # CATASTROPHIC | CRITICAL | HIGH | MEDIUM | LOW
    asset_criticality: str
    cloud_exposure: str
    privilege_level: str
    reachability_confirmed: bool
    estimated_assets_at_risk: int     # number of affected resources
    contributing_factors: List[str]   # human-readable explanation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "impact_class": self.impact_class,
            "asset_criticality": self.asset_criticality,
            "cloud_exposure": self.cloud_exposure,
            "privilege_level": self.privilege_level,
            "reachability_confirmed": self.reachability_confirmed,
            "estimated_assets_at_risk": self.estimated_assets_at_risk,
            "contributing_factors": self.contributing_factors,
        }


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------


class BusinessImpactScorer:
    """
    Computes business impact score for individual findings and exploit chains.

    Scoring methodology
    -------------------
    1. Base score from finding severity.
    2. Multiplicative adjustments for exposure, privilege, criticality, reachability.
    3. Result capped at 100.
    """

    # Base scores by severity
    _BASE_SCORES: Dict[str, int] = {
        "CRITICAL": 80,
        "HIGH":     60,
        "MEDIUM":   40,
        "LOW":      20,
        "INFO":     5,
    }

    # Multipliers
    _EXPOSURE_MULT: Dict[CloudExposure, float] = {
        CloudExposure.PUBLIC_INTERNET: 1.5,
        CloudExposure.VPC_EXPOSED:     1.2,
        CloudExposure.INTERNAL_ONLY:   1.0,
        CloudExposure.PRIVATE:         0.8,
    }

    _PRIVILEGE_MULT: Dict[PrivilegeLevel, float] = {
        PrivilegeLevel.ROOT_ADMIN: 1.4,
        PrivilegeLevel.ELEVATED:   1.2,
        PrivilegeLevel.STANDARD:   1.0,
        PrivilegeLevel.READ_ONLY:  0.7,
    }

    _CRITICALITY_MULT: Dict[AssetCriticality, float] = {
        AssetCriticality.PRODUCTION_CRITICAL: 1.3,
        AssetCriticality.PRODUCTION:          1.15,
        AssetCriticality.STAGING:             0.9,
        AssetCriticality.DEVELOPMENT:         0.7,
        AssetCriticality.UNKNOWN:             1.0,
    }

    _REACHABILITY_MULT: float = 1.2

    # Attack-type base scores for chain scoring
    _ATTACK_BASE: Dict[str, int] = {
        "FULL_COMPROMISE":      95,
        "DATA_EXFILTRATION":    80,
        "PRIVILEGE_ESCALATION": 75,
        "LATERAL_MOVEMENT":     60,
    }

    def score_finding(
        self,
        finding: Dict[str, Any],
        context: Optional[Dict] = None,
    ) -> BusinessImpactScore:
        """Score a single finding dict.

        *context* may provide:
            asset_criticality, cloud_exposure, privilege_level,
            reachability_confirmed, estimated_assets_at_risk
        """
        context = context or {}
        factors: List[str] = []

        # --- severity base ---
        sev = str(finding.get("severity", "LOW")).upper()
        base = self._BASE_SCORES.get(sev, 20)
        factors.append(f"Base score {base} from {sev} severity")

        # --- asset criticality ---
        criticality_str = context.get("asset_criticality") or self._infer_criticality(finding).value
        try:
            criticality = AssetCriticality(criticality_str)
        except ValueError:
            criticality = AssetCriticality.UNKNOWN
        crit_mult = self._CRITICALITY_MULT[criticality]
        if crit_mult != 1.0:
            factors.append(f"Asset criticality '{criticality.value}' ×{crit_mult:.2f}")

        # --- cloud exposure ---
        exposure_str = context.get("cloud_exposure") or self._infer_exposure(finding).value
        try:
            exposure = CloudExposure(exposure_str)
        except ValueError:
            exposure = CloudExposure.INTERNAL_ONLY
        exp_mult = self._EXPOSURE_MULT[exposure]
        if exp_mult != 1.0:
            factors.append(f"Cloud exposure '{exposure.value}' ×{exp_mult:.2f}")

        # --- privilege level ---
        priv_str = context.get("privilege_level") or self._infer_privilege(finding).value
        try:
            privilege = PrivilegeLevel(priv_str)
        except ValueError:
            privilege = PrivilegeLevel.STANDARD
        priv_mult = self._PRIVILEGE_MULT[privilege]
        if priv_mult != 1.0:
            factors.append(f"Privilege level '{privilege.value}' ×{priv_mult:.2f}")

        # --- reachability ---
        reachability = bool(context.get("reachability_confirmed", False))
        if not reachability:
            # Infer reachability from finding itself
            desc_lower = str(finding.get("description", "")).lower()
            rule_lower = str(finding.get("rule_id", "")).lower()
            reachability = any(
                kw in desc_lower or kw in rule_lower
                for kw in ("publicly accessible", "internet-facing", "public endpoint", "confirmed reachable")
            )
        reach_mult = self._REACHABILITY_MULT if reachability else 1.0
        if reachability:
            factors.append(f"Reachability confirmed ×{reach_mult:.2f}")

        # --- compute ---
        raw = base * crit_mult * exp_mult * priv_mult * reach_mult
        score = min(100, int(round(raw)))

        # --- assets at risk ---
        assets_at_risk = int(context.get("estimated_assets_at_risk", 0))
        if assets_at_risk == 0:
            # Rough estimate from finding text
            desc = str(finding.get("description", "")).lower()
            resource = str(finding.get("resource", "")).lower()
            if "all" in desc or "wildcard" in desc or resource == "*":
                assets_at_risk = 100
            elif "many" in desc or "multiple" in desc:
                assets_at_risk = 10
            else:
                assets_at_risk = 1

        return BusinessImpactScore(
            score=score,
            impact_class=self._classify(score),
            asset_criticality=criticality.value,
            cloud_exposure=exposure.value,
            privilege_level=privilege.value,
            reachability_confirmed=reachability,
            estimated_assets_at_risk=assets_at_risk,
            contributing_factors=factors,
        )

    def score_chain(self, chain: "ExploitChain") -> BusinessImpactScore:
        """Score an exploit chain produced by CloudCorrelationEngine."""
        factors: List[str] = []

        attack_type = getattr(chain, "attack_type", "LATERAL_MOVEMENT")
        base = self._ATTACK_BASE.get(attack_type, 60)
        factors.append(f"Base score {base} from attack type '{attack_type}'")

        # Layer span multiplier: each layer beyond 2 adds 5%
        n_layers = chain.layers_count()
        layer_mult = 1.0 + 0.05 * max(0, n_layers - 2)
        if layer_mult != 1.0:
            factors.append(f"Chain spans {n_layers} layers ×{layer_mult:.2f}")

        # Confidence multiplier (chain confidence 0–1 → 0.8–1.0 scale)
        confidence = getattr(chain, "confidence", 0.5)
        conf_mult = 0.8 + 0.2 * confidence
        factors.append(f"Correlation confidence {confidence:.2f} ×{conf_mult:.2f}")

        # Chain severity
        chain_sev = getattr(chain, "chain_severity", "MEDIUM").upper()
        sev_mult_map = {"CRITICAL": 1.3, "HIGH": 1.15, "MEDIUM": 1.0, "LOW": 0.8, "INFO": 0.6}
        sev_mult = sev_mult_map.get(chain_sev, 1.0)
        if sev_mult != 1.0:
            factors.append(f"Chain severity '{chain_sev}' ×{sev_mult:.2f}")

        raw = base * layer_mult * conf_mult * sev_mult
        score = min(100, int(round(raw)))

        # Determine privilege level from chain links
        links = getattr(chain, "links", [])
        has_iam = any(getattr(lnk, "layer", "") == "iam" for lnk in links)
        has_cloud = any(getattr(lnk, "layer", "") == "cloud" for lnk in links)
        privilege = PrivilegeLevel.ELEVATED if has_iam else PrivilegeLevel.STANDARD
        exposure = CloudExposure.PUBLIC_INTERNET if (has_iam and has_cloud) else CloudExposure.VPC_EXPOSED

        return BusinessImpactScore(
            score=score,
            impact_class=self._classify(score),
            asset_criticality=AssetCriticality.PRODUCTION.value if has_cloud else AssetCriticality.UNKNOWN.value,
            cloud_exposure=exposure.value,
            privilege_level=privilege.value,
            reachability_confirmed=has_iam and has_cloud,
            estimated_assets_at_risk=n_layers * 5,
            contributing_factors=factors,
        )

    def score_bulk(
        self,
        findings: List[Dict],
        context: Optional[Dict] = None,
    ) -> List[BusinessImpactScore]:
        """Score all findings, return sorted by score descending."""
        scores = [self.score_finding(f, context=context) for f in findings]
        return sorted(scores, key=lambda s: s.score, reverse=True)

    # ------------------------------------------------------------------
    # Inference helpers
    # ------------------------------------------------------------------

    def _infer_exposure(self, finding: Dict) -> CloudExposure:
        """Infer cloud exposure from finding text."""
        text = " ".join(
            str(finding.get(k, "")).lower()
            for k in ("description", "rule_id", "label", "title", "resource")
        )

        public_signals = ("public", "internet", "0.0.0.0", "open to world", "ingress all", "publicly accessible", "0/0")
        vpc_signals = ("vpc", "internal vpc", "cross-account", "peer", "private link")
        internal_signals = ("internal", "localhost", "loopback", "127.0.0.1")
        private_signals = ("private subnet", "no internet", "isolated", "air-gapped")

        if any(kw in text for kw in public_signals):
            return CloudExposure.PUBLIC_INTERNET
        if any(kw in text for kw in private_signals):
            return CloudExposure.PRIVATE
        if any(kw in text for kw in internal_signals):
            return CloudExposure.INTERNAL_ONLY
        if any(kw in text for kw in vpc_signals):
            return CloudExposure.VPC_EXPOSED
        return CloudExposure.INTERNAL_ONLY

    def _infer_privilege(self, finding: Dict) -> PrivilegeLevel:
        """Infer privilege level from finding text."""
        text = " ".join(
            str(finding.get(k, "")).lower()
            for k in ("description", "rule_id", "label", "title", "permission", "principal")
        )

        root_signals = ("root", "cluster-admin", "full admin", "administrator", "iam:*", "*:*", "wildcard admin")
        elevated_signals = ("admin", "elevated", "privileged", "superuser", "power user", "passrole")
        readonly_signals = ("read-only", "readonly", "get only", "list only", "view only")

        if any(kw in text for kw in root_signals):
            return PrivilegeLevel.ROOT_ADMIN
        if any(kw in text for kw in elevated_signals):
            return PrivilegeLevel.ELEVATED
        if any(kw in text for kw in readonly_signals):
            return PrivilegeLevel.READ_ONLY
        return PrivilegeLevel.STANDARD

    def _infer_criticality(self, finding: Dict) -> AssetCriticality:
        """Infer asset criticality from resource name, file path, or description."""
        text = " ".join(
            str(finding.get(k, "")).lower()
            for k in ("resource", "resource_id", "description", "file", "label", "title")
        )

        prod_critical_signals = (
            "production-critical", "prod-critical", "revenue", "payment", "checkout",
            "billing", "pci", "customer-data", "gdpr", "hipaa", "phi", "pii-critical",
        )
        prod_signals = ("prod", "production", "live", "release", "main", "master")
        staging_signals = ("staging", "stage", "pre-prod", "uat", "qa", "preprod")
        dev_signals = ("dev", "development", "sandbox", "test", "local", "feature", "experiment")

        if any(kw in text for kw in prod_critical_signals):
            return AssetCriticality.PRODUCTION_CRITICAL
        if any(kw in text for kw in dev_signals):
            return AssetCriticality.DEVELOPMENT
        if any(kw in text for kw in staging_signals):
            return AssetCriticality.STAGING
        if any(kw in text for kw in prod_signals):
            return AssetCriticality.PRODUCTION
        return AssetCriticality.UNKNOWN

    def _classify(self, score: int) -> str:
        if score >= 90:
            return "CATASTROPHIC"
        if score >= 70:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        return "LOW"
