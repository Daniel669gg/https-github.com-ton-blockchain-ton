"""
TythanAI Phase 8 — TON Economic Risk Scorer

Assigns real economic impact scores to TON contract vulnerabilities.
Estimates potential fund loss, blast radius, and overall risk class
based on: severity, CWE type, contract type, and cross-contract paths.

Scale: all monetary estimates are in TON (not nanotons).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class EconomicRiskClass(str, Enum):
    CATASTROPHIC = "CATASTROPHIC"   # > 1M TON potential loss
    CRITICAL     = "CRITICAL"       # 100K – 1M TON
    HIGH         = "HIGH"           # 10K – 100K TON
    MEDIUM       = "MEDIUM"         # 1K – 10K TON
    LOW          = "LOW"            # < 1K TON


# Base impact estimates per contract type (in TON)
_CONTRACT_TYPE_IMPACT: Dict[str, float] = {
    "treasury":      500_000.0,
    "multisig":      200_000.0,
    "dao":           300_000.0,
    "jetton_master": 100_000.0,
    "defi":          150_000.0,
    "bridge":        500_000.0,
    "nft_collection":  5_000.0,
    "jetton_wallet":   1_000.0,
    "wallet":          5_000.0,
    "proxy":          50_000.0,
    "lockup":         20_000.0,
    "unknown":         2_000.0,
}

# Base impact per severity class (in TON)
_SEVERITY_BASE: Dict[str, float] = {
    "CRITICAL": 50_000.0,
    "HIGH":      5_000.0,
    "MEDIUM":      500.0,
    "LOW":          50.0,
    "INFO":          0.0,
}

# CWE → impact multiplier (how much this class of bug amplifies loss potential)
_CWE_MULTIPLIER: Dict[str, float] = {
    "CWE-284": 2.0,    # Access Control → ownership takeover
    "CWE-285": 2.0,    # Improper Authorization
    "CWE-691": 3.0,    # Insufficient Control Flow → fund drain (mode 128)
    "CWE-190": 1.5,    # Integer Overflow
    "CWE-362": 1.8,    # Race Condition (TON async)
    "CWE-294": 1.6,    # Replay Attack
    "CWE-338": 1.3,    # Weak PRNG → lottery manipulation
    "CWE-400": 1.1,    # Gas Griefing
    "CWE-754": 1.2,    # Missing Error Handling (bounce handler)
    "CWE-20":  1.3,    # Improper Input Validation
    "CWE-369": 1.1,    # Divide by Zero
}

# Blast radius (number of users/contracts potentially affected) per contract type
_BLAST_RADIUS: Dict[str, int] = {
    "treasury": 10_000,
    "dao":       5_000,
    "bridge":   50_000,
    "jetton_master": 10_000,
    "defi":      5_000,
    "multisig":    100,
    "nft_collection": 1_000,
    "wallet":         10,
    "proxy":       1_000,
    "unknown":        50,
}


@dataclass
class AffectedAssets:
    contracts: List[str] = field(default_factory=list)
    wallets:   List[str] = field(default_factory=list)
    jettons:   List[str] = field(default_factory=list)
    nfts:      List[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.contracts) + len(self.wallets) + len(self.jettons) + len(self.nfts)


@dataclass
class ScoredFinding:
    rule_id:          str
    severity:         str
    file:             str
    contract_type:    str
    cwe:              str
    description:      str
    estimated_loss_ton: float
    blast_radius:     int
    risk_score:       int       # 0–100

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id":              self.rule_id,
            "severity":             self.severity,
            "file":                 self.file,
            "contract_type":        self.contract_type,
            "cwe":                  self.cwe,
            "description":          self.description,
            "estimated_loss_ton":   round(self.estimated_loss_ton, 2),
            "blast_radius":         self.blast_radius,
            "risk_score":           self.risk_score,
        }


@dataclass
class EconomicRiskReport:
    total_risk_score:      int
    max_fund_loss_ton:     float
    total_potential_loss:  float
    affected_assets:       AffectedAssets
    economic_risk_class:   EconomicRiskClass
    critical_findings:     int
    high_findings:         int
    scored_findings:       List[ScoredFinding]
    fund_loss_paths:       List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_risk_score":      self.total_risk_score,
            "max_fund_loss_ton":     round(self.max_fund_loss_ton, 2),
            "total_potential_loss":  round(self.total_potential_loss, 2),
            "economic_risk_class":   self.economic_risk_class.value,
            "critical_findings":     self.critical_findings,
            "high_findings":         self.high_findings,
            "affected_assets": {
                "contracts": self.affected_assets.contracts,
                "wallets":   self.affected_assets.wallets,
                "jettons":   self.affected_assets.jettons,
                "nfts":      self.affected_assets.nfts,
                "total":     self.affected_assets.total,
            },
            "fund_loss_paths": self.fund_loss_paths,
            "top_findings": [
                f.to_dict()
                for f in sorted(self.scored_findings, key=lambda x: -x.risk_score)[:20]
            ],
        }


class EconomicRiskScorer:
    """
    Assigns economic impact scores to TON contract vulnerability findings.

    Input: list of finding dicts with keys:
      rule_id (or id), severity, file, description, cwe, category, evidence

    Output: EconomicRiskReport with per-finding estimates and aggregate metrics.
    """

    def score(
        self,
        findings: List[Dict[str, Any]],
        cross_contract_paths: Optional[List[Dict[str, Any]]] = None,
    ) -> EconomicRiskReport:
        scored: List[ScoredFinding] = []
        assets = AffectedAssets()
        max_loss = 0.0
        total_loss = 0.0

        for f in findings:
            sf = self._score_finding(f)
            scored.append(sf)
            total_loss += sf.estimated_loss_ton
            if sf.estimated_loss_ton > max_loss:
                max_loss = sf.estimated_loss_ton
            self._accumulate_assets(f, sf.contract_type, assets)

        # Cross-contract paths add their own loss estimates
        fund_paths: List[Dict[str, Any]] = []
        for path in (cross_contract_paths or []):
            finding_type = path.get("finding_type", "")
            if finding_type in ("FUND_DRAIN", "OWNERSHIP_TAKEOVER", "REENTRANCY",
                                "JETTON_ABUSE", "GOVERNANCE_ATTACK"):
                path_loss = _SEVERITY_BASE.get(path.get("risk", "HIGH"), 5_000.0) * 2.0
                total_loss += path_loss
                max_loss = max(max_loss, path_loss)
                fund_paths.append({
                    "path":                path.get("path", []),
                    "attack_type":         finding_type,
                    "risk":                path.get("risk", "HIGH"),
                    "description":         path.get("attack_description", ""),
                    "estimated_loss_ton":  round(path_loss, 2),
                })

        composite = self._composite_score(total_loss)
        risk_class = self._classify(total_loss)

        return EconomicRiskReport(
            total_risk_score=composite,
            max_fund_loss_ton=max_loss,
            total_potential_loss=total_loss,
            affected_assets=assets,
            economic_risk_class=risk_class,
            critical_findings=sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            high_findings=sum(1 for f in findings if f.get("severity") == "HIGH"),
            scored_findings=scored,
            fund_loss_paths=fund_paths,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _score_finding(self, f: Dict[str, Any]) -> ScoredFinding:
        severity = f.get("severity", "INFO").upper()
        cwe = f.get("cwe", f.get("cwe_id", ""))
        file_path = f.get("file", "")
        desc = f.get("description", "")
        contract_type = _infer_contract_type(file_path, desc)

        base = _SEVERITY_BASE.get(severity, 0.0)
        if base == 0.0:
            # INFO findings have no financial impact
            return ScoredFinding(
                rule_id=f.get("rule_id", f.get("id", "UNKNOWN")),
                severity=severity, file=file_path,
                contract_type=contract_type, cwe=cwe,
                description=desc, estimated_loss_ton=0.0,
                blast_radius=0, risk_score=0,
            )
        cwe_mult = _CWE_MULTIPLIER.get(cwe, 1.0)
        type_impact = _CONTRACT_TYPE_IMPACT.get(contract_type, 2_000.0)
        # Estimated loss: weighted average of severity-base and contract-type impact
        estimated_loss = (base * cwe_mult * 0.4 + type_impact * 0.6) * cwe_mult
        blast = _BLAST_RADIUS.get(contract_type, 50)

        # Risk score 0–100 (log scale)
        if estimated_loss <= 0:
            risk_score = 0
        else:
            risk_score = min(100, int(math.log10(max(1.0, estimated_loss)) / 6.0 * 100))

        return ScoredFinding(
            rule_id=f.get("rule_id", f.get("id", "UNKNOWN")),
            severity=severity,
            file=file_path,
            contract_type=contract_type,
            cwe=cwe,
            description=desc,
            estimated_loss_ton=estimated_loss,
            blast_radius=blast,
            risk_score=risk_score,
        )

    def _accumulate_assets(
        self, f: Dict[str, Any], contract_type: str, assets: AffectedAssets
    ) -> None:
        fp = f.get("file", "")
        if not fp:
            return
        if contract_type == "wallet" and fp not in assets.wallets:
            assets.wallets.append(fp)
        elif contract_type in ("jetton_master", "jetton_wallet") and fp not in assets.jettons:
            assets.jettons.append(fp)
        elif contract_type == "nft_collection" and fp not in assets.nfts:
            assets.nfts.append(fp)
        elif fp not in assets.contracts:
            assets.contracts.append(fp)

    @staticmethod
    def _composite_score(total_loss: float) -> int:
        if total_loss <= 0:
            return 0
        return min(100, int(math.log10(max(1.0, total_loss)) * 14))

    @staticmethod
    def _classify(total_loss: float) -> EconomicRiskClass:
        if total_loss >= 1_000_000:
            return EconomicRiskClass.CATASTROPHIC
        if total_loss >= 100_000:
            return EconomicRiskClass.CRITICAL
        if total_loss >= 10_000:
            return EconomicRiskClass.HIGH
        if total_loss >= 1_000:
            return EconomicRiskClass.MEDIUM
        return EconomicRiskClass.LOW


def _infer_contract_type(file_path: str, description: str) -> str:
    name = (file_path + " " + description).lower()
    if "treasury" in name:                               return "treasury"
    if "bridge" in name:                                 return "bridge"
    if "multisig" in name or "multi_sig" in name:        return "multisig"
    if "dao" in name:                                    return "dao"
    if "jetton_master" in name or "jetton-master" in name: return "jetton_master"
    if "jetton_wallet" in name or "jetton-wallet" in name: return "jetton_wallet"
    if "jetton" in name:                                 return "jetton_master"
    if "nft_collection" in name or "collection" in name: return "nft_collection"
    if "defi" in name or "pool" in name or "swap" in name: return "defi"
    if "proxy" in name:                                  return "proxy"
    if "lockup" in name or "vesting" in name:            return "lockup"
    if "wallet" in name:                                 return "wallet"
    return "unknown"
