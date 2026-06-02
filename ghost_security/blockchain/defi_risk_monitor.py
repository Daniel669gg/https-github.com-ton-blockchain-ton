"""
TythanAI Phase 10 — DeFi Risk Monitor

Protocol-level risk assessment for DeFi projects on TON and EVM chains.
Extends EconomicRiskScorer (Phase 8) with:
  - TVL concentration risk
  - Liquidity depth scoring
  - Token distribution analysis
  - Anomaly detection (unusual volume, ownership concentration)
  - On-chain data connectors (stubbed for offline use, monkeypatchable for live feeds)

Risk classes:
  CRITICAL  — Immediate fund safety concern
  HIGH      — Elevated protocol risk
  MEDIUM    — Moderate risk, monitor closely
  LOW       — Within acceptable parameters
  SAFE      — No significant risk indicators
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


# ─── Enums & constants ───────────────────────────────────────────────────────

class DeFiRiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    SAFE     = "SAFE"


class DeFiRiskCategory(str, Enum):
    LIQUIDITY    = "LIQUIDITY"
    CONCENTRATION = "CONCENTRATION"
    VOLATILITY   = "VOLATILITY"
    GOVERNANCE   = "GOVERNANCE"
    SMART_CONTRACT = "SMART_CONTRACT"
    ORACLE       = "ORACLE"
    BRIDGE       = "BRIDGE"


# ─── Data models ─────────────────────────────────────────────────────────────

@dataclass
class ProtocolSnapshot:
    """On-chain data snapshot for a DeFi protocol."""
    protocol_name:       str
    chain:               str = "TON"           # TON | ETH | BSC | …
    tvl_usd:             float = 0.0           # Total Value Locked in USD
    daily_volume_usd:    float = 0.0
    token_price_usd:     float = 0.0
    token_supply_total:  float = 0.0
    top10_holder_pct:    float = 0.0           # % held by top 10 wallets
    pool_count:          int = 0
    liquidity_depth_usd: float = 0.0           # 2% price-impact depth
    oracle_type:         str = "unknown"       # chainlink | twap | centralized | none
    has_timelock:        bool = False
    has_multisig:        bool = False
    audit_count:         int = 0
    days_since_launch:   int = 0
    extra:               Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeFiRiskFinding:
    category:    DeFiRiskCategory
    level:       DeFiRiskLevel
    title:       str
    description: str = ""
    metric:      str = ""
    value:       float = 0.0
    threshold:   float = 0.0
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "category":    self.category.value,
            "level":       self.level.value,
            "title":       self.title,
            "description": self.description,
            "metric":      self.metric,
            "value":       self.value,
            "threshold":   self.threshold,
            "remediation": self.remediation,
        }


@dataclass
class DeFiRiskReport:
    protocol_name:  str
    chain:          str
    overall_level:  DeFiRiskLevel
    risk_score:     float          # 0.0 (safe) – 100.0 (critical)
    findings:       List[DeFiRiskFinding] = field(default_factory=list)
    summary:        str = ""

    def to_dict(self) -> dict:
        return {
            "protocol_name": self.protocol_name,
            "chain":         self.chain,
            "overall_level": self.overall_level.value,
            "risk_score":    round(self.risk_score, 2),
            "findings":      [f.to_dict() for f in self.findings],
            "summary":       self.summary,
            "critical_count": sum(1 for f in self.findings if f.level == DeFiRiskLevel.CRITICAL),
            "high_count":    sum(1 for f in self.findings if f.level == DeFiRiskLevel.HIGH),
        }


# ─── On-chain data connector (monkeypatchable stub) ──────────────────────────

def _fetch_protocol_snapshot(protocol_name: str, chain: str = "TON") -> Optional[ProtocolSnapshot]:
    """
    Default stub — returns None (offline mode).
    Replace with a real implementation for live data:

        from ghost_security.blockchain.defi_risk_monitor import _fetch_protocol_snapshot
        import ghost_security.blockchain.defi_risk_monitor as _m
        _m._fetch_protocol_snapshot = my_live_fetcher
    """
    return None


# Allow tests and integrations to override the fetcher
_connector: Callable[[str, str], Optional[ProtocolSnapshot]] = _fetch_protocol_snapshot


# ─── Risk scoring rules ──────────────────────────────────────────────────────

def _check_liquidity(snap: ProtocolSnapshot) -> List[DeFiRiskFinding]:
    findings = []

    # TVL too low for the protocol's activity
    if snap.tvl_usd > 0 and snap.daily_volume_usd > 0:
        vol_tvl_ratio = snap.daily_volume_usd / snap.tvl_usd
        if vol_tvl_ratio > 5.0:
            findings.append(DeFiRiskFinding(
                category=DeFiRiskCategory.LIQUIDITY,
                level=DeFiRiskLevel.HIGH,
                title="Volume/TVL ratio extremely high",
                description=f"Daily volume is {vol_tvl_ratio:.1f}x the TVL. "
                            "This may indicate wash trading or insufficient liquidity reserves.",
                metric="volume_tvl_ratio", value=vol_tvl_ratio, threshold=5.0,
                remediation="Monitor for wash trading patterns; ensure liquidity incentives are sustainable.",
            ))
        elif vol_tvl_ratio > 2.0:
            findings.append(DeFiRiskFinding(
                category=DeFiRiskCategory.LIQUIDITY,
                level=DeFiRiskLevel.MEDIUM,
                title="Elevated volume/TVL ratio",
                description=f"Daily volume is {vol_tvl_ratio:.1f}x the TVL.",
                metric="volume_tvl_ratio", value=vol_tvl_ratio, threshold=2.0,
                remediation="Watch for sudden TVL drops that could cause slippage spikes.",
            ))

    # Low liquidity depth
    if snap.tvl_usd > 10_000 and snap.liquidity_depth_usd > 0:
        depth_ratio = snap.liquidity_depth_usd / snap.tvl_usd
        if depth_ratio < 0.01:
            findings.append(DeFiRiskFinding(
                category=DeFiRiskCategory.LIQUIDITY,
                level=DeFiRiskLevel.HIGH,
                title="Shallow liquidity depth (<1% of TVL)",
                description="A 2%-price-impact trade requires very little capital, "
                            "making the protocol vulnerable to price manipulation.",
                metric="liquidity_depth_ratio", value=depth_ratio, threshold=0.01,
                remediation="Incentivize concentrated liquidity positions or increase liquidity rewards.",
            ))

    return findings


def _check_concentration(snap: ProtocolSnapshot) -> List[DeFiRiskFinding]:
    findings = []
    if snap.top10_holder_pct > 80:
        findings.append(DeFiRiskFinding(
            category=DeFiRiskCategory.CONCENTRATION,
            level=DeFiRiskLevel.CRITICAL,
            title="Extreme token concentration (top 10 hold >80%)",
            description=f"Top 10 wallets hold {snap.top10_holder_pct:.1f}% of supply. "
                        "A coordinated dump would collapse the token price.",
            metric="top10_holder_pct", value=snap.top10_holder_pct, threshold=80.0,
            remediation="Implement vesting schedules; ensure team/VC tokens are locked.",
        ))
    elif snap.top10_holder_pct > 60:
        findings.append(DeFiRiskFinding(
            category=DeFiRiskCategory.CONCENTRATION,
            level=DeFiRiskLevel.HIGH,
            title="High token concentration (top 10 hold >60%)",
            description=f"Top 10 wallets hold {snap.top10_holder_pct:.1f}% of supply.",
            metric="top10_holder_pct", value=snap.top10_holder_pct, threshold=60.0,
            remediation="Improve token distribution; publish lockup schedules publicly.",
        ))
    elif snap.top10_holder_pct > 40:
        findings.append(DeFiRiskFinding(
            category=DeFiRiskCategory.CONCENTRATION,
            level=DeFiRiskLevel.MEDIUM,
            title="Moderate token concentration (top 10 hold >40%)",
            description=f"Top 10 wallets hold {snap.top10_holder_pct:.1f}% of supply.",
            metric="top10_holder_pct", value=snap.top10_holder_pct, threshold=40.0,
            remediation="Monitor for coordinated selling; engage community governance.",
        ))
    return findings


def _check_governance(snap: ProtocolSnapshot) -> List[DeFiRiskFinding]:
    findings = []
    if not snap.has_timelock:
        findings.append(DeFiRiskFinding(
            category=DeFiRiskCategory.GOVERNANCE,
            level=DeFiRiskLevel.HIGH,
            title="No timelock on upgrades",
            description="Contract upgrades can be deployed immediately without delay. "
                        "Users have no time to exit before a malicious upgrade.",
            metric="has_timelock", value=0, threshold=1,
            remediation="Implement a 24-48h timelock on all privileged administrative actions.",
        ))
    if not snap.has_multisig:
        findings.append(DeFiRiskFinding(
            category=DeFiRiskCategory.GOVERNANCE,
            level=DeFiRiskLevel.MEDIUM,
            title="No multisig on admin wallet",
            description="Admin operations are controlled by a single key. "
                        "Key compromise gives full control of the protocol.",
            metric="has_multisig", value=0, threshold=1,
            remediation="Move admin operations to a 3/5 or 4/7 multisig wallet.",
        ))
    if snap.audit_count == 0:
        findings.append(DeFiRiskFinding(
            category=DeFiRiskCategory.SMART_CONTRACT,
            level=DeFiRiskLevel.HIGH,
            title="No formal audit completed",
            description="Protocol has not undergone a third-party security audit.",
            metric="audit_count", value=0, threshold=1,
            remediation="Engage a reputable auditor before TVL exceeds $100K.",
        ))
    return findings


def _check_oracle(snap: ProtocolSnapshot) -> List[DeFiRiskFinding]:
    findings = []
    risky_oracles = {"centralized", "none", "unknown"}
    if snap.oracle_type.lower() in risky_oracles:
        findings.append(DeFiRiskFinding(
            category=DeFiRiskCategory.ORACLE,
            level=DeFiRiskLevel.HIGH,
            title=f"Risky oracle type: {snap.oracle_type}",
            description="Centralized or missing oracles are vulnerable to price manipulation.",
            metric="oracle_type", value=0, threshold=0,
            remediation="Migrate to Chainlink, Pyth, or a TWAP oracle with sufficient observation window.",
        ))
    return findings


def _check_new_protocol(snap: ProtocolSnapshot) -> List[DeFiRiskFinding]:
    findings = []
    if 0 < snap.days_since_launch < 30 and snap.tvl_usd > 100_000:
        findings.append(DeFiRiskFinding(
            category=DeFiRiskCategory.SMART_CONTRACT,
            level=DeFiRiskLevel.MEDIUM,
            title="Protocol launched less than 30 days ago with significant TVL",
            description=f"Protocol is {snap.days_since_launch} days old with "
                        f"${snap.tvl_usd:,.0f} TVL. Undetected issues are more likely in new protocols.",
            metric="days_since_launch", value=snap.days_since_launch, threshold=30,
            remediation="Apply extra caution; consider bug bounty program and gradual TVL caps.",
        ))
    return findings


# ─── Scoring ─────────────────────────────────────────────────────────────────

_LEVEL_WEIGHT = {
    DeFiRiskLevel.CRITICAL: 40.0,
    DeFiRiskLevel.HIGH:     20.0,
    DeFiRiskLevel.MEDIUM:   8.0,
    DeFiRiskLevel.LOW:      2.0,
    DeFiRiskLevel.SAFE:     0.0,
}


def _compute_score(findings: List[DeFiRiskFinding]) -> float:
    raw = sum(_LEVEL_WEIGHT[f.level] for f in findings)
    return min(100.0, raw)


def _overall_level(score: float) -> DeFiRiskLevel:
    if score >= 60:
        return DeFiRiskLevel.CRITICAL
    if score >= 35:
        return DeFiRiskLevel.HIGH
    if score >= 15:
        return DeFiRiskLevel.MEDIUM
    if score > 0:
        return DeFiRiskLevel.LOW
    return DeFiRiskLevel.SAFE


def _build_summary(level: DeFiRiskLevel, findings: List[DeFiRiskFinding], proto: str) -> str:
    crit = sum(1 for f in findings if f.level == DeFiRiskLevel.CRITICAL)
    high = sum(1 for f in findings if f.level == DeFiRiskLevel.HIGH)
    if level == DeFiRiskLevel.SAFE:
        return f"{proto}: No significant risk indicators detected."
    parts = []
    if crit:
        parts.append(f"{crit} critical")
    if high:
        parts.append(f"{high} high")
    count_str = " and ".join(parts) or f"{len(findings)}"
    return f"{proto}: {level.value} risk — {count_str} finding(s). Immediate review recommended."


# ─── DeFiRiskMonitor ─────────────────────────────────────────────────────────

class DeFiRiskMonitor:
    """
    Protocol-level DeFi risk assessment.

    Usage:
        monitor = DeFiRiskMonitor()

        # From a pre-built snapshot
        snap = ProtocolSnapshot(
            protocol_name="MyDEX", chain="TON",
            tvl_usd=500_000, daily_volume_usd=2_000_000,
            top10_holder_pct=75, has_timelock=False,
            has_multisig=False, audit_count=0, oracle_type="none",
        )
        report = monitor.assess(snap)
        print(report.to_dict())

        # Or fetch live (requires connector override)
        report = monitor.assess_by_name("MyDEX", chain="TON")
    """

    def assess(self, snapshot: ProtocolSnapshot) -> DeFiRiskReport:
        findings: List[DeFiRiskFinding] = []
        findings.extend(_check_liquidity(snapshot))
        findings.extend(_check_concentration(snapshot))
        findings.extend(_check_governance(snapshot))
        findings.extend(_check_oracle(snapshot))
        findings.extend(_check_new_protocol(snapshot))

        score   = _compute_score(findings)
        level   = _overall_level(score)
        summary = _build_summary(level, findings, snapshot.protocol_name)

        return DeFiRiskReport(
            protocol_name=snapshot.protocol_name,
            chain=snapshot.chain,
            overall_level=level,
            risk_score=score,
            findings=findings,
            summary=summary,
        )

    def assess_by_name(self, protocol_name: str, chain: str = "TON") -> Optional[DeFiRiskReport]:
        """Fetch live snapshot and assess. Returns None if connector returns no data."""
        snap = _connector(protocol_name, chain)
        if snap is None:
            return None
        return self.assess(snap)

    def batch_assess(self, snapshots: List[ProtocolSnapshot]) -> List[DeFiRiskReport]:
        return [self.assess(s) for s in snapshots]
