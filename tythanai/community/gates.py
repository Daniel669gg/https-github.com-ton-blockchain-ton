# TythanAI Security Platform — Community Edition
# Copyright (c) 2026 TythanAI Labs
# Licensed under the Business Source License 1.1 (see LICENSE).

"""
community/gates.py — Feature gating for community vs premium tiers.

All gated features return a GatedResult instead of raising; callers can
render the gate message and continue the scan.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


UPGRADE_URL = "https://tythanai.io/upgrade"

# Premium feature registry — maps feature_key → description shown to user
PREMIUM_FEATURES: dict[str, str] = {
    "autopr":           "Auto-generate fix Pull Requests for every finding",
    "dast":             "DAST / active web scanning (ZAP-based)",
    "cpg_taint":        "Full CPG taint analysis (Go / Java / Rust)",
    "ai_fix":           "AI-powered fix suggestions (LLM-based)",
    "rules_marketplace":"Community rules marketplace with semantic search",
    "saas_dashboard":   "SaaS usage dashboard & billing API",
    "webhooks":         "Webhook push for CI/CD pipeline integration",
    "economic_risk":    "On-chain economic risk scorer (TON / EVM)",
    "sbom_compliance":  "SBOM compliance scoring (NTIA / SPDX full profile)",
    "p2p_consensus":    "P2P consensus simulation & validator analysis",
    "full_ruleset":     "Full 3 462-rule library (vs 500 in Community)",
    "code_quality_adv": "Advanced code-quality grades (cognitive complexity, A–F)",
    "multi_agent":      "Multi-agent orchestrator (parallel scanner fleet)",
}


@dataclass
class GatedResult:
    """Returned instead of real results when a premium feature is called."""
    feature_key: str
    is_gated: bool = True

    @property
    def title(self) -> str:
        desc = PREMIUM_FEATURES.get(self.feature_key, self.feature_key)
        return f"[PREMIUM] {desc}"

    @property
    def upgrade_message(self) -> str:
        desc = PREMIUM_FEATURES.get(self.feature_key, self.feature_key)
        return (
            f"  🔒  {desc}\n"
            f"      Available in TythanAI Pro/Enterprise → {UPGRADE_URL}"
        )

    def to_dict(self) -> dict:
        return {
            "gated": True,
            "feature": self.feature_key,
            "message": self.upgrade_message.strip(),
            "upgrade_url": UPGRADE_URL,
        }


def gate(feature_key: str) -> GatedResult:
    """Return a GatedResult for a premium feature; never raises."""
    return GatedResult(feature_key=feature_key)


def is_premium(feature_key: str) -> bool:
    """True if the feature is gated in the community edition."""
    return feature_key in PREMIUM_FEATURES


# Community scan limits
COMMUNITY_LIMITS: dict[str, Any] = {
    "max_rules":          500,        # rule cap per scanner
    "max_sca_packages":   300,        # SCA packages checked per scan
    "max_files":          2_000,      # file cap per scan
    "web3_rules_per_chain": 3,        # max Web3 rules shown per chain
    "sarif_max_results":  200,        # SARIF result cap
}
