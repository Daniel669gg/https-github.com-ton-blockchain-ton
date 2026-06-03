# TythanAI Security Platform — Community Edition
# Copyright (c) 2026 TythanAI Labs
# Licensed under the Business Source License 1.1 (see LICENSE).

"""
community/scanner.py — Community-edition scan orchestrator.

Runs the free-tier pipeline: SAST (Semgrep + custom rules up to limit),
SCA (OSV.dev), secrets, IaC basics, and Web3 basics (TON/Solana/CosmWasm/
Solidity). Premium feature calls return GatedResult objects.
"""
from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from community.gates import (
    COMMUNITY_LIMITS,
    GatedResult,
    PREMIUM_FEATURES,
    gate,
)

logger = logging.getLogger("tythanai.community")


# ─── Result containers ────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    target: str
    sast_findings:    List[dict] = field(default_factory=list)
    sca_findings:     List[dict] = field(default_factory=list)
    secrets_findings: List[dict] = field(default_factory=list)
    iac_findings:     List[dict] = field(default_factory=list)
    web3_findings:    List[dict] = field(default_factory=list)
    gated_features:   List[GatedResult] = field(default_factory=list)
    errors:           List[str] = field(default_factory=list)

    # ── Convenience ───────────────────────────────────────────────────────────

    @property
    def all_findings(self) -> List[dict]:
        return (
            self.sast_findings
            + self.sca_findings
            + self.secrets_findings
            + self.iac_findings
            + self.web3_findings
        )

    @property
    def total(self) -> int:
        return len(self.all_findings)

    @property
    def by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        }
        for f in self.all_findings:
            sev = f.get("severity", "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def risk_score(self) -> int:
        weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
        return min(100, sum(
            weights.get(f.get("severity", "INFO").upper(), 0)
            for f in self.all_findings
        ))

    def risk_level(self) -> str:
        s = self.risk_score()
        if s >= 60:   return "CRITICAL"
        if s >= 30:   return "HIGH"
        if s >= 10:   return "MEDIUM"
        if s > 0:     return "LOW"
        return "CLEAN"


# ─── Community Scanner ────────────────────────────────────────────────────────

class CommunityScanner:
    """
    Orchestrates the community-edition scan pipeline.
    Never raises on partial failures — errors are recorded in result.errors.
    """

    def __init__(self, target: str) -> None:
        self.target = str(Path(target).resolve())
        self._result = ScanResult(target=self.target)
        self._limit_files = COMMUNITY_LIMITS["max_files"]

    # ── Public entry point ────────────────────────────────────────────────────

    def run(
        self,
        *,
        sast: bool = True,
        sca: bool = True,
        secrets: bool = True,
        iac: bool = True,
        web3: bool = True,
        # Premium flags — always ignored; kept for API compatibility
        autopr: bool = False,
        dast: bool = False,
        ai_fix: bool = False,
    ) -> ScanResult:

        if sast:
            self._run_sast()
        if sca:
            self._run_sca()
        if secrets:
            self._run_secrets()
        if iac:
            self._run_iac()
        if web3:
            self._run_web3()

        # Always register gated features so the CLI can display the upsell
        self._register_gated_features(autopr=autopr, dast=dast, ai_fix=ai_fix)

        return self._result

    # ── SAST ──────────────────────────────────────────────────────────────────

    def _run_sast(self) -> None:
        try:
            from scanners.semgrep_integration import SemgrepScanner
            scanner = SemgrepScanner()
            result = scanner.scan_directory(
                self.target,
                max_findings=COMMUNITY_LIMITS["max_rules"],
            )
            self._result.sast_findings = [
                _normalise(f, source="sast") for f in _extract(result)
            ]
        except Exception as exc:
            self._result.errors.append(f"SAST: {exc}")
            logger.debug("SAST error: %s", exc, exc_info=True)

    # ── SCA (OSV.dev) ─────────────────────────────────────────────────────────

    def _run_sca(self) -> None:
        try:
            from scanners.osv_scanner import OSVScanner
            scanner = OSVScanner()
            result = scanner.scan_directory(self.target)
            findings = _extract(result)
            # OSV needs network; if it returned nothing, supplement with the
            # offline known-CVE database so the community user still gets value.
            if not findings:
                raise RuntimeError("OSV returned no data (offline?)")
            self._result.sca_findings = [
                _normalise(f, source="sca") for f in findings
            ]
        except Exception:
            # Fallback: built-in offline dependency_scanner
            try:
                from scanners.dependency_scanner import DependencyScanner
                scanner2 = DependencyScanner()
                result2 = scanner2.scan_directory(self.target)
                self._result.sca_findings = [
                    _normalise(f, source="sca") for f in _extract(result2)
                ]
            except Exception as exc2:
                self._result.errors.append(f"SCA: {exc2}")
                logger.debug("SCA error: %s", exc2, exc_info=True)

    # ── Secrets ───────────────────────────────────────────────────────────────

    def _run_secrets(self) -> None:
        try:
            from scanners.secret_scanner.secret_detector import SecretDetector
            detector = SecretDetector()
            result = detector.scan_directory(self.target)
            self._result.secrets_findings = [
                _normalise(f, source="secrets") for f in _extract(result)
            ]
        except Exception as exc:
            self._result.errors.append(f"Secrets: {exc}")
            logger.debug("Secrets error: %s", exc, exc_info=True)

    # ── IaC ───────────────────────────────────────────────────────────────────

    def _run_iac(self) -> None:
        try:
            from backend.scanners.iac_scanner import IaCScanner
            scanner = IaCScanner()
            result = scanner.scan_directory(self.target)
            self._result.iac_findings = [
                _normalise(f, source="iac") for f in _extract(result)
            ]
        except Exception as exc:
            self._result.errors.append(f"IaC: {exc}")
            logger.debug("IaC error: %s", exc, exc_info=True)

    # ── Web3 basics ───────────────────────────────────────────────────────────

    def _run_web3(self) -> None:
        rule_cap = COMMUNITY_LIMITS["web3_rules_per_chain"]
        findings: List[dict] = []

        # TON (FunC / Tolk)
        try:
            from blockchain.smart_contract_auditor import SmartContractAuditor
            auditor = SmartContractAuditor()
            ton = [
                _normalise(f, source="web3:ton")
                for f in _extract(auditor.audit_directory(self.target))
            ]
            findings.extend(ton[: rule_cap * 2])  # TON is the wedge — show more
        except Exception as exc:
            self._result.errors.append(f"Web3/TON: {exc}")

        # Solidity (EVM)
        try:
            from scanners.solidity_scanner import SolidityScanner
            scanner = SolidityScanner()
            sol = [
                _normalise(f, source="web3:solidity")
                for f in _extract(scanner.scan_directory(self.target))
            ]
            findings.extend(sol[:rule_cap])
        except Exception as exc:
            self._result.errors.append(f"Web3/Solidity: {exc}")

        # Solana + CosmWasm (one auditor, findings carry a `chain` field)
        try:
            from blockchain.multichain_auditor import MultiChainAuditor
            auditor = MultiChainAuditor()
            raw = _extract(auditor.audit_directory(self.target))
            per_chain: Dict[str, int] = {}
            for f in raw:
                chain = str(f.get("chain", "MULTICHAIN")).upper()
                if per_chain.get(chain, 0) >= rule_cap:
                    continue
                per_chain[chain] = per_chain.get(chain, 0) + 1
                findings.append(_normalise(f, source=f"web3:{chain.lower()}"))
        except Exception as exc:
            self._result.errors.append(f"Web3/MultiChain: {exc}")

        self._result.web3_findings = findings

    # ── Gated feature registration ────────────────────────────────────────────

    def _register_gated_features(
        self,
        autopr: bool,
        dast: bool,
        ai_fix: bool,
    ) -> None:
        always_gated = [
            "cpg_taint", "ai_fix", "rules_marketplace", "saas_dashboard",
            "webhooks", "economic_risk", "sbom_compliance", "full_ruleset",
            "multi_agent",
        ]
        for key in always_gated:
            self._result.gated_features.append(gate(key))

        # Explicitly requested but gated
        if autopr:
            self._result.gated_features.append(gate("autopr"))
        if dast:
            self._result.gated_features.append(gate("dast"))


# ─── Extraction + normalisation helpers ───────────────────────────────────────

def _extract(result: Any) -> List[Any]:
    """
    Pull the findings list out of a scanner result, which may be either a
    bare list or a dict with a "findings" key. Always returns a list.
    """
    if result is None:
        return []
    if isinstance(result, dict):
        return list(result.get("findings", []) or [])
    if isinstance(result, (list, tuple)):
        return list(result)
    return []


# Common alternative severity field names used across the bundled scanners.
_SEV_KEYS = ("severity", "sev", "level", "severity_level")
_TITLE_KEYS = ("title", "message", "desc", "description", "name")
_VALID_SEV = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _normalise(finding: Any, source: str) -> dict:
    """Ensure every finding is a plain dict with required, canonical keys."""
    if hasattr(finding, "to_dict"):
        d = finding.to_dict()
    elif isinstance(finding, dict):
        d = dict(finding)
    else:
        d = {"raw": str(finding)}

    # Canonical severity — map sev/level/etc. and normalise casing.
    sev = "INFO"
    for k in _SEV_KEYS:
        v = d.get(k)
        if v:
            sev = str(v).upper()
            break
    d["severity"] = sev if sev in _VALID_SEV else "INFO"

    # Canonical title — first non-empty of the known title keys.
    if not d.get("title"):
        for k in _TITLE_KEYS:
            v = d.get(k)
            if v:
                d["title"] = str(v)
                break
        else:
            d["title"] = d.get("rule_id", d.get("cve", "Finding"))

    d.setdefault("source", source)
    return d
