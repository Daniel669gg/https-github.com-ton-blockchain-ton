"""
TythanAI Phase 8 — TON Security Dashboard

Aggregates results from all Phase 8 TON analysis components into a
unified security dashboard:
  - Critical contracts (with vulnerability summary)
  - Attack paths (from cross-contract analyzer)
  - Exploitable contracts (by risk level)
  - Economic impact summary
  - Privileged actors and upgrade risks
  - Attack graph summary

Works as a pure aggregator — no analysis of its own. Consumes outputs
from TonAnalyzer, CrossContractAnalyzer, EconomicRiskScorer,
BlockchainSBOMBuilder, and AttackGraphBuilder.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ContractSummary:
    name:           str
    file:           str
    contract_type:  str
    risk_level:     str
    finding_count:  int
    critical_count: int
    high_count:     int
    upgrade_path:   bool
    privileged_actors: List[str]
    top_findings:   List[str]       # rule IDs of most severe findings

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name":              self.name,
            "file":              self.file,
            "contract_type":     self.contract_type,
            "risk_level":        self.risk_level,
            "finding_count":     self.finding_count,
            "critical_count":    self.critical_count,
            "high_count":        self.high_count,
            "upgrade_path":      self.upgrade_path,
            "privileged_actors": self.privileged_actors,
            "top_findings":      self.top_findings,
        }


@dataclass
class AttackPathSummary:
    path_type:    str       # FUND_DRAIN, OWNERSHIP_TAKEOVER, REENTRANCY, etc.
    contracts:    List[str]
    risk:         str
    description:  str
    estimated_loss_ton: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_type":          self.path_type,
            "contracts":          self.contracts,
            "risk":               self.risk,
            "description":        self.description,
            "estimated_loss_ton": round(self.estimated_loss_ton, 2),
        }


@dataclass
class PrivilegedActorEntry:
    address:      str
    role:         str           # "owner", "admin", "manager", "unknown"
    contracts:    List[str]     # contracts this actor controls
    risk:         str           # risk if compromised

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address":   self.address,
            "role":      self.role,
            "contracts": self.contracts,
            "risk":      self.risk,
        }


@dataclass
class DashboardReport:
    project_name:       str
    scan_timestamp:     str
    total_contracts:    int
    critical_contracts: List[ContractSummary]
    high_contracts:     List[ContractSummary]
    attack_paths:       List[AttackPathSummary]
    exploitable_contracts: List[ContractSummary]
    economic_impact:    Dict[str, Any]
    privileged_actors:  List[PrivilegedActorEntry]
    upgrade_risks:      List[Dict[str, Any]]
    findings_summary:   Dict[str, int]          # severity → count
    coverage:           Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_name":       self.project_name,
            "scan_timestamp":     self.scan_timestamp,
            "total_contracts":    self.total_contracts,
            "findings_summary":   self.findings_summary,
            "economic_impact":    self.economic_impact,
            "critical_contracts": [c.to_dict() for c in self.critical_contracts],
            "high_contracts":     [c.to_dict() for c in self.high_contracts],
            "attack_paths":       [a.to_dict() for a in self.attack_paths],
            "exploitable_contracts": [c.to_dict() for c in self.exploitable_contracts],
            "privileged_actors":  [p.to_dict() for p in self.privileged_actors],
            "upgrade_risks":      self.upgrade_risks,
            "coverage":           self.coverage,
        }

    def text_report(self) -> str:
        """Generate human-readable text dashboard."""
        lines = [
            "=" * 70,
            f"TON SECURITY DASHBOARD — {self.project_name}",
            f"Scan: {self.scan_timestamp}",
            "=" * 70,
            "",
            f"CONTRACTS ANALYZED: {self.total_contracts}",
            f"CRITICAL: {self.findings_summary.get('CRITICAL', 0)}  "
            f"HIGH: {self.findings_summary.get('HIGH', 0)}  "
            f"MEDIUM: {self.findings_summary.get('MEDIUM', 0)}  "
            f"LOW: {self.findings_summary.get('LOW', 0)}",
            "",
        ]

        if self.economic_impact:
            ec = self.economic_impact
            lines += [
                "ECONOMIC RISK",
                f"  Risk Class:        {ec.get('economic_risk_class', 'UNKNOWN')}",
                f"  Max Fund Loss:     {ec.get('max_fund_loss_ton', 0):.0f} TON",
                f"  Total Potential:   {ec.get('total_potential_loss', 0):.0f} TON",
                f"  Affected Assets:   {ec.get('affected_assets', {}).get('total', 0)}",
                "",
            ]

        if self.critical_contracts:
            lines.append(f"CRITICAL CONTRACTS ({len(self.critical_contracts)}):")
            for c in self.critical_contracts[:5]:
                lines.append(
                    f"  [{c.risk_level}] {c.name} ({c.contract_type}) "
                    f"— {c.finding_count} findings"
                    + (" [UPGRADEABLE]" if c.upgrade_path else "")
                )
            lines.append("")

        if self.attack_paths:
            lines.append(f"ATTACK PATHS ({len(self.attack_paths)}):")
            for path in self.attack_paths[:5]:
                contracts_str = " → ".join(path.contracts[:4])
                lines.append(
                    f"  [{path.risk}] {path.path_type}: {contracts_str}"
                    + (f" (~{path.estimated_loss_ton:.0f} TON)" if path.estimated_loss_ton else "")
                )
            lines.append("")

        if self.privileged_actors:
            lines.append(f"PRIVILEGED ACTORS ({len(self.privileged_actors)}):")
            for actor in self.privileged_actors[:5]:
                lines.append(
                    f"  [{actor.role.upper()}] {actor.address[:20]}... "
                    f"controls {len(actor.contracts)} contract(s)"
                )
            lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)


class TONSecurityDashboard:
    """
    Aggregates Phase 8 analysis results into a unified TON security dashboard.
    """

    def generate(
        self,
        findings:           List[Dict[str, Any]],
        sbom:               Optional[Any] = None,      # BlockchainSBOM
        economic_report:    Optional[Any] = None,      # EconomicRiskReport
        cross_contract:     Optional[Any] = None,      # CrossContractResult
        attack_graph:       Optional[Any] = None,      # AttackGraph
        project_name:       str = "TON Project",
        scan_timestamp:     str = "",
    ) -> DashboardReport:
        import datetime
        ts = scan_timestamp or datetime.datetime.utcnow().isoformat() + "Z"

        # 1. Aggregate contracts from SBOM
        contracts = self._extract_contract_summaries(findings, sbom)
        critical_contracts = [c for c in contracts if c.risk_level == "CRITICAL"]
        high_contracts     = [c for c in contracts if c.risk_level == "HIGH"]
        exploitable        = [c for c in contracts if c.risk_level in ("CRITICAL", "HIGH")]

        # 2. Attack paths from cross-contract result
        attack_paths = self._extract_attack_paths(cross_contract, economic_report)

        # 3. Economic impact summary
        economic_impact = {}
        if economic_report is not None:
            economic_impact = economic_report.to_dict() if hasattr(economic_report, "to_dict") else {}

        # 4. Privileged actors
        priv_actors = self._extract_privileged_actors(sbom)

        # 5. Upgrade risks
        upgrade_risks = self._extract_upgrade_risks(sbom, findings)

        # 6. Findings summary
        counts: Dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        }
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1

        # 7. Coverage
        total_contracts = sbom.total_contracts if sbom else len(
            {f.get("file", "") for f in findings if f.get("file")}
        )
        coverage = {
            "total_contracts":    total_contracts,
            "contracts_with_findings": len({f.get("file", "") for f in findings if f.get("file")}),
            "rules_fired":        len({f.get("rule_id", f.get("id", "")) for f in findings}),
            "attack_paths_found": len(attack_paths),
        }

        return DashboardReport(
            project_name=project_name,
            scan_timestamp=ts,
            total_contracts=total_contracts,
            critical_contracts=critical_contracts,
            high_contracts=high_contracts,
            attack_paths=attack_paths,
            exploitable_contracts=exploitable,
            economic_impact=economic_impact,
            privileged_actors=priv_actors,
            upgrade_risks=upgrade_risks,
            findings_summary=counts,
            coverage=coverage,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_contract_summaries(
        self,
        findings: List[Dict[str, Any]],
        sbom: Optional[Any],
    ) -> List[ContractSummary]:
        # Group findings by file
        by_file: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            fp = f.get("file", "unknown")
            by_file.setdefault(fp, []).append(f)

        summaries: List[ContractSummary] = []
        sbom_entries: Dict[str, Any] = {}
        if sbom and hasattr(sbom, "entries"):
            sbom_entries = {e.file: e for e in sbom.entries}

        for file_path, file_findings in by_file.items():
            sbom_entry = sbom_entries.get(file_path)
            name = sbom_entry.name if sbom_entry else file_path.rsplit("/", 1)[-1]
            ctype = sbom_entry.contract_type if sbom_entry else "unknown"
            upgrade = sbom_entry.upgrade_path if sbom_entry else False
            actors = sbom_entry.privileged_actors if sbom_entry else []

            critical = [f for f in file_findings if f.get("severity") == "CRITICAL"]
            high     = [f for f in file_findings if f.get("severity") == "HIGH"]

            if critical:
                risk = "CRITICAL"
            elif high:
                risk = "HIGH"
            elif file_findings:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            top = [
                f.get("rule_id", f.get("id", "?"))
                for f in sorted(
                    file_findings,
                    key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
                        x.get("severity", "LOW"), 0
                    ),
                    reverse=True,
                )[:3]
            ]

            summaries.append(ContractSummary(
                name=name,
                file=file_path,
                contract_type=ctype,
                risk_level=risk,
                finding_count=len(file_findings),
                critical_count=len(critical),
                high_count=len(high),
                upgrade_path=upgrade,
                privileged_actors=actors,
                top_findings=top,
            ))

        return sorted(summaries, key=lambda c: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "SAFE": 0}.get(c.risk_level, 0), reverse=True)

    def _extract_attack_paths(
        self,
        cross_contract: Optional[Any],
        economic_report: Optional[Any],
    ) -> List[AttackPathSummary]:
        paths: List[AttackPathSummary] = []
        if cross_contract is None:
            return paths

        loss_by_type = {}
        if economic_report and hasattr(economic_report, "fund_loss_paths"):
            for p in economic_report.fund_loss_paths:
                k = tuple(p.get("path", []))
                loss_by_type[k] = p.get("estimated_loss_ton", 0.0)

        all_paths = []
        for attr in ("reentrancy_paths", "fund_drain_paths", "ownership_takeover_paths",
                     "jetton_abuse_paths", "governance_attack_paths"):
            for p in getattr(cross_contract, attr, []):
                all_paths.append(p)

        for path_obj in all_paths:
            contracts = getattr(path_obj, "path", [])
            loss = loss_by_type.get(tuple(contracts), 0.0)
            paths.append(AttackPathSummary(
                path_type=getattr(path_obj, "finding_type", "UNKNOWN"),
                contracts=contracts,
                risk=getattr(path_obj, "risk", "HIGH"),
                description=getattr(path_obj, "attack_description", ""),
                estimated_loss_ton=loss,
            ))

        return sorted(paths, key=lambda p: {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}.get(p.risk, 0), reverse=True)

    def _extract_privileged_actors(
        self, sbom: Optional[Any]
    ) -> List[PrivilegedActorEntry]:
        if sbom is None or not hasattr(sbom, "entries"):
            return []

        actor_map: Dict[str, PrivilegedActorEntry] = {}
        for entry in sbom.entries:
            for actor in entry.privileged_actors:
                if actor not in actor_map:
                    risk = "CRITICAL" if entry.upgrade_path else "HIGH"
                    actor_map[actor] = PrivilegedActorEntry(
                        address=actor,
                        role=_infer_actor_role(actor),
                        contracts=[entry.file],
                        risk=risk,
                    )
                else:
                    if entry.file not in actor_map[actor].contracts:
                        actor_map[actor].contracts.append(entry.file)

        return list(actor_map.values())

    def _extract_upgrade_risks(
        self, sbom: Optional[Any], findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        risks: List[Dict[str, Any]] = []
        if sbom and hasattr(sbom, "entries"):
            for entry in sbom.entries:
                if entry.upgrade_path:
                    vuln_count = len([
                        f for f in findings if f.get("file") == entry.file
                    ])
                    risks.append({
                        "contract":       entry.name,
                        "file":           entry.file,
                        "contract_type":  entry.contract_type,
                        "vulnerability_count": vuln_count,
                        "risk":           "CRITICAL" if vuln_count > 0 else "HIGH",
                        "description": (
                            f"Contract {entry.name} has upgrade capability "
                            + ("AND existing vulnerabilities — critical risk." if vuln_count > 0
                               else "— requires multisig + timelock protection.")
                        ),
                    })
        return risks


def _infer_actor_role(address: str) -> str:
    addr_lower = address.lower()
    if "owner" in addr_lower:    return "owner"
    if "admin" in addr_lower:    return "admin"
    if "manager" in addr_lower:  return "manager"
    if "gov" in addr_lower:      return "governor"
    return "unknown"
