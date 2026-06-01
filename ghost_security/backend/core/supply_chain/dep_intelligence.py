"""Dependency Intelligence Engine — unified Phase 3 entry point.

Orchestrates:
  - DependencyTaintAnalyzer (existing)
  - ReachableCVEAnalyzer (new)
  - PackageReputationEngine (new)
  - CycloneDXGenerator (existing)
  - VEXGenerator + ReachableVEXGenerator (existing + new)
  - SBOMDiffEngine (new)
  - SecurityKnowledgeGraph integration (Phase 2)
  - AttackGraphBuilder integration (Phase 2)
  - SecurityQueryLanguage integration (Phase 2)
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class DepIntelReport:
    """Aggregated output of the Dependency Intelligence Platform."""

    # ── Metadata ──────────────────────────────────────────────────────────
    timestamp: str = ""
    analysis_time_ms: float = 0.0

    # ── Package counts ────────────────────────────────────────────────────
    total_packages: int = 0
    total_vulnerable: int = 0
    total_reachable_critical: int = 0
    overall_risk_score: float = 0.0      # 0.0-100.0

    # ── Sub-reports ───────────────────────────────────────────────────────
    dep_analysis: Optional[Any] = None          # DependencyAnalysisResult
    reachable_cves: List[Any] = field(default_factory=list)    # List[ReachableCVE]
    package_reputations: List[Any] = field(default_factory=list)  # List[PackageReputation]
    vex_document: Optional[Any] = None          # VEXDocument
    sbom: Optional[Any] = None                  # CycloneDXBOM

    # ── Aggregated risk ───────────────────────────────────────────────────
    top_risks: List[str] = field(default_factory=list)
    suspicious_packages: List[str] = field(default_factory=list)

    # ── Knowledge Graph / Attack Graph ────────────────────────────────────
    kg_nodes_added: int = 0
    attack_paths_found: int = 0
    query_results: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "analysis_time_ms": self.analysis_time_ms,
            "total_packages": self.total_packages,
            "total_vulnerable": self.total_vulnerable,
            "total_reachable_critical": self.total_reachable_critical,
            "overall_risk_score": self.overall_risk_score,
            "top_risks": self.top_risks,
            "suspicious_packages": self.suspicious_packages,
            "kg_nodes_added": self.kg_nodes_added,
            "attack_paths_found": self.attack_paths_found,
            "reachable_cves": [
                rc.to_dict() if hasattr(rc, "to_dict") else str(rc)
                for rc in self.reachable_cves
            ],
            "package_reputations": [
                pr.to_dict() if hasattr(pr, "to_dict") else str(pr)
                for pr in self.package_reputations
            ],
            "query_results": self.query_results,
        }


# ---------------------------------------------------------------------------
# Intelligence engine
# ---------------------------------------------------------------------------


class DepIntelligenceEngine:
    """Unified Dependency Intelligence Platform entry point."""

    def __init__(self) -> None:
        self._dep_taint = _lazy_import_dep_taint()
        self._rep_engine = _lazy_import_rep_engine()
        self._reach_analyzer = _lazy_import_reach_analyzer()

    # ------------------------------------------------------------------
    # Primary analysis APIs
    # ------------------------------------------------------------------

    def analyze(
        self,
        manifest_path: str,
        source_code: str = "",
        cpg: Optional[Any] = None,
        kg: Optional[Any] = None,
        attack_builder: Optional[Any] = None,
        queries: Optional[List[str]] = None,
    ) -> DepIntelReport:
        """Full dependency intelligence analysis starting from a manifest file.

        Parameters
        ----------
        manifest_path : str
            Path to requirements.txt, package.json, pyproject.toml, etc.
        source_code : str
            Optional application source code for reachability analysis.
        cpg : CodePropertyGraph, optional
            If provided, CPG-based path tracing enriches reachability results.
        kg : SecurityKnowledgeGraph, optional
            If provided, dependency findings are added as KG nodes.
        attack_builder : AttackGraphBuilder, optional
            If provided, dependency CVEs are woven into the attack graph.
        queries : list of str, optional
            SGL queries to execute against the CPG (e.g. "find vulnerable_dependency").

        Returns
        -------
        DepIntelReport
        """
        t_start = time.monotonic()
        report = DepIntelReport(timestamp=datetime.now(timezone.utc).isoformat())

        # ── 1. Dependency taint analysis ──────────────────────────────────
        dep_result = None
        if self._dep_taint and manifest_path:
            try:
                dep_result = self._dep_taint.analyze_manifest(
                    manifest_path, source_code=source_code
                )
                report.dep_analysis = dep_result
                report.total_packages = getattr(dep_result, "total_dependencies", 0)
                report.total_vulnerable = getattr(dep_result, "total_vulnerable", 0)
            except Exception as exc:
                logger.warning("DependencyTaintAnalyzer failed: %s", exc)

        # ── 2. Package reputation scoring ─────────────────────────────────
        if self._rep_engine and dep_result:
            packages = self._extract_package_names(dep_result)
            try:
                reputations = self._rep_engine.score_batch(packages)
                report.package_reputations = reputations
                report.suspicious_packages = [
                    r.package_name for r in reputations if r.reputation_score < 65.0
                ]
            except Exception as exc:
                logger.warning("PackageReputationEngine failed: %s", exc)

        # ── 3. Reachable CVE analysis ────────────────────────────────────
        if self._reach_analyzer and dep_result:
            try:
                reach_result = self._reach_analyzer.analyze(
                    dep_result=dep_result, cpg=cpg, source_code=source_code
                )
                report.reachable_cves = reach_result.reachable_cves + reach_result.not_reachable_cves
                report.total_reachable_critical = len(reach_result.reachable_critical)
            except Exception as exc:
                logger.warning("ReachableCVEAnalyzer failed: %s", exc)

        # ── 4. Knowledge Graph integration ───────────────────────────────
        if kg and dep_result:
            report.kg_nodes_added = self._integrate_into_kg(kg, dep_result)

        # ── 5. Attack Graph integration ───────────────────────────────────
        if attack_builder and dep_result:
            report.attack_paths_found = self._integrate_into_attack_graph(
                attack_builder, dep_result
            )

        # ── 6. Security Query Language integration ────────────────────────
        if queries and cpg:
            report.query_results = self._run_queries(queries, cpg)

        # ── 7. Overall risk score ─────────────────────────────────────────
        report.overall_risk_score = self._compute_overall_risk(report)
        report.top_risks = self._collect_top_risks(report)

        report.analysis_time_ms = round((time.monotonic() - t_start) * 1000, 2)
        return report

    def analyze_packages(
        self,
        packages: List[Any],  # List[InstalledPackage]
        source_code: str = "",
        cpg: Optional[Any] = None,
    ) -> DepIntelReport:
        """Analyze a pre-parsed list of InstalledPackage objects."""
        t_start = time.monotonic()
        report = DepIntelReport(timestamp=datetime.now(timezone.utc).isoformat())

        # Build a minimal dep_result-like object from packages
        dep_result = _MockDepResult(packages=packages)
        report.total_packages = len(packages)

        # Package reputation
        if self._rep_engine:
            pkg_names = [getattr(p, "name", "") for p in packages]
            try:
                reputations = self._rep_engine.score_batch(pkg_names)
                report.package_reputations = reputations
                report.suspicious_packages = [
                    r.package_name for r in reputations if r.reputation_score < 65.0
                ]
            except Exception as exc:
                logger.warning("PackageReputationEngine.score_batch failed: %s", exc)

        # Reachable CVE analysis using dep_taint on packages
        if self._reach_analyzer:
            try:
                reach_result = self._reach_analyzer.analyze(
                    dep_result=dep_result, cpg=cpg, source_code=source_code
                )
                report.reachable_cves = reach_result.reachable_cves + reach_result.not_reachable_cves
                report.total_reachable_critical = len(reach_result.reachable_critical)
            except Exception as exc:
                logger.warning("ReachableCVEAnalyzer.analyze failed: %s", exc)

        report.overall_risk_score = self._compute_overall_risk(report)
        report.top_risks = self._collect_top_risks(report)
        report.analysis_time_ms = round((time.monotonic() - t_start) * 1000, 2)
        return report

    # ------------------------------------------------------------------
    # Export helpers
    # ------------------------------------------------------------------

    def generate_sbom(
        self,
        manifest_path: str,
        project_name: str = "unknown",
        output_format: str = "cyclonedx",
    ) -> str:
        """Generate a CycloneDX or SPDX SBOM for the given manifest."""
        try:
            if output_format == "spdx":
                from backend.sbom.spdx import SPDXGenerator
                gen = SPDXGenerator()
                bom = gen.generate(manifest_path=manifest_path, project_name=project_name)
                return gen.to_json(bom)
            else:
                from backend.sbom.cyclonedx import CycloneDXGenerator
                gen = CycloneDXGenerator()
                bom = gen.generate(manifest_path=manifest_path, project_name=project_name)
                self._last_sbom = bom
                return gen.to_json(bom)
        except Exception as exc:
            logger.warning("SBOM generation failed: %s", exc)
            return json.dumps({"error": str(exc)})

    def export_vex(
        self,
        report: DepIntelReport,
        product: str = "application",
    ) -> str:
        """Generate a VEX document from the report, enriched with reachability data."""
        try:
            from backend.sbom.vex import VEXGenerator, VEXStatus, VEXDocument
            from backend.sbom.reachable_vex import ReachableVEXGenerator

            # Build base VEX from dep_analysis
            base_statements = []
            dep_result = report.dep_analysis
            if dep_result:
                from backend.sbom.vex import VEXStatement
                now_iso = datetime.now(timezone.utc).isoformat()
                vuln_pkgs = getattr(dep_result, "vulnerable_packages", []) or []
                for vpkg in vuln_pkgs:
                    for rec in getattr(vpkg, "cve_records", []):
                        cve_id = getattr(rec, "cve_id", "")
                        if cve_id:
                            base_statements.append(
                                VEXStatement(
                                    vulnerability_id=cve_id,
                                    product=product,
                                    status=VEXStatus.AFFECTED,
                                    timestamp=now_iso,
                                )
                            )

            import uuid
            base_vex = VEXDocument(
                id=f"urn:uuid:{uuid.uuid4()}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                statements=base_statements,
            )

            if report.reachable_cves:
                rvg = ReachableVEXGenerator()
                enriched_vex = rvg.generate_from_reachability(base_vex, report.reachable_cves)
                return rvg.to_json(enriched_vex)

            vg = VEXGenerator()
            return vg.to_json(base_vex)

        except Exception as exc:
            logger.warning("VEX export failed: %s", exc)
            return json.dumps({"error": str(exc)})

    def diff_sboms(self, old_json: str, new_json: str) -> Any:
        """Diff two CycloneDX SBOM JSON strings."""
        from backend.sbom.sbom_diff import SBOMDiffEngine
        return SBOMDiffEngine().diff_json(old_json, new_json)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_package_names(dep_result: Any) -> List[str]:
        """Extract package name strings from a DependencyAnalysisResult."""
        names: List[str] = []
        for pkg in getattr(dep_result, "all_packages", []) or []:
            name = getattr(pkg, "name", "")
            if name:
                names.append(name)
        for vpkg in getattr(dep_result, "vulnerable_packages", []) or []:
            name = getattr(vpkg, "package_name", "") or getattr(vpkg, "name", "")
            if name and name not in names:
                names.append(name)
        return names

    @staticmethod
    def _integrate_into_kg(kg: Any, dep_result: Any) -> int:
        """Add dependency vulnerability nodes into the SecurityKnowledgeGraph."""
        nodes_added = 0
        try:
            from backend.analysis.knowledge_graph import (
                KnowledgeGraphBuilder, KGNode, KGNodeType, KGEdge,
            )
            builder = KnowledgeGraphBuilder()
            vuln_pkgs = getattr(dep_result, "vulnerable_packages", []) or []
            for vpkg in vuln_pkgs:
                pkg_name = getattr(vpkg, "package_name", "") or getattr(vpkg, "name", "")
                if not pkg_name:
                    continue
                node = KGNode(
                    node_id=f"dep::{pkg_name}",
                    type=KGNodeType.DEPENDENCY,
                    label=pkg_name,
                    properties={
                        "vulnerable": True,
                        "package_name": pkg_name,
                        "installed_version": getattr(vpkg, "installed_version", ""),
                    },
                )
                builder.add_node(kg, node)
                nodes_added += 1

                # Link to CWE/CVE nodes
                for rec in getattr(vpkg, "cve_records", []):
                    cve_id = getattr(rec, "cve_id", "")
                    if cve_id:
                        cve_node = KGNode(
                            node_id=f"cve::{cve_id}",
                            type=KGNodeType.CWE_NODE,
                            label=cve_id,
                            properties={"severity": getattr(rec, "severity", "UNKNOWN")},
                        )
                        builder.add_node(kg, cve_node)
                        edge = KGEdge(
                            from_id=f"dep::{pkg_name}",
                            to_id=f"cve::{cve_id}",
                            relation="VULNERABLE_TO",
                            weight=1.0,
                        )
                        builder.add_edge(kg, edge)
                        nodes_added += 1
        except Exception as exc:
            logger.debug("KG integration failed: %s", exc)
        return nodes_added

    @staticmethod
    def _integrate_into_attack_graph(attack_builder: Any, dep_result: Any) -> int:
        """Weave dependency CVEs into the attack graph."""
        paths_found = 0
        try:
            vuln_pkgs = getattr(dep_result, "vulnerable_packages", []) or []
            if vuln_pkgs:
                # Trigger a re-build of the attack graph with dep findings
                dep_findings = []
                for vpkg in vuln_pkgs:
                    for rec in getattr(vpkg, "cve_records", []):
                        dep_findings.append(rec)
                if dep_findings:
                    graph = attack_builder.build(dep_findings, [])
                    paths = attack_builder.rank_attack_paths(10, graph)
                    paths_found = len(paths)
        except Exception as exc:
            logger.debug("Attack graph integration failed: %s", exc)
        return paths_found

    @staticmethod
    def _run_queries(queries: List[str], cpg: Any) -> Dict[str, Any]:
        """Execute SGL queries against the CPG."""
        results: Dict[str, Any] = {}
        try:
            from backend.core.cpg.query_engine import SecurityQueryLanguage
            sql = SecurityQueryLanguage(cpg)
            for q in queries:
                try:
                    result = sql.execute(q)
                    results[q] = result.to_dict() if hasattr(result, "to_dict") else str(result)
                except Exception as exc:
                    results[q] = {"error": str(exc)}
        except Exception as exc:
            logger.debug("SGL query execution failed: %s", exc)
        return results

    @staticmethod
    def _compute_overall_risk(report: DepIntelReport) -> float:
        """Compute overall risk score 0-100 from all sub-reports."""
        score = 0.0

        if report.total_vulnerable > 0 and report.total_packages > 0:
            vuln_ratio = report.total_vulnerable / report.total_packages
            score += vuln_ratio * 40.0

        if report.total_reachable_critical > 0:
            score += min(report.total_reachable_critical * 10.0, 40.0)

        suspicious_count = len(report.suspicious_packages)
        if suspicious_count > 0:
            score += min(suspicious_count * 5.0, 20.0)

        return round(min(score, 100.0), 2)

    @staticmethod
    def _collect_top_risks(report: DepIntelReport) -> List[str]:
        """Return a ranked list of top risk descriptions."""
        risks: List[str] = []

        # Reachable critical CVEs
        for rc in report.reachable_cves:
            if getattr(rc, "is_reachable", False) and \
               getattr(rc, "severity", "") in ("CRITICAL", "HIGH"):
                cve = getattr(rc, "cve_id", "")
                pkg = getattr(rc, "package_name", "")
                risks.append(f"Reachable {getattr(rc, 'severity', '')} CVE {cve} in {pkg}")
            if len(risks) >= 5:
                break

        # Suspicious packages
        for pkg in report.suspicious_packages[:3]:
            risks.append(f"Suspicious package: {pkg}")

        return risks[:10]


# ---------------------------------------------------------------------------
# Lazy import helpers (all imports wrapped in try/except for graceful degradation)
# ---------------------------------------------------------------------------


def _lazy_import_dep_taint() -> Optional[Any]:
    try:
        from backend.core.supply_chain.dependency_taint import DependencyTaintAnalyzer
        return DependencyTaintAnalyzer()
    except Exception as exc:
        logger.debug("DependencyTaintAnalyzer import failed: %s", exc)
        return None


def _lazy_import_rep_engine() -> Optional[Any]:
    try:
        from backend.core.supply_chain.package_reputation import PackageReputationEngine
        return PackageReputationEngine()
    except Exception as exc:
        logger.debug("PackageReputationEngine import failed: %s", exc)
        return None


def _lazy_import_reach_analyzer() -> Optional[Any]:
    try:
        from backend.core.supply_chain.reachable_cve import ReachableCVEAnalyzer
        return ReachableCVEAnalyzer()
    except Exception as exc:
        logger.debug("ReachableCVEAnalyzer import failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Minimal mock for analyze_packages()
# ---------------------------------------------------------------------------


class _MockDepResult:
    """Lightweight wrapper around a list of InstalledPackage objects."""

    def __init__(self, packages: List[Any]) -> None:
        self.all_packages = packages
        self.vulnerable_packages = []
        self.total_dependencies = len(packages)
        self.total_vulnerable = 0
        self.total_safe = len(packages)
        self.critical_count = 0
        self.high_count = 0
        self.analysis_errors: List[str] = []
