"""
TythanAI Phase 11 — Unified Scan Orchestrator & Report

Runs ALL active scanners (Phase 1-11) against a target directory and
aggregates results into one structured report + beautiful HTML output.

Usage:
    orch = UnifiedScanOrchestrator()
    report = orch.scan("/path/to/project")
    html = orch.to_html(report)
    Path("report.html").write_text(html)
    Path("report.json").write_text(orch.to_json(report))
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# ─── Result container ─────────────────────────────────────────────────────────

@dataclass
class ScannerResult:
    scanner_name:  str
    enabled:       bool
    findings:      List[dict] = field(default_factory=list)
    error:         Optional[str] = None
    duration_ms:   float = 0.0

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def critical(self) -> int:
        return sum(1 for f in self.findings if f.get("severity") == "CRITICAL")

    @property
    def high(self) -> int:
        return sum(1 for f in self.findings if f.get("severity") == "HIGH")


@dataclass
class UnifiedReport:
    target:         str
    generated_at:   str
    duration_ms:    float
    scanner_results: List[ScannerResult] = field(default_factory=list)
    _all_findings:  List[dict] = field(default_factory=list, repr=False)

    @property
    def all_findings(self) -> List[dict]:
        if not self._all_findings:
            for r in self.scanner_results:
                self._all_findings.extend(r.findings)
        return self._all_findings

    @property
    def total(self) -> int:
        return len(self.all_findings)

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.all_findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @property
    def risk_score(self) -> float:
        weights = {"CRITICAL": 40.0, "HIGH": 15.0, "MEDIUM": 5.0, "LOW": 1.0}
        raw = sum(weights.get(f.get("severity", ""), 0) for f in self.all_findings)
        return round(min(100.0, raw), 1)

    @property
    def risk_level(self) -> str:
        score = self.risk_score
        if score >= 60: return "CRITICAL"
        if score >= 30: return "HIGH"
        if score >= 10: return "MEDIUM"
        if score >  0:  return "LOW"
        return "SAFE"

    def to_dict(self) -> dict:
        sc = self.severity_counts
        return {
            "target":          self.target,
            "generated_at":    self.generated_at,
            "duration_ms":     round(self.duration_ms, 1),
            "total_findings":  self.total,
            "risk_score":      self.risk_score,
            "risk_level":      self.risk_level,
            "severity_counts": sc,
            "critical":        sc.get("CRITICAL", 0),
            "high":            sc.get("HIGH", 0),
            "medium":          sc.get("MEDIUM", 0),
            "low":             sc.get("LOW", 0),
            "scanners": [
                {
                    "name":       r.scanner_name,
                    "enabled":    r.enabled,
                    "findings":   r.total,
                    "critical":   r.critical,
                    "error":      r.error,
                    "duration_ms": round(r.duration_ms, 1),
                }
                for r in self.scanner_results
            ],
            "findings": self.all_findings,
        }


# ─── Scanner runners ──────────────────────────────────────────────────────────

def _run_scanner(name: str, fn) -> ScannerResult:
    t0 = time.time()
    try:
        findings = fn()
        if isinstance(findings, dict):
            findings = findings.get("findings", [])
        if isinstance(findings, list) and findings and hasattr(findings[0], "to_dict"):
            findings = [f.to_dict() for f in findings]
        return ScannerResult(
            scanner_name=name, enabled=True,
            findings=findings or [],
            duration_ms=(time.time() - t0) * 1000,
        )
    except Exception as e:
        return ScannerResult(
            scanner_name=name, enabled=True,
            error=str(e),
            duration_ms=(time.time() - t0) * 1000,
        )


# ─── UnifiedScanOrchestrator ─────────────────────────────────────────────────

class UnifiedScanOrchestrator:
    """
    Runs all TythanAI scanners against a directory and returns a UnifiedReport.

    Scanners included:
      - IaCScanner          (Terraform, CloudFormation, Kubernetes)
      - ContainerScanner    (Dockerfile, docker-compose)
      - SupplyChainScanner  (dependencies, typosquatting, OSV)
      - Web3SupplyChainScanner (Web3-specific packages)
      - SmartContractAuditor   (FunC/Tolk + Solidity)
      - MultiChainAuditor      (Solana, CosmWasm)
      - BlockchainSBOMService  (SBOM generation)
      - TaintAnalyzer          (Python taint analysis)
    """

    def scan(self, target: str, fix_suggestions: bool = True) -> UnifiedReport:
        t0 = time.time()
        target_path = Path(target)
        results: List[ScannerResult] = []

        # IaC Scanner
        try:
            from backend.scanners.iac_scanner import IaCScanner
            results.append(_run_scanner(
                "IaCScanner",
                lambda: IaCScanner().scan_directory(target)
            ))
        except Exception as e:
            results.append(ScannerResult("IaCScanner", True, error=str(e)))

        # Container Scanner
        try:
            from backend.scanners.container_scanner import ContainerScanner
            results.append(_run_scanner(
                "ContainerScanner",
                lambda: ContainerScanner().scan_directory(target)
            ))
        except Exception as e:
            results.append(ScannerResult("ContainerScanner", True, error=str(e)))

        # Supply Chain
        try:
            from backend.scanners.supply_chain import SupplyChainScanner
            results.append(_run_scanner(
                "SupplyChainScanner",
                lambda: SupplyChainScanner().scan(target)
            ))
        except Exception as e:
            results.append(ScannerResult("SupplyChainScanner", True, error=str(e)))

        # Web3 Supply Chain
        try:
            from backend.scanners.web3_supply_chain import Web3SupplyChainScanner
            results.append(_run_scanner(
                "Web3SupplyChainScanner",
                lambda: Web3SupplyChainScanner().scan_directory(target)
            ))
        except Exception as e:
            results.append(ScannerResult("Web3SupplyChainScanner", True, error=str(e)))

        # Smart Contract Auditor (TON + Solidity)
        try:
            from blockchain.smart_contract_auditor import SmartContractAuditor
            results.append(_run_scanner(
                "SmartContractAuditor",
                lambda: SmartContractAuditor().audit_directory(target)
            ))
        except Exception as e:
            results.append(ScannerResult("SmartContractAuditor", True, error=str(e)))

        # Multi-chain Auditor (Solana + CosmWasm)
        try:
            from blockchain.multichain_auditor import MultiChainAuditor
            results.append(_run_scanner(
                "MultiChainAuditor",
                lambda: MultiChainAuditor().audit_directory(target)
            ))
        except Exception as e:
            results.append(ScannerResult("MultiChainAuditor", True, error=str(e)))

        # Python Taint Analyzer
        try:
            from backend.scanners.taint_analyzer import TaintAnalyzer
            results.append(_run_scanner(
                "TaintAnalyzer",
                lambda: TaintAnalyzer().scan_directory(target)
            ))
        except Exception as e:
            results.append(ScannerResult("TaintAnalyzer", True, error=str(e)))

        # SBOM
        try:
            from blockchain.sbom_service import BlockchainSBOMService
            svc = BlockchainSBOMService()
            sbom_report = svc.generate(target)
            results.append(ScannerResult(
                scanner_name="BlockchainSBOMService",
                enabled=True,
                findings=[c.to_dict() for c in sbom_report.components],
                duration_ms=0,
            ))
        except Exception as e:
            results.append(ScannerResult("BlockchainSBOMService", True, error=str(e)))

        # Optionally enrich with fix suggestions
        if fix_suggestions:
            try:
                from core.fix_suggestions import FixSuggestionsEngine
                engine = FixSuggestionsEngine()
                for r in results:
                    r.findings = engine.enrich(r.findings)
            except Exception:
                pass

        report = UnifiedReport(
            target=str(target_path.resolve()),
            generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            duration_ms=(time.time() - t0) * 1000,
            scanner_results=results,
        )
        return report

    # ─── Export ──────────────────────────────────────────────────────────────

    def to_json(self, report: UnifiedReport) -> str:
        return json.dumps(report.to_dict(), indent=2)

    def to_html(self, report: UnifiedReport) -> str:
        try:
            from reports.report_generator import ReportGenerator
            rg = ReportGenerator()
            return rg.generate_html(report.to_dict())
        except Exception:
            return self._fallback_html(report)

    def _fallback_html(self, report: UnifiedReport) -> str:
        sc = report.severity_counts
        rows = ""
        for f in report.all_findings:
            sev = f.get("severity", "INFO")
            color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c",
                     "MEDIUM": "#d97706", "LOW": "#2563eb"}.get(sev, "#6b7280")
            rows += (
                f'<tr><td><span style="color:{color};font-weight:700">{sev}</span></td>'
                f'<td>{f.get("rule_id","")}</td>'
                f'<td>{f.get("message") or f.get("title","")}</td>'
                f'<td>{f.get("file","")}</td></tr>'
            )
        scanner_rows = "".join(
            f'<tr><td>{r.scanner_name}</td><td>{r.total}</td>'
            f'<td style="color:{"#22c55e" if not r.error else "#dc2626"}">'
            f'{"OK" if not r.error else "ERROR"}</td></tr>'
            for r in report.scanner_results
        )
        risk_color = {"CRITICAL": "#dc2626", "HIGH": "#ea580c",
                      "MEDIUM": "#d97706", "LOW": "#2563eb",
                      "SAFE": "#22c55e"}.get(report.risk_level, "#6b7280")
        return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>TythanAI Report — {report.target}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     background:#0a0f1e;color:#f1f5f9;padding:2rem}}
h1{{color:#38bdf8;margin-bottom:1rem}}
h2{{color:#94a3b8;margin:1.5rem 0 .5rem}}
.stat{{display:inline-block;background:#1f2937;border-radius:8px;
       padding:.75rem 1.5rem;margin:.25rem;text-align:center}}
.stat-n{{font-size:2rem;font-weight:800}}
.stat-l{{font-size:.75rem;color:#94a3b8;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;background:#111827;
       border-radius:8px;overflow:hidden;margin-top:.5rem}}
th{{background:#1f2937;padding:.6rem 1rem;text-align:left;
    font-size:.8rem;color:#94a3b8;text-transform:uppercase}}
td{{padding:.6rem 1rem;border-bottom:1px solid #1f2937;font-size:.875rem}}
.badge{{display:inline-block;padding:.2rem .6rem;border-radius:4px;
        font-size:.75rem;font-weight:700;color:#fff}}
@media print{{body{{background:#fff;color:#000}}}}
</style></head><body>
<h1>TythanAI Security Report</h1>
<p style="color:#94a3b8">Target: <strong style="color:#f1f5f9">{report.target}</strong>
 &nbsp;·&nbsp; {report.generated_at}
 &nbsp;·&nbsp; {round(report.duration_ms/1000,1)}s</p>

<h2>Risk Overview</h2>
<div>
  <div class="stat">
    <div class="stat-n" style="color:{risk_color}">{report.risk_score}</div>
    <div class="stat-l">Risk Score</div>
  </div>
  <div class="stat"><div class="stat-n" style="color:{risk_color}">{report.risk_level}</div>
    <div class="stat-l">Risk Level</div></div>
  <div class="stat"><div class="stat-n">{report.total}</div>
    <div class="stat-l">Total Findings</div></div>
  <div class="stat"><div class="stat-n" style="color:#dc2626">{sc.get("CRITICAL",0)}</div>
    <div class="stat-l">Critical</div></div>
  <div class="stat"><div class="stat-n" style="color:#ea580c">{sc.get("HIGH",0)}</div>
    <div class="stat-l">High</div></div>
  <div class="stat"><div class="stat-n" style="color:#d97706">{sc.get("MEDIUM",0)}</div>
    <div class="stat-l">Medium</div></div>
</div>

<h2>Scanners</h2>
<table><tr><th>Scanner</th><th>Findings</th><th>Status</th></tr>
{scanner_rows}</table>

<h2>Findings</h2>
<table>
  <tr><th>Severity</th><th>Rule</th><th>Description</th><th>File</th></tr>
  {rows if rows else '<tr><td colspan="4" style="text-align:center;color:#22c55e">No findings — all clear</td></tr>'}
</table>
</body></html>"""
