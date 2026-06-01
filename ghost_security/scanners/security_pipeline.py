"""
TythanAI — Unified Security Pipeline v2.2
Runs all available scanners, merges results, applies triage.
"""
import time
from pathlib import Path
from typing import Dict, List, Optional


class SecurityPipeline:
    """
    Orchestrates all static analysis scanners for a given target.
    Returns a unified, triaged, deduplicated findings report.
    """

    def __init__(self):
        self._load_scanners()

    def _load_scanners(self):
        import sys; sys.path.insert(0, str(Path(__file__).parent.parent))
        try:
            from scanners.ast_scanner.ast_analyzer import ASTScanner
            self._ast = ASTScanner()
        except Exception: self._ast = None
        try:
            from scanners.secret_scanner.secret_detector import SecretDetector
            self._secrets = SecretDetector()
        except Exception: self._secrets = None
        try:
            from scanners.ton_scanner.ton_analyzer import TONAnalyzer
            self._ton = TONAnalyzer()
        except Exception: self._ton = None
        try:
            from scanners.owasp_scanner import OWASPScanner
            self._owasp = OWASPScanner()
        except Exception: self._owasp = None
        try:
            from scanners.js_analyzer import JSAnalyzer
            self._js = JSAnalyzer()
        except Exception: self._js = None
        try:
            from scanners.solidity_scanner import SolidityScanner
            self._solidity = SolidityScanner()
        except Exception: self._solidity = None
        try:
            from scanners.dependency_scanner import DependencyScanner
            self._deps = DependencyScanner()
        except Exception: self._deps = None
        try:
            from core.analysis.taint_tracker import TaintTracker
            self._taint = TaintTracker()
        except Exception: self._taint = None
        # ── Phase 6: Real Detection Engine additions ──────────────────────
        try:
            from scanners.semgrep_integration import SemgrepScanner
            self._semgrep = SemgrepScanner()
        except Exception: self._semgrep = None
        try:
            from scanners.osv_scanner import OSVScanner
            self._osv = OSVScanner()
        except Exception: self._osv = None
        try:
            from scanners.epss_enricher import EPSSEnricher
            self._epss = EPSSEnricher()
        except Exception: self._epss = None

    def scan(self, directory: str, mode: str = "all",
             run_triage: bool = True) -> Dict:
        """
        Run all applicable scanners on a directory.
        mode: all | ast | secrets | deps | owasp | ton | js | solidity | taint
        """
        t0 = time.time()
        all_findings: List[Dict] = []
        scanner_log: List[Dict]  = []
        root = Path(directory)

        def _run(name, fn):
            try:
                t = time.time()
                result = fn()
                findings = result.get("findings", result) if isinstance(result, dict) else result
                if isinstance(findings, list):
                    all_findings.extend(findings)
                    scanner_log.append({"scanner": name, "findings": len(findings),
                                        "duration_ms": round((time.time()-t)*1000)})
            except Exception as e:
                scanner_log.append({"scanner": name, "error": str(e)[:80]})

        run_all = mode == "all"

        if (run_all or mode == "secrets") and self._secrets:
            _run("secret_detector", lambda: self._secrets.scan_directory(directory))

        if (run_all or mode == "ast") and self._ast:
            _run("ast_scanner", lambda: self._ast.scan_directory(directory))

        if (run_all or mode == "owasp") and self._owasp:
            _run("owasp_scanner", lambda: self._owasp.scan_directory(directory))

        if (run_all or mode == "js") and self._js:
            _run("js_analyzer", lambda: self._js.scan_directory(directory))

        if (run_all or mode == "solidity") and self._solidity:
            _run("solidity_scanner", lambda: self._solidity.scan_directory(directory))

        if (run_all or mode == "ton") and self._ton:
            _run("ton_analyzer", lambda: self._ton.scan_directory(directory))

        if (run_all or mode == "deps") and self._deps:
            _run("dependency_scanner", lambda: self._deps.scan_directory(directory))

        if (run_all or mode == "semgrep") and self._semgrep and self._semgrep.is_available():
            _run("semgrep", lambda: self._semgrep.scan_directory(directory))

        if (run_all or mode == "osv") and self._osv:
            _run("osv_scanner", lambda: self._osv.scan_directory(directory))

        if (run_all or mode == "taint") and self._taint:
            py_files = list(root.rglob("*.py"))[:50]  # cap for performance
            taint_findings = []
            for f in py_files:
                if not any(s in f.parts for s in ("__pycache__","venv",".venv")):
                    taint_findings.extend(self._taint.analyze_file(str(f)))
            all_findings.extend(taint_findings)
            scanner_log.append({"scanner": "taint_tracker", "findings": len(taint_findings)})

        # Triage + dedup
        if run_triage and all_findings:
            try:
                from core.security.findings_triage import FindingsTriage
                triaged = FindingsTriage().triage(all_findings)
                all_findings = triaged["findings"]
            except Exception:
                pass

        # EPSS enrichment for CVE findings
        if self._epss and all_findings:
            cve_findings = [f for f in all_findings if str(f.get("cve", f.get("id",""))).startswith("CVE-")]
            if cve_findings:
                try:
                    enriched = self._epss.enrich(cve_findings)
                    # Replace enriched findings back
                    cve_ids_enriched = {f.get("cve", f.get("id","")) for f in enriched}
                    all_findings = [f for f in all_findings if not str(f.get("cve", f.get("id",""))).startswith("CVE-")]
                    all_findings.extend(enriched)
                except Exception:
                    pass

        # Count severity
        sev_c: Dict[str,int] = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
        for f in all_findings:
            sev_c[f.get("severity","INFO")] = sev_c.get(f.get("severity","INFO"),0)+1

        risk_score = min(
            sev_c["CRITICAL"]*25 + sev_c["HIGH"]*15 +
            sev_c["MEDIUM"]*8 + sev_c["LOW"]*3, 100)

        return {
            "target":           directory,
            "mode":             mode,
            "timestamp":        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "duration_s":       round(time.time()-t0, 2),
            "total_findings":   len(all_findings),
            "severity_counts":  sev_c,
            "risk_score":       risk_score,
            "risk_level":       ("CRITICAL" if risk_score>=75 else "HIGH"
                                if risk_score>=50 else "MEDIUM" if risk_score>=25 else "LOW"),
            "scanners_run":     scanner_log,
            "findings":         all_findings,
            "recommendations":  self._recommendations(sev_c, all_findings),
            "semgrep_available": self._semgrep.is_available() if self._semgrep else False,
            "osv_online":        self._osv.is_online() if self._osv else False,
        }

    def _recommendations(self, counts: Dict, findings: List[Dict]) -> List[str]:
        recs = []
        if counts["CRITICAL"]:
            recs.append(f"Fix {counts['CRITICAL']} critical finding(s) before any deployment.")
        if counts["HIGH"]:
            recs.append(f"Address {counts['HIGH']} high-severity finding(s) within one sprint.")
        cwes = {f.get("cwe","") for f in findings}
        if "CWE-798" in cwes:
            recs.append("Rotate all exposed credentials immediately — check git history too.")
        if "CWE-89" in cwes:
            recs.append("Use parameterised queries throughout — review all database interactions.")
        if "CWE-78" in cwes or "CWE-95" in cwes:
            recs.append("Remove all shell=True and eval() calls; validate all inputs strictly.")
        if "CWE-918" in cwes:
            recs.append("Validate all user-supplied URLs server-side; block internal IP ranges.")
        if not recs:
            recs.append("No critical issues found — maintain regular scanning in your CI/CD pipeline.")
        return recs
