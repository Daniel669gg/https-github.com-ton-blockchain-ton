"""
backend/core/engine/unified_scan_engine.py — Unified Real-Time Scan Engine.

The single entry point for all security scanning. Orchestrates:
  1. AST Scanner       — real Python AST vulnerability detection
  2. Semgrep           — 3000+ rules, multi-language SAST
  3. OSV.dev           — real-time CVE/GHSA dependency vulnerability scanning
  4. Secret Scanner    — hardcoded credentials and API keys
  5. OWASP Scanner     — OWASP Top 10 pattern matching
  6. EPSS Enrichment   — adds exploitation probability scores

All scanner errors are caught; partial results are always returned.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Dict, List, Optional

# Ensure project root is importable
_ENGINE_DIR = Path(__file__).parent
_PROJECT_ROOT = _ENGINE_DIR.parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from backend.core.engine.finding_normalizer import FindingNormalizer, NormalizedFinding

if TYPE_CHECKING:
    from scanners.ast_scanner.ast_analyzer import ASTScanner
    from scanners.semgrep_integration import SemgrepScanner
    from scanners.osv_scanner import OSVScanner
    from scanners.secret_scanner.secret_detector import SecretDetector
    from scanners.owasp_scanner import OWASPScanner
    from scanners.epss_enricher import EPSSEnricher

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Language extension mapping
# ---------------------------------------------------------------------------

_EXT_LANG: Dict[str, str] = {
    ".py":   "python",
    ".js":   "javascript",
    ".ts":   "typescript",
    ".jsx":  "javascript",
    ".tsx":  "typescript",
    ".java": "java",
    ".go":   "go",
    ".rb":   "ruby",
    ".php":  "php",
    ".kt":   "kotlin",
    ".cs":   "csharp",
    ".rs":   "rust",
    ".c":    "c",
    ".cpp":  "cpp",
    ".cc":   "cpp",
    ".sh":   "shell",
}

# Severity ranks (highest = most urgent)
_SEV_RANK: Dict[str, int] = {
    "CRITICAL": 5,
    "HIGH":     4,
    "MEDIUM":   3,
    "LOW":      2,
    "INFO":     1,
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ScanOptions:
    enable_semgrep: bool = True
    enable_osv: bool = True
    enable_epss: bool = True
    enable_ast: bool = True
    enable_secrets: bool = True
    enable_owasp: bool = True
    # Phase 7 — DAST options
    enable_dast: bool = False              # master DAST switch
    dast_target_url: str = ""             # live app URL for DAST
    dast_zap_url: str = "http://localhost:8080"
    dast_zap_api_key: str = ""
    dast_openapi_spec: str = ""           # path to OpenAPI spec for API scan
    dast_auth_token: str = ""             # Bearer token for authenticated DAST
    dast_crawl_live: bool = False         # crawl live app for endpoint discovery
    max_findings: int = 500
    timeout_s: int = 120
    languages: List[str] = field(default_factory=list)   # empty = auto-detect
    semgrep_rules: List[str] = field(default_factory=list)  # empty = auto
    severity_filter: List[str] = field(default_factory=list)  # empty = all


@dataclass
class ScanResult:
    target: str
    findings: List[dict]
    severity_counts: Dict[str, int]
    risk_score: int       # 0–100
    risk_level: str       # CRITICAL / HIGH / MEDIUM / LOW
    scan_duration_s: float
    scanners_used: List[str]
    scanner_errors: List[str]
    timestamp: str
    total_files_scanned: int
    total_dependencies_checked: int
    options: dict = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def critical_findings(self) -> List[dict]:
        """Return only CRITICAL severity findings."""
        return [f for f in self.findings if f.get("severity") == "CRITICAL"]

    def high_findings(self) -> List[dict]:
        """Return only HIGH severity findings."""
        return [f for f in self.findings if f.get("severity") == "HIGH"]

    def by_cwe(self, cwe_id: str) -> List[dict]:
        """Return findings with the given CWE ID."""
        return [
            f for f in self.findings
            if f.get("cwe_id", "").upper() == cwe_id.upper()
            or f.get("cwe", "").upper() == cwe_id.upper()
        ]

    def to_dict(self) -> dict:
        return {
            "target":                    self.target,
            "findings":                  self.findings,
            "severity_counts":           self.severity_counts,
            "risk_score":                self.risk_score,
            "risk_level":                self.risk_level,
            "scan_duration_s":           self.scan_duration_s,
            "scanners_used":             self.scanners_used,
            "scanner_errors":            self.scanner_errors,
            "timestamp":                 self.timestamp,
            "total_files_scanned":       self.total_files_scanned,
            "total_dependencies_checked": self.total_dependencies_checked,
            "total_findings":            self.total_findings,
            "options":                   self.options,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)

    def summary(self) -> str:
        c = self.severity_counts
        crit  = c.get("CRITICAL", 0)
        high  = c.get("HIGH",     0)
        med   = c.get("MEDIUM",   0)
        return (
            f"Scan: {crit} critical, {high} high, {med} medium "
            f"in {self.scan_duration_s:.1f}s"
        )


# ---------------------------------------------------------------------------
# UnifiedScanEngine
# ---------------------------------------------------------------------------

class UnifiedScanEngine:
    """
    Top-level scan orchestrator.

    All customers should call :py:meth:`scan` or :py:meth:`scan_code`.
    Every scanner failure is swallowed so partial results are always returned.
    """

    def __init__(self, options: Optional[ScanOptions] = None) -> None:
        self._opts = options or ScanOptions()
        self._normalizer = FindingNormalizer()
        self._load_errors: List[str] = []
        self._ast:     Optional[ASTScanner]    = None
        self._semgrep: Optional[SemgrepScanner] = None
        self._osv:     Optional[OSVScanner]    = None
        self._secrets: Optional[SecretDetector] = None
        self._owasp:   Optional[OWASPScanner]  = None
        self._epss:    Optional[EPSSEnricher]  = None
        self._load_scanners()

    # ------------------------------------------------------------------
    # Scanner loading
    # ------------------------------------------------------------------

    def _load_scanners(self) -> None:
        """Attempt to load every scanner. Failures are recorded, never raised."""
        if self._opts.enable_ast:
            try:
                from scanners.ast_scanner.ast_analyzer import ASTScanner
                self._ast = ASTScanner()
            except (ImportError, ModuleNotFoundError) as exc:
                self._load_errors.append(f"AST scanner load failed: {exc}")

        if self._opts.enable_semgrep:
            try:
                from scanners.semgrep_integration import SemgrepScanner
                self._semgrep = SemgrepScanner()
            except (ImportError, ModuleNotFoundError) as exc:
                self._load_errors.append(f"Semgrep scanner load failed: {exc}")

        if self._opts.enable_osv:
            try:
                from scanners.osv_scanner import OSVScanner
                self._osv = OSVScanner()
            except (ImportError, ModuleNotFoundError) as exc:
                self._load_errors.append(f"OSV scanner load failed: {exc}")

        if self._opts.enable_secrets:
            try:
                from scanners.secret_scanner.secret_detector import SecretDetector
                self._secrets = SecretDetector()
            except (ImportError, ModuleNotFoundError) as exc:
                self._load_errors.append(f"Secret scanner load failed: {exc}")

        if self._opts.enable_owasp:
            try:
                from scanners.owasp_scanner import OWASPScanner
                self._owasp = OWASPScanner()
            except (ImportError, ModuleNotFoundError) as exc:
                self._load_errors.append(f"OWASP scanner load failed: {exc}")

        if self._opts.enable_epss:
            try:
                from scanners.epss_enricher import EPSSEnricher
                self._epss = EPSSEnricher()
            except (ImportError, ModuleNotFoundError) as exc:
                self._load_errors.append(f"EPSS enricher load failed: {exc}")

    # ------------------------------------------------------------------
    # Core public API
    # ------------------------------------------------------------------

    def scan(self, target: str) -> ScanResult:
        """Full scan of a directory or single file."""
        t0 = time.time()
        target_path = Path(target)

        # If a single file is given, treat its parent dir as root for OSV etc.
        if target_path.is_file():
            scan_dir = str(target_path.parent)
        else:
            scan_dir = str(target_path)

        # ── Count files ────────────────────────────────────────────────────
        total_files = self._count_files(target)
        total_deps  = 0  # updated after OSV

        # ── Gather raw findings from all enabled scanners ──────────────────
        all_raw: List[dict] = []
        scanner_errors: List[str] = list(self._load_errors)   # include load errors
        scanners_used: List[str] = []

        def _run_scanner(name: str, fn: Callable[[], dict]) -> None:
            nonlocal total_deps
            try:
                result = fn()
                if not isinstance(result, dict):
                    result = {"findings": result if isinstance(result, list) else []}
                raw_findings = result.get("findings", [])
                if not isinstance(raw_findings, list):
                    raw_findings = []
                normalized = self._normalizer.normalize_batch(raw_findings, name)
                all_raw.extend(normalized)
                scanners_used.append(name)
                # Track dependency count from OSV
                if name == "osv":
                    total_deps = result.get("total_packages", len(raw_findings))
            except Exception as exc:
                scanner_errors.append(f"{name}: {exc}")

        is_single_file = target_path.is_file()

        # AST — handles both file and directory
        if self._opts.enable_ast and self._ast:
            if is_single_file:
                _run_scanner("ast", lambda: {"findings": self._ast.scan_file(target)})
            else:
                _run_scanner("ast", lambda: self._ast.scan_directory(target))

        # Semgrep — works on both file and directory
        if self._opts.enable_semgrep and self._semgrep:
            if self._semgrep.is_available():
                kwargs: dict = {}
                if self._opts.languages:
                    kwargs["languages"] = self._opts.languages
                if self._opts.semgrep_rules:
                    kwargs["rulesets"] = self._opts.semgrep_rules
                kwargs["timeout"] = self._opts.timeout_s
                _run_scanner("semgrep", lambda: self._semgrep.scan_directory(target, **kwargs))
            else:
                scanner_errors.append("semgrep: binary not available")

        # OSV — only on directories (single files have no dependency manifests)
        if self._opts.enable_osv and self._osv and not is_single_file:
            _run_scanner("osv", lambda: self._osv.scan_directory(scan_dir))

        # Secrets — route to scan_file for single files
        if self._opts.enable_secrets and self._secrets:
            if is_single_file:
                _run_scanner("secrets", lambda: {"findings": self._secrets.scan_file(target)})
            else:
                _run_scanner("secrets", lambda: self._secrets.scan_directory(target))

        # OWASP — route to scan_file for single files
        if self._opts.enable_owasp and self._owasp:
            if is_single_file:
                _run_scanner("owasp", lambda: {"findings": self._owasp.scan_file(target)})
            else:
                _run_scanner("owasp", lambda: self._owasp.scan_directory(target))

        # ── Post-processing ────────────────────────────────────────────────
        # Deduplicate
        all_raw = self._normalizer.deduplicate(all_raw)

        # Enrich CWE metadata
        all_raw = self._normalizer.enrich_cwe_data(all_raw)

        # Severity filter
        if self._opts.severity_filter:
            allowed = {s.upper() for s in self._opts.severity_filter}
            all_raw = [f for f in all_raw if f.severity.upper() in allowed]

        # Sort by priority
        all_raw = self._normalizer.sort_by_priority(all_raw)

        # Cap
        all_raw = all_raw[: self._opts.max_findings]

        # Convert to dicts for EPSS enrichment + serialization
        all_dicts = [f.to_dict() for f in all_raw]

        # EPSS enrichment
        if self._opts.enable_epss and self._epss and all_dicts:
            cve_findings = [
                f for f in all_dicts
                if str(f.get("cve", f.get("cve_id", ""))).upper().startswith("CVE-")
            ]
            if cve_findings:
                try:
                    enriched = self._epss.enrich(cve_findings)
                    # Merge EPSS data back by finding_id
                    enriched_map = {e.get("finding_id", ""): e for e in enriched}
                    for fd in all_dicts:
                        fid = fd.get("finding_id", "")
                        if fid in enriched_map:
                            fd.update({
                                k: v
                                for k, v in enriched_map[fid].items()
                                if k in ("epss_score", "epss_percentile",
                                         "cisa_kev", "priority_score", "exploit_status")
                            })
                except Exception as exc:
                    scanner_errors.append(f"epss_enrichment: {exc}")

        # ── Severity counts + risk ─────────────────────────────────────────
        sev_counts: Dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        }
        for fd in all_dicts:
            sev = fd.get("severity", "INFO").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        risk_score = min(
            sev_counts["CRITICAL"] * 25
            + sev_counts["HIGH"]     * 15
            + sev_counts["MEDIUM"]   * 8
            + sev_counts["LOW"]      * 3,
            100,
        )
        if risk_score >= 75:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return ScanResult(
            target=target,
            findings=all_dicts,
            severity_counts=sev_counts,
            risk_score=risk_score,
            risk_level=risk_level,
            scan_duration_s=round(time.time() - t0, 2),
            scanners_used=scanners_used,
            scanner_errors=scanner_errors,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            total_files_scanned=total_files,
            total_dependencies_checked=total_deps,
            options={
                "enable_semgrep": self._opts.enable_semgrep,
                "enable_osv":     self._opts.enable_osv,
                "enable_epss":    self._opts.enable_epss,
                "enable_ast":     self._opts.enable_ast,
                "enable_secrets": self._opts.enable_secrets,
                "enable_owasp":   self._opts.enable_owasp,
                "max_findings":   self._opts.max_findings,
                "severity_filter": self._opts.severity_filter,
            },
        )

    def scan_code(
        self,
        code: str,
        language: str = "python",
        filename: str = "stdin",
    ) -> ScanResult:
        """
        Scan a code string.

        Writes *code* to a temp file, calls :py:meth:`scan`, replaces temp paths
        with *filename* in the returned findings, then deletes the temp file.
        """
        # Choose appropriate extension
        _LANG_EXT: Dict[str, str] = {
            "python":     ".py",
            "javascript": ".js",
            "typescript": ".ts",
            "java":       ".java",
            "go":         ".go",
            "ruby":       ".rb",
            "php":        ".php",
            "c":          ".c",
            "cpp":        ".cpp",
            "rust":       ".rs",
        }
        ext = _LANG_EXT.get(language.lower(), ".py")
        tmp_path: Optional[str] = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=ext, delete=False, encoding="utf-8"
            ) as fh:
                fh.write(code)
                tmp_path = fh.name

            result = self.scan(tmp_path)

            # Replace tmp path with human-friendly filename
            for fd in result.findings:
                for key in ("file_path", "file", "path"):
                    if fd.get(key) == tmp_path:
                        fd[key] = filename

            result.target = filename
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

        return result

    def quick_scan(self, target: str) -> ScanResult:
        """
        Fast scan: secrets + AST only.

        Temporarily disables Semgrep, OSV, and EPSS for speed.
        """
        saved_opts = self._opts
        self._opts = ScanOptions(
            enable_semgrep=False,
            enable_osv=False,
            enable_epss=False,
            enable_ast=True,
            enable_secrets=True,
            enable_owasp=False,
            max_findings=saved_opts.max_findings,
            timeout_s=saved_opts.timeout_s,
            severity_filter=saved_opts.severity_filter,
        )
        try:
            return self.scan(target)
        finally:
            self._opts = saved_opts

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _count_files(self, target: str) -> int:
        """Count source files in *target* (file or directory)."""
        p = Path(target)
        if p.is_file():
            return 1
        skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"}
        count = 0
        try:
            for fp in p.rglob("*"):
                if fp.is_file() and not any(s in fp.parts for s in skip_dirs):
                    if fp.suffix.lower() in _EXT_LANG:
                        count += 1
        except Exception:
            pass
        return count

    # -----------------------------------------------------------------------
    # Phase 7 — DAST integration
    # -----------------------------------------------------------------------

    def run_dast(self, options: Optional["ScanOptions"] = None) -> List[dict]:
        """
        Run the full Phase 7 DAST pipeline against a live application.

        Steps:
          1. API security scan (no ZAP required)
          2. Security headers analysis
          3. OWASP ZAP scan (if ZAP available)
          4. SAST↔DAST correlation

        Returns a list of normalised finding dicts.
        """
        opts    = options or ScanOptions()
        target  = opts.dast_target_url
        if not target:
            logger.warning("DAST scan requested but dast_target_url is not set")
            return []

        dast_raw: List[dict] = []

        # 1. Security headers
        try:
            from scanners.dast.headers_analyzer import SecurityHeadersAnalyzer
            analyzer = SecurityHeadersAnalyzer(timeout=10)
            h_report = analyzer.analyze(target)
            dast_raw += analyzer.to_normalized_findings(h_report)
            logger.info("Headers analyzer: %d findings", len(h_report.findings))
        except Exception as exc:
            logger.debug("Headers analyzer error: %s", exc)

        # 2. Live API scanner
        try:
            from scanners.dast.api_scanner import APIScanner, APIScanConfig
            api_cfg = APIScanConfig(
                base_url=target,
                openapi_spec_path=opts.dast_openapi_spec,
                auth_token=opts.dast_auth_token,
                timeout=10,
            )
            api_result = APIScanner(api_cfg).scan()
            from scanners.dast.api_scanner import APIScanner as _API
            dast_raw += _API(api_cfg).to_normalized_findings(api_result)
            logger.info("API scanner: %d findings", len(api_result.findings))
        except Exception as exc:
            logger.debug("API scanner error: %s", exc)

        # 3. ZAP scan (optional — requires running ZAP daemon)
        zap_available = False
        try:
            from scanners.dast.zap_integration import (
                ZAPScanner, ZAPScanConfig, ScanType, ZAPAuthConfig,
            )
            zap_cfg = ZAPScanConfig(
                target_url=target,
                zap_api_url=opts.dast_zap_url,
                api_key=opts.dast_zap_api_key,
                scan_types=[ScanType.SPIDER, ScanType.PASSIVE, ScanType.ACTIVE],
                openapi_url=(
                    opts.dast_openapi_spec
                    if opts.dast_openapi_spec.startswith("http") else ""
                ),
            )
            zap_scanner = ZAPScanner(zap_cfg)
            ok, _ = zap_scanner.check_zap_available()
            if ok:
                zap_result = zap_scanner.scan()
                dast_raw  += zap_scanner.to_normalized_findings(zap_result)
                zap_available = True
                logger.info("ZAP scanner: %d findings", len(zap_result.findings))
            else:
                logger.info("ZAP not available — skipping ZAP scan")
        except Exception as exc:
            logger.debug("ZAP scanner error: %s", exc)

        # 4. Return normalised findings (normalizer handles dedup)
        normalizer = FindingNormalizer()
        normalised = normalizer.normalize_batch(dast_raw, "dast")
        return [self._normalised_to_dict(n) for n in normalised]

    def scan_with_dast(self, target: str,
                       dast_url: str,
                       options: Optional["ScanOptions"] = None) -> "ScanResult":
        """
        Full scan: SAST on *target* directory + DAST against *dast_url*.

        SAST and DAST findings are merged and correlated.
        """
        opts = options or ScanOptions(
            enable_dast=True,
            dast_target_url=dast_url,
        )

        # SAST phase
        sast_result = self.scan(target)

        # DAST phase
        dast_findings = self.run_dast(opts)

        # Correlation
        correlated_findings: List[dict] = []
        try:
            from core.runtime_correlation import RuntimeCorrelator
            from scanners.dast.attack_surface import AttackSurfaceMapper
            mapper  = AttackSurfaceMapper(
                base_url=dast_url,
                project_root=target,
                crawl_live=opts.dast_crawl_live,
            )
            surface = mapper.map()
            ep_nodes = mapper.to_attack_graph_nodes(surface)

            correlator = RuntimeCorrelator(
                attack_surface_endpoints=ep_nodes,
                sast_findings=sast_result.findings,
                dast_findings=dast_findings,
            )
            corr_report  = correlator.correlate()
            correlated_findings = [cf.to_dict()
                                   for cf in corr_report.correlated_findings]
        except Exception as exc:
            logger.warning("Correlation error: %s", exc)

        merged = sast_result.findings + dast_findings
        normalizer = FindingNormalizer()
        deduped    = normalizer.deduplicate(
            [f if isinstance(f, NormalizedFinding)
             else NormalizedFinding(**{k: v for k, v in f.items()
                                       if k in NormalizedFinding.__dataclass_fields__})
             for f in merged
             if isinstance(f, (dict, NormalizedFinding))]
        )
        deduped_dicts = [self._normalised_to_dict(f)
                         if isinstance(f, NormalizedFinding) else f
                         for f in deduped]

        counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in deduped_dicts:
            s = f.get("severity", "INFO")
            counts[s] = counts.get(s, 0) + 1

        raw_score = (counts["CRITICAL"] * 25 + counts["HIGH"] * 15 +
                     counts["MEDIUM"] * 8 + counts["LOW"] * 3)
        risk_score = min(100, raw_score * 100 // 500 if raw_score else 0)
        risk_level = (
            "CRITICAL" if risk_score >= 75 else
            "HIGH" if risk_score >= 50 else
            "MEDIUM" if risk_score >= 25 else "LOW"
        )

        return ScanResult(
            target=target,
            findings=deduped_dicts,
            severity_counts=counts,
            risk_score=risk_score,
            risk_level=risk_level,
            scan_duration_s=sast_result.scan_duration_s,
            scanners_used=sast_result.scanners_used + (
                ["dast", "api_scanner", "headers_analyzer"] +
                (["zap"] if opts.dast_zap_url else [])
            ),
            scanner_errors=sast_result.scanner_errors,
            timestamp=sast_result.timestamp,
            total_files_scanned=sast_result.total_files_scanned,
            total_dependencies_checked=sast_result.total_dependencies_checked,
            options={
                **sast_result.options,
                "dast_enabled": True,
                "dast_url": dast_url,
                "correlated_findings": correlated_findings,
            },
        )

    @staticmethod
    def _normalised_to_dict(nf: "NormalizedFinding") -> dict:
        if hasattr(nf, "__dict__"):
            return {k: v for k, v in nf.__dict__.items()}
        return {}  # pragma: no cover
