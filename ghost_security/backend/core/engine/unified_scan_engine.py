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
from typing import Dict, List, Optional

# Ensure project root is importable
_ENGINE_DIR = Path(__file__).parent
_PROJECT_ROOT = _ENGINE_DIR.parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from backend.core.engine.finding_normalizer import FindingNormalizer, NormalizedFinding

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
        self._ast     = None
        self._semgrep = None
        self._osv     = None
        self._secrets = None
        self._owasp   = None
        self._epss    = None
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

        def _run_scanner(name: str, fn) -> None:
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
