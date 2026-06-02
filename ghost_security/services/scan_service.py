"""
services/scan_service.py — Application service for all security scanning.

Centralises scan orchestration so API routes and CLI commands share
identical business logic.  All scanner configuration and result
post-processing happens here; callers receive plain dicts.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


class ScanService:
    """
    Application-level scanning service.

    Wraps :class:`backend.core.engine.unified_scan_engine.UnifiedScanEngine`
    and exposes a clean interface for route handlers, CLI commands, and tests.
    """

    def __init__(
        self,
        enable_semgrep: bool = True,
        enable_osv:     bool = True,
        enable_epss:    bool = True,
        enable_ast:     bool = True,
        enable_secrets: bool = True,
        enable_owasp:   bool = True,
        max_findings:   int  = 500,
        timeout_s:      int  = 120,
    ) -> None:
        from backend.core.engine.unified_scan_engine import UnifiedScanEngine, ScanOptions
        opts = ScanOptions(
            enable_semgrep=enable_semgrep,
            enable_osv=enable_osv,
            enable_epss=enable_epss,
            enable_ast=enable_ast,
            enable_secrets=enable_secrets,
            enable_owasp=enable_owasp,
            max_findings=max_findings,
            timeout_s=timeout_s,
        )
        self._engine = UnifiedScanEngine(opts)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_path(self, path: str) -> Dict[str, Any]:
        """Scan a file or directory. Returns serialisable result dict."""
        result = self._engine.scan(path)
        return result.to_dict()

    def scan_code(
        self,
        code: str,
        language: str = "python",
        filename: str = "stdin",
    ) -> Dict[str, Any]:
        """Scan an in-memory code string."""
        result = self._engine.scan_code(code, language=language, filename=filename)
        return result.to_dict()

    def quick_scan(self, path: str) -> Dict[str, Any]:
        """Fast secrets + AST scan, no Semgrep/OSV/EPSS."""
        result = self._engine.quick_scan(path)
        return result.to_dict()

    def filter_by_severity(
        self,
        result: Dict[str, Any],
        min_severity: str = "HIGH",
    ) -> List[Dict[str, Any]]:
        """Return only findings at or above *min_severity*."""
        _RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        threshold = _RANK.get(min_severity.upper(), 0)
        return [
            f for f in result.get("findings", [])
            if _RANK.get(str(f.get("severity", "")).upper(), 0) >= threshold
        ]

    def summary(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Return a compact summary dict suitable for CI/CD step outputs."""
        return {
            "total_findings":   result.get("total_findings", 0),
            "severity_counts":  result.get("severity_counts", {}),
            "risk_score":       result.get("risk_score", 0),
            "risk_level":       result.get("risk_level", "LOW"),
            "scan_duration_s":  result.get("scan_duration_s", 0),
            "scanners_used":    result.get("scanners_used", []),
            "scanner_errors":   result.get("scanner_errors", []),
        }
