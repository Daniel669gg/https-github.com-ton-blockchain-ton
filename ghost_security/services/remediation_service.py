"""
services/remediation_service.py — Application service for remediation and triage.

Centralises patch generation, findings triage, and fix validation so route
handlers don't instantiate domain objects directly.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


class RemediationService:
    """
    Application service wrapping patch generation and triage logic.
    """

    # ------------------------------------------------------------------
    # Patch generation
    # ------------------------------------------------------------------

    def patch_findings(
        self, findings: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Generate patches for a list of findings.

        Returns ``(patched_findings, patches_generated_count)``.
        """
        from core.remediation.patch_generator import PatchGenerator
        gen = PatchGenerator()
        patched, count = gen.patch_all(list(findings))
        return patched, count

    # ------------------------------------------------------------------
    # Triage
    # ------------------------------------------------------------------

    def triage(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Triage, deduplicate, and score a list of findings.

        Returns a triage result dict with ``findings``, ``duplicates_removed``,
        and ``severity_counts`` keys.
        """
        from core.security.findings_triage import FindingsTriage
        return FindingsTriage().triage(list(findings))

    # ------------------------------------------------------------------
    # Risk profiling
    # ------------------------------------------------------------------

    def profile_repository(self, path: str) -> Dict[str, Any]:
        """Return a risk heatmap and profile for a repository path."""
        from core.analysis.repository_risk_profiler import RepositoryRiskProfiler
        return RepositoryRiskProfiler().profile(path)

    # ------------------------------------------------------------------
    # Taint analysis
    # ------------------------------------------------------------------

    def taint_scan(
        self,
        *,
        code: str = "",
        path: str = "",
    ) -> Dict[str, Any]:
        """
        Run taint/dataflow analysis on a code string or file path.

        Pass either ``code`` (string) or ``path`` (file path), not both.
        """
        from core.analysis.taint_tracker import TaintTracker
        tracker = TaintTracker()
        if code:
            findings = tracker.analyze_code(code, "<snippet>")
        elif path:
            findings = tracker.analyze_file(path)
        else:
            raise ValueError("Provide 'code' or 'path'")

        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "HIGH")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        return {
            "findings":        findings,
            "total":           len(findings),
            "severity_counts": sev_counts,
        }
