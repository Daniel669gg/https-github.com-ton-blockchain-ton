"""
services/report_service.py — Application service for report generation and export.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, Optional

_ROOT = Path(__file__).parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


class ReportService:
    """Application service for report formatting and multi-format export."""

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------

    def to_html(self, report: Dict[str, Any]) -> str:
        """Render a report dict to an HTML string."""
        from reports.report_generator import ReportGenerator
        return ReportGenerator().generate_html(report)

    # ------------------------------------------------------------------
    # SARIF 2.1.0
    # ------------------------------------------------------------------

    def to_sarif(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Export a report dict to SARIF 2.1.0 format."""
        from reports.sarif_exporter import SARIFExporter
        return SARIFExporter().export(report)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(
        self,
        report: Dict[str, Any],
        output_dir: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> str:
        """
        Save report as JSON.  Returns the path to the saved file.
        """
        import json, time
        reports_dir = Path(output_dir) if output_dir else Path(_ROOT) / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        fname = filename or f"report_{report.get('session_id', int(time.time()))}.json"
        out_path = reports_dir / fname
        out_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        return str(out_path)
