"""
backend/core/engine/scan_report.py — Unified scan report generator.

Generates SARIF 2.1.0 (for GitHub Code Scanning / CI), Markdown (human readable),
JSON (machine readable), HTML (for dashboard), and CSV (compliance).
"""
from __future__ import annotations

import csv
import html
import io
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, TYPE_CHECKING

if TYPE_CHECKING:
    from backend.core.engine.finding_normalizer import NormalizedFinding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SARIF severity mapping
# ---------------------------------------------------------------------------

_SEVERITY_TO_SARIF: Dict[str, str] = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "INFO":     "none",
}

# ---------------------------------------------------------------------------
# Risk scoring thresholds
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 40,
    "HIGH":     20,
    "MEDIUM":   8,
    "LOW":      3,
    "INFO":     1,
}

# Severity → CSS badge colour
_SEVERITY_CSS: Dict[str, str] = {
    "CRITICAL": "#dc2626",   # red-600
    "HIGH":     "#ea580c",   # orange-600
    "MEDIUM":   "#d97706",   # amber-600
    "LOW":      "#65a30d",   # lime-600
    "INFO":     "#0891b2",   # cyan-600
}


# ---------------------------------------------------------------------------
# ScanReport dataclass
# ---------------------------------------------------------------------------

@dataclass
class ScanReport:
    """Aggregated output of a full scan run."""

    target: str
    timestamp: str                        # ISO 8601
    total_findings: int
    severity_counts: Dict[str, int]
    risk_score: int                        # 0-100
    risk_level: str                        # CRITICAL / HIGH / MEDIUM / LOW
    findings: List[dict]                   # serialised NormalizedFinding dicts
    scanners_used: List[str]
    scan_duration_s: float
    report_version: str = "6.0"


# ---------------------------------------------------------------------------
# ReportGenerator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Converts a list of NormalizedFindings into multiple report formats."""

    def __init__(
        self,
        tool_name: str = "TythanAI",
        tool_version: str = "6.5",
    ) -> None:
        self.tool_name    = tool_name
        self.tool_version = tool_version

    # ------------------------------------------------------------------
    # Primary entry point
    # ------------------------------------------------------------------

    def generate(
        self,
        findings: List["NormalizedFinding"],
        target: str,
        scan_duration_s: float,
        scanners_used: List[str],
    ) -> ScanReport:
        """Build a ScanReport from a list of NormalizedFinding objects."""
        severity_counts: Dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        }
        for f in findings:
            sev = f.severity if f.severity in severity_counts else "INFO"
            severity_counts[sev] += 1

        risk_score = self._compute_risk_score(severity_counts, len(findings))
        risk_level = self._risk_level(risk_score)

        return ScanReport(
            target=target,
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_findings=len(findings),
            severity_counts=severity_counts,
            risk_score=risk_score,
            risk_level=risk_level,
            findings=[f.to_dict() for f in findings],
            scanners_used=list(scanners_used),
            scan_duration_s=scan_duration_s,
        )

    def generate_from_result(self, scan_result: "ScanResult") -> ScanReport:
        """Build a ScanReport directly from a ScanResult (findings are already dicts)."""
        return ScanReport(
            target=scan_result.target,
            timestamp=scan_result.timestamp,
            total_findings=scan_result.total_findings,
            severity_counts=dict(scan_result.severity_counts),
            risk_score=scan_result.risk_score,
            risk_level=scan_result.risk_level,
            findings=list(scan_result.findings),
            scanners_used=list(scan_result.scanners_used),
            scan_duration_s=scan_result.scan_duration_s,
        )

    # ------------------------------------------------------------------
    # SARIF 2.1.0
    # ------------------------------------------------------------------

    def to_sarif(self, report: ScanReport) -> dict:
        """Generate a SARIF 2.1.0 document suitable for GitHub Code Scanning."""
        # Build unique rules list from findings
        rules_seen: Dict[str, dict] = {}
        for f in report.findings:
            rule_id  = f.get("rule_id") or f.get("finding_id", "unknown")
            cwe_id   = f.get("cwe_id", "")
            title    = f.get("title", rule_id)
            desc     = f.get("description", title)
            severity = f.get("severity", "MEDIUM")

            if rule_id not in rules_seen:
                rule_entry: dict = {
                    "id":   rule_id,
                    "name": _slug(title),
                    "shortDescription": {"text": title[:200]},
                    "fullDescription":  {"text": desc[:1000]},
                    "defaultConfiguration": {
                        "level": _SEVERITY_TO_SARIF.get(severity, "warning"),
                    },
                    "properties": {},
                }
                if cwe_id:
                    rule_entry["properties"]["cwe"] = cwe_id
                owasp = f.get("owasp_category", "")
                if owasp:
                    rule_entry["properties"]["owasp"] = owasp
                help_text = f.get("fix_hint", "") or f.get("recommendation", "")
                if help_text:
                    rule_entry["help"] = {"text": help_text}
                rules_seen[rule_id] = rule_entry

        # Build results list
        results: List[dict] = []
        for f in report.findings:
            rule_id   = f.get("rule_id") or f.get("finding_id", "unknown")
            severity  = f.get("severity", "MEDIUM")
            file_path = f.get("file_path", "")
            line      = f.get("line", 1) or 1
            col       = f.get("column", 1) or 1
            message   = f.get("description") or f.get("title", "Security finding")

            result_entry: dict = {
                "ruleId": rule_id,
                "message": {"text": message[:500]},
                "level":   _SEVERITY_TO_SARIF.get(severity, "warning"),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine":   line,
                                "startColumn": col,
                            },
                        }
                    }
                ],
            }
            # Attach tags / CWE as properties
            props: dict = {}
            cwe = f.get("cwe_id", "")
            if cwe:
                props["cwe"] = cwe
            tags = f.get("tags", [])
            if tags:
                props["tags"] = tags
            if props:
                result_entry["properties"] = props

            # Evidence as a related location snippet if available
            evidence = f.get("evidence", "")
            if evidence:
                result_entry["message"]["text"] += f"\n\nEvidence:\n{evidence[:300]}"

            results.append(result_entry)

        sarif: dict = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name":            self.tool_name,
                            "version":         self.tool_version,
                            "informationUri":  "https://github.com/TythanAI/ghost-security",
                            "rules":           list(rules_seen.values()),
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "endTimeUtc": report.timestamp,
                        }
                    ],
                    "properties": {
                        "target":          report.target,
                        "risk_score":      report.risk_score,
                        "risk_level":      report.risk_level,
                        "scan_duration_s": report.scan_duration_s,
                        "scanners_used":   report.scanners_used,
                    },
                }
            ],
        }
        return sarif

    # ------------------------------------------------------------------
    # Markdown
    # ------------------------------------------------------------------

    def to_markdown(self, report: ScanReport) -> str:
        """Human-readable Markdown report."""
        lines: List[str] = [
            f"# {self.tool_name} Security Report",
            "",
            f"**Target:** `{report.target}`  ",
            f"**Scan Date:** {report.timestamp}  ",
            f"**Duration:** {report.scan_duration_s:.2f}s  ",
            f"**Risk Score:** {report.risk_score}/100 ({report.risk_level})  ",
            f"**Report Version:** {report.report_version}",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = report.severity_counts.get(sev, 0)
            lines.append(f"| {sev} | {count} |")

        lines += [
            "",
            f"**Total Findings:** {report.total_findings}",
            f"**Scanners Used:** {', '.join(report.scanners_used) or 'N/A'}",
            "",
            "## Findings",
            "",
            "| Severity | File | Line | Title | CWE | OWASP | Scanner |",
            "|----------|------|------|-------|-----|-------|---------|",
        ]
        for f in report.findings:
            sev      = f.get("severity", "")
            fpath    = f.get("file_path", "")
            line     = f.get("line", 0)
            title    = _md_escape(f.get("title", ""))[:60]
            cwe      = f.get("cwe_id", "")
            owasp    = _md_escape(f.get("owasp_category", ""))[:30]
            scanner  = f.get("source_scanner", "")
            lines.append(f"| {sev} | `{fpath}` | {line} | {title} | {cwe} | {owasp} | {scanner} |")

        lines += ["", "---", f"*Generated by {self.tool_name} v{self.tool_version}*"]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def to_json(self, report: ScanReport) -> str:
        """Machine-readable JSON report."""
        payload = {
            "report_version":  report.report_version,
            "tool":            {"name": self.tool_name, "version": self.tool_version},
            "target":          report.target,
            "timestamp":       report.timestamp,
            "scan_duration_s": report.scan_duration_s,
            "scanners_used":   report.scanners_used,
            "summary": {
                "total_findings": report.total_findings,
                "severity_counts": report.severity_counts,
                "risk_score": report.risk_score,
                "risk_level": report.risk_level,
            },
            "findings": report.findings,
        }
        return json.dumps(payload, indent=2, default=str)

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------

    def to_html(self, report: ScanReport) -> str:
        """Self-contained HTML dashboard — no external CDN dependencies."""
        sev_badge_css = "\n".join(
            f"    .badge-{sev.lower()} {{ background:{col}; }}"
            for sev, col in _SEVERITY_CSS.items()
        )

        # Severity summary pills
        summary_pills = "".join(
            f'<span class="badge badge-{s.lower()}">'
            f'{s}: {report.severity_counts.get(s, 0)}'
            f"</span>\n"
            for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        )

        # Table rows
        rows: List[str] = []
        for f in report.findings:
            sev     = html.escape(f.get("severity", ""))
            fpath   = html.escape(f.get("file_path", ""))
            line    = f.get("line", 0)
            title   = html.escape(f.get("title", "")[:80])
            cwe     = html.escape(f.get("cwe_id", ""))
            owasp   = html.escape(f.get("owasp_category", "")[:40])
            scanner = html.escape(f.get("source_scanner", ""))
            desc    = html.escape(f.get("description", "")[:200])
            hint    = html.escape(f.get("fix_hint", f.get("recommendation", ""))[:200])
            badge   = f'<span class="badge badge-{sev.lower()}">{sev}</span>'
            rows.append(
                f"<tr>"
                f"<td>{badge}</td>"
                f"<td><code>{fpath}</code></td>"
                f"<td>{line}</td>"
                f"<td title=\"{desc}\">{title}</td>"
                f"<td>{cwe}</td>"
                f"<td>{owasp}</td>"
                f"<td>{scanner}</td>"
                f"<td>{hint}</td>"
                f"</tr>"
            )
        rows_html = "\n".join(rows)

        risk_colour = _SEVERITY_CSS.get(report.risk_level, "#6b7280")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{html.escape(self.tool_name)} Security Report</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; }}
    body {{ font-family: system-ui, -apple-system, sans-serif; margin: 0; padding: 1.5rem;
            background: #f8fafc; color: #1e293b; }}
    h1 {{ font-size: 1.6rem; margin-bottom: 0.25rem; }}
    h2 {{ font-size: 1.1rem; margin: 1.25rem 0 0.5rem; border-bottom: 1px solid #e2e8f0;
          padding-bottom: 0.25rem; }}
    .meta {{ color: #64748b; font-size: 0.85rem; margin-bottom: 1rem; }}
    .risk-badge {{ display: inline-block; padding: 0.3rem 0.8rem; border-radius: 9999px;
                  color: #fff; font-weight: 700; background: {risk_colour}; font-size: 1rem; }}
    .badge {{ display: inline-block; padding: 0.15rem 0.55rem; border-radius: 4px;
              color: #fff; font-weight: 600; font-size: 0.78rem; white-space: nowrap; }}
{sev_badge_css}
    .summary-pills {{ display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem; }}
    .summary-pills .badge {{ font-size: 0.9rem; padding: 0.35rem 0.75rem; }}
    table {{ border-collapse: collapse; width: 100%; font-size: 0.82rem; background: #fff;
             border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
    th {{ background: #1e293b; color: #f1f5f9; padding: 0.5rem 0.65rem; text-align: left; }}
    td {{ padding: 0.4rem 0.65rem; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #f1f5f9; }}
    code {{ background: #e2e8f0; padding: 0.1rem 0.3rem; border-radius: 3px;
            font-size: 0.78rem; word-break: break-all; }}
    .footer {{ margin-top: 1.5rem; color: #94a3b8; font-size: 0.78rem; }}
  </style>
</head>
<body>
  <h1>{html.escape(self.tool_name)} Security Report</h1>
  <div class="meta">
    Target: <strong>{html.escape(report.target)}</strong> &nbsp;|&nbsp;
    {html.escape(report.timestamp)} &nbsp;|&nbsp;
    Duration: {report.scan_duration_s:.2f}s &nbsp;|&nbsp;
    Scanners: {html.escape(', '.join(report.scanners_used) or 'N/A')}
  </div>

  <h2>Risk Score</h2>
  <p><span class="risk-badge">{report.risk_score}/100 — {html.escape(report.risk_level)}</span>
  &nbsp; Total findings: <strong>{report.total_findings}</strong></p>

  <h2>Severity Breakdown</h2>
  <div class="summary-pills">
{summary_pills}  </div>

  <h2>Findings ({report.total_findings})</h2>
  <table>
    <thead>
      <tr>
        <th>Severity</th><th>File</th><th>Line</th><th>Title</th>
        <th>CWE</th><th>OWASP</th><th>Scanner</th><th>Fix Hint</th>
      </tr>
    </thead>
    <tbody>
{rows_html}
    </tbody>
  </table>

  <p class="footer">Generated by {html.escape(self.tool_name)} v{html.escape(self.tool_version)}
  &mdash; Report v{html.escape(report.report_version)}</p>
</body>
</html>
"""

    # ------------------------------------------------------------------
    # CSV
    # ------------------------------------------------------------------

    def to_csv(self, report: ScanReport) -> str:
        """CSV export — compatible with spreadsheet / compliance tools."""
        buf = io.StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
        writer.writerow([
            "severity", "cwe", "file", "line", "title",
            "scanner", "rule_id", "owasp", "cvss_score",
            "confidence", "description",
        ])
        for f in report.findings:
            writer.writerow([
                f.get("severity", ""),
                f.get("cwe_id", ""),
                f.get("file_path", ""),
                f.get("line", 0),
                f.get("title", ""),
                f.get("source_scanner", ""),
                f.get("rule_id", ""),
                f.get("owasp_category", ""),
                f.get("cvss_score", 0.0),
                f.get("confidence", 0.0),
                f.get("description", "").replace("\n", " "),
            ])
        return buf.getvalue()

    # ------------------------------------------------------------------
    # File save
    # ------------------------------------------------------------------

    def save(self, report: ScanReport, path: str, format: str = "json") -> None:
        """Serialize *report* in *format* and write to *path*."""
        fmt = format.lower().strip()
        dispatch = {
            "json":     lambda: self.to_json(report),
            "sarif":    lambda: json.dumps(self.to_sarif(report), indent=2),
            "markdown": lambda: self.to_markdown(report),
            "md":       lambda: self.to_markdown(report),
            "html":     lambda: self.to_html(report),
            "csv":      lambda: self.to_csv(report),
        }
        fn = dispatch.get(fmt)
        if fn is None:
            raise ValueError(f"Unsupported report format: {format!r}. Choose from: {list(dispatch)}")

        content = fn()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        logger.info("Report saved to %s (%s)", path, fmt)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_risk_score(severity_counts: Dict[str, int], total: int) -> int:
        """Compute a 0-100 risk score from severity distribution."""
        if total == 0:
            return 0
        raw = sum(
            _SEVERITY_WEIGHTS.get(sev, 1) * count
            for sev, count in severity_counts.items()
        )
        # Normalise: 40 * 5 criticals = 200, treat 500+ as ceiling
        score = min(100, int((raw / 500) * 100))
        # Guarantee CRITICAL findings always push score above 75
        if severity_counts.get("CRITICAL", 0) > 0:
            score = max(score, 76)
        elif severity_counts.get("HIGH", 0) > 0:
            score = max(score, 51)
        return score

    @staticmethod
    def _risk_level(score: int) -> str:
        if score >= 76:
            return "CRITICAL"
        if score >= 51:
            return "HIGH"
        if score >= 26:
            return "MEDIUM"
        if score >= 1:
            return "LOW"
        return "LOW"


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _slug(text: str) -> str:
    """Convert a title to a CamelCase-ish SARIF rule name."""
    import re
    words = re.sub(r"[^a-zA-Z0-9 ]", " ", text).split()
    return "".join(w.capitalize() for w in words[:6]) or "UnknownRule"


def _md_escape(text: str) -> str:
    """Escape pipe characters for Markdown table cells."""
    return text.replace("|", "\\|").replace("\n", " ")
