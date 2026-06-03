# TythanAI Security Platform — Community Edition
# Copyright (c) 2026 TythanAI Labs
# Licensed under the Business Source License 1.1 (see LICENSE).

"""
community/report.py — SARIF + HTML report generation for community edition.
"""
from __future__ import annotations

import json
import html as html_lib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List

from community.gates import UPGRADE_URL
from community.scanner import ScanResult

_VERSION = "1.0.0"

# ─── SARIF ────────────────────────────────────────────────────────────────────

def to_sarif(result: ScanResult) -> dict:
    results = []
    for f in result.all_findings[: 200]:   # community cap
        results.append({
            "ruleId": f.get("rule_id", f.get("id", "UNKNOWN")),
            "level": _sarif_level(f.get("severity", "INFO")),
            "message": {"text": f.get("title", f.get("message", "Finding"))},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("file", "unknown")},
                    "region": {"startLine": max(1, int(f.get("line", 1)))},
                }
            }],
            "properties": {"severity": f.get("severity", "INFO"), "source": f.get("source", "")},
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "TythanAI Community",
                    "version": _VERSION,
                    "informationUri": "https://tythanai.io",
                    "rules": [],
                }
            },
            "results": results,
        }],
    }


def _sarif_level(severity: str) -> str:
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
            "LOW": "note", "INFO": "none"}.get(severity.upper(), "none")


def write_sarif(result: ScanResult, output_path: str) -> None:
    Path(output_path).write_text(
        json.dumps(to_sarif(result), indent=2), encoding="utf-8"
    )


# ─── HTML ─────────────────────────────────────────────────────────────────────

_SEVERITY_COLOR = {
    "CRITICAL": "#b91c1c",
    "HIGH":     "#c2410c",
    "MEDIUM":   "#b45309",
    "LOW":      "#1d4ed8",
    "INFO":     "#374151",
}

_SEVERITY_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fefce8",
    "LOW":      "#eff6ff",
    "INFO":     "#f9fafb",
}


def to_html(result: ScanResult) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sev = result.by_severity
    risk = result.risk_level()
    risk_score = result.risk_score()

    sev_bars = "".join(
        f'<div class="sev-bar"><span class="sev-label" style="color:{_SEVERITY_COLOR[s]}">'
        f'{s}</span><span class="sev-count">{sev[s]}</span></div>'
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    )

    finding_rows = "".join(_finding_row(f) for f in result.all_findings)

    gated_rows = "".join(
        f'<li><span class="lock">🔒</span> <strong>{g.title.replace("[PREMIUM] ","")}</strong></li>'
        for g in result.gated_features
    )

    error_section = ""
    if result.errors:
        errs = "".join(f"<li>{html_lib.escape(e)}</li>" for e in result.errors)
        error_section = f'<div class="errors"><h3>Scan warnings</h3><ul>{errs}</ul></div>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TythanAI Community — Scan Report</title>
<style>
  body{{font-family:system-ui,sans-serif;margin:0;background:#f9fafb;color:#111827}}
  .header{{background:#0f172a;color:#f8fafc;padding:1.5rem 2rem;display:flex;justify-content:space-between;align-items:center}}
  .header h1{{margin:0;font-size:1.4rem}}
  .badge{{background:#6366f1;color:#fff;padding:.2rem .7rem;border-radius:999px;font-size:.75rem;font-weight:700}}
  .container{{max-width:1100px;margin:2rem auto;padding:0 1rem}}
  .summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:2rem}}
  .card{{background:#fff;border:1px solid #e5e7eb;border-radius:.75rem;padding:1.2rem;text-align:center}}
  .card .big{{font-size:2.5rem;font-weight:800;line-height:1}}
  .card .label{{font-size:.8rem;color:#6b7280;margin-top:.3rem}}
  .risk-card{{border-left:4px solid {_SEVERITY_COLOR.get(risk,"#374151")}}}
  .sev-bars{{display:flex;gap:.75rem;flex-wrap:wrap;margin-bottom:2rem}}
  .sev-bar{{background:#fff;border:1px solid #e5e7eb;border-radius:.5rem;padding:.5rem .9rem;display:flex;gap:.5rem;align-items:center}}
  .sev-label{{font-weight:700;font-size:.85rem}}
  .sev-count{{font-size:.85rem;color:#374151}}
  table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e5e7eb;border-radius:.75rem;overflow:hidden;margin-bottom:2rem}}
  th{{background:#f3f4f6;text-align:left;padding:.75rem 1rem;font-size:.8rem;color:#374151;text-transform:uppercase;letter-spacing:.05em}}
  td{{padding:.7rem 1rem;font-size:.85rem;border-top:1px solid #f3f4f6;vertical-align:top}}
  .sev-chip{{padding:.15rem .6rem;border-radius:999px;font-size:.75rem;font-weight:700}}
  .premium-box{{background:#fff;border:1px solid #e5e7eb;border-radius:.75rem;padding:1.2rem 1.5rem;margin-bottom:2rem}}
  .premium-box h3{{margin:0 0 .75rem;font-size:1rem;color:#374151}}
  .premium-box ul{{margin:.5rem 0;padding-left:1.25rem;columns:2}}
  .premium-box li{{margin:.25rem 0;font-size:.85rem;color:#6b7280}}
  .lock{{font-size:.9rem}}
  .upgrade-btn{{display:inline-block;background:#6366f1;color:#fff;padding:.5rem 1.25rem;border-radius:.5rem;text-decoration:none;font-size:.85rem;font-weight:600;margin-top:.75rem}}
  .errors{{background:#fef2f2;border:1px solid #fecaca;border-radius:.5rem;padding:1rem;margin-bottom:1.5rem;font-size:.85rem}}
  .footer{{text-align:center;color:#9ca3af;font-size:.75rem;padding:2rem}}
</style>
</head>
<body>
<div class="header">
  <h1>TythanAI Community — Security Scan Report</h1>
  <div>
    <span class="badge">COMMUNITY</span>
    <span style="font-size:.8rem;margin-left:1rem;opacity:.7">{ts}</span>
  </div>
</div>

<div class="container">

  <div class="summary">
    <div class="card risk-card">
      <div class="big" style="color:{_SEVERITY_COLOR.get(risk,'#374151')}">{risk}</div>
      <div class="label">Risk Level ({risk_score}/100)</div>
    </div>
    <div class="card">
      <div class="big">{result.total}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="card">
      <div class="big">{len(result.sast_findings)}</div>
      <div class="label">SAST</div>
    </div>
    <div class="card">
      <div class="big">{len(result.sca_findings)}</div>
      <div class="label">SCA / CVE</div>
    </div>
    <div class="card">
      <div class="big">{len(result.secrets_findings)}</div>
      <div class="label">Secrets</div>
    </div>
    <div class="card">
      <div class="big">{len(result.web3_findings)}</div>
      <div class="label">Web3</div>
    </div>
  </div>

  <div class="sev-bars">{sev_bars}</div>

  {error_section}

  <table>
    <thead><tr>
      <th>Severity</th><th>Category</th><th>Title</th><th>File</th><th>Line</th>
    </tr></thead>
    <tbody>{finding_rows if finding_rows else "<tr><td colspan=5 style='text-align:center;color:#6b7280'>No findings — looks clean!</td></tr>"}</tbody>
  </table>

  <div class="premium-box">
    <h3>🔒 Unlock Premium Features</h3>
    <ul>{gated_rows}</ul>
    <a class="upgrade-btn" href="{UPGRADE_URL}" target="_blank">Upgrade to Pro →</a>
  </div>

</div>
<div class="footer">
  TythanAI Community Edition · <a href="https://tythanai.io">tythanai.io</a> ·
  Licensed under BSL 1.1 · Target: {html_lib.escape(result.target)}
</div>
</body>
</html>"""


def _finding_row(f: dict) -> str:
    sev = f.get("severity", "INFO").upper()
    color = _SEVERITY_COLOR.get(sev, "#374151")
    bg = _SEVERITY_BG.get(sev, "#f9fafb")
    title = html_lib.escape(str(f.get("title", f.get("message", "Finding"))))
    category = html_lib.escape(str(f.get("category", f.get("source", ""))))
    fname = html_lib.escape(str(f.get("file", "")))
    line = f.get("line", "")
    return (
        f'<tr style="background:{bg}">'
        f'<td><span class="sev-chip" style="background:{color};color:#fff">{sev}</span></td>'
        f'<td>{category}</td><td>{title}</td>'
        f'<td style="font-family:monospace;font-size:.78rem">{fname}</td>'
        f'<td>{line}</td></tr>'
    )


def write_html(result: ScanResult, output_path: str) -> None:
    Path(output_path).write_text(to_html(result), encoding="utf-8")
