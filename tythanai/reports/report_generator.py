"""
TythanAI — Report Generator v2.2
Generates interactive HTML (with Chart.js), Markdown, and JSON reports.
HTML report: severity donut chart, filterable/searchable findings table,
CVSS scores, confidence badges, code-fix cards — all in a dark theme.
"""
import json
import time
from typing import Dict, List
from pathlib import Path

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626", "HIGH": "#ea580c",
    "MEDIUM": "#d97706",   "LOW": "#2563eb", "INFO": "#6b7280",
}
SEVERITY_BADGES = {
    "CRITICAL": "🔴 CRITICAL", "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",     "LOW": "🔵 LOW", "INFO": "⚪ INFO",
}


class ReportGenerator:

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_html(self, report: Dict) -> str:
        findings        = report.get("findings", [])
        severity_counts = report.get("severity_counts", self._count_severity(findings))
        risk_score      = report.get("risk_score", 0)
        risk_level      = report.get("risk_level", "UNKNOWN")
        target          = report.get("target", "Unknown")
        ts              = report.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ"))
        summary         = report.get("executive_summary", "")
        risk_color      = SEVERITY_COLORS.get(risk_level, "#6b7280")

        findings_json   = json.dumps(findings, ensure_ascii=False)
        sc_json         = json.dumps(severity_counts)

        findings_html   = self._render_findings(findings)
        recs_html       = "".join(f"<li>{r}</li>" for r in report.get("recommendations", []))

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TythanAI Report — {target}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#0a0f1e;--surface:#111827;--surface2:#1f2937;--border:#374151;
      --text:#f1f5f9;--muted:#94a3b8;--accent:#38bdf8;
      --critical:#dc2626;--high:#ea580c;--medium:#d97706;--low:#2563eb;--info:#6b7280}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
      background:var(--bg);color:var(--text);line-height:1.6;min-height:100vh}}
.container{{max-width:1200px;margin:0 auto;padding:2rem}}
/* Header */
header{{background:linear-gradient(135deg,#1e293b,#0f172a);border:1px solid var(--border);
        border-radius:12px;padding:2rem;margin-bottom:1.5rem}}
.logo{{font-size:1.8rem;font-weight:800;color:var(--accent)}}
.logo span{{color:#f43f5e}}
.meta{{color:var(--muted);font-size:.85rem;margin-top:.4rem}}
/* Stats row */
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin-bottom:1.5rem}}
.stat{{background:var(--surface);border:1px solid var(--border);border-radius:10px;
       padding:1.2rem;text-align:center}}
.stat-num{{font-size:2.2rem;font-weight:800;line-height:1}}
.stat-lbl{{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-top:.3rem}}
/* Two-column */
.row{{display:grid;grid-template-columns:1fr 320px;gap:1.5rem;margin-bottom:1.5rem}}
@media(max-width:900px){{.row{{grid-template-columns:1fr}}}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.5rem}}
.card-title{{font-size:.8rem;font-weight:700;color:var(--muted);text-transform:uppercase;
             letter-spacing:.08em;margin-bottom:1rem}}
/* Risk score */
.risk-ring{{display:flex;align-items:center;gap:1.5rem;margin-bottom:1rem}}
.risk-num{{font-size:3.5rem;font-weight:900;color:{risk_color}}}
.risk-label{{font-size:1.1rem;font-weight:700;color:{risk_color}}}
/* Summary */
.summary-text{{color:var(--muted);font-size:.9rem}}
/* Toolbar */
.toolbar{{display:flex;flex-wrap:wrap;gap:.75rem;margin-bottom:1rem;align-items:center}}
.search-box{{flex:1;min-width:200px;background:var(--surface2);border:1px solid var(--border);
             border-radius:8px;padding:.5rem .9rem;color:var(--text);font-size:.9rem}}
.search-box::placeholder{{color:var(--muted)}}
.filter-btn{{padding:.45rem .9rem;border-radius:6px;border:1px solid var(--border);
             background:var(--surface2);color:var(--muted);cursor:pointer;font-size:.82rem;
             transition:all .2s}}
.filter-btn.active,.filter-btn:hover{{background:var(--accent);color:#000;border-color:var(--accent)}}
/* Findings */
.finding{{background:var(--surface2);border:1px solid var(--border);border-radius:10px;
          margin-bottom:1rem;overflow:hidden;transition:box-shadow .2s}}
.finding:hover{{box-shadow:0 0 0 1px var(--accent)}}
.finding-header{{display:flex;align-items:center;gap:.75rem;padding:1rem 1.2rem;
                 cursor:pointer;user-select:none}}
.sev-badge{{padding:.2rem .6rem;border-radius:4px;font-size:.72rem;font-weight:700;color:#fff;
            white-space:nowrap}}
.finding-id{{font-size:.78rem;color:var(--muted);font-family:monospace}}
.finding-desc{{flex:1;font-size:.88rem}}
.finding-loc{{font-size:.75rem;color:var(--muted);font-family:monospace;white-space:nowrap}}
.chevron{{color:var(--muted);transition:transform .2s;font-size:.8rem}}
.finding-body{{display:none;padding:0 1.2rem 1.2rem;border-top:1px solid var(--border)}}
.finding-body.open{{display:block}}
/* Body sections */
.body-grid{{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-top:1rem}}
@media(max-width:700px){{.body-grid{{grid-template-columns:1fr}}}}
.field{{margin-bottom:.8rem}}
.field-lbl{{font-size:.72rem;font-weight:700;color:var(--muted);text-transform:uppercase;
            letter-spacing:.06em;margin-bottom:.25rem}}
.field-val{{font-size:.85rem;color:var(--text)}}
pre.evidence{{background:#0a0f1e;border:1px solid var(--border);border-radius:6px;
              padding:.7rem;font-size:.78rem;overflow-x:auto;color:#a5f3fc;
              max-height:120px;overflow-y:auto}}
.fix-block{{background:#052e16;border:1px solid #16a34a;border-radius:6px;
            padding:.7rem;font-size:.78rem;font-family:monospace;
            white-space:pre-wrap;color:#86efac;max-height:180px;overflow-y:auto}}
/* Confidence bar */
.conf-bar{{height:6px;border-radius:3px;background:var(--border);margin-top:.4rem}}
.conf-fill{{height:100%;border-radius:3px;background:var(--accent)}}
/* CVSS badge */
.cvss-badge{{display:inline-block;padding:.15rem .5rem;border-radius:4px;
             font-size:.75rem;font-weight:700;background:#1e293b;border:1px solid var(--border)}}
/* Chart */
#donut-wrap{{position:relative;width:180px;margin:0 auto}}
/* Recommendations */
.rec-list li{{margin:.4rem 0 .4rem 1rem;font-size:.88rem;color:var(--muted)}}
/* No findings */
.empty{{text-align:center;padding:3rem;color:var(--muted)}}
</style>
</head>
<body>
<div class="container">

<!-- Header -->
<header>
  <div class="logo">Ghost<span>Security</span></div>
  <div class="meta">
    Target: <strong>{target}</strong> &nbsp;·&nbsp;
    Generated: <strong>{ts}</strong> &nbsp;·&nbsp;
    Findings: <strong>{len(findings)}</strong>
  </div>
</header>

<!-- Stats -->
<div class="stats">
  <div class="stat">
    <div class="stat-num" style="color:var(--critical)">{severity_counts.get("CRITICAL",0)}</div>
    <div class="stat-lbl">Critical</div>
  </div>
  <div class="stat">
    <div class="stat-num" style="color:var(--high)">{severity_counts.get("HIGH",0)}</div>
    <div class="stat-lbl">High</div>
  </div>
  <div class="stat">
    <div class="stat-num" style="color:var(--medium)">{severity_counts.get("MEDIUM",0)}</div>
    <div class="stat-lbl">Medium</div>
  </div>
  <div class="stat">
    <div class="stat-num" style="color:var(--low)">{severity_counts.get("LOW",0)}</div>
    <div class="stat-lbl">Low</div>
  </div>
  <div class="stat">
    <div class="stat-num" style="color:var(--info)">{severity_counts.get("INFO",0)}</div>
    <div class="stat-lbl">Info</div>
  </div>
  <div class="stat">
    <div class="stat-num" style="color:{risk_color}">{risk_score}</div>
    <div class="stat-lbl">Risk Score</div>
  </div>
</div>

<!-- Two-column: summary + donut -->
<div class="row">
  <div class="card">
    <div class="card-title">Executive Summary</div>
    <div class="risk-ring">
      <div>
        <div class="risk-num">{risk_score}</div>
        <div class="risk-label">{risk_level}</div>
      </div>
    </div>
    <p class="summary-text">{summary or "Automated security audit completed."}</p>
    {"<ul class='rec-list' style='margin-top:1rem'>" + recs_html + "</ul>" if recs_html else ""}
  </div>
  <div class="card" style="display:flex;flex-direction:column;align-items:center">
    <div class="card-title" style="align-self:flex-start">Severity Distribution</div>
    <div id="donut-wrap"><canvas id="donut"></canvas></div>
  </div>
</div>

<!-- Findings -->
<div class="card">
  <div class="card-title">Findings ({len(findings)})</div>
  <div class="toolbar">
    <input class="search-box" id="search" type="text" placeholder="Search findings…" oninput="filterFindings()">
    <button class="filter-btn active" onclick="setFilter('ALL',this)">All</button>
    <button class="filter-btn" onclick="setFilter('CRITICAL',this)">Critical</button>
    <button class="filter-btn" onclick="setFilter('HIGH',this)">High</button>
    <button class="filter-btn" onclick="setFilter('MEDIUM',this)">Medium</button>
    <button class="filter-btn" onclick="setFilter('LOW',this)">Low</button>
  </div>
  <div id="findings-list">
    {"<div class='empty'>✅ No findings detected</div>" if not findings else findings_html}
  </div>
</div>

</div><!-- /container -->

<script>
// ── Chart ───────────────────────────────────────────────────────────────────
const sc = {sc_json};
new Chart(document.getElementById('donut'),{{
  type:'doughnut',
  data:{{
    labels:['Critical','High','Medium','Low','Info'],
    datasets:[{{
      data:[sc.CRITICAL||0,sc.HIGH||0,sc.MEDIUM||0,sc.LOW||0,sc.INFO||0],
      backgroundColor:['#dc2626','#ea580c','#d97706','#2563eb','#6b7280'],
      borderWidth:0,
    }}]
  }},
  options:{{
    cutout:'70%',plugins:{{legend:{{position:'bottom',
      labels:{{color:'#94a3b8',font:{{size:11}},boxWidth:12,padding:8}}}}}},
    animation:{{duration:600}}
  }}
}});

// ── Filter / search ──────────────────────────────────────────────────────────
let activeFilter='ALL';
function setFilter(f,btn){{
  activeFilter=f;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  filterFindings();
}}
function filterFindings(){{
  const q=document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('.finding').forEach(el=>{{
    const sev=el.dataset.severity;
    const txt=el.textContent.toLowerCase();
    const sevOk=activeFilter==='ALL'||sev===activeFilter;
    const txtOk=!q||txt.includes(q);
    el.style.display=(sevOk&&txtOk)?'':'none';
  }});
}}

// ── Accordion ────────────────────────────────────────────────────────────────
function toggle(id){{
  const body=document.getElementById('body-'+id);
  const chev=document.getElementById('chev-'+id);
  body.classList.toggle('open');
  chev.textContent=body.classList.contains('open')?'▲':'▼';
}}
</script>
</body>
</html>"""

    def generate_markdown(self, report: Dict) -> str:
        findings        = report.get("findings", [])
        severity_counts = report.get("severity_counts", self._count_severity(findings))
        risk_score      = report.get("risk_score", 0)
        risk_level      = report.get("risk_level", "UNKNOWN")
        target          = report.get("target", "Unknown")
        ts              = report.get("timestamp", "")
        summary         = report.get("executive_summary", "")

        lines = [
            "# TythanAI Audit Report",
            f"\n**Target:** `{target}`  ",
            f"**Date:** {ts}  ",
            f"**Risk Score:** {risk_score}/100 ({risk_level})\n",
            "## Severity Summary\n",
            "| Severity | Count |",
            "|---|---|",
        ]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}.get(sev,"")
            lines.append(f"| {icon} {sev} | {severity_counts.get(sev,0)} |")

        if summary:
            lines += ["\n## Executive Summary\n", summary]

        lines += ["\n## Findings\n"]
        for i, f in enumerate(findings, 1):
            sev   = f.get("severity","INFO")
            icon  = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}.get(sev,"")
            lines.append(f"### {i}. {icon} [{sev}] {f.get('id','?')} — {f.get('type','Unknown')}")
            lines.append(f"\n**File:** `{f.get('file','N/A')}` line {f.get('line','?')}  ")
            lines.append(f"**Description:** {f.get('description','')}")
            if f.get("cwe"):
                lines.append(f"**CWE:** [{f['cwe']}](https://cwe.mitre.org/data/definitions/{f['cwe'].replace('CWE-','')}.html)")
            if f.get("cvss_score"):
                lines.append(f"**CVSS Score:** {f['cvss_score']}  ")
            if f.get("confidence") is not None:
                lines.append(f"**Confidence:** {f['confidence']}%")
            if f.get("evidence"):
                lines.append(f"\n```\n{f['evidence']}\n```")
            if f.get("recommendation"):
                lines.append(f"\n> **Fix:** {f['recommendation']}")
            if f.get("code_fix") and f["code_fix"] != "N/A":
                lines.append(f"\n```\n{f['code_fix']}\n```")
            lines.append("")

        recs = report.get("recommendations", [])
        if recs:
            lines += ["\n## Recommendations\n"]
            for r in recs:
                lines.append(f"- {r}")

        return "\n".join(lines)

    def generate_json(self, report: Dict) -> str:
        return json.dumps(report, indent=2, ensure_ascii=False)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _count_severity(self, findings: List[Dict]) -> Dict:
        counts: Dict[str, int] = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
        for f in findings:
            s = f.get("severity","INFO")
            counts[s] = counts.get(s,0) + 1
        return counts

    def _render_findings(self, findings: List[Dict]) -> str:
        html = []
        for i, f in enumerate(findings, 1):
            sev   = f.get("severity","INFO")
            color = SEVERITY_COLORS.get(sev,"#6b7280")
            ev    = (f.get("evidence","") or "").replace("<","&lt;").replace(">","&gt;")
            fix   = f.get("code_fix","") or ""
            conf  = f.get("confidence", None)
            cvss  = f.get("cvss_score", None)
            fp    = f.get("false_positive_risk","")
            desc  = f.get("description","")
            rec   = f.get("recommendation","")
            cwe   = f.get("cwe","")
            scenario = f.get("exploit_scenario","")

            conf_html = ""
            if conf is not None:
                conf_html = f"""
              <div class="field">
                <div class="field-lbl">Confidence</div>
                <div class="conf-bar"><div class="conf-fill" style="width:{conf}%"></div></div>
                <div class="field-val" style="font-size:.78rem;margin-top:.2rem">{conf}%</div>
              </div>"""

            cvss_html = ""
            if cvss:
                c = float(cvss)
                cc = "#dc2626" if c>=9 else "#ea580c" if c>=7 else "#d97706" if c>=4 else "#2563eb"
                cvss_html = f'<span class="cvss-badge" style="color:{cc}">CVSS {c:.1f}</span> '

            html.append(f"""
<div class="finding" data-severity="{sev}" id="f{i}">
  <div class="finding-header" onclick="toggle({i})">
    <span class="sev-badge" style="background:{color}">{sev}</span>
    <span class="finding-id">{f.get("id","?")}</span>
    <span class="finding-desc">{desc[:90]}{"…" if len(desc)>90 else ""}</span>
    <span class="finding-loc">{f.get("file","")[:40]}:{f.get("line","")}</span>
    <span class="chevron" id="chev-{i}">▼</span>
  </div>
  <div class="finding-body" id="body-{i}">
    <div class="body-grid">
      <div>
        <div class="field"><div class="field-lbl">Description</div>
          <div class="field-val">{desc}</div></div>
        {f'<div class="field"><div class="field-lbl">CWE</div><div class="field-val"><a href="https://cwe.mitre.org/data/definitions/{cwe.replace("CWE-","")}.html" target="_blank" style="color:var(--accent)">{cwe}</a></div></div>' if cwe else ""}
        {f'<div class="field"><div class="field-lbl">Exploit Scenario</div><div class="field-val" style="color:#fca5a5">{scenario}</div></div>' if scenario and scenario!="N/A" else ""}
        <div class="field"><div class="field-lbl">Recommendation</div>
          <div class="field-val">{rec}</div></div>
        {f'<div class="field"><div class="field-lbl">Evidence</div><pre class="evidence">{ev}</pre></div>' if ev else ""}
        {f'<div class="field"><div class="field-lbl">Code Fix</div><div class="fix-block">{fix.replace("<","&lt;").replace(">","&gt;")}</div></div>' if fix and fix!="N/A" else ""}
      </div>
      <div>
        <div class="field"><div class="field-lbl">Metrics</div>
          <div>{cvss_html}{f'<span class="cvss-badge">{f.get("cvss_vector","")[:30]}</span>' if f.get("cvss_vector") else ""}</div>
        </div>
        {conf_html}
        {f'<div class="field"><div class="field-lbl">False Positive Risk</div><div class="field-val">{fp}</div></div>' if fp else ""}
        <div class="field"><div class="field-lbl">Source</div>
          <div class="field-val">{f.get("source","ghost")} / {f.get("category","")}</div></div>
      </div>
    </div>
  </div>
</div>""")
        return "".join(html)
