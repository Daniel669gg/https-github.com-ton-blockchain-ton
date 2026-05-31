"""
backend/pipeline/defensive_lifecycle.py — Defensive Lifecycle Pipeline (Phase 1)

6 Stages:
  1. Code Review    — Bandit + Semgrep + custom scanners (parallel via asyncio.gather)
  2. Taint Analysis — Python AST taint_analyzer
  3. Dependency Audit — OSV API + AST usage check
  4. Detection Engineering — auto-generate Sigma + YARA rules for HIGH/CRITICAL findings
  5. Patch Validation — diff against baseline (fixed / introduced / remaining)
  6. Report Generation — JSON + HTML with severity breakdown, Risk Score top-10, CWE stats

FastAPI endpoint: POST /api/v2/audit/full
CLI:             ghost audit-full <path> [--output report.json]
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from backend.core.confidence import (
    ConfidenceFilter,
    ContextVerifier,
    Deduplicator,
    Finding,
    findings_from_dicts,
)
from backend.scanners.taint_analyzer import TaintAnalyzer
from backend.scanners.supply_chain import SupplyChainScanner
from backend.scoring.risk_scorer import RiskScorer

logger = logging.getLogger("tythanai.pipeline")

# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — individual scanner runners
# ─────────────────────────────────────────────────────────────────────────────

async def _run_bandit(path: str) -> List[Finding]:
    try:
        proc = await asyncio.create_subprocess_exec(
            "bandit", "-r", path, "-f", "json", "-q",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        data = json.loads(stdout.decode("utf-8", errors="replace"))
        raw = data.get("results", [])
    except (FileNotFoundError, asyncio.TimeoutError, json.JSONDecodeError) as exc:
        logger.warning("Bandit unavailable or failed: %s", exc)
        return []

    conf_map = {"HIGH": 0.9, "MEDIUM": 0.75, "LOW": 0.6}
    return [
        Finding(
            rule_id=f"BANDIT-{r.get('test_id', 'B000')}",
            file=r.get("filename", ""),
            line=r.get("line_number", 0),
            severity=r.get("issue_severity", "MEDIUM").upper(),
            confidence=conf_map.get(r.get("issue_confidence", "MEDIUM").upper(), 0.75),
            cwe_id=str(r.get("issue_cwe", {}).get("id", "")),
            description=r.get("issue_text", ""),
            recommendation=f"See Bandit documentation for {r.get('test_id', '')}",
            sources=["bandit"],
            context_lines=r.get("code", "").splitlines()[:5],
        )
        for r in raw
    ]


async def _run_semgrep(path: str) -> List[Finding]:
    try:
        proc = await asyncio.create_subprocess_exec(
            "semgrep", "--config", "auto", path,
            "--json", "--quiet", "--no-git-ignore",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
        data = json.loads(stdout.decode("utf-8", errors="replace"))
        raw = data.get("results", [])
    except (FileNotFoundError, asyncio.TimeoutError, json.JSONDecodeError) as exc:
        logger.warning("Semgrep unavailable or failed: %s", exc)
        return []

    sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    return [
        Finding(
            rule_id=r.get("check_id", "SEMGREP"),
            file=r.get("path", ""),
            line=r.get("start", {}).get("line", 0),
            severity=sev_map.get(r.get("extra", {}).get("severity", "WARNING"), "MEDIUM"),
            confidence=0.75,
            description=r.get("extra", {}).get("message", ""),
            sources=["semgrep"],
            context_lines=r.get("extra", {}).get("lines", "").splitlines()[:5],
        )
        for r in raw
    ]


async def _run_custom_scanners(path: str) -> List[Finding]:
    findings: List[Finding] = []
    try:
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent.parent))
        from scanners.ast_scanner.ast_analyzer import ASTScanner
        raw = ASTScanner().scan_directory(path)
        findings.extend(findings_from_dicts(
            raw.get("findings", raw) if isinstance(raw, dict) else raw
        ))
    except Exception as exc:
        logger.debug("Custom AST scanner: %s", exc)
    try:
        from scanners.secret_scanner.secret_detector import SecretDetector
        raw = SecretDetector().scan_directory(path)
        findings.extend(findings_from_dicts(
            raw.get("findings", raw) if isinstance(raw, dict) else raw
        ))
    except Exception as exc:
        logger.debug("Secret scanner: %s", exc)
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Stage 3 — OSV dependency helpers
# ─────────────────────────────────────────────────────────────────────────────

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def _ast_uses_import(directory: str, package_name: str) -> bool:
    safe_name = re.escape(package_name.replace("-", "_"))
    pattern = re.compile(
        rf"^\s*(import\s+{safe_name}|from\s+{safe_name}\s+import)",
        re.MULTILINE | re.IGNORECASE,
    )
    skip = {"__pycache__", ".venv", "venv", "node_modules"}
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in skip]
        for fname in files:
            if not fname.endswith(".py"):
                continue
            try:
                text = Path(os.path.join(root, fname)).read_text(errors="replace")
                if pattern.search(text):
                    return True
            except OSError:
                pass
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Stage 4 — Detection Engineering
# ─────────────────────────────────────────────────────────────────────────────

def _severity_to_sigma(severity: str) -> str:
    return {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
            "LOW": "low", "INFO": "informational"}.get(severity.upper(), "medium")


def _generate_sigma_rule(finding: Finding) -> str:
    title = finding.rule_id.replace("-", " ").replace("_", " ").title()
    return f"""title: {title}
id: {str(uuid.uuid4())[:8]}
status: experimental
description: >
  {finding.description[:200] or finding.rule_id}
references:
  - {finding.cwe_id or 'CWE-unknown'}
tags:
  - attack.initial_access
  - {finding.cwe_id.lower().replace('-', '_') if finding.cwe_id else 'security'}
logsource:
  category: application
  product: ghost_security
detection:
  selection:
    rule_id: '{finding.rule_id}'
    severity: '{finding.severity}'
    file|contains: '{Path(finding.file).name}'
  condition: selection
falsepositives:
  - False positives reduced via confidence scoring (threshold 0.7)
level: {_severity_to_sigma(finding.severity)}
"""


def _generate_yara_rule(finding: Finding) -> str:
    rule_name = re.sub(r"[^A-Za-z0-9_]", "_", finding.rule_id)
    keywords = [
        w for w in re.findall(r"[a-zA-Z]{4,}", finding.description)
        if len(w) < 30
    ][:4]
    strings_block = "\n".join(
        f'        $s{i} = "{kw}" nocase' for i, kw in enumerate(keywords)
    ) or '        $s0 = "suspicious_pattern" nocase'
    condition = " or ".join(f"$s{i}" for i in range(len(keywords) or 1))
    return f"""rule Auto_{rule_name} {{
    meta:
        description = "{finding.description[:100] or finding.rule_id}"
        cwe = "{finding.cwe_id}"
        severity = "{finding.severity}"
        confidence = "{finding.confidence:.2f}"
        auto_generated = true
    strings:
{strings_block}
    condition:
        {condition}
}}
"""


def _run_sigma_validate(sigma_path: str) -> bool:
    try:
        result = subprocess.run(
            ["sigma", "check", sigma_path],
            capture_output=True, timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return True   # assume valid if sigma-cli not installed


def _generate_detection_rules(
    findings: List[Finding],
    output_dir: str,
) -> Dict[str, Any]:
    """Generate Sigma + YARA rules for HIGH/CRITICAL findings."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    sigma_dir = out / "sigma"
    yara_dir = out / "yara"
    sigma_dir.mkdir(exist_ok=True)
    yara_dir.mkdir(exist_ok=True)

    generated_sigma: List[str] = []
    generated_yara: List[str] = []

    high_crit = [f for f in findings if f.severity in ("CRITICAL", "HIGH") and f.confidence >= 0.7]
    seen_rules: set = set()

    for finding in high_crit:
        if finding.rule_id in seen_rules:
            continue
        seen_rules.add(finding.rule_id)

        # Sigma
        sigma_content = _generate_sigma_rule(finding)
        sigma_file = sigma_dir / f"{finding.rule_id.replace('/', '_')}.yml"
        sigma_file.write_text(sigma_content)
        if _run_sigma_validate(str(sigma_file)):
            generated_sigma.append(str(sigma_file))

        # YARA
        yara_content = _generate_yara_rule(finding)
        yara_file = yara_dir / f"{finding.rule_id.replace('/', '_')}.yar"
        yara_file.write_text(yara_content)
        generated_yara.append(str(yara_file))

    return {
        "sigma_rules": generated_sigma,
        "yara_rules": generated_yara,
        "total_generated": len(generated_sigma) + len(generated_yara),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Stage 5 — Patch validation
# ─────────────────────────────────────────────────────────────────────────────

class PatchReport(BaseModel):
    fixed: List[Dict[str, Any]] = Field(default_factory=list)
    introduced: List[Dict[str, Any]] = Field(default_factory=list)
    remaining: List[Dict[str, Any]] = Field(default_factory=list)
    regression: bool = False


def _compare_baselines(baseline: List[Finding], current: List[Finding]) -> PatchReport:
    baseline_keys = {f.fingerprint() for f in baseline}
    current_keys = {f.fingerprint() for f in current}
    fp_to_finding = {f.fingerprint(): f for f in current}
    fp_to_baseline = {f.fingerprint(): f for f in baseline}

    fixed_fps = baseline_keys - current_keys
    intro_fps = current_keys - baseline_keys
    remain_fps = baseline_keys & current_keys

    regression = any(
        fp_to_finding[fp].severity in ("HIGH", "CRITICAL")
        for fp in intro_fps if fp in fp_to_finding
    )
    return PatchReport(
        fixed=[fp_to_baseline[fp].model_dump() for fp in fixed_fps if fp in fp_to_baseline],
        introduced=[fp_to_finding[fp].model_dump() for fp in intro_fps if fp in fp_to_finding],
        remaining=[fp_to_finding[fp].model_dump() for fp in remain_fps if fp in fp_to_finding],
        regression=regression,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Stage 6 — HTML report generation
# ─────────────────────────────────────────────────────────────────────────────

def _render_html_report(report_data: Dict[str, Any]) -> str:
    sev = report_data.get("severity_breakdown", {})
    top = report_data.get("top_findings", [])
    cwe = report_data.get("cwe_stats", {})

    top_rows = "".join(
        f"<tr><td>{f.get('rule_id','')}</td><td>{f.get('file','')}</td>"
        f"<td>{f.get('severity','')}</td><td>{f.get('risk_score',0):.1f}</td>"
        f"<td>{f.get('description','')[:80]}</td></tr>"
        for f in top[:10]
    )
    cwe_rows = "".join(
        f"<tr><td>{cwe_id}</td><td>{cnt}</td></tr>"
        for cwe_id, cnt in sorted(cwe.items(), key=lambda x: -x[1])[:10]
    )
    patch_section = ""
    if report_data.get("patch"):
        p = report_data["patch"]
        patch_section = f"""
        <h2>Patch Validation</h2>
        <p>Fixed: <b>{len(p.get('fixed', []))}</b> &nbsp;
           Introduced: <b style="color:{'red' if p.get('regression') else 'inherit'}">{len(p.get('introduced', []))}</b> &nbsp;
           Remaining: <b>{len(p.get('remaining', []))}</b></p>
        {'<p style="color:red;font-weight:bold">⚠ REGRESSION: new HIGH/CRITICAL findings introduced</p>' if p.get("regression") else ''}
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>TythanAI — Audit Report</title>
<style>
  body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#1a1a2e}}
  h1{{color:#e94560}}h2{{color:#16213e;border-bottom:2px solid #e94560;padding-bottom:4px}}
  table{{width:100%;border-collapse:collapse;margin:1rem 0}}
  th,td{{text-align:left;padding:8px;border:1px solid #ddd}}
  th{{background:#16213e;color:#fff}}
  tr:nth-child(even){{background:#f9f9f9}}
  .CRITICAL{{color:#c0392b;font-weight:bold}}.HIGH{{color:#e67e22;font-weight:bold}}
  .MEDIUM{{color:#f39c12}}.LOW{{color:#27ae60}}.INFO{{color:#7f8c8d}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.8em;font-weight:bold;color:#fff}}
  .bg-critical{{background:#c0392b}}.bg-high{{background:#e67e22}}
  .bg-medium{{background:#f39c12}}.bg-low{{background:#27ae60}}.bg-info{{background:#7f8c8d}}
</style>
</head>
<body>
<h1>🛡 TythanAI — Audit Report</h1>
<p><b>Target:</b> {report_data.get('path','')}<br>
<b>Scan time:</b> {report_data.get('timestamp','')}<br>
<b>Duration:</b> {report_data.get('duration_s',0):.1f}s &nbsp;
<b>Total findings:</b> {report_data.get('total_findings',0)}</p>

<h2>Severity Breakdown</h2>
<table>
<tr><th>Severity</th><th>Count</th></tr>
{''.join(f'<tr><td class="{s}">{s}</td><td>{sev.get(s,0)}</td></tr>' for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"])}
</table>

<h2>Top Findings by Risk Score</h2>
<table>
<tr><th>Rule</th><th>File</th><th>Severity</th><th>Risk Score</th><th>Description</th></tr>
{top_rows}
</table>

<h2>CWE Distribution</h2>
<table><tr><th>CWE</th><th>Count</th></tr>{cwe_rows}</table>

{patch_section}

<h2>Recommendations</h2>
<ul>{''.join(f'<li>{r}</li>' for r in report_data.get('recommendations',[]))}</ul>

<h2>Taint Chains ({len(report_data.get("taint_chains",[]))})</h2>
{''.join(f'<p><code>{c.get("rule_id","")}</code> — {c.get("description","")[:120]}</p>' for c in report_data.get("taint_chains",[])[:5])}

<footer style="margin-top:3rem;color:#aaa;font-size:0.8em">
Generated by TythanAI Platform • {report_data.get('timestamp','')}
</footer>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline request/response models
# ─────────────────────────────────────────────────────────────────────────────

class AuditRequest(BaseModel):
    path: str
    confidence_threshold: float = 0.7
    baseline_findings: List[Dict[str, Any]] = Field(default_factory=list)
    skip_stages: List[str] = Field(default_factory=list)
    fetch_epss: bool = False
    detection_rules_dir: str = "reports/detection_rules"


class AuditReport(BaseModel):
    path: str
    scan_id: str
    timestamp: str
    duration_s: float
    severity_breakdown: Dict[str, int]
    cwe_stats: Dict[str, int]
    total_findings: int
    top_findings: List[Dict[str, Any]]
    taint_chains: List[Dict[str, Any]]
    dep_vulns: List[Dict[str, Any]]
    detection_rules: Dict[str, Any] = Field(default_factory=dict)
    patch: Optional[Dict[str, Any]] = None
    recommendations: List[str]
    scanner_log: List[Dict[str, Any]]
    all_findings: List[Dict[str, Any]]
    html_report_path: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Main pipeline
# ─────────────────────────────────────────────────────────────────────────────

class DefensiveLifecyclePipeline:
    """Runs all 6 stages of the defensive lifecycle audit."""

    def __init__(self) -> None:
        self._verifier = ContextVerifier()
        self._dedup = Deduplicator()
        self._taint = TaintAnalyzer()
        self._supply = SupplyChainScanner()
        self._scorer = RiskScorer(fetch_epss=False)

    def run(self, request: AuditRequest) -> AuditReport:
        return asyncio.run(self.run_async(request))

    async def run_async(self, request: AuditRequest) -> AuditReport:
        t0 = time.time()
        path = request.path
        skip = set(request.skip_stages)
        scanner_log: List[Dict[str, Any]] = []
        all_findings: List[Finding] = []
        scan_id = str(uuid.uuid4())[:12]

        # ── Stage 1: Code Review ──────────────────────────────────────────────
        if "code_review" not in skip:
            ts = time.time()
            bandit_f, semgrep_f, custom_f = await asyncio.gather(
                _run_bandit(path),
                _run_semgrep(path),
                _run_custom_scanners(path),
            )
            stage1_raw = bandit_f + semgrep_f + custom_f
            verified = [self._verifier.verify(f) for f in stage1_raw]
            filtered = ConfidenceFilter(request.confidence_threshold).filter(verified)
            deduped = self._dedup.deduplicate(filtered)
            all_findings.extend(deduped)
            scanner_log.append({
                "stage": "code_review",
                "bandit": len(bandit_f), "semgrep": len(semgrep_f),
                "custom": len(custom_f), "after_filter": len(deduped),
                "duration_s": round(time.time() - ts, 2),
            })
            logger.info("Stage 1 complete: %d findings", len(deduped))

        # ── Stage 2: Taint Analysis ───────────────────────────────────────────
        taint_chains: List[Dict[str, Any]] = []
        if "taint" not in skip:
            ts = time.time()
            taint_f = self._taint.analyze_directory(path)
            verified_t = [self._verifier.verify(f) for f in taint_f]
            filtered_t = ConfidenceFilter(request.confidence_threshold).filter(verified_t)
            all_findings.extend(filtered_t)
            taint_chains = [f.model_dump() for f in filtered_t]
            scanner_log.append({
                "stage": "taint_analysis", "findings": len(filtered_t),
                "duration_s": round(time.time() - ts, 2),
            })
            logger.info("Stage 2 complete: %d taint findings", len(filtered_t))

        # ── Stage 3: Dependency Audit ─────────────────────────────────────────
        dep_findings: List[Dict[str, Any]] = []
        if "deps" not in skip:
            ts = time.time()
            dep_result = self._supply.scan(path)
            dep_findings = dep_result.get("findings", [])
            for df in dep_findings:
                pkg = df.get("package", "")
                if pkg and not _ast_uses_import(path, pkg):
                    df["severity"] = "INFO"
                    df["_note"] = "package not actively imported in source"
            scanner_log.append({
                "stage": "dependency_audit", "findings": len(dep_findings),
                "duration_s": round(time.time() - ts, 2),
            })
            logger.info("Stage 3 complete: %d dep findings", len(dep_findings))

        # ── Stage 4: Detection Engineering ───────────────────────────────────
        detection_rules: Dict[str, Any] = {}
        if "detection" not in skip:
            ts = time.time()
            detection_rules = _generate_detection_rules(
                all_findings, request.detection_rules_dir
            )
            scanner_log.append({
                "stage": "detection_engineering",
                "sigma_rules": len(detection_rules.get("sigma_rules", [])),
                "yara_rules": len(detection_rules.get("yara_rules", [])),
                "duration_s": round(time.time() - ts, 2),
            })
            logger.info("Stage 4 complete: %d rules generated", detection_rules.get("total_generated", 0))

        # ── Stage 5: Patch Validation ─────────────────────────────────────────
        patch_report_dict: Optional[Dict[str, Any]] = None
        if "patch" not in skip and request.baseline_findings:
            ts = time.time()
            baseline = findings_from_dicts(request.baseline_findings)
            patch = _compare_baselines(baseline, all_findings)
            patch_report_dict = patch.model_dump()
            if patch.regression:
                logger.warning(
                    "REGRESSION: %d new HIGH/CRITICAL findings introduced",
                    len(patch.introduced),
                )
            scanner_log.append({
                "stage": "patch_validation",
                "fixed": len(patch.fixed), "introduced": len(patch.introduced),
                "remaining": len(patch.remaining), "regression": patch.regression,
                "duration_s": round(time.time() - ts, 2),
            })

        # ── Stage 6: Report Generation ────────────────────────────────────────
        sev_breakdown: Dict[str, int] = {
            k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        }
        cwe_stats: Dict[str, int] = {}
        for f in all_findings:
            sev_breakdown[f.severity] = sev_breakdown.get(f.severity, 0) + 1
            if f.cwe_id:
                cwe_stats[f.cwe_id] = cwe_stats.get(f.cwe_id, 0) + 1

        scored = self._scorer.score_all(all_findings)
        top_findings = [r.model_dump() for r in scored[:20]]
        recommendations = self._recommendations(sev_breakdown, cwe_stats)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        report_data = {
            "path": path, "scan_id": scan_id, "timestamp": timestamp,
            "duration_s": round(time.time() - t0, 2),
            "severity_breakdown": sev_breakdown, "cwe_stats": cwe_stats,
            "total_findings": len(all_findings), "top_findings": top_findings,
            "taint_chains": taint_chains, "dep_vulns": dep_findings,
            "detection_rules": detection_rules, "patch": patch_report_dict,
            "recommendations": recommendations, "scanner_log": scanner_log,
            "all_findings": [f.model_dump() for f in all_findings],
        }

        # Save HTML report
        html_path = ""
        try:
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)
            html_path = str(reports_dir / f"audit_{scan_id}.html")
            Path(html_path).write_text(_render_html_report(report_data))
        except Exception as exc:
            logger.warning("HTML report write failed: %s", exc)

        report_data["html_report_path"] = html_path
        logger.info("Audit complete: %d findings in %.1fs", len(all_findings), report_data["duration_s"])
        return AuditReport(**report_data)

    @staticmethod
    def _recommendations(sev: Dict[str, int], cwe: Dict[str, int]) -> List[str]:
        recs = []
        if sev.get("CRITICAL", 0):
            recs.append(f"Fix {sev['CRITICAL']} CRITICAL finding(s) before any deployment.")
        if sev.get("HIGH", 0):
            recs.append(f"Resolve {sev['HIGH']} HIGH-severity finding(s) within one sprint.")
        if "CWE-89" in cwe:
            recs.append("Use parameterized queries everywhere; never interpolate user data into SQL.")
        if "CWE-78" in cwe:
            recs.append("Remove shell=True; pass subprocess arguments as a list.")
        if "CWE-95" in cwe:
            recs.append("Eliminate eval()/exec(); validate/whitelist input at entry points.")
        if "CWE-502" in cwe:
            recs.append("Replace pickle with json/msgpack for untrusted data deserialization.")
        if "CWE-321" in cwe:
            recs.append("Remove hardcoded cryptographic keys; load from environment or KMS.")
        if "CWE-338" in cwe:
            recs.append("Use secrets.token_bytes() / os.urandom() for security-sensitive randomness.")
        if not recs:
            recs.append("No critical issues found — maintain regular scanning in CI/CD.")
        return recs


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI route registration
# ─────────────────────────────────────────────────────────────────────────────

def register_routes(app: Any) -> None:
    try:
        from fastapi import HTTPException
        from fastapi.responses import JSONResponse, HTMLResponse
    except ImportError:
        return

    pipeline = DefensiveLifecyclePipeline()

    @app.post("/api/v2/audit/full")
    async def audit_full(request: AuditRequest) -> JSONResponse:
        if not os.path.exists(request.path):
            raise HTTPException(status_code=400, detail=f"Path not found: {request.path}")
        report = await pipeline.run_async(request)
        return JSONResponse(content=report.model_dump())

    @app.get("/api/v2/audit/{scan_id}/report.html", response_class=HTMLResponse)
    async def audit_html(scan_id: str) -> HTMLResponse:
        html_file = Path("reports") / f"audit_{scan_id}.html"
        if not html_file.exists():
            raise HTTPException(status_code=404, detail="Report not found")
        return HTMLResponse(content=html_file.read_text())


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def cli_audit_full(
    path: str,
    output: Optional[str] = None,
    threshold: float = 0.7,
    skip: Optional[List[str]] = None,
) -> int:
    if not os.path.exists(path):
        print(f"ERROR: path not found: {path}")
        return 2

    pipeline = DefensiveLifecyclePipeline()
    request = AuditRequest(
        path=path,
        confidence_threshold=threshold,
        skip_stages=skip or [],
    )
    print(f"Running full audit on: {path}")
    report = pipeline.run(request)
    result = report.model_dump()

    if output:
        Path(output).write_text(json.dumps(result, indent=2))
        print(f"JSON report: {output}")
    if report.html_report_path:
        print(f"HTML report: {report.html_report_path}")

    total = report.total_findings
    crit = report.severity_breakdown.get("CRITICAL", 0)
    high = report.severity_breakdown.get("HIGH", 0)
    print(f"\n[Summary] total={total} critical={crit} high={high} duration={report.duration_s:.1f}s")
    return 1 if total > 0 else 0


async def run_full_audit(
    path: str,
    confidence_threshold: float = 0.7,
    skip_stages: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Convenience coroutine — run the full pipeline and return the report dict."""
    pipeline = DefensiveLifecyclePipeline()
    request = AuditRequest(
        path=path,
        confidence_threshold=confidence_threshold,
        skip_stages=skip_stages or [],
    )
    report = await pipeline.run_async(request)
    return report.model_dump()
