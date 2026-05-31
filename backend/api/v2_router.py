"""
backend/api/v2_router.py — FastAPI v2 router for TythanAI TythanAI.

Exposes all 15 scanner/analysis modules under /api/v2/ with:
  POST /api/v2/scan/taint         — taint analysis
  POST /api/v2/scan/supply-chain  — dependency vulnerability scan
  POST /api/v2/scan/git-secrets   — git secrets scan
  POST /api/v2/scan/infra         — infra/Dockerfile/k8s scan
  POST /api/v2/scan/crypto        — cryptographic weakness scan
  POST /api/v2/scan/auth          — auth/IDOR checker
  POST /api/v2/scan/headers       — security headers checker
  POST /api/v2/scan/malware       — static malware pre-analysis
  POST /api/v2/scan/dynamic       — Docker-sandbox dynamic analysis
  POST /api/v2/audit/full         — full 6-stage defensive lifecycle
  GET  /api/v2/audit/{scan_id}/report.html  — HTML audit report
  GET  /api/v2/graph/dependency   — dependency graph (DOT/JSON)
  POST /api/v2/rules/generate     — auto-generate Semgrep rules
  POST /api/v2/agent/run          — run ReAct agent on a finding list
  GET  /metrics                   — Prometheus metrics
  WS   /ws/scan-progress          — streaming scan progress
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

from backend.core.confidence import Finding, findings_from_dicts
from backend.telemetry import prometheus as _prom

logger = logging.getLogger("tythanai.v2_router")

router = APIRouter(prefix="/api/v2", tags=["v2"])

# ─────────────────────────────────────────────────────────────────────────────
# Request / Response models
# ─────────────────────────────────────────────────────────────────────────────


class ScanRequest(BaseModel):
    path: str = Field(..., description="Absolute or relative path to scan (file or directory)")
    confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    include_test_files: bool = False


class FindingsResponse(BaseModel):
    scan_id: str
    scanner: str
    path: str
    findings: List[Dict[str, Any]]
    total: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class AuditRequest(BaseModel):
    path: str
    confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    skip_stages: List[str] = Field(default_factory=list)


class GraphRequest(BaseModel):
    path: str
    format: str = Field(default="json", pattern="^(json|dot|svg)$")
    max_depth: int = Field(default=5, ge=1, le=20)


class RuleGenRequest(BaseModel):
    findings: List[Dict[str, Any]]
    output_dir: str = "rules/generated"


class AgentRequest(BaseModel):
    findings: List[Dict[str, Any]]
    session_id: Optional[str] = None
    max_iterations: int = Field(default=10, ge=1, le=50)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _sev_counts(findings: List[Finding]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        key = f.severity.lower()
        if key in counts:
            counts[key] += 1
    return counts


def _make_response(
    scanner: str,
    path: str,
    findings: List[Finding],
) -> FindingsResponse:
    counts = _sev_counts(findings)
    return FindingsResponse(
        scan_id=str(uuid.uuid4()),
        scanner=scanner,
        path=path,
        findings=[f.model_dump() for f in findings],
        total=len(findings),
        **counts,
    )


def _resolve_path(path: str) -> str:
    """Resolve path; raise 400 if it doesn't exist."""
    p = Path(path)
    if not p.exists():
        raise HTTPException(status_code=400, detail=f"Path does not exist: {path}")
    return str(p.resolve())


# ─────────────────────────────────────────────────────────────────────────────
# Taint analysis
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/scan/taint", response_model=FindingsResponse)
async def scan_taint(req: ScanRequest) -> FindingsResponse:
    """Run AST-based taint analysis on Python source files."""
    path = _resolve_path(req.path)
    with _prom.scan_timer("taint"):
        from backend.scanners.taint_analyzer import TaintAnalyzer
        from backend.core.confidence import ConfidenceFilter, ContextVerifier, Deduplicator

        analyzer = TaintAnalyzer(confidence_threshold=req.confidence_threshold)
        p = Path(path)
        raw: List[Finding] = []
        if p.is_file():
            raw = analyzer.analyze_file(path)
        else:
            for py_file in p.rglob("*.py"):
                raw.extend(analyzer.analyze_file(str(py_file)))

        verifier = ContextVerifier()
        deduplicator = Deduplicator()
        cf = ConfidenceFilter(threshold=req.confidence_threshold)

        findings = cf.filter(
            deduplicator.deduplicate(
                [verifier.verify(f) for f in raw]
            )
        )

    _prom.record_scan("taint")
    _prom.record_findings(findings, "taint")
    return _make_response("taint", path, findings)


# ─────────────────────────────────────────────────────────────────────────────
# Supply chain
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/scan/supply-chain", response_model=FindingsResponse)
async def scan_supply_chain(req: ScanRequest) -> FindingsResponse:
    """Scan dependency manifests for vulnerabilities and typosquatting."""
    path = _resolve_path(req.path)
    with _prom.scan_timer("supply_chain"):
        from backend.scanners.supply_chain import SupplyChainScanner
        scanner = SupplyChainScanner()
        result = scanner.scan(path)
        findings_raw = result.get("findings", [])
        findings = findings_from_dicts(findings_raw) if findings_raw and isinstance(findings_raw[0], dict) else findings_raw

    _prom.record_scan("supply_chain")
    _prom.record_findings(findings, "supply_chain")
    return _make_response("supply_chain", path, findings)


# ─────────────────────────────────────────────────────────────────────────────
# Git secrets
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/scan/git-secrets", response_model=FindingsResponse)
async def scan_git_secrets(req: ScanRequest) -> FindingsResponse:
    """Scan git history and working tree for leaked secrets."""
    path = _resolve_path(req.path)
    with _prom.scan_timer("git_secrets"):
        from backend.scanners.git_secrets import GitSecretsScanner
        scanner = GitSecretsScanner()
        result = scanner.scan(path)
        raw = result.get("findings", [])
        findings = findings_from_dicts(raw) if raw and isinstance(raw[0], dict) else raw

    _prom.record_scan("git_secrets")
    _prom.record_findings(findings, "git_secrets")
    return _make_response("git_secrets", path, findings)


# ─────────────────────────────────────────────────────────────────────────────
# Infrastructure scanner
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/scan/infra", response_model=FindingsResponse)
async def scan_infra(req: ScanRequest) -> FindingsResponse:
    """Scan Dockerfiles, GitHub Actions, and Kubernetes manifests."""
    path = _resolve_path(req.path)
    with _prom.scan_timer("infra"):
        from backend.scanners.infra_scanner import InfraScanner
        scanner = InfraScanner()
        p = Path(path)
        if p.is_file():
            findings = scanner.scan_file(path)
        else:
            findings = scanner.scan_directory(path)

    _prom.record_scan("infra")
    _prom.record_findings(findings, "infra")
    return _make_response("infra", path, findings)


# ─────────────────────────────────────────────────────────────────────────────
# Crypto checker
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/scan/crypto", response_model=FindingsResponse)
async def scan_crypto(req: ScanRequest) -> FindingsResponse:
    """Detect weak cryptographic primitives (MD5, SHA1, ECB, DES, etc.)."""
    path = _resolve_path(req.path)
    with _prom.scan_timer("crypto"):
        from backend.scanners.crypto_checker import CryptoChecker
        checker = CryptoChecker()
        p = Path(path)
        if p.is_file():
            findings = checker.scan_file(path)
        else:
            findings = checker.scan_directory(path)

    _prom.record_scan("crypto")
    _prom.record_findings(findings, "crypto")
    return _make_response("crypto", path, findings)


# ─────────────────────────────────────────────────────────────────────────────
# Auth checker
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/scan/auth", response_model=FindingsResponse)
async def scan_auth(req: ScanRequest) -> FindingsResponse:
    """Check FastAPI routers for missing auth dependencies and IDOR patterns."""
    path = _resolve_path(req.path)
    with _prom.scan_timer("auth"):
        from backend.scanners.auth_checker import scan_file, scan_directory
        p = Path(path)
        if p.is_file():
            findings = scan_file(path)
        else:
            findings = scan_directory(path)

    _prom.record_scan("auth")
    _prom.record_findings(findings, "auth")
    return _make_response("auth", path, findings)


# ─────────────────────────────────────────────────────────────────────────────
# Headers checker
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/scan/headers", response_model=FindingsResponse)
async def scan_headers(req: ScanRequest) -> FindingsResponse:
    """Check FastAPI apps for missing/misconfigured security headers and CORS."""
    path = _resolve_path(req.path)
    with _prom.scan_timer("headers"):
        from backend.scanners.headers_checker import scan_file, scan_directory
        p = Path(path)
        if p.is_file():
            findings = scan_file(path)
        else:
            findings = scan_directory(path)

    _prom.record_scan("headers")
    _prom.record_findings(findings, "headers")
    return _make_response("headers", path, findings)


# ─────────────────────────────────────────────────────────────────────────────
# Malware analyzer
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/scan/malware", response_model=FindingsResponse)
async def scan_malware(req: ScanRequest) -> FindingsResponse:
    """Static malware pre-analysis (entropy, obfuscation, suspicious patterns)."""
    path = _resolve_path(req.path)
    with _prom.scan_timer("malware"):
        from backend.sandbox.malware_analyzer import MalwareAnalyzer
        analyzer = MalwareAnalyzer()
        p = Path(path)
        if p.is_file():
            report = analyzer.analyze(path)
            findings = report.findings
        else:
            findings = []
            for f in p.rglob("*.py"):
                rep = analyzer.analyze(str(f))
                findings.extend(rep.findings)

    _prom.record_scan("malware")
    _prom.record_findings(findings, "malware")
    return _make_response("malware", path, findings)


# ─────────────────────────────────────────────────────────────────────────────
# Dynamic analyzer
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/scan/dynamic")
async def scan_dynamic(req: ScanRequest) -> Dict[str, Any]:
    """Run code in an isolated Docker sandbox and report anomalies."""
    path = _resolve_path(req.path)
    with _prom.scan_timer("dynamic"):
        from backend.sandbox.dynamic_analyzer import DynamicAnalyzer
        analyzer = DynamicAnalyzer()
        report = await asyncio.get_event_loop().run_in_executor(
            None, analyzer.analyze, path
        )

    _prom.record_scan("dynamic")
    return report.model_dump()


# ─────────────────────────────────────────────────────────────────────────────
# Full audit pipeline
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/audit/full")
async def audit_full(req: AuditRequest) -> Dict[str, Any]:
    """Run the complete 6-stage defensive lifecycle pipeline."""
    path = _resolve_path(req.path)
    with _prom.scan_timer("pipeline_full"):
        from backend.pipeline.defensive_lifecycle import run_full_audit
        report = await run_full_audit(
            path=path,
            confidence_threshold=req.confidence_threshold,
            skip_stages=req.skip_stages,
        )

    _prom.record_scan("pipeline_full")
    return report


@router.get("/audit/{scan_id}/report.html", response_class=HTMLResponse)
async def get_html_report(scan_id: str) -> HTMLResponse:
    """Retrieve the HTML report for a completed audit."""
    reports_dir = Path("reports")
    report_file = reports_dir / f"{scan_id}.html"
    if not report_file.exists():
        raise HTTPException(status_code=404, detail=f"Report not found: {scan_id}")
    return HTMLResponse(content=report_file.read_text(encoding="utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# Dependency graph
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/graph/dependency")
async def dependency_graph(req: GraphRequest) -> Dict[str, Any]:
    """Build and return the dependency/call graph for a Python project."""
    path = _resolve_path(req.path)
    from backend.analysis.dependency_graph import DependencyGraphBuilder
    builder = DependencyGraphBuilder()
    graph = builder.build(path, max_depth=req.max_depth)

    if req.format == "dot":
        dot_str = builder.to_dot(graph)
        return {"format": "dot", "content": dot_str}
    elif req.format == "svg":
        svg_str = builder.to_svg(graph)
        return {"format": "svg", "content": svg_str}
    else:
        return {"format": "json", "graph": graph.model_dump() if hasattr(graph, "model_dump") else graph}


# ─────────────────────────────────────────────────────────────────────────────
# Rule generator
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/rules/generate")
async def generate_rules(req: RuleGenRequest) -> Dict[str, Any]:
    """Auto-generate Semgrep rules from a list of confirmed findings."""
    findings = findings_from_dicts(req.findings)
    from backend.agents.rule_generator import RuleGenerator
    generator = RuleGenerator()
    rules = generator.generate(findings, output_dir=req.output_dir)
    return {
        "rules_generated": len(rules),
        "rules": [r.model_dump() for r in rules],
    }


# ─────────────────────────────────────────────────────────────────────────────
# ReAct agent
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/agent/run")
async def run_agent(req: AgentRequest) -> Dict[str, Any]:
    """Run the ReAct agent to re-evaluate and enrich a finding list."""
    findings = findings_from_dicts(req.findings)
    session_id = req.session_id or str(uuid.uuid4())

    from backend.agents.react_agent import ReactAgent
    agent = ReactAgent(session_id=session_id, max_iterations=req.max_iterations)
    result = await agent.run(findings)

    from backend.telemetry.prometheus import agent_iterations
    agent_iterations.set(result.get("iterations", 0))

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Prometheus metrics endpoint
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/metrics", include_in_schema=False)
async def prometheus_metrics() -> Response:
    """Prometheus scrape endpoint."""
    body, content_type = _prom.metrics_response()
    return Response(content=body, media_type=content_type)


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket — streaming scan progress
# ─────────────────────────────────────────────────────────────────────────────


_ws_connections: Dict[str, WebSocket] = {}


@router.websocket("/ws/scan-progress")
async def ws_scan_progress(websocket: WebSocket) -> None:
    """
    WebSocket endpoint for real-time scan progress streaming.

    Client sends: {"path": "...", "scanners": ["taint", "supply_chain", ...]}
    Server emits: {"event": "progress"|"finding"|"done"|"error", ...}
    """
    await websocket.accept()
    session_id = str(uuid.uuid4())
    _ws_connections[session_id] = websocket
    logger.info("WS scan-progress session started: %s", session_id)

    try:
        msg = await websocket.receive_text()
        try:
            params = json.loads(msg)
        except json.JSONDecodeError:
            await websocket.send_json({"event": "error", "message": "Invalid JSON"})
            return

        path = params.get("path", "")
        requested_scanners = params.get("scanners", ["taint", "supply_chain", "git_secrets"])

        if not path or not Path(path).exists():
            await websocket.send_json({"event": "error", "message": f"Path not found: {path}"})
            return

        await websocket.send_json({
            "event": "started",
            "session_id": session_id,
            "path": path,
            "scanners": requested_scanners,
        })

        all_findings: List[Dict[str, Any]] = []

        scanner_map = {
            "taint": _ws_run_taint,
            "supply_chain": _ws_run_supply_chain,
            "git_secrets": _ws_run_git_secrets,
            "infra": _ws_run_infra,
            "crypto": _ws_run_crypto,
            "auth": _ws_run_auth,
            "headers": _ws_run_headers,
            "malware": _ws_run_malware,
        }

        for scanner_name in requested_scanners:
            if scanner_name not in scanner_map:
                await websocket.send_json({
                    "event": "warning",
                    "message": f"Unknown scanner: {scanner_name}",
                })
                continue

            await websocket.send_json({
                "event": "progress",
                "scanner": scanner_name,
                "status": "running",
            })

            try:
                findings = await scanner_map[scanner_name](path)
                all_findings.extend(findings)
                await websocket.send_json({
                    "event": "progress",
                    "scanner": scanner_name,
                    "status": "done",
                    "findings_count": len(findings),
                })
                # Stream individual findings
                for f in findings:
                    await websocket.send_json({"event": "finding", "finding": f})

            except Exception as exc:
                logger.exception("Scanner %s failed: %s", scanner_name, exc)
                await websocket.send_json({
                    "event": "error",
                    "scanner": scanner_name,
                    "message": str(exc),
                })

        await websocket.send_json({
            "event": "done",
            "session_id": session_id,
            "total_findings": len(all_findings),
        })

    except WebSocketDisconnect:
        logger.info("WS session %s disconnected", session_id)
    except Exception as exc:
        logger.exception("WS session %s error: %s", session_id, exc)
        try:
            await websocket.send_json({"event": "error", "message": str(exc)})
        except Exception:
            pass
    finally:
        _ws_connections.pop(session_id, None)


# ─────────────────────────────────────────────────────────────────────────────
# Internal WS scanner runners (async wrappers)
# ─────────────────────────────────────────────────────────────────────────────


async def _ws_run_taint(path: str) -> List[Dict[str, Any]]:
    from backend.scanners.taint_analyzer import TaintAnalyzer
    from backend.core.confidence import ConfidenceFilter, ContextVerifier, Deduplicator

    analyzer = TaintAnalyzer(confidence_threshold=0.5)
    p = Path(path)
    raw: List[Finding] = []
    if p.is_file():
        raw = await asyncio.get_event_loop().run_in_executor(None, analyzer.analyze_file, path)
    else:
        for py_file in p.rglob("*.py"):
            raw.extend(await asyncio.get_event_loop().run_in_executor(None, analyzer.analyze_file, str(py_file)))

    findings = ConfidenceFilter(0.5).filter(
        Deduplicator().deduplicate([ContextVerifier().verify(f) for f in raw])
    )
    return [f.model_dump() for f in findings]


async def _ws_run_supply_chain(path: str) -> List[Dict[str, Any]]:
    from backend.scanners.supply_chain import SupplyChainScanner
    scanner = SupplyChainScanner()
    result = await asyncio.get_event_loop().run_in_executor(None, scanner.scan, path)
    raw = result.get("findings", [])
    return raw if raw and isinstance(raw[0], dict) else [f.model_dump() for f in raw]


async def _ws_run_git_secrets(path: str) -> List[Dict[str, Any]]:
    from backend.scanners.git_secrets import GitSecretsScanner
    scanner = GitSecretsScanner()
    result = await asyncio.get_event_loop().run_in_executor(None, scanner.scan, path)
    raw = result.get("findings", [])
    return raw if raw and isinstance(raw[0], dict) else [f.model_dump() for f in raw]


async def _ws_run_infra(path: str) -> List[Dict[str, Any]]:
    from backend.scanners.infra_scanner import InfraScanner
    scanner = InfraScanner()
    p = Path(path)
    if p.is_file():
        fn = scanner.scan_file
    else:
        fn = scanner.scan_directory
    findings = await asyncio.get_event_loop().run_in_executor(None, fn, path)
    return [f.model_dump() for f in findings]


async def _ws_run_crypto(path: str) -> List[Dict[str, Any]]:
    from backend.scanners.crypto_checker import CryptoChecker
    checker = CryptoChecker()
    p = Path(path)
    if p.is_file():
        findings = await asyncio.get_event_loop().run_in_executor(None, checker.scan_file, path)
    else:
        findings = await asyncio.get_event_loop().run_in_executor(None, checker.scan_directory, path)
    return [f.model_dump() for f in findings]


async def _ws_run_auth(path: str) -> List[Dict[str, Any]]:
    from backend.scanners.auth_checker import scan_file, scan_directory
    p = Path(path)
    if p.is_file():
        findings = await asyncio.get_event_loop().run_in_executor(None, scan_file, path)
    else:
        findings = await asyncio.get_event_loop().run_in_executor(None, scan_directory, path)
    return [f.model_dump() for f in findings]


async def _ws_run_headers(path: str) -> List[Dict[str, Any]]:
    from backend.scanners.headers_checker import scan_file, scan_directory
    p = Path(path)
    if p.is_file():
        findings = await asyncio.get_event_loop().run_in_executor(None, scan_file, path)
    else:
        findings = await asyncio.get_event_loop().run_in_executor(None, scan_directory, path)
    return [f.model_dump() for f in findings]


async def _ws_run_malware(path: str) -> List[Dict[str, Any]]:
    from backend.sandbox.malware_analyzer import MalwareAnalyzer
    analyzer = MalwareAnalyzer()
    p = Path(path)
    findings: List[Finding] = []
    if p.is_file():
        rep = await asyncio.get_event_loop().run_in_executor(None, analyzer.analyze, path)
        findings = rep.findings
    else:
        for f in p.rglob("*.py"):
            rep = await asyncio.get_event_loop().run_in_executor(None, analyzer.analyze, str(f))
            findings.extend(rep.findings)
    return [f.model_dump() for f in findings]


# ─────────────────────────────────────────────────────────────────────────────
# TythanAI Phase 16 — Advanced Intelligence Routes
# ─────────────────────────────────────────────────────────────────────────────


class SkillSearchRequest(BaseModel):
    q: str = Field(..., description="Search query for skills")
    top_n: int = Field(default=5, ge=1, le=20)
    domain: Optional[str] = None
    framework: Optional[str] = None
    framework_id: Optional[str] = None


class ThreatHuntRequest(BaseModel):
    findings: List[Dict[str, Any]]
    project_root: Optional[str] = None


class IRPlaybookRequest(BaseModel):
    finding: Dict[str, Any]
    risk_score: float = Field(default=80.0, ge=0.0, le=100.0)
    scan_id: Optional[str] = None


class PatchValidateRequest(BaseModel):
    baseline_findings: List[Dict[str, Any]]
    current_findings: List[Dict[str, Any]]
    project_root: Optional[str] = None


class CrossRepoRequest(BaseModel):
    repo_paths: List[str]


@router.get("/skills/search")
async def search_skills(q: str = Query(...), top_n: int = Query(default=5, ge=1, le=20),
                        domain: Optional[str] = Query(default=None),
                        framework: Optional[str] = Query(default=None),
                        framework_id: Optional[str] = Query(default=None)) -> Dict[str, Any]:
    """Search cybersecurity skills by query, domain, or framework mapping."""
    try:
        from backend.agents.skills_loader import SkillsLoader
        loader = SkillsLoader()
        if framework and framework_id:
            results = loader.search_by_framework(framework, framework_id)
        elif domain:
            results = loader.search_by_domain(domain)
        else:
            results = loader.scan_all(q, top_n=top_n)
        return {
            "query": q,
            "total": len(results),
            "skills": [{"skill_id": s.skill_id, "name": s.name, "domain": s.domain,
                        "tags": s.tags, "mitre_ids": s.mitre_ids} for s in results],
        }
    except Exception as exc:
        logger.exception("skills search failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/audit/threat-hunt")
async def threat_hunt(req: ThreatHuntRequest) -> Dict[str, Any]:
    """Run hypothesis-driven threat hunting on a list of findings."""
    try:
        from backend.core.confidence import Finding as F
        from backend.agents.threat_hunter import ThreatHunterAgent
        findings = []
        for fd in req.findings:
            try:
                findings.append(F(**fd))
            except Exception:
                pass
        root = Path(req.project_root) if req.project_root else None
        agent = ThreatHunterAgent()
        report = await asyncio.get_event_loop().run_in_executor(
            None, agent.hunt, findings, root
        )
        return {
            "scan_id": report.scan_id,
            "hypotheses_generated": report.hypotheses_generated,
            "hypotheses_confirmed": report.hypotheses_confirmed,
            "lotl_patterns": report.lotl_patterns,
            "sigma_rules_count": len(report.sigma_rules),
            "results": [
                {
                    "description": r.hypothesis.description,
                    "attck_technique": r.hypothesis.attck_technique,
                    "confirmed": r.confirmed,
                    "evidence": r.evidence[:5],
                }
                for r in report.results
            ],
        }
    except Exception as exc:
        logger.exception("threat hunt failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/ir-playbook/{scan_id}")
async def get_ir_playbook(scan_id: str) -> Dict[str, Any]:
    """Retrieve a previously generated IR playbook by scan_id."""
    playbook_dir = Path("/tmp/reports/ir_playbooks")
    matches = list(playbook_dir.glob(f"*{scan_id}*.md")) if playbook_dir.exists() else []
    if not matches:
        raise HTTPException(status_code=404, detail=f"No playbook found for scan_id={scan_id}")
    content = matches[0].read_text()
    return {"scan_id": scan_id, "playbook_path": str(matches[0]), "content": content}


@router.post("/ir-playbook/generate")
async def generate_ir_playbook(req: IRPlaybookRequest) -> Dict[str, Any]:
    """Generate an IR playbook for a single finding."""
    try:
        from backend.core.confidence import Finding as F
        from backend.agents.ir_playbook import IRPlaybookGenerator
        finding = F(**req.finding)
        scan_id = req.scan_id or str(uuid.uuid4())[:8]
        gen = IRPlaybookGenerator()
        playbook = gen.generate(finding, risk_score=req.risk_score, scan_id=scan_id)
        saved_path = gen.save(playbook)
        return {
            "scan_id": scan_id,
            "playbook_id": playbook.playbook_id,
            "vulnerability_type": playbook.vulnerability_type,
            "severity": playbook.severity,
            "attck_ids": playbook.attck_ids,
            "steps_count": len(playbook.steps),
            "saved_path": str(saved_path),
            "markdown": playbook.to_markdown(),
        }
    except Exception as exc:
        logger.exception("ir playbook generation failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/patch-validate")
async def patch_validate(req: PatchValidateRequest) -> Dict[str, Any]:
    """Compare baseline vs current findings to validate a patch."""
    try:
        from backend.core.confidence import Finding as F
        from backend.core.patch_validator import PatchValidator
        baseline = [F(**f) for f in req.baseline_findings if isinstance(f, dict)]
        current = [F(**f) for f in req.current_findings if isinstance(f, dict)]
        root = Path(req.project_root) if req.project_root else None
        validator = PatchValidator()
        report = await asyncio.get_event_loop().run_in_executor(
            None, validator.validate, baseline, current, root
        )
        return {
            "validation_id": report.validation_id,
            "fixed": report.fixed_count,
            "remaining": report.remaining_count,
            "regressed": report.regressed_count,
            "partial": report.partial_count,
            "patch_effectiveness": report.patch_effectiveness,
            "verdict": report.verdict,
            "summary": report.summary_line(),
        }
    except Exception as exc:
        logger.exception("patch validation failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/threat-intel/{cve_id}")
async def get_threat_intel(cve_id: str, refresh: bool = Query(default=False)) -> Dict[str, Any]:
    """Get aggregated threat intelligence for a CVE ID."""
    try:
        from backend.intelligence.threat_intel_aggregator import ThreatIntelAggregator
        agg = ThreatIntelAggregator()
        intel = await asyncio.get_event_loop().run_in_executor(
            None, agg.aggregate, cve_id, refresh
        )
        return intel.model_dump()
    except Exception as exc:
        logger.exception("threat intel lookup failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/adversarial-test")
async def adversarial_test() -> Dict[str, Any]:
    """Run adversarial input simulation against own endpoints (ENV=test only)."""
    import os
    env = os.getenv("ENV", "test")
    if env.lower() not in ("test", "staging"):
        raise HTTPException(status_code=403, detail="Adversarial testing only available in ENV=test or ENV=staging")
    try:
        from backend.agents.adversarial_simulator import AdversarialSimulator
        sim = AdversarialSimulator()
        report = await asyncio.get_event_loop().run_in_executor(None, sim.run)
        return {
            "simulation_id": report.simulation_id,
            "environment": report.environment,
            "total_tests": report.total_tests,
            "passed": report.passed,
            "failed": report.failed,
            "failure_rate": report.failure_rate,
            "failures": [f.model_dump() for f in report.failures[:10]],
        }
    except Exception as exc:
        logger.exception("adversarial simulation failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/cross-repo-taint")
async def cross_repo_taint(req: CrossRepoRequest) -> Dict[str, Any]:
    """Analyze taint flows between multiple repositories/microservices."""
    try:
        from backend.analysis.cross_repo_taint import CrossRepoTaintAnalyzer
        analyzer = CrossRepoTaintAnalyzer()
        paths = [Path(p) for p in req.repo_paths]
        report = await asyncio.get_event_loop().run_in_executor(
            None, analyzer.analyze, paths
        )
        return {
            "analysis_id": report.analysis_id,
            "repos_analyzed": report.repos_analyzed,
            "total_paths": report.total_paths,
            "unsanitized_paths": report.unsanitized_paths,
            "critical_paths": report.critical_paths,
            "shared_databases": report.shared_databases,
            "taint_paths": [p.model_dump() for p in report.taint_paths[:20]],
        }
    except Exception as exc:
        logger.exception("cross repo taint failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Phase 18: Memory, Knowledge, Multi-Agent, Explainability, Chain Analysis
# ─────────────────────────────────────────────────────────────────────────────


class MultiAgentRequest(BaseModel):
    findings: List[Dict[str, Any]]
    quick_mode: bool = False


class ChainAnalysisRequest(BaseModel):
    findings: List[Dict[str, Any]]


class ExplainRequest(BaseModel):
    findings: List[Dict[str, Any]]


class FeedbackRequest(BaseModel):
    scan_id: str
    fp_fingerprints: List[str] = Field(default_factory=list)
    fn_descriptions: List[str] = Field(default_factory=list)


class MemorySearchRequest(BaseModel):
    query: str
    layer: str = "all"   # "long_term" | "semantic" | "episodic" | "all"
    top_k: int = Field(default=5, ge=1, le=20)


class RuleProposeRequest(BaseModel):
    findings: List[Dict[str, Any]]


class RuleConfirmRequest(BaseModel):
    rule_id: str


@router.post("/multi-agent/analyze")
async def multi_agent_analyze(req: MultiAgentRequest) -> Dict[str, Any]:
    """Run full 8-agent analysis pipeline on findings."""
    try:
        from backend.agents.multi_agent_orchestrator import MultiAgentOrchestrator
        findings = findings_from_dicts(req.findings)
        orchestrator = MultiAgentOrchestrator()
        if req.quick_mode:
            result = await asyncio.get_event_loop().run_in_executor(
                None, orchestrator.run_quick, findings
            )
        else:
            result = await asyncio.get_event_loop().run_in_executor(
                None, orchestrator.run, findings
            )
        return {
            "session_id": result.session_id,
            "original_count": len(result.original_findings),
            "confirmed_count": len(result.confirmed_findings),
            "removed_count": len(result.removed_findings),
            "attack_chains": result.attack_chains,
            "generated_rules": result.generated_rules,
            "precision_estimate": result.precision_estimate,
            "report_markdown": result.report_markdown,
            "plan_notes": result.plan_notes,
            "total_iterations": result.total_iterations,
        }
    except Exception as exc:
        logger.exception("multi-agent analysis failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/attack-chains/analyze")
async def attack_chain_analyze(req: ChainAnalysisRequest) -> Dict[str, Any]:
    """Analyze findings for attack chains and exploit paths."""
    try:
        from backend.analysis.chain_analyzer import analyze_attack_chains
        findings = findings_from_dicts(req.findings)
        chains = await asyncio.get_event_loop().run_in_executor(
            None, analyze_attack_chains, findings
        )
        return {
            "total_chains": len(chains),
            "critical_chains": sum(1 for c in chains if c.severity == "CRITICAL"),
            "chains": [
                {
                    "chain_id": c.chain_id,
                    "severity": c.severity,
                    "chain_type": c.chain_type,
                    "combined_risk_score": c.combined_risk_score,
                    "confidence": c.confidence,
                    "narrative": c.narrative,
                    "finding_count": len(c.finding_fingerprints),
                }
                for c in chains
            ],
        }
    except Exception as exc:
        logger.exception("attack chain analysis failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/explain/findings")
async def explain_findings(req: ExplainRequest) -> Dict[str, Any]:
    """Generate explainability reports for findings."""
    try:
        from backend.core.explainability import ExplainabilityEngine
        findings = findings_from_dicts(req.findings)
        engine = ExplainabilityEngine()
        explanations = await asyncio.get_event_loop().run_in_executor(
            None, engine.batch_explain, findings
        )
        return {
            "total_explained": len(explanations),
            "explanations": {
                fp: {
                    "why_detected": e.why_detected,
                    "reasoning_chain": e.reasoning_chain,
                    "false_positive_risk": e.false_positive_risk,
                    "confidence_explanation": {
                        "base": e.confidence_explanation.base_confidence,
                        "final": e.confidence_explanation.final_confidence,
                        "explanation": e.confidence_explanation.explanation,
                    },
                    "evidence_count": len(e.evidence),
                    "recommended_verification": e.recommended_verification,
                }
                for fp, e in explanations.items()
            },
        }
    except Exception as exc:
        logger.exception("explainability failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/learning/feedback")
async def submit_feedback(req: FeedbackRequest) -> Dict[str, Any]:
    """Submit FP/FN feedback to trigger continuous learning."""
    try:
        from backend.core.continuous_learning import ContinuousLearningCoordinator
        coordinator = ContinuousLearningCoordinator()
        count = coordinator.process_feedback(
            scan_id=req.scan_id,
            fp_fingerprints=req.fp_fingerprints,
            fn_descriptions=req.fn_descriptions,
        )
        return {
            "scan_id": req.scan_id,
            "learning_actions_taken": count,
            "fp_count": len(req.fp_fingerprints),
            "fn_count": len(req.fn_descriptions),
        }
    except Exception as exc:
        logger.exception("feedback submission failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/learning/stats")
async def learning_stats() -> Dict[str, Any]:
    """Get continuous learning statistics."""
    try:
        from backend.core.continuous_learning import ContinuousLearningCoordinator
        coordinator = ContinuousLearningCoordinator()
        stats = coordinator.get_stats()
        return {
            "total_events": stats.total_events,
            "processed_events": stats.processed_events,
            "total_scans_learned_from": stats.total_scans_learned_from,
            "total_rules_evolved": stats.total_rules_evolved,
            "total_fps_learned": stats.total_fps_learned,
            "total_confirmed_tps": stats.total_confirmed_tps,
            "current_precision": stats.current_system_precision,
            "current_recall": stats.current_system_recall,
            "last_learning_cycle": stats.last_learning_cycle,
            "knowledge_entries": stats.knowledge_entries,
        }
    except Exception as exc:
        logger.exception("learning stats failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/learning/cycle")
async def trigger_learning_cycle() -> Dict[str, Any]:
    """Manually trigger a learning cycle."""
    try:
        from backend.core.continuous_learning import ContinuousLearningCoordinator
        coordinator = ContinuousLearningCoordinator()
        result = await asyncio.get_event_loop().run_in_executor(
            None, coordinator.trigger_learning_cycle
        )
        return result
    except Exception as exc:
        logger.exception("learning cycle failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/memory/search")
async def memory_search(req: MemorySearchRequest) -> Dict[str, Any]:
    """Search the memory system across all layers."""
    try:
        from backend.memory.memory_manager import MemoryManager
        mm = MemoryManager()
        results = mm.retrieve_before_decision(req.query, top_k_per_layer=req.top_k)
        return {
            "query": req.query,
            "results": {
                layer: [
                    {
                        "entry_id": r.entry.entry_id,
                        "content": r.entry.content[:200],
                        "score": r.score,
                        "memory_type": r.entry.memory_type,
                        "timestamp": r.entry.timestamp,
                    }
                    for r in items
                ]
                for layer, items in results.items()
            },
        }
    except Exception as exc:
        logger.exception("memory search failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/memory/stats")
async def memory_stats() -> Dict[str, Any]:
    """Get memory system statistics."""
    try:
        from backend.memory.memory_manager import MemoryManager
        mm = MemoryManager()
        return mm.get_stats()
    except Exception as exc:
        logger.exception("memory stats failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/rules/evolve/propose")
async def rules_propose(req: RuleProposeRequest) -> Dict[str, Any]:
    """Propose new evolved rules from confirmed findings."""
    try:
        from backend.core.rule_evolution import RuleEvolutionSystem
        findings = findings_from_dicts(req.findings)
        evolution = RuleEvolutionSystem()
        proposals = []
        for finding in findings[:10]:  # cap at 10
            proposed = evolution.propose_rule(finding)
            proposals.append({
                "proposal_id": proposed.proposal_id,
                "rule_id": proposed.rule_id,
                "name": proposed.name,
                "status": proposed.status,
                "confidence": proposed.confidence,
                "cwe_id": proposed.cwe_id,
                "severity": proposed.severity,
            })
        return {"proposed_count": len(proposals), "proposals": proposals}
    except Exception as exc:
        logger.exception("rule proposal failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/rules/evolve/confirm")
async def rules_confirm(req: RuleConfirmRequest) -> Dict[str, Any]:
    """Confirm a proposed rule (increments confirmation count)."""
    try:
        from backend.core.rule_evolution import RuleEvolutionSystem
        evolution = RuleEvolutionSystem()
        rule = evolution.confirm_rule(req.rule_id)
        return {
            "rule_id": rule.rule_id,
            "status": rule.status,
            "confirmation_count": rule.confirmation_count,
            "confidence": rule.confidence,
        }
    except Exception as exc:
        logger.exception("rule confirm failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/rules/evolved")
async def rules_evolved_list() -> Dict[str, Any]:
    """List all evolved rules by status."""
    try:
        from backend.core.rule_evolution import RuleEvolutionSystem
        evolution = RuleEvolutionSystem()
        stats = evolution.get_stats()
        active = evolution.list_active_rules()
        proposed = evolution.list_proposed_rules()
        return {
            "stats": stats,
            "active_rules": [
                {
                    "rule_id": r.rule_id,
                    "name": r.name,
                    "cwe_id": r.cwe_id,
                    "severity": r.severity,
                    "version": r.version,
                    "benchmark_precision": r.benchmark_precision,
                }
                for r in active
            ],
            "proposed_rules": [
                {
                    "proposal_id": r.proposal_id,
                    "rule_id": r.rule_id,
                    "status": r.status,
                    "confirmation_count": r.confirmation_count,
                }
                for r in proposed
            ],
        }
    except Exception as exc:
        logger.exception("evolved rules listing failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/dataset/stats")
async def dataset_stats() -> Dict[str, Any]:
    """Get training dataset statistics."""
    try:
        from backend.core.dataset_manager import DatasetManager
        dm = DatasetManager()
        stats = dm.get_stats()
        return {
            "total_entries": stats.total_entries,
            "true_positives": stats.true_positives,
            "false_positives": stats.false_positives,
            "needs_review": stats.needs_review,
            "tp_rate": stats.tp_rate,
            "fp_rate": stats.fp_rate,
            "coverage_rules": stats.coverage_rules,
            "by_severity": stats.by_severity,
        }
    except Exception as exc:
        logger.exception("dataset stats failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Autonomous Security Copilot routes
# ─────────────────────────────────────────────────────────────────────────────


class CopilotRequest(BaseModel):
    path: str = Field(..., description="File or directory path to analyze")
    confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    generate_patches: bool = Field(default=True)


@router.post("/copilot/full-cycle")
async def copilot_full_cycle(req: CopilotRequest) -> Dict[str, Any]:
    """Run the autonomous Security Copilot full cycle: Scan→Analyze→Patch→Report."""
    try:
        from backend.agents.security_copilot import SecurityCopilot
        copilot = SecurityCopilot(confidence_threshold=req.confidence_threshold)
        report = copilot.full_cycle(req.path)
        return report
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.exception("copilot full_cycle failed")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/copilot/scan")
async def copilot_scan(req: CopilotRequest) -> Dict[str, Any]:
    """Run taint + DSL scan via the Security Copilot and return enriched findings."""
    try:
        from backend.agents.security_copilot import SecurityCopilot
        copilot = SecurityCopilot(confidence_threshold=req.confidence_threshold)
        findings = copilot.scan(req.path)
        analyzed = copilot.analyze(findings)
        return {
            "scan_id": str(uuid.uuid4()),
            "path": req.path,
            "findings_count": len(findings),
            "findings": analyzed,
        }
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.exception("copilot scan failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# GAP Analysis route
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/gap-analysis")
async def gap_analysis() -> Dict[str, Any]:
    """Run GAP analysis comparing TythanAI against Semgrep, Snyk, CodeQL, Wiz."""
    try:
        from backend.core.gap_analysis import GAPAnalyzer
        analyzer = GAPAnalyzer()
        result = analyzer.analyze()
        report_text = analyzer.format_report(result)
        return {
            "overall_score": result.overall_score,
            "our_metrics": {
                "name": result.our_metrics.name,
                "avg_precision": result.our_metrics.avg_precision,
                "avg_recall": result.our_metrics.avg_recall,
                "avg_f1": result.our_metrics.avg_f1,
                "interprocedural_depth": result.our_metrics.interprocedural_depth,
                "languages_supported": result.our_metrics.languages_supported,
            },
            "gaps": result.gaps,
            "strengths": result.strengths,
            "recommendations": result.recommendations,
            "tool_profiles": {
                name: {
                    "avg_precision": p.avg_precision,
                    "avg_recall": p.avg_recall,
                    "avg_f1": p.avg_f1,
                    "kb_rules_count": p.kb_rules_count,
                    "interprocedural_depth": p.interprocedural_depth,
                    "cloud_native": p.cloud_native,
                }
                for name, p in result.tool_profiles.items()
            },
            "report_text": report_text,
        }
    except Exception as exc:
        logger.exception("gap analysis failed")
        raise HTTPException(status_code=500, detail=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Security Knowledge Graph route
# ─────────────────────────────────────────────────────────────────────────────


class KGBuildRequest(BaseModel):
    project_root: str = Field(..., description="Root directory of the project")
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="Finding dicts to build graph from")


@router.post("/knowledge-graph/build")
async def knowledge_graph_build(req: KGBuildRequest) -> Dict[str, Any]:
    """Build a Security Knowledge Graph from findings and return graph summary."""
    try:
        from backend.analysis.knowledge_graph import KnowledgeGraphBuilder
        builder = KnowledgeGraphBuilder()
        raw_findings = findings_from_dicts(req.findings)
        graph = builder.build(project_root=req.project_root, findings=raw_findings)
        node_types: Dict[str, int] = {}
        for node in graph.nodes:
            node_types[node.type.value] = node_types.get(node.type.value, 0) + 1
        edge_types: Dict[str, int] = {}
        for edge in graph.edges:
            edge_types[edge.relation] = edge_types.get(edge.relation, 0) + 1
        return {
            "total_nodes": len(graph.nodes),
            "total_edges": len(graph.edges),
            "node_types": node_types,
            "edge_types": edge_types,
        }
    except Exception as exc:
        logger.exception("knowledge graph build failed")
        raise HTTPException(status_code=500, detail=str(exc))
