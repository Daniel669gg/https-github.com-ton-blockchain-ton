"""
Ghost Security Platform — Extension API Routes
New endpoints for:
  • Task graph orchestration
  • Confidence engine
  • CVE/CWE enrichment
  • SARIF enriched export
  • Repo indexer
  • Call graph
  • TON contract graph
  • Ollama AI runtime
  • Runtime supervisor diagnostics
  • GitHub Actions workflow generator

Mount this router in api/server.py:
    from api.routes_ext import router as ext_router
    app.include_router(ext_router, prefix="/api/v2")
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(tags=["v2"])


# ── Request models ──────────────────────────────────────────────────────────────

class EnrichRequest(BaseModel):
    findings: List[dict]
    online: bool = False   # CVE live lookup (requires network)

class ConfidenceRequest(BaseModel):
    findings: List[dict]
    fp_threshold: float = 0.50

class IndexRequest(BaseModel):
    path: str

class CallGraphRequest(BaseModel):
    path: str
    format: str = "json"   # json | dot

class TONGraphRequest(BaseModel):
    path: str

class OllamaRequest(BaseModel):
    task: str                   # reasoning | remediation | explain | summarise | threat_model
    prompt: Optional[str] = None
    finding: Optional[dict] = None
    findings: Optional[List[dict]] = None
    code_context: Optional[str] = None
    target: Optional[str] = ""

class SARIFRequest(BaseModel):
    report: dict
    repo_root: str = "."

class GraphPipelineRequest(BaseModel):
    path: str
    scanners: Optional[List[str]] = None
    max_concurrent: int = 4

class WorkflowRequest(BaseModel):
    scan_type: str = "all"


# ── Confidence + FP Reduction ───────────────────────────────────────────────────

@router.post("/confidence/process")
async def confidence_process(req: ConfidenceRequest):
    """Score, deduplicate and prioritise findings via ConfidenceEngine."""
    from verifier.confidence_engine import ConfidenceEngine
    engine = ConfidenceEngine(fp_threshold=req.fp_threshold)
    result = engine.process(req.findings)
    return result


@router.post("/confidence/explain")
async def confidence_explain(body: dict):
    """Explain the confidence decision for a single finding."""
    from verifier.confidence_engine import ConfidenceEngine
    finding = body.get("finding")
    if not finding:
        raise HTTPException(status_code=400, detail="'finding' required")
    engine = ConfidenceEngine()
    return {"explanation": engine.explain(finding)}


# ── CVE / CWE / OWASP Enrichment ───────────────────────────────────────────────

@router.post("/enrich/cve")
async def enrich_cve(req: EnrichRequest):
    """Enrich findings with CWE, OWASP, and optionally live CVE data."""
    from core.knowledge.cve_enricher import CVEEnricher
    enricher = CVEEnricher(online=req.online)
    enriched = enricher.enrich(req.findings)
    summary  = enricher.summary(enriched)
    return {"findings": enriched, "summary": summary, "enriched_count": len(enriched)}


@router.post("/enrich/deps")
async def enrich_deps(body: dict):
    """Enrich dependency findings with live CVE lookup via osv.dev."""
    from core.knowledge.cve_enricher import CVEEnricher
    findings = body.get("findings", [])
    if not findings:
        raise HTTPException(status_code=400, detail="'findings' required")
    enricher = CVEEnricher(online=body.get("online", True))
    return {"findings": enricher.enrich_deps(findings)}


@router.get("/enrich/cwe/{cwe_id}")
async def cwe_info(cwe_id: str):
    """Get CWE metadata for a given CWE-NNN identifier."""
    from core.knowledge.cve_enricher import CVEEnricher
    full_id = cwe_id if cwe_id.upper().startswith("CWE-") else f"CWE-{cwe_id}"
    info    = CVEEnricher(online=False).cwe_info(full_id)
    if info.get("name") == "Unknown":
        raise HTTPException(status_code=404, detail=f"{full_id} not in embedded DB")
    return {"id": full_id, **info}


# ── Repository Indexer ──────────────────────────────────────────────────────────

@router.post("/repo/index")
async def repo_index(req: IndexRequest):
    """Full semantic index: language stats, heatmap, deps, fingerprint."""
    from core.indexing.repo_indexer import RepoIndexer
    if not Path(req.path).exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {req.path}")
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, RepoIndexer().index, req.path)
    return result


@router.post("/repo/heatmap")
async def repo_heatmap(req: IndexRequest):
    """Return only the risk heatmap for a repository (fast)."""
    from core.indexing.repo_indexer import RepoIndexer
    if not Path(req.path).exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {req.path}")
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, RepoIndexer().index, req.path)
    return {
        "path":               result["path"],
        "fingerprint":        result["fingerprint"],
        "risk_heatmap":       result["risk_heatmap"],
        "overall_risk_score": result["overall_risk_score"],
        "risk_level":         result["risk_level"],
    }


# ── Call Graph ─────────────────────────────────────────────────────────────────

@router.post("/analysis/callgraph")
async def call_graph(req: CallGraphRequest):
    """Generate Python AST call graph. Returns JSON or DOT format."""
    from core.analysis.call_graph import CallGraphGenerator
    if not Path(req.path).exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {req.path}")
    loop  = asyncio.get_running_loop()
    gen   = CallGraphGenerator()
    graph = await loop.run_in_executor(None, gen.build, req.path)
    if req.format == "dot":
        return {"dot": gen.dot(graph), "stats": graph["stats"]}
    return graph


# ── TON Contract Graph ──────────────────────────────────────────────────────────

@router.post("/ton/contract-graph")
async def ton_contract_graph(req: TONGraphRequest):
    """
    Full TON contract interaction graph with:
    upgradeability, ownership, replay risk, privilege escalation detection.
    """
    from scanners.ton_scanner.contract_graph import TONContractGraph
    if not Path(req.path).exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {req.path}")
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, TONContractGraph().analyze, req.path)
    return result


# ── Ollama AI Runtime ───────────────────────────────────────────────────────────

@router.get("/ollama/status")
async def ollama_status():
    """Check Ollama availability and model routing table."""
    from runtime.ollama_runtime import OLLAMA_AI
    return OLLAMA_AI.status()


@router.post("/ollama/reason")
async def ollama_reason(req: OllamaRequest):
    """Multi-step security reasoning via local Ollama model."""
    from runtime.ollama_runtime import OLLAMA_AI
    if not req.prompt:
        raise HTTPException(status_code=400, detail="'prompt' required")
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, OLLAMA_AI.reason, req.prompt)
    return {"answer": result}


@router.post("/ollama/remediate")
async def ollama_remediate(req: OllamaRequest):
    """Generate a concrete code fix for a finding using local Ollama."""
    from runtime.ollama_runtime import OLLAMA_AI
    if not req.finding:
        raise HTTPException(status_code=400, detail="'finding' required")
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, OLLAMA_AI.generate_remediation, req.finding, req.code_context or ""
    )
    return {"remediation": result}


@router.post("/ollama/explain")
async def ollama_explain(req: OllamaRequest):
    """Plain-language explanation of a finding via local Ollama."""
    from runtime.ollama_runtime import OLLAMA_AI
    if not req.finding:
        raise HTTPException(status_code=400, detail="'finding' required")
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, OLLAMA_AI.explain_finding, req.finding)
    return {"explanation": result}


@router.post("/ollama/summarise")
async def ollama_summarise(req: OllamaRequest):
    """Executive summary of scan findings via local Ollama."""
    from runtime.ollama_runtime import OLLAMA_AI
    findings = req.findings or []
    loop     = asyncio.get_running_loop()
    result   = await loop.run_in_executor(
        None, OLLAMA_AI.summarise_findings, findings, req.target or ""
    )
    return {"summary": result}


@router.post("/ollama/threat-model")
async def ollama_threat_model(req: OllamaRequest):
    """STRIDE threat model from findings via local Ollama."""
    from runtime.ollama_runtime import OLLAMA_AI
    findings = req.findings or []
    loop     = asyncio.get_running_loop()
    result   = await loop.run_in_executor(
        None, OLLAMA_AI.threat_model, findings, req.target or "Application"
    )
    return {"threat_model": result}


# ── SARIF Enriched Export ───────────────────────────────────────────────────────

@router.post("/export/sarif/enriched")
async def export_sarif_enriched(req: SARIFRequest):
    """
    Export findings to SARIF 2.1.0 with full CWE/OWASP enrichment
    and GitHub Code Scanning compatible format.
    """
    from reports.sarif_enriched import SARIFExporter
    exporter = SARIFExporter(repo_root=req.repo_root)
    return exporter.export(req.report)


@router.post("/export/github-workflow")
async def export_github_workflow(req: WorkflowRequest):
    """Generate a GitHub Actions workflow YAML for CI/CD integration."""
    from reports.sarif_enriched import generate_github_actions_workflow
    yaml = generate_github_actions_workflow(scan_type=req.scan_type)
    return {"workflow": yaml, "filename": ".github/workflows/ghost-security.yml"}


# ── Orchestration Pipeline ──────────────────────────────────────────────────────

@router.post("/pipeline/run")
async def run_pipeline(req: GraphPipelineRequest):
    """
    Execute a full DAG security scan pipeline with task graph orchestration.
    Returns run trace + aggregated findings.
    """
    from orchestrator.task_graph import GraphOrchestrator
    if not Path(req.path).exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {req.path}")
    orch   = GraphOrchestrator()
    run    = await orch.run_security_pipeline(
        req.path,
        scanners=req.scanners,
        max_concurrent=req.max_concurrent,
    )
    return {
        "run_id":    run.run_id,
        "summary":   run.summary(),
        "trace":     run.trace[-50:],  # last 50 events
        "nodes":     {nid: n.to_dict() for nid, n in run.nodes.items()},
    }


@router.get("/pipeline/history")
async def pipeline_history():
    """Return history of pipeline runs (in-memory, resets on restart)."""
    from orchestrator.task_graph import GraphOrchestrator
    # Note: stateless per-request; always returns empty without persistent state
    return {"runs": [], "note": "History is per-instance; use /api/memory for persistence"}


# ── Runtime Supervisor ──────────────────────────────────────────────────────────

@router.get("/supervisor/status")
async def supervisor_status():
    """Runtime supervisor diagnostics and task queue status."""
    from runtime.supervisor import SUPERVISOR
    return SUPERVISOR.status()


@router.get("/supervisor/tasks")
async def supervisor_tasks(state: Optional[str] = None):
    """List supervised tasks optionally filtered by state."""
    from runtime.supervisor import SUPERVISOR, TaskState
    ts = TaskState(state) if state else None
    return {"tasks": SUPERVISOR.list_tasks(state=ts)}


@router.get("/supervisor/tasks/{task_id}")
async def supervisor_task(task_id: str):
    """Get details of a specific supervised task."""
    from runtime.supervisor import SUPERVISOR
    st = SUPERVISOR.get_task(task_id)
    if not st:
        raise HTTPException(status_code=404, detail="Task not found")
    return st.to_dict()
