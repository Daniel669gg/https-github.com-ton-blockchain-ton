"""
TythanAI Platform — FastAPI REST API Server
Real API with SSE streaming, real endpoints, no placeholders.
"""
import json
import time
import asyncio
import hashlib
import os
import sys
from typing import Optional, List, Dict, Any
from pathlib import Path

try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Depends
    from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, FileResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    import uvicorn
except ImportError as _fastapi_err:  # pragma: no cover
    raise ImportError(
        f"API server requires: pip install fastapi uvicorn pydantic\n({_fastapi_err})"
    ) from _fastapi_err

sys.path.insert(0, str(Path(__file__).parent.parent))
from config.config import API_HOST, API_PORT, REPORTS_DIR
from agents.orchestrator import MultiAgentOrchestrator
from reports.report_generator import ReportGenerator
from scanners.ast_scanner.ast_analyzer import ASTScanner
from scanners.secret_scanner.secret_detector import SecretDetector
from scanners.semgrep_scanner.semgrep_scanner import SemgrepScanner
from scanners.github_watcher.github_watcher import GitHubWatcher
from scanners.ton_scanner.ton_analyzer import TONAnalyzer
from core.memory.memory_manager import MemoryManager
from core.security.middleware import verify_api_key, rate_limit


app = FastAPI(
    docs_url=None if os.getenv("ENV") == "production" else "/docs",
    title="TythanAI Platform",
    description="Autonomous AI Security Auditor — Real vulnerability detection, no placeholders",
    version="2.0.0"
)

# Production middleware (rate limiting, logging, security headers, error handling)
try:
    from core.security.middleware import register_middleware
    register_middleware(app)
except Exception as _mw_err:
    import logging
    logging.getLogger("ghost").warning("Middleware init failed: %s", _mw_err)


app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(","),
    allow_methods=["*"],
    allow_headers=["*"]
)

# Global instances
orchestrator = MultiAgentOrchestrator()
report_gen = ReportGenerator()
ast_scanner = ASTScanner()
secret_detector = SecretDetector()
semgrep_scanner = SemgrepScanner()
github_watcher = GitHubWatcher()
ton_analyzer = TONAnalyzer()
memory = MemoryManager()

# SSE event queues per session
_sse_queues: Dict[str, asyncio.Queue] = {}


# ---- Request Models ----

class AuditRequest(BaseModel):
    target: str
    audit_type: str = "full"
    session_id: Optional[str] = None


class ScanRequest(BaseModel):
    path: str
    scanner: str = "all"  # all, ast, semgrep, secrets


class GitHubRequest(BaseModel):
    owner: str
    repo: str
    branch: str = "main"
    max_commits: int = 5


class AgentTaskRequest(BaseModel):
    task: str
    context: Optional[str] = None


class CodeScanRequest(BaseModel):
    code: str
    language: str = "python"
    filename: str = "code_snippet.py"


# ---- Helper ----

def _session_callback(session_id: str):
    """Create callback that pushes events to SSE queue."""
    def callback(event_type: str, data: Any):
        queue = _sse_queues.get(session_id)
        if queue:
            try:
                asyncio.get_event_loop().call_soon_threadsafe(
                    queue.put_nowait,
                    {"event": event_type, "data": data}
                )
            except Exception:
                pass
    return callback




@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response
# ---- Routes ----

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main dashboard."""
    web_dir = Path(__file__).parent.parent / "web"
    index_path = web_dir / "templates" / "index.html"
    if index_path.exists():
        return HTMLResponse(index_path.read_text())
    return HTMLResponse("<h1>TythanAI Platform API</h1><p>Visit /docs for API documentation</p>")


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "2.0.0",
        "timestamp": time.time(),
        "components": {
            "semgrep": semgrep_scanner.semgrep_available,
            "memory": True,
            "llm": bool(os.environ.get("OPENAI_API_KEY"))
        }
    }


@app.post("/api/audit/start")
async def start_audit(request: AuditRequest, background_tasks: BackgroundTasks, _: bool = Depends(verify_api_key), __: bool = Depends(rate_limit)):
    """Start a full multi-agent security audit."""
    session_id = request.session_id or hashlib.md5(
        f"{request.target}{time.time()}".encode()
    ).hexdigest()[:12]

    # Create SSE queue for this session
    _sse_queues[session_id] = asyncio.Queue()

    # Start audit with callback
    actual_session_id = orchestrator.start_audit(
        target=request.target,
        audit_type=request.audit_type,
        session_id=session_id,
        callback=_session_callback(session_id)
    )

    return {
        "session_id": actual_session_id,
        "status": "started",
        "target": request.target,
        "stream_url": f"/api/audit/{actual_session_id}/stream"
    }


@app.get("/api/audit/{session_id}/status")
async def get_audit_status(session_id: str):
    """Get current audit status."""
    status = orchestrator.get_session_status(session_id)
    if "error" in status:
        raise HTTPException(status_code=404, detail=status["error"])
    return status


@app.get("/api/audit/{session_id}/report")
async def get_audit_report(session_id: str):
    """Get completed audit report."""
    session = orchestrator.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.status != "completed":
        raise HTTPException(status_code=202, detail=f"Audit still in progress: {session.status}")
    return session.report


@app.get("/api/audit/{session_id}/report/html")
async def get_audit_report_html(session_id: str):
    """Get HTML version of audit report."""
    session = orchestrator.get_session(session_id)
    if not session or not session.report:
        raise HTTPException(status_code=404, detail="Report not found")
    html = report_gen.generate_html(session.report)
    return HTMLResponse(html)


@app.get("/api/audit/{session_id}/stream")
async def stream_audit_events(session_id: str):
    """Stream audit events via Server-Sent Events."""
    queue = _sse_queues.get(session_id)
    if not queue:
        raise HTTPException(status_code=404, detail="Session not found or not streaming")

    async def event_generator():
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30.0)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("event") in ["completed", "error"]:
                    break
            except asyncio.TimeoutError:
                yield f"data: {json.dumps({'event': 'ping', 'data': {}})}\n\n"
            except Exception:
                break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


@app.post("/api/scan/code")
async def scan_code(request: CodeScanRequest, _: bool = Depends(verify_api_key), __: bool = Depends(rate_limit)):
    """Scan a code snippet for security issues."""
    import tempfile
    with tempfile.NamedTemporaryFile(
        mode='w', suffix=f'.{request.language}',
        delete=False, prefix='ghost_scan_'
    ) as f:
        f.write(request.code)
        tmpfile = f.name

    try:
        findings = ast_scanner.scan_file(tmpfile)
        secret_findings = secret_detector.scan_file(tmpfile)
        all_findings = findings + secret_findings

        # Deduplicate
        seen = set()
        deduped = []
        for f in all_findings:
            key = (f.get("line", 0), f.get("type", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return {
            "findings": deduped,
            "total_findings": len(deduped),
            "language": request.language,
            "summary": {
                "CRITICAL": sum(1 for f in deduped if f.get("severity") == "CRITICAL"),
                "HIGH": sum(1 for f in deduped if f.get("severity") == "HIGH"),
                "MEDIUM": sum(1 for f in deduped if f.get("severity") == "MEDIUM"),
                "LOW": sum(1 for f in deduped if f.get("severity") == "LOW"),
            }
        }
    finally:
        try:
            os.unlink(tmpfile)
        except Exception:
            pass


@app.post("/api/scan/path")
async def scan_path(request: ScanRequest):
    """Scan a local path for security issues."""
    target = Path(request.path)
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {request.path}")

    results = {}

    if request.scanner in ["all", "secrets"]:
        if target.is_file():
            results["secrets"] = {"findings": secret_detector.scan_file(str(target))}
        else:
            results["secrets"] = secret_detector.scan_directory(str(target))

    if request.scanner in ["all", "ast"]:
        if target.is_file():
            results["ast"] = {"findings": ast_scanner.scan_file(str(target))}
        else:
            results["ast"] = ast_scanner.scan_directory(str(target))

    if request.scanner in ["all", "semgrep"]:
        results["semgrep"] = semgrep_scanner.scan_path(str(target))

    if request.scanner in ["all", "ton"]:
        results["ton"] = {"findings": ton_analyzer.scan_directory(str(target))}

    # Aggregate all findings
    all_findings = []
    for scanner_result in results.values():
        all_findings.extend(scanner_result.get("findings", []))

    return {
        "path": str(target),
        "scanner_results": results,
        "total_findings": len(all_findings),
        "all_findings": all_findings
    }


@app.post("/api/github/watch")
async def watch_github(request: GitHubRequest):
    """Watch GitHub repository for security issues."""
    result = github_watcher.watch_repository(
        request.owner, request.repo,
        request.branch, request.max_commits
    )
    return result


@app.get("/api/github/repo/{owner}/{repo}")
async def get_github_repo(owner: str, repo: str):
    """Get GitHub repository security information."""
    info = github_watcher.get_repo_info(owner, repo)
    commits = github_watcher.get_commits(owner, repo, per_page=5)
    return {"repo_info": info, "recent_commits": commits}


@app.post("/api/agent/task")
async def run_agent_task(request: AgentTaskRequest):
    """Run a single agent task with full tool access."""
    from core.agent.agent_loop import AgentLoop
    from core.tools.tool_registry import ToolRegistry

    agent = AgentLoop(orchestrator.tool_registry, memory)
    result = agent.run(request.task, context=request.context, max_iterations=8)
    return result


@app.get("/api/memory/stats")
async def get_memory_stats():
    """Get memory system statistics."""
    return memory.get_stats()


@app.get("/api/memory/search")
async def search_memory(q: str, n: int = 5):
    """Search memory for similar findings."""
    results = memory.search_similar(q, n_results=n)
    return {"query": q, "results": results}




@app.post("/api/scan/owasp")
async def scan_owasp(body: dict):
    """OWASP Top 10 (2021) systematic scan for a directory or file."""
    from scanners.owasp_scanner import OWASPScanner
    from pathlib import Path as _P
    path = body.get("path", "")
    if not path or not _P(path).exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {path}")
    scanner = OWASPScanner()
    result = scanner.scan_directory(path) if _P(path).is_dir() else {
        "files_scanned": 1,
        "findings": scanner.scan_file(path),
    }
    return result


@app.post("/api/scan/js")
async def scan_javascript(body: dict):
    """JavaScript / TypeScript static security analysis."""
    from scanners.js_analyzer import JSAnalyzer
    from pathlib import Path as _P
    path = body.get("path", "")
    code = body.get("code", "")
    if code:
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(code); tmp = f.name
        try:
            findings = JSAnalyzer().analyze_file(tmp)
            for fi in findings: fi["file"] = "<snippet>"
        finally:
            os.unlink(tmp)
        return {"findings": findings, "total": len(findings)}
    if not path or not _P(path).exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {path}")
    return JSAnalyzer().scan_directory(path)


@app.post("/api/scan/solidity")
async def scan_solidity(body: dict):
    """Solidity smart contract static security analysis."""
    from scanners.solidity_scanner import SolidityScanner
    from pathlib import Path as _P
    path = body.get("path", "")
    if not path or not _P(path).exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {path}")
    scanner = SolidityScanner()
    if _P(path).is_dir():
        return scanner.scan_directory(path)
    return {"files_scanned": 1, "findings": scanner.analyze_file(path),
            "severity_counts": {}}


@app.post("/api/scan/all")
async def scan_all(body: dict):
    """Full pipeline scan using all available scanners."""
    from scanners.security_pipeline import SecurityPipeline
    from pathlib import Path as _P
    path = body.get("path", "")
    mode = body.get("mode", "all")
    if not path or not _P(path).exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {path}")
    result = SecurityPipeline().scan(path, mode=mode)
    # Persist to memory
    try:
        from core.knowledge.security_memory import MEMORY
        MEMORY.store_scan(result)
        MEMORY.store_all_findings(result.get("findings",[]), path)
    except Exception:
        pass
    return result


@app.post("/api/scan/deps")
async def scan_dependencies(body: dict):
    """Scan dependency manifests for known CVEs."""
    from scanners.dependency_scanner import DependencyScanner
    from pathlib import Path as _P
    target = body.get("path", "")
    if not target or not _P(target).exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {target}")
    scanner = DependencyScanner()
    p = _P(target)
    if p.is_dir():
        result = scanner.scan_directory(str(p))
    else:
        findings = scanner.scan_file(str(p))
        sev_c: dict = {}
        for f in findings:
            sev_c[f.get("severity","LOW")] = sev_c.get(f.get("severity","LOW"),0) + 1
        result = {"manifests_scanned": 1, "total_findings": len(findings),
                  "severity_counts": sev_c, "findings": findings}
    return result


@app.post("/api/enrich")
async def enrich_findings(body: dict):
    """Enrich findings with LLM analysis, confidence scores, CVSS vectors."""
    from scanners.llm_analyzer import LLMAnalyzer
    findings = body.get("findings", [])
    min_sev  = body.get("min_severity", "HIGH")
    analyzer = LLMAnalyzer(min_severity=min_sev, max_findings=body.get("max_findings", 10))
    enriched = analyzer.enrich_findings(list(findings))
    return {"findings": enriched, "enriched_count": sum(1 for f in enriched if "llm_analysis" in f)}


@app.post("/api/export/sarif")
async def export_sarif(body: dict):
    """Export a report dict to SARIF 2.1.0 format."""
    from reports.sarif_exporter import SARIFExporter
    report = body.get("report", {})
    if not report:
        raise HTTPException(status_code=400, detail="'report' field required")
    return SARIFExporter().export(report)


@app.get("/api/health/llm")
async def llm_health():
    """Return LLM / model router status."""
    from runtime.model_router import ModelRouter
    return ModelRouter().status()


@app.get("/api/ton/rules")
async def get_ton_rules_v2():
    """List all 28 active TON analyzer rules."""
    rules = ton_analyzer.get_rules_summary()
    return {"rules": rules, "total": len(rules)}



# ── Security Copilot endpoint ────────────────────────────────────────────────
@app.post("/api/copilot/ask")
async def copilot_ask(body: dict):
    """Security Copilot — answer security questions via LLM."""
    from core.security.security_copilot import SecurityCopilot
    question = body.get("question", "")
    if not question.strip():
        raise HTTPException(status_code=400, detail="'question' field required")
    copilot = SecurityCopilot()
    answer = copilot.ask(question, use_history=False)
    return {"answer": answer}


@app.post("/api/copilot/explain")
async def copilot_explain(body: dict):
    """Explain a specific finding in plain language."""
    from core.security.security_copilot import SecurityCopilot
    finding = body.get("finding", {})
    if not finding:
        raise HTTPException(status_code=400, detail="'finding' field required")
    return {"explanation": SecurityCopilot().explain_finding(finding)}


@app.post("/api/copilot/fix")
async def copilot_fix(body: dict):
    """Generate a code fix for a finding."""
    from core.security.security_copilot import SecurityCopilot
    finding = body.get("finding", {})
    code    = body.get("code_context", "")
    return {"fix": SecurityCopilot().suggest_fix(finding, code)}


@app.post("/api/copilot/review")
async def copilot_review(body: dict):
    """Security review of a code snippet."""
    from core.security.security_copilot import SecurityCopilot
    code = body.get("code", "")
    lang = body.get("language", "python")
    if not code.strip():
        raise HTTPException(status_code=400, detail="'code' field required")
    return {"review": SecurityCopilot().review_code(code, lang)}


# ── Patch / remediation endpoints ────────────────────────────────────────────
@app.post("/api/remediate")
async def auto_remediate(body: dict):
    """Auto-generate patches for a list of findings."""
    from core.remediation.patch_generator import PatchGenerator
    findings = body.get("findings", [])
    if not findings:
        raise HTTPException(status_code=400, detail="'findings' list required")
    gen = PatchGenerator()
    patched, count = gen.patch_all(list(findings))
    return {"findings": patched, "patches_generated": count}


# ── Triage endpoints ─────────────────────────────────────────────────────────
@app.post("/api/triage")
async def triage_findings(body: dict):
    """Triage, deduplicate, and score a list of findings."""
    from core.security.findings_triage import FindingsTriage
    findings = body.get("findings", [])
    return FindingsTriage().triage(list(findings))


# ── Repository profiler ──────────────────────────────────────────────────────
@app.post("/api/repo/profile")
async def repo_profile(body: dict):
    """Risk profile + heatmap for a repository."""
    from core.analysis.repository_risk_profiler import RepositoryRiskProfiler
    from pathlib import Path as _P
    path = body.get("path", "")
    if not path or not _P(path).exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {path}")
    return RepositoryRiskProfiler().profile(path)


# ── Taint analysis endpoint ──────────────────────────────────────────────────
@app.post("/api/scan/taint")
async def taint_scan(body: dict):
    """AST dataflow / taint analysis for Python code or file."""
    from core.analysis.taint_tracker import TaintTracker
    from pathlib import Path as _P
    code = body.get("code", "")
    path = body.get("path", "")
    tracker = TaintTracker()
    if code:
        findings = tracker.analyze_code(code, "<snippet>")
    elif path and _P(path).exists():
        findings = tracker.analyze_file(path)
    else:
        raise HTTPException(status_code=400, detail="Provide 'code' or 'path'")
    sev_c: dict = {}
    for f in findings:
        sev_c[f.get("severity","HIGH")] = sev_c.get(f.get("severity","HIGH"), 0) + 1
    return {"findings": findings, "total": len(findings), "severity_counts": sev_c}


# ── Memory endpoints ─────────────────────────────────────────────────────────
@app.get("/api/memory/summary")
async def memory_summary():
    from core.knowledge.security_memory import MEMORY
    return MEMORY.summary()

@app.get("/api/memory/recurring")
async def memory_recurring(min_occurrences: int = 2):
    from core.knowledge.security_memory import MEMORY
    return {"findings": MEMORY.recurring_findings(min_occurrences)}

@app.get("/api/memory/cwes")
async def memory_cwes(limit: int = 10):
    from core.knowledge.security_memory import MEMORY
    return {"cwes": MEMORY.top_cwes(limit)}

@app.get("/api/memory/trend")
async def memory_trend(days: int = 30):
    from core.knowledge.security_memory import MEMORY
    return {"trend": MEMORY.risk_trend(days)}

@app.post("/api/memory/search")
async def memory_search(body: dict):
    from core.knowledge.security_memory import MEMORY
    return {"results": MEMORY.search(body.get("query",""), body.get("limit",20))}


# ── Bug bounty endpoints ─────────────────────────────────────────────────────
@app.post("/api/bounty/triage")
async def bounty_triage(body: dict):
    """Triage a finding for bug bounty eligibility."""
    from agents_ext.bug_bounty_agent import BugBountyAgent
    finding = body.get("finding", {})
    if not finding:
        raise HTTPException(status_code=400, detail="'finding' required")
    agent = BugBountyAgent()
    triage = agent.triage(finding)
    programs = agent.match_programs(finding, body.get("target_type","general"))
    return {"triage": triage, "programs": programs}

@app.post("/api/bounty/writeup")
async def bounty_writeup(body: dict):
    """Generate a bug bounty disclosure write-up for a finding."""
    from agents_ext.bug_bounty_agent import BugBountyAgent
    finding = body.get("finding", {})
    target  = body.get("target", "Target Application")
    return {"writeup": BugBountyAgent().generate_writeup(finding, target)}


# ── Threat model endpoint ────────────────────────────────────────────────────
@app.post("/api/threat-model")
async def threat_model(body: dict):
    """STRIDE threat model for a list of findings."""
    from agents_ext.threat_model_agent import ThreatModelAgent
    findings = body.get("findings", [])
    asset    = body.get("asset", "Application")
    return ThreatModelAgent().analyze(asset, findings)


# ── HTML report generation ───────────────────────────────────────────────────
@app.post("/api/reports/generate-html")
async def generate_html_report(body: dict):
    """Generate a full HTML report from a report dict."""
    from reports.report_generator import ReportGenerator
    html = ReportGenerator().generate_html(body)
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html)


# ── Task queue endpoints ─────────────────────────────────────────────────────
@app.get("/api/queue/status")
async def queue_status():
    from core.distributed.task_queue import QUEUE
    return QUEUE.status()

@app.get("/api/queue/task/{task_id}")
async def queue_task(task_id: str):
    from core.distributed.task_queue import QUEUE
    t = QUEUE.get(task_id)
    if not t:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"task_id":t.task_id,"name":t.name,"status":t.status,
            "duration":t.duration,"error":t.error}


# ── TON message flow endpoint ────────────────────────────────────────────────
@app.post("/api/ton/message-flow")
async def ton_message_flow(body: dict):
    """Analyse TON contract message flow (state transitions, guards, upgrades)."""
    from blockchain.ton.message_flow_analyzer import MessageFlowAnalyzer
    from pathlib import Path as _P
    path = body.get("path","")
    if not path or not _P(path).exists():
        raise HTTPException(status_code=404, detail=f"File not found: {path}")
    return MessageFlowAnalyzer().analyze(path)


# ── Serve dashboard ──────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def dashboard():
    from fastapi.responses import HTMLResponse
    from pathlib import Path as _P
    tpl = _P("web/templates/index.html")
    if tpl.exists():
        return HTMLResponse(content=tpl.read_text())
    return HTMLResponse(content="<h1>TythanAI Platform</h1><p>Dashboard template missing.</p>")


@app.get("/api/reports")
async def list_reports():
    """List all generated reports."""
    reports_dir = Path(REPORTS_DIR)
    if not reports_dir.exists():
        return {"reports": []}

    reports = []
    for f in reports_dir.glob("report_*.json"):
        try:
            data = json.loads(f.read_text())
            reports.append({
                "session_id": data.get("session_id"),
                "target": data.get("target"),
                "timestamp": data.get("timestamp"),
                "risk_score": data.get("risk_score"),
                "risk_level": data.get("risk_level"),
                "total_findings": data.get("total_findings"),
                "file": str(f)
            })
        except Exception:
            pass

    return {"reports": sorted(reports, key=lambda r: r.get("timestamp", ""), reverse=True)}


@app.get("/api/reports/{session_id}")
async def get_report(session_id: str):
    """Get a specific report by session ID."""
    report_path = Path(REPORTS_DIR) / f"report_{session_id}.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return json.loads(report_path.read_text())


@app.get("/api/reports/{session_id}/html")
async def get_report_html(session_id: str):
    """Get HTML version of a report."""
    report_path = Path(REPORTS_DIR) / f"report_{session_id}.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    report = json.loads(report_path.read_text())
    return HTMLResponse(report_gen.generate_html(report))


# ── Extension routes (v2 API) ────────────────────────────────────────────────
try:
    from api.routes_ext import router as _ext_router
    app.include_router(_ext_router, prefix="/api/v2")
except Exception as _e:
    import logging as _log
    _log.getLogger("ghost.server").warning("Extension routes not loaded: %s", _e)

# Mount static files
web_static = Path(__file__).parent.parent / "web" / "static"
if web_static.exists():
    app.mount("/static", StaticFiles(directory=str(web_static)), name="static")


def run_server():
    """Run the API server."""
    uvicorn.run(app, host=API_HOST, port=API_PORT, log_level="info")


if __name__ == "__main__":
    run_server()


# ---- TON Audit Endpoints (Absolute Edition) ----

class TONAuditRequest(BaseModel):
    contract_path: str
    audit_type: str = "full"  # full, fuzzing, traces, rollback
    wallet_address: Optional[str] = None


@app.post("/api/audit/ton")
async def audit_ton_contract(request: TONAuditRequest):
    """TON Smart Contract Audit — static analysis via TONAnalyzer (28 rules)."""
    from pathlib import Path as _P
    cp = _P(request.contract_path)
    if not cp.exists():
        raise HTTPException(status_code=404, detail=f"Contract path not found: {request.contract_path}")
    if cp.is_dir():
        result = ton_analyzer.scan_directory(str(cp))
        findings = result.get("findings", [])
        severity_counts = result.get("severity_counts", {})
    else:
        findings = ton_analyzer.analyze_file(str(cp))
        severity_counts: dict = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
    risk_score = min(
        severity_counts.get("CRITICAL", 0) * 25 +
        severity_counts.get("HIGH", 0) * 15 +
        severity_counts.get("MEDIUM", 0) * 8 +
        severity_counts.get("LOW", 0) * 3, 100
    )
    return {
        "contract": request.contract_path,
        "audit_type": request.audit_type,
        "findings": findings,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "risk_score": risk_score,
        "risk_level": (
            "CRITICAL" if risk_score >= 75 else
            "HIGH"     if risk_score >= 50 else
            "MEDIUM"   if risk_score >= 25 else "LOW"
        ),
        "status": "completed",
        "timestamp": time.time(),
    }


@app.get("/api/ton/rules")
async def get_ton_rules():
    """List all active TON analyzer rules with metadata."""
    rules = ton_analyzer.get_rules_summary()
    return {"rules": rules, "total": len(rules)}


@app.post("/api/ton/analyze-snippet")
async def analyze_ton_snippet(body: dict):
    """Analyze a raw FunC/Tact code snippet (no file required)."""
    import tempfile as _tmp, os as _os
    code = body.get("code", "")
    lang = body.get("lang", "fc").lstrip(".")
    if not code.strip():
        raise HTTPException(status_code=400, detail="'code' field is required")
    with _tmp.NamedTemporaryFile(mode="w", suffix=f".{lang}", delete=False) as f:
        f.write(code); tmppath = f.name
    try:
        findings = ton_analyzer.analyze_file(tmppath)
        for fi in findings:
            fi["file"] = "<snippet>"
        severity_counts: dict = {}
        for fi in findings:
            sev = fi.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        return {"findings": findings, "total_findings": len(findings),
                "severity_counts": severity_counts, "status": "completed"}
    finally:
        _os.unlink(tmppath)


# ═══════════════════════════════════════════════════════════════════════════════
# НОВЫЕ ЭНДПОИНТЫ — 5 улучшений
# ═══════════════════════════════════════════════════════════════════════════════

# ── 1. Inline scan для VS Code extension ─────────────────────────────────────
@app.post("/api/scan/inline")
async def scan_inline(body: dict):
    """
    Сканирует контент файла переданный как строка (для VS Code extension).
    Не требует файловой системы — всё в памяти.
    """
    import tempfile as _tmp, os as _os
    content  = body.get("content", "")
    language = body.get("language", "python")
    path     = body.get("path", "untitled")

    if not content.strip():
        return {"findings": [], "severity_counts": {}, "scan_id": None}

    ext_map  = {
        "python":             ".py",
        "javascript":         ".js",
        "typescript":         ".ts",
        "javascriptreact":    ".jsx",
        "typescriptreact":    ".tsx",
        "solidity":           ".sol",
    }
    suffix = ext_map.get(language, ".py")

    with _tmp.NamedTemporaryFile(mode="w", suffix=suffix, delete=False,
                                  encoding="utf-8") as f:
        f.write(content); tmp = f.name

    try:
        findings = []
        if suffix == ".py":
            from scanners.owasp_scanner import OWASPScanner
            from scanners.secret_scanner.secret_detector import SecretDetector
            findings += OWASPScanner().scan_file(tmp)
            findings += SecretDetector().scan_file(tmp)
        elif suffix in (".js", ".ts", ".jsx", ".tsx"):
            from scanners.js_scanner import JSScanner
            findings += JSScanner().scan_file(tmp)
        elif suffix == ".sol":
            from scanners.solidity_scanner.solidity_analyzer import SolidityAnalyzer
            findings += SolidityAnalyzer().scan_file(tmp)

        # Нормализация + enrichment + confidence
        from core.knowledge.message_normalizer import normalise_all
        from core.knowledge.cve_enricher import CVEEnricher
        from verifier.confidence_engine import ConfidenceEngine
        import uuid

        findings = normalise_all(findings)
        findings = CVEEnricher(online=False).enrich(findings)
        processed = ConfidenceEngine(fp_threshold=0.35).process(findings)

        # Исправляем пути на оригинальный
        for f in processed["findings"]:
            f["file"] = path

        sev_counts: dict = {}
        for f in processed["findings"]:
            s = f.get("severity", "MEDIUM")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        return {
            "findings":       processed["findings"],
            "severity_counts": sev_counts,
            "stats":          processed["stats"],
            "scan_id":        None,
        }
    finally:
        _os.unlink(tmp)


# ── 2. Persistence endpoints ──────────────────────────────────────────────────
@app.get("/api/history")
async def scan_history(target: str = "", limit: int = 20):
    """История сканов с фильтром по target."""
    from core.persistence.db import get_db
    db = get_db()
    return {"scans": db.list_scans(target=target or None, limit=limit)}


@app.get("/api/history/{scan_id}")
async def scan_detail(scan_id: str):
    """Детали конкретного скана + findings."""
    from core.persistence.db import get_db
    db   = get_db()
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {**scan, "findings": db.get_findings(scan_id)}


@app.get("/api/history/{scan_id}/diff")
async def scan_diff(scan_id: str):
    """Diff нового скана с предыдущим (новые + исправленные findings)."""
    from core.persistence.db import get_db
    return get_db().diff_with_previous(scan_id)


@app.get("/api/stats/trend")
async def risk_trend(target: str, days: int = 30):
    """Тренд risk-score за N дней для заданного target."""
    from core.persistence.db import get_db
    return {"trend": get_db().risk_trend(target, days)}


@app.get("/api/stats/global")
async def global_stats():
    """Глобальная статистика: всего сканов, findings, топ CWE."""
    from core.persistence.db import get_db
    db = get_db()
    return {**db.global_stats(), "top_cwes": db.top_cwes(limit=10)}


@app.get("/api/findings/search")
async def findings_search(q: str, severity: str = "", cwe: str = "", limit: int = 50):
    """Полнотекстовый поиск по findings."""
    from core.persistence.db import get_db
    return {"findings": get_db().search_findings(q, severity or None, cwe or None, limit)}


# ── 3. Reachability analysis ──────────────────────────────────────────────────
@app.post("/api/scan/deps/reachable")
async def scan_deps_reachable(body: dict):
    """
    Сканирует зависимости + фильтрует недостижимые CVE.
    Снижает шум на ~70%.
    """
    import asyncio
    path = body.get("path", "")
    if not path or not Path(path).exists():
        raise HTTPException(status_code=400, detail="'path' required and must exist")

    from scanners.dependency_scanner import DependencyScanner
    from core.analysis.reachability import ReachabilityAnalyzer
    from core.knowledge.message_normalizer import normalise_all

    loop     = asyncio.get_running_loop()
    raw_deps = await loop.run_in_executor(None, DependencyScanner().scan_directory, path)
    findings = raw_deps.get("findings", [])
    findings = normalise_all(findings)

    analyzer              = ReachabilityAnalyzer(path)
    reachable, unreachable = await loop.run_in_executor(
        None, analyzer.filter_unreachable, findings
    )
    stats = analyzer.stats(findings)

    return {
        "path":           path,
        "reachable":      reachable,
        "unreachable":    unreachable,
        "stats":          stats,
        "total_raw":      len(findings),
        "noise_reduced":  stats["noise_reduced"],
    }


# ── 4. GitHub App webhook ─────────────────────────────────────────────────────
@app.post("/github/webhook")
async def github_webhook(request: Request):
    """GitHub App webhook — принимает PR events, запускает скан."""
    from integrations.github_app import handle_webhook
    payload   = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")
    result    = await handle_webhook(payload, signature)
    return result


@app.get("/github/app/status")
async def github_app_status():
    """Статус GitHub App интеграции."""
    from integrations.github_app import APP
    return {
        "configured":  APP.is_configured(),
        "app_id":      APP.app_id if APP.is_configured() else None,
        "webhook_url": "/github/webhook",
        "setup_docs":  "https://docs.github.com/en/apps/creating-github-apps",
    }



# ── TON Bug Bounty Pipeline ───────────────────────────────────────────────────
@app.post("/api/ton/bounty-scan")
async def ton_bounty_scan(body: dict):
    """
    Полный TON bug bounty pipeline:
    1. Статический анализ FunC/Tact/Fift (87 правил)
    2. Dataflow-анализ (4 межфункциональных правила)
    3. CVE/CWE обогащение
    4. Confidence scoring + FP-фильтрация
    5. Генерация Immunefi/HackenProof отчётов
    """
    import asyncio
    path            = body.get("path", "")
    contract_name   = body.get("contract_name", Path(path).name if path else "Contract")
    min_severity    = body.get("min_severity", "MEDIUM")
    generate_reports = body.get("generate_reports", True)
    output_dir      = body.get("output_dir", "ghost_reports/bounty")

    if not path or not Path(path).exists():
        raise HTTPException(status_code=400, detail="'path' required and must exist")

    loop = asyncio.get_running_loop()

    # Сканирование
    def _run_scan():
        from scanners.ton_scanner.ton_analyzer import TONAnalyzer
        from core.knowledge.cve_enricher import CVEEnricher
        from core.knowledge.message_normalizer import normalise_all
        from verifier.confidence_engine import ConfidenceEngine
        from reports.bounty_report import BugBountyReportGenerator

        p = Path(path)
        if p.is_file():
            raw = TONAnalyzer().analyze_file(str(p))
        else:
            result = TONAnalyzer().scan_directory(str(p))
            raw = result.get("findings", [])

        # Normalise → enrich → confidence
        findings = normalise_all(raw)
        findings = CVEEnricher(online=False).enrich(findings)
        processed = ConfidenceEngine(fp_threshold=0.25).process(findings)
        final_findings = processed["findings"]

        # Генерация отчётов
        reports_out = {}
        if generate_reports and final_findings:
            gen = BugBountyReportGenerator(contract_name)
            reports_out = gen.generate_all(
                final_findings, output_dir,
                min_severity=min_severity,
                formats=["markdown", "json", "summary"],
            )

        # Статистика
        sev_counts: dict = {}
        for f in final_findings:
            s = f.get("severity", "MEDIUM")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        return {
            "path":              path,
            "contract_name":     contract_name,
            "total_findings":    len(final_findings),
            "severity_counts":   sev_counts,
            "findings":          final_findings,
            "reports_generated": list(reports_out.keys()),
            "stats":             processed.get("stats", {}),
            "scanner":           "TON Analyzer v2 (87 rules)",
        }

    result = await loop.run_in_executor(None, _run_scan)
    return result


@app.post("/api/ton/bounty-report")
async def ton_bounty_report(body: dict):
    """
    Генерирует Immunefi/HackenProof Markdown отчёт
    из уже готового списка findings.
    """
    from reports.bounty_report import BugBountyReportGenerator
    findings      = body.get("findings", [])
    contract_name = body.get("contract_name", "TON Smart Contract")
    min_severity  = body.get("min_severity", "MEDIUM")
    fmt           = body.get("format", "markdown")   # markdown | json | summary

    if not findings:
        raise HTTPException(status_code=400, detail="'findings' required")

    gen     = BugBountyReportGenerator(contract_name)
    reports = gen.from_findings(findings, min_severity)

    if fmt == "summary":
        return {"summary": gen.executive_summary(findings, reports), "count": len(reports)}

    output = []
    for r in reports:
        output.append({
            "title":    r.title,
            "severity": r.severity,
            "category": r.category,
            "markdown": r.immunefi_markdown() if fmt == "markdown" else None,
            "json":     r.hackenproof_json()  if fmt == "json"     else None,
        })
    return {"reports": output, "count": len(output)}


# ═══════════════════════════════════════════════════════════════════
# ЭТАП 1-5: Multi-LLM Router, Vector Memory, Telemetry, K8s, Remediation
# ═══════════════════════════════════════════════════════════════════

# ── Multi-LLM Router ──────────────────────────────────────────────
@app.get("/api/llm/status")
async def llm_status():
    """Статус всех LLM провайдеров и таблица маршрутизации."""
    from runtime.providers.multi_llm_router import ROUTER
    return ROUTER.status()

@app.post("/api/llm/call")
async def llm_call(body: dict):
    """Вызов через Multi-LLM Router с fallback chain."""
    import asyncio
    from runtime.providers.multi_llm_router import ROUTER
    task   = body.get("task", "default")
    prompt = body.get("prompt", "")
    system = body.get("system", "")
    if not prompt:
        raise HTTPException(status_code=400, detail="'prompt' required")
    loop = asyncio.get_running_loop()
    resp = await loop.run_in_executor(None, lambda: ROUTER.call(task, prompt, system=system))
    return {
        "text":       resp.text,
        "provider":   resp.provider,
        "model":      resp.model,
        "latency_ms": resp.latency_ms,
        "cost_usd":   resp.cost_usd,
        "ok":         resp.ok,
        "error":      resp.error,
    }

@app.post("/api/llm/consensus")
async def llm_consensus(body: dict):
    """Consensus от нескольких провайдеров (claude+openai+ollama голосуют)."""
    import asyncio
    from runtime.providers.multi_llm_router import ROUTER
    task      = body.get("task", "security")
    prompt    = body.get("prompt", "")
    strategy  = body.get("strategy", "vote")
    providers = body.get("providers")
    if not prompt:
        raise HTTPException(status_code=400, detail="'prompt' required")
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(
        None, lambda: ROUTER.consensus(task, prompt, providers=providers, strategy=strategy)
    )
    return result.to_dict()

@app.get("/api/llm/costs")
async def llm_costs():
    """Суммарная стоимость LLM вызовов по провайдерам."""
    from runtime.providers.multi_llm_router import ROUTER
    return ROUTER.costs.summary()

# ── Vector Memory ─────────────────────────────────────────────────
@app.get("/api/memory/status")
async def memory_status():
    from memory.vector.ghost_memory import MEMORY
    return MEMORY.status()

@app.post("/api/memory/search")
async def memory_search(body: dict):
    """Семантический поиск похожих находок из истории."""
    from memory.vector.ghost_memory import MEMORY
    finding = body.get("finding")
    limit   = body.get("limit", 5)
    if not finding:
        raise HTTPException(status_code=400, detail="'finding' required")
    results = MEMORY.similar_findings(finding, limit=limit)
    return {"results": [r.to_dict() for r in results], "count": len(results)}

@app.post("/api/memory/remediations")
async def memory_remediations(body: dict):
    """Найти успешные фиксы для похожих уязвимостей."""
    from memory.vector.ghost_memory import MEMORY
    finding = body.get("finding")
    if not finding:
        raise HTTPException(status_code=400, detail="'finding' required")
    results = MEMORY.get_remediations(finding, limit=3)
    return {"results": [r.to_dict() for r in results]}

# ── Telemetry ──────────────────────────────────────────────────────
@app.get("/metrics")
async def prometheus_metrics():
    """Prometheus /metrics endpoint — подключи к Grafana."""
    from fastapi.responses import PlainTextResponse
    from telemetry.metrics import METRICS
    return PlainTextResponse(METRICS.export(), media_type="text/plain; version=0.0.4")

@app.get("/api/telemetry/traces")
async def recent_traces(limit: int = 50):
    """Последние OpenTelemetry traces."""
    from telemetry.metrics import TRACER
    return {"traces": TRACER.recent_traces(limit)}

@app.get("/api/telemetry/grafana-dashboard")
async def grafana_dashboard():
    """Grafana dashboard JSON — импортируй в Grafana UI."""
    from telemetry.metrics import GRAFANA_DASHBOARD
    return GRAFANA_DASHBOARD

# ── Kubernetes Security ────────────────────────────────────────────
@app.post("/api/scan/k8s/manifest")
async def scan_k8s_manifest(body: dict):
    """
    Статический анализ Kubernetes YAML манифестов.
    Принимает path к директории или YAML-контент напрямую.
    """
    import asyncio
    from scanners.k8s_scanner.k8s_scanner import K8sSecurityScanner, ManifestScanner
    from core.knowledge.message_normalizer import normalise_all

    path    = body.get("path", "")
    content = body.get("content", "")  # прямой YAML контент

    loop = asyncio.get_running_loop()
    if content:
        findings_raw = await loop.run_in_executor(
            None, lambda: ManifestScanner().scan_string(content)
        )
    elif path and Path(path).exists():
        scanner      = K8sSecurityScanner()
        result       = await loop.run_in_executor(None, lambda: scanner.scan(path, mode="manifest"))
        findings_raw = result.get("findings", [])
        return result
    else:
        raise HTTPException(status_code=400, detail="'path' or 'content' required")

    dicts = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings_raw]
    dicts = normalise_all(dicts)

    counts: dict = {}
    for f in dicts:
        s = f.get("severity", "MEDIUM")
        counts[s] = counts.get(s, 0) + 1

    return {"findings": dicts, "total": len(dicts), "severity_counts": counts}

@app.post("/api/scan/k8s/live")
async def scan_k8s_live(body: dict = None):
    """Сканирование живого кластера через kubectl."""
    import asyncio
    from scanners.k8s_scanner.k8s_scanner import K8sSecurityScanner
    kubeconfig = (body or {}).get("kubeconfig", "")
    context    = (body or {}).get("context", "")
    scanner    = K8sSecurityScanner(kubeconfig=kubeconfig, context=context)
    if not scanner._kubectl.is_available():
        return {"error": "kubectl not available", "findings": [], "mode": "live"}
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, lambda: scanner.scan(mode="live"))
    return result

@app.get("/api/scan/k8s/status")
async def k8s_status():
    from scanners.k8s_scanner.k8s_scanner import K8sSecurityScanner
    return K8sSecurityScanner().status()

# ── Autonomous Remediation ─────────────────────────────────────────
@app.post("/api/remediate/generate")
async def remediate_generate(body: dict):
    """
    Генерирует патч для security finding.
    Возвращает diff — не применяет автоматически.
    """
    import asyncio
    from remediation.remediation_engine import REMEDIATION
    finding      = body.get("finding")
    code_context = body.get("code_context", "")
    use_llm      = body.get("use_llm", True)
    if not finding:
        raise HTTPException(status_code=400, detail="'finding' required")
    loop  = asyncio.get_running_loop()
    patch = await loop.run_in_executor(
        None, lambda: REMEDIATION.generate(finding, code_context, use_llm)
    )
    if not patch:
        return {"patch": None, "message": "No automated fix available for this finding type"}
    return {"patch": patch.to_dict(), "diff": patch.diff, "safe_to_apply": patch.safe_to_apply}

@app.post("/api/remediate/batch")
async def remediate_batch(body: dict):
    """Генерирует патчи для нескольких findings сразу."""
    import asyncio
    from remediation.remediation_engine import REMEDIATION
    findings = body.get("findings", [])
    use_llm  = body.get("use_llm", False)   # batch по умолчанию без LLM (быстро)
    if not findings:
        raise HTTPException(status_code=400, detail="'findings' required")
    loop    = asyncio.get_running_loop()
    patches = await loop.run_in_executor(
        None, lambda: REMEDIATION.generate_batch(findings, use_llm)
    )
    return {
        "patches":  [p.to_dict() for p in patches],
        "count":    len(patches),
        "coverage": f"{len(patches)/len(findings)*100:.0f}%",
    }

@app.post("/api/remediate/create-pr")
async def remediate_create_pr(body: dict):
    """
    Создаёт GitHub PR с патчем (draft — требует ревью перед merge).
    Требует GITHUB_TOKEN.
    """
    import asyncio
    from remediation.remediation_engine import REMEDIATION, RemediationPatch
    patch_data = body.get("patch")
    owner      = body.get("owner", "")
    repo       = body.get("repo", "")
    if not all([patch_data, owner, repo]):
        raise HTTPException(status_code=400, detail="'patch', 'owner', 'repo' required")

    p = RemediationPatch(**{k: patch_data[k] for k in [
        "finding_id","finding_type","file","line","original","fixed","diff",
        "description","method","confidence"
    ] if k in patch_data})

    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, lambda: REMEDIATION.create_pr(p, owner, repo))
    return result

@app.get("/api/remediate/history")
async def remediate_history():
    from remediation.remediation_engine import REMEDIATION
    return {"patches": REMEDIATION.history()}

# ═══════════════════════════════════════════════════════════════
# ЭТАПЫ 6-11: Attack Path, FP Feedback, Multi-tenant,
#              OpenAPI, Supply Chain, Symbolic TON
# ═══════════════════════════════════════════════════════════════

# ── Incremental scan ────────────────────────────────────────────
@app.post("/api/scan/incremental")
async def scan_incremental(body: dict):
    import asyncio
    from core.incremental import IncrementalScanner
    path = body.get("path", ".")
    base = body.get("base", "HEAD~1")
    if not Path(path).exists():
        raise HTTPException(status_code=400, detail="path not found")
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, lambda: IncrementalScanner(path).scan(base=base))
    s = result.summary()
    return {**s, "new_findings": result.new_findings[:200]}

@app.get("/api/scan/cache/stats")
async def cache_stats():
    from core.incremental import ScanCache
    return ScanCache().stats()

@app.delete("/api/scan/cache")
async def cache_clear():
    from core.incremental import ScanCache
    n = ScanCache().clear()
    return {"cleared": n}

# ── Attack Path ─────────────────────────────────────────────────
@app.post("/api/analysis/attack-paths")
async def attack_paths(body: dict):
    import asyncio
    from core.attack_path import AttackPathAnalyzer
    findings = body.get("findings", [])
    if not findings:
        raise HTTPException(status_code=400, detail="'findings' required")
    loop   = asyncio.get_running_loop()
    graph  = await loop.run_in_executor(None, AttackPathAnalyzer().analyze, findings)
    return graph

@app.post("/api/analysis/attack-paths/mermaid")
async def attack_paths_mermaid(body: dict):
    from core.attack_path import AttackPathAnalyzer
    findings = body.get("findings", [])
    analyzer = AttackPathAnalyzer()
    graph    = analyzer.analyze(findings)
    return {"mermaid": analyzer.mermaid(graph), "narrative": analyzer.narrative(graph)}

# ── FP Feedback ─────────────────────────────────────────────────
@app.post("/api/feedback/fp")
async def report_fp(body: dict):
    from core.fp_feedback import FP_STORE
    finding = body.get("finding")
    reason  = body.get("reason", "")
    if not finding:
        raise HTTPException(status_code=400, detail="'finding' required")
    return FP_STORE.report_fp(finding, reason)

@app.post("/api/feedback/fp/reset")
async def reset_fp(body: dict):
    from core.fp_feedback import FP_STORE
    finding = body.get("finding")
    if not finding:
        raise HTTPException(status_code=400, detail="'finding' required")
    return {"reset": FP_STORE.reset_fingerprint(finding)}

@app.get("/api/feedback/fp/stats")
async def fp_stats():
    from core.fp_feedback import FP_STORE
    return {**FP_STORE.stats(), "top_fp_rules": FP_STORE.top_fp_rules()}

# ── Multi-tenant ─────────────────────────────────────────────────
@app.post("/api/auth/register")
async def register(body: dict):
    from core.tenants import TENANTS
    org_name = body.get("org_name", "")
    email    = body.get("email", "")
    password = body.get("password", "")
    plan     = body.get("plan", "free")
    if not all([org_name, email, password]):
        raise HTTPException(status_code=400, detail="org_name, email, password required")
    import re, secrets as sec
    slug = re.sub(r"[^a-z0-9]", "-", org_name.lower())[:20] + "-" + sec.token_hex(3)
    org  = TENANTS.create_org(org_name, slug, plan)
    user = TENANTS.create_user(org["id"], email, password, role="owner")
    token = TENANTS.issue_token(user)
    return {"token": token, "org": org, "user": {k: v for k, v in user.items() if k != "password_hash"}}

@app.post("/api/auth/login")
async def login(body: dict):
    from core.tenants import TENANTS
    user = TENANTS.authenticate(body.get("email",""), body.get("password",""))
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": TENANTS.issue_token(user), "user": user}

@app.post("/api/auth/api-key")
async def create_api_key(body: dict, authorization: str = ""):
    from core.tenants import TENANTS
    ctx = TENANTS.resolve_auth(authorization)
    if not ctx:
        raise HTTPException(status_code=401, detail="Unauthorized")
    ctx.require("write")
    return TENANTS.create_api_key(ctx.org_id, body.get("name","default"))

@app.get("/api/org/projects")
async def list_projects(authorization: str = ""):
    from core.tenants import TENANTS
    ctx = TENANTS.resolve_auth(authorization)
    if not ctx:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"projects": TENANTS.list_projects(ctx.org_id)}

@app.get("/api/org/quota")
async def check_quota(authorization: str = ""):
    from core.tenants import TENANTS
    ctx = TENANTS.resolve_auth(authorization)
    if not ctx:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return TENANTS.check_quota(ctx.org_id)

# ── OpenAPI Scanner ──────────────────────────────────────────────
@app.post("/api/scan/openapi")
async def scan_openapi(body: dict):
    import asyncio
    from scanners.openapi_scanner import OpenAPIScanner
    from core.knowledge.message_normalizer import normalise_all
    source = body.get("path") or body.get("url") or body.get("content", "")
    if not source:
        raise HTTPException(status_code=400, detail="'path', 'url', or 'content' required")
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, OpenAPIScanner().scan, source)
    result["findings"] = normalise_all(result.get("findings", []))
    return result

# ── Supply Chain Scanner ─────────────────────────────────────────
@app.post("/api/scan/supply-chain")
async def scan_supply_chain(body: dict):
    import asyncio
    from scanners.supply_chain_scanner import SupplyChainScanner
    from core.knowledge.message_normalizer import normalise_all
    path   = body.get("path", "")
    online = body.get("online", False)
    if not path or not Path(path).exists():
        raise HTTPException(status_code=400, detail="'path' required")
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, SupplyChainScanner(online=online).scan_directory, path)
    result["findings"] = normalise_all(result.get("findings", []))
    return result

# ── TON Symbolic Execution ───────────────────────────────────────
@app.post("/api/ton/symbolic")
async def ton_symbolic(body: dict):
    import asyncio
    from scanners.ton_scanner.ton_symbolic import TONSymbolicExecutor
    from core.knowledge.message_normalizer import normalise_all
    path = body.get("path", "")
    if not path or not Path(path).exists():
        raise HTTPException(status_code=400, detail="'path' required")
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, TONSymbolicExecutor().analyze, path)
    result["findings"] = normalise_all(result.get("findings", []))
    return result

@app.get("/api/ton/symbolic/status")
async def ton_symbolic_status():
    from scanners.ton_scanner.ton_symbolic import TONSymbolicExecutor
    return TONSymbolicExecutor().status()

# ── Semgrep Scanner ──────────────────────────────────────────────
@app.post("/api/scan/semgrep")
async def scan_semgrep(body: dict):
    import asyncio
    from scanners.semgrep_scanner import SemgrepScanner
    from core.knowledge.message_normalizer import normalise_all
    from core.knowledge.cve_enricher import CVEEnricher
    path = body.get("path", "")
    if not path or not Path(path).exists():
        raise HTTPException(status_code=400, detail="'path' required")
    s    = SemgrepScanner()
    if not s.is_available():
        return {"error": "Semgrep not installed", "install": "pip install semgrep", "findings": []}
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, s.scan_directory, path)
    result["findings"] = normalise_all(CVEEnricher(online=False).enrich(result.get("findings",[])))
    return result

@app.get("/api/scan/semgrep/status")
async def semgrep_status():
    from scanners.semgrep_scanner import SemgrepScanner
    return SemgrepScanner().status()

# ── Benchmark ─────────────────────────────────────────────────────
@app.post("/api/benchmark/run")
async def benchmark_run():
    import asyncio, io, contextlib
    from tests.benchmark import run_benchmark
    buf    = io.StringIO()
    loop   = asyncio.get_running_loop()
    with contextlib.redirect_stdout(buf):
        code = await loop.run_in_executor(None, run_benchmark, False)
    return {"output": buf.getvalue(), "exit_code": code,
            "passed": code == 0}

# ══════════════════════════════════════════════════════════════
# НОВЫЕ ENDPOINTS: Rule Engine, Audit Log, SSO, Compliance,
#                  Disclosure, Performance, Community Rules
# ══════════════════════════════════════════════════════════════

# ── Community Rule Engine ─────────────────────────────────────
@app.get("/api/rules")
async def list_rules(language: str = ""):
    from core.rule_engine.rule_engine import REGISTRY
    REGISTRY.load_dir("rules")
    if language:
        rules = REGISTRY.for_language(language)
    else:
        rules = REGISTRY.all_rules()
    return {
        "rules": [{"id": r.rule_id, "name": r.name, "severity": r.severity,
                   "languages": r.languages, "cwe": r.cwe, "tags": r.tags} for r in rules],
        "stats": REGISTRY.stats(),
    }

@app.post("/api/rules/validate")
async def validate_rule(body: dict):
    from core.rule_engine.rule_engine import CommunityRuleScanner
    import tempfile, os
    content = body.get("content","")
    if not content:
        raise HTTPException(status_code=400, detail="'content' required")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write(content); tmp = f.name
    try:
        from core.rule_engine.rule_engine import CommunityRuleScanner, REGISTRY
        result = CommunityRuleScanner(REGISTRY).validate_rule_file(tmp)
        return result
    finally:
        os.unlink(tmp)

@app.post("/api/scan/community")
async def scan_community(body: dict):
    import asyncio
    from core.rule_engine.rule_engine import CommunityRuleScanner, REGISTRY
    path = body.get("path","")
    if not path or not Path(path).exists():
        raise HTTPException(status_code=400, detail="'path' required")
    REGISTRY.load_dir("rules")
    scanner = CommunityRuleScanner(REGISTRY)
    loop    = asyncio.get_running_loop()
    result  = await loop.run_in_executor(None, scanner.scan_directory, path)
    return result

# ── Audit Log ────────────────────────────────────────────────
@app.get("/api/audit/logs")
async def audit_logs(
    event_type: str = "",
    actor_id: str = "",
    limit: int = 100,
    authorization: str = "",
):
    from core.audit_log import AUDIT
    return {"events": AUDIT.query(event_type=event_type or None,
                                   actor_id=actor_id or None, limit=limit)}

@app.get("/api/audit/verify")
async def audit_verify():
    from core.audit_log import AUDIT
    return AUDIT.verify_integrity()

@app.get("/api/audit/stats")
async def audit_stats():
    from core.audit_log import AUDIT
    return AUDIT.stats()

# ── SSO ──────────────────────────────────────────────────────
@app.get("/api/auth/sso/status")
async def sso_status():
    from core.sso import SSO
    return SSO.status()

@app.get("/api/auth/sso/login")
async def sso_login():
    from core.sso import SSO
    from fastapi.responses import RedirectResponse
    if not SSO.is_enabled():
        raise HTTPException(status_code=501, detail="SSO not configured")
    url, state = SSO.authorization_url()
    return {"url": url, "state": state}

@app.get("/api/auth/sso/callback")
async def sso_callback(code: str, state: str):
    from core.sso import SSO
    from core.tenants import TENANTS
    user = SSO.handle_callback(code, state)
    if not user:
        raise HTTPException(status_code=401, detail="SSO authentication failed")
    # Find or create user in our system
    existing = None
    try:
        existing = TENANTS.authenticate(user.email, "")
    except Exception:
        pass
    if not existing:
        # Auto-provision
        import secrets as sec
        slug = user.email.split("@")[0][:12] + "-" + sec.token_hex(3)
        org  = TENANTS.create_org(user.name or user.email, slug, "pro")
        db_user = TENANTS.create_user(org["id"], user.email, sec.token_hex(16), name=user.name, role="owner")
        token = TENANTS.issue_token(db_user)
    else:
        token = TENANTS.issue_token(existing)
    return {"token": token, "provider": user.provider, "email": user.email}

# ── Compliance Reports ────────────────────────────────────────
@app.post("/api/compliance/report")
async def compliance_report(body: dict):
    from reports.compliance_report import ComplianceReportGenerator
    findings  = body.get("findings", [])
    framework = body.get("framework", "soc2")
    target    = body.get("target", "")
    fmt       = body.get("format", "json")
    gen       = ComplianceReportGenerator()
    report    = gen.generate(findings, framework, target)
    if fmt == "markdown":
        return {"markdown": report.to_markdown(), "framework": framework}
    return report.to_dict()

@app.post("/api/compliance/report/all")
async def compliance_report_all(body: dict):
    from reports.compliance_report import ComplianceReportGenerator
    findings = body.get("findings", [])
    target   = body.get("target", "")
    gen      = ComplianceReportGenerator()
    reports  = gen.generate_all(findings, target)
    return {k: v.to_dict() for k, v in reports.items()}

# ── Responsible Disclosure ────────────────────────────────────
@app.post("/api/disclosure")
async def create_disclosure(body: dict):
    from core.disclosure import DISCLOSURE_TRACKER
    rec = DISCLOSURE_TRACKER.create(
        title          = body.get("title",""),
        severity       = body.get("severity","HIGH"),
        target         = body.get("target",""),
        findings       = body.get("findings",[]),
        program        = body.get("program",""),
        program_url    = body.get("program_url",""),
        poc_notes      = body.get("poc_notes",""),
        reporter_name  = body.get("reporter_name",""),
    )
    return rec.to_dict()

@app.get("/api/disclosure")
async def list_disclosures(status: str = ""):
    from core.disclosure import DISCLOSURE_TRACKER
    records = DISCLOSURE_TRACKER.list(status=status or None)
    return {"disclosures": [r.to_dict() for r in records], "stats": DISCLOSURE_TRACKER.stats()}

@app.get("/api/disclosure/{did}")
async def get_disclosure(did: str):
    from core.disclosure import DISCLOSURE_TRACKER
    rec = DISCLOSURE_TRACKER.get(did)
    if not rec:
        raise HTTPException(status_code=404, detail="Disclosure not found")
    return rec.to_dict()

@app.post("/api/disclosure/{did}/advance")
async def advance_disclosure(did: str, body: dict):
    from core.disclosure import DISCLOSURE_TRACKER
    rec = DISCLOSURE_TRACKER.advance(did, body.get("status",""), **{
        k: v for k, v in body.items() if k not in ("status",)
    })
    return rec.to_dict() if rec else {"error": "not found"}

@app.get("/api/disclosure/{did}/submission")
async def disclosure_submission(did: str):
    from core.disclosure import DISCLOSURE_TRACKER
    md = DISCLOSURE_TRACKER.generate_submission(did)
    return {"markdown": md}

@app.get("/api/disclosure/overdue")
async def overdue_disclosures():
    from core.disclosure import DISCLOSURE_TRACKER
    return {"overdue": [r.to_dict() for r in DISCLOSURE_TRACKER.overdue()]}

# ── Parallel fast scan ────────────────────────────────────────
@app.post("/api/scan/fast")
async def scan_fast(body: dict):
    import asyncio
    from core.perf.optimizer import PARALLEL, make_fast_scanner
    from core.knowledge.message_normalizer import normalise_all
    path = body.get("path","")
    if not path or not Path(path).exists():
        raise HTTPException(status_code=400, detail="'path' required")
    scanner_fn = make_fast_scanner()
    loop       = asyncio.get_running_loop()
    result     = await loop.run_in_executor(None, lambda: PARALLEL.scan_directory(path, scanner_fn))
    result["findings"] = normalise_all(result.get("findings",[]))
    return result

@app.get("/api/scan/performance/stats")
async def perf_stats():
    from core.perf.optimizer import compile_cached
    # Report regex cache stats
    cache_info = compile_cached.cache_info()
    return {
        "regex_cache": {
            "hits":    cache_info.hits,
            "misses":  cache_info.misses,
            "maxsize": cache_info.maxsize,
            "currsize":cache_info.currsize,
        }
    }

# ═══════════════════════════════════════════════════════════════
# MERGED FROM V9 SUPER: SBOM, Local Embeddings,
# Bug Bounty Agent, Writeup Generator, Sandbox, Copilot
# ═══════════════════════════════════════════════════════════════

# ── CycloneDX SBOM ────────────────────────────────────────────
@app.post("/api/sbom/generate")
async def generate_sbom(body: dict):
    """Generate CycloneDX 1.4 SBOM for a repository."""
    import asyncio
    from scanners.supply_chain_scanner import generate_sbom as _gen_sbom
    path    = body.get("path","")
    name    = body.get("project_name", Path(path).name if path else "project")
    version = body.get("version","0.0.0")
    if not path or not Path(path).exists():
        raise HTTPException(status_code=400, detail="'path' required")
    loop = asyncio.get_running_loop()
    sbom = await loop.run_in_executor(None, lambda: _gen_sbom(path, name, version))
    return sbom

# ── Local Embeddings ───────────────────────────────────────────
@app.get("/api/embeddings/status")
async def embeddings_status():
    """Status of local embeddings engine (sentence-transformers or TF-IDF)."""
    try:
        from embeddings.local_embeddings import get_embeddings
        return get_embeddings().status()
    except Exception as e:
        return {"available": False, "error": str(e)}

@app.post("/api/embeddings/similar")
async def embeddings_similar(body: dict):
    """Find similar findings using local embeddings (no API key needed)."""
    import asyncio
    from embeddings.local_embeddings import get_embeddings
    findings   = body.get("findings",[])
    query_f    = body.get("query_finding",{})
    top_k      = body.get("top_k",5)
    min_score  = body.get("min_score",0.6)
    if not query_f or not findings:
        raise HTTPException(status_code=400, detail="'query_finding' and 'findings' required")
    loop   = asyncio.get_running_loop()
    engine = get_embeddings()
    result = await loop.run_in_executor(None, lambda: engine.find_similar_findings(query_f, findings, top_k, min_score))
    return {"similar": result, "backend": engine.backend}

# ── Bug Bounty Agent ───────────────────────────────────────────
@app.post("/api/bounty/triage")
async def bounty_triage(body: dict):
    """Triage a finding for bug bounty eligibility with CVSS scoring."""
    import asyncio
    from agents_ext.bug_bounty_agent import BugBountyAgent
    finding   = body.get("finding",{})
    program   = body.get("program","immunefi")
    if not finding:
        raise HTTPException(status_code=400, detail="'finding' required")
    loop   = asyncio.get_running_loop()
    agent  = BugBountyAgent()
    result = await loop.run_in_executor(None, lambda: agent.triage(finding))
    return result

@app.post("/api/bounty/writeup")
async def bounty_writeup(body: dict):
    """Generate professional bug bounty writeup for TON or general finding."""
    import asyncio
    from agents_ext.writeup_generator import TONWriteupGenerator
    findings  = body.get("findings",[])
    target    = body.get("target","")
    platform  = body.get("platform","immunefi")
    if not findings:
        raise HTTPException(status_code=400, detail="'findings' required")
    loop   = asyncio.get_running_loop()
    gen    = TONWriteupGenerator()
    result = await loop.run_in_executor(None, lambda: gen.generate(findings, target, platform))
    return {"writeup": result}

@app.get("/api/bounty/targets")
async def bounty_targets():
    """List known TON bug bounty programs with payout ranges."""
    from agents_ext.writeup_generator import TON_AUDIT_TARGETS
    return {"targets": TON_AUDIT_TARGETS}

# ── Security Copilot (streaming) ───────────────────────────────
@app.post("/api/copilot/ask")
async def copilot_ask(body: dict):
    """Ask TythanAI Copilot a security question."""
    import asyncio
    from core.security.security_copilot import SecurityCopilot
    question = body.get("question","")
    if not question:
        raise HTTPException(status_code=400, detail="'question' required")
    loop    = asyncio.get_running_loop()
    copilot = SecurityCopilot()
    answer  = await loop.run_in_executor(None, lambda: copilot.ask(question))
    return {"answer": answer}

@app.post("/api/copilot/explain")
async def copilot_explain(body: dict):
    """Explain a security finding in plain language."""
    import asyncio
    from core.security.security_copilot import SecurityCopilot
    finding = body.get("finding",{})
    if not finding:
        raise HTTPException(status_code=400, detail="'finding' required")
    loop    = asyncio.get_running_loop()
    copilot = SecurityCopilot()
    answer  = await loop.run_in_executor(None, lambda: copilot.explain_finding(finding))
    return {"explanation": answer}

@app.post("/api/copilot/fix")
async def copilot_fix(body: dict):
    """Generate a secure code fix for a finding."""
    import asyncio
    from core.security.security_copilot import SecurityCopilot
    finding  = body.get("finding",{})
    context  = body.get("code_context","")
    if not finding:
        raise HTTPException(status_code=400, detail="'finding' required")
    loop    = asyncio.get_running_loop()
    copilot = SecurityCopilot()
    fix     = await loop.run_in_executor(None, lambda: copilot.suggest_fix(finding, context))
    return {"fix": fix}

# ── Docker Sandbox ─────────────────────────────────────────────
@app.post("/api/sandbox/run")
async def sandbox_run(body: dict):
    """Execute code in isolated Docker sandbox (requires Docker)."""
    import asyncio
    from core.tools.sandbox_manager import SandboxManager
    code     = body.get("code","")
    filename = body.get("filename","test.py")
    if not code:
        raise HTTPException(status_code=400, detail="'code' required")
    loop   = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, lambda: SandboxManager().run_code(code, filename))
    return result

# ═══════════════════════════════════════════════════════════════
# PRODUCTION HARDENING: Pilot System, Plugin Registry, Health
# ═══════════════════════════════════════════════════════════════

# ── Deep Health Check ─────────────────────────────────────────
@app.get("/health/deep")
async def health_deep():
    """Readiness probe — checks all dependencies."""
    from core.security.middleware import deep_health_check
    result = await deep_health_check()
    status = 200 if result["ok"] else 503
    from fastapi.responses import JSONResponse
    return JSONResponse(content=result, status_code=status)

@app.get("/ping")
async def ping():
    """Liveness probe — fastest possible response."""
    return {"ok": True, "ts": __import__("time").time()}

# ── Rate Limiter ──────────────────────────────────────────────
@app.get("/api/admin/rate-limiter")
async def rate_limiter_status():
    from core.security.rate_limiter import RATE_LIMITER
    return RATE_LIMITER.status()

@app.delete("/api/admin/rate-limiter/{key}")
async def reset_rate_limit(key: str):
    from core.security.rate_limiter import RATE_LIMITER
    RATE_LIMITER.reset(key)
    return {"reset": key}

# ── Customer Pilot System ─────────────────────────────────────
@app.post("/api/pilots")
async def create_pilot(body: dict):
    from core.pilot import PILOTS
    from core.audit_log import AUDIT, AuditEvent
    if not body.get("company_name") or not body.get("contact_email"):
        raise HTTPException(status_code=400, detail="company_name and contact_email required")
    pilot = PILOTS.create_pilot(
        org_id        = body.get("org_id", "unset"),
        company_name  = body["company_name"],
        contact_email = body["contact_email"],
        contact_name  = body.get("contact_name",""),
        trial_days    = body.get("trial_days", 14),
        seats         = body.get("seats", 5),
        source        = body.get("source","api"),
        notes         = body.get("notes",""),
    )
    AUDIT.log(AuditEvent("pilot.created", f"Pilot created for {body['company_name']}",
                          org_id=body.get("org_id","")))
    return pilot.to_dict()

@app.get("/api/pilots")
async def list_pilots(status: str = ""):
    from core.pilot import PILOTS
    return {
        "pilots": [p.to_dict() for p in PILOTS.list(status=status or None)],
        "stats":  PILOTS.stats(),
    }

@app.get("/api/pilots/expiring")
async def expiring_pilots(days: int = 3):
    from core.pilot import PILOTS
    return {"expiring": [p.to_dict() for p in PILOTS.expiring_soon(days)]}

@app.get("/api/pilots/{pilot_id}")
async def get_pilot(pilot_id: str):
    from core.pilot import PILOTS
    p = PILOTS.get(pilot_id)
    if not p: raise HTTPException(404, "Pilot not found")
    return {**p.to_dict(), "usage": PILOTS.usage_summary(pilot_id)}

@app.post("/api/pilots/{pilot_id}/convert")
async def convert_pilot(pilot_id: str, body: dict):
    from core.pilot import PILOTS
    from core.audit_log import AUDIT, AuditEvent
    p = PILOTS.convert(pilot_id, plan=body.get("plan","pro"), notes=body.get("notes",""))
    if not p: raise HTTPException(404, "Pilot not found")
    AUDIT.log(AuditEvent("pilot.converted", f"Pilot converted: {p.company_name}",
                          resource=pilot_id))
    return p.to_dict()

@app.post("/api/pilots/{pilot_id}/extend")
async def extend_pilot(pilot_id: str, body: dict):
    from core.pilot import PILOTS
    p = PILOTS.extend(pilot_id, body.get("extra_days", 14))
    if not p: raise HTTPException(404, "Pilot not found")
    return p.to_dict()

@app.post("/api/pilots/{pilot_id}/churn")
async def churn_pilot(pilot_id: str, body: dict):
    from core.pilot import PILOTS
    p = PILOTS.churn(pilot_id, reason=body.get("reason",""))
    if not p: raise HTTPException(404, "Pilot not found")
    return p.to_dict()

@app.get("/api/pilots/stats/summary")
async def pilot_stats():
    from core.pilot import PILOTS
    return PILOTS.stats()

# ── Plugin Registry ────────────────────────────────────────────
@app.get("/api/plugins")
async def list_plugins():
    from core.plugin_registry import PLUGIN_REGISTRY
    return {
        "plugins": PLUGIN_REGISTRY.list_all(),
        "stats":   PLUGIN_REGISTRY.stats(),
    }

@app.post("/api/plugins/discover")
async def discover_plugins():
    from core.plugin_registry import PLUGIN_REGISTRY
    n = PLUGIN_REGISTRY.discover()
    return {"discovered": n, "total": len(PLUGIN_REGISTRY.list_all())}

@app.post("/api/plugins/{plugin_id}/load")
async def load_plugin(plugin_id: str):
    from core.plugin_registry import PLUGIN_REGISTRY
    ok = PLUGIN_REGISTRY.load(plugin_id)
    return {"plugin_id": plugin_id, "loaded": ok}

@app.post("/api/plugins/{plugin_id}/reload")
async def reload_plugin(plugin_id: str):
    from core.plugin_registry import PLUGIN_REGISTRY
    ok = PLUGIN_REGISTRY.reload(plugin_id)
    return {"plugin_id": plugin_id, "reloaded": ok}

@app.post("/api/plugins/{plugin_id}/enable")
async def enable_plugin(plugin_id: str):
    from core.plugin_registry import PLUGIN_REGISTRY
    return {"enabled": PLUGIN_REGISTRY.enable(plugin_id)}

@app.post("/api/plugins/{plugin_id}/disable")
async def disable_plugin(plugin_id: str):
    from core.plugin_registry import PLUGIN_REGISTRY
    return {"disabled": PLUGIN_REGISTRY.disable(plugin_id)}

@app.post("/api/plugins/validate")
async def validate_plugin(body: dict):
    import tempfile, os
    from core.plugin_registry import PLUGIN_REGISTRY
    plugin_dir = body.get("path","")
    if not plugin_dir or not Path(plugin_dir).exists():
        raise HTTPException(400, "'path' to plugin directory required")
    return PLUGIN_REGISTRY.validate(plugin_dir)

@app.post("/api/plugins/load-all")
async def load_all_plugins():
    from core.plugin_registry import PLUGIN_REGISTRY
    return PLUGIN_REGISTRY.load_all()
