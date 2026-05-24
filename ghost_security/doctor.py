#!/usr/bin/env python3
"""Ghost Security Platform v2.2 — Full Health Check"""
import sys, os, importlib, subprocess, tempfile, inspect
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

OK = "\033[92m✅\033[0m"; FAIL = "\033[91m❌\033[0m"; WARN = "\033[93m⚠️\033[0m"
results = []

def check(label, fn):
    try: fn(); results.append((OK, label))
    except Exception as e: results.append((FAIL, f"{label}: {e}"))

def warn(label, fn):
    try: fn(); results.append((OK, label))
    except Exception as e: results.append((WARN, f"{label} (optional): {e}"))

# ── Core deps ──────────────────────────────────────────────────────────────
for m in ["openai","fastapi","uvicorn","pydantic","requests","bandit"]:
    warn(f"pip: {m}", lambda x=m: importlib.import_module(x))

# ── All internal modules ───────────────────────────────────────────────────
MODULES = [
    "config.config",
    "scanners.ast_scanner.ast_analyzer",
    "scanners.secret_scanner.secret_detector",
    "scanners.ton_scanner.ton_analyzer",
    "scanners.llm_analyzer",
    "scanners.dependency_scanner",
    "agents.planner_agent", "agents.critic_agent", "agents.security_agent",
    "agents_ext.bug_bounty_agent", "agents_ext.threat_model_agent",
    "runtime.tool_executor", "runtime.model_router",
    "reports.report_generator", "reports.sarif_exporter",
    "orchestrator.multi_agent_runtime",
    "core.analysis.taint_tracker",
    "core.analysis.repository_risk_profiler",
    "core.knowledge.security_memory",
    "core.security.security_copilot",
    "core.security.findings_triage",
    "core.remediation.patch_generator",
    "core.distributed.task_queue",
    "core.runtime.health_monitor",
    "core.telemetry.security_event_bus",
    "core.autonomy.consensus_engine",
    "core.autonomy.decision_engine",
    "blockchain.ton.message_flow_analyzer",
]
for m in MODULES:
    check(f"import {m}", lambda x=m: importlib.import_module(x))

# ── Functional checks ──────────────────────────────────────────────────────
def _ton():
    from scanners.ton_scanner.ton_analyzer import TONAnalyzer
    a = TONAnalyzer()
    assert len(a.get_rules_summary()) >= 28
    with tempfile.NamedTemporaryFile(mode="w", suffix=".fc", delete=False) as f:
        f.write("accept_message();\n"); p = f.name
    try:
        assert any(x["id"]=="TON001" for x in a.analyze_file(p))
    finally: os.unlink(p)
check("TON Analyzer: 28 rules + TON001 fires", _ton)

def _taint():
    from core.analysis.taint_tracker import TaintTracker
    code = "data = request.args.get('x')\nsubprocess.run(data, shell=True)"
    findings = TaintTracker().analyze_code(code)
    assert len(findings) >= 1, "No taint flows found"
check("TaintTracker: source→sink flow detected", _taint)

def _deps():
    from scanners.dependency_scanner import DependencyScanner
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("pyyaml==5.3\n"); p = f.name
    try: assert len(DependencyScanner().scan_file(p)) >= 1
    finally: os.unlink(p)
check("DependencyScanner: CVE-2020-14343 detected", _deps)

def _sarif():
    from reports.sarif_exporter import SARIFExporter
    r = SARIFExporter().export({"target":"t","findings":[{
        "id":"T1","type":"X","severity":"HIGH","file":"f.py","line":1,
        "description":"d","evidence":"e","recommendation":"r","cwe":"CWE-78","source":"s","category":"c"
    }],"timestamp":"2025-01-01T00:00:00Z"})
    assert r["version"] == "2.1.0"
check("SARIF Exporter: valid 2.1.0 output", _sarif)

def _patch():
    from core.remediation.patch_generator import PatchGenerator
    f = {"id":"X","severity":"HIGH","description":"test","evidence":"subprocess.run(cmd, shell=True)","cwe":"CWE-78"}
    result = PatchGenerator().patch_finding(dict(f))
    assert result.get("code_fix") and result["code_fix"] != "N/A"
check("PatchGenerator: offline patch for CWE-78", _patch)

def _triage():
    from core.security.findings_triage import FindingsTriage
    findings = [
        {"id":"A","severity":"critical","description":"x","evidence":"y","file":"src.py","line":1,"source":"ast"},
        {"id":"A","severity":"HIGH","description":"x","evidence":"y","file":"src.py","line":1,"source":"semgrep"},
    ]
    result = FindingsTriage().triage(findings)
    assert result["duplicates_removed"] == 1, f"Expected 1 dup, got {result['duplicates_removed']}"
    assert result["findings"][0]["severity"] == "CRITICAL"
check("FindingsTriage: dedup + severity normalise", _triage)

def _consensus():
    from core.autonomy.consensus_engine import ConsensusEngine, Vote
    engine = ConsensusEngine()
    finding = {"id":"T1","severity":"HIGH"}
    votes = [
        {"agent":"ton_analyzer","vote":Vote.CONFIRM,"confidence":85,"reason":"real"},
        {"agent":"critic_agent","vote":Vote.CONFIRM,"confidence":75,"reason":"confirmed"},
        {"agent":"llm_analyzer","vote":Vote.DOWNGRADE,"confidence":40,"reason":"uncertain"},
    ]
    result = engine.vote(finding, votes)
    assert result["verdict"] in (Vote.CONFIRM, Vote.DOWNGRADE)
check("ConsensusEngine: weighted voting works", _consensus)

def _memory():
    from core.knowledge.security_memory import SecurityMemory
    import tempfile as _tmp
    db = Path(_tmp.mktemp(suffix=".db"))
    mem = SecurityMemory(db_path=db)
    mem.store_finding({"id":"T1","severity":"HIGH","cwe":"CWE-78","description":"test",
                       "file":"a.py","category":"x","source":"y"}, target="test_target")
    s = mem.summary()
    assert s["total_findings_ever"] >= 1
    db.unlink(missing_ok=True)
check("SecurityMemory: SQLite store + query", _memory)

def _repo():
    from core.analysis.repository_risk_profiler import RepositoryRiskProfiler
    with tempfile.TemporaryDirectory() as d:
        Path(d,"test.py").write_text("password = 'hardcoded123'\n")
        r = RepositoryRiskProfiler().profile(d)
        assert r["risk_tier"] in ("CRITICAL","HIGH","MEDIUM","LOW")
        assert len(r["hotspot_files"]) >= 1
check("RepositoryRiskProfiler: hardcoded cred detected", _repo)

def _bounty():
    from agents_ext.bug_bounty_agent import BugBountyAgent
    f = {"id":"T","severity":"CRITICAL","cwe":"CWE-798","description":"Hardcoded key",
         "evidence":"API_KEY='sk-abc123'","confidence":90}
    t = BugBountyAgent().triage(f)
    assert t["qualified"] == True
    assert "writeup" not in t   # triage only
check("BugBountyAgent: CRITICAL qualifies for bounty", _bounty)

def _threat():
    from agents_ext.threat_model_agent import ThreatModelAgent
    findings = [{"id":"T","severity":"HIGH","cwe":"CWE-78","description":"cmd inject"}]
    result = ThreatModelAgent().analyze("API", findings)
    assert result["total_threats"] >= 1
    assert "stride_coverage" in result
check("ThreatModelAgent: STRIDE analysis runs", _threat)

def _tool():
    from runtime.tool_executor import ToolExecutor
    src = inspect.getsource(ToolExecutor.run)
    for line in src.splitlines():
        assert "shell=True" not in line.split("#")[0]
    r = ToolExecutor().run("echo ghost_ok")
    assert "ghost_ok" in r.get("stdout","")
check("ToolExecutor: injection-safe + functional", _tool)

def _queue():
    from core.distributed.task_queue import AsyncTaskQueue, Priority
    q = AsyncTaskQueue()
    tid = q.submit("test", {"x":1}, Priority.HIGH)
    t = q.next_task()
    assert t is not None
    q.complete(t.task_id, result={"ok":True})
    done = q.wait(tid, timeout=2)
    assert done.status == "completed"
check("AsyncTaskQueue: submit→execute→complete", _queue)

def _event():
    from core.telemetry.security_event_bus import SecurityEventBus, SecurityEvent
    bus = SecurityEventBus()
    received = []
    bus.subscribe(SecurityEvent.FINDING_ADDED, lambda e: received.append(e))
    bus.publish(SecurityEvent.FINDING_ADDED, "test", {"id":"X"})
    assert len(received) == 1
check("SecurityEventBus: publish→subscribe works", _event)

def _router():
    from runtime.model_router import ModelRouter
    s = ModelRouter().status()
    assert "active_backend" in s and "routes" in s
check("ModelRouter: routing status available", _router)

def _stubs():
    assert "0.91"               not in inspect.getsource(importlib.import_module("agents.critic_agent").CriticAgent)
    assert '"semgrep": "passed"'not in inspect.getsource(importlib.import_module("agents.security_agent").SecurityAgent)
    assert "UNCENSORED"         not in open("core/agent/agent_loop.py").read()
check("No stub agents / unprofessional prompts remain", _stubs)

# ── Files present ──────────────────────────────────────────────────────────
for f in ["install.sh","Dockerfile","docker-compose.yml","tests/test_ton_analyzer.py",
          "integrations/github/github_actions.yml","web/templates/index.html"]:
    check(f"file: {f}", lambda p=f: (_ for _ in ()).throw(FileNotFoundError(p)) if not Path(p).exists() else None)

# ── External tools ─────────────────────────────────────────────────────────
for tool in ["git","curl","docker"]:
    try:
        r = subprocess.run([tool,"--version"], capture_output=True, text=True, timeout=5)
        results.append((OK if r.returncode==0 else WARN, f"external: {tool}"))
    except: results.append((WARN, f"external: {tool} not found (optional)"))

# ── Summary ────────────────────────────────────────────────────────────────
print("\n╔═══════════════════════════════════════════════════════════════╗")
print("║   Ghost Security Platform v2.2 — Full Health Check           ║")
print("╚═══════════════════════════════════════════════════════════════╝\n")
passed = sum(1 for s,_ in results if s==OK)
warned = sum(1 for s,_ in results if s==WARN)
failed = sum(1 for s,_ in results if s==FAIL)
for status, label in results:
    print(f"  {status}  {label}")
print(f"\n  ✅ {passed} passed   ⚠️  {warned} warned   ❌ {failed} failed")
if failed == 0:
    print("\n  \033[92mAll systems go — Ghost Security v2.2 is production-ready ✅\033[0m\n")
else:
    print("\n  \033[91mSome checks failed — see above\033[0m\n"); sys.exit(1)

# ── New scanner checks (appended) ─────────────────────────────────────────
def _owasp():
    from scanners.owasp_scanner import OWASPScanner, RULES
    assert len(RULES) >= 35, f"Expected ≥35 OWASP rules, got {len(RULES)}"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write('eval(user_input)\n'); p = f.name
    try:
        findings = OWASPScanner().scan_file(p)
        assert any("A03" in f.get("owasp_category","") for f in findings)
    finally: os.unlink(p)
check("OWASPScanner: 35+ rules, A03 injection fires", _owasp)

def _js():
    from scanners.js_analyzer import JSAnalyzer, JS_RULES
    assert len(JS_RULES) >= 20
    with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
        f.write("eval(x);\n"); p = f.name
    try:
        assert any(f["id"]=="JS010" for f in JSAnalyzer().analyze_file(p))
    finally: os.unlink(p)
check("JSAnalyzer: 20+ rules, JS010 eval fires", _js)

def _sol():
    from scanners.solidity_scanner import SolidityScanner, SOL_RULES
    assert len(SOL_RULES) >= 12
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as f:
        f.write("selfdestruct(owner);\n"); p = f.name
    try:
        assert any(f["id"]=="SOL004" for f in SolidityScanner().analyze_file(p))
    finally: os.unlink(p)
check("SolidityScanner: 12+ rules, SOL004 selfdestruct fires", _sol)

def _secrets_v2():
    from scanners.secret_scanner.secret_detector import SecretDetector, SECRET_PATTERNS
    assert len(SECRET_PATTERNS) >= 35, f"Expected ≥35, got {len(SECRET_PATTERNS)}"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write('key = "AKIAIOSFODNN7EXAMPLE"\n'); p = f.name
    try:
        findings = SecretDetector().scan_file(p)
        assert len(findings) >= 1
        # Ensure masking works
        assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].get("evidence","")
    finally: os.unlink(p)
check("SecretDetector v2: 35+ patterns, AWS detected + masked", _secrets_v2)

def _deps_v2():
    from scanners.dependency_scanner import DependencyScanner, KNOWN_VULNS
    assert len(KNOWN_VULNS) >= 40, f"Expected ≥40 packages, got {len(KNOWN_VULNS)}"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("pyyaml==5.3\njsonwebtoken==8.5.1\n"); p = f.name
    try:
        findings = DependencyScanner().scan_file(p)
        assert len(findings) >= 2
    finally: os.unlink(p)
check("DependencyScanner v2: 40+ packages, multi-CVE detection", _deps_v2)

def _pipeline():
    from scanners.security_pipeline import SecurityPipeline
    with tempfile.TemporaryDirectory() as d:
        Path(d,"app.py").write_text('import subprocess\nsubprocess.run(cmd,shell=True)\n')
        Path(d,"requirements.txt").write_text("pyyaml==5.3\n")
        result = SecurityPipeline().scan(d, mode="all")
        assert result["total_findings"] > 0
        assert "scanners_run" in result
check("SecurityPipeline: full scan, multi-scanner merge", _pipeline)
