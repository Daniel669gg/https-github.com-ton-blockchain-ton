#!/usr/bin/env python3
"""
TythanAI Platform — CLI
Real command-line interface for the security auditor.
Usage: python3 ghost_cli.py [command] [options]
"""
import sys
import json
import time
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from config.config import OPENAI_API_KEY


def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════╗
║          TythanAI Platform v2.2                     ║
║          Autonomous AI Security Auditor                   ║
║          Real analysis. No placeholders.                  ║
╚═══════════════════════════════════════════════════════════╝
""")


def print_finding(f: dict, index: int = None):
    """Pretty-print a security finding."""
    sev = f.get("severity", "INFO")
    colors = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[93m",      # Yellow
        "MEDIUM": "\033[33m",    # Orange
        "LOW": "\033[94m",       # Blue
        "INFO": "\033[90m"       # Gray
    }
    reset = "\033[0m"
    color = colors.get(sev, "")

    prefix = f"[{index}] " if index else ""
    print(f"\n{color}{'─'*60}{reset}")
    print(f"{color}{prefix}[{sev}] {f.get('type', 'Unknown')}{reset}")
    print(f"  File: {f.get('file', 'N/A')} (line {f.get('line', 'N/A')})")
    print(f"  Description: {f.get('description', '')}")
    if f.get("cwe"):
        print(f"  CWE: {f['cwe']}")
    if f.get("evidence"):
        print(f"  Evidence: {f['evidence'][:100]}")
    if f.get("recommendation"):
        print(f"  \033[96mRecommendation: {f['recommendation'][:100]}{reset}")


def cmd_scan(args):
    """Run security scan on a path."""
    from scanners.ast_scanner.ast_analyzer import ASTScanner
    from scanners.secret_scanner.secret_detector import SecretDetector
    from scanners.semgrep_scanner.semgrep_scanner import SemgrepScanner

    target = Path(args.target)
    if not target.exists():
        print(f"\033[91mError: Path not found: {args.target}\033[0m")
        sys.exit(1)

    print(f"\n🔍 Scanning: {args.target}")
    print(f"   Mode: {args.mode}")
    all_findings = []

    # Secret detection
    if args.mode in ["all", "secrets"]:
        print("\n[1/3] Running secret detection...")
        detector = SecretDetector()
        if target.is_file():
            findings = detector.scan_file(str(target))
        else:
            result = detector.scan_directory(str(target))
            findings = result.get("findings", [])
        print(f"      Found {len(findings)} secret-related issues")
        all_findings.extend(findings)

    # AST analysis
    if args.mode in ["all", "ast"]:
        print("\n[2/3] Running AST security analysis...")
        scanner = ASTScanner()
        if target.is_file():
            findings = scanner.scan_file(str(target))
        else:
            result = scanner.scan_directory(str(target))
            findings = result.get("findings", [])
        print(f"      Found {len(findings)} code security issues")
        all_findings.extend(findings)

    # Semgrep
    if args.mode in ["all", "semgrep"]:
        print("\n[3/3] Running Semgrep analysis...")
        semgrep = SemgrepScanner()
        if semgrep.semgrep_available:
            result = semgrep.scan_path(str(target))
            findings = result.get("findings", [])
            print(f"      Found {len(findings)} Semgrep findings")
            all_findings.extend(findings)
        else:
            print("      Semgrep not available, skipping")

    # Deduplicate
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f.get("file", ""), f.get("line", 0), f.get("type", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda f: severity_order.get(f.get("severity", "INFO"), 5))

    # Print results
    print(f"\n{'═'*60}")
    print(f"SCAN RESULTS: {args.target}")
    print(f"{'═'*60}")

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in deduped:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

    print(f"\n  🔴 Critical: {counts['CRITICAL']}")
    print(f"  🟠 High:     {counts['HIGH']}")
    print(f"  🟡 Medium:   {counts['MEDIUM']}")
    print(f"  🔵 Low:      {counts['LOW']}")
    print(f"  ─────────────────")
    print(f"  Total:       {len(deduped)}")

    if deduped:
        print(f"\n{'─'*60}")
        print("FINDINGS:")
        for i, f in enumerate(deduped, 1):
            print_finding(f, i)

    # Save report
    if args.output:
        from reports.report_generator import ReportGenerator
        risk_score = min(counts["CRITICAL"]*25 + counts["HIGH"]*15 + counts["MEDIUM"]*8 + counts["LOW"]*3, 100)
        report = {
            "session_id": "cli_scan",
            "target": str(target),
            "audit_type": "cli",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "risk_score": risk_score,
            "risk_level": "CRITICAL" if risk_score >= 75 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 25 else "LOW",
            "executive_summary": f"CLI scan of {target} found {len(deduped)} issues.",
            "severity_counts": counts,
            "total_findings": len(deduped),
            "findings": deduped,
            "recommendations": []
        }
        gen = ReportGenerator()
        if args.output.endswith(".html"):
            Path(args.output).write_text(gen.generate_html(report))
        elif args.output.endswith(".md"):
            Path(args.output).write_text(gen.generate_markdown(report))
        else:
            Path(args.output).write_text(json.dumps(report, indent=2))
        print(f"\n✅ Report saved to: {args.output}")

    return len(deduped)


def cmd_audit(args):
    """Run full multi-agent audit."""
    if not OPENAI_API_KEY:
        import os
        os.environ["OPENAI_API_KEY"] = "ollama"

    from agents.orchestrator import MultiAgentOrchestrator
    from reports.report_generator import ReportGenerator

    print(f"\n🚀 Starting full audit of: {args.target}")
    print(f"   Audit type: {args.audit_type}")

    orchestrator = MultiAgentOrchestrator()
    events_log = []

    def callback(event_type, data):
        events_log.append((event_type, data))
        if event_type == "status":
            print(f"   [{event_type}] {data.get('step', '')}")
        elif event_type in ["scanner_result", "agent_complete"]:
            print(f"   [{event_type}] {json.dumps(data)[:80]}")
        elif event_type == "completed":
            print(f"\n✅ Audit completed!")

    session_id = orchestrator.start_audit(
        target=args.target,
        audit_type=args.audit_type,
        callback=callback
    )

    print(f"   Session ID: {session_id}")
    print(f"   Waiting for completion...")

    # Wait for completion
    max_wait = 300  # 5 minutes
    start = time.time()
    while time.time() - start < max_wait:
        status = orchestrator.get_session_status(session_id)
        if status.get("status") in ["completed", "failed"]:
            break
        time.sleep(2)

    session = orchestrator.get_session(session_id)
    if not session or not session.report:
        print("\033[91mAudit failed or timed out\033[0m")
        sys.exit(1)

    report = session.report
    print(f"\n{'═'*60}")
    print(f"AUDIT RESULTS")
    print(f"{'═'*60}")
    print(f"  Risk Score: {report['risk_score']}/100 — {report['risk_level']}")
    print(f"  Critical: {report['severity_counts'].get('CRITICAL', 0)}")
    print(f"  High: {report['severity_counts'].get('HIGH', 0)}")
    print(f"  Total: {report['total_findings']}")
    print(f"\n  Summary: {report.get('executive_summary', '')[:200]}")

    # Save report
    gen = ReportGenerator()
    output_dir = args.output or "./ghost_reports"
    paths = gen.save_report(report, output_dir)
    print(f"\n✅ Reports saved:")
    for fmt, path in paths.items():
        print(f"   {fmt}: {path}")


def cmd_github(args):
    """Watch GitHub repository."""
    from scanners.github_watcher.github_watcher import GitHubWatcher

    print(f"\n👁 Watching GitHub: {args.owner}/{args.repo} ({args.branch})")
    watcher = GitHubWatcher()
    result = watcher.watch_repository(args.owner, args.repo, args.branch, args.commits)

    if "error" in result:
        print(f"\033[91mError: {result['error']}\033[0m")
        sys.exit(1)

    print(f"\n  Repository: {result['repo']}")
    print(f"  Commits checked: {result.get('total_commits_checked', 0)}")
    print(f"  Issues found: {result.get('total_findings', 0)}")

    for f in result.get("findings", []):
        print_finding(f)


def cmd_server(args):
    """Start the API server."""
    print(f"\n🌐 Starting TythanAI API Server")
    print(f"   Host: {args.host}:{args.port}")
    print(f"   Dashboard: http://{args.host}:{args.port}/")
    print(f"   API Docs: http://{args.host}:{args.port}/docs")

    import uvicorn
    from api.server import app
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")




def cmd_ton(args):
    """Scan TON smart contracts (.fc / .func / .tact / .fift)."""
    from scanners.ton_scanner.ton_analyzer import TONAnalyzer
    from pathlib import Path as _P

    target = _P(args.target)
    if not target.exists():
        print(f"\033[91mError: path not found: {args.target}\033[0m")
        sys.exit(1)

    print(f"\n⛓  TON Smart Contract Audit: {args.target}")
    analyzer = TONAnalyzer()

    if target.is_dir():
        result = analyzer.scan_directory(str(target))
        findings = result.get("findings", [])
        print(f"   Files scanned: {result.get('files_scanned', 0)}")
    else:
        findings = analyzer.analyze_file(str(target))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.get("severity", "INFO")] = counts.get(f.get("severity", "INFO"), 0) + 1

    print(f"\n{'═'*60}")
    print(f"  🔴 Critical : {counts['CRITICAL']}")
    print(f"  🟠 High     : {counts['HIGH']}")
    print(f"  🟡 Medium   : {counts['MEDIUM']}")
    print(f"  🔵 Low      : {counts['LOW']}")
    print(f"  ⚪ Info     : {counts['INFO']}")
    print(f"  {'─'*30}")
    print(f"  Total       : {len(findings)}")
    print(f"{'═'*60}")

    for i, f in enumerate(findings, 1):
        print_finding(f, i)

    if hasattr(args, "output") and args.output:
        import json as _j, time as _t
        from pathlib import Path as _P2
        risk = min(counts["CRITICAL"]*25 + counts["HIGH"]*15 + counts["MEDIUM"]*8 + counts["LOW"]*3, 100)
        from reports.report_generator import ReportGenerator
        report = {
            "session_id": "ton_cli", "target": str(target),
            "audit_type": "ton",
            "timestamp": _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime()),
            "risk_score": risk,
            "risk_level": "CRITICAL" if risk>=75 else "HIGH" if risk>=50 else "MEDIUM" if risk>=25 else "LOW",
            "executive_summary": f"TON audit of {target}: {len(findings)} finding(s).",
            "severity_counts": counts, "total_findings": len(findings),
            "findings": findings, "recommendations": [],
        }
        gen = ReportGenerator()
        out = _P2(args.output)
        if args.output.endswith(".html"):
            out.write_text(gen.generate_html(report))
        elif args.output.endswith(".md"):
            out.write_text(gen.generate_markdown(report))
        else:
            out.write_text(_j.dumps(report, indent=2))
        print(f"\n✅ Report saved: {args.output}")



def cmd_deps(args):
    """Scan dependency files for known CVEs."""
    from scanners.dependency_scanner import DependencyScanner
    from pathlib import Path as _P
    import json as _json

    target = _P(args.target)
    if not target.exists():
        print(f"\033[91mError: path not found: {args.target}\033[0m")
        sys.exit(1)

    print(f"\n📦 Dependency Scan: {args.target}")
    scanner = DependencyScanner()

    if target.is_dir():
        result = scanner.scan_directory(str(target))
        findings = result["findings"]
        print(f"   Manifests scanned: {result['manifests_scanned']}")
    else:
        findings = scanner.scan_file(str(target))

    counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for f in findings:
        sev = f.get("severity","LOW")
        counts[sev] = counts.get(sev,0) + 1

    print(f"\n{'═'*60}")
    print(f"  🔴 CRITICAL : {counts['CRITICAL']}")
    print(f"  🟠 HIGH     : {counts['HIGH']}")
    print(f"  🟡 MEDIUM   : {counts['MEDIUM']}")
    print(f"  {'─'*20}")
    print(f"  Total       : {len(findings)}")
    print(f"{'═'*60}")

    for i, f in enumerate(findings, 1):
        print_finding(f, i)

    if args.output:
        from pathlib import Path as _P2
        _P2(args.output).write_text(_json.dumps({"findings": findings}, indent=2))
        print(f"\n✅ Saved: {args.output}")


def cmd_sarif(args):
    """Export an existing JSON report to SARIF format for GitHub Code Scanning."""
    import json as _json
    from pathlib import Path as _P
    from reports.sarif_exporter import SARIFExporter

    src = _P(args.input)
    if not src.exists():
        print(f"\033[91mError: report not found: {args.input}\033[0m")
        sys.exit(1)

    report = _json.loads(src.read_text())
    exporter = SARIFExporter()
    out = args.output or str(src.with_suffix(".sarif"))
    exporter.export_to_file(report, out)
    print(f"\n✅ SARIF exported: {out}")
    print(f"   Upload to GitHub → Security → Code Scanning → Upload SARIF file")


def cmd_llm_status(args):
    """Show LLM / model routing status."""
    from runtime.model_router import ModelRouter
    import json as _json
    status = ModelRouter().status()
    print("\n🤖 LLM / Model Router Status")
    print(f"{'═'*40}")
    print(f"  Ollama available : {status['ollama_available']}")
    if status['ollama_models']:
        print(f"  Ollama models    : {', '.join(status['ollama_models'])}")
    print(f"  Cloud available  : {status['cloud_available']}")
    print(f"  Active backend   : {status['active_backend']}")
    print(f"\n  Task routing:")
    for task, model in status['routes'].items():
        print(f"    {task:<12} → {model}")



def cmd_taint(args):
    """AST dataflow / taint analysis for Python source code."""
    from core.analysis.taint_tracker import TaintTracker
    from pathlib import Path as _P
    import json as _json
    target = _P(args.target)
    if not target.exists():
        print(f"\033[91mError: path not found: {args.target}\033[0m"); sys.exit(1)
    tracker = TaintTracker()
    if target.is_file():
        findings = tracker.analyze_file(str(target))
    else:
        findings = []
        for f in target.rglob("*.py"):
            findings.extend(tracker.analyze_file(str(f)))
    counts = {}
    for f in findings:
        s = f.get("severity","HIGH"); counts[s] = counts.get(s,0)+1
    print(f"\n🔀 Taint Analysis: {args.target}")
    print(f"{'═'*55}")
    print(f"  🔴 CRITICAL : {counts.get('CRITICAL',0)}")
    print(f"  🟠 HIGH     : {counts.get('HIGH',0)}")
    print(f"  🟡 MEDIUM   : {counts.get('MEDIUM',0)}")
    print(f"  ─────────────────────")
    print(f"  Total flows : {len(findings)}")
    print(f"{'═'*55}")
    for i, f in enumerate(findings,1): print_finding(f,i)
    if args.output:
        _P(args.output).write_text(_json.dumps({"findings":findings,"total":len(findings)},indent=2))
        print(f"\n✅ Saved: {args.output}")


def cmd_profile(args):
    """Repository risk profile and file heatmap."""
    from core.analysis.repository_risk_profiler import RepositoryRiskProfiler
    from pathlib import Path as _P
    import json as _json
    target = args.target
    if not _P(target).exists():
        print(f"\033[91mError: path not found: {target}\033[0m"); sys.exit(1)
    print(f"\n📊 Repository Risk Profile: {target}")
    rp = RepositoryRiskProfiler().profile(target)
    print(f"{'═'*55}")
    print(f"  Fingerprint : {rp.get('fingerprint','?')}")
    print(f"  Files       : {rp.get('total_files',0)}")
    print(f"  Lines       : {rp.get('total_lines',0):,}")
    print(f"  Risk Score  : {rp.get('risk_score',0)}/100 ({rp.get('risk_tier','?')})")
    print(f"  Languages   : {', '.join(f'{k}({v})' for k,v in (rp.get('languages') or {}).items())}")
    print(f"\nHotspot Files:")
    for h in (rp.get('hotspot_files') or [])[:8]:
        sev = h.get('risk_level','LOW')
        icon = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🔵'}.get(sev,'⚪')
        print(f"  {icon} [{h['score']:4d}] {h['file']}")
    if args.output:
        _P(args.output).write_text(_json.dumps(rp,indent=2))
        print(f"\n✅ Saved: {args.output}")


def cmd_memory(args):
    """Query the security memory / knowledge base."""
    from core.knowledge.security_memory import MEMORY
    sub = getattr(args,'subcmd','summary')
    if sub == 'summary':
        s = MEMORY.summary()
        print(f"\n🧠 Security Memory Summary")
        print(f"{'═'*40}")
        for k,v in s.items(): print(f"  {k:<25}: {v}")
    elif sub == 'recurring':
        findings = MEMORY.recurring_findings(2)
        print(f"\n🔁 Recurring Findings ({len(findings)})")
        for f in findings:
            print(f"  [{f['severity']}] {f['finding_id']} — seen {f['occurrences']}x — {f.get('description','')[:60]}")
    elif sub == 'cwes':
        cwes = MEMORY.top_cwes(10)
        print("\n📊 Top CWEs")
        for c in cwes:
            print(f"  {c['cwe']:<12} {c['count']:3d}x  max={c['max_severity']}")
    elif sub == 'trend':
        trend = MEMORY.risk_trend(30)
        print("\n📈 Risk Trend (30 days)")
        for t in trend[-10:]:
            bar = '█' * int(t['avg_risk']/10)
            print(f"  {t['date']}  {bar:<10}  {t['avg_risk']:.0f}")


def cmd_bounty(args):
    """Bug bounty triage and write-up generation."""
    from agents_ext.bug_bounty_agent import BugBountyAgent
    import json as _json
    from pathlib import Path as _P
    agent = BugBountyAgent()

    if args.mode == 'triage':
        if not args.input:
            print("Provide --input findings.json"); sys.exit(1)
        findings = _json.loads(_P(args.input).read_text()).get("findings",[])
        print(f"\n🎯 Bug Bounty Triage ({len(findings)} findings)")
        print(f"{'═'*55}")
        qualified = 0
        for f in findings:
            t = agent.triage(f)
            q = t['qualified']
            if q: qualified += 1
            icon = '✅' if q else '❌'
            print(f"  {icon} [{f.get('severity','?')}] {f.get('id','?')}: {t['payout_estimate']} — score {t['triage_score']}")
        print(f"\n  Qualified for bounty: {qualified}/{len(findings)}")
    elif args.mode == 'writeup':
        if not args.input:
            print("Provide --input finding.json"); sys.exit(1)
        finding = _json.loads(_P(args.input).read_text())
        if isinstance(finding, list): finding = finding[0]
        writeup = agent.generate_writeup(finding, args.target or "Target")
        if args.output:
            _P(args.output).write_text(writeup)
            print(f"✅ Write-up saved: {args.output}")
        else:
            print(writeup)



def cmd_owasp(args):
    """OWASP Top 10 (2021) systematic scan."""
    from scanners.owasp_scanner import OWASPScanner
    from pathlib import Path as _P
    import json as _json
    target = args.target
    if not _P(target).exists():
        print(f"\033[91mError: {target} not found\033[0m"); sys.exit(1)
    print(f"\n🔟 OWASP Top 10 Scan: {target}")
    scanner = OWASPScanner()
    result = scanner.scan_directory(target) if _P(target).is_dir() else {"findings": scanner.scan_file(target)}
    findings = result.get("findings", [])
    owasp_c = result.get("owasp_counts", {})
    sev_c   = result.get("severity_counts", {})
    print(f"{'═'*60}")
    print(f"  Files scanned : {result.get('files_scanned', '?')}")
    print(f"  Total findings: {len(findings)}")
    print(f"  Critical: {sev_c.get('CRITICAL',0)}  High: {sev_c.get('HIGH',0)}  Medium: {sev_c.get('MEDIUM',0)}")
    if owasp_c:
        print(f"\n  OWASP Categories hit:")
        for cat, cnt in sorted(owasp_c.items(), key=lambda x: -x[1]):
            print(f"    {cat}: {cnt}")
    print(f"{'═'*60}")
    for i, f in enumerate(findings, 1): print_finding(f, i)
    if args.output:
        _P(args.output).write_text(_json.dumps(result, indent=2))
        print(f"\n✅ Saved: {args.output}")


def cmd_solidity(args):
    """Solidity (.sol) smart contract security audit."""
    from scanners.solidity_scanner import SolidityScanner
    from pathlib import Path as _P
    import json as _json
    target = args.target
    if not _P(target).exists():
        print(f"\033[91mError: {target} not found\033[0m"); sys.exit(1)
    print(f"\n⬟  Solidity Audit: {target}")
    scanner = SolidityScanner()
    result  = scanner.scan_directory(target) if _P(target).is_dir() else {
        "findings": scanner.analyze_file(target)}
    findings = result.get("findings", [])
    sev_c    = result.get("severity_counts", {})
    print(f"{'═'*60}")
    print(f"  🔴 CRITICAL : {sev_c.get('CRITICAL',0)}")
    print(f"  🟠 HIGH     : {sev_c.get('HIGH',0)}")
    print(f"  🟡 MEDIUM   : {sev_c.get('MEDIUM',0)}")
    print(f"  ─────────────────────")
    print(f"  Total       : {len(findings)}")
    print(f"{'═'*60}")
    for i, f in enumerate(findings, 1): print_finding(f, i)
    if args.output:
        _P(args.output).write_text(_json.dumps(result, indent=2))
        print(f"\n✅ Saved: {args.output}")

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="TythanAI Platform — Autonomous AI Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Quick security scan")
    scan_parser.add_argument("target", help="File or directory to scan")
    scan_parser.add_argument("--mode", choices=["all", "ast", "secrets", "semgrep"], default="all")
    scan_parser.add_argument("--output", "-o", help="Output report file (.json, .html, .md)")

    # audit command
    audit_parser = subparsers.add_parser("audit", help="Full multi-agent audit")
    audit_parser.add_argument("target", help="Target to audit (path or GitHub URL)")
    audit_parser.add_argument("--audit-type", choices=["full", "quick", "secrets", "code"], default="full")
    audit_parser.add_argument("--output", "-o", help="Output directory for reports")

    # github command
    gh_parser = subparsers.add_parser("github", help="Watch GitHub repository")
    gh_parser.add_argument("owner", help="Repository owner")
    gh_parser.add_argument("repo", help="Repository name")
    gh_parser.add_argument("--branch", default="main")
    gh_parser.add_argument("--commits", type=int, default=5)

    # ton command
    ton_parser = subparsers.add_parser("ton", help="Audit TON smart contracts (.fc/.tact/.fift)")
    ton_parser.add_argument("target", help="Contract file or directory to audit")
    ton_parser.add_argument("--output", "-o", help="Save report (.json / .html / .md)")

    # deps command
    deps_parser = subparsers.add_parser("deps", help="Scan dependencies for known CVEs")
    deps_parser.add_argument("target", help="requirements.txt, package.json, or directory")
    deps_parser.add_argument("--output", "-o", help="Output JSON file")

    # sarif command
    sarif_parser = subparsers.add_parser("sarif", help="Export report to SARIF (GitHub Code Scanning)")
    sarif_parser.add_argument("input", help="JSON report file to convert")
    sarif_parser.add_argument("--output", "-o", help="Output .sarif file (default: input.sarif)")

    # llm-status command
    llms_parser = subparsers.add_parser("llm-status", help="Show LLM / model routing status")

    # owasp command
    owasp_p = subparsers.add_parser("owasp", help="OWASP Top 10 (2021) systematic scan")
    owasp_p.add_argument("target", help="Directory or file")
    owasp_p.add_argument("--output","-o", help="Output JSON")

    # solidity command
    sol_p = subparsers.add_parser("solidity", help="Solidity smart contract audit")
    sol_p.add_argument("target", help=".sol file or directory")
    sol_p.add_argument("--output","-o", help="Output JSON")

    # taint command
    taint_p = subparsers.add_parser("taint", help="AST dataflow / taint analysis (Python)")
    taint_p.add_argument("target", help="Python file or directory")
    taint_p.add_argument("--output","-o", help="Output JSON")

    # profile command
    prof_p = subparsers.add_parser("profile", help="Repository risk profile and heatmap")
    prof_p.add_argument("target", help="Repository directory")
    prof_p.add_argument("--output","-o", help="Output JSON")

    # memory command
    mem_p = subparsers.add_parser("memory", help="Security memory / knowledge base")
    mem_p.add_argument("subcmd", nargs="?", default="summary",
                       choices=["summary","recurring","cwes","trend"])

    # bounty command
    bnty_p = subparsers.add_parser("bounty", help="Bug bounty triage and write-up")
    bnty_p.add_argument("mode", choices=["triage","writeup"])
    bnty_p.add_argument("--input","-i", help="findings.json input")
    bnty_p.add_argument("--target", default="Target Application")
    bnty_p.add_argument("--output","-o", help="Output write-up file")

    # server command
    srv_parser = subparsers.add_parser("server", help="Start web API server")
    srv_parser.add_argument("--host", default="0.0.0.0")
    srv_parser.add_argument("--port", type=int, default=8000)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "audit":
        cmd_audit(args)
    elif args.command == "github":
        cmd_github(args)
    elif args.command == "deps":
        cmd_deps(args)
    elif args.command == "sarif":
        cmd_sarif(args)
    elif args.command == "llm-status":
        cmd_llm_status(args)
    elif args.command == "ton":
        cmd_ton(args)
    elif args.command == "server":
        cmd_server(args)


if __name__ == "__main__":
    main()


def cmd_doctor(args):
    from doctor import run
    run()
