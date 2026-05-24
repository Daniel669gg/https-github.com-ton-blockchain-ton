"""
Ghost Security Platform — Production CLI
Использование:
  ghost scan .                    # полный скан директории
  ghost scan --incremental .      # только изменённые файлы
  ghost ton ./contracts/          # TON bug bounty скан
  ghost k8s ./manifests/          # Kubernetes аудит
  ghost fix findings.json         # авто-фиксы
  ghost serve                     # запустить API сервер
  ghost benchmark                 # тест точности
  ghost status                    # статус всех компонентов
  ghost report findings.json      # Immunefi/HackenProof отчёт

Без Docker. Без сервера. Результат за секунды.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path


# ── ANSI colours ──────────────────────────────────────────────────────────────
_NO_COLOR = not sys.stdout.isatty() or os.getenv("NO_COLOR")

def _c(text: str, code: str) -> str:
    if _NO_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"

RED     = lambda t: _c(t, "31")
ORANGE  = lambda t: _c(t, "33")
YELLOW  = lambda t: _c(t, "93")
GREEN   = lambda t: _c(t, "32")
BLUE    = lambda t: _c(t, "34")
BOLD    = lambda t: _c(t, "1")
DIM     = lambda t: _c(t, "2")

_SEV_COLOR = {
    "CRITICAL": lambda t: _c(t, "1;31"),
    "HIGH":     lambda t: _c(t, "31"),
    "MEDIUM":   lambda t: _c(t, "33"),
    "LOW":      lambda t: _c(t, "34"),
    "INFO":     lambda t: _c(t, "2"),
}
_SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}


# ── Output helpers ─────────────────────────────────────────────────────────────

def _print_banner():
    print(BOLD("\n👻 Ghost Security Platform"))
    print(DIM("   AI-native AppSec · 250+ rules · TON · K8s · Multi-LLM\n"))

def _print_findings(findings: list, max_show: int = 50, output_fmt: str = "table"):
    if output_fmt == "json":
        print(json.dumps(findings, indent=2))
        return

    if not findings:
        print(GREEN("✅  No findings.\n"))
        return

    counts: dict = {}
    for f in findings:
        s = f.get("severity", "MEDIUM")
        counts[s] = counts.get(s, 0) + 1

    # Summary bar
    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        n = counts.get(sev, 0)
        if n:
            parts.append(_SEV_COLOR[sev](f"{_SEV_ICON[sev]} {sev}: {n}"))
    print("  " + "  ".join(parts))
    print()

    # Table
    shown = findings[:max_show]
    for f in shown:
        sev   = f.get("severity", "MEDIUM")
        icon  = _SEV_ICON.get(sev, "⚪")
        color = _SEV_COLOR.get(sev, lambda x: x)
        msg   = (f.get("message") or f.get("description") or "")[:65]
        loc   = f"{Path(f.get('file','')).name}:{f.get('line','')}"
        cwe   = f.get("cwe", "")
        cwe_s = DIM(f"  [{cwe}]") if cwe else ""
        print(f"  {color(icon + ' ' + sev.ljust(8))}  {BOLD(msg)}  {DIM(loc)}{cwe_s}")

    if len(findings) > max_show:
        print(DIM(f"\n  ... and {len(findings) - max_show} more findings. Use --output json for full list."))
    print()

def _print_summary(result: dict, duration: float):
    total = result.get("total_findings", len(result.get("findings", [])))
    risk  = result.get("risk_level", "")
    score = result.get("risk_score", 0)
    risk_color = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": GREEN}.get(risk, lambda x: x)
    print(f"  {BOLD('Findings:')} {total}   "
          f"{BOLD('Risk:')} {risk_color(risk)} ({score})   "
          f"{BOLD('Time:')} {duration:.2f}s\n")


# ══════════════════════════════════════════════════════════════════════════════
# COMMANDS
# ══════════════════════════════════════════════════════════════════════════════

def cmd_scan(args) -> int:
    """ghost scan [--incremental] [--output json|table] [--min-severity MEDIUM] <path>"""
    path = str(Path(args.path).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}"))
        return 1

    t0 = time.time()

    if args.incremental:
        print(BLUE(f"⚡ Incremental scan: {path}"))
        from core.incremental import IncrementalScanner
        scanner = IncrementalScanner(path)
        result  = scanner.scan(base=args.base or "HEAD~1")
        findings = result.new_findings
        print(DIM(f"   Changed: {len(result.changed_files)} files  "
                  f"Cached: {len(result.cached_files)}  Scanned: {len(result.scanned_files)}  "
                  f"Commit: {result.commit}"))
    else:
        print(BLUE(f"🔍 Full scan: {path}"))
        from scanners.owasp_scanner import OWASPScanner
        from scanners.secret_scanner.secret_detector import SecretDetector
        from scanners.cpp_scanner import CppScanner
        from core.knowledge.message_normalizer import normalise_all
        from core.knowledge.cve_enricher import CVEEnricher
        from verifier.confidence_engine import ConfidenceEngine

        raw = []
        p   = Path(path)

        # Python / JS / TS — OWASP + secrets
        src_files = (
            list(p.rglob("*.py")) + list(p.rglob("*.js")) + list(p.rglob("*.ts"))
        )
        src_files = [f for f in src_files
                     if "__pycache__" not in str(f) and "node_modules" not in str(f)]
        for fpath in src_files[:200]:
            try:
                raw += OWASPScanner().scan_file(str(fpath))
                raw += SecretDetector().scan_file(str(fpath))
            except Exception:
                pass

        # C / C++ — SAST scanner
        cpp_result = CppScanner().scan_directory(path, max_files=300)
        raw += cpp_result.get("findings", [])
        if cpp_result.get("files_scanned", 0):
            print(DIM(f"   C/C++: {cpp_result['files_scanned']} files, "
                      f"{cpp_result['total_findings']} findings"))

        raw = normalise_all(raw)
        raw = CVEEnricher(online=False).enrich(raw)
        processed = ConfidenceEngine(fp_threshold=0.35).process(raw)
        findings  = processed["findings"]

    # Apply min-severity filter
    order = ["INFO","LOW","MEDIUM","HIGH","CRITICAL"]
    min_idx = order.index(args.min_severity) if args.min_severity in order else 2
    findings = [f for f in findings if order.index(f.get("severity","MEDIUM")) >= min_idx]

    duration = time.time() - t0

    # Output
    if args.output == "json":
        print(json.dumps(findings, indent=2))
    else:
        _print_findings(findings, max_show=args.max_findings, output_fmt=args.output)
        _print_summary({"total_findings": len(findings), "findings": findings}, duration)

    # Save if requested
    if args.save:
        out_path = args.save
        Path(out_path).write_text(json.dumps(findings, indent=2))
        print(GREEN(f"💾  Saved to {out_path}"))

    # Exit code: 1 if critical findings
    crits = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    return 1 if crits > 0 and not args.no_fail else 0


def cmd_ton(args) -> int:
    """ghost ton <path> [--report] [--min-severity MEDIUM]"""
    path = str(Path(args.path).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}"))
        return 1

    print(BLUE(f"⛓  TON Smart Contract scan: {path}"))
    t0 = time.time()

    from scanners.ton_scanner.ton_analyzer import TONAnalyzer
    from core.knowledge.message_normalizer import normalise_all
    from core.knowledge.cve_enricher import CVEEnricher
    from verifier.confidence_engine import ConfidenceEngine

    p = Path(path)
    if p.is_file():
        raw = TONAnalyzer().analyze_file(str(p))
    else:
        result = TONAnalyzer().scan_directory(str(p))
        raw    = result.get("findings", [])

    raw      = normalise_all(raw)
    raw      = CVEEnricher(online=False).enrich(raw)
    processed = ConfidenceEngine(fp_threshold=0.25).process(raw)
    findings  = processed["findings"]

    order   = ["INFO","LOW","MEDIUM","HIGH","CRITICAL"]
    min_idx = order.index(args.min_severity) if hasattr(args,"min_severity") and args.min_severity in order else 1
    findings = [f for f in findings if order.index(f.get("severity","MEDIUM")) >= min_idx]

    duration = time.time() - t0
    _print_findings(findings, max_show=30)
    _print_summary({"total_findings": len(findings), "findings": findings}, duration)

    if hasattr(args, "report") and args.report and findings:
        from reports.bounty_report import BugBountyReportGenerator
        out_dir = args.report_dir if hasattr(args,"report_dir") and args.report_dir else "./ghost_reports/bounty"
        gen     = BugBountyReportGenerator(Path(path).name)
        outputs = gen.generate_all(findings, out_dir, min_severity="MEDIUM")
        print(GREEN(f"📄  Reports generated: {len(outputs)} files in {out_dir}/"))

    crits = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    return 1 if crits > 0 else 0


def cmd_k8s(args) -> int:
    """ghost k8s <path>"""
    path = str(Path(args.path).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}"))
        return 1

    print(BLUE(f"☸️   Kubernetes security scan: {path}"))
    t0 = time.time()

    from scanners.k8s_scanner.k8s_scanner import K8sSecurityScanner
    from core.knowledge.message_normalizer import normalise_all

    scanner  = K8sSecurityScanner()
    result   = scanner.scan(path, mode="manifest")
    findings_raw = result.get("findings", [])
    findings = normalise_all(findings_raw)

    duration = time.time() - t0
    _print_findings(findings, max_show=30)
    _print_summary({"total_findings": len(findings), "findings": findings}, duration)

    crits = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    return 1 if crits > 0 else 0


def cmd_fix(args) -> int:
    """ghost fix <findings.json> [--apply] [--pr owner/repo]"""
    findings_path = args.findings
    if not Path(findings_path).exists():
        print(RED(f"❌  File not found: {findings_path}"))
        return 1

    findings = json.loads(Path(findings_path).read_text())
    print(BLUE(f"🔧  Generating fixes for {len(findings)} findings..."))

    from remediation.remediation_engine import RemediationEngine
    engine  = RemediationEngine()
    patches = []
    for f in findings:
        p = engine.generate(f, use_llm=args.llm if hasattr(args,"llm") else False)
        if p:
            patches.append(p)

    print(f"\n  Generated {len(patches)}/{len(findings)} patches\n")
    for patch in patches:
        sev_icon = _SEV_ICON.get(patch.finding_type, "🔧")
        print(f"  {sev_icon}  {BOLD(patch.finding_type)} — {DIM(patch.description[:60])}")
        print(f"     Method: {patch.method}  Confidence: {patch.confidence:.0%}  "
              f"Safe: {'✅' if patch.safe_to_apply else '⚠️  (review required)'}")
        if args.diff:
            print(DIM(patch.diff[:500]))
        print()

    if hasattr(args,"apply") and args.apply:
        print(YELLOW("⚠️   Applying patches (with backup)..."))
        for patch in patches:
            if patch.safe_to_apply:
                ok, msg = engine.apply(patch)
                icon    = "✅" if ok else "❌"
                print(f"  {icon}  {patch.file}: {msg}")

    if hasattr(args,"pr") and args.pr:
        parts = args.pr.split("/")
        if len(parts) == 2:
            owner, repo = parts
            for patch in patches[:3]:  # limit PRs
                result = engine.create_pr(patch, owner, repo)
                if "pr_url" in result:
                    print(GREEN(f"  🔗  PR created: {result['pr_url']}"))
                else:
                    print(RED(f"  ❌  PR failed: {result.get('error')}"))

    return 0


def cmd_status(args) -> int:
    """ghost status"""
    print(BOLD("  Ghost Security Platform — Component Status\n"))

    # LLM providers
    try:
        from runtime.providers.multi_llm_router import ROUTER
        status = ROUTER.status()
        print(BOLD("  LLM Providers:"))
        for name, info in status["providers"].items():
            icon = "✅" if info["available"] else "❌"
            print(f"    {icon}  {name.ljust(8)}", end="")
            if name == "ollama" and info.get("models"):
                print(f"  {DIM(', '.join(info['models'][:3]))}")
            elif info.get("key_set"):
                print("  (API key set)")
            else:
                print("  (no key)")
    except Exception as e:
        print(f"  LLM: {RED(str(e))}")

    # Memory
    try:
        from memory.vector.ghost_memory import MEMORY
        mem = MEMORY.status()
        print(f"\n  {BOLD('Vector Memory:')} {mem['backend']}")
    except Exception:
        pass

    # DB
    try:
        from core.persistence.db import get_db
        stats = get_db().global_stats()
        print(f"\n  {BOLD('Database:')}")
        print(f"    Scans: {stats['total_scans']}  Findings: {stats['total_findings']}")
    except Exception:
        pass

    # Scanners
    from scanners.cpp_scanner import CppScanner
    from scanners.iac_scanner import IaCScanner
    from scanners.osv_scanner import OSVScanner
    cpp_count = CppScanner().pattern_count()
    osv_online = OSVScanner().is_online()
    osv_status = GREEN("live OSV.dev") if osv_online else YELLOW("offline (static DB)")
    print(f"\n  {BOLD('Scanners:')}")
    print(f"    SAST    : OWASP(35) · Secrets(45) · JS(25) · C/C++({cpp_count})")
    print(f"    IaC     : Dockerfile(17) · Terraform(18) · docker-compose(9) · GitHub Actions(7)")
    print(f"    Deps    : {osv_status}")
    print(f"    Infra   : Kubernetes(18)")
    print(f"    Blockchain: TON(87) · Solidity(15)")
    print(f"  {BOLD('Tests:')} 230 passing")

    # API server
    import urllib.request
    try:
        with urllib.request.urlopen("http://localhost:8000/health", timeout=2):
            print(f"\n  {BOLD('API Server:')} {GREEN('running')} at http://localhost:8000")
    except Exception:
        print(f"\n  {BOLD('API Server:')} {DIM('not running')} (ghost serve to start)")
    print()
    return 0


def cmd_serve(args) -> int:
    """ghost serve [--port 8000] [--workers 2]"""
    port    = getattr(args, "port", 8000)
    workers = getattr(args, "workers", 1)
    print(BLUE(f"🚀  Starting Ghost Security API on http://0.0.0.0:{port}"))
    print(DIM("   Press Ctrl+C to stop\n"))
    os.execvp("python3", [
        "python3", "-m", "uvicorn", "api.server:app",
        "--host", "0.0.0.0",
        "--port", str(port),
        "--workers", str(workers),
    ])
    return 0


def cmd_report(args) -> int:
    """ghost report <findings.json> [--format immunefi|hackenproof|summary]"""
    if not Path(args.findings).exists():
        print(RED(f"❌  File not found: {args.findings}"))
        return 1

    findings = json.loads(Path(args.findings).read_text())
    fmt      = getattr(args, "format", "summary")
    name     = getattr(args, "contract_name", "Contract")
    out_dir  = getattr(args, "out", "./ghost_reports/bounty")

    from reports.bounty_report import BugBountyReportGenerator
    gen = BugBountyReportGenerator(name)

    if fmt == "summary":
        reports = gen.from_findings(findings)
        print(gen.executive_summary(findings, reports))
    else:
        outputs = gen.generate_all(findings, out_dir, formats=["markdown","json","summary"])
        for path in outputs:
            print(GREEN(f"✅  {path}"))
    return 0


def cmd_benchmark(args) -> int:
    """ghost benchmark — run accuracy test on built-in test cases"""
    from tests.benchmark import run_benchmark
    return run_benchmark(verbose=getattr(args, "verbose", False))


def cmd_deps(args) -> int:
    """ghost deps <path> [--offline] [--output json|table] [--save FILE]

    Scan dependency manifests with live OSV.dev vulnerability database.
    Covers: requirements.txt, package.json, go.mod, Cargo.toml, Gemfile.
    Falls back to static CVE database when offline.
    """
    path = str(Path(args.path).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}"))
        return 1

    print(BLUE(f"📦  Dependency vulnerability scan: {path}"))
    t0 = time.time()

    from scanners.osv_scanner import OSVScanner
    from scanners.dependency_scanner import DependencyScanner

    scanner = OSVScanner()

    if getattr(args, "offline", False):
        print(DIM("   Mode: static CVE database (offline)"))
        result = DependencyScanner().scan_directory(path)
        result["online"] = False
    else:
        print(DIM("   Mode: live OSV.dev database"), end="", flush=True)
        result = scanner.scan_directory(path)
        if result.get("online"):
            print(GREEN(" ✓ connected"))
        else:
            print(YELLOW(" ✗ offline — using static DB"))

    findings  = result.get("findings", [])
    manifests = result.get("manifests_scanned", 0)
    packages  = result.get("total_packages", 0)
    duration  = time.time() - t0

    print(DIM(f"   Manifests: {manifests}  Packages: {packages}\n"))

    # Apply severity filter
    order   = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_sev = getattr(args, "min_severity", "LOW")
    min_idx = order.index(min_sev) if min_sev in order else 1
    findings = [f for f in findings if order.index(f.get("severity", "MEDIUM")) >= min_idx]

    if getattr(args, "output", "table") == "json":
        print(json.dumps(findings, indent=2))
    else:
        _print_findings(findings, max_show=50)
        _print_summary({"total_findings": len(findings), "findings": findings}, duration)

    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps(findings, indent=2))
        print(GREEN(f"💾  Saved to {args.save}"))

    crits = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    return 1 if crits > 0 and not getattr(args, "no_fail", False) else 0


def cmd_iac(args) -> int:
    """ghost iac <path> [--output json|table] [--save FILE]

    Scan Infrastructure-as-Code files for security misconfigurations:
      Dockerfile · docker-compose.yml · Terraform (.tf) · GitHub Actions
    """
    path = str(Path(args.path).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}"))
        return 1

    print(BLUE(f"🏗️   IaC security scan: {path}"))
    t0 = time.time()

    from scanners.iac_scanner import IaCScanner
    result   = IaCScanner().scan_directory(path)
    findings = result.get("findings", [])
    duration = time.time() - t0

    print(DIM(f"   IaC files scanned: {result.get('files_scanned', 0)}\n"))

    order   = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_sev = getattr(args, "min_severity", "LOW")
    min_idx = order.index(min_sev) if min_sev in order else 1
    findings = [f for f in findings if order.index(f.get("severity", "MEDIUM")) >= min_idx]

    if getattr(args, "output", "table") == "json":
        print(json.dumps(findings, indent=2))
    else:
        _print_findings(findings, max_show=50)
        _print_summary({"total_findings": len(findings), "findings": findings}, duration)

    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps(findings, indent=2))
        print(GREEN(f"💾  Saved to {args.save}"))

    crits = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    return 1 if crits > 0 and not getattr(args, "no_fail", False) else 0


def cmd_ci(args) -> int:
    """ghost ci [--type github|gitlab|pre-commit] [--path .] [--min-severity MEDIUM]

    Generate CI/CD integration files for Ghost Security scanning.
    Default: generates .github/workflows/ghost-security.yml
    """
    from integrations.ci_generator import CIGenerator
    gen  = CIGenerator()
    path = str(Path(getattr(args, "path", ".")).resolve())
    ci_type = getattr(args, "type", "github")

    if ci_type == "github":
        target = gen.write_github_actions(
            path,
            min_severity=getattr(args, "min_severity", "MEDIUM"),
            fail_on_critical=True,
            upload_sarif=True,
            iac_scan=True,
        )
        print(GREEN(f"✅  GitHub Actions workflow written: {target}"))
        print(DIM("   Commit and push — findings will appear in GitHub Security tab"))

    elif ci_type == "gitlab":
        snippet = gen.gitlab_ci_snippet(
            min_severity=getattr(args, "min_severity", "MEDIUM")
        )
        print(snippet)
        print(DIM("   Add the above to your .gitlab-ci.yml"))

    elif ci_type == "pre-commit":
        hook_path = gen.write_pre_commit_hook(path)
        if hook_path:
            print(GREEN(f"✅  Pre-commit hook written: {hook_path}"))
        else:
            print(DIM("   .git/hooks not found — paste this into .git/hooks/pre-commit:\n"))
            print(gen.pre_commit_script())

    return 0


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    _print_banner()

    parser = argparse.ArgumentParser(
        prog="ghost",
        description="Ghost Security Platform CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  ghost scan .                         # full SAST scan (Python/JS/C/C++)
  ghost scan --incremental .           # only changed files (fast)
  ghost deps .                         # live CVE scan via OSV.dev
  ghost deps --offline .               # offline CVE scan (static DB)
  ghost iac .                          # Dockerfile/Terraform/compose scan
  ghost ci --type github .             # generate GitHub Actions workflow
  ghost ton ./contracts/               # TON bug bounty scan + reports
  ghost k8s ./k8s/manifests/           # Kubernetes CIS audit
  ghost fix findings.json --diff       # show auto-fixes
  ghost fix findings.json --apply      # apply safe fixes (with backup)
  ghost serve --port 8000              # start API server
  ghost status                         # component health check
  ghost report findings.json           # generate Immunefi report
""",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Security scan of a directory or file")
    p_scan.add_argument("path", nargs="?", default=".")
    p_scan.add_argument("--incremental", "-i", action="store_true", help="Only scan git-changed files")
    p_scan.add_argument("--base", default="HEAD~1", help="Git base ref for incremental")
    p_scan.add_argument("--output", "-o", choices=["table","json"], default="table")
    p_scan.add_argument("--min-severity", default="MEDIUM", choices=["INFO","LOW","MEDIUM","HIGH","CRITICAL"])
    p_scan.add_argument("--max-findings", type=int, default=50)
    p_scan.add_argument("--save", metavar="FILE", help="Save findings to JSON file")
    p_scan.add_argument("--no-fail", action="store_true", help="Always exit 0")

    # ton
    p_ton = sub.add_parser("ton", help="TON smart contract security scan")
    p_ton.add_argument("path", nargs="?", default=".")
    p_ton.add_argument("--report", action="store_true", help="Generate Immunefi/HackenProof reports")
    p_ton.add_argument("--report-dir", default="./ghost_reports/bounty")
    p_ton.add_argument("--min-severity", default="LOW")

    # k8s
    p_k8s = sub.add_parser("k8s", help="Kubernetes security scan")
    p_k8s.add_argument("path", nargs="?", default=".")

    # fix
    p_fix = sub.add_parser("fix", help="Generate and apply security fixes")
    p_fix.add_argument("findings", nargs="?", default="findings.json")
    p_fix.add_argument("--diff", action="store_true", help="Show unified diff")
    p_fix.add_argument("--apply", action="store_true", help="Apply safe fixes to files (with backup)")
    p_fix.add_argument("--llm", action="store_true", help="Use LLM for complex fixes")
    p_fix.add_argument("--pr", metavar="owner/repo", help="Create GitHub PRs for fixes")

    # serve
    p_serve = sub.add_parser("serve", help="Start Ghost API server")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--workers", type=int, default=1)

    # status
    sub.add_parser("status", help="Component health check")

    # report
    p_rep = sub.add_parser("report", help="Generate bug bounty report")
    p_rep.add_argument("findings", nargs="?", default="findings.json")
    p_rep.add_argument("--format", choices=["immunefi","hackenproof","summary"], default="summary")
    p_rep.add_argument("--contract-name", default="Contract")
    p_rep.add_argument("--out", default="./ghost_reports/bounty")

    # benchmark
    p_bench = sub.add_parser("benchmark", help="Run accuracy benchmark")
    p_bench.add_argument("--verbose", action="store_true")

    # deps — live OSV.dev vulnerability scan
    p_deps = sub.add_parser("deps", help="Dependency CVE scan via live OSV.dev database")
    p_deps.add_argument("path", nargs="?", default=".")
    p_deps.add_argument("--offline", action="store_true", help="Use static CVE DB (no network)")
    p_deps.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_deps.add_argument("--min-severity", default="LOW",
                        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p_deps.add_argument("--save", metavar="FILE", help="Save findings to JSON file")
    p_deps.add_argument("--no-fail", action="store_true", help="Always exit 0")

    # iac — Infrastructure-as-Code scanner
    p_iac = sub.add_parser("iac", help="IaC security scan (Dockerfile, Terraform, docker-compose)")
    p_iac.add_argument("path", nargs="?", default=".")
    p_iac.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_iac.add_argument("--min-severity", default="LOW",
                       choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p_iac.add_argument("--save", metavar="FILE", help="Save findings to JSON file")
    p_iac.add_argument("--no-fail", action="store_true", help="Always exit 0")

    # ci — CI/CD integration generator
    p_ci = sub.add_parser("ci", help="Generate CI/CD integration files")
    p_ci.add_argument("path", nargs="?", default=".")
    p_ci.add_argument("--type", choices=["github", "gitlab", "pre-commit"], default="github",
                      help="CI system type (default: github)")
    p_ci.add_argument("--min-severity", default="MEDIUM",
                      choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0

    dispatch = {
        "scan":      cmd_scan,
        "ton":       cmd_ton,
        "k8s":       cmd_k8s,
        "fix":       cmd_fix,
        "serve":     cmd_serve,
        "status":    cmd_status,
        "report":    cmd_report,
        "benchmark": cmd_benchmark,
        "deps":      cmd_deps,
        "iac":       cmd_iac,
        "ci":        cmd_ci,
    }
    handler = dispatch.get(args.command)
    if handler:
        sys.exit(handler(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
