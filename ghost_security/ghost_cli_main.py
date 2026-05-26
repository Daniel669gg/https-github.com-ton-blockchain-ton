"""
Ghost Security Platform — Production CLI
Использование:
  ghost scan .                    # полный скан директории
  ghost scan --incremental .      # только изменённые файлы
  ghost ton ./contracts/          # TON bug bounty скан
  ghost k8s ./manifests/          # Kubernetes аудит
  ghost deps .                    # live CVE scan (OSV.dev)
  ghost iac .                     # IaC scan (Docker/Terraform/Ansible/Helm/CFN)
  ghost container nginx:1.21.0    # container image CVE scan
  ghost sbom .                    # generate SPDX 2.3 / CycloneDX SBOM
  ghost compliance .              # compliance gap report (PCI-DSS/SOC2/HIPAA/NIST)
  ghost fix-deps .                # auto-fix vulnerable dependency versions
  ghost suppress .ghostignore     # manage finding suppressions
  ghost fix findings.json         # авто-фиксы кода
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
    print(DIM("   AI-native AppSec · 3000+ rules · TON · K8s · Multi-LLM\n"))

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

    # Apply rule tuner if requested
    if getattr(args, "tune", False):
        try:
            from core.analysis.rule_tuner import RuleTuner
            tuner = RuleTuner()
            loaded = tuner.load()
            if loaded:
                findings = tuner.apply(findings)
                findings = [f for f in findings if not f.get("suppressed")]
                print(DIM(f"   Rule tuner: {loaded} override(s) applied"))
        except Exception as e:
            print(DIM(f"   Rule tuner skipped: {e}"))

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

    elite = getattr(args, "elite", False)

    # ── Elite: Gas Risk Analysis ───────────────────────────────────────────────
    if elite or getattr(args, "gas", False):
        print(BLUE("\n⛽  Gas Risk Analysis"))
        try:
            from scanners.ton_scanner.gas_analyzer import GasAnalyzer
            ga = GasAnalyzer()
            gas_findings = []
            p2 = Path(path)
            for ext in ("*.fc", "*.func", "*.tact"):
                for fp in (p2.rglob(ext) if p2.is_dir() else [p2]):
                    r = ga.analyze(str(fp))
                    gas_findings.extend(r.get("findings", []))
            gas_findings = [f if isinstance(f, dict) else f.__dict__ for f in gas_findings]
            if gas_findings:
                _print_findings(gas_findings, max_show=15)
            else:
                print(GREEN("   ✓ No gas risks detected"))
            findings.extend(gas_findings)
        except Exception as e:
            print(DIM(f"   Gas analyzer error: {e}"))

    # ── Elite: State Machine Analysis ─────────────────────────────────────────
    if elite or getattr(args, "state_machine", False):
        print(BLUE("\n🔄  State Machine Analysis"))
        try:
            from scanners.ton_scanner.state_machine import StateMachineAnalyzer
            sa = StateMachineAnalyzer()
            stm_findings = []
            p2 = Path(path)
            for ext in ("*.fc", "*.func", "*.tact"):
                for fp in (p2.rglob(ext) if p2.is_dir() else [p2]):
                    r = sa.analyze(str(fp))
                    stm_findings.extend(r.get("findings", []))
            stm_findings = [f if isinstance(f, dict) else f.__dict__ for f in stm_findings]
            if stm_findings:
                _print_findings(stm_findings, max_show=15)
            else:
                print(GREEN("   ✓ No state machine violations detected"))
            findings.extend(stm_findings)
        except Exception as e:
            print(DIM(f"   State machine analyzer error: {e}"))

    # ── Elite: Attack Surface Mapping ─────────────────────────────────────────
    if elite or getattr(args, "surface", False):
        print(BLUE("\n🗺️   Attack Surface Mapping"))
        try:
            from scanners.ton_scanner.attack_surface import AttackSurfaceMapper
            mapper = AttackSurfaceMapper()
            p2 = Path(path)
            if p2.is_file():
                surface = mapper.map_file(str(p2))
                surf_findings = mapper.to_findings(surface)
                print(f"   Risk: {surface.risk_level} ({surface.risk_score}/100)  "
                      f"Entry points: {len(surface.entry_points)}  "
                      f"Upgradeable: {surface.upgradeable}")
            else:
                result = mapper.map_directory(str(p2))
                surf_findings = []
                for surf in result.get("surfaces", []):
                    surf_findings.extend(mapper.to_findings(surf))
                print(f"   Files: {len(result.get('surfaces',[]))}  "
                      f"Total risk score: {result.get('total_risk_score', 0)}  "
                      f"Highest risk: {result.get('highest_risk_file', '—')}")
            if surf_findings:
                _print_findings(surf_findings, max_show=10)
            findings.extend(surf_findings)
        except Exception as e:
            print(DIM(f"   Attack surface error: {e}"))

    if hasattr(args, "report") and args.report and findings:
        from reports.bounty_report import BugBountyReportGenerator
        out_dir = args.report_dir if hasattr(args,"report_dir") and args.report_dir else "./ghost_reports/bounty"
        gen     = BugBountyReportGenerator(Path(path).name)
        outputs = gen.generate_all(findings, out_dir, min_severity="MEDIUM")
        print(GREEN(f"📄  Reports generated: {len(outputs)} files in {out_dir}/"))

    if elite:
        print(BLUE(f"\n🏆  TON Elite Mode — Total findings: {len(findings)}"))

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
    from scanners.container_scanner import ContainerScanner
    cpp_count  = CppScanner().pattern_count()
    osv_online = OSVScanner().is_online()
    osv_status = GREEN("live OSV.dev") if osv_online else YELLOW("offline (static DB)")
    container  = ContainerScanner()
    cont_back  = container.backend()
    cont_color = GREEN(cont_back) if cont_back in ("trivy", "grype") else YELLOW("static DB")
    print(f"\n  {BOLD('Scanners:')}")
    print(f"    SAST       : OWASP(35) · Secrets(45) · JS(25) · C/C++({cpp_count}) · Cross-file taint")
    print(f"    IaC        : Dockerfile(17) · Terraform(18) · docker-compose(9) · GitHub Actions(7)")
    print(f"               : Ansible(11) · Helm(13) · CloudFormation(16)")
    print(f"    Deps       : {osv_status} + EPSS enrichment + CISA KEV")
    print(f"    Container  : {cont_color} (Trivy > Grype > static)")
    print(f"    SBOM       : SPDX 2.3 · CycloneDX 1.4")
    print(f"    Compliance : PCI-DSS 4.0 · SOC2 · HIPAA · NIST 800-53 · ISO27001 · ASVS")
    print(f"    Infra      : Kubernetes(18)")
    print(f"    Blockchain : TON(87) · Solidity(15)")
    print(f"  {BOLD('Suppression:')} .ghostignore (YAML · expiry dates · file patterns)")
    print(f"  {BOLD('Auto-fix:')}   Dep bumps (PyPI/npm/Go/Rust) · Code patches · GitHub PR")

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
    """ghost iac <path> [--output json|table] [--save FILE] [--format docker|terraform|ansible|helm|cfn]

    Scan Infrastructure-as-Code files for security misconfigurations:
      Dockerfile · docker-compose.yml · Terraform (.tf) · GitHub Actions
      Ansible playbooks · Helm charts · AWS CloudFormation templates
    """
    path = str(Path(args.path).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}"))
        return 1

    print(BLUE(f"🏗️   IaC security scan: {path}"))
    t0 = time.time()

    from scanners.iac_scanner import IaCScanner
    from scanners.iac_extended import IaCExtendedScanner

    result1  = IaCScanner().scan_directory(path)
    result2  = IaCExtendedScanner().scan_directory(path)
    findings = result1.get("findings", []) + result2.get("findings", [])

    # Sort combined by severity
    _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: _sev_order.get(f.get("severity", "LOW"), 4))

    files_scanned = result1.get("files_scanned", 0) + result2.get("files_scanned", 0)
    breakdown     = result2.get("breakdown", {})
    duration      = time.time() - t0

    print(DIM(f"   IaC files scanned: {files_scanned}"
              f"  (Docker/TF/compose + Ansible:{breakdown.get('ansible',0)}"
              f"  Helm:{breakdown.get('helm',0)}"
              f"  CloudFormation:{breakdown.get('cloudformation',0)})\n"))

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


def cmd_container(args) -> int:
    """ghost container <image|dockerfile> [--output json|table] [--save FILE]

    Scan a Docker image (or all Dockerfiles in a directory) for OS-level CVEs.
    Uses Trivy (preferred) → Grype → static known-vulnerable image database.
    """
    target   = getattr(args, "target", "")
    t0       = time.time()
    from scanners.container_scanner import ContainerScanner
    scanner  = ContainerScanner()
    backend  = scanner.backend()
    print(BLUE(f"🐳  Container scan: {target}"))
    print(DIM(f"   Backend: {backend}"))

    p = Path(target)
    if p.is_dir():
        result   = scanner.scan_directory(target)
        findings = result.get("findings", [])
        print(DIM(f"   Dockerfiles: {result.get('dockerfiles_scanned', 0)}\n"))
    elif p.is_file() and p.name.lower().startswith("dockerfile"):
        findings = scanner.scan_dockerfile(target)
        print(DIM(f"   Dockerfile: {target}\n"))
    else:
        # Treat as image name/tag
        findings = scanner.scan_image(target)
        print(DIM(f"   Image: {target}\n"))

    duration = time.time() - t0
    order    = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_sev  = getattr(args, "min_severity", "LOW")
    min_idx  = order.index(min_sev) if min_sev in order else 1
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


def cmd_sbom(args) -> int:
    """ghost sbom [--format spdx|cyclonedx] [--out sbom.json] [--name app] [--version 1.0] <path>

    Generate a Software Bill of Materials (SBOM) from dependency manifests.
    SPDX 2.3 — required by NTIA/US EO 14028 and EU Cyber Resilience Act.
    CycloneDX 1.4 — used by OWASP Dependency-Track, JFrog, Sonatype Nexus.
    """
    path    = str(Path(getattr(args, "path", ".")).resolve())
    fmt     = getattr(args, "format", "spdx")
    out     = getattr(args, "out", None)
    name    = getattr(args, "name", Path(path).name or "project")
    version = getattr(args, "version", "0.0.0")

    print(BLUE(f"📋  Generating {fmt.upper()} SBOM: {path}"))
    t0 = time.time()

    if fmt == "spdx":
        from sbom.spdx_exporter import SPDXExporter
        exporter = SPDXExporter()
        sbom     = exporter.from_directory(path, name, version)
        if not out:
            out = f"{name}-sbom.spdx.json"
        exporter.write(sbom, out)
        pkg_count = len(sbom.get("packages", [])) - 1  # exclude root
        print(DIM(f"   Packages: {pkg_count}  Format: SPDX {sbom['spdxVersion']}"))
    else:
        # CycloneDX — use existing supply chain scanner
        from sbom.supply_chain import SupplyChainScanner
        scanner  = SupplyChainScanner()
        result   = scanner.scan_directory(path)
        packages = []
        for m in result.get("manifests", []):
            packages.extend(m.get("packages", []))
        if not out:
            out = f"{name}-sbom.cyclonedx.json"
        import json as _json
        import time as _time
        import uuid as _uuid
        cdx = {
            "bomFormat":   "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{_uuid.uuid4()}",
            "version":     1,
            "metadata": {
                "timestamp": _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime()),
                "component": {"type": "application", "name": name, "version": version},
            },
            "components": [
                {
                    "type":    "library",
                    "name":    p.get("name", "unknown"),
                    "version": p.get("version_spec", "").lstrip("=^~><!* ") or "unknown",
                    "purl":    f"pkg:{'pypi' if p.get('ecosystem','').lower()=='pypi' else p.get('ecosystem','unknown').lower()}/{p.get('name','unknown')}",
                }
                for p in packages
            ],
        }
        Path(out).write_text(json.dumps(cdx, indent=2))
        print(DIM(f"   Components: {len(packages)}  Format: CycloneDX 1.4"))

    duration = time.time() - t0
    print(GREEN(f"\n✅  SBOM written: {out}  ({duration:.2f}s)"))
    print(DIM("   Compatible with: syft · FOSSA · Black Duck · dependency-track"))
    return 0


def cmd_compliance(args) -> int:
    """ghost compliance [--frameworks PCI-DSS,SOC2,HIPAA] [--output md|json] [--save FILE] <path|findings.json>

    Map findings to compliance framework control violations.
    Frameworks: PCI-DSS 4.0 · SOC 2 · HIPAA · NIST SP 800-53 · ISO 27001 · OWASP ASVS.
    """
    target = getattr(args, "path", "findings.json")
    t0     = time.time()

    from core.compliance.compliance_mapper import ComplianceMapper

    # Accept either a findings.json or a directory to scan
    tp = Path(target)
    if tp.suffix == ".json" and tp.exists():
        findings = json.loads(tp.read_text())
        print(BLUE(f"📊  Compliance mapping: {target} ({len(findings)} findings)"))
    elif tp.is_dir():
        print(BLUE(f"📊  Compliance scan + mapping: {target}"))
        from scanners.owasp_scanner import OWASPScanner
        from scanners.secret_scanner.secret_detector import SecretDetector
        findings = []
        for fpath in list(tp.rglob("*.py"))[:100]:
            try:
                findings += OWASPScanner().scan_file(str(fpath))
                findings += SecretDetector().scan_file(str(fpath))
            except Exception:
                pass
        print(DIM(f"   Scanned: {len(list(tp.rglob('*.py'))[:100])} files  "
                  f"Raw findings: {len(findings)}"))
    else:
        print(RED(f"❌  Not found: {target}"))
        return 1

    fw_arg = getattr(args, "frameworks", "")
    active_fw = [f.strip() for f in fw_arg.split(",")] if fw_arg else None

    mapper  = ComplianceMapper()
    enriched = mapper.enrich(findings)
    out_fmt  = getattr(args, "output_fmt", "md")

    if out_fmt == "json":
        report = mapper.compliance_report(enriched, active_fw)
        if getattr(args, "save", None):
            Path(args.save).write_text(json.dumps(report, indent=2))
            print(GREEN(f"💾  Saved to {args.save}"))
        else:
            print(json.dumps(report, indent=2))
    else:
        md = mapper.markdown_report(enriched, active_fw)
        if getattr(args, "save", None):
            Path(args.save).write_text(md)
            print(GREEN(f"💾  Report saved: {args.save}  ({time.time()-t0:.2f}s)"))
        else:
            print(md)

    return 0


def cmd_fix_deps(args) -> int:
    """ghost fix-deps [--apply] [--backup] [--pr owner/repo --token TOKEN] <path>

    Automatically bump vulnerable dependencies to their safe versions.
    Reads findings from OSV scan; patches requirements.txt / package.json / go.mod / Cargo.toml.
    Creates a .ghost.bak backup before modifying files unless --no-backup.
    """
    path = str(Path(getattr(args, "path", ".")).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}"))
        return 1

    print(BLUE(f"🔧  Dependency auto-fix: {path}"))
    t0 = time.time()

    from scanners.osv_scanner import OSVScanner
    from remediation.dependency_fixer import DependencyFixer

    # Run live OSV scan to get findings
    print(DIM("   Running OSV.dev scan..."), end="", flush=True)
    osv_result = OSVScanner().scan_directory(path)
    findings   = osv_result.get("findings", [])
    print(DIM(f" {len(findings)} vulnerabilities found"))

    if not findings:
        print(GREEN("✅  No vulnerable dependencies found."))
        return 0

    fixer = DependencyFixer(path)
    fixes = fixer.compute_fixes(findings)

    if not fixes:
        print(YELLOW("⚠️   Findings found but no actionable version fixes available."))
        return 0

    print(f"\n  {BOLD('Proposed fixes')} ({len(fixes)}):\n")
    for fix in fixes:
        sev_color = _SEV_COLOR.get(fix.severity, lambda x: x)
        cves = ", ".join(fix.cve_ids[:2]) + ("…" if len(fix.cve_ids) > 2 else "")
        print(f"  {sev_color(_SEV_ICON.get(fix.severity,'●') + ' ' + fix.severity.ljust(8))}"
              f"  {BOLD(fix.package)}: {fix.old_version} → {GREEN(fix.new_version)}"
              f"  {DIM('(' + cves + ')')}")
        print(f"    {DIM(Path(fix.file).name + ':' + str(fix.line_number))}")
    print()

    apply = getattr(args, "apply", False)
    if not apply:
        print(DIM("   Run with --apply to patch files. Run with --pr owner/repo to create a GitHub PR."))
        return 0

    backup = not getattr(args, "no_backup", False)
    results = fixer.apply_fixes(fixes, backup=backup)
    for r in results:
        if r.get("applied"):
            print(GREEN(f"  ✅  {r['file']}: {r['fixes']} fix(es) applied") +
                  (DIM(f"  (backup: {r.get('backup')})") if r.get("backup") else ""))
        else:
            print(RED(f"  ❌  {r['file']}: {r.get('error')}"))

    pr_target = getattr(args, "pr", None)
    if pr_target:
        token = getattr(args, "token", "") or os.getenv("GITHUB_TOKEN", "")
        if not token:
            print(RED("  ❌  --token or GITHUB_TOKEN required for PR creation"))
            return 1
        parts = pr_target.split("/")
        if len(parts) < 2:
            print(RED("  ❌  --pr must be owner/repo"))
            return 1
        owner, repo = parts[0], parts[1]
        pr = fixer.create_pr(fixes, owner=owner, repo=repo, token=token)
        if "error" in pr:
            print(RED(f"  ❌  {pr['error']}"))
        else:
            print(GREEN(f"\n  PR ready!  Branch: {pr['branch']}"))
            print(DIM(pr.get("instructions", "")))

    print(DIM(f"\n  Done in {time.time()-t0:.2f}s"))
    return 0


def cmd_suppress(args) -> int:
    """ghost suppress [--add RULE_ID] [--reason TEXT] [--files GLOB] [--expires DATE] <project>
                      [--list] [--create-example]

    Manage finding suppressions via .ghostignore file.
    Suppressions expire automatically on the given date.
    """
    path = str(Path(getattr(args, "path", ".")).resolve())

    from core.suppression import SuppressionManager
    mgr = SuppressionManager(path)

    if getattr(args, "create_example", False):
        out = mgr.create_example(path)
        print(GREEN(f"✅  Example .ghostignore created: {out}"))
        return 0

    if getattr(args, "list", False):
        sups = mgr.suppressions
        if not sups:
            print(DIM("  No suppressions found in .ghostignore"))
            return 0
        print(BOLD(f"  Active suppressions ({len(sups)}):\n"))
        for s in sups:
            expired = DIM(" [EXPIRED]") if s.is_expired() else ""
            print(f"  {BOLD(s.raw_id)}{expired}")
            print(f"    Reason : {s.reason}")
            if s.expires:
                print(f"    Expires: {s.expires}")
            if s.files:
                print(f"    Files  : {', '.join(s.files)}")
            print()
        return 0

    rule_id = getattr(args, "add", None)
    if rule_id:
        mgr.add_suppression(
            rule_id=rule_id,
            reason=getattr(args, "reason", "Suppressed via CLI"),
            files=getattr(args, "files", []),
            expires=getattr(args, "expires", None),
        )
        print(GREEN(f"✅  Suppression added: {rule_id}"))
        print(DIM(f"   Edit .ghostignore to review or remove"))
        return 0

    # Default: show status
    sups    = mgr.suppressions
    active  = [s for s in sups if not s.is_expired()]
    expired = [s for s in sups if s.is_expired()]
    print(f"  {BOLD('.ghostignore')} — {len(active)} active, {len(expired)} expired")
    print(DIM("   Use --list to show all, --add RULE_ID to add, --create-example to scaffold"))
    return 0


def cmd_enrich(args) -> int:
    """ghost enrich <findings.json> [--kev] [--output json|table] [--save FILE]

    Enrich findings with EPSS exploit probability scores and CISA KEV status.
    Adds: epss_score, epss_percentile, cisa_kev (bool), priority_score, exploit_status.
    """
    findings_path = getattr(args, "findings", "findings.json")
    if not Path(findings_path).exists():
        print(RED(f"❌  File not found: {findings_path}"))
        return 1

    findings = json.loads(Path(findings_path).read_text())
    print(BLUE(f"🎯  EPSS enrichment: {len(findings)} findings"))
    t0 = time.time()

    from scanners.epss_enricher import EPSSEnricher
    enricher = EPSSEnricher()
    enriched = enricher.enrich(findings)

    kev_count  = sum(1 for f in enriched if f.get("cisa_kev"))
    high_epss  = sum(1 for f in enriched if f.get("epss_score", 0) > 0.5)
    duration   = time.time() - t0

    print(DIM(f"   CISA KEV matches: {kev_count}  High EPSS (>50%): {high_epss}  "
              f"Time: {duration:.2f}s\n"))

    out_fmt = getattr(args, "output", "table")
    if out_fmt == "json":
        print(json.dumps(enriched, indent=2))
    else:
        # Show top-priority findings
        top = sorted(enriched, key=lambda f: f.get("priority_score", 0), reverse=True)[:20]
        for f in top:
            sev   = f.get("severity", "MEDIUM")
            color = _SEV_COLOR.get(sev, lambda x: x)
            icon  = _SEV_ICON.get(sev, "●")
            epss  = f.get("epss_score", 0)
            kev   = " 🚨KEV" if f.get("cisa_kev") else ""
            prio  = f.get("priority_score", 0)
            msg   = (f.get("message") or "")[:55]
            cve   = f.get("cve", f.get("id", ""))[:15]
            print(f"  {color(icon+' '+sev.ljust(8))}  {BOLD(cve.ljust(16))} "
                  f"EPSS:{epss:.2f} Prio:{prio:.0f}{kev}  {DIM(msg)}")

    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps(enriched, indent=2))
        print(GREEN(f"\n💾  Saved to {args.save}"))

    return 0


def cmd_sarif(args) -> int:
    """ghost sarif <findings.json> [--out results.sarif]"""
    src = getattr(args, "findings", "findings.json")
    out = getattr(args, "out", "results.sarif")
    if not Path(src).exists():
        print(RED(f"❌  File not found: {src}"))
        return 1
    from reports.sarif_exporter import SARIFExporter
    path = SARIFExporter.from_file(src, out)
    print(GREEN(f"✅  SARIF written: {path}"))
    print(DIM("   Upload to GitHub → Security → Code scanning → Upload SARIF file"))
    return 0


def _lang_scan_cmd(args, ScannerClass, label: str, scanner_name: str) -> int:
    path = str(Path(getattr(args, "path", ".")).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}")); return 1
    print(BLUE(f"🔍  {label} scan: {path}"))
    t0 = time.time()
    result   = ScannerClass().scan_directory(path)
    findings = result.get("findings", [])
    duration = time.time() - t0
    print(DIM(f"   Files: {result.get('files_scanned',0)}  "
              f"Patterns: {ScannerClass().pattern_count()}\n"))
    if getattr(args, "output", "table") == "json":
        print(json.dumps(findings, indent=2))
    else:
        _print_findings(findings, max_show=50)
        _print_summary({"total_findings": len(findings)}, duration)
    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps(findings, indent=2))
        print(GREEN(f"💾  Saved to {args.save}"))
    crits = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    return 1 if crits and not getattr(args, "no_fail", False) else 0


def cmd_java(args) -> int:
    """ghost java <path> — Java SAST scanner (12 patterns)."""
    from scanners.java_scanner import JavaScanner
    return _lang_scan_cmd(args, JavaScanner, "Java SAST", "java")


def cmd_go(args) -> int:
    """ghost go <path> — Go SAST scanner (12 patterns)."""
    from scanners.go_scanner import GoScanner
    return _lang_scan_cmd(args, GoScanner, "Go SAST", "go")


def cmd_evm(args) -> int:
    """ghost evm <path> — EVM/Solidity security scan (reentrancy, access control, flash loans, MEV, ...)."""
    from scanners.evm_scanner import EVMScanner
    return _lang_scan_cmd(args, EVMScanner, "EVM/Solidity", "evm")


def cmd_solana(args) -> int:
    """ghost solana <path> — Solana/Anchor security scan (signer, PDA, CPI, arithmetic, ...)."""
    from scanners.solana_scanner import SolanaScanner
    return _lang_scan_cmd(args, SolanaScanner, "Solana/Anchor", "solana")


def cmd_cosmos(args) -> int:
    """ghost cosmos <path> — CosmWasm security scan (execute auth, IBC, reentrancy, ...)."""
    from scanners.cosmos_scanner import CosmosScanner
    return _lang_scan_cmd(args, CosmosScanner, "CosmWasm", "cosmos")


def cmd_polkadot(args) -> int:
    """ghost polkadot <path> — ink! (Polkadot) security scan (access control, arithmetic, ...)."""
    from scanners.polkadot_scanner import PolkadotScanner
    return _lang_scan_cmd(args, PolkadotScanner, "ink!/Polkadot", "polkadot")


def cmd_move(args) -> int:
    """ghost move <path> — Move language (Sui/Aptos) security scan (capabilities, resources, ...)."""
    from scanners.move_scanner import MoveScanner
    return _lang_scan_cmd(args, MoveScanner, "Move (Sui/Aptos)", "move")


def cmd_web3(args) -> int:
    """ghost web3 <path> — Auto-detect blockchain and scan (EVM/Solana/Cosmos/Polkadot/Move/TON)."""
    path = str(Path(getattr(args, "path", ".")).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}")); return 1

    p = Path(path)
    t0 = time.time()

    # Auto-detect chain by file extensions and config files
    sol_files  = list(p.rglob("*.sol")) + list(p.rglob("*.vy"))
    rs_files   = list(p.rglob("*.rs"))
    move_files = list(p.rglob("*.move"))
    fc_files   = list(p.rglob("*.fc")) + list(p.rglob("*.func")) + list(p.rglob("*.tact"))

    has_anchor  = any(p.rglob("Anchor.toml"))
    has_cosm    = any("cosmwasm" in f.read_text(errors="ignore")
                      for f in list(p.rglob("Cargo.toml"))[:3])
    has_ink     = any("#[ink::contract]" in f.read_text(errors="ignore")
                      for f in rs_files[:10])
    has_sui     = any(f.name == "Move.toml" for f in p.rglob("Move.toml"))

    all_findings: list = []
    chains_detected: list = []

    if sol_files:
        chains_detected.append("EVM/Solidity")
        from scanners.evm_scanner import EVMScanner
        sc = EVMScanner()
        for f in sol_files[:100]:
            all_findings += sc.scan_file(str(f))

    if fc_files:
        chains_detected.append("TON/FunC")
        try:
            from scanners.ton_scanner.ton_analyzer import TonAnalyzer
            ta = TonAnalyzer()
            for f in fc_files[:50]:
                all_findings += ta.scan_file(str(f))
        except Exception:
            pass

    if rs_files:
        if has_anchor:
            chains_detected.append("Solana/Anchor")
            from scanners.solana_scanner import SolanaScanner
            sc = SolanaScanner()
            for f in rs_files[:100]:
                all_findings += sc.scan_file(str(f))
        elif has_cosm:
            chains_detected.append("CosmWasm")
            from scanners.cosmos_scanner import CosmosScanner
            sc = CosmosScanner()
            for f in rs_files[:100]:
                all_findings += sc.scan_file(str(f))
        elif has_ink:
            chains_detected.append("Polkadot/ink!")
            from scanners.polkadot_scanner import PolkadotScanner
            sc = PolkadotScanner()
            for f in rs_files[:100]:
                all_findings += sc.scan_file(str(f))

    if move_files:
        chains_detected.append("Move (Sui/Aptos)")
        from scanners.move_scanner import MoveScanner
        sc = MoveScanner()
        for f in move_files[:100]:
            all_findings += sc.scan_file(str(f))

    if not chains_detected:
        print(YELLOW("⚠️   No blockchain source files detected. Supported: .sol, .vy, .fc, .rs (Anchor/CosmWasm/ink!), .move"))
        return 0

    duration = time.time() - t0
    print(BLUE(f"🌐  Web3 scan: {path}"))
    print(DIM(f"   Chains detected: {', '.join(chains_detected)}"))
    if getattr(args, "output", "table") == "json":
        print(json.dumps(all_findings, indent=2))
    else:
        _print_findings(all_findings, max_show=50)
        _print_summary({"total_findings": len(all_findings), "findings": all_findings}, duration)
    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps(all_findings, indent=2))
        print(GREEN(f"💾  Saved to {args.save}"))
    crits = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    return 1 if crits > 0 and not getattr(args, "no_fail", False) else 0


def cmd_reachability(args) -> int:
    """ghost reachability <findings.json> [--root .] — Is vulnerable code actually called?"""
    src = getattr(args, "findings", "findings.json")
    if not Path(src).exists():
        print(RED(f"❌  File not found: {src}")); return 1
    findings = json.loads(Path(src).read_text())
    root     = str(Path(getattr(args, "root", ".")).resolve())
    print(BLUE(f"🔗  Reachability analysis: {len(findings)} findings  root: {root}"))
    t0 = time.time()
    from core.analysis.reachability import ReachabilityAnalyzer
    enriched = ReachabilityAnalyzer(root).analyze_all(findings)
    summary  = ReachabilityAnalyzer(root).summary(enriched)
    duration = time.time() - t0
    print(DIM(f"   Reachable: {summary['reachable']}  "
              f"Not reachable: {summary['not_reachable']}  "
              f"Unknown: {summary['unknown']}  "
              f"Noise reduction: {summary['noise_reduction']}  "
              f"({duration:.2f}s)\n"))
    if getattr(args, "output", "table") == "json":
        print(json.dumps(enriched, indent=2))
    else:
        for f in enriched[:30]:
            status = f.get("reachability_status", "UNKNOWN")
            color  = GREEN if status == "NOT_REACHABLE" else (RED if status == "REACHABLE" else YELLOW)
            sev    = f.get("severity", "")
            msg    = (f.get("message") or "")[:55]
            print(f"  {color(status.ljust(20))}  {DIM(sev.ljust(8))}  {msg}")
    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps(enriched, indent=2))
        print(GREEN(f"\n💾  Saved to {args.save}"))
    return 0


def cmd_rules(args) -> int:
    """ghost rules <path|update|list> [--rules-dir DIR] — Custom YAML rules + CDN update."""
    path = getattr(args, "path", ".")

    # CDN subcommands: ghost rules update / ghost rules list
    if path in ("update", "list"):
        from integrations.rules_cdn import RulesCDN
        cdn = RulesCDN()
        if path == "list":
            rules = cdn.list_local_rules()
            if not rules:
                print(DIM("   No rules installed. Run: ghost rules update"))
                return 0
            print(BLUE(f"📏  Installed rules ({len(rules)})  — version: {cdn.get_version() or 'unknown'}"))
            for r in rules[:50]:
                print(f"   {r.get('name','?'):<45}  {r.get('size_bytes',0):>8} bytes")
            return 0

        # update
        check_only = getattr(args, "check_only", False)
        force      = getattr(args, "force", False)
        print(BLUE("🔄  Checking rules CDN for updates..."))
        status = cdn.check_updates()
        if status.get("error"):
            print(YELLOW(f"⚠️   {status['error']}"))
            return 0
        if not status["has_update"] and not force:
            print(GREEN(f"✅  Rules up-to-date (v{status.get('current','?')})"))
            return 0
        new_count = len(status.get("new_rules", []))
        print(DIM(f"   Current: {status.get('current','?')}  Latest: {status.get('latest','?')}  New/changed: {new_count}"))
        if check_only:
            print(DIM("   Run without --check to download"))
            return 0
        result = cdn.download_rules(force=force)
        print(GREEN(f"✅  Downloaded: {result['downloaded']}  Skipped: {result['skipped']}  "
                    f"Errors: {result['errors']}  Version: {result.get('version','?')}"))
        return 0

    path = str(Path(path).resolve())
    if getattr(args, "create_example", False):
        from core.rules.custom_rules import create_example_rules
        out = create_example_rules(path)
        print(GREEN(f"✅  Example rules written: {out}"))
        return 0
    # Always include bundled rules from the package rules/ directory
    bundled_rules = str(Path(__file__).parent / "rules")
    extra = [bundled_rules]
    if getattr(args, "rules_dir", None):
        extra.append(args.rules_dir)
    print(BLUE(f"📏  Custom rules scan: {path}"))
    t0 = time.time()
    from core.rules.custom_rules import CustomRuleScanner
    scanner  = CustomRuleScanner(path, extra_rule_paths=extra)
    result   = scanner.scan_directory(path)
    findings = result.get("findings", [])
    duration = time.time() - t0
    print(DIM(f"   Rules loaded: {result.get('rules_loaded',0)}  "
              f"Files: {result.get('files_scanned',0)}\n"))
    if getattr(args, "output", "table") == "json":
        print(json.dumps(findings, indent=2))
    else:
        _print_findings(findings, max_show=50)
        _print_summary({"total_findings": len(findings)}, duration)
    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps(findings, indent=2))
        print(GREEN(f"💾  Saved to {args.save}"))
    return 0


def cmd_ide(args) -> int:
    """ghost ide <install|status|rules> — IDE plugin management."""
    action = getattr(args, "action", "status")
    plugin_dir = Path(__file__).parent / "vscode_extension"

    if action == "install":
        print(BOLD("\n🔌  Ghost Security VS Code Extension"))
        print(DIM("   Real-time security scanning · 3000+ rules · SARIF export\n"))
        print(BLUE("📦  Installation options:\n"))
        print(f"   1. VS Code Marketplace (recommended):")
        print(f"      Open VS Code → Extensions → Search 'Ghost Security'\n")
        print(f"   2. Install from local VSIX:")
        if plugin_dir.exists():
            print(f"      Extension path: {plugin_dir}")
            print(f"      Run: cd {plugin_dir} && npm install && vsce package")
            print(f"      Then: code --install-extension ghost-security-*.vsix\n")
        else:
            print(f"      Extension not found at {plugin_dir}\n")
        print(f"   3. Keyboard shortcuts after install:")
        print(f"      Ctrl+Shift+G S — scan current file")
        print(f"      Ctrl+Shift+G W — scan workspace")
        print(f"      Ctrl+Shift+G F — show findings panel\n")
        return 0

    if action == "rules":
        rules_dir = Path(__file__).parent / "rules"
        if not rules_dir.exists():
            print(YELLOW(f"⚠️   Rules directory not found: {rules_dir}"))
            return 1
        yaml_files = list(rules_dir.rglob("*.yaml")) + list(rules_dir.rglob("*.yml"))
        total_rules = 0
        categories: dict = {}
        for f in yaml_files:
            try:
                import yaml as _yaml
                data = _yaml.safe_load(f.read_text())
                if isinstance(data, list):
                    count = len(data)
                elif isinstance(data, dict) and "rules" in data:
                    count = len(data["rules"])
                else:
                    count = 0
                total_rules += count
                cat = f.parent.name
                categories[cat] = categories.get(cat, 0) + count
            except Exception:
                pass
        print(BOLD(f"\n📏  Ghost Security Rules: {total_rules} total\n"))
        for cat, cnt in sorted(categories.items(), key=lambda x: -x[1]):
            bar = "█" * min(30, cnt // 10)
            print(f"   {cat:<20} {cnt:>5}  {bar}")
        print()
        return 0

    # status (default)
    print(BOLD("\n🔌  Ghost Security IDE Integration Status\n"))
    print(f"   VS Code extension : {plugin_dir}")
    ext_js = plugin_dir / "out" / "extension.js"
    pkg_json = plugin_dir / "package.json"
    if ext_js.exists() and pkg_json.exists():
        import json as _json
        try:
            pkg = _json.loads(pkg_json.read_text())
            version = pkg.get("version", "?")
            cmd_count = len(pkg.get("contributes", {}).get("commands", []))
            print(GREEN(f"   Status           : ✅  Ready (v{version}, {cmd_count} commands)"))
        except Exception:
            print(GREEN("   Status           : ✅  Ready"))
    else:
        print(YELLOW("   Status           : ⚠️   Not compiled (run: ghost ide install)"))
    rules_dir = Path(__file__).parent / "rules"
    yaml_count = len(list(rules_dir.rglob("*.yaml"))) + len(list(rules_dir.rglob("*.yml"))) if rules_dir.exists() else 0
    print(f"   Rules directory  : {rules_dir}")
    print(f"   Rule files       : {yaml_count}")
    print(DIM("\n   Run 'ghost ide install' for installation instructions."))
    print(DIM("   Run 'ghost ide rules' to list rule categories.\n"))
    return 0


def cmd_license(args) -> int:
    """ghost license <path> — License compliance (GPL/AGPL/LGPL risk)."""
    path = str(Path(getattr(args, "path", ".")).resolve())
    print(BLUE(f"⚖️   License compliance scan: {path}"))
    t0 = time.time()
    from scanners.license_scanner import LicenseScanner
    result   = LicenseScanner().scan_directory(path)
    findings = result.get("findings", [])
    duration = time.time() - t0
    rc = result.get("risk_counts", {})
    print(DIM(f"   Packages: {result.get('packages_found',0)}  "
              f"Blocked: {rc.get('BLOCKED',0)}  "
              f"Copyleft-strong: {rc.get('COPYLEFT_STRONG',0)}  "
              f"Copyleft-weak: {rc.get('COPYLEFT_WEAK',0)}  "
              f"Permissive: {rc.get('PERMISSIVE',0)}\n"))
    if getattr(args, "output", "table") == "json":
        print(json.dumps(findings, indent=2))
    else:
        _print_findings(findings, max_show=50)
        _print_summary({"total_findings": len(findings)}, duration)
    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps(findings, indent=2))
        print(GREEN(f"💾  Saved to {args.save}"))
    return 1 if rc.get("BLOCKED", 0) > 0 else 0


def cmd_git_secrets(args) -> int:
    """ghost git-secrets <path> [--max-commits 200] — Scan git history for secrets."""
    path = str(Path(getattr(args, "path", ".")).resolve())
    max_c = getattr(args, "max_commits", 200)
    print(BLUE(f"🔐  Git history secret scan: {path}  (max {max_c} commits)"))
    t0 = time.time()
    from scanners.git_history_scanner import GitHistoryScanner
    result   = GitHistoryScanner(path, max_commits=max_c).scan()
    if "error" in result:
        print(RED(f"❌  {result['error']}")); return 1
    findings = result.get("findings", [])
    duration = time.time() - t0
    print(DIM(f"   Commits scanned: {result.get('commits_scanned',0)}\n"))
    if getattr(args, "output", "table") == "json":
        print(json.dumps(findings, indent=2))
    else:
        _print_findings(findings, max_show=30)
        _print_summary({"total_findings": len(findings)}, duration)
        if findings:
            print(RED("⚠️   Rotate all exposed credentials immediately!"))
            print(DIM("   Use git-filter-repo to purge secrets from history."))
    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps(findings, indent=2))
        print(GREEN(f"💾  Saved to {args.save}"))
    return 1 if findings else 0


def cmd_vex(args) -> int:
    """ghost vex <findings.json> [--name app] [--version 1.0] [--out vex.json]"""
    src = getattr(args, "findings", "findings.json")
    if not Path(src).exists():
        print(RED(f"❌  File not found: {src}")); return 1
    findings = json.loads(Path(src).read_text())
    name     = getattr(args, "name", "project")
    version  = getattr(args, "version", "0.0.0")
    out      = getattr(args, "out", "vex.json")
    print(BLUE(f"📄  Generating VEX: {len(findings)} findings → {out}"))
    from sbom.vex_exporter import VEXExporter
    exp = VEXExporter(name, version)
    vex = exp.from_findings(findings)
    exp.write(vex, out)
    affected     = sum(1 for v in vex["vulnerabilities"] if v.get("analysis",{}).get("state")=="affected")
    not_affected = sum(1 for v in vex["vulnerabilities"] if v.get("analysis",{}).get("state")=="not_affected")
    print(GREEN(f"✅  VEX written: {out}"))
    print(DIM(f"   Affected: {affected}  Not affected: {not_affected}  "
              f"Total: {len(vex['vulnerabilities'])}"))
    print(DIM("   Compatible with: OWASP dependency-track · CycloneDX tools"))
    return 0


def cmd_graphql(args) -> int:
    """ghost graphql <path> — GraphQL security scan."""
    path = str(Path(getattr(args, "path", ".")).resolve())
    print(BLUE(f"🔷  GraphQL security scan: {path}"))
    t0 = time.time()
    from scanners.graphql_scanner import GraphQLScanner
    result   = GraphQLScanner().scan_directory(path)
    findings = result.get("findings", [])
    duration = time.time() - t0
    print(DIM(f"   Schema files: {result.get('schema_files',0)}  "
              f"Server files: {result.get('server_files',0)}\n"))
    if getattr(args, "output", "table") == "json":
        print(json.dumps(findings, indent=2))
    else:
        _print_findings(findings, max_show=50)
        _print_summary({"total_findings": len(findings)}, duration)
    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps(findings, indent=2))
        print(GREEN(f"💾  Saved to {args.save}"))
    return 1 if any(f.get("severity")=="CRITICAL" for f in findings) else 0


def cmd_jwt(args) -> int:
    """ghost jwt <path> — JWT/OAuth misconfiguration scan."""
    path = str(Path(getattr(args, "path", ".")).resolve())
    print(BLUE(f"🔑  JWT/OAuth scan: {path}"))
    t0 = time.time()
    from scanners.jwt_scanner import JWTScanner
    result   = JWTScanner().scan_directory(path)
    findings = result.get("findings", [])
    duration = time.time() - t0
    print(DIM(f"   Files: {result.get('files_scanned',0)}  "
              f"JWT: {result.get('jwt_findings',0)}  "
              f"OAuth: {result.get('oauth_findings',0)}\n"))
    if getattr(args, "output", "table") == "json":
        print(json.dumps(findings, indent=2))
    else:
        _print_findings(findings, max_show=50)
        _print_summary({"total_findings": len(findings)}, duration)
    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps(findings, indent=2))
        print(GREEN(f"💾  Saved to {args.save}"))
    crits = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    return 1 if crits and not getattr(args, "no_fail", False) else 0


def cmd_tasks(args) -> int:
    """ghost tasks [--stats] [--clean DAYS] [--state STATE] [--limit N]"""
    from core.runtime.task_persistence import TaskStore
    store = TaskStore()

    if getattr(args, "clean", None):
        n = store.cleanup_old(days=args.clean)
        print(GREEN(f"🗑️   Removed {n} tasks older than {args.clean} days"))
        return 0

    if getattr(args, "stats", False):
        stats = store.stats()
        print(BLUE("📊  Task Store Statistics"))
        for k, v in stats.items():
            print(f"   {k:<18} {v}")
        return 0

    tasks = store.list_tasks(
        state=getattr(args, "state_filter", None),
        limit=getattr(args, "limit", 50),
    )
    if not tasks:
        print(DIM("   No tasks found in store"))
        return 0

    print(BLUE(f"📋  Tasks ({len(tasks)})"))
    print(DIM(f"   {'STATE':<12}  {'ID':<14}  {'NAME':<38}  {'DUR':>7}"))
    for t in tasks:
        state = t.get("state", "?")
        col = GREEN if state == "succeeded" else (RED if state == "failed" else YELLOW)
        dur = f"{t.get('duration', 0):.1f}s" if t.get("duration") else "—"
        print(f"   {col(state[:11]):<12}  {t['task_id'][:14]:<14}  "
              f"{t.get('name','?')[:38]:<38}  {dur:>7}")
    return 0


def cmd_tune(args) -> int:
    """ghost tune <findings.json> [--config rule_tuning.yaml] [--out FILE]"""
    from core.analysis.rule_tuner import RuleTuner

    if getattr(args, "create_example", False):
        tuner = RuleTuner()
        out = tuner.create_example_config(
            getattr(args, "example_out", "rule_tuning.yaml")
        )
        print(GREEN(f"✅  Example config → {out}"))
        print(DIM("   Edit it, then: ghost tune findings.json --config rule_tuning.yaml"))
        return 0

    findings_path = args.findings
    if not Path(findings_path).exists():
        print(RED(f"❌  File not found: {findings_path}"))
        return 1

    raw = json.loads(Path(findings_path).read_text())
    findings = raw if isinstance(raw, list) else raw.get("findings", [])

    config_paths = [args.config] if getattr(args, "config", None) else None
    tuner = RuleTuner(config_paths=config_paths)
    loaded = tuner.load()
    print(BLUE(f"🎛️   Rule Tuner — {loaded} override(s) loaded"))
    if loaded == 0:
        print(DIM("   Hint: ghost tune --create-example  to scaffold rule_tuning.yaml"))

    tuned      = tuner.apply(findings)
    suppressed = sum(1 for f in tuned if f.get("suppressed"))
    adjusted   = sum(1 for f in tuned if f.get("tuning_note") and not f.get("suppressed"))

    print(f"   Findings in:  {len(findings)}")
    print(f"   Adjusted:     {adjusted}")
    print(f"   Suppressed:   {suppressed}")
    print(f"   Active:       {len(tuned) - suppressed}")

    out_path = getattr(args, "out", None) or findings_path.replace(".json", "_tuned.json")
    Path(out_path).write_text(json.dumps(tuned, indent=2))
    print(GREEN(f"💾  Tuned findings → {out_path}"))
    return 0


def cmd_ton_gas(args) -> int:
    """ghost ton-gas <path> — Gas consumption risk analysis for FunC/Tact"""
    path = str(Path(args.path).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}"))
        return 1

    print(BLUE(f"⛽  TON Gas Risk Analysis: {path}"))
    t0 = time.time()

    from scanners.ton_scanner.gas_analyzer import GasAnalyzer
    analyzer = GasAnalyzer()
    p = Path(path)

    if p.is_file():
        result   = analyzer.analyze(str(p))
        findings = result.get("findings", [])
    else:
        findings = []
        for ext in ("*.fc", "*.func", "*.tact"):
            for fpath in p.rglob(ext):
                r = analyzer.analyze(str(fpath))
                findings.extend(r.get("findings", []))

    findings = [f if isinstance(f, dict) else f.__dict__ for f in findings]
    duration = time.time() - t0
    _print_findings(findings, max_show=30)
    _print_summary({"total_findings": len(findings), "findings": findings}, duration)

    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps(findings, indent=2))
        print(GREEN(f"💾  Saved to {args.save}"))

    highs = sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH"))
    return 1 if highs > 0 and not getattr(args, "no_fail", False) else 0


def cmd_ton_state(args) -> int:
    """ghost ton-state <path> — State machine transition analysis for FunC/Tact"""
    path = str(Path(args.path).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}"))
        return 1

    print(BLUE(f"🔄  TON State Machine Analysis: {path}"))
    t0 = time.time()

    from scanners.ton_scanner.state_machine import StateMachineAnalyzer
    analyzer = StateMachineAnalyzer()
    p = Path(path)

    if p.is_file():
        result   = analyzer.analyze(str(p))
        findings = result.get("findings", [])
    else:
        findings = []
        for ext in ("*.fc", "*.func", "*.tact"):
            for fpath in p.rglob(ext):
                r = analyzer.analyze(str(fpath))
                findings.extend(r.get("findings", []))

    findings = [f if isinstance(f, dict) else f.__dict__ for f in findings]
    duration = time.time() - t0
    _print_findings(findings, max_show=30)
    _print_summary({"total_findings": len(findings), "findings": findings}, duration)

    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps(findings, indent=2))
        print(GREEN(f"💾  Saved to {args.save}"))

    crits = sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH"))
    return 1 if crits > 0 and not getattr(args, "no_fail", False) else 0


def cmd_ton_surface(args) -> int:
    """ghost ton-surface <path> — Attack surface mapping for TON contracts"""
    path = str(Path(args.path).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}"))
        return 1

    print(BLUE(f"🗺️   TON Attack Surface Mapping: {path}"))
    t0 = time.time()

    from scanners.ton_scanner.attack_surface import AttackSurfaceMapper
    mapper = AttackSurfaceMapper()
    p = Path(path)

    if p.is_file():
        surface  = mapper.map_file(str(p))
        findings = mapper.to_findings(surface)
        summary  = {
            "file":           str(p.name),
            "risk_level":     surface.risk_level,
            "risk_score":     surface.risk_score,
            "entry_points":   len(surface.entry_points),
            "upgradeable":    surface.upgradeable,
            "external_calls": surface.external_calls,
        }
    else:
        result   = mapper.map_directory(str(p))
        findings = []
        for surf in result.get("surfaces", []):
            findings.extend(mapper.to_findings(surf))
        summary = {
            "files":            len(result.get("surfaces", [])),
            "total_risk_score": result.get("total_risk_score", 0),
            "highest_risk":     result.get("highest_risk_file", "—"),
        }

    duration = time.time() - t0
    print(BLUE("   Surface Summary"))
    for k, v in summary.items():
        print(f"   {k:<22}  {v}")

    _print_findings(findings, max_show=20)
    _print_summary({"total_findings": len(findings), "findings": findings}, duration)

    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps({"summary": summary, "findings": findings}, indent=2))
        print(GREEN(f"💾  Saved to {args.save}"))

    high = sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH"))
    return 1 if high > 0 and not getattr(args, "no_fail", False) else 0


def cmd_notify(args) -> int:
    """ghost notify <findings.json> [--jira] [--slack] [--min-severity HIGH]"""
    findings_path = getattr(args, "findings", "findings.json")

    if getattr(args, "test_connection", False):
        if getattr(args, "jira", False):
            from integrations.jira.jira_integration import JiraIntegration
            result = JiraIntegration().test_connection()
            if result["ok"]:
                print(GREEN(f"✅  Jira connection OK — user: {result.get('user','?')}"))
            else:
                print(RED(f"❌  Jira error: {result.get('error','unknown')}"))
        if getattr(args, "slack", False):
            from integrations.slack.slack_notifier import SlackNotifier
            ok = SlackNotifier().test()
            print(GREEN("✅  Slack connection OK") if ok else RED("❌  Slack connection failed"))
        return 0

    if not Path(findings_path).exists():
        print(RED(f"❌  File not found: {findings_path}"))
        return 1

    raw = json.loads(Path(findings_path).read_text())
    findings = raw if isinstance(raw, list) else raw.get("findings", [])
    min_sev   = getattr(args, "min_severity", "HIGH")
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_idx = order.index(min_sev) if min_sev in order else 3
    filtered = [f for f in findings if order.index(f.get("severity", "INFO")) >= min_idx]

    print(BLUE(f"📣  Notifying about {len(filtered)} findings (min: {min_sev})"))

    if getattr(args, "jira", False):
        from integrations.jira.jira_integration import JiraIntegration
        jira = JiraIntegration()
        if not jira.is_configured():
            print(YELLOW("⚠️   Jira not configured — set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY"))
        else:
            created = jira.create_issues_batch(filtered, min_severity=min_sev)
            print(GREEN(f"✅  Jira: {len(created)} issue(s) created"))

    if getattr(args, "slack", False):
        from integrations.slack.slack_notifier import SlackNotifier
        slack = SlackNotifier()
        if not slack.is_configured():
            print(YELLOW("⚠️   Slack not configured — set SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN"))
        else:
            path = getattr(args, "findings", "project")
            ok = slack.send_scan_summary(filtered, scan_path=path, duration=0.0)
            print(GREEN("✅  Slack summary sent") if ok else RED("❌  Slack delivery failed"))

    if not getattr(args, "jira", False) and not getattr(args, "slack", False):
        print(YELLOW("   Specify --jira and/or --slack"))
    return 0


def cmd_sla(args) -> int:
    """ghost sla [findings.json] [--open] [--report] [--overdue] [--policy NAME]"""
    from core.enterprise.sla_tracker import SLATracker, SLAPolicy

    policy_name = getattr(args, "policy", "default")
    policy_map = {"default": SLAPolicy.default, "pci-dss": SLAPolicy.pci_dss, "soc2": SLAPolicy.soc2}
    policy = policy_map.get(policy_name, SLAPolicy.default)()
    tracker = SLATracker(policy=policy)

    if getattr(args, "open_findings", False):
        findings_path = getattr(args, "findings", "findings.json")
        if not Path(findings_path).exists():
            print(RED(f"❌  File not found: {findings_path}"))
            return 1
        raw = json.loads(Path(findings_path).read_text())
        findings = raw if isinstance(raw, list) else raw.get("findings", [])
        summary = tracker.track_batch(findings)
        print(GREEN(f"✅  SLA opened for {summary['total']} findings"))
        return 0

    if getattr(args, "overdue", False):
        items = tracker.overdue()
        if not items:
            print(GREEN("✅  No overdue findings"))
            return 0
        print(RED(f"🚨  {len(items)} overdue finding(s):"))
        for s in items:
            print(f"   {RED(s.rule_id):<20}  {s.file[:40]}  overdue by {abs(s.days_remaining)}d")
        return 1

    if getattr(args, "report", False):
        fmt = getattr(args, "fmt", "table")
        print(tracker.report(fmt=fmt))
        return 0

    # Default: summary
    summary = tracker.summary()
    sla_score = summary.get("sla_score", 100.0)
    color = GREEN if sla_score >= 90 else (YELLOW if sla_score >= 70 else RED)
    print(BLUE("📊  SLA Compliance Status"))
    print(f"   Score:     {color(f'{sla_score:.1f}/100')}")
    print(f"   Total:     {summary.get('total', 0)}")
    print(f"   On track:  {summary.get('on_track', 0)}")
    print(f"   At risk:   {summary.get('at_risk', 0)}")
    print(f"   Overdue:   {summary.get('overdue', 0)}")
    return 0


def cmd_audit_log(args) -> int:
    """ghost audit-log [--tail N] [--stats] [--export FILE]"""
    from core.audit_log import AuditLog
    log = AuditLog()

    if getattr(args, "export_path", None):
        out = log.export_csv(args.export_path)
        print(GREEN(f"💾  Audit log exported: {out}"))
        return 0

    if getattr(args, "stats", False):
        stats = log.stats()
        print(BLUE("📊  Audit Log Statistics"))
        for k, v in stats.items():
            print(f"   {k:<25}  {v}")
        return 0

    n = getattr(args, "tail", 50)
    events = log.tail(n)
    if not events:
        print(DIM("   Audit log is empty"))
        return 0
    print(BLUE(f"📋  Last {len(events)} audit events"))
    print(DIM(f"   {'TIME':<20}  {'EVENT':<25}  {'DETAIL'}"))
    for e in events:
        ts = e.get("timestamp", "")
        if isinstance(ts, (int, float)):
            import datetime
            ts = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
        etype = e.get("event_type", e.get("action", "?"))[:25]
        detail = str(e.get("detail", e.get("message", e.get("target", ""))))[:60]
        print(f"   {str(ts)[:20]:<20}  {etype:<25}  {detail}")
    return 0


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
  ghost scan .                              # full SAST scan (Python/JS/C/C++)
  ghost scan --incremental .               # only changed files (fast)
  ghost deps .                             # live CVE scan via OSV.dev
  ghost deps --offline .                   # offline CVE scan (static DB)
  ghost iac .                              # Docker/Terraform/Ansible/Helm/CFN scan
  ghost container nginx:1.21.0            # container image CVE scan
  ghost container ./Dockerfile            # scan Dockerfile base images
  ghost sbom . --format spdx             # generate SPDX 2.3 SBOM
  ghost sbom . --format cyclonedx        # generate CycloneDX 1.4 SBOM
  ghost compliance findings.json         # PCI-DSS/SOC2/HIPAA/NIST gap report
  ghost compliance . --frameworks PCI-DSS,SOC2 --save report.md
  ghost fix-deps .                       # preview vulnerable dep fixes
  ghost fix-deps . --apply               # patch manifests (with .ghost.bak backup)
  ghost fix-deps . --apply --pr org/repo --token ghp_...
  ghost suppress . --create-example     # scaffold .ghostignore
  ghost suppress . --add CVE-2023-1234 --reason "Not reachable" --expires 2025-12-31
  ghost enrich findings.json            # add EPSS scores + CISA KEV flags
  ghost ci --type github .              # generate GitHub Actions workflow
  ghost ton ./contracts/               # TON bug bounty scan + reports
  ghost ton ./contracts/ --elite       # TON + gas + state-machine + attack surface
  ghost ton-gas ./contracts/           # gas consumption risk only
  ghost ton-state ./contracts/         # state machine violation analysis
  ghost ton-surface ./contracts/       # attack surface mapping (risk score 0-100)
  ghost scan . --tune                  # scan + apply rule_tuning.yaml overrides
  ghost tune findings.json             # apply rule tuner to existing findings
  ghost tune --create-example          # scaffold rule_tuning.yaml
  ghost tasks --stats                  # view SQLite task history
  ghost k8s ./k8s/manifests/           # Kubernetes CIS audit
  ghost fix findings.json --apply      # apply code-level fixes (with backup)
  ghost serve --port 8000              # start API server + WebSocket live feed
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
    p_scan.add_argument("--tune", action="store_true",
                        help="Apply rule_tuning.yaml overrides after scan")

    # ton
    p_ton = sub.add_parser("ton", help="TON smart contract security scan")
    p_ton.add_argument("path", nargs="?", default=".")
    p_ton.add_argument("--report", action="store_true", help="Generate Immunefi/HackenProof reports")
    p_ton.add_argument("--report-dir", default="./ghost_reports/bounty")
    p_ton.add_argument("--min-severity", default="LOW")
    p_ton.add_argument("--elite", action="store_true",
                       help="Run all elite analyzers: gas + state-machine + attack surface")
    p_ton.add_argument("--gas", action="store_true", help="Run gas risk analysis")
    p_ton.add_argument("--state-machine", action="store_true",
                       dest="state_machine", help="Run state machine analysis")
    p_ton.add_argument("--surface", action="store_true", help="Run attack surface mapping")

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

    # container — Docker image CVE scanner
    p_con = sub.add_parser("container", help="Container image CVE scan (Trivy/Grype/static)")
    p_con.add_argument("target", nargs="?", default=".", help="Image name, Dockerfile, or directory")
    p_con.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_con.add_argument("--min-severity", default="LOW",
                       choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p_con.add_argument("--save", metavar="FILE", help="Save findings to JSON file")
    p_con.add_argument("--no-fail", action="store_true")

    # sbom — SBOM generator (SPDX 2.3 / CycloneDX 1.4)
    p_sbom = sub.add_parser("sbom", help="Generate SPDX 2.3 or CycloneDX 1.4 SBOM")
    p_sbom.add_argument("path", nargs="?", default=".")
    p_sbom.add_argument("--format", dest="format", choices=["spdx", "cyclonedx"], default="spdx")
    p_sbom.add_argument("--out", metavar="FILE", help="Output file path")
    p_sbom.add_argument("--name", default="", help="Project name")
    p_sbom.add_argument("--version", default="0.0.0", help="Project version")

    # compliance — framework compliance report
    p_comp = sub.add_parser("compliance", help="Compliance gap report (PCI-DSS/SOC2/HIPAA/NIST/ISO27001/ASVS)")
    p_comp.add_argument("path", nargs="?", default="findings.json",
                        help="findings.json file or directory to scan")
    p_comp.add_argument("--frameworks", default="",
                        help="Comma-separated framework IDs (default: all)")
    p_comp.add_argument("--output", dest="output_fmt", choices=["md", "json"], default="md")
    p_comp.add_argument("--save", metavar="FILE")

    # fix-deps — auto-fix vulnerable dependency versions
    p_fd = sub.add_parser("fix-deps", help="Auto-fix vulnerable dependency versions")
    p_fd.add_argument("path", nargs="?", default=".")
    p_fd.add_argument("--apply", action="store_true", help="Patch manifest files (with backup)")
    p_fd.add_argument("--no-backup", action="store_true", help="Skip .ghost.bak backup")
    p_fd.add_argument("--pr", metavar="owner/repo", help="Create GitHub PR after patching")
    p_fd.add_argument("--token", metavar="TOKEN", help="GitHub PAT (or set GITHUB_TOKEN env var)")

    # suppress — .ghostignore management
    p_sup = sub.add_parser("suppress", help="Manage .ghostignore finding suppressions")
    p_sup.add_argument("path", nargs="?", default=".", help="Project root")
    p_sup.add_argument("--add", metavar="RULE_ID", help="Add suppression for rule/CVE")
    p_sup.add_argument("--reason", default="Suppressed via CLI")
    p_sup.add_argument("--files", nargs="*", default=[], metavar="GLOB")
    p_sup.add_argument("--expires", metavar="YYYY-MM-DD", help="Expiry date")
    p_sup.add_argument("--list", action="store_true", help="List all suppressions")
    p_sup.add_argument("--create-example", action="store_true", help="Write .ghostignore template")

    # enrich — EPSS + CISA KEV enrichment
    p_enr = sub.add_parser("enrich", help="Enrich findings with EPSS scores and CISA KEV data")
    p_enr.add_argument("findings", nargs="?", default="findings.json")
    p_enr.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_enr.add_argument("--save", metavar="FILE")

    # sarif — export findings to SARIF 2.1.0
    p_sarif = sub.add_parser("sarif", help="Export findings to SARIF 2.1.0 (GitHub Code Scanning)")
    p_sarif.add_argument("findings", nargs="?", default="findings.json")
    p_sarif.add_argument("--out", default="results.sarif", metavar="FILE")

    # java — Java SAST
    p_java = sub.add_parser("java", help="Java SAST scan (SQL injection, XXE, deserialization, ...)")
    p_java.add_argument("path", nargs="?", default=".")
    p_java.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_java.add_argument("--save", metavar="FILE")
    p_java.add_argument("--no-fail", action="store_true")

    # go — Go SAST
    p_go = sub.add_parser("go", help="Go SAST scan (SQL injection, TLS, command injection, ...)")
    p_go.add_argument("path", nargs="?", default=".")
    p_go.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_go.add_argument("--save", metavar="FILE")
    p_go.add_argument("--no-fail", action="store_true")

    # reachability — reachability analysis
    p_reach = sub.add_parser("reachability",
                              help="Reachability analysis — is the vulnerable code actually called?")
    p_reach.add_argument("findings", nargs="?", default="findings.json")
    p_reach.add_argument("--root", default=".", help="Project root for call-graph analysis")
    p_reach.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_reach.add_argument("--save", metavar="FILE")

    # rules — custom YAML rules
    p_rules = sub.add_parser("rules", help="Run custom YAML security rules against a directory")
    p_rules.add_argument("path", nargs="?", default=".")
    p_rules.add_argument("--rules-dir", metavar="DIR", help="Extra rules directory")
    p_rules.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_rules.add_argument("--save", metavar="FILE")
    p_rules.add_argument("--create-example", action="store_true",
                         help="Write .ghost/rules/example.yml to current directory")

    # license — license compliance
    p_lic = sub.add_parser("license", help="License compliance scan (GPL/AGPL/LGPL risk)")
    p_lic.add_argument("path", nargs="?", default=".")
    p_lic.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_lic.add_argument("--save", metavar="FILE")

    # git-secrets — git history secret scan
    p_gs = sub.add_parser("git-secrets",
                           help="Scan git commit history for accidentally committed secrets")
    p_gs.add_argument("path", nargs="?", default=".", help="Git repository root")
    p_gs.add_argument("--max-commits", type=int, default=200)
    p_gs.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_gs.add_argument("--save", metavar="FILE")

    # vex — VEX exporter
    p_vex = sub.add_parser("vex",
                            help="Generate CycloneDX VEX (Vulnerability Exploitability eXchange)")
    p_vex.add_argument("findings", nargs="?", default="findings.json")
    p_vex.add_argument("--name", default="project", help="Product name")
    p_vex.add_argument("--version", default="0.0.0")
    p_vex.add_argument("--out", default="vex.json", metavar="FILE")

    # graphql — GraphQL security scanner
    p_gql = sub.add_parser("graphql", help="GraphQL security scan (introspection, depth, auth)")
    p_gql.add_argument("path", nargs="?", default=".")
    p_gql.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_gql.add_argument("--save", metavar="FILE")

    # jwt — JWT/OAuth scanner
    p_jwt = sub.add_parser("jwt", help="JWT/OAuth misconfiguration scan (alg:none, PKCE, CSRF)")
    p_jwt.add_argument("path", nargs="?", default=".")
    p_jwt.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_jwt.add_argument("--save", metavar="FILE")
    p_jwt.add_argument("--no-fail", action="store_true")

    # tasks — SQLite task store viewer
    p_tasks = sub.add_parser("tasks", help="View/manage persisted task history (SQLite store)")
    p_tasks.add_argument("--stats", action="store_true", help="Show counts by state")
    p_tasks.add_argument("--state", dest="state_filter", metavar="STATE",
                         help="Filter by state: pending|running|succeeded|failed|cancelled")
    p_tasks.add_argument("--limit", type=int, default=50)
    p_tasks.add_argument("--clean", type=int, metavar="DAYS",
                         help="Delete tasks older than DAYS days")

    # tune — rule tuner
    p_tune = sub.add_parser("tune", help="Apply YAML rule-weight overrides to reduce false positives")
    p_tune.add_argument("findings", nargs="?", default="findings.json")
    p_tune.add_argument("--config", metavar="FILE", help="Path to rule_tuning.yaml (auto-discovered if omitted)")
    p_tune.add_argument("--out", metavar="FILE", help="Output path (default: findings_tuned.json)")
    p_tune.add_argument("--create-example", action="store_true",
                        dest="create_example", help="Scaffold a rule_tuning.yaml example")
    p_tune.add_argument("--example-out", default="rule_tuning.yaml", dest="example_out")

    # ton-gas — gas risk analysis
    p_tgas = sub.add_parser("ton-gas", help="TON gas consumption risk analysis (GAS-001..006)")
    p_tgas.add_argument("path", nargs="?", default=".")
    p_tgas.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_tgas.add_argument("--save", metavar="FILE")
    p_tgas.add_argument("--no-fail", action="store_true")

    # ton-state — state machine analysis
    p_tstate = sub.add_parser("ton-state",
                               help="TON state machine transition analysis (STM-001..004)")
    p_tstate.add_argument("path", nargs="?", default=".")
    p_tstate.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_tstate.add_argument("--save", metavar="FILE")
    p_tstate.add_argument("--no-fail", action="store_true")

    # ton-surface — attack surface mapping
    p_tsurf = sub.add_parser("ton-surface",
                              help="TON attack surface mapping (entry points, risk score 0-100)")
    p_tsurf.add_argument("path", nargs="?", default=".")
    p_tsurf.add_argument("--save", metavar="FILE")
    p_tsurf.add_argument("--no-fail", action="store_true")

    # notify — Jira + Slack notification dispatch
    p_notify = sub.add_parser("notify",
                               help="Send findings to Jira and/or Slack")
    p_notify.add_argument("findings", nargs="?", default="findings.json",
                          help="Findings JSON file (default: findings.json)")
    p_notify.add_argument("--jira", action="store_true", help="Create Jira issues")
    p_notify.add_argument("--slack", action="store_true", help="Send Slack summary")
    p_notify.add_argument("--min-severity", dest="min_severity", default="HIGH",
                          choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                          help="Minimum severity to notify (default: HIGH)")
    p_notify.add_argument("--test-connection", dest="test_connection", action="store_true",
                          help="Test Jira/Slack connectivity without sending findings")

    # sla — SLA compliance tracking
    p_sla = sub.add_parser("sla", help="SLA compliance tracking and reporting")
    p_sla.add_argument("findings", nargs="?", default="findings.json",
                       help="Findings JSON file (used with --open)")
    p_sla.add_argument("--open", dest="open_findings", action="store_true",
                       help="Open SLA tickets for findings in FILE")
    p_sla.add_argument("--overdue", action="store_true",
                       help="List overdue findings (exit 1 if any)")
    p_sla.add_argument("--report", action="store_true",
                       help="Print full SLA compliance report")
    p_sla.add_argument("--fmt", default="table", choices=["table", "json"],
                       help="Report format (default: table)")
    p_sla.add_argument("--policy", default="default",
                       choices=["default", "pci-dss", "soc2"],
                       help="SLA policy to apply (default: default)")

    # audit-log — audit event viewer
    p_audit = sub.add_parser("audit-log", help="View and export the platform audit log")
    p_audit.add_argument("--tail", type=int, default=50, metavar="N",
                         help="Show last N audit events (default: 50)")
    p_audit.add_argument("--stats", action="store_true",
                         help="Show aggregate statistics")
    p_audit.add_argument("--export", dest="export_path", metavar="FILE",
                         help="Export audit log to CSV")

    # ide — VS Code / JetBrains IDE plugin management
    p_ide = sub.add_parser("ide", help="IDE plugin management (install, status, rules)")
    p_ide.add_argument("action", nargs="?", default="status",
                       choices=["install", "status", "rules"],
                       help="Action: install | status | rules (default: status)")

    # ── Multi-chain Web3 scanners ──────────────────────────────────────────────
    p_evm = sub.add_parser("evm", help="EVM/Solidity scan (reentrancy, access control, flash loans, MEV, ...)")
    p_evm.add_argument("path", nargs="?", default=".")
    p_evm.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_evm.add_argument("--save", metavar="FILE")
    p_evm.add_argument("--no-fail", action="store_true")

    p_sol = sub.add_parser("solana", help="Solana/Anchor scan (signer checks, PDA, CPI, arithmetic, ...)")
    p_sol.add_argument("path", nargs="?", default=".")
    p_sol.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_sol.add_argument("--save", metavar="FILE")
    p_sol.add_argument("--no-fail", action="store_true")

    p_cos = sub.add_parser("cosmos", help="CosmWasm scan (execute auth, IBC, reentrancy, ...)")
    p_cos.add_argument("path", nargs="?", default=".")
    p_cos.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_cos.add_argument("--save", metavar="FILE")
    p_cos.add_argument("--no-fail", action="store_true")

    p_dot = sub.add_parser("polkadot", help="ink!/Polkadot scan (access control, arithmetic, storage, ...)")
    p_dot.add_argument("path", nargs="?", default=".")
    p_dot.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_dot.add_argument("--save", metavar="FILE")
    p_dot.add_argument("--no-fail", action="store_true")

    p_mv = sub.add_parser("move", help="Move (Sui/Aptos) scan (capabilities, resources, access control, ...)")
    p_mv.add_argument("path", nargs="?", default=".")
    p_mv.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_mv.add_argument("--save", metavar="FILE")
    p_mv.add_argument("--no-fail", action="store_true")

    p_w3 = sub.add_parser("web3", help="Auto-detect blockchain and scan (EVM/Solana/Cosmos/Polkadot/Move/TON)")
    p_w3.add_argument("path", nargs="?", default=".")
    p_w3.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_w3.add_argument("--save", metavar="FILE")
    p_w3.add_argument("--no-fail", action="store_true")

    # ── Parse (must be AFTER all sub.add_parser calls) ────────────────────────
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0

    dispatch = {
        "scan":         cmd_scan,
        "ton":          cmd_ton,
        "k8s":          cmd_k8s,
        "fix":          cmd_fix,
        "serve":        cmd_serve,
        "status":       cmd_status,
        "report":       cmd_report,
        "benchmark":    cmd_benchmark,
        "deps":         cmd_deps,
        "iac":          cmd_iac,
        "ci":           cmd_ci,
        "container":    cmd_container,
        "sbom":         cmd_sbom,
        "compliance":   cmd_compliance,
        "fix-deps":     cmd_fix_deps,
        "suppress":     cmd_suppress,
        "enrich":       cmd_enrich,
        "sarif":        cmd_sarif,
        "java":         cmd_java,
        "go":           cmd_go,
        "reachability": cmd_reachability,
        "rules":        cmd_rules,
        "license":      cmd_license,
        "git-secrets":  cmd_git_secrets,
        "vex":          cmd_vex,
        "graphql":      cmd_graphql,
        "jwt":          cmd_jwt,
        "tasks":        cmd_tasks,
        "tune":         cmd_tune,
        "ton-gas":      cmd_ton_gas,
        "ton-state":    cmd_ton_state,
        "ton-surface":  cmd_ton_surface,
        "notify":       cmd_notify,
        "sla":          cmd_sla,
        "audit-log":    cmd_audit_log,
        "ide":          cmd_ide,
        "evm":          cmd_evm,
        "solana":       cmd_solana,
        "cosmos":       cmd_cosmos,
        "polkadot":     cmd_polkadot,
        "move":         cmd_move,
        "web3":         cmd_web3,
    }
    handler = dispatch.get(args.command)
    if handler:
        sys.exit(handler(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
