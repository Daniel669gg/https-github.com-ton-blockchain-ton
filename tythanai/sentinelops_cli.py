"""
TythanAI — Multi-Chain Web3 + AppSec Security Platform CLI
Использование:
  sentinelops scan .               # full SAST scan (Python/JS/C/C++)
  sentinelops scan --incremental . # only changed files
  sentinelops ton ./contracts/     # TON bug bounty scan
  sentinelops evm ./contracts/     # EVM/Solidity security scan (16 rules)
  sentinelops solana ./program/    # Solana/Anchor security scan (11 rules)
  sentinelops cosmos ./contracts/  # CosmWasm security scan (8 rules)
  sentinelops polkadot ./lib.rs    # Polkadot/ink! security scan (7 rules)
  sentinelops move ./sources/      # Move language security scan (8 rules)
  sentinelops web3 ./              # Scan all Web3 chains in one pass
  sentinelops k8s ./manifests/     # Kubernetes audit
  sentinelops deps .               # live CVE scan (OSV.dev)
  sentinelops iac .                # IaC scan (Docker/Terraform/Ansible/Helm/CFN)
  sentinelops container nginx:1.21.0  # container image CVE scan
  sentinelops sbom .               # generate SPDX 2.3 / CycloneDX SBOM
  sentinelops compliance .         # compliance gap report (PCI-DSS/SOC2/HIPAA/NIST)
  sentinelops fix-deps .           # auto-fix vulnerable dependency versions
  sentinelops suppress .           # manage finding suppressions
  sentinelops fix findings.json    # auto-fix code
  sentinelops serve                # start API server
  sentinelops benchmark            # accuracy test
  sentinelops status               # component health check
  sentinelops report findings.json # Immunefi/HackenProof report

No Docker. No server. Results in seconds.
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
    print(BOLD("\n🛡️  TythanAI"))
    print(DIM("   Multi-Chain Web3 + AppSec · 3000+ rules · TON/EVM/Solana/Cosmos/Polkadot/Move · K8s · Multi-LLM\n"))

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
    """sentinelops status"""
    print(BOLD("  TythanAI — Multi-Chain Web3 + AppSec Platform Status\n"))

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
    print(f"    Blockchain : TON(87+) · EVM(16) · Solana(11) · CosmWasm(8) · Polkadot/ink!(7) · Move(8)")
    print(f"    Web3 rules : EVM({len(list((Path(__file__).parent/'rules'/'evm').rglob('*.yaml')))} files) · "
          f"Solana · Cosmos · Polkadot · Move · TON-advanced")
    print(f"    Advanced   : AST engine · OpenAPI (OWASP API Top 10) · Semgrep · LLM deep analysis")
    print(f"  {BOLD('Suppression:')} .ghostignore (YAML · expiry dates · file patterns)")
    print(f"  {BOLD('Auto-fix:')}   Dep bumps (PyPI/npm/Go/Rust) · Code patches · GitHub PR")

    # Cloud
    try:
        from cloud.tenant.tenant_manager import TenantManager
        tenants = TenantManager().list_tenants()
        print(f"\n  {BOLD('Cloud:')} multi-tenant  ({len(tenants)} tenant(s) registered)")
    except Exception:
        print(f"\n  {BOLD('Cloud:')} {DIM('standalone mode (no tenants)')}")

    # Telemetry
    otel_ep = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    prom_port = os.getenv("PROMETHEUS_PORT", "")
    print(f"  {BOLD('Telemetry:')} "
          f"OTLP={'enabled → ' + otel_ep if otel_ep else DIM('disabled')}  "
          f"Prometheus={'port ' + prom_port if prom_port else DIM('disabled')}")

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
    print(BLUE(f"🚀  Starting TythanAI API on http://0.0.0.0:{port}"))
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
        print(BOLD("\n🔌  TythanAI VS Code Extension"))
        print(DIM("   Real-time security scanning · 3000+ rules · SARIF export\n"))
        print(BLUE("📦  Installation options:\n"))
        print(f"   1. VS Code Marketplace (recommended):")
        print(f"      Open VS Code → Extensions → Search 'TythanAI'\n")
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
        print(BOLD(f"\n📏  TythanAI Rules: {total_rules} total\n"))
        for cat, cnt in sorted(categories.items(), key=lambda x: -x[1]):
            bar = "█" * min(30, cnt // 10)
            print(f"   {cat:<20} {cnt:>5}  {bar}")
        print()
        return 0

    # status (default)
    print(BOLD("\n🔌  TythanAI IDE Integration Status\n"))
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


def cmd_evm(args) -> int:
    """sentinelops evm <path> [--output json|table] [--min-severity MEDIUM] [--save FILE]

    Static security analysis for EVM-compatible smart contracts (.sol, .vy).
    Detects: reentrancy, tx.origin auth, unchecked return values, integer overflow,
    delegatecall, selfdestruct, block timestamp, weak randomness, missing access control,
    flash loan vectors, price oracle manipulation, proxy storage collision,
    ERC-20 approve race, and signature replay (16 rules).
    """
    path = str(Path(getattr(args, "path", ".")).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}"))
        return 1

    print(BLUE(f"⛓  EVM/Solidity security scan: {path}"))
    t0 = time.time()

    from scanners.evm_scanner.evm_analyzer import EVMScanner

    p = Path(path)
    scanner = EVMScanner()
    if p.is_file():
        findings = scanner.scan_file(str(p))
        files_scanned = 1
    else:
        result = scanner.scan_directory(str(p))
        findings = result.get("findings", [])
        files_scanned = result.get("files_scanned", 0)
        sev_counts = result.get("severity_counts", {})
        print(DIM(f"   Files: {files_scanned}  "
                  f"Critical: {sev_counts.get('CRITICAL',0)}  "
                  f"High: {sev_counts.get('HIGH',0)}  "
                  f"Medium: {sev_counts.get('MEDIUM',0)}\n"))

    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_sev = getattr(args, "min_severity", "MEDIUM")
    min_idx = order.index(min_sev) if min_sev in order else 2
    findings = [f for f in findings if order.index(f.get("severity", "MEDIUM")) >= min_idx]

    duration = time.time() - t0

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


def cmd_solana(args) -> int:
    """sentinelops solana <path> [--output json|table] [--min-severity MEDIUM] [--save FILE]

    Static security analysis for Solana/Anchor programs (.rs files).
    Detects: missing signer checks, missing owner checks, PDA seed manipulation,
    arithmetic overflow, unchecked CPI return values, account discriminator bypass,
    missing account constraints, unsafe deserialization, integer truncation,
    missing rent exemption, and reinitialization attacks (11 rules).
    """
    path = str(Path(getattr(args, "path", ".")).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}"))
        return 1

    print(BLUE(f"◎  Solana/Anchor security scan: {path}"))
    t0 = time.time()

    from scanners.solana_scanner.solana_analyzer import SolanaScanner

    p = Path(path)
    scanner = SolanaScanner()
    if p.is_file():
        findings = scanner.scan_file(str(p))
        files_scanned = 1
    else:
        result = scanner.scan_directory(str(p))
        findings = result.get("findings", [])
        files_scanned = result.get("files_scanned", 0)
        sev_counts = result.get("severity_counts", {})
        print(DIM(f"   Files: {files_scanned}  "
                  f"Critical: {sev_counts.get('CRITICAL',0)}  "
                  f"High: {sev_counts.get('HIGH',0)}  "
                  f"Medium: {sev_counts.get('MEDIUM',0)}\n"))

    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_sev = getattr(args, "min_severity", "MEDIUM")
    min_idx = order.index(min_sev) if min_sev in order else 2
    findings = [f for f in findings if order.index(f.get("severity", "MEDIUM")) >= min_idx]

    duration = time.time() - t0

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


def cmd_cosmos(args) -> int:
    """sentinelops cosmos <path> [--output json|table] [--min-severity MEDIUM] [--save FILE]

    Static security analysis for CosmWasm smart contracts (.rs files).
    Detects: unauthorized execute handlers, missing admin check in migration,
    reentrancy via submessages, unbounded query/iteration, missing input validation,
    unsafe math, IBC channel ordering, and missing reply handler error cases (8 rules).
    """
    path = str(Path(getattr(args, "path", ".")).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}"))
        return 1

    print(BLUE(f"🌌  CosmWasm/Cosmos security scan: {path}"))
    t0 = time.time()

    from scanners.cosmos_scanner.cosmwasm_analyzer import CosmosScanner

    p = Path(path)
    scanner = CosmosScanner()
    if p.is_file():
        findings = scanner.scan_file(str(p))
        files_scanned = 1
    else:
        result = scanner.scan_directory(str(p))
        findings = result.get("findings", [])
        files_scanned = result.get("files_scanned", 0)
        sev_counts = result.get("severity_counts", {})
        print(DIM(f"   Files: {files_scanned}  "
                  f"Critical: {sev_counts.get('CRITICAL',0)}  "
                  f"High: {sev_counts.get('HIGH',0)}  "
                  f"Medium: {sev_counts.get('MEDIUM',0)}\n"))

    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_sev = getattr(args, "min_severity", "MEDIUM")
    min_idx = order.index(min_sev) if min_sev in order else 2
    findings = [f for f in findings if order.index(f.get("severity", "MEDIUM")) >= min_idx]

    duration = time.time() - t0

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


def cmd_polkadot(args) -> int:
    """sentinelops polkadot <path> [--output json|table] [--min-severity MEDIUM] [--save FILE]

    Static security analysis for Polkadot/ink! smart contracts (.rs files).
    Detects: missing constructor access control, unchecked arithmetic,
    missing caller() validation, storage key collision risk, missing payable
    annotation, unsafe unwrap(), and cross-contract call error handling (7 rules).
    """
    path = str(Path(getattr(args, "path", ".")).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}"))
        return 1

    print(BLUE(f"🔴  Polkadot/ink! security scan: {path}"))
    t0 = time.time()

    from scanners.polkadot_scanner.ink_analyzer import PolkadotScanner

    p = Path(path)
    scanner = PolkadotScanner()
    if p.is_file():
        findings = scanner.scan_file(str(p))
        files_scanned = 1
    else:
        result = scanner.scan_directory(str(p))
        findings = result.get("findings", [])
        files_scanned = result.get("files_scanned", 0)
        sev_counts = result.get("severity_counts", {})
        print(DIM(f"   Files: {files_scanned}  "
                  f"Critical: {sev_counts.get('CRITICAL',0)}  "
                  f"High: {sev_counts.get('HIGH',0)}  "
                  f"Medium: {sev_counts.get('MEDIUM',0)}\n"))

    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_sev = getattr(args, "min_severity", "MEDIUM")
    min_idx = order.index(min_sev) if min_sev in order else 2
    findings = [f for f in findings if order.index(f.get("severity", "MEDIUM")) >= min_idx]

    duration = time.time() - t0

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


def cmd_move(args) -> int:
    """sentinelops move <path> [--output json|table] [--min-severity MEDIUM] [--save FILE]

    Static security analysis for Move language smart contracts (.move files).
    Supports both Sui Move and Aptos Move dialects.
    Detects: missing capability checks, unchecked arithmetic, missing object
    ownership validation, public entry without access control, coin/balance
    manipulation, missing abort conditions, shared object reentrancy,
    and dynamic field access without validation (8 rules).
    """
    path = str(Path(getattr(args, "path", ".")).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}"))
        return 1

    print(BLUE(f"🔷  Move language security scan: {path}"))
    t0 = time.time()

    from scanners.move_scanner.move_analyzer import MoveScanner

    p = Path(path)
    scanner = MoveScanner()
    if p.is_file():
        findings = scanner.scan_file(str(p))
        files_scanned = 1
    else:
        result = scanner.scan_directory(str(p))
        findings = result.get("findings", [])
        files_scanned = result.get("files_scanned", 0)
        sev_counts = result.get("severity_counts", {})
        print(DIM(f"   Files: {files_scanned}  "
                  f"Critical: {sev_counts.get('CRITICAL',0)}  "
                  f"High: {sev_counts.get('HIGH',0)}  "
                  f"Medium: {sev_counts.get('MEDIUM',0)}\n"))

    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_sev = getattr(args, "min_severity", "MEDIUM")
    min_idx = order.index(min_sev) if min_sev in order else 2
    findings = [f for f in findings if order.index(f.get("severity", "MEDIUM")) >= min_idx]

    duration = time.time() - t0

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


def cmd_web3(args) -> int:
    """sentinelops web3 <path> [--output json|table] [--min-severity MEDIUM] [--save FILE]

    Combined multi-chain Web3 security scan.
    Runs all available blockchain scanners in a single pass:
      TON (FunC/Tact/Fift) · EVM/Solidity · Solana/Anchor · CosmWasm
      Polkadot/ink! · Move (Sui/Aptos)

    Each scanner runs only on files it understands — no false positives
    from cross-chain rule mismatches.
    """
    path = str(Path(getattr(args, "path", ".")).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}"))
        return 1

    print(BLUE(f"🌐  Multi-chain Web3 security scan: {path}"))
    t0 = time.time()

    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_sev = getattr(args, "min_severity", "MEDIUM")
    min_idx = order.index(min_sev) if min_sev in order else 2

    all_findings = []
    chain_summary = []

    # TON
    try:
        from scanners.ton_scanner.ton_analyzer import TONAnalyzer
        ton_result = TONAnalyzer().scan_directory(path)
        ton_findings = ton_result.get("findings", [])
        all_findings.extend(ton_findings)
        chain_summary.append(("TON", ton_result.get("files_scanned", 0), len(ton_findings)))
    except Exception as e:
        chain_summary.append(("TON", 0, 0))
        print(DIM(f"   TON scanner error: {e}"))

    # EVM/Solidity
    try:
        from scanners.evm_scanner.evm_analyzer import EVMScanner
        evm_result = EVMScanner().scan_directory(path)
        evm_findings = evm_result.get("findings", [])
        all_findings.extend(evm_findings)
        chain_summary.append(("EVM/Solidity", evm_result.get("files_scanned", 0), len(evm_findings)))
    except Exception as e:
        chain_summary.append(("EVM/Solidity", 0, 0))
        print(DIM(f"   EVM scanner error: {e}"))

    # Solana
    try:
        from scanners.solana_scanner.solana_analyzer import SolanaScanner
        sol_result = SolanaScanner().scan_directory(path)
        sol_findings = sol_result.get("findings", [])
        all_findings.extend(sol_findings)
        chain_summary.append(("Solana/Anchor", sol_result.get("files_scanned", 0), len(sol_findings)))
    except Exception as e:
        chain_summary.append(("Solana/Anchor", 0, 0))
        print(DIM(f"   Solana scanner error: {e}"))

    # Cosmos/CosmWasm
    try:
        from scanners.cosmos_scanner.cosmwasm_analyzer import CosmosScanner
        cos_result = CosmosScanner().scan_directory(path)
        cos_findings = cos_result.get("findings", [])
        all_findings.extend(cos_findings)
        chain_summary.append(("CosmWasm", cos_result.get("files_scanned", 0), len(cos_findings)))
    except Exception as e:
        chain_summary.append(("CosmWasm", 0, 0))
        print(DIM(f"   Cosmos scanner error: {e}"))

    # Polkadot/ink!
    try:
        from scanners.polkadot_scanner.ink_analyzer import PolkadotScanner
        ink_result = PolkadotScanner().scan_directory(path)
        ink_findings = ink_result.get("findings", [])
        all_findings.extend(ink_findings)
        chain_summary.append(("Polkadot/ink!", ink_result.get("files_scanned", 0), len(ink_findings)))
    except Exception as e:
        chain_summary.append(("Polkadot/ink!", 0, 0))
        print(DIM(f"   Polkadot scanner error: {e}"))

    # Move
    try:
        from scanners.move_scanner.move_analyzer import MoveScanner
        mov_result = MoveScanner().scan_directory(path)
        mov_findings = mov_result.get("findings", [])
        all_findings.extend(mov_findings)
        chain_summary.append(("Move (Sui/Aptos)", mov_result.get("files_scanned", 0), len(mov_findings)))
    except Exception as e:
        chain_summary.append(("Move (Sui/Aptos)", 0, 0))
        print(DIM(f"   Move scanner error: {e}"))

    # Print per-chain summary
    print(DIM(f"   {'Chain':<20}  {'Files':>6}  {'Findings':>8}"))
    for chain, files, count in chain_summary:
        marker = RED("●") if count > 0 else GREEN("●")
        print(f"   {marker}  {chain:<20}  {files:>6}  {count:>8}")
    print()

    # Apply min-severity filter
    all_findings = [f for f in all_findings
                    if order.index(f.get("severity", "MEDIUM")) >= min_idx]

    # Deduplicate by (rule_id/id, file, line)
    seen: set = set()
    deduped = []
    for f in all_findings:
        key = (f.get("rule_id") or f.get("id", ""), f.get("file", ""), f.get("line", 0))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # Sort by severity
    _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    deduped.sort(key=lambda f: _sev_order.get(f.get("severity", "MEDIUM"), 5))

    duration = time.time() - t0

    if getattr(args, "output", "table") == "json":
        print(json.dumps(deduped, indent=2))
    else:
        _print_findings(deduped, max_show=60)
        _print_summary({"total_findings": len(deduped), "findings": deduped}, duration)

    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps(deduped, indent=2))
        print(GREEN(f"💾  Saved to {args.save}"))

    if getattr(args, "report", False):
        from reports.bounty_report import BugBountyReportGenerator
        out_dir = getattr(args, "report_dir", "./sentinelops_reports/web3")
        gen = BugBountyReportGenerator(Path(path).name)
        outputs = gen.generate_all(deduped, out_dir, min_severity=min_sev)
        print(GREEN(f"📄  Reports generated: {len(outputs)} files in {out_dir}/"))

    crits = sum(1 for f in deduped if f.get("severity") == "CRITICAL")
    return 1 if crits > 0 and not getattr(args, "no_fail", False) else 0


def cmd_ast(args) -> int:
    """sentinelops ast <path> [--output json|table] [--save FILE]

    AST-based deep static analysis for Python source files.
    Detects: SQL injection via string concatenation, eval/exec misuse,
    hardcoded credentials, unsafe pickle, subprocess injection,
    SSRF patterns, insecure deserialization, and taint-flow issues.
    """
    path = str(Path(getattr(args, "path", ".")).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}")); return 1

    print(BLUE(f"🌳  AST deep analysis: {path}"))
    t0 = time.time()

    from scanners.ast_scanner.ast_analyzer import ASTScanner
    p = Path(path)
    scanner = ASTScanner()
    if p.is_file():
        findings = scanner.scan_file(str(p))
        print(DIM(f"   File: {p.name}\n"))
    else:
        result = scanner.scan_directory(str(p))
        findings = result.get("findings", [])
        print(DIM(f"   Files: {result.get('files_scanned', 0)}  "
                  f"Rules: {result.get('rules_applied', 0)}\n"))

    # Normalise ASTFinding dataclasses to dicts
    out = []
    for f in findings:
        out.append(f.to_dict() if hasattr(f, "to_dict") else (f if isinstance(f, dict) else vars(f)))
    findings = out

    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_sev = getattr(args, "min_severity", "MEDIUM")
    min_idx = order.index(min_sev) if min_sev in order else 2
    findings = [f for f in findings if order.index(f.get("severity", "MEDIUM")) >= min_idx]

    duration = time.time() - t0
    if getattr(args, "output", "table") == "json":
        print(json.dumps(findings, indent=2))
    else:
        _print_findings(findings, max_show=50)
        _print_summary({"total_findings": len(findings), "findings": findings}, duration)

    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps(findings, indent=2))
        print(GREEN(f"💾  Saved to {args.save}"))

    crits = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    return 1 if crits and not getattr(args, "no_fail", False) else 0


def cmd_openapi(args) -> int:
    """sentinelops openapi <spec> [--output json|table] [--save FILE]

    OWASP API Security Top 10 2023 scan for OpenAPI 3.x / Swagger 2.x specs.
    Detects: BOLA, broken auth, excessive data exposure, missing rate limits,
    BFLA, HTTP-only endpoints, weak authentication schemes, admin path exposure,
    and sensitive field leaks.
    Accepts: file path (.json/.yaml/.yml) or URL.
    """
    spec = getattr(args, "spec", "openapi.yaml")
    print(BLUE(f"🔷  OpenAPI security scan: {spec}"))
    t0 = time.time()

    # If a directory is given, find all spec files
    p = Path(spec)
    if p.is_dir():
        from scanners.openapi_scanner import OpenAPIScanner
        scanner = OpenAPIScanner()
        findings = []
        spec_files = list(p.rglob("openapi*.json")) + list(p.rglob("openapi*.yaml")) + \
                     list(p.rglob("swagger*.json")) + list(p.rglob("swagger*.yaml")) + \
                     list(p.rglob("api*.yaml")) + list(p.rglob("api*.json"))
        spec_files = list(dict.fromkeys(spec_files))[:50]
        for sf in spec_files:
            result = scanner.scan_file(str(sf))
            findings.extend(result)
        print(DIM(f"   Spec files: {len(spec_files)}\n"))
    else:
        from scanners.openapi_scanner import OpenAPIScanner
        scanner = OpenAPIScanner()
        if p.is_file():
            findings = scanner.scan_file(str(p))
        else:
            result = scanner.scan(spec)
            findings = result.get("findings", [])

    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_sev = getattr(args, "min_severity", "LOW")
    min_idx = order.index(min_sev) if min_sev in order else 1
    findings = [f for f in findings if order.index(f.get("severity", "MEDIUM")) >= min_idx]

    duration = time.time() - t0
    if getattr(args, "output", "table") == "json":
        print(json.dumps(findings, indent=2))
    else:
        _print_findings(findings, max_show=50)
        _print_summary({"total_findings": len(findings), "findings": findings}, duration)

    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps(findings, indent=2))
        print(GREEN(f"💾  Saved to {args.save}"))

    crits = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    return 1 if crits and not getattr(args, "no_fail", False) else 0


def cmd_semgrep(args) -> int:
    """sentinelops semgrep <path> [--rules RULESET] [--output json|table] [--save FILE]

    Run Semgrep with TythanAI's curated rule packs.
    Falls back gracefully to pattern-based scanning when semgrep is not installed.
    Rulesets: auto | p/python | p/javascript | p/java | p/go | p/owasp-top-ten
    """
    path = str(Path(getattr(args, "path", ".")).resolve())
    if not Path(path).exists():
        print(RED(f"❌  Path not found: {path}")); return 1

    ruleset = getattr(args, "rules", "auto")
    print(BLUE(f"🔬  Semgrep scan: {path}  [rules: {ruleset}]"))
    t0 = time.time()

    from scanners.semgrep_integration import SemgrepScanner
    scanner = SemgrepScanner()
    result = scanner.scan_directory(path, ruleset=ruleset,
                                    timeout=getattr(args, "timeout", 120))
    findings = result.get("findings", [])
    print(DIM(f"   Engine: {result.get('engine', 'semgrep')}  "
              f"Files: {result.get('files_scanned', 0)}  "
              f"Rules: {result.get('rules_loaded', 0)}\n"))

    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    min_sev = getattr(args, "min_severity", "MEDIUM")
    min_idx = order.index(min_sev) if min_sev in order else 2
    findings = [f for f in findings if order.index(f.get("severity", "MEDIUM")) >= min_idx]

    duration = time.time() - t0
    if getattr(args, "output", "table") == "json":
        print(json.dumps(findings, indent=2))
    else:
        _print_findings(findings, max_show=50)
        _print_summary({"total_findings": len(findings), "findings": findings}, duration)

    if getattr(args, "save", None):
        Path(args.save).write_text(json.dumps(findings, indent=2))
        print(GREEN(f"💾  Saved to {args.save}"))

    crits = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    return 1 if crits and not getattr(args, "no_fail", False) else 0


def cmd_llm_scan(args) -> int:
    """sentinelops llm-scan <findings.json> [--min-severity HIGH] [--max N] [--save FILE]

    Enrich existing static findings with LLM-powered deep analysis:
      · Confidence score & reason
      · CVSS 3.1 vector + score
      · Realistic exploit scenario
      · Deeper technical explanation
      · Concrete code fix snippet
      · False positive risk rating

    Requires OPENAI_API_KEY or a running Ollama instance.
    Processes HIGH/CRITICAL findings by default (use --min-severity MEDIUM for more).
    """
    findings_path = getattr(args, "findings", "findings.json")
    if not Path(findings_path).exists():
        print(RED(f"❌  File not found: {findings_path}")); return 1

    raw = json.loads(Path(findings_path).read_text())
    findings = raw if isinstance(raw, list) else raw.get("findings", [])
    min_sev = getattr(args, "min_severity", "HIGH")
    max_n   = getattr(args, "max_findings", 20)

    print(BLUE(f"🤖  LLM deep analysis: {len(findings)} findings  "
               f"(min: {min_sev}, max: {max_n})"))
    t0 = time.time()

    from scanners.llm_analyzer import LLMAnalyzer
    analyzer = LLMAnalyzer(min_severity=min_sev, max_findings=max_n)
    enriched = analyzer.enrich_findings(findings)
    duration = time.time() - t0

    enriched_count = sum(1 for f in enriched if f.get("llm_analysis"))
    print(DIM(f"   Enriched: {enriched_count}/{len(findings)}  ({duration:.1f}s)\n"))

    out_fmt = getattr(args, "output", "table")
    if out_fmt == "json":
        print(json.dumps(enriched, indent=2))
    else:
        for f in enriched[:30]:
            sev    = f.get("severity", "MEDIUM")
            color  = _SEV_COLOR.get(sev, lambda x: x)
            icon   = _SEV_ICON.get(sev, "●")
            msg    = (f.get("message") or f.get("description") or "")[:55]
            llm    = f.get("llm_analysis", {})
            conf   = f"conf:{llm.get('confidence', '?')}%" if llm else ""
            cvss   = f"CVSS:{llm.get('cvss_score', '')}" if llm else ""
            fp_r   = f"FP:{llm.get('false_positive_risk', '')}" if llm else DIM("(no LLM)")
            print(f"  {color(icon+' '+sev.ljust(8))}  {BOLD(msg)}")
            if llm:
                print(f"    {DIM(conf)}  {DIM(cvss)}  {DIM(fp_r)}")
                expl = llm.get("exploit_scenario", "")
                if expl and expl != "N/A":
                    print(f"    {DIM(expl[:100])}")
            print()

    out_path = getattr(args, "save", None) or findings_path.replace(".json", "_llm.json")
    Path(out_path).write_text(json.dumps(enriched, indent=2))
    print(GREEN(f"💾  Saved to {out_path}"))
    return 0


def cmd_cloud(args) -> int:
    """sentinelops cloud <subcommand> [options]

    Multi-tenant cloud management: tenants, API keys, usage/billing.

    Subcommands:
      tenants list                          # list all tenants
      tenants create --name ACME --plan pro # create a new tenant
      tenants quota --org ORG_ID            # check scan quota
      keys create --org ORG_ID --name CI    # create API key
      keys list --org ORG_ID               # list API keys
      keys revoke --key-id KEY_ID --org ORG_ID
      usage --org ORG_ID                   # show monthly usage report
    """
    sub = getattr(args, "cloud_sub", "")
    action = getattr(args, "cloud_action", "")

    if sub == "tenants":
        from cloud.tenant.tenant_manager import TenantManager
        mgr = TenantManager()
        if action == "list":
            tenants = mgr.list_tenants()
            if not tenants:
                print(DIM("  No tenants found"))
                return 0
            print(BOLD(f"  Tenants ({len(tenants)})"))
            print(DIM(f"  {'ORG ID':<36}  {'NAME':<24}  {'PLAN':<10}  CREATED"))
            for t in tenants:
                print(f"  {t.get('org_id','')[:36]:<36}  "
                      f"{t.get('name','')[:24]:<24}  "
                      f"{t.get('plan',''):<10}  "
                      f"{str(t.get('created_at',''))[:10]}")
            return 0
        if action == "create":
            name = getattr(args, "name", "") or getattr(args, "org_name", "")
            plan = getattr(args, "plan", "free")
            if not name:
                print(RED("❌  --name required")); return 1
            t = mgr.create_tenant(name, plan=plan)
            print(GREEN(f"✅  Tenant created"))
            print(f"   Org ID : {t['org_id']}")
            print(f"   Name   : {t['name']}")
            print(f"   Plan   : {t['plan']}")
            return 0
        if action == "quota":
            org_id = getattr(args, "org", None)
            if not org_id:
                print(RED("❌  --org required")); return 1
            t = mgr.get_tenant(org_id)
            if not t:
                print(RED(f"❌  Tenant not found: {org_id}")); return 1
            print(BLUE(f"  Quota — {t['name']} ({t['plan']})"))
            ok = mgr.check_quota(org_id, "scans_per_month")
            color = GREEN if ok else RED
            print(f"  Scans this month: {color('within quota' if ok else 'EXCEEDED')}")
            usage = mgr.get_usage(org_id)
            print(f"  Scans:   {usage.get('scans', 0)}")
            return 0

    elif sub == "keys":
        from cloud.auth.api_key_manager import APIKeyManager
        mgr = APIKeyManager()
        if action == "create":
            org_id = getattr(args, "org", None)
            name   = getattr(args, "name", "default")
            scopes = getattr(args, "scopes", ["scan", "read"])
            if not org_id:
                print(RED("❌  --org required")); return 1
            result = mgr.create_key(org_id, name, scopes)
            print(GREEN(f"✅  API key created"))
            print(f"   Key ID : {result['key_id']}")
            print(f"   Key    : {BOLD(result['key'])}")
            print(RED("   ⚠️   Save this key — it will not be shown again!"))
            return 0
        if action == "list":
            org_id = getattr(args, "org", None)
            if not org_id:
                print(RED("❌  --org required")); return 1
            keys = mgr.list_keys(org_id)
            if not keys:
                print(DIM("  No API keys for this org"))
                return 0
            print(BOLD(f"  API Keys ({len(keys)})"))
            for k in keys:
                status = GREEN("active") if not k.get("revoked") else RED("revoked")
                print(f"  {k['key_id'][:12]}  {k.get('name',''):<16}  {status}  "
                      f"created: {str(k.get('created_at',''))[:10]}")
            return 0
        if action == "revoke":
            key_id = getattr(args, "key_id", None)
            org_id = getattr(args, "org", None)
            if not key_id or not org_id:
                print(RED("❌  --key-id and --org required")); return 1
            ok = mgr.revoke_key(key_id, org_id)
            print(GREEN(f"✅  Key {key_id} revoked") if ok else RED(f"❌  Key not found"))
            return 0 if ok else 1

    elif sub == "usage":
        org_id = getattr(args, "org", None)
        if not org_id:
            print(RED("❌  --org required")); return 1
        from cloud.billing.usage_tracker import UsageTracker
        tracker = UsageTracker()
        report = tracker.get_usage_report(org_id)
        print(BLUE(f"📊  Usage Report — org: {org_id}"))
        monthly = report.get("monthly", [])
        if monthly:
            for m in monthly[-6:]:
                print(f"   {m.get('month','?'):>7}  scans: {m.get('scans',0):>6}  "
                      f"api_calls: {m.get('api_calls',0):>8}")
        else:
            print(DIM("   No usage data yet"))
        return 0

    # Default: show cloud platform overview
    print(BOLD("\n  TythanAI Cloud — Multi-Tenant Platform\n"))
    print(DIM("  Subcommands:"))
    print(DIM("    sentinelops cloud tenants list"))
    print(DIM("    sentinelops cloud tenants create --name ACME --plan pro"))
    print(DIM("    sentinelops cloud tenants quota --org ORG_ID"))
    print(DIM("    sentinelops cloud keys create --org ORG_ID --name CI"))
    print(DIM("    sentinelops cloud keys list --org ORG_ID"))
    print(DIM("    sentinelops cloud keys revoke --key-id ID --org ORG_ID"))
    print(DIM("    sentinelops cloud usage --org ORG_ID"))
    try:
        from cloud.tenant.tenant_manager import TenantManager
        tenants = TenantManager().list_tenants()
        print(f"\n  Active tenants: {GREEN(str(len(tenants)))}")
    except Exception:
        pass
    return 0


def cmd_supervisor(args) -> int:
    """sentinelops supervisor [--status] [--tasks] [--list-tasks]

    Runtime supervisor status — view active async tasks, worker pool state,
    circuit breaker health, and retry policy statistics.
    """
    print(BOLD("  TythanAI Runtime Supervisor\n"))

    # Circuit breakers
    try:
        from runtime.circuit_breaker import CircuitBreakerRegistry
        reg = CircuitBreakerRegistry.global_instance()
        breakers = reg.list_all() if hasattr(reg, "list_all") else {}
        if breakers:
            print(BOLD("  Circuit Breakers:"))
            for name, cb in (breakers.items() if isinstance(breakers, dict) else []):
                state = cb.get_state()
                st = getattr(state, "state", state) if state else "?"
                color = GREEN if str(st) == "closed" else (RED if str(st) == "open" else YELLOW)
                print(f"    {name:<20}  {color(str(st))}")
        else:
            print(DIM("  No circuit breakers registered"))
    except Exception as e:
        print(DIM(f"  Circuit breakers: {e}"))

    # Worker pool
    try:
        from runtime.worker_pool import WorkerPool
        print(f"\n  {BOLD('Worker Pool:')} {DIM('(use programmatic API)')}")
    except Exception:
        pass

    # Task store
    try:
        from core.runtime.task_persistence import TaskStore
        store = TaskStore()
        stats = store.stats()
        print(f"\n  {BOLD('Task Store:')}")
        for k, v in stats.items():
            print(f"    {k:<18} {v}")
    except Exception as e:
        print(DIM(f"  Task store: {e}"))

    # Graceful shutdown state
    try:
        from runtime.graceful_shutdown import GracefulShutdown
        gs = GracefulShutdown.instance() if hasattr(GracefulShutdown, "instance") else None
        if gs:
            shutting = gs.is_shutting_down
            print(f"\n  {BOLD('Graceful Shutdown:')} {'🛑 shutting down' if shutting else GREEN('idle')}")
    except Exception:
        pass

    print()
    return 0


def cmd_telemetry(args) -> int:
    """sentinelops telemetry [--metrics] [--traces] [--export FILE]

    OpenTelemetry observability status — show Prometheus metrics, OTLP trace
    endpoint configuration, and export current metrics snapshot.
    """
    print(BOLD("  TythanAI Telemetry & Observability\n"))

    action = getattr(args, "action", "status")

    if action == "metrics":
        try:
            from telemetry.prometheus_metrics import PrometheusMetrics
            pm = PrometheusMetrics()
            rendered = pm.render()
            print(rendered[:4000])
            if getattr(args, "export_path", None):
                Path(args.export_path).write_text(rendered)
                print(GREEN(f"💾  Metrics exported: {args.export_path}"))
        except Exception as e:
            print(RED(f"❌  {e}"))
        return 0

    if action == "traces":
        try:
            from telemetry.otel_setup import setup_tracing, get_tracer
            print(BLUE("  OpenTelemetry Trace Configuration"))
            otlp = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "(not set)")
            svc  = os.getenv("OTEL_SERVICE_NAME", "sentinelops")
            print(f"   OTLP endpoint   : {otlp}")
            print(f"   Service name    : {svc}")
            print(f"   SDK             : opentelemetry-sdk")
        except Exception as e:
            print(DIM(f"  OTEL: {e}"))
        return 0

    # Default: full telemetry status
    try:
        from telemetry.prometheus_metrics import PrometheusMetrics
        pm = PrometheusMetrics()
        print(f"  {BOLD('Prometheus metrics:')} {GREEN('enabled')}")
        print(DIM("   Run: sentinelops telemetry metrics  to view current snapshot"))
    except Exception as e:
        print(f"  {BOLD('Prometheus metrics:')} {RED(str(e))}")

    try:
        from telemetry.otel_setup import setup_tracing
        otlp = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
        if otlp:
            print(f"  {BOLD('OTLP traces:')}      {GREEN('enabled')}  → {otlp}")
        else:
            print(f"  {BOLD('OTLP traces:')}      {DIM('disabled (set OTEL_EXPORTER_OTLP_ENDPOINT)')}")
    except Exception:
        pass

    try:
        from telemetry.trace_context import TraceContext
        print(f"  {BOLD('Trace context:')}    {GREEN('available')}")
    except Exception:
        pass

    print(DIM("\n  Subcommands: metrics | traces"))
    print()
    return 0


def cmd_ci(args) -> int:
    """sentinelops ci [--type github|gitlab|pre-commit] [--path .] [--min-severity MEDIUM]

    Generate CI/CD integration files for TythanAI scanning.
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
# ENTERPRISE MODULE COMMANDS  (Phase 14 additions)
# ══════════════════════════════════════════════════════════════════════════════

def cmd_mitre(args) -> int:
    """sentinelops mitre <findings.json> [--format json|text]
    Map findings to MITRE ATT&CK techniques and tactics.
    """
    from core.mitre.mitre_mapper import MITREMapper

    findings_file = getattr(args, "findings", "findings.json")
    fmt           = getattr(args, "format", "text")

    try:
        with open(findings_file) as fh:
            findings = json.load(fh)
        if isinstance(findings, dict):
            findings = findings.get("findings", [])
    except FileNotFoundError:
        print(RED(f"✗  File not found: {findings_file}"))
        return 1
    except json.JSONDecodeError as exc:
        print(RED(f"✗  Invalid JSON: {exc}"))
        return 1

    mapper  = MITREMapper()
    results = mapper.enrich(findings)

    if fmt == "json":
        print(json.dumps(results, indent=2))
    else:
        report = mapper.report(findings)
        print(report)

    return 0


def cmd_stride(args) -> int:
    """sentinelops stride <findings.json> [--format json|text]
    Classify findings according to the STRIDE threat model.
    """
    from core.threat_model.stride_analyzer import STRIDEAnalyzer

    findings_file = getattr(args, "findings", "findings.json")
    fmt           = getattr(args, "format", "text")

    try:
        with open(findings_file) as fh:
            findings = json.load(fh)
        if isinstance(findings, dict):
            findings = findings.get("findings", [])
    except FileNotFoundError:
        print(RED(f"✗  File not found: {findings_file}"))
        return 1
    except json.JSONDecodeError as exc:
        print(RED(f"✗  Invalid JSON: {exc}"))
        return 1

    analyzer = STRIDEAnalyzer()
    print(analyzer.generate_report(findings, fmt=fmt))
    return 0


def cmd_fuzz(args) -> int:
    """sentinelops fuzz <path> [--format json|text]
    Smart contract fuzzer — boundary-value and reentrancy path analysis.
    Supports TON FunC/Tact, EVM Solidity/Vyper, Move, Solana.
    """
    from scanners.fuzzer.contract_fuzzer import ContractFuzzer

    path = str(Path(getattr(args, "path", ".")).resolve())
    fmt  = getattr(args, "format", "text")

    fuzzer = ContractFuzzer()

    if os.path.isfile(path):
        raw = fuzzer.fuzz_file(path)
    else:
        raw = []
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if any(fname.endswith(ext) for ext in (".sol", ".vy", ".fc", ".tact", ".move", ".rs")):
                    raw.extend(fuzzer.fuzz_file(os.path.join(root, fname)))

    findings = [f.to_dict() if hasattr(f, "to_dict") else f for f in raw]

    if fmt == "json":
        print(json.dumps(findings, indent=2))
        return 0

    if not findings:
        print(GREEN("✅  No fuzzing vulnerabilities detected."))
        return 0

    crits = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
    highs = sum(1 for f in findings if f.get("severity", "").lower() == "high")
    print(BOLD(f"\n🔬  Contract Fuzzer — {len(findings)} issue(s) found  "
               f"({crits} critical, {highs} high)\n"))
    for f in findings:
        sev  = f.get("severity", "medium").upper()
        col  = _SEV_COLOR.get(sev, lambda t: t)
        fid  = f.get("rule_id", "FUZZ")
        loc  = f"{f.get('file','')}"
        if f.get("line"):
            loc += f":{f['line']}"
        print(f"  {col(f'[{sev}]')}  {BOLD(fid)}  {loc}")
        print(f"    {f.get('title', f.get('message', ''))}")
        if f.get("attack_vector"):
            print(DIM(f"    Vector: {f['attack_vector']}"))
        if f.get("input_values"):
            print(DIM(f"    Boundary inputs: {f['input_values'][:3]}"))
    return 1 if crits or highs else 0


def cmd_entropy_scan(args) -> int:
    """sentinelops entropy-scan <path> [--format json|text] [--threshold FLOAT]
    Shannon entropy secret scanner — detects high-entropy strings (potential secrets)
    that evade regex-only detectors.
    """
    from scanners.secret_scanner.entropy_analyzer import EntropyAnalyzer

    path      = str(Path(getattr(args, "path", ".")).resolve())
    fmt       = getattr(args, "format", "text")
    threshold = float(getattr(args, "threshold", 0.0) or 0.0)

    kwargs = {}
    if threshold:
        kwargs["base64_threshold"] = threshold
        kwargs["hex_threshold"]    = threshold
        kwargs["general_threshold"]= threshold

    analyzer = EntropyAnalyzer(**kwargs)

    if os.path.isfile(path):
        findings = analyzer.scan_file(path)
    else:
        findings = analyzer.scan_directory(path)

    if fmt == "json":
        print(json.dumps([f.to_dict() if hasattr(f, "to_dict") else f for f in findings], indent=2))
        return 0

    print(analyzer.generate_report(findings))
    return 1 if any(
        (f.severity if isinstance(f, object) and hasattr(f, "severity") else f.get("severity","")) in ("high","critical")
        for f in findings
    ) else 0


def cmd_attack_chain(args) -> int:
    """sentinelops attack-chain <findings.json> [--format mermaid|dot|json|text]
    Build and visualize multi-step attack chains from findings.
    """
    from core.attack_graph.attack_chain import AttackChainBuilder

    findings_file = getattr(args, "findings", "findings.json")
    fmt           = getattr(args, "format", "text")
    save          = getattr(args, "save", None)

    try:
        with open(findings_file) as fh:
            findings = json.load(fh)
        if isinstance(findings, dict):
            findings = findings.get("findings", [])
    except FileNotFoundError:
        print(RED(f"✗  File not found: {findings_file}"))
        return 1

    builder = AttackChainBuilder()
    graph   = builder.build(findings)

    if fmt == "mermaid":
        output = builder.to_mermaid(graph)
    elif fmt == "dot":
        output = builder.to_dot(graph)
    elif fmt == "json":
        output = builder.generate_report(findings, fmt="json")
    else:
        output = builder.generate_report(findings, fmt="text")

    if save:
        with open(save, "w") as fh:
            fh.write(output)
        print(GREEN(f"✅  Attack chain saved: {save}"))
    else:
        print(output)

    return 0


def cmd_dep_confusion(args) -> int:
    """sentinelops dep-confusion <path> [--format json|text]
    Dependency confusion & namespace squatting detector.
    Checks package.json, requirements.txt, go.mod, Cargo.toml, pom.xml.
    """
    from scanners.dependency_confusion import DependencyConfusionScanner

    path = str(Path(getattr(args, "path", ".")).resolve())
    fmt  = getattr(args, "format", "text")

    scanner  = DependencyConfusionScanner()
    findings = scanner.scan_directory(path)

    if fmt == "json":
        out = [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]
        print(json.dumps(out, indent=2))
        return 0

    if not findings:
        print(GREEN("✅  No dependency confusion risks detected."))
        return 0

    crits = sum(1 for f in findings if (f.severity if hasattr(f, "severity") else f.get("severity","")).lower() in ("critical","high"))
    print(BOLD(f"\n📦  Dependency Confusion Scan — {len(findings)} risk(s)  ({crits} critical/high)\n"))
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else f
        sev = d.get("severity","medium").upper()
        col = _SEV_COLOR.get(sev, lambda t: t)
        print(f"  {col(f'[{sev}]')}  {BOLD(d.get('package','?'))}  →  {d.get('file','')}")
        print(f"    {d.get('title', d.get('message',''))}")
    return 1 if crits else 0


def cmd_priority(args) -> int:
    """sentinelops priority <findings.json> [--format json|text] [--capacity DAYS]
    Risk-adjusted remediation prioritizer + sprint planner.
    """
    from core.priority.remediation_ranker import RemediationRanker

    findings_file = getattr(args, "findings", "findings.json")
    fmt           = getattr(args, "format", "text")
    capacity      = float(getattr(args, "capacity", 5) or 5)

    try:
        with open(findings_file) as fh:
            findings = json.load(fh)
        if isinstance(findings, dict):
            findings = findings.get("findings", [])
    except FileNotFoundError:
        print(RED(f"✗  File not found: {findings_file}"))
        return 1

    ranker = RemediationRanker(sprint_capacity_days=capacity)
    print(ranker.generate_report(findings, fmt=fmt))
    return 0


def cmd_policy(args) -> int:
    """sentinelops policy <findings.json> [--gate FILE] [--format json|text]
    Evaluate findings against Policy-as-Code security gate.
    Exits 1 if gate fails (for CI/CD integration).
    """
    from core.policy.policy_engine import PolicyEngine

    findings_file = getattr(args, "findings", "findings.json")
    gate_file     = getattr(args, "gate", None)
    fmt           = getattr(args, "format", "text")
    create_eg     = getattr(args, "create_example", False)

    if create_eg:
        engine  = PolicyEngine()
        example = engine.create_example_policy()
        dest    = "example_gate.yaml"
        import yaml as _yaml
        with open(dest, "w") as fh:
            _yaml.dump(example, fh, default_flow_style=False)
        print(GREEN(f"✅  Example policy gate written: {dest}"))
        return 0

    try:
        with open(findings_file) as fh:
            findings = json.load(fh)
        if isinstance(findings, dict):
            findings = findings.get("findings", [])
    except FileNotFoundError:
        print(RED(f"✗  File not found: {findings_file}"))
        return 1

    engine = PolicyEngine()

    if gate_file:
        engine.load_policies(gate_file)
    else:
        default = Path(__file__).parent / "policies" / "default_gate.yaml"
        if default.exists():
            engine.load_policies(str(default))

    result = engine.evaluate(findings)
    report = engine.generate_gate_report(result, fmt=fmt)

    if fmt == "json":
        print(report)
    else:
        status_col = GREEN if result.gate_status == "PASS" else (
            YELLOW if result.gate_status == "WARN" else RED
        )
        print(report)
        print(status_col(f"\n  Gate status: {result.gate_status}"))

    return 0 if result.gate_status in ("PASS", "WARN") else 1


def cmd_pr_comment(args) -> int:
    """sentinelops pr-comment <findings.json> --platform github|gitlab
                              --token TOKEN --owner ORG --repo REPO --pr NUMBER
    Post inline security findings as PR review comments (GitHub / GitLab).
    """
    from integrations.pr_commenter import PRCommenter

    findings_file = getattr(args, "findings", "findings.json")
    platform      = getattr(args, "platform", "github")
    token         = getattr(args, "token", "") or os.getenv("GITHUB_TOKEN", "") or os.getenv("GITLAB_TOKEN", "")
    owner         = getattr(args, "owner", "")
    repo          = getattr(args, "repo", "")
    pr_number     = int(getattr(args, "pr", 0) or 0)
    dry_run       = getattr(args, "dry_run", False)

    if not token:
        print(RED("✗  No token provided. Set GITHUB_TOKEN / GITLAB_TOKEN or use --token."))
        return 1

    try:
        with open(findings_file) as fh:
            findings = json.load(fh)
        if isinstance(findings, dict):
            findings = findings.get("findings", [])
    except FileNotFoundError:
        print(RED(f"✗  File not found: {findings_file}"))
        return 1

    commenter = PRCommenter(
        platform=platform,
        token=token,
        owner=owner,
        repo=repo,
        project_id=f"{owner}/{repo}",
    )

    if dry_run:
        print(DIM("Dry-run mode — showing what would be posted:\n"))
        for f in findings[:5]:
            print(commenter.format_comment(f))
        return 0

    stats = commenter.post_findings(pr_number, findings)
    print(GREEN(f"✅  Posted {stats.get('posted', 0)} inline comments"))
    if stats.get("skipped_off_diff"):
        print(DIM(f"   Skipped {stats['skipped_off_diff']} findings not in diff"))
    if stats.get("errors"):
        print(YELLOW(f"   {stats['errors']} error(s) — check token/permissions"))
    return 0 if not stats.get("errors") else 1


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    _print_banner()

    parser = argparse.ArgumentParser(
        prog="sentinelops",
        description="TythanAI — Multi-Chain Web3 + AppSec Security Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  sentinelops scan .                         # full SAST scan (Python/JS/C/C++)
  sentinelops scan --incremental .           # only changed files (fast)
  sentinelops deps .                         # live CVE scan via OSV.dev
  sentinelops deps --offline .               # offline CVE scan (static DB)
  sentinelops iac .                          # Docker/Terraform/Ansible/Helm/CFN scan
  sentinelops container nginx:1.21.0        # container image CVE scan
  sentinelops container ./Dockerfile        # scan Dockerfile base images
  sentinelops sbom . --format spdx         # generate SPDX 2.3 SBOM
  sentinelops sbom . --format cyclonedx    # generate CycloneDX 1.4 SBOM
  sentinelops compliance findings.json     # PCI-DSS/SOC2/HIPAA/NIST gap report
  sentinelops fix-deps . --apply           # patch manifests (with .ghost.bak backup)
  sentinelops suppress . --create-example  # scaffold .ghostignore
  sentinelops enrich findings.json         # add EPSS scores + CISA KEV flags
  sentinelops ci --type github .           # generate GitHub Actions workflow

  # ── Blockchain / Web3 ──────────────────────────────────────────────────────
  sentinelops ton ./contracts/             # TON bug bounty scan + reports
  sentinelops ton ./contracts/ --elite    # TON + gas + state-machine + attack surface
  sentinelops ton-gas ./contracts/        # gas consumption risk only
  sentinelops ton-state ./contracts/      # state machine violation analysis
  sentinelops ton-surface ./contracts/    # attack surface mapping (risk score 0-100)
  sentinelops evm ./contracts/            # EVM/Solidity security scan (16 rules)
  sentinelops solana ./program/           # Solana/Anchor security scan (11 rules)
  sentinelops cosmos ./contracts/         # CosmWasm security scan (8 rules)
  sentinelops polkadot ./lib.rs           # Polkadot/ink! security scan (7 rules)
  sentinelops move ./sources/             # Move language security scan (8 rules)
  sentinelops web3 ./                     # All Web3 chains in one pass
  sentinelops web3 ./ --report            # Multi-chain + Immunefi-style report

  # ── Advanced Analysis ──────────────────────────────────────────────────────
  sentinelops ast ./src/                  # AST deep analysis (taint, eval, SQL inject)
  sentinelops openapi ./api.yaml          # OWASP API Top 10 scan for OpenAPI/Swagger
  sentinelops semgrep . --rules auto      # Semgrep-powered scan with Ghost rule packs
  sentinelops llm-scan findings.json     # LLM enrichment: CVSS, exploit scenario, fix

  # ── Enterprise / Cloud ─────────────────────────────────────────────────────
  sentinelops cloud tenants list          # list cloud tenants
  sentinelops cloud tenants create --name ACME --plan pro
  sentinelops cloud keys create --org ORG_ID --name CI
  sentinelops cloud usage --org ORG_ID    # monthly usage/billing report
  sentinelops supervisor                  # runtime supervisor + circuit breakers
  sentinelops telemetry metrics           # Prometheus metrics snapshot
  sentinelops telemetry traces            # OpenTelemetry trace config

  # ── Analysis & Tuning ──────────────────────────────────────────────────────
  sentinelops scan . --tune               # scan + apply rule_tuning.yaml overrides
  sentinelops tune findings.json         # apply rule tuner to existing findings
  sentinelops tune --create-example      # scaffold rule_tuning.yaml
  sentinelops reachability findings.json  # is vulnerable code actually called?
  sentinelops tasks --stats              # view SQLite task history
  sentinelops k8s ./k8s/manifests/       # Kubernetes CIS audit
  sentinelops fix findings.json --apply  # apply code-level fixes (with backup)
  sentinelops serve --port 8000          # start API server + WebSocket live feed
  sentinelops status                     # component health check
  sentinelops report findings.json       # generate Immunefi report

  # ── Phase 14: Enterprise Intelligence ─────────────────────────────────────
  sentinelops mitre findings.json        # map findings to MITRE ATT&CK techniques
  sentinelops stride findings.json       # STRIDE threat model classification
  sentinelops fuzz ./contracts/          # smart contract boundary-value fuzzer
  sentinelops entropy-scan ./src/        # Shannon entropy secret scanner
  sentinelops attack-chain findings.json --format mermaid  # Mermaid attack chain diagram
  sentinelops dep-confusion .            # dependency confusion / namespace squatting
  sentinelops priority findings.json --capacity 5  # sprint-ready remediation plan
  sentinelops policy findings.json       # Policy-as-Code CI/CD security gate
  sentinelops policy findings.json --create-example  # scaffold example gate YAML
  sentinelops pr-comment findings.json --platform github --owner ORG --repo REPO --pr 42
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

    # ── Web3 / Multi-chain scanners ───────────────────────────────────────────

    # evm — EVM/Solidity scanner
    p_evm = sub.add_parser("evm", help="EVM/Solidity smart contract security scan (16 rules)")
    p_evm.add_argument("path", nargs="?", default=".")
    p_evm.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_evm.add_argument("--min-severity", default="MEDIUM",
                       choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p_evm.add_argument("--save", metavar="FILE")
    p_evm.add_argument("--no-fail", action="store_true")

    # solana — Solana/Anchor scanner
    p_sol = sub.add_parser("solana", help="Solana/Anchor smart contract security scan (11 rules)")
    p_sol.add_argument("path", nargs="?", default=".")
    p_sol.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_sol.add_argument("--min-severity", default="MEDIUM",
                       choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p_sol.add_argument("--save", metavar="FILE")
    p_sol.add_argument("--no-fail", action="store_true")

    # cosmos — CosmWasm scanner
    p_cos = sub.add_parser("cosmos", help="CosmWasm/Cosmos smart contract security scan (8 rules)")
    p_cos.add_argument("path", nargs="?", default=".")
    p_cos.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_cos.add_argument("--min-severity", default="MEDIUM",
                       choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p_cos.add_argument("--save", metavar="FILE")
    p_cos.add_argument("--no-fail", action="store_true")

    # polkadot — Polkadot/ink! scanner
    p_dot = sub.add_parser("polkadot", help="Polkadot/ink! smart contract security scan (7 rules)")
    p_dot.add_argument("path", nargs="?", default=".")
    p_dot.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_dot.add_argument("--min-severity", default="MEDIUM",
                       choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p_dot.add_argument("--save", metavar="FILE")
    p_dot.add_argument("--no-fail", action="store_true")

    # move — Move language scanner
    p_mov = sub.add_parser("move", help="Move language smart contract security scan (8 rules)")
    p_mov.add_argument("path", nargs="?", default=".")
    p_mov.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_mov.add_argument("--min-severity", default="MEDIUM",
                       choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p_mov.add_argument("--save", metavar="FILE")
    p_mov.add_argument("--no-fail", action="store_true")

    # web3 — combined multi-chain scan
    p_web3 = sub.add_parser("web3",
                             help="Combined multi-chain Web3 scan (TON+EVM+Solana+Cosmos+Polkadot+Move)")
    p_web3.add_argument("path", nargs="?", default=".")
    p_web3.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_web3.add_argument("--min-severity", default="MEDIUM",
                        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p_web3.add_argument("--save", metavar="FILE")
    p_web3.add_argument("--no-fail", action="store_true")
    p_web3.add_argument("--report", action="store_true",
                        help="Generate Immunefi-style report after scan")
    p_web3.add_argument("--report-dir", default="./sentinelops_reports/web3")

    # ── AST deep analysis ─────────────────────────────────────────────────────
    p_ast = sub.add_parser("ast", help="AST-based deep analysis (SQL injection, eval, taint flow, ...)")
    p_ast.add_argument("path", nargs="?", default=".")
    p_ast.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_ast.add_argument("--min-severity", default="MEDIUM",
                       choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p_ast.add_argument("--save", metavar="FILE")
    p_ast.add_argument("--no-fail", action="store_true")

    # ── OpenAPI security scan ─────────────────────────────────────────────────
    p_oapi = sub.add_parser("openapi", help="OWASP API Security Top 10 scan for OpenAPI/Swagger specs")
    p_oapi.add_argument("spec", nargs="?", default=".",
                        help="OpenAPI spec file, URL, or directory to search")
    p_oapi.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_oapi.add_argument("--min-severity", default="LOW",
                        choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p_oapi.add_argument("--save", metavar="FILE")
    p_oapi.add_argument("--no-fail", action="store_true")

    # ── Semgrep integration ───────────────────────────────────────────────────
    p_sem = sub.add_parser("semgrep", help="Semgrep-powered scan with TythanAI rule packs")
    p_sem.add_argument("path", nargs="?", default=".")
    p_sem.add_argument("--rules", default="auto",
                       help="Semgrep ruleset (default: auto)")
    p_sem.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_sem.add_argument("--min-severity", default="MEDIUM",
                       choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p_sem.add_argument("--timeout", type=int, default=120, help="Timeout in seconds")
    p_sem.add_argument("--save", metavar="FILE")
    p_sem.add_argument("--no-fail", action="store_true")

    # ── LLM deep analysis ─────────────────────────────────────────────────────
    p_llm = sub.add_parser("llm-scan",
                            help="LLM-powered enrichment: CVSS, exploit scenario, code fix")
    p_llm.add_argument("findings", nargs="?", default="findings.json")
    p_llm.add_argument("--min-severity", default="HIGH",
                       choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    p_llm.add_argument("--max-findings", type=int, default=20, dest="max_findings")
    p_llm.add_argument("--output", "-o", choices=["table", "json"], default="table")
    p_llm.add_argument("--save", metavar="FILE")

    # ── Cloud management ──────────────────────────────────────────────────────
    p_cloud = sub.add_parser("cloud", help="Multi-tenant cloud management (tenants, keys, usage)")
    p_cloud.add_argument("cloud_sub", nargs="?", default="",
                         choices=["tenants", "keys", "usage", ""],
                         help="Subcommand: tenants | keys | usage")
    p_cloud.add_argument("cloud_action", nargs="?", default="",
                         help="Action: list | create | quota | revoke")
    p_cloud.add_argument("--name", metavar="NAME", help="Tenant/key name")
    p_cloud.add_argument("--plan", default="free",
                         choices=["free", "starter", "pro", "enterprise"])
    p_cloud.add_argument("--org", metavar="ORG_ID", help="Organisation ID")
    p_cloud.add_argument("--key-id", dest="key_id", metavar="KEY_ID")
    p_cloud.add_argument("--scopes", nargs="*", default=["scan", "read"])

    # ── Runtime supervisor ────────────────────────────────────────────────────
    p_sup = sub.add_parser("supervisor",
                            help="Runtime supervisor status (circuit breakers, tasks, workers)")
    p_sup.add_argument("action", nargs="?", default="status",
                       choices=["status", "tasks"],
                       help="Action: status | tasks (default: status)")

    # ── Telemetry / observability ─────────────────────────────────────────────
    p_tel = sub.add_parser("telemetry",
                            help="OpenTelemetry + Prometheus observability status")
    p_tel.add_argument("action", nargs="?", default="status",
                       choices=["status", "metrics", "traces"],
                       help="Action: status | metrics | traces (default: status)")
    p_tel.add_argument("--export", dest="export_path", metavar="FILE",
                       help="Export metrics to file")

    # ── MITRE ATT&CK mapper ───────────────────────────────────────────────────
    p_mitre = sub.add_parser("mitre", help="Map findings to MITRE ATT&CK techniques")
    p_mitre.add_argument("findings", nargs="?", default="findings.json")
    p_mitre.add_argument("--format", choices=["text", "json"], default="text")

    # ── STRIDE threat model ───────────────────────────────────────────────────
    p_stride = sub.add_parser("stride", help="Classify findings by STRIDE threat category")
    p_stride.add_argument("findings", nargs="?", default="findings.json")
    p_stride.add_argument("--format", choices=["text", "json"], default="text")

    # ── Smart contract fuzzer ─────────────────────────────────────────────────
    p_fuzz = sub.add_parser("fuzz", help="Boundary-value + reentrancy fuzzer for smart contracts")
    p_fuzz.add_argument("path", nargs="?", default=".")
    p_fuzz.add_argument("--format", choices=["text", "json"], default="text")

    # ── Shannon entropy secret scanner ───────────────────────────────────────
    p_entropy = sub.add_parser("entropy-scan", help="High-entropy string / secret detector")
    p_entropy.add_argument("path", nargs="?", default=".")
    p_entropy.add_argument("--format", choices=["text", "json"], default="text")
    p_entropy.add_argument("--threshold", type=float, default=0.0,
                           help="Custom entropy threshold (default: charset-specific)")

    # ── Attack chain visualizer ───────────────────────────────────────────────
    p_chain = sub.add_parser("attack-chain", help="Build multi-step attack chain graph from findings")
    p_chain.add_argument("findings", nargs="?", default="findings.json")
    p_chain.add_argument("--format", choices=["text", "json", "mermaid", "dot"], default="text")
    p_chain.add_argument("--save", metavar="FILE", help="Save output to file")

    # ── Dependency confusion detector ─────────────────────────────────────────
    p_depconf = sub.add_parser("dep-confusion", help="Dependency confusion / namespace squatting detector")
    p_depconf.add_argument("path", nargs="?", default=".")
    p_depconf.add_argument("--format", choices=["text", "json"], default="text")

    # ── Remediation priority ranker ───────────────────────────────────────────
    p_prio = sub.add_parser("priority", help="Risk-adjusted remediation priority + sprint planner")
    p_prio.add_argument("findings", nargs="?", default="findings.json")
    p_prio.add_argument("--format", choices=["text", "json"], default="text")
    p_prio.add_argument("--capacity", type=float, default=5.0,
                        help="Sprint capacity in person-days (default: 5.0)")

    # ── Policy-as-Code gate ───────────────────────────────────────────────────
    p_pol = sub.add_parser("policy", help="Evaluate findings against Policy-as-Code security gate")
    p_pol.add_argument("findings", nargs="?", default="findings.json")
    p_pol.add_argument("--gate", metavar="FILE", help="Custom policy gate YAML (default: policies/default_gate.yaml)")
    p_pol.add_argument("--format", choices=["text", "json"], default="text")
    p_pol.add_argument("--create-example", dest="create_example", action="store_true",
                       help="Write example_gate.yaml and exit")

    # ── PR inline comment poster ──────────────────────────────────────────────
    p_prc = sub.add_parser("pr-comment", help="Post findings as inline PR review comments (GitHub/GitLab)")
    p_prc.add_argument("findings", nargs="?", default="findings.json")
    p_prc.add_argument("--platform", choices=["github", "gitlab"], default="github")
    p_prc.add_argument("--token", metavar="TOKEN", default="", help="API token (or GITHUB_TOKEN / GITLAB_TOKEN env var)")
    p_prc.add_argument("--owner", metavar="OWNER", default="", help="GitHub org/user or GitLab namespace")
    p_prc.add_argument("--repo",  metavar="REPO",  default="", help="Repository name")
    p_prc.add_argument("--pr",    metavar="NUMBER", type=int, default=0, help="PR / MR number")
    p_prc.add_argument("--dry-run", dest="dry_run", action="store_true",
                       help="Print what would be posted without making API calls")

    # ── Phase 15: Symbolic execution ─────────────────────────────────────────
    p_sym = sub.add_parser("symbolic", help="Symbolic execution engine for EVM/Solidity contracts")
    p_sym.add_argument("path", nargs="?", default=".",
                       help="Solidity file / directory or hex bytecode file")
    p_sym.add_argument("--format", choices=["text", "json"], default="text")
    p_sym.add_argument("--depth", type=int, default=50, metavar="N",
                       help="Max path exploration depth (default: 50)")
    p_sym.add_argument("--tool", choices=["slither", "mythril", "native", "auto"], default="auto",
                       help="Preferred external tool (auto = use best available)")

    # ── Phase 15: Taint analysis ──────────────────────────────────────────────
    p_taint = sub.add_parser("taint", help="Taint analysis — track attacker-controlled data to dangerous sinks")
    p_taint.add_argument("path", nargs="?", default=".",
                         help="File or directory to analyze")
    p_taint.add_argument("--lang", choices=["auto", "cpp", "rust", "go", "solidity", "python"],
                          default="auto", help="Source language (default: auto-detect)")
    p_taint.add_argument("--format", choices=["text", "json"], default="text")
    p_taint.add_argument("--min-confidence", type=float, default=0.3, dest="min_confidence",
                          metavar="FLOAT", help="Minimum confidence threshold 0.0–1.0 (default: 0.3)")

    # ── Phase 15: Language-specific analyzers ─────────────────────────────────
    p_lang = sub.add_parser("lang-scan", help="Language-specific security scan (Solidity/Rust/Go/C++)")
    p_lang.add_argument("path", nargs="?", default=".",
                        help="File or directory to analyze")
    p_lang.add_argument("--lang", choices=["auto", "solidity", "rust", "go", "cpp"],
                         default="auto", help="Force language (default: auto-detect from extension)")
    p_lang.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    p_lang.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                         default="LOW", metavar="LEVEL",
                         help="Minimum severity to report (default: LOW)")

    # ── Phase 15: Formal verification ────────────────────────────────────────
    p_formal = sub.add_parser("formal", help="Formal property verification — invariants, safety, liveness")
    p_formal.add_argument("path", nargs="?", default=".",
                          help="Solidity file or directory")
    p_formal.add_argument("--invariants", metavar="FILE",
                           help="YAML file with custom invariants to verify")
    p_formal.add_argument("--depth", type=int, default=10, metavar="N",
                           help="Bounded model checking depth (default: 10)")
    p_formal.add_argument("--tool", choices=["halmos", "native", "auto"], default="auto")
    p_formal.add_argument("--format", choices=["text", "json"], default="text")

    # ── Phase 15: Cryptographic analysis ─────────────────────────────────────
    p_crypto = sub.add_parser("crypto-audit", help="Cryptographic vulnerability audit (RNG, timing, algorithms, keys)")
    p_crypto.add_argument("path", nargs="?", default=".",
                          help="File or directory to audit")
    p_crypto.add_argument("--format", choices=["text", "json"], default="text")
    p_crypto.add_argument("--lang", choices=["auto", "python", "go", "cpp", "rust", "solidity"],
                           default="auto", help="Source language (default: auto)")

    # ── Phase 15: P2P / Consensus simulator ──────────────────────────────────
    p_p2p = sub.add_parser("p2p-sim", help="P2P network & consensus attack simulator (eclipse, sybil, selfish mining)")
    p_p2p.add_argument("attack", nargs="?", default="all",
                       choices=["all", "eclipse", "sybil", "selfish-mining", "nothing-at-stake",
                                "routing", "consensus"],
                       help="Attack type to simulate (default: all)")
    p_p2p.add_argument("--network-size", type=int, default=100, dest="network_size",
                        metavar="N", help="Total network node count (default: 100)")
    p_p2p.add_argument("--attacker-fraction", type=float, default=0.3, dest="attacker_fraction",
                        metavar="F", help="Attacker resource fraction 0.0–1.0 (default: 0.30)")
    p_p2p.add_argument("--consensus", choices=["pbft", "tendermint", "ton_bft", "avalanche",
                                                "nakamoto", "casper_ffg", "hotstuff"],
                        default="ton_bft", help="Consensus protocol (default: ton_bft)")
    p_p2p.add_argument("--routing", choices=["kademlia", "gossip", "structured_overlay"],
                        default="kademlia", help="Routing protocol (default: kademlia)")
    p_p2p.add_argument("--format", choices=["text", "json"], default="text")

    # ── TythanAI Phase 16: Advanced Intelligence & Hunting ───────────────────
    p_th = sub.add_parser("threat-hunt", help="Hypothesis-driven threat hunting from findings JSON")
    p_th.add_argument("findings", nargs="?", default="findings.json", help="Path to findings JSON")
    p_th.add_argument("--root", default=".", help="Project root for code analysis")
    p_th.add_argument("--save", metavar="FILE", help="Save hunting report to file")
    p_th.add_argument("--format", choices=["text", "json", "markdown"], default="text")

    p_irp = sub.add_parser("ir-playbook", help="Generate IR playbook for a finding/findings JSON")
    p_irp.add_argument("findings", nargs="?", default="findings.json", help="Path to findings JSON")
    p_irp.add_argument("--scan-id", metavar="ID", dest="scan_id", help="Scan ID for playbook naming")
    p_irp.add_argument("--risk-score", type=float, default=80.0, dest="risk_score")
    p_irp.add_argument("--out-dir", default="reports/ir_playbooks", dest="out_dir")

    p_pv = sub.add_parser("patch-validate", help="Compare pre/post-patch findings to verify closure")
    p_pv.add_argument("baseline", help="Path to baseline findings JSON (before patch)")
    p_pv.add_argument("current", help="Path to current findings JSON (after patch)")
    p_pv.add_argument("--root", default=".", help="Project root for taint re-check")
    p_pv.add_argument("--save", metavar="FILE", help="Save validation report to file")
    p_pv.add_argument("--format", choices=["text", "json", "markdown"], default="text")

    p_ti = sub.add_parser("threat-intel", help="Aggregate threat intelligence for a CVE ID")
    p_ti.add_argument("cve_id", help="CVE ID (e.g. CVE-2023-12345)")
    p_ti.add_argument("--refresh", action="store_true", help="Force cache refresh")
    p_ti.add_argument("--format", choices=["text", "json"], default="text")

    p_cal = sub.add_parser("calibrate", help="Auto-calibrate rule thresholds based on FP history")
    p_cal.add_argument("--db", default=None, metavar="PATH", help="SQLite DB path (default: auto)")
    p_cal.add_argument("--out", default="config/calibration.json", help="Output config path")
    p_cal.add_argument("--format", choices=["text", "json"], default="text")

    p_cr = sub.add_parser("cross-repo", help="Cross-repository/microservice taint analysis")
    p_cr.add_argument("repos", nargs="+", help="Paths to repositories/microservice directories")
    p_cr.add_argument("--save", metavar="FILE", help="Save report to file")
    p_cr.add_argument("--format", choices=["text", "json", "markdown"], default="text")

    # ── Parse (must be AFTER all sub.add_parser calls) ────────────────────────
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0

    # ── Phase 15 command handlers ─────────────────────────────────────────────

    def cmd_symbolic(args) -> int:
        """Symbolic execution engine."""
        from core.symbolic.symbolic_executor import SymbolicExecutor
        path = getattr(args, "path", ".")
        fmt  = getattr(args, "format", "text")
        depth = getattr(args, "depth", 50)
        print(f"[symbolic] Analyzing {path} (depth={depth}) …")
        executor = SymbolicExecutor()
        result = executor.analyze_file(path) if path.endswith((".sol", ".vy", ".hex")) \
                 else executor.analyze_solidity(path)
        if fmt == "json":
            import json
            print(json.dumps({
                "paths_explored": result.paths_explored,
                "tool_used": result.tool_used,
                "execution_time": round(result.execution_time, 3),
                "vulnerabilities": [
                    {"type": v.vuln_type, "severity": v.severity,
                     "description": v.description, "path": v.path}
                    for v in result.vulnerabilities
                ],
            }, indent=2))
        else:
            print(executor.generate_report(result))
        return 0

    def cmd_taint(args) -> int:
        """Taint analysis."""
        from core.taint.taint_engine import TaintEngine
        path   = getattr(args, "path", ".")
        lang   = getattr(args, "lang", "auto")
        fmt    = getattr(args, "format", "text")
        min_c  = getattr(args, "min_confidence", 0.3)
        print(f"[taint] Tracing data flows in {path} (lang={lang}) …")
        engine = TaintEngine(language=lang)
        report = engine.analyze(path)
        # Filter by min confidence
        report.flows = [f for f in report.flows if f.confidence >= min_c]
        if fmt == "json":
            import json
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(engine.generate_report(report))
        return 1 if any(f.sink.severity in ("CRITICAL", "HIGH") for f in report.flows) else 0

    def cmd_lang_scan(args) -> int:
        """Language-specific security scan."""
        import json as _json
        path     = getattr(args, "path", ".")
        lang     = getattr(args, "lang", "auto")
        fmt      = getattr(args, "format", "text")
        min_sev  = getattr(args, "severity", "LOW")
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        min_rank = sev_rank.get(min_sev, 0)

        # Auto-detect language from path extension
        if lang == "auto":
            from pathlib import Path as _Path
            ext = _Path(path).suffix.lower()
            lang_map = {".sol": "solidity", ".vy": "solidity", ".rs": "rust",
                        ".go": "go", ".cpp": "cpp", ".cc": "cpp", ".c": "cpp", ".h": "cpp"}
            lang = lang_map.get(ext, "cpp")  # default to cpp for dirs
            print(f"[lang-scan] Detected language: {lang}")

        from scanners.lang_analyzers import (
            SolidityAnalyzer, RustAnalyzer, GoAnalyzer, CppAnalyzer
        )
        analyzer_map = {
            "solidity": SolidityAnalyzer,
            "rust":     RustAnalyzer,
            "go":       GoAnalyzer,
            "cpp":      CppAnalyzer,
        }
        Analyzer = analyzer_map.get(lang, CppAnalyzer)
        print(f"[lang-scan] Scanning {path} with {Analyzer.__name__} …")
        result = Analyzer().analyze(path)
        findings = [f for f in result.findings if sev_rank.get(f.severity, 0) >= min_rank]

        if fmt == "json":
            print(_json.dumps({"language": result.language,
                               "files": result.files_analyzed,
                               "findings": [vars(f) for f in findings]}, indent=2))
        elif fmt == "sarif":
            sarif = result.to_sarif()
            print(_json.dumps(sarif, indent=2))
        else:
            print(f"\n{'='*65}")
            print(f"  LANG-SCAN — {result.language.upper()} — {result.files_analyzed} file(s)")
            print(f"{'='*65}")
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                cnt = result.summary.get(sev, 0)
                if cnt:
                    print(f"  {sev:<12} {cnt}")
            print()
            for f in findings:
                print(f"  [{f.severity}] {f.rule_id}: {f.title}")
                print(f"    {f.filepath}:{f.line}")
                print(f"    {f.code_snippet[:80]}")
                print(f"    Fix: {f.recommendation[:100]}")
                print()
        return 1 if any(f.severity in ("CRITICAL", "HIGH") for f in findings) else 0

    def cmd_formal(args) -> int:
        """Formal property verification."""
        import json as _json
        from core.formal.formal_verifier import FormalVerifier
        path  = getattr(args, "path", ".")
        depth = getattr(args, "depth", 10)
        fmt   = getattr(args, "format", "text")
        print(f"[formal] Verifying invariants in {path} (BMC depth={depth}) …")
        verifier = FormalVerifier()
        result = verifier.verify_invariants(path, [])
        if fmt == "json":
            print(_json.dumps({
                "verified": result.verified_properties,
                "violated": result.violated_properties,
                "tool_used": result.tool_used,
                "proof_depth": result.proof_depth,
                "findings": [
                    {"property": f.property_violated, "severity": f.severity,
                     "description": f.description,
                     "counterexample": f.counterexample}
                    for f in result.findings
                ],
            }, indent=2))
        else:
            print(verifier.generate_report(result))
        return 1 if result.violated_properties > 0 else 0

    def cmd_crypto_audit(args) -> int:
        """Cryptographic vulnerability audit."""
        import json as _json
        from core.crypto_analysis.crypto_analyzer import CryptoAnalyzer
        path = getattr(args, "path", ".")
        fmt  = getattr(args, "format", "text")
        print(f"[crypto-audit] Scanning {path} for cryptographic vulnerabilities …")
        analyzer = CryptoAnalyzer()
        report = analyzer.analyze(path)
        if fmt == "json":
            print(_json.dumps(report.to_dict(), indent=2))
        else:
            print(analyzer.generate_report(report))
        return 1 if report.risk_score >= 5.0 else 0

    def cmd_p2p_sim(args) -> int:
        """P2P / Consensus attack simulator."""
        import json as _json
        from core.consensus_sim.p2p_simulator import P2PSimulator
        attack   = getattr(args, "attack", "all")
        net_size = getattr(args, "network_size", 100)
        frac     = getattr(args, "attacker_fraction", 0.3)
        consensus = getattr(args, "consensus", "ton_bft")
        routing  = getattr(args, "routing", "kademlia")
        fmt      = getattr(args, "format", "text")

        sim = P2PSimulator(network_size=net_size)
        results = []

        if attack in ("all", "eclipse"):
            results.append(sim.simulate_eclipse_attack(
                attacker_nodes=int(frac * net_size),
                routing_table_size=8,
            ))
        if attack in ("all", "sybil"):
            results.append(sim.simulate_sybil_attack(sybil_fraction=frac))
        if attack in ("all", "selfish-mining"):
            results.append(sim.simulate_selfish_mining(attacker_hash_fraction=frac))
        if attack in ("all", "nothing-at-stake"):
            results.append(sim.simulate_nothing_at_stake())
        if attack in ("all", "routing"):
            ra = sim.analyze_routing_security(protocol=routing)
            print(f"\n[routing] Protocol: {ra.protocol}")
            for finding in ra.findings:
                print(f"  • {finding}")
        if attack in ("all", "consensus"):
            ca = sim.check_consensus_liveness(
                byzantine_fraction=frac, consensus_type=consensus
            )
            print(f"\n[consensus] {ca.consensus_type.upper()} analysis:")
            for finding in ca.findings:
                print(f"  • {finding}")

        if fmt == "json":
            print(_json.dumps([vars(r) for r in results], indent=2, default=str))
        else:
            if results:
                print(sim.generate_report(results))
        return 0

    # ── TythanAI Phase 16 command handlers ───────────────────────────────────

    def cmd_threat_hunt(args) -> int:
        """Hypothesis-driven threat hunting."""
        import json as _json
        src = getattr(args, "findings", "findings.json")
        if not Path(src).exists():
            print(RED(f"❌  File not found: {src}")); return 1
        raw = _json.loads(Path(src).read_text())
        root = Path(getattr(args, "root", ".")).resolve()
        print(BLUE(f"🔍  Threat hunting: {len(raw)} findings  root: {root}"))
        t0 = time.time()
        from backend.core.confidence import Finding
        findings = []
        for f in raw:
            try:
                findings.append(Finding(**f) if isinstance(f, dict) else f)
            except Exception:
                pass
        from backend.agents.threat_hunter import ThreatHunterAgent
        agent = ThreatHunterAgent()
        report = agent.hunt(findings, project_root=root if root.exists() else None)
        duration = time.time() - t0
        fmt = getattr(args, "format", "text")
        if fmt == "json":
            print(_json.dumps({
                "hypotheses_generated": report.hypotheses_generated,
                "hypotheses_confirmed": report.hypotheses_confirmed,
                "lotl_patterns": report.lotl_patterns,
                "results": [{"hypothesis": r.hypothesis.description, "confirmed": r.confirmed, "evidence": r.evidence} for r in report.results],
            }, indent=2))
        else:
            print(DIM(f"   Hypotheses: {report.hypotheses_generated}  Confirmed: {report.hypotheses_confirmed}  LOTL: {len(report.lotl_patterns)}  ({duration:.2f}s)"))
            for r in report.results[:10]:
                icon = GREEN("✅") if r.confirmed else DIM("○")
                print(f"  {icon}  {r.hypothesis.description[:80]}")
            if report.report_path:
                print(GREEN(f"\n💾  Report: {report.report_path}"))
        if getattr(args, "save", None):
            Path(args.save).write_text(_json.dumps({"hypotheses_generated": report.hypotheses_generated, "confirmed": report.hypotheses_confirmed}, indent=2))
        return 0

    def cmd_ir_playbook(args) -> int:
        """Generate IR playbook for critical findings."""
        import json as _json, uuid as _uuid
        src = getattr(args, "findings", "findings.json")
        if not Path(src).exists():
            print(RED(f"❌  File not found: {src}")); return 1
        raw = _json.loads(Path(src).read_text())
        scan_id = getattr(args, "scan_id", None) or str(_uuid.uuid4())[:8]
        risk_score = getattr(args, "risk_score", 80.0)
        out_dir = getattr(args, "out_dir", "reports/ir_playbooks")
        print(BLUE(f"📋  IR Playbook generation: {len(raw)} findings  scan_id: {scan_id}"))
        t0 = time.time()
        from backend.core.confidence import Finding
        from backend.agents.ir_playbook import IRPlaybookGenerator
        gen = IRPlaybookGenerator(output_dir=out_dir)
        generated = 0
        for f in raw:
            try:
                finding = Finding(**f) if isinstance(f, dict) else f
                sev = (f.get("severity", "") if isinstance(f, dict) else finding.severity) or ""
                if sev.upper() in ("CRITICAL", "HIGH") or risk_score > 60:
                    path = gen.generate_and_save(finding, risk_score=risk_score, scan_id=f"{scan_id}_{generated}")
                    if path:
                        generated += 1
                        print(GREEN(f"   ✅  {path}"))
            except Exception as e:
                print(DIM(f"   skipped: {e}"))
        duration = time.time() - t0
        print(DIM(f"\n   Generated: {generated} playbooks  ({duration:.2f}s)"))
        return 0

    def cmd_patch_validate(args) -> int:
        """Compare pre/post-patch findings."""
        import json as _json
        baseline_path = getattr(args, "baseline", None)
        current_path = getattr(args, "current", None)
        if not baseline_path or not Path(baseline_path).exists():
            print(RED("❌  baseline file required and must exist")); return 1
        if not current_path or not Path(current_path).exists():
            print(RED("❌  current file required and must exist")); return 1
        print(BLUE(f"🔄  Patch validation: {baseline_path} → {current_path}"))
        t0 = time.time()
        from backend.core.confidence import Finding
        from backend.core.patch_validator import PatchValidator
        baseline_raw = _json.loads(Path(baseline_path).read_text())
        current_raw = _json.loads(Path(current_path).read_text())
        baseline = [Finding(**f) for f in baseline_raw if isinstance(f, dict)]
        current = [Finding(**f) for f in current_raw if isinstance(f, dict)]
        validator = PatchValidator()
        root = Path(getattr(args, "root", ".")).resolve()
        report = validator.validate(baseline, current, project_root=root if root.exists() else None)
        duration = time.time() - t0
        fmt = getattr(args, "format", "text")
        if fmt == "json":
            print(report.to_json())
        elif fmt == "markdown":
            print(report.to_markdown())
        else:
            print(report.summary_line())
            print(DIM(f"   Effectiveness: {report.patch_effectiveness:.1f}%  Verdict: {report.verdict}  ({duration:.2f}s)"))
        if getattr(args, "save", None):
            Path(args.save).write_text(report.to_json())
            print(GREEN(f"💾  Saved to {args.save}"))
        return 0 if report.verdict == "APPROVED" else 1

    def cmd_threat_intel_lookup(args) -> int:
        """Aggregate threat intel for a CVE."""
        import json as _json
        cve_id = getattr(args, "cve_id", "")
        if not cve_id:
            print(RED("❌  CVE ID required")); return 1
        force = getattr(args, "refresh", False)
        print(BLUE(f"🌐  Threat intel: {cve_id}"))
        t0 = time.time()
        from backend.intelligence.threat_intel_aggregator import ThreatIntelAggregator
        agg = ThreatIntelAggregator()
        intel = agg.aggregate(cve_id, force_refresh=force)
        duration = time.time() - t0
        fmt = getattr(args, "format", "text")
        if fmt == "json":
            print(_json.dumps(intel.model_dump(), indent=2, default=str))
        else:
            kev = GREEN("YES — KEV listed") if intel.in_kev else DIM("not in KEV")
            print(f"   CVE: {intel.cve_id}")
            print(f"   KEV: {kev}")
            print(f"   EPSS: {intel.epss_score:.3f}  CVSS: {intel.cvss_score:.1f}")
            print(f"   Risk boost: +{intel.risk_score_boost:.0f}  Sources: {', '.join(intel.sources)}")
            print(DIM(f"   ({duration:.2f}s)"))
        return 0

    def cmd_calibrate(args) -> int:
        """Auto-calibrate confidence thresholds."""
        import json as _json
        db_path = getattr(args, "db", None)
        out = getattr(args, "out", "config/calibration.json")
        fmt = getattr(args, "format", "text")
        print(BLUE("⚙️   Self-calibration engine running…"))
        t0 = time.time()
        from backend.core.self_calibration import SelfCalibrationEngine
        engine = SelfCalibrationEngine(db_path=db_path, config_path=out)
        report = engine.run()
        duration = time.time() - t0
        if fmt == "json":
            print(_json.dumps(report.model_dump(), indent=2, default=str))
        else:
            print(DIM(f"   Rules analyzed: {report.total_rules_analyzed}  Adjusted: {report.rules_adjusted}  ({duration:.2f}s)"))
            for r in report.rules[:10]:
                icon = ORANGE("⚠️ ") if r.action == "raise_threshold" else (GREEN("✅") if r.action == "lower_threshold" else DIM("○"))
                print(f"   {icon}  {r.rule_id:<25}  FP rate: {r.fp_rate:.0%}  threshold: {r.current_threshold:.2f} → {r.suggested_threshold:.2f}")
            print(GREEN(f"\n💾  Config: {report.config_path}"))
        return 0

    def cmd_cross_repo(args) -> int:
        """Cross-repository taint analysis."""
        import json as _json
        repos = getattr(args, "repos", ["."])
        fmt = getattr(args, "format", "text")
        print(BLUE(f"🔗  Cross-repo taint analysis: {len(repos)} repos"))
        t0 = time.time()
        from backend.analysis.cross_repo_taint import analyze_cross_repo
        report = analyze_cross_repo(repos)
        duration = time.time() - t0
        if fmt == "json":
            print(report.to_json())
        elif fmt == "markdown":
            print(report.to_markdown())
        else:
            print(DIM(f"   Repos: {len(report.repos_analyzed)}  Taint paths: {report.total_paths}  Unsanitized: {report.unsanitized_paths}  ({duration:.2f}s)"))
            for p in report.taint_paths[:10]:
                icon = RED("CRITICAL") if p.severity == "CRITICAL" else ORANGE("HIGH") if p.severity == "HIGH" else YELLOW("MEDIUM")
                print(f"   [{icon}]  {p.source_service} → {p.sink_service}  via {p.transmission}  {'(sanitized)' if p.sanitized else '(UNSANITIZED)'}")
        if getattr(args, "save", None):
            Path(args.save).write_text(report.to_json())
            print(GREEN(f"💾  Saved to {args.save}"))
        return 1 if report.critical_paths > 0 else 0

    # ── Phase 18: Memory, Knowledge, Multi-Agent, Explainability ────────────

    def cmd_multi_agent(args) -> int:
        """Run full 8-agent analysis on findings."""
        import json as _json
        from backend.agents.multi_agent_orchestrator import MultiAgentOrchestrator
        from backend.core.confidence import findings_from_dicts

        if not args.target:
            console.print("[red]Usage: tythanai multi-agent <findings.json>[/red]")
            return 1
        try:
            raw = _json.loads(Path(args.target).read_text())
            findings = findings_from_dicts(raw if isinstance(raw, list) else raw.get("findings", []))
        except Exception as exc:
            console.print(f"[red]Error reading findings: {exc}[/red]")
            return 1
        console.print(f"[cyan]Running 8-agent analysis on {len(findings)} findings...[/cyan]")
        orchestrator = MultiAgentOrchestrator()
        quick = getattr(args, "quick", False)
        result = orchestrator.run_quick(findings) if quick else orchestrator.run(findings)
        console.print(f"[green]✓ Session {result.session_id}[/green]")
        console.print(f"  Confirmed: {len(result.confirmed_findings)}")
        console.print(f"  Removed FPs: {len(result.removed_findings)}")
        console.print(f"  Attack chains: {len(result.attack_chains)}")
        console.print(f"  New rule proposals: {len(result.generated_rules)}")
        console.print(f"  Precision estimate: {result.precision_estimate:.1%}")
        if result.report_markdown:
            report_path = Path("reports") / f"multi_agent_{result.session_id}.md"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(result.report_markdown)
            console.print(f"  Report: {report_path}")
        return 0

    def cmd_explain(args) -> int:
        """Explain why findings were detected."""
        import json as _json
        from backend.core.explainability import ExplainabilityEngine
        from backend.core.confidence import findings_from_dicts

        if not args.target:
            console.print("[red]Usage: tythanai explain <findings.json>[/red]")
            return 1
        try:
            raw = _json.loads(Path(args.target).read_text())
            findings = findings_from_dicts(raw if isinstance(raw, list) else raw.get("findings", []))
        except Exception as exc:
            console.print(f"[red]Error reading findings: {exc}[/red]")
            return 1
        engine = ExplainabilityEngine()
        explanations = engine.batch_explain(findings)
        for fp, expl in explanations.items():
            console.print(f"\n[bold]{fp}[/bold] ({expl.rule_id})")
            console.print(f"  Why: {expl.why_detected}")
            console.print(f"  FP risk: {expl.false_positive_risk}")
            console.print(f"  Confidence: {expl.confidence_explanation.explanation}")
        return 0

    def cmd_chain_analyze(args) -> int:
        """Analyze findings for attack chains."""
        import json as _json
        from backend.analysis.chain_analyzer import analyze_attack_chains
        from backend.core.confidence import findings_from_dicts

        if not args.target:
            console.print("[red]Usage: tythanai chain-analyze <findings.json>[/red]")
            return 1
        try:
            raw = _json.loads(Path(args.target).read_text())
            findings = findings_from_dicts(raw if isinstance(raw, list) else raw.get("findings", []))
        except Exception as exc:
            console.print(f"[red]Error reading findings: {exc}[/red]")
            return 1
        chains = analyze_attack_chains(findings)
        if not chains:
            console.print("[green]No attack chains detected.[/green]")
            return 0
        console.print(f"[red]Found {len(chains)} attack chain(s):[/red]")
        for chain in chains:
            sev_color = "red" if chain.severity == "CRITICAL" else "yellow"
            console.print(f"\n  [{sev_color}]{chain.severity}[/{sev_color}] Chain: {chain.chain_type}")
            console.print(f"  Risk score: {chain.combined_risk_score:.1f}/10")
            console.print(f"  {chain.narrative}")
        return 1 if any(c.severity == "CRITICAL" for c in chains) else 0

    def cmd_learn(args) -> int:
        """Trigger learning cycle and show stats."""
        from backend.core.continuous_learning import ContinuousLearningCoordinator
        coordinator = ContinuousLearningCoordinator()
        console.print("[cyan]Running learning cycle...[/cyan]")
        result = coordinator.trigger_learning_cycle()
        stats = coordinator.get_stats()
        console.print(f"[green]✓ Learning cycle complete[/green]")
        console.print(f"  Scans learned from: {stats.total_scans_learned_from}")
        console.print(f"  Rules evolved: {stats.total_rules_evolved}")
        console.print(f"  FPs learned: {stats.total_fps_learned}")
        console.print(f"  Confirmed TPs: {stats.total_confirmed_tps}")
        console.print(f"  System precision: {stats.current_system_precision:.1%}")
        console.print(f"  System recall: {stats.current_system_recall:.1%}")
        return 0

    def cmd_memory_stats(args) -> int:
        """Show memory system statistics."""
        from backend.memory.memory_manager import MemoryManager
        mm = MemoryManager()
        stats = mm.get_stats()
        console.print("[cyan]Memory System Statistics:[/cyan]")
        for layer, count in stats.items():
            console.print(f"  {layer}: {count} entries")
        return 0

    def cmd_dataset_stats(args) -> int:
        """Show training dataset statistics."""
        from backend.core.dataset_manager import DatasetManager
        dm = DatasetManager()
        stats = dm.get_stats()
        console.print("[cyan]Training Dataset:[/cyan]")
        console.print(f"  Total entries: {stats.total_entries}")
        console.print(f"  True positives: {stats.true_positives}")
        console.print(f"  False positives: {stats.false_positives}")
        console.print(f"  Needs review: {stats.needs_review}")
        console.print(f"  TP rate: {stats.tp_rate:.1%}")
        console.print(f"  Coverage rules: {stats.coverage_rules}")
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
        # Web3 multi-chain
        "evm":          cmd_evm,
        "solana":       cmd_solana,
        "cosmos":       cmd_cosmos,
        "polkadot":     cmd_polkadot,
        "move":         cmd_move,
        "web3":         cmd_web3,
        # v13 new capabilities
        "ast":          cmd_ast,
        "openapi":      cmd_openapi,
        "semgrep":      cmd_semgrep,
        "llm-scan":     cmd_llm_scan,
        "cloud":        cmd_cloud,
        "supervisor":   cmd_supervisor,
        "telemetry":    cmd_telemetry,
        # Phase 14 — enterprise intelligence modules
        "mitre":        cmd_mitre,
        "stride":       cmd_stride,
        "fuzz":         cmd_fuzz,
        "entropy-scan": cmd_entropy_scan,
        "attack-chain": cmd_attack_chain,
        "dep-confusion":cmd_dep_confusion,
        "priority":     cmd_priority,
        "policy":       cmd_policy,
        "pr-comment":   cmd_pr_comment,
        # Phase 15 — advanced analysis (symbolic, taint, lang-scan, formal, crypto, p2p)
        "symbolic":     cmd_symbolic,
        "taint":        cmd_taint,
        "lang-scan":    cmd_lang_scan,
        "formal":       cmd_formal,
        "crypto-audit": cmd_crypto_audit,
        "p2p-sim":      cmd_p2p_sim,
        # TythanAI Phase 16 — advanced intelligence
        "threat-hunt":  cmd_threat_hunt,
        "ir-playbook":  cmd_ir_playbook,
        "patch-validate": cmd_patch_validate,
        "threat-intel": cmd_threat_intel_lookup,
        "calibrate":    cmd_calibrate,
        "cross-repo":   cmd_cross_repo,
        # TythanAI Phase 18 — autonomous AI platform evolution
        "multi-agent":  cmd_multi_agent,
        "explain":      cmd_explain,
        "chain-analyze": cmd_chain_analyze,
        "learn":        cmd_learn,
        "memory-stats": cmd_memory_stats,
        "dataset-stats": cmd_dataset_stats,
    }
    handler = dispatch.get(args.command)
    if handler:
        sys.exit(handler(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
