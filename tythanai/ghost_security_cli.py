#!/usr/bin/env python3
"""
ghost_security_cli.py — TythanAI TythanAI Platform (Phase 2 CLI)

Full-featured command-line interface supporting all 15 scanner modules.

Usage examples:
    python ghost_security_cli.py --full-audit /path/to/project
    python ghost_security_cli.py --taint /path/to/src --threshold 0.7
    python ghost_security_cli.py --supply-chain /path/to/project
    python ghost_security_cli.py --git-secrets /path/to/repo
    python ghost_security_cli.py --infra /path/to/infra
    python ghost_security_cli.py --crypto /path/to/src
    python ghost_security_cli.py --auth /path/to/src
    python ghost_security_cli.py --headers /path/to/src
    python ghost_security_cli.py --malware /path/to/src
    python ghost_security_cli.py --dynamic /path/to/script.py
    python ghost_security_cli.py --graph /path/to/src
    python ghost_security_cli.py --all /path/to/project --output report.html
    python ghost_security_cli.py --serve --port 8000
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent))

_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[94m",
    "INFO":     "\033[90m",
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "GREEN":    "\033[92m",
    "CYAN":     "\033[96m",
}


def _c(color: str, text: str) -> str:
    if sys.stdout.isatty():
        return _COLORS.get(color, "") + text + _COLORS["RESET"]
    return text


def _banner() -> None:
    print(_c("CYAN", "\n╔══════════════════════════════════════════════════╗"))
    print(_c("CYAN",   "║   TythanAI TythanAI Platform v2         ║"))
    print(_c("CYAN",   "║   15-Module AppSec — No Stubs, Full Coverage      ║"))
    print(_c("CYAN",   "╚══════════════════════════════════════════════════╝\n"))


def _sev(f: Any) -> str:
    if hasattr(f, "severity"):
        return f.severity.upper()
    if isinstance(f, dict):
        return f.get("severity", "INFO").upper()
    return "INFO"


def _print_finding(f: Any, index: int = 0) -> None:
    d = f.model_dump() if hasattr(f, "model_dump") else (f if isinstance(f, dict) else {})
    sev   = d.get("severity", "INFO").upper()
    rid   = d.get("rule_id", "unknown")
    fpath = d.get("file", "")
    line  = d.get("line", 0)
    desc  = d.get("description", "")[:120]
    conf  = d.get("confidence", 0.0)
    print(f"  {_c(sev, f'[{sev}]')} {_c('BOLD', rid)}")
    print(f"         {fpath}:{line}  conf={conf:.2f}")
    print(f"         {desc}")


def _print_summary(name: str, findings: List[Any], elapsed: float) -> None:
    if not findings:
        print(_c("GREEN", f"  ✔ {name}: 0 findings ({elapsed:.2f}s)"))
        return
    sev_counts = Counter(_sev(f) for f in findings)
    parts = [_c(s, f"{sev_counts[s]} {s}") for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO") if sev_counts.get(s)]
    print(f"  {_c('BOLD', name)}: {len(findings)} findings — {', '.join(parts)} ({elapsed:.2f}s)")


def _save(data: Any, output_path: str) -> None:
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if output_path.endswith(".html") and isinstance(data, dict) and "html_report_path" in data:
        src = Path(data["html_report_path"])
        if src.exists():
            import shutil; shutil.copy2(str(src), str(p))
            print(f"  HTML report saved → {output_path}")
            return
    text = data if isinstance(data, str) else json.dumps(data, indent=2, default=str)
    p.write_text(text, encoding="utf-8")
    print(f"  Output saved → {output_path}")


# ─────────────────────────────────────────────────────────────────────────────
# Scanner runners
# ─────────────────────────────────────────────────────────────────────────────

def run_taint(path: str, threshold: float, verbose: bool) -> List[Any]:
    from backend.scanners.taint_analyzer import TaintAnalyzer
    from backend.core.confidence import ConfidenceFilter, ContextVerifier, Deduplicator
    analyzer = TaintAnalyzer(confidence_threshold=threshold)
    p = Path(path)
    raw: List[Any] = []
    files = [p] if p.is_file() else list(p.rglob("*.py"))
    for f in files:
        raw.extend(analyzer.analyze_file(str(f)))
    return ConfidenceFilter(threshold).filter(
        Deduplicator().deduplicate([ContextVerifier().verify(f) for f in raw])
    )


def run_supply_chain(path: str, threshold: float, verbose: bool) -> List[Any]:
    from backend.scanners.supply_chain import SupplyChainScanner
    result = SupplyChainScanner().scan(path)
    if verbose and result.get("typosquatting"):
        print(f"  Typosquatting suspects: {len(result['typosquatting'])}")
    raw = result.get("findings", [])
    if raw and isinstance(raw[0], dict):
        from backend.core.confidence import findings_from_dicts
        return findings_from_dicts(raw)
    return raw


def run_git_secrets(path: str, threshold: float, verbose: bool) -> List[Any]:
    from backend.scanners.git_secrets import GitSecretsScanner
    result = GitSecretsScanner().scan(path)
    raw = result.get("findings", [])
    if raw and isinstance(raw[0], dict):
        from backend.core.confidence import findings_from_dicts
        return findings_from_dicts(raw)
    return raw


def run_infra(path: str, threshold: float, verbose: bool) -> List[Any]:
    from backend.scanners.infra_scanner import InfraScanner
    s = InfraScanner()
    p = Path(path)
    return s.scan_file(path) if p.is_file() else s.scan_directory(path)


def run_crypto(path: str, threshold: float, verbose: bool) -> List[Any]:
    from backend.scanners.crypto_checker import CryptoChecker
    c = CryptoChecker()
    p = Path(path)
    return c.scan_file(path) if p.is_file() else c.scan_directory(path)


def run_auth(path: str, threshold: float, verbose: bool) -> List[Any]:
    from backend.scanners.auth_checker import scan_file, scan_directory
    p = Path(path)
    return scan_file(path) if p.is_file() else scan_directory(path)


def run_headers(path: str, threshold: float, verbose: bool) -> List[Any]:
    from backend.scanners.headers_checker import scan_file, scan_directory
    p = Path(path)
    return scan_file(path) if p.is_file() else scan_directory(path)


def run_malware(path: str, threshold: float, verbose: bool) -> List[Any]:
    from backend.sandbox.malware_analyzer import MalwareAnalyzer
    a = MalwareAnalyzer()
    p = Path(path)
    if p.is_file():
        return a.analyze(path).findings
    findings: List[Any] = []
    for f in p.rglob("*.py"):
        findings.extend(a.analyze(str(f)).findings)
    return findings


def run_dynamic(path: str, threshold: float, verbose: bool) -> Dict[str, Any]:
    from backend.sandbox.dynamic_analyzer import DynamicAnalyzer
    return DynamicAnalyzer().analyze(path).model_dump()


def run_graph(path: str, threshold: float, verbose: bool, fmt: str = "json") -> Any:
    from backend.analysis.dependency_graph import DependencyGraphBuilder
    builder = DependencyGraphBuilder()
    graph = builder.build(path)
    if fmt == "dot":
        return builder.to_dot(graph)
    return graph.model_dump() if hasattr(graph, "model_dump") else graph


async def _full_audit(path: str, threshold: float, skip: List[str]) -> Dict[str, Any]:
    from backend.pipeline.defensive_lifecycle import run_full_audit
    return await run_full_audit(path=path, confidence_threshold=threshold, skip_stages=skip)


# ─────────────────────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ghost-security",
        description="TythanAI TythanAI Platform — 15-module AppSec scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("path", nargs="?", default=".", help="Target path (file or directory)")

    # Scanner flags
    grp = ap.add_argument_group("scanners")
    grp.add_argument("--full-audit",   action="store_true", help="Full 6-stage defensive lifecycle pipeline")
    grp.add_argument("--all",          action="store_true", help="Run all individual scanners")
    grp.add_argument("--taint",        action="store_true", help="AST taint analysis (SQLi, shell injection, ...)")
    grp.add_argument("--supply-chain", action="store_true", help="Dependency vulnerability + typosquatting scan")
    grp.add_argument("--git-secrets",  action="store_true", help="Git history + working-tree secret scanner")
    grp.add_argument("--infra",        action="store_true", help="Dockerfile / K8s / GitHub Actions scanner")
    grp.add_argument("--crypto",       action="store_true", help="Weak cryptography checker (MD5, ECB, ...)")
    grp.add_argument("--auth",         action="store_true", help="FastAPI auth checker (missing Depends, IDOR, JWT)")
    grp.add_argument("--headers",      action="store_true", help="Security headers / CORS checker")
    grp.add_argument("--malware",      action="store_true", help="Static malware pre-analysis")
    grp.add_argument("--dynamic",      action="store_true", help="Docker-sandbox dynamic analysis")
    grp.add_argument("--graph",        action="store_true", help="Build and output dependency graph")

    # Output / control
    ctrl = ap.add_argument_group("output & control")
    ctrl.add_argument("--output",       "-o", default="", help="Save output to .html or .json file")
    ctrl.add_argument("--threshold",    "-t", type=float, default=0.5, metavar="0.0-1.0",
                      help="Confidence threshold (default 0.5)")
    ctrl.add_argument("--skip",         nargs="+", default=[], metavar="STAGE",
                      help="Pipeline stages to skip when using --full-audit")
    ctrl.add_argument("--graph-format", default="json", choices=["json", "dot"],
                      help="Output format for --graph")
    ctrl.add_argument("--verbose",      "-v", action="store_true", help="Print each finding")
    ctrl.add_argument("--json-output",  "-j", action="store_true", help="Machine-readable JSON output only")
    ctrl.add_argument("--serve",        action="store_true",
                      help="Start FastAPI server (requires uvicorn)")
    ctrl.add_argument("--port",         type=int, default=8000, help="Port for --serve (default 8000)")
    return ap


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.json_output:
        _banner()

    path = str(Path(args.path).resolve())
    if not Path(path).exists():
        print(f"Error: path does not exist: {path}", file=sys.stderr)
        return 1

    # ── Serve mode ───────────────────────────────────────────────────────────
    if args.serve:
        try:
            import uvicorn
            from fastapi import FastAPI
            from backend.api.v2_router import router as _v2
            app = FastAPI(title="TythanAI TythanAI", version="2.0")
            app.include_router(_v2)
            print(f"  Starting API server → http://0.0.0.0:{args.port}/docs")
            uvicorn.run(app, host="0.0.0.0", port=args.port)
            return 0
        except ImportError as e:
            print(f"Error: {e}. Install: pip install uvicorn", file=sys.stderr)
            return 1

    # ── Full audit pipeline ──────────────────────────────────────────────────
    if args.full_audit:
        print(f"Full 6-stage audit → {path}")
        t0 = time.monotonic()
        result = asyncio.run(_full_audit(path, args.threshold, args.skip))
        elapsed = time.monotonic() - t0
        n = len(result.get("findings", []))
        if args.json_output:
            print(json.dumps(result, indent=2, default=str))
        else:
            print(f"\nAudit done: {n} findings in {elapsed:.1f}s")
            if args.verbose:
                for f in result.get("findings", []):
                    _print_finding(f)
        if args.output:
            _save(result, args.output)
        return 2 if any(_sev(f) in ("CRITICAL","HIGH") for f in result.get("findings", [])) else (1 if n else 0)

    # ── Individual scanner(s) ────────────────────────────────────────────────
    any_flag = any([
        args.taint, args.supply_chain, args.git_secrets, args.infra,
        args.crypto, args.auth, args.headers, args.malware, args.dynamic, args.graph,
    ])
    use_all = args.all or not any_flag

    runners: List[tuple] = []
    if args.taint        or use_all: runners.append(("taint",        run_taint))
    if args.supply_chain or use_all: runners.append(("supply-chain", run_supply_chain))
    if args.git_secrets  or use_all: runners.append(("git-secrets",  run_git_secrets))
    if args.infra        or use_all: runners.append(("infra",        run_infra))
    if args.crypto       or use_all: runners.append(("crypto",       run_crypto))
    if args.auth         or use_all: runners.append(("auth",         run_auth))
    if args.headers      or use_all: runners.append(("headers",      run_headers))
    if args.malware      or use_all: runners.append(("malware",      run_malware))
    if args.dynamic:                 runners.append(("dynamic",      run_dynamic))

    all_findings: List[Any] = []
    all_results: Dict[str, Any] = {}

    for name, fn in runners:
        if not args.json_output:
            print(f"\n{_c('BOLD', f'[{name}]')} → {path}")
        t0 = time.monotonic()
        try:
            res = fn(path, args.threshold, args.verbose)
        except Exception as exc:
            if not args.json_output:
                print(f"  {_c('HIGH', 'ERROR')}: {exc}")
            continue
        elapsed = time.monotonic() - t0

        if isinstance(res, list):
            all_findings.extend(res)
            all_results[name] = [f.model_dump() if hasattr(f, "model_dump") else f for f in res]
            if not args.json_output:
                _print_summary(name, res, elapsed)
                if args.verbose:
                    for i, f in enumerate(res):
                        _print_finding(f, i)
        else:
            all_results[name] = res
            if not args.json_output:
                print(f"  Result: {json.dumps(res, default=str)[:200]}")

    if args.graph:
        if not args.json_output:
            print(f"\n{_c('BOLD', '[graph]')} → {path}")
        t0 = time.monotonic()
        try:
            g = run_graph(path, args.threshold, args.verbose, args.graph_format)
            all_results["graph"] = g
            if not args.json_output:
                print(f"  Graph built in {time.monotonic()-t0:.2f}s")
        except Exception as exc:
            if not args.json_output:
                print(f"  ERROR: {exc}")

    if not args.json_output and all_findings:
        counts = Counter(_sev(f) for f in all_findings)
        print(f"\n{_c('BOLD', '═══ TOTAL FINDINGS ═══')}")
        for s in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
            if counts.get(s):
                print(f"  {_c(s, f'{counts[s]:4d} {s}')}")
        print(f"  {'─'*22}")
        print(f"  {len(all_findings):4d} total\n")

    if args.json_output:
        print(json.dumps(all_results, indent=2, default=str))

    if args.output:
        _save(all_results, args.output)

    crit_high = sum(1 for f in all_findings if _sev(f) in ("CRITICAL", "HIGH"))
    return 2 if crit_high else (1 if all_findings else 0)


if __name__ == "__main__":
    sys.exit(main())
