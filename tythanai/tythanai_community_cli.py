#!/usr/bin/env python3
# TythanAI Security Platform — Community Edition
# Copyright (c) 2026 TythanAI Labs
# Licensed under the Business Source License 1.1 (see LICENSE).

"""
tythanai_community_cli.py — Community Edition CLI entry point.

Usage:
    python tythanai_community_cli.py scan <target>  [options]
    python tythanai_community_cli.py version

Options:
    --no-sast          Skip SAST (Semgrep + custom rules)
    --no-sca           Skip SCA / dependency CVE scan
    --no-secrets       Skip secrets detection
    --no-iac           Skip IaC scan
    --no-web3          Skip Web3 / smart-contract audit
    --sarif <file>     Write SARIF 2.1.0 output to <file>
    --html  <file>     Write HTML report to <file>
    --json  <file>     Write JSON findings to <file>
    --quiet            Suppress progress messages
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

# ── Ensure repo root is on the path ──────────────────────────────────────────
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from community.gates import PREMIUM_FEATURES, UPGRADE_URL
from community.scanner import CommunityScanner
from community.report import write_sarif, write_html

# ─── ANSI colours (graceful fallback on Windows/CI) ──────────────────────────

_NO_COLOR = not sys.stdout.isatty() or os.environ.get("NO_COLOR")

def _c(code: str, text: str) -> str:
    return text if _NO_COLOR else f"\033[{code}m{text}\033[0m"

RED    = lambda t: _c("31", t)
YELLOW = lambda t: _c("33", t)
GREEN  = lambda t: _c("32", t)
CYAN   = lambda t: _c("36", t)
BOLD   = lambda t: _c("1",  t)
DIM    = lambda t: _c("2",  t)
PURPLE = lambda t: _c("35", t)

_SEV_FN = {
    "CRITICAL": RED,
    "HIGH":     lambda t: _c("31;1", t),
    "MEDIUM":   YELLOW,
    "LOW":      CYAN,
    "INFO":     DIM,
}

# ─── Banner ───────────────────────────────────────────────────────────────────

_BANNER = r"""
  ______      __  __               ___    ____
 /_  __/_  __/ /_/ /_  ____ ____  /   |  /  _/
  / / / / / / __/ __ \/ __ `/ _ \/ /| |  / /
 / / / /_/ / /_/ / / / /_/ /  __/ ___ |_/ /
/_/  \__, /\__/_/ /_/\__,_/\___/_/  |_/___/
    /____/   Community Edition  v1.0
"""

def _print_banner() -> None:
    print(PURPLE(_BANNER))
    print(BOLD("  SAST · SCA · Secrets · IaC · TON · Solana · CosmWasm · Solidity"))
    print(DIM("  Free, source-available, no account required — tythanai.io\n"))

# ─── Summary helpers ──────────────────────────────────────────────────────────

_RISK_COLORS = {
    "CRITICAL": RED, "HIGH": lambda t: _c("31;1", t),
    "MEDIUM": YELLOW, "LOW": CYAN, "CLEAN": GREEN,
}

def _print_summary(result) -> None:
    risk = result.risk_level()
    risk_fn = _RISK_COLORS.get(risk, DIM)
    sev = result.by_severity

    print()
    print(BOLD("━" * 60))
    print(BOLD("  SCAN SUMMARY"))
    print(BOLD("━" * 60))
    print(f"  Target    : {result.target}")
    print(f"  Risk      : {risk_fn(BOLD(risk))} ({result.risk_score()}/100)")
    print(f"  Findings  : {BOLD(str(result.total))}")
    print()
    print(f"  {'CRITICAL':10s} {RED(str(sev['CRITICAL'])):>4}")
    print(f"  {'HIGH':10s} {_c('31;1',str(sev['HIGH'])):>4}")
    print(f"  {'MEDIUM':10s} {YELLOW(str(sev['MEDIUM'])):>4}")
    print(f"  {'LOW':10s} {CYAN(str(sev['LOW'])):>4}")
    print(f"  {'INFO':10s} {DIM(str(sev['INFO'])):>4}")
    print()
    print(f"  SAST     : {len(result.sast_findings)} findings")
    print(f"  SCA/CVE  : {len(result.sca_findings)} findings")
    print(f"  Secrets  : {len(result.secrets_findings)} findings")
    print(f"  IaC      : {len(result.iac_findings)} findings")
    print(f"  Web3     : {len(result.web3_findings)} findings")

    if result.errors:
        print()
        print(YELLOW("  Partial scan warnings:"))
        for e in result.errors:
            print(DIM(f"    · {e}"))

    print(BOLD("━" * 60))


def _print_findings(result, quiet: bool) -> None:
    if quiet or not result.all_findings:
        return
    print()
    print(BOLD("  FINDINGS"))
    print()
    for i, f in enumerate(result.all_findings, 1):
        sev = f.get("severity", "INFO").upper()
        fn  = _SEV_FN.get(sev, DIM)
        title = f.get("title", f.get("message", "Finding"))
        file_ = f.get("file", "")
        line  = f.get("line", "")
        src   = f.get("source", "")
        loc   = f"{file_}:{line}" if file_ and line else file_
        print(f"  {DIM(str(i).rjust(3))}  {fn(sev.ljust(8))}  {BOLD(title)}")
        if loc:
            print(f"        {DIM(loc)}")
        rule_id = f.get("rule_id", f.get("id", ""))
        if rule_id:
            print(f"        {DIM(rule_id + '  [' + src + ']')}")
        print()


def _print_gated(result) -> None:
    shown = set()
    lines = []
    for g in result.gated_features:
        if g.feature_key not in shown:
            shown.add(g.feature_key)
            desc = PREMIUM_FEATURES.get(g.feature_key, g.feature_key)
            lines.append(f"  🔒  {desc}")
    if lines:
        print()
        print(BOLD("  PREMIUM FEATURES (not included in Community Edition)"))
        for l in lines:
            print(DIM(l))
        print()
        print(f"  {BOLD('Upgrade:')} {CYAN(UPGRADE_URL)}")
        print()


# ─── Command handlers ─────────────────────────────────────────────────────────

def cmd_scan(args) -> int:
    target = args.target
    if not Path(target).exists():
        print(RED(f"Error: target not found: {target}"), file=sys.stderr)
        return 1

    if not args.quiet:
        _print_banner()
        print(f"  Scanning {BOLD(target)} …\n")

    t0 = time.monotonic()
    scanner = CommunityScanner(target)
    result = scanner.run(
        sast=not args.no_sast,
        sca=not args.no_sca,
        secrets=not args.no_secrets,
        iac=not args.no_iac,
        web3=not args.no_web3,
    )
    elapsed = time.monotonic() - t0

    _print_findings(result, args.quiet)
    _print_summary(result)
    _print_gated(result)

    if not args.quiet:
        print(DIM(f"  Completed in {elapsed:.1f}s"))
        print()

    # ── Output files ──────────────────────────────────────────────────────────
    if args.sarif:
        write_sarif(result, args.sarif)
        if not args.quiet:
            print(f"  SARIF   → {args.sarif}")

    if args.html:
        write_html(result, args.html)
        if not args.quiet:
            print(f"  HTML    → {args.html}")

    if args.json:
        payload = {
            "target": result.target,
            "risk_level": result.risk_level(),
            "risk_score": result.risk_score(),
            "total": result.total,
            "by_severity": result.by_severity,
            "findings": result.all_findings,
        }
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        if not args.quiet:
            print(f"  JSON    → {args.json}")

    # Exit code: 0 = clean / info only, 1 = low+, 2 = medium+, 3 = critical/high
    risk = result.risk_level()
    if risk == "CLEAN":      return 0
    if risk == "LOW":        return 1
    if risk == "MEDIUM":     return 2
    return 3


def cmd_version(args) -> int:
    print("TythanAI Community Edition v1.0.0")
    print("Copyright (c) 2026 TythanAI Labs — BSL 1.1")
    print("https://tythanai.io")
    return 0


# ─── Argument parser ──────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tythanai-community",
        description="TythanAI Community Edition — Web3-native security scanner",
    )
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan a directory or file")
    scan.add_argument("target", help="Path to scan")
    scan.add_argument("--no-sast",    action="store_true")
    scan.add_argument("--no-sca",     action="store_true")
    scan.add_argument("--no-secrets", action="store_true")
    scan.add_argument("--no-iac",     action="store_true")
    scan.add_argument("--no-web3",    action="store_true")
    scan.add_argument("--sarif", metavar="FILE")
    scan.add_argument("--html",  metavar="FILE")
    scan.add_argument("--json",  metavar="FILE")
    scan.add_argument("--quiet", "-q", action="store_true")

    sub.add_parser("version", help="Show version information")

    return p


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "version":
        sys.exit(cmd_version(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
