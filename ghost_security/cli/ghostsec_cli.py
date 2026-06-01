"""
cli/ghostsec_cli.py — TythanAI Security Scanner CLI

Usage:
    python -m cli.ghostsec_cli scan /path/to/project
    python -m cli.ghostsec_cli scan ./myapp --format sarif --output results.sarif
    python -m cli.ghostsec_cli scan ./myapp --severity HIGH,CRITICAL
    python -m cli.ghostsec_cli scan ./myapp --no-semgrep --quick
    python -m cli.ghostsec_cli version
    python -m cli.ghostsec_cli status
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

# Ensure project root is importable
_CLI_DIR = Path(__file__).parent
_PROJECT_ROOT = _CLI_DIR.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Version constant
# ---------------------------------------------------------------------------

_VERSION = "6.5"
_PRODUCT = "TythanAI"

# ---------------------------------------------------------------------------
# ANSI colour helpers (graceful fallback when not a TTY)
# ---------------------------------------------------------------------------

_IS_TTY = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    """Wrap *text* with ANSI escape *code* when connected to a TTY."""
    if not _IS_TTY:
        return text
    return f"\033[{code}m{text}\033[0m"


def _bold(text: str) -> str:
    return _c("1", text)


def _red(text: str) -> str:
    return _c("31;1", text)


def _orange(text: str) -> str:
    return _c("33;1", text)


def _yellow(text: str) -> str:
    return _c("33", text)


def _blue(text: str) -> str:
    return _c("34;1", text)


def _green(text: str) -> str:
    return _c("32;1", text)


def _dim(text: str) -> str:
    return _c("2", text)


_SEV_COLOR = {
    "CRITICAL": _red,
    "HIGH":     _orange,
    "MEDIUM":   _yellow,
    "LOW":      _blue,
    "INFO":     _dim,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sev_bar(count: int, scale: int = 50) -> str:
    """Render a simple ASCII bar proportional to *count*."""
    if count <= 0:
        return ""
    width = max(1, min(count, scale))
    return "█" * width


def _box_line(content: str, width: int = 56) -> str:
    pad = width - len(content) - 2
    return f"║  {content}{' ' * max(0, pad)}║"


def _build_box(lines: List[str], width: int = 56) -> str:
    top = "╔" + "═" * (width - 2) + "╗"
    bot = "╚" + "═" * (width - 2) + "╝"
    rows = [top] + [_box_line(l, width) for l in lines] + [bot]
    return "\n".join(rows)


# ---------------------------------------------------------------------------
# cmd_version
# ---------------------------------------------------------------------------

def cmd_version() -> None:
    print(f"{_PRODUCT} v{_VERSION} — Security Scanner")


# ---------------------------------------------------------------------------
# cmd_status
# ---------------------------------------------------------------------------

def cmd_status() -> None:
    """Print the availability and version of each scanner component."""
    print(_bold(f"\n{_PRODUCT} v{_VERSION} — Scanner Status\n"))

    rows: List[tuple] = []

    # AST
    try:
        from scanners.ast_scanner.ast_analyzer import ASTScanner
        ASTScanner()
        rows.append(("AST Scanner", "available", "built-in"))
    except Exception as exc:
        rows.append(("AST Scanner", "unavailable", str(exc)[:60]))

    # Semgrep
    try:
        from scanners.semgrep_integration import SemgrepScanner
        s = SemgrepScanner()
        if s.is_available():
            rows.append(("Semgrep", "available", s.version()))
        else:
            rows.append(("Semgrep", "unavailable", "binary not found"))
    except Exception as exc:
        rows.append(("Semgrep", "unavailable", str(exc)[:60]))

    # OSV
    try:
        from scanners.osv_scanner import OSVScanner
        osv = OSVScanner()
        online = osv.is_online()
        rows.append(("OSV.dev", "online" if online else "offline", "https://api.osv.dev/v1"))
    except Exception as exc:
        rows.append(("OSV.dev", "unavailable", str(exc)[:60]))

    # EPSS
    try:
        from scanners.epss_enricher import EPSSEnricher
        epss = EPSSEnricher()
        online = epss.is_online()
        rows.append(("EPSS / KEV", "online" if online else "offline", "https://api.first.org"))
    except Exception as exc:
        rows.append(("EPSS / KEV", "unavailable", str(exc)[:60]))

    # Secret scanner
    try:
        from scanners.secret_scanner.secret_detector import SecretDetector
        SecretDetector()
        rows.append(("Secret Scanner", "available", "built-in 60+ patterns"))
    except Exception as exc:
        rows.append(("Secret Scanner", "unavailable", str(exc)[:60]))

    # OWASP
    try:
        from scanners.owasp_scanner import OWASPScanner
        OWASPScanner()
        rows.append(("OWASP Scanner", "available", "OWASP Top 10 (2021)"))
    except Exception as exc:
        rows.append(("OWASP Scanner", "unavailable", str(exc)[:60]))

    # VerifiedFixEngine
    try:
        from backend.core.remediation.verified_fix_engine import VerifiedFixEngine  # noqa: F401
        rows.append(("VerifiedFixEngine", "available", "auto-remediation"))
    except Exception as exc:
        rows.append(("VerifiedFixEngine", "unavailable", str(exc)[:60]))

    col_w = max(len(r[0]) for r in rows) + 2
    for name, status, note in rows:
        icon   = _green("✓") if "available" in status or "online" in status else _red("✗")
        colour = _green if "available" in status or "online" in status else _red
        print(f"  {icon}  {name:<{col_w}} {colour(status):<30}  {_dim(note)}")

    print()


# ---------------------------------------------------------------------------
# _print_summary
# ---------------------------------------------------------------------------

def _print_summary(result) -> None:
    """Print a coloured summary box for a ScanResult."""
    from backend.core.engine.unified_scan_engine import ScanResult
    sc = result.severity_counts
    crit = sc.get("CRITICAL", 0)
    high = sc.get("HIGH",     0)
    med  = sc.get("MEDIUM",   0)
    low  = sc.get("LOW",      0)
    info = sc.get("INFO",     0)

    target_str = str(result.target)[:50]
    header = f"TythanAI Security Scan — {target_str}"

    box_width = max(60, len(header) + 6)
    top = "╔" + "═" * (box_width - 2) + "╗"
    bot = "╚" + "═" * (box_width - 2) + "╝"

    def _bline(text: str) -> str:
        pad = box_width - len(text) - 4
        return f"║  {text}{' ' * max(0, pad)}  ║"

    scanners_str = ", ".join(result.scanners_used) if result.scanners_used else "none"
    meta_str = (
        f"Duration: {result.scan_duration_s:.1f}s | "
        f"Files: {result.total_files_scanned} | "
        f"Dependencies: {result.total_dependencies_checked}"
    )

    risk_fn = {
        "CRITICAL": _red,
        "HIGH":     _orange,
        "MEDIUM":   _yellow,
        "LOW":      _green,
    }.get(result.risk_level, _dim)

    print(_bold(top))
    print(_bold(_bline(header)))
    print(_bold(bot))
    print(f"  Scanners : {scanners_str}")
    print(f"  {meta_str}")
    print()

    for sev, count in [
        ("CRITICAL", crit), ("HIGH", high),
        ("MEDIUM", med),    ("LOW",  low),
    ]:
        bar  = _sev_bar(count, scale=30)
        fn   = _SEV_COLOR.get(sev, _dim)
        label = f"  {fn(f'{sev:<10}')} {count:>4}  {fn(bar)}"
        print(label)

    print()
    risk_str = risk_fn(f"{result.risk_level}")
    print(f"  Risk Score: {risk_fn(str(result.risk_score))}/100 ({risk_str})")
    print()


# ---------------------------------------------------------------------------
# _print_findings_table
# ---------------------------------------------------------------------------

def _print_findings_table(findings: List[dict], max_rows: int = 25) -> None:
    """Print a text table of findings."""
    if not findings:
        print(_green("  No findings.\n"))
        return

    shown = findings[:max_rows]
    header = f"  {'SEV':<10}  {'CWE':<12}  {'DESCRIPTION':<50}  {'LOCATION'}"
    sep    = "  " + "-" * (len(header) - 2)
    print(_bold(header))
    print(sep)

    for fd in shown:
        sev  = str(fd.get("severity", "INFO")).upper()
        cwe  = str(fd.get("cwe_id", fd.get("cwe", "")))[:12]
        desc = str(fd.get("description", fd.get("title", "")))[:50]
        fp   = str(fd.get("file_path", fd.get("file", "")))
        line = fd.get("line", 0)
        loc  = f"{Path(fp).name}:{line}" if fp else ""

        fn  = _SEV_COLOR.get(sev, _dim)
        row = f"  {fn(f'[{sev}]'):<22}  {cwe:<12}  {desc:<50}  {_dim(loc)}"
        print(row)

    if len(findings) > max_rows:
        print(f"\n  {_dim(f'... and {len(findings) - max_rows} more findings')}\n")
    else:
        print()


# ---------------------------------------------------------------------------
# cmd_scan
# ---------------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    """Run UnifiedScanEngine.scan() and display/export results."""
    try:
        from backend.core.engine.unified_scan_engine import UnifiedScanEngine, ScanOptions
    except ImportError as exc:
        print(_red(f"[ERROR] Cannot import UnifiedScanEngine: {exc}"), file=sys.stderr)
        return 1

    # Build ScanOptions from args
    severity_filter: List[str] = []
    if args.severity:
        severity_filter = [s.strip().upper() for s in args.severity.split(",") if s.strip()]

    opts = ScanOptions(
        enable_semgrep  = not getattr(args, "no_semgrep", False),
        enable_osv      = not getattr(args, "no_osv",     False),
        enable_epss     = not getattr(args, "no_epss",    False),
        enable_ast      = not getattr(args, "no_ast",     False),
        enable_secrets  = not getattr(args, "no_secrets", False),
        enable_owasp    = not getattr(args, "no_owasp",   False),
        max_findings    = getattr(args, "max_findings", 500),
        timeout_s       = getattr(args, "timeout",      120),
        severity_filter = severity_filter,
    )

    engine = UnifiedScanEngine(opts)

    target = args.target
    if not Path(target).exists():
        print(_red(f"[ERROR] Target not found: {target}"), file=sys.stderr)
        return 1

    print(_dim(f"\nScanning {target} …\n"))

    if getattr(args, "quick", False):
        result = engine.quick_scan(target)
    else:
        result = engine.scan(target)

    # ── Output ─────────────────────────────────────────────────────────────────
    fmt = getattr(args, "format", "text").lower()
    out_path: Optional[str] = getattr(args, "output", None)

    if fmt == "json":
        output_str = result.to_json()
        if out_path:
            Path(out_path).write_text(output_str, encoding="utf-8")
            print(f"JSON report written to {out_path}")
        else:
            print(output_str)

    elif fmt == "sarif":
        try:
            from reports.sarif_enriched import SARIFExporter
            sarif_data = SARIFExporter().export(result.to_dict())
        except Exception:
            # Fallback: basic SARIF 2.1.0 envelope
            sarif_data = {
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [{
                    "tool": {"driver": {"name": "TythanAI", "version": _VERSION, "rules": []}},
                    "results": [
                        {
                            "ruleId": f.get("rule_id", f.get("cwe_id", "UNKNOWN")),
                            "message": {"text": f.get("description", "")},
                            "level": {"CRITICAL": "error", "HIGH": "error",
                                      "MEDIUM": "warning", "LOW": "note",
                                      "INFO": "note"}.get(f.get("severity", "INFO"), "warning"),
                            "locations": [{
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.get("file_path", "")},
                                    "region": {"startLine": max(1, f.get("line", 1))},
                                }
                            }],
                        }
                        for f in result.findings
                    ],
                }],
            }
        output_str = json.dumps(sarif_data, indent=2, default=str)
        if out_path:
            Path(out_path).write_text(output_str, encoding="utf-8")
            print(f"SARIF report written to {out_path}")
        else:
            print(output_str)

    else:
        # Default: text output
        _print_summary(result)
        print(_bold("Top findings:"))
        _print_findings_table(result.findings)

        if result.scanner_errors:
            print(_dim("Scanner warnings:"))
            for err in result.scanner_errors[:5]:
                print(_dim(f"  • {err}"))
            print()

        if out_path:
            try:
                from reports.report_generator import ReportGenerator
                html = ReportGenerator().generate_html(result.to_dict())
                Path(out_path).write_text(html, encoding="utf-8")
                print(f"HTML report written to {out_path}")
            except Exception as exc:
                # Fallback: write JSON
                Path(out_path).write_text(result.to_json(), encoding="utf-8")
                print(f"Report (JSON fallback) written to {out_path} ({exc})")

    # Return exit code based on critical findings
    return 0 if not result.critical_findings() else 2


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ghostsec",
        description=f"{_PRODUCT} v{_VERSION} — AI-powered security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── scan ──────────────────────────────────────────────────────────────────
    scan_p = sub.add_parser("scan", help="Scan a file or directory for vulnerabilities")
    scan_p.add_argument("target", help="Path to file or directory to scan")
    scan_p.add_argument(
        "--format", "-f",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    scan_p.add_argument("--output", "-o", metavar="FILE", help="Write report to FILE")
    scan_p.add_argument(
        "--severity", "-s",
        metavar="LEVELS",
        help="Comma-separated severity filter e.g. HIGH,CRITICAL",
    )
    scan_p.add_argument("--no-semgrep",  action="store_true", help="Disable Semgrep scanner")
    scan_p.add_argument("--no-osv",      action="store_true", help="Disable OSV dependency scanner")
    scan_p.add_argument("--no-epss",     action="store_true", help="Disable EPSS enrichment")
    scan_p.add_argument("--no-ast",      action="store_true", help="Disable AST scanner")
    scan_p.add_argument("--no-secrets",  action="store_true", help="Disable secret scanner")
    scan_p.add_argument("--no-owasp",    action="store_true", help="Disable OWASP scanner")
    scan_p.add_argument(
        "--quick", "-q",
        action="store_true",
        help="Quick mode: AST + secrets only (faster)",
    )
    scan_p.add_argument(
        "--max-findings",
        type=int,
        default=500,
        metavar="N",
        help="Cap on number of findings returned (default: 500)",
    )
    scan_p.add_argument(
        "--timeout",
        type=int,
        default=120,
        metavar="SECONDS",
        help="Per-scanner timeout in seconds (default: 120)",
    )

    # ── version ───────────────────────────────────────────────────────────────
    sub.add_parser("version", help="Print version and exit")

    # ── status ────────────────────────────────────────────────────────────────
    sub.add_parser("status", help="Show scanner component availability")

    return parser


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "version":
        cmd_version()
        sys.exit(0)

    if args.command == "status":
        cmd_status()
        sys.exit(0)

    if args.command == "scan":
        exit_code = cmd_scan(args)
        sys.exit(exit_code)

    # No command given — show help
    parser.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
