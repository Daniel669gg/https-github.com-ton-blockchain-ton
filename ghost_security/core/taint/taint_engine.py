"""Ghost Security Platform — Taint Analysis Engine (Phase 15)

Tracks attacker-controlled data through C++/Rust/Go/Solidity codebases.
"""

from __future__ import annotations

import re
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class TaintSource:
    name: str
    pattern: str        # regex matching source expressions
    category: str       # "network_input", "user_input", "env_var", "file_read"
    languages: List[str] = field(default_factory=list)  # [] = all


@dataclass
class TaintSink:
    name: str
    pattern: str
    severity: str       # "CRITICAL", "HIGH", "MEDIUM"
    category: str       # "cmd_injection", "sql_injection", "memory_write", etc.
    languages: List[str] = field(default_factory=list)


@dataclass
class TaintFlow:
    source: TaintSource
    sink: TaintSink
    filepath: str
    source_line: int
    sink_line: int
    path: List[str]     # intermediate steps
    sanitized: bool
    confidence: float   # 0.0–1.0


@dataclass
class TaintReport:
    flows: List[TaintFlow]
    sources_found: int
    sinks_found: int
    language: str
    files_analyzed: int
    scan_time: float

    def to_dict(self) -> dict:
        return {
            "language": self.language,
            "files_analyzed": self.files_analyzed,
            "sources_found": self.sources_found,
            "sinks_found": self.sinks_found,
            "flows": len(self.flows),
            "scan_time": round(self.scan_time, 3),
            "findings": [
                {
                    "source": f.source.name,
                    "sink": f.sink.name,
                    "filepath": f.filepath,
                    "source_line": f.source_line,
                    "sink_line": f.sink_line,
                    "severity": f.sink.severity,
                    "category": f.sink.category,
                    "sanitized": f.sanitized,
                    "confidence": round(f.confidence, 2),
                }
                for f in self.flows
            ],
        }


# ---------------------------------------------------------------------------
# Built-in source/sink definitions
# ---------------------------------------------------------------------------

CPP_SOURCES: List[TaintSource] = [
    TaintSource("recv/read",       r"\b(recv|read|fread|fgets|gets|scanf|fscanf)\s*\(", "network_input", ["cpp"]),
    TaintSource("getenv",          r"\bgetenv\s*\(", "env_var", ["cpp"]),
    TaintSource("argv",            r"\bargv\s*\[", "user_input", ["cpp"]),
    TaintSource("accept",          r"\baccept\s*\(", "network_input", ["cpp"]),
    TaintSource("message_field",   r"message\.\w+_\s*[,\)]", "network_input", ["cpp"]),
    TaintSource("tl_field",        r"\bmessage\.(max_answer_size|data_size|seqno)_", "network_input", ["cpp"]),
]

CPP_SINKS: List[TaintSink] = [
    TaintSink("system/exec",    r"\b(system|execvp?|popen|execl)\s*\(", "CRITICAL", "cmd_injection", ["cpp"]),
    TaintSink("memcpy_size",    r"\bmemcpy\s*\([^,]+,[^,]+,\s*[a-zA-Z_]\w*\s*\)", "HIGH", "memory_write", ["cpp"]),
    TaintSink("static_cast_u64", r"static_cast\s*<\s*(td::uint64|uint64_t)\s*>\s*\(\s*\w+\.\w+_\s*\)", "HIGH", "sign_confusion", ["cpp"]),
    TaintSink("emplace_back",   r"\.emplace_back\s*\(", "MEDIUM", "unbounded_growth", ["cpp"]),
    TaintSink("new_actor",      r"create_actor\s*<[^>]+>\s*\([^)]+\)\.release\(\)", "MEDIUM", "resource_exhaustion", ["cpp"]),
    TaintSink("printf_fmt",     r"\b(printf|fprintf|sprintf|snprintf)\s*\(\s*\w+\s*,\s*[a-zA-Z_]\w*\s*[,)]", "HIGH", "format_string", ["cpp"]),
]

RUST_SOURCES: List[TaintSource] = [
    TaintSource("std_io_read",   r"\b(stdin|BufReader|File::open)\b.*\.read", "file_read", ["rust"]),
    TaintSource("clap_args",     r"\bArg\b|\.value_of\s*\(|\.get_one\s*\(", "user_input", ["rust"]),
    TaintSource("tcp_stream",    r"TcpStream::connect|TcpListener::accept", "network_input", ["rust"]),
    TaintSource("env_var",       r"\benv::var\s*\(|std::env::args", "env_var", ["rust"]),
    TaintSource("from_network",  r"\.read_to_end\s*\(|\.read_exact\s*\(", "network_input", ["rust"]),
]

RUST_SINKS: List[TaintSink] = [
    TaintSink("unsafe_deref",    r"\bunsafe\s*\{[^}]*\*[a-zA-Z_]", "CRITICAL", "memory_safety", ["rust"]),
    TaintSink("process_command", r"Command::new\s*\(|\.arg\s*\(", "CRITICAL", "cmd_injection", ["rust"]),
    TaintSink("from_raw_parts",  r"from_raw_parts\s*\(|transmute\s*\(", "CRITICAL", "memory_safety", ["rust"]),
    TaintSink("unwrap_panic",    r"\.(unwrap|expect)\s*\(\)", "MEDIUM", "panic", ["rust"]),
    TaintSink("as_cast",         r"\bas\s+u(8|16|32|64)\b", "HIGH", "sign_confusion", ["rust"]),
]

GO_SOURCES: List[TaintSource] = [
    TaintSource("http_request",  r"r\.FormValue\s*\(|r\.URL\.Query|r\.Body|r\.Header", "network_input", ["go"]),
    TaintSource("os_args",       r"os\.Args\[", "user_input", ["go"]),
    TaintSource("os_getenv",     r"os\.Getenv\s*\(", "env_var", ["go"]),
    TaintSource("net_read",      r"\.Read\s*\(|bufio\.NewReader", "network_input", ["go"]),
    TaintSource("json_unmarshal", r"json\.Unmarshal\s*\(", "network_input", ["go"]),
]

GO_SINKS: List[TaintSink] = [
    TaintSink("exec_command",    r"exec\.Command\s*\(", "CRITICAL", "cmd_injection", ["go"]),
    TaintSink("sql_query_fmt",   r"db\.(Query|Exec)\s*\(.*fmt\.Sprintf", "CRITICAL", "sql_injection", ["go"]),
    TaintSink("unsafe_pointer",  r"unsafe\.Pointer\s*\(", "HIGH", "memory_safety", ["go"]),
    TaintSink("http_get_url",    r"http\.(Get|Post)\s*\(\s*\w+\s*\+", "HIGH", "ssrf", ["go"]),
    TaintSink("file_open",       r"os\.(Open|Create)\s*\(\s*\w+\s*\+", "HIGH", "path_traversal", ["go"]),
]

SOLIDITY_SOURCES: List[TaintSource] = [
    TaintSource("msg_sender",    r"\bmsg\.sender\b", "user_input", ["solidity"]),
    TaintSource("msg_value",     r"\bmsg\.value\b", "user_input", ["solidity"]),
    TaintSource("calldata",      r"\bcalldata\b|\bcalldataload\b", "network_input", ["solidity"]),
    TaintSource("tx_origin",     r"\btx\.origin\b", "user_input", ["solidity"]),
    TaintSource("block_values",  r"\bblock\.(timestamp|number|difficulty|coinbase)\b", "network_input", ["solidity"]),
]

SOLIDITY_SINKS: List[TaintSink] = [
    TaintSink("call_value",      r"\.call\{value:", "CRITICAL", "reentrancy", ["solidity"]),
    TaintSink("selfdestruct",    r"\bselfdestruct\s*\(", "CRITICAL", "fund_loss", ["solidity"]),
    TaintSink("assembly_block",  r"\bassembly\s*\{", "HIGH", "low_level_call", ["solidity"]),
    TaintSink("delegatecall",    r"\.delegatecall\s*\(", "CRITICAL", "storage_collision", ["solidity"]),
    TaintSink("low_level_call",  r"\.call\s*\(", "HIGH", "unchecked_call", ["solidity"]),
]

SANITIZER_PATTERNS: List[str] = [
    r"\bif\s*\(\s*\w+\s*<\s*0\s*\)",   # negative check before cast
    r"\brequire\s*\(",                   # Solidity require
    r"\bassert\s*\(",
    r"\.is_err\(\)",                     # Rust error handling
    r"\.is_ok\(\)",
    r"\berr\s*!=\s*nil\b",              # Go error check
    r"\bcheck\w*\s*\(",                  # generic check function
    r"sanitize\w*\s*\(",
    r"validate\w*\s*\(",
    r"hmac\.compare_digest\s*\(",
    r"constant_time_compare\s*\(",
]

ALL_SOURCES = CPP_SOURCES + RUST_SOURCES + GO_SOURCES + SOLIDITY_SOURCES
ALL_SINKS   = CPP_SINKS   + RUST_SINKS   + GO_SINKS   + SOLIDITY_SINKS


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

EXT_TO_LANG: Dict[str, str] = {
    ".sol": "solidity", ".vy": "solidity",
    ".rs":  "rust",
    ".go":  "go",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".c": "cpp", ".h": "cpp", ".hpp": "cpp",
    ".py":  "python",
}


def detect_language(path: str) -> str:
    return EXT_TO_LANG.get(Path(path).suffix.lower(), "unknown")


def collect_files(path: str, lang: str) -> List[str]:
    ext_map = {
        "solidity": {".sol", ".vy"},
        "rust":     {".rs"},
        "go":       {".go"},
        "cpp":      {".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"},
        "python":   {".py"},
    }
    exts = ext_map.get(lang, set())
    p = Path(path)
    if p.is_file():
        return [path]
    result = []
    for f in p.rglob("*"):
        if f.suffix.lower() in exts and f.is_file():
            result.append(str(f))
    return result


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------

class TaintEngine:
    def __init__(self, language: str = "auto"):
        self.language = language
        self._sources: List[TaintSource] = []
        self._sinks: List[TaintSink]     = []

    def set_sources(self, sources: List[TaintSource]) -> None:
        self._sources = sources

    def set_sinks(self, sinks: List[TaintSink]) -> None:
        self._sinks = sinks

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, path: str) -> TaintReport:
        t0 = time.time()

        lang = self.language if self.language != "auto" else detect_language(path)
        if lang == "unknown" and Path(path).is_dir():
            # try to auto-detect dominant language
            lang = self._sniff_directory(path)

        files = collect_files(path, lang)
        sources = self._sources or [s for s in ALL_SOURCES if not s.languages or lang in s.languages]
        sinks   = self._sinks   or [s for s in ALL_SINKS   if not s.languages or lang in s.languages]

        all_flows: List[TaintFlow] = []
        total_src = 0
        total_snk = 0

        for filepath in files:
            try:
                src_txt = Path(filepath).read_text(errors="replace")
            except OSError:
                continue

            lines = src_txt.splitlines()
            src_hits = self._find_hits(lines, sources)
            snk_hits = self._find_hits(lines, sinks)
            total_src += len(src_hits)
            total_snk += len(snk_hits)

            flows = self._correlate(filepath, lines, src_hits, snk_hits, sources, sinks)
            all_flows.extend(flows)

        return TaintReport(
            flows=all_flows,
            sources_found=total_src,
            sinks_found=total_snk,
            language=lang,
            files_analyzed=len(files),
            scan_time=time.time() - t0,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _sniff_directory(self, path: str) -> str:
        counts: Dict[str, int] = {}
        for f in Path(path).rglob("*"):
            lang = EXT_TO_LANG.get(f.suffix.lower())
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
        return max(counts, key=counts.get) if counts else "unknown"

    def _find_hits(self, lines: List[str], patterns: List) -> Dict[int, List]:
        """Return {line_number: [matched_items]}"""
        hits: Dict[int, list] = {}
        for i, line in enumerate(lines, 1):
            for pat in patterns:
                if re.search(pat.pattern, line):
                    hits.setdefault(i, []).append(pat)
        return hits

    def _correlate(
        self,
        filepath: str,
        lines: List[str],
        src_hits: Dict[int, list],
        snk_hits: Dict[int, list],
        sources: List[TaintSource],
        sinks: List[TaintSink],
    ) -> List[TaintFlow]:
        flows: List[TaintFlow] = []
        if not src_hits or not snk_hits:
            return flows

        # For each (source, sink) pair where source appears before sink
        for src_line, src_items in src_hits.items():
            for snk_line, snk_items in snk_hits.items():
                if snk_line <= src_line:
                    continue
                # Extract variable names from source line to check propagation
                src_text = lines[src_line - 1] if src_line <= len(lines) else ""
                snk_text = lines[snk_line - 1] if snk_line <= len(lines) else ""

                for src_item in src_items:
                    for snk_item in snk_items:
                        # Check if tainted variable appears in sink
                        tainted_vars = self._extract_lhs_vars(src_text)
                        propagated = any(v and v in snk_text for v in tainted_vars)

                        # Also check simple proximity (same function heuristic)
                        in_proximity = (snk_line - src_line) < 50

                        if not propagated and not in_proximity:
                            continue

                        sanitized = self._check_sanitized(lines, src_line, snk_line)
                        confidence = self._compute_confidence(
                            propagated, in_proximity, sanitized, snk_line - src_line
                        )

                        if confidence < 0.15:
                            continue

                        intermediate = self._extract_path(lines, src_line, snk_line)
                        flows.append(TaintFlow(
                            source=src_item,
                            sink=snk_item,
                            filepath=filepath,
                            source_line=src_line,
                            sink_line=snk_line,
                            path=intermediate,
                            sanitized=sanitized,
                            confidence=confidence,
                        ))
        return flows

    def _extract_lhs_vars(self, line: str) -> List[str]:
        """Try to extract variable name assigned on this line."""
        # pattern: type varname = expr; or auto varname = ...
        m = re.search(r'(?:auto|var|let(?:\s+mut)?|\w+)\s+(\w+)\s*[=:]', line)
        if m:
            return [m.group(1)]
        # C++ member: foo.bar_ = ...
        m2 = re.search(r'(\w+(?:\.\w+)?)\s*=', line)
        if m2:
            return [m2.group(1), m2.group(1).split(".")[-1]]
        return []

    def _check_sanitized(self, lines: List[str], src_line: int, snk_line: int) -> bool:
        for line in lines[src_line - 1: snk_line - 1]:
            for pat in SANITIZER_PATTERNS:
                if re.search(pat, line):
                    return True
        return False

    def _compute_confidence(
        self,
        propagated: bool,
        in_proximity: bool,
        sanitized: bool,
        distance: int,
    ) -> float:
        score = 0.0
        if propagated:
            score += 0.6
        if in_proximity:
            score += 0.25
        # distance penalty
        score -= min(distance / 200.0, 0.2)
        if sanitized:
            score *= 0.2
        return max(0.0, min(score, 1.0))

    def _extract_path(self, lines: List[str], src: int, snk: int) -> List[str]:
        """Return a short list of intermediate call/assign lines."""
        step_lines = []
        for i in range(src, min(snk, src + 20)):
            line = lines[i - 1].strip() if i <= len(lines) else ""
            if line and re.search(r'[=({]', line):
                step_lines.append(f"line {i}: {line[:80]}")
        return step_lines[:5]

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report(self, report: TaintReport) -> str:
        lines = [
            "=" * 70,
            "  TAINT ANALYSIS REPORT — SentinelOps Phase 15",
            "=" * 70,
            f"Language:        {report.language}",
            f"Files analyzed:  {report.files_analyzed}",
            f"Sources found:   {report.sources_found}",
            f"Sinks found:     {report.sinks_found}",
            f"Taint flows:     {len(report.flows)}",
            f"Scan time:       {report.scan_time:.2f}s",
            "",
        ]
        if not report.flows:
            lines.append("No taint flows detected.")
            return "\n".join(lines)

        # Group by severity
        by_sev: Dict[str, List[TaintFlow]] = {}
        for f in report.flows:
            by_sev.setdefault(f.sink.severity, []).append(f)

        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev not in by_sev:
                continue
            lines.append(f"\n[{sev}] — {len(by_sev[sev])} flow(s)")
            lines.append("-" * 50)
            for fl in by_sev[sev]:
                lines.append(f"  Source : {fl.source.name}  (line {fl.source_line})")
                lines.append(f"  Sink   : {fl.sink.name}  (line {fl.sink_line})")
                lines.append(f"  File   : {fl.filepath}")
                lines.append(f"  Conf.  : {fl.confidence:.0%}  Sanitized: {fl.sanitized}")
                lines.append(f"  Cat.   : {fl.sink.category}")
                if fl.path:
                    lines.append(f"  Path   : {fl.path[0]}")
                lines.append("")

        return "\n".join(lines)

    def trace_flow(self, source: TaintSource, ast: dict) -> List[TaintFlow]:
        """Stub for AST-based tracing (placeholder for future AST integration)."""
        return []
