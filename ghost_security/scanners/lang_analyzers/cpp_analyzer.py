"""Ghost Security Platform — C++ Security Analyzer (Phase 15)

Critical for Ethereum/TON/Solana node codebases. Covers the exact
vulnerability patterns found in TON validator source code.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path
from typing import List

from .base import LangFinding, LangAnalysisResult


class CppAnalyzer:
    """Security analyzer for C/C++ codebases.

    Runs cppcheck when available, then applies native rules covering:
    - Signed→unsigned cast without sign guard (the TON RLDP pattern)
    - Unbounded container growth in event loops
    - actor.release() without connection counter
    - Format string injection
    - Memory management errors
    - Assertion in network-input code paths
    """

    RULES = [
        # rule_id, title, pattern, severity, category, recommendation
        ("CP001", "Signed-to-unsigned cast without negative check (TON RLDP pattern)",
         r"static_cast\s*<\s*(?:td::)?u?int64(?:_t)?\s*>\s*\(\s*\w+(?:\.\w+)*_?\s*\)",
         "HIGH", "sign_confusion",
         "Add a sign guard before casting: if (val < 0) { return error; }. "
         "Negative int64 cast to uint64 yields UINT64_MAX, bypassing size checks."),
        ("CP002", "emplace_back / push_back in loop without size cap",
         r"(?:emplace_back|push_back)\s*\(",
         "HIGH", "resource_exhaustion",
         "Enforce a maximum size before calling emplace_back inside request-handling loops."),
        ("CP003", "Actor .release() without connection counter (TON liteserver pattern)",
         r"create_actor\s*<[^>]+>\s*\([^)]+\)\s*\.release\s*\(\)",
         "HIGH", "resource_exhaustion",
         "Track active actors with an atomic counter. Reject new connections when limit reached."),
        ("CP004", "printf/fprintf with non-literal format string",
         r'\b(?:printf|fprintf|sprintf|snprintf|vprintf)\s*\(\s*(?:stderr|stdout|[a-zA-Z_]\w*)\s*,\s*[a-zA-Z_]\w*\s*[,)]',
         "HIGH", "format_string",
         'Use a literal format string: printf("%s", user_str) not printf(user_str).'),
        ("CP005", "Signed/unsigned comparison (int vs size_t / uint)",
         r'if\s*\([^)]*(?:int|long)\s+\w+[^)]*[<>]=?\s*(?:size_t|uint|unsigned)',
         "MEDIUM", "sign_confusion",
         "Cast to the same type before comparison to avoid signed/unsigned wrap-around."),
        ("CP006", "Manual new without matching delete (potential leak)",
         r'\bnew\s+\w[\w:<>]*\s*(?:\([^)]*\))?\s*;',
         "MEDIUM", "memory_leak",
         "Prefer smart pointers (std::unique_ptr, std::shared_ptr) over raw new/delete."),
        ("CP007", "strlen / strcpy / strcat / gets usage (buffer overflow risk)",
         r'\b(?:strcpy|strcat|gets|sprintf)\s*\(',
         "HIGH", "buffer_overflow",
         "Use strlcpy/strlcat or std::string. Never use gets()."),
        ("CP008", "memcpy with attacker-controlled size",
         r'\bmemcpy\s*\([^,]+,[^,]+,\s*(?:message|msg|data|buf|input|recv)\w*\s*[,)]',
         "CRITICAL", "memory_write",
         "Validate size against destination buffer capacity before memcpy."),
        ("CP009", "CHECK / DCHECK / assert on network-controlled input",
         r'\b(?:CHECK|DCHECK|assert)\s*\([^)]*(?:message|msg|packet|data|recv|request)\w*',
         "HIGH", "crash_on_input",
         "Replace CHECK with proper error return. Assertions abort the process on failure."),
        ("CP010", "std::vector/map without size limit in actor/server context",
         r'(?:shard_client_waiters_|waiters_|pending_)\[\w+\]\.\w+\.emplace_back',
         "CRITICAL", "resource_exhaustion",
         "Cap the waiting_ vector before emplace_back. Use MAX_WAITERS constant."),
        ("CP011", "Accepted TCP connection without limit check",
         r'void\s+\w+::accepted\s*\([^)]*\)\s*\{[^}]*create_actor',
         "HIGH", "resource_exhaustion",
         "Track active_connections_ counter. Drop connections above MAX_CONNECTIONS."),
        ("CP012", "Integer overflow in multiplication used as buffer size",
         r'(?:malloc|new\s+\w+\[)\s*\(\s*\w+\s*\*\s*\w+\s*\)',
         "HIGH", "integer_overflow",
         "Check for overflow before multiplication: use checked_mul or compare against SIZE_MAX."),
        ("CP013", "std::map with unbounded key space (potential OOM)",
         r'std::map<[^>]+>\s+\w+_;',
         "MEDIUM", "resource_exhaustion",
         "Bound map size or use LRU eviction to prevent unbounded growth from attacker input."),
        ("CP014", "Use of rand() / srand() for security",
         r'\brand\s*\(\s*\)|\bsrand\s*\(',
         "HIGH", "weak_randomness",
         "Use a cryptographically secure PRNG (e.g., /dev/urandom, RAND_bytes) for security."),
        ("CP015", "Reinterpret_cast to incompatible type",
         r'\breinterpret_cast\s*<\s*(?:char|uint8_t)\s*\*\s*>',
         "MEDIUM", "undefined_behavior",
         "Ensure alignment and aliasing rules are respected. Prefer memcpy for type punning."),
    ]

    def __init__(self, cppcheck_path: str = "cppcheck"):
        self.cppcheck_path = cppcheck_path

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, path: str) -> LangAnalysisResult:
        t0 = time.time()
        findings: List[LangFinding] = []
        tool_available = False

        cppcheck_findings, tool_available = self.run_cppcheck(path)
        findings.extend(cppcheck_findings)

        native_findings = self.run_native(path)
        findings.extend(native_findings)

        # Deduplicate by (file, line, rule_id)
        seen: set = set()
        deduped: List[LangFinding] = []
        for f in findings:
            key = (f.filepath, f.line, f.rule_id)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        summary = self._summarize(deduped)
        return LangAnalysisResult(
            language="cpp",
            files_analyzed=len(self._collect_files(path)),
            findings=deduped,
            tool_available=tool_available,
            scan_time=time.time() - t0,
            summary=summary,
        )

    def run_cppcheck(self, path: str) -> tuple[List[LangFinding], bool]:
        try:
            result = subprocess.run(
                [self.cppcheck_path, "--enable=all", "--xml", "--xml-version=2", path],
                capture_output=True, text=True, timeout=120,
            )
            tool_available = True
            findings = self._parse_cppcheck_xml(result.stderr, path)
            return findings, True
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return [], False

    def _parse_cppcheck_xml(self, xml_output: str, base_path: str) -> List[LangFinding]:
        findings: List[LangFinding] = []
        # Simple regex XML parse to avoid lxml dependency
        pattern = re.compile(
            r'<error[^>]+id="([^"]+)"[^>]+severity="([^"]+)"[^>]+msg="([^"]+)"'
            r'(?:[^>]+file="([^"]+)")?(?:[^>]+line="([^"]+)")?',
            re.DOTALL,
        )
        sev_map = {"error": "HIGH", "warning": "MEDIUM", "style": "LOW",
                   "performance": "LOW", "portability": "LOW", "information": "INFO"}
        for m in pattern.finditer(xml_output):
            rid, sev_raw, msg, filepath, line = m.groups()
            findings.append(LangFinding(
                filepath=filepath or base_path,
                line=int(line) if line else 0,
                column=0,
                rule_id=f"CPPCHECK-{rid}",
                title=msg[:80],
                description=msg,
                severity=sev_map.get(sev_raw, "MEDIUM"),
                category=rid,
                code_snippet="",
                recommendation="Review cppcheck documentation for rule " + rid,
                tool="cppcheck",
                confidence=0.85,
            ))
        return findings

    def run_native(self, path: str) -> List[LangFinding]:
        findings: List[LangFinding] = []
        for filepath in self._collect_files(path):
            try:
                source = Path(filepath).read_text(errors="replace")
            except OSError:
                continue
            findings.extend(self.check_integer_overflow(source, filepath))
            findings.extend(self.check_memory_safety(source, filepath))
            findings.extend(self.check_format_string(source, filepath))
            findings.extend(self.check_signed_unsigned_mismatch(source, filepath))
            findings.extend(self.check_use_after_free(source, filepath))
            findings.extend(self.check_unbounded_operations(source, filepath))
        return findings

    # ------------------------------------------------------------------
    # Specific checks
    # ------------------------------------------------------------------

    def check_integer_overflow(self, source: str, filepath: str) -> List[LangFinding]:
        return self._apply_rules(source, filepath, ["CP001", "CP005", "CP012"])

    def check_memory_safety(self, source: str, filepath: str) -> List[LangFinding]:
        return self._apply_rules(source, filepath, ["CP006", "CP007", "CP008", "CP015"])

    def check_format_string(self, source: str, filepath: str) -> List[LangFinding]:
        return self._apply_rules(source, filepath, ["CP004"])

    def check_signed_unsigned_mismatch(self, source: str, filepath: str) -> List[LangFinding]:
        return self._apply_rules(source, filepath, ["CP001", "CP005"])

    def check_use_after_free(self, source: str, filepath: str) -> List[LangFinding]:
        # Pattern: pointer used after free() / delete
        findings: List[LangFinding] = []
        lines = source.splitlines()
        freed_vars: set = set()
        for i, line in enumerate(lines, 1):
            m = re.search(r'(?:free|delete(?:\s*\[\])?)\s*\(?\s*(\w+)', line)
            if m:
                freed_vars.add(m.group(1))
            for var in freed_vars:
                if re.search(r'\b' + re.escape(var) + r'\b', line) and not re.search(
                    r'(?:free|delete)\s*\(?\s*' + re.escape(var), line
                ):
                    findings.append(LangFinding(
                        filepath=filepath,
                        line=i,
                        column=0,
                        rule_id="CP-UAF",
                        title="Potential use-after-free",
                        description=f"Variable '{var}' used after free/delete.",
                        severity="CRITICAL",
                        category="use_after_free",
                        code_snippet=line.strip()[:120],
                        recommendation="Set pointer to nullptr after free. Use smart pointers.",
                        tool="native",
                        confidence=0.45,
                    ))
        return findings

    def check_toctou(self, source: str, filepath: str) -> List[LangFinding]:
        findings: List[LangFinding] = []
        lines = source.splitlines()
        check_funcs = re.compile(r'\b(?:access|stat|lstat|faccessat)\s*\(')
        use_funcs   = re.compile(r'\b(?:open|fopen|unlink|rename|chmod)\s*\(')
        last_check  = 0
        for i, line in enumerate(lines, 1):
            if check_funcs.search(line):
                last_check = i
            elif use_funcs.search(line) and 0 < i - last_check < 10:
                findings.append(LangFinding(
                    filepath=filepath,
                    line=i,
                    column=0,
                    rule_id="CP-TOCTOU",
                    title="TOCTOU race condition",
                    description="File checked then used — window for race condition.",
                    severity="HIGH",
                    category="toctou",
                    code_snippet=line.strip()[:120],
                    recommendation="Use O_CREAT|O_EXCL with open() instead of access()+open().",
                    tool="native",
                    confidence=0.6,
                ))
        return findings

    def check_unbounded_operations(self, source: str, filepath: str) -> List[LangFinding]:
        return self._apply_rules(source, filepath, ["CP002", "CP003", "CP010", "CP011", "CP013"])

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_rules(self, source: str, filepath: str, rule_ids: List[str]) -> List[LangFinding]:
        findings: List[LangFinding] = []
        lines = source.splitlines()
        rules = {r[0]: r for r in self.RULES}
        for rid in rule_ids:
            if rid not in rules:
                continue
            rule_id, title, pattern, severity, category, recommendation = rules[rid]
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    findings.append(LangFinding(
                        filepath=filepath,
                        line=i,
                        column=0,
                        rule_id=rule_id,
                        title=title,
                        description=f"Pattern matched at line {i}: {line.strip()[:100]}",
                        severity=severity,
                        category=category,
                        code_snippet=line.strip()[:120],
                        recommendation=recommendation,
                        tool="native",
                        confidence=0.75,
                    ))
        return findings

    def _collect_files(self, path: str) -> List[str]:
        p = Path(path)
        exts = {".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"}
        if p.is_file() and p.suffix.lower() in exts:
            return [str(p)]
        return [str(f) for f in p.rglob("*") if f.is_file() and f.suffix.lower() in exts]

    def _summarize(self, findings: List[LangFinding]) -> dict:
        s: dict = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            s[f.severity] = s.get(f.severity, 0) + 1
        return s
