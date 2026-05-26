"""Ghost Security Platform — Go Security Analyzer (Phase 15)"""

from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path
from typing import List

from .base import LangFinding, LangAnalysisResult


class GoAnalyzer:
    """Security analyzer for Go codebases.

    Runs gosec when available, then applies native pattern-based checks
    for command injection, SQL injection, crypto misuse, TLS misconfiguration,
    goroutine leaks, and SSRF.
    """

    RULES = [
        ("GO001", "Command injection via exec.Command with string concat",
         r"exec\.Command\s*\([^)]*\+[^)]*\)|exec\.Command\s*\([^)]*fmt\.Sprintf",
         "CRITICAL", "cmd_injection",
         "Build command arguments as separate strings, never via concatenation or Sprintf."),
        ("GO002", "SQL injection via fmt.Sprintf in query",
         r'db\.\s*(?:Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf|db\.\s*(?:Query|Exec|QueryRow)\s*\([^)]*\+',
         "CRITICAL", "sql_injection",
         "Use parameterized queries (db.Query(sql, args...)) instead of string formatting."),
        ("GO003", "Goroutine leak — go keyword without sync primitive",
         r'^\s*go\s+\w+\s*\(',
         "MEDIUM", "goroutine_leak",
         "Ensure goroutines terminate. Use WaitGroup, done channels, or context cancellation."),
        ("GO004", "Insecure TLS — InsecureSkipVerify",
         r'InsecureSkipVerify\s*:\s*true',
         "CRITICAL", "tls_misconfiguration",
         "Never set InsecureSkipVerify=true in production. Use proper certificate validation."),
        ("GO005", "Weak PRNG — math/rand for security",
         r'\bmath/rand\b|\brand\.Intn\b|\brand\.Int63\b',
         "HIGH", "weak_randomness",
         "Use crypto/rand for security-sensitive random values."),
        ("GO006", "SSRF — http.Get with user-controlled URL",
         r'http\.(?:Get|Post|Do)\s*\([^)]*\+[^)]*\)|http\.(?:Get|Post)\s*\([^)]*r\.',
         "HIGH", "ssrf",
         "Validate and allowlist URLs before making outbound HTTP requests."),
        ("GO007", "Path traversal — os.Open with string concat",
         r'os\.(?:Open|Create|OpenFile)\s*\([^)]*\+[^)]*\)',
         "HIGH", "path_traversal",
         "Use filepath.Clean and validate paths against a known base directory."),
        ("GO008", "Hardcoded credentials in source",
         r'(?:password|secret|token|apikey|api_key)\s*:?=\s*"[^"]{8,}"',
         "HIGH", "hardcoded_secret",
         "Store secrets in environment variables or a secrets manager, not source code."),
        ("GO009", "Unbounded goroutine creation in loop",
         r'for\s+[^{]*\{\s*\n[^\n]*\bgo\s+\w',
         "HIGH", "resource_exhaustion",
         "Bound goroutine creation with a worker pool or semaphore."),
        ("GO010", "Type assertion without ok check",
         r'\.\s*\(\s*\w[\w.]*\s*\)[^,\n]',
         "MEDIUM", "panic",
         "Use two-value type assertion (v, ok := x.(T)) to avoid panic on type mismatch."),
        ("GO011", "Defer in loop — resource leak",
         r'for\s+[^{]*\{[^}]*\bdefer\b',
         "MEDIUM", "resource_leak",
         "Avoid defer inside loops; call cleanup functions directly or extract to helper."),
        ("GO012", "SHA-1 / MD5 usage for security",
         r'crypto/md5|crypto/sha1|md5\.New\(\)|sha1\.New\(\)',
         "HIGH", "weak_algorithm",
         "Use SHA-256 or SHA-3 for security-sensitive hashing."),
        ("GO013", "Integer overflow in slice length computation",
         r'make\s*\(\s*\[\]byte\s*,\s*\w+\s*\*\s*\w+\s*\)',
         "MEDIUM", "integer_overflow",
         "Check for overflow before computing slice lengths with multiplication."),
        ("GO014", "Unhandled error return",
         r'^\s*\w[\w.]*\s*\([^)]*\)\s*$',
         "LOW", "error_handling",
         "Always check error return values. Use _ only when intentional and safe."),
    ]

    def __init__(self, gosec_path: str = "gosec"):
        self.gosec_path = gosec_path

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, path: str) -> LangAnalysisResult:
        t0 = time.time()
        findings: List[LangFinding] = []
        tool_available = False

        gosec_findings, tool_available = self.run_gosec(path)
        findings.extend(gosec_findings)

        native_findings = self.run_native(path)
        findings.extend(native_findings)

        summary = self._summarize(findings)
        return LangAnalysisResult(
            language="go",
            files_analyzed=len(self._collect_files(path)),
            findings=findings,
            tool_available=tool_available,
            scan_time=time.time() - t0,
            summary=summary,
        )

    def run_gosec(self, path: str) -> tuple[List[LangFinding], bool]:
        try:
            result = subprocess.run(
                [self.gosec_path, "-fmt=json", "./..."],
                cwd=path if Path(path).is_dir() else str(Path(path).parent),
                capture_output=True, text=True, timeout=120,
            )
            tool_available = True
            if not result.stdout.strip():
                return [], True
            data = json.loads(result.stdout)
            findings = []
            for issue in data.get("Issues", []):
                findings.append(LangFinding(
                    filepath=issue.get("file", path),
                    line=int(issue.get("line", 0)),
                    column=int(issue.get("column", 0)),
                    rule_id=issue.get("rule_id", "GOSEC"),
                    title=issue.get("details", "gosec finding"),
                    description=issue.get("details", ""),
                    severity=self._map_gosec_severity(issue.get("severity", "MEDIUM")),
                    category=issue.get("rule_id", "").lower(),
                    code_snippet=issue.get("code", ""),
                    recommendation="Review gosec rule documentation for fix guidance.",
                    tool="gosec",
                    confidence=float(issue.get("confidence", "MEDIUM") == "HIGH"),
                ))
            return findings, True
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            return [], False

    def run_native(self, path: str) -> List[LangFinding]:
        findings: List[LangFinding] = []
        for filepath in self._collect_files(path):
            try:
                source = Path(filepath).read_text(errors="replace")
            except OSError:
                continue
            findings.extend(self.check_command_injection(source, filepath))
            findings.extend(self.check_sql_injection(source, filepath))
            findings.extend(self.check_race_conditions(source, filepath))
            findings.extend(self.check_crypto_misuse(source, filepath))
            findings.extend(self.check_tls_config(source, filepath))
            findings.extend(self.check_goroutine_leaks(source, filepath))
        return findings

    # ------------------------------------------------------------------
    # Specific checks
    # ------------------------------------------------------------------

    def check_command_injection(self, source: str, filepath: str) -> List[LangFinding]:
        return self._apply_rules(source, filepath, ["GO001"])

    def check_sql_injection(self, source: str, filepath: str) -> List[LangFinding]:
        return self._apply_rules(source, filepath, ["GO002"])

    def check_race_conditions(self, source: str, filepath: str) -> List[LangFinding]:
        return self._apply_rules(source, filepath, ["GO003", "GO009", "GO011"])

    def check_crypto_misuse(self, source: str, filepath: str) -> List[LangFinding]:
        return self._apply_rules(source, filepath, ["GO005", "GO012"])

    def check_tls_config(self, source: str, filepath: str) -> List[LangFinding]:
        return self._apply_rules(source, filepath, ["GO004"])

    def check_goroutine_leaks(self, source: str, filepath: str) -> List[LangFinding]:
        return self._apply_rules(source, filepath, ["GO003", "GO009"])

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
                        description=f"Pattern matched: {line.strip()[:100]}",
                        severity=severity,
                        category=category,
                        code_snippet=line.strip()[:120],
                        recommendation=recommendation,
                        tool="native",
                        confidence=0.70,
                    ))
        return findings

    def _collect_files(self, path: str) -> List[str]:
        p = Path(path)
        if p.is_file() and p.suffix == ".go":
            return [str(p)]
        return [str(f) for f in p.rglob("*.go") if f.is_file()]

    def _summarize(self, findings: List[LangFinding]) -> dict:
        s: dict = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            s[f.severity] = s.get(f.severity, 0) + 1
        return s

    def _map_gosec_severity(self, sev: str) -> str:
        return {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}.get(sev.upper(), "MEDIUM")
