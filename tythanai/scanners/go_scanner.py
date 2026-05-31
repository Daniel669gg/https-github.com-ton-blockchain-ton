"""
TythanAI — Go SAST Scanner
===================================
Pattern-based static analysis for Go source files (.go).

Covers 12 vulnerability classes including SQL injection, command injection,
path traversal, hardcoded secrets, TLS verification bypass, HTTP server
misconfiguration, weak RNG, integer overflow, unrecovered panics, unsafe
package usage, SSRF, and defer-in-loop resource leaks.

_test.go files are skipped for most patterns (exceptions: GO-001, GO-002,
GO-005, which are relevant even in test files).

Usage::

    from scanners.go_scanner import GoScanner

    scanner = GoScanner()

    # Scan a single file
    findings = scanner.scan_file("/path/to/handler.go")

    # Scan a whole module
    result = scanner.scan_directory("/path/to/module")
    print(result["total_findings"])
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Pattern definition dataclass
# ---------------------------------------------------------------------------

@dataclass
class _GoPattern:
    """Internal representation of a single Go vulnerability pattern."""

    id: str
    severity: str
    cwe: str
    regex: str
    message: str
    description: str
    recommendation: str
    # When True this pattern is applied even to _test.go files
    apply_in_tests: bool = False
    confidence: int = 75
    _compiled: Optional[re.Pattern[str]] = field(default=None, init=False, repr=False)

    def compiled(self) -> re.Pattern[str]:
        """Return (lazily) the compiled regular expression."""
        if self._compiled is None:
            self._compiled = re.compile(self.regex, re.MULTILINE | re.DOTALL)
        return self._compiled


# ---------------------------------------------------------------------------
# Vulnerability patterns
# ---------------------------------------------------------------------------

_PATTERNS: List[_GoPattern] = [
    _GoPattern(
        id="GO-001",
        severity="CRITICAL",
        cwe="CWE-89",
        regex=r'db\.(Query|Exec|QueryRow)\s*\(\s*fmt\.Sprintf',
        message="SQL injection via fmt.Sprintf in db.Query/Exec/QueryRow",
        description=(
            "A SQL query is constructed using fmt.Sprintf and passed directly to "
            "a database method. If any Sprintf argument is user-controlled, an "
            "attacker can alter the SQL statement to bypass authentication, "
            "exfiltrate data, or corrupt the database."
        ),
        recommendation=(
            "Use parameterised queries with '?' or '$N' placeholders: "
            "db.Query(\"SELECT * FROM users WHERE id = ?\", userID). "
            "Never build SQL strings through string formatting functions."
        ),
        apply_in_tests=True,
        confidence=85,
    ),
    _GoPattern(
        id="GO-002",
        severity="HIGH",
        cwe="CWE-78",
        regex=r'exec\.Command\s*\([^)]*\+|exec\.Command\s*\([^)]*fmt\.Sprintf',
        message="Command injection — exec.Command argument built via string concatenation or fmt.Sprintf",
        description=(
            "exec.Command is called with an argument assembled through string "
            "concatenation or fmt.Sprintf. When any part of the command or its "
            "arguments originates from user input, an attacker can inject "
            "additional shell commands or arguments."
        ),
        recommendation=(
            "Pass each argument as a separate string to exec.Command rather than "
            "building a single concatenated string: exec.Command(\"ls\", \"-la\", dir). "
            "Validate and allowlist each argument value before use."
        ),
        apply_in_tests=True,
        confidence=80,
    ),
    _GoPattern(
        id="GO-003",
        severity="HIGH",
        cwe="CWE-22",
        regex=r'filepath\.Join\s*\([^)]*(?:r\.URL|request|param|user)|os\.Open\s*\([^)]*\+',
        message="Path traversal — filepath.Join or os.Open constructed from user input",
        description=(
            "A file path is assembled using user-supplied values (URL, request "
            "parameter, 'user' or 'param' variable). An attacker can embed '../' "
            "sequences to escape the intended directory and read or write "
            "arbitrary files on the server."
        ),
        recommendation=(
            "After constructing the path, call filepath.Clean and verify it has "
            "the expected base directory prefix before opening. Reject any path "
            "that does not start within the allowed root."
        ),
        confidence=75,
    ),
    _GoPattern(
        id="GO-004",
        severity="HIGH",
        cwe="CWE-798",
        regex=r'(?:password|secret|apiKey|token)\s*(?::=|=)\s*"[^"]{6,}"',
        message="Hardcoded secret, password, API key, or token",
        description=(
            "A variable whose name indicates a credential is assigned a hardcoded "
            "string literal of six or more characters. This secret is exposed to "
            "anyone with access to the source code or version control history."
        ),
        recommendation=(
            "Load credentials from environment variables (os.Getenv), a secrets "
            "manager, or an encrypted configuration file that is excluded from "
            "version control via .gitignore."
        ),
        confidence=80,
    ),
    _GoPattern(
        id="GO-005",
        severity="HIGH",
        cwe="CWE-295",
        regex=r'InsecureSkipVerify\s*:\s*true',
        message="TLS certificate verification disabled (InsecureSkipVerify: true)",
        description=(
            "Setting InsecureSkipVerify to true in a tls.Config disables all "
            "certificate and hostname verification, making TLS connections "
            "completely vulnerable to man-in-the-middle attacks."
        ),
        recommendation=(
            "Remove InsecureSkipVerify or set it to false. If a custom CA is "
            "needed, load it into a x509.CertPool and set tls.Config.RootCAs. "
            "Never disable verification in production code."
        ),
        apply_in_tests=True,
        confidence=95,
    ),
    _GoPattern(
        id="GO-006",
        severity="MEDIUM",
        cwe="CWE-400",
        regex=r'http\.ListenAndServe\s*\(|&http\.Server\{(?![^}]*Timeout)',
        message="HTTP server started without read/write timeouts",
        description=(
            "http.ListenAndServe or an http.Server struct is used without "
            "configuring ReadTimeout, WriteTimeout, and IdleTimeout. A slow or "
            "malicious client can hold open connections indefinitely, exhausting "
            "server resources (Slowloris-style denial of service)."
        ),
        recommendation=(
            "Always configure timeouts on http.Server: "
            "ReadTimeout, ReadHeaderTimeout, WriteTimeout, IdleTimeout. "
            "Typical safe values are 5–30 seconds depending on the workload."
        ),
        confidence=70,
    ),
    _GoPattern(
        id="GO-007",
        severity="MEDIUM",
        cwe="CWE-330",
        regex=r'\"math/rand\"|rand\.Intn\s*\(|rand\.Float',
        message="Weak RNG — math/rand used instead of crypto/rand",
        description=(
            "math/rand produces deterministic, predictable sequences seeded "
            "from a small integer. Using it for security-sensitive values "
            "(tokens, nonces, session IDs, OTPs) allows attackers who know "
            "or can guess the seed to predict all generated values."
        ),
        recommendation=(
            "Use crypto/rand for all security-sensitive random number generation. "
            "For integer ranges use crypto/rand.Int with big.NewInt, or "
            "math/big.Int.Rand with a crypto/rand source."
        ),
        confidence=70,
    ),
    _GoPattern(
        id="GO-008",
        severity="MEDIUM",
        cwe="CWE-190",
        regex=r'int(?:32|16|8)\s*\(\s*(?:user|input|request|param)',
        message="Integer overflow — unchecked narrowing conversion from user input",
        description=(
            "A value whose name implies user origin is cast to a smaller integer "
            "type (int8, int16, int32) without range validation. Values outside "
            "the target type's range silently wrap around, potentially causing "
            "logic errors, buffer over-reads, or security bypasses."
        ),
        recommendation=(
            "Validate that the input value falls within the valid range for the "
            "target type before casting. Return an error or reject the input if "
            "it is out of range."
        ),
        confidence=70,
    ),
    _GoPattern(
        id="GO-009",
        severity="LOW",
        cwe="CWE-400",
        regex=r'\bpanic\s*\(',
        message="Explicit panic call — may crash the service in production",
        description=(
            "An explicit panic() call was found. In a production HTTP or gRPC "
            "server, an unrecovered panic in a goroutine crashes the entire "
            "process unless a recovery middleware is in place, causing a denial "
            "of service."
        ),
        recommendation=(
            "Replace panic() with proper error returns. If a panic cannot be "
            "avoided (e.g. programming error detected at startup), ensure a "
            "recover() middleware is registered for all request handlers."
        ),
        confidence=60,
    ),
    _GoPattern(
        id="GO-010",
        severity="MEDIUM",
        cwe="CWE-119",
        regex=r'\bunsafe\.Pointer\b|\bunsafe\.Sizeof\b',
        message="Use of unsafe package — potential memory corruption",
        description=(
            "The unsafe package bypasses Go's type and memory safety guarantees. "
            "Incorrect use of unsafe.Pointer can cause memory corruption, "
            "data races, or undefined behaviour that is exploitable by attackers."
        ),
        recommendation=(
            "Avoid the unsafe package wherever possible. If required for "
            "performance-critical interop with C code, restrict usage to a "
            "dedicated package, document the invariants carefully, and audit "
            "every usage site."
        ),
        confidence=75,
    ),
    _GoPattern(
        id="GO-011",
        severity="HIGH",
        cwe="CWE-918",
        regex=r'http\.(?:Get|Post)\s*\(\s*(?!")[^)]*\)',
        message="SSRF risk — http.Get/Post called with a variable URL",
        description=(
            "http.Get or http.Post is invoked with a URL that is not a string "
            "literal. If the URL is derived from user input, an attacker can "
            "direct the server to make requests to internal services, cloud "
            "metadata endpoints, or other restricted resources."
        ),
        recommendation=(
            "Validate the URL against an allowlist of permitted schemes, hosts, "
            "and ports before making the request. Use a custom http.Client with "
            "a dial hook that enforces network-level restrictions."
        ),
        confidence=70,
    ),
    _GoPattern(
        id="GO-012",
        severity="LOW",
        cwe="CWE-400",
        regex=r'for\s+[^\n{]*\{[^}]{0,300}defer\s+',
        message="Defer statement inside a loop — resource leak risk",
        description=(
            "A defer statement is used inside a loop body. Deferred calls are "
            "not executed until the surrounding function returns, so resources "
            "(file handles, database connections, mutexes) opened in each "
            "iteration accumulate until the function exits, potentially "
            "exhausting system resources."
        ),
        recommendation=(
            "Extract the loop body into a helper function so that each deferred "
            "call executes at the end of the helper's scope, or explicitly close "
            "resources within the loop instead of deferring them."
        ),
        confidence=65,
    ),
]

# Patterns applied even to _test.go files
_TEST_EXEMPT_IDS: Set[str] = {
    p.id for p in _PATTERNS if p.apply_in_tests
}

# Quick lookup by ID
_PATTERN_BY_ID: Dict[str, _GoPattern] = {p.id: p for p in _PATTERNS}


# ---------------------------------------------------------------------------
# GoScanner
# ---------------------------------------------------------------------------

class GoScanner:
    """Static analysis scanner for Go source files.

    Applies regex-based vulnerability patterns to .go files and returns
    structured finding dicts compatible with the TythanAI platform.

    _test.go files are skipped by default, except for patterns explicitly
    marked with ``apply_in_tests=True`` (GO-001, GO-002, GO-005).
    """

    def __init__(self) -> None:
        # Pre-compile all patterns once at construction time
        for p in _PATTERNS:
            p.compiled()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a single Go source file and return a list of finding dicts.

        Parameters
        ----------
        file_path:
            Absolute or relative path to a .go source file.

        Returns
        -------
        list[dict]
            One dict per finding.  Returns an empty list when no issues
            are found or the file cannot be read.
        """
        path = Path(file_path)
        if not path.is_file():
            return []

        is_test_file = path.name.endswith("_test.go")

        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        lines = source.splitlines()
        findings: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, int]] = set()

        for pattern in _PATTERNS:
            # Skip non-exempt patterns for test files
            if is_test_file and pattern.id not in _TEST_EXEMPT_IDS:
                continue

            for match in pattern.compiled().finditer(source):
                line_no = source[: match.start()].count("\n") + 1
                dedup_key = (pattern.id, line_no)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                raw_line = lines[line_no - 1] if line_no <= len(lines) else ""

                # Skip lines that are pure Go single-line comments
                stripped_line = raw_line.lstrip()
                if stripped_line.startswith("//"):
                    continue

                evidence = raw_line.strip()[:120]
                findings.append(
                    self._make_finding(
                        pattern=pattern,
                        file_path=str(path),
                        line_no=line_no,
                        evidence=evidence,
                    )
                )

        return findings

    def scan_directory(
        self,
        directory: str,
        max_files: int = 300,
    ) -> Dict[str, Any]:
        """Recursively scan all .go files in *directory*.

        Parameters
        ----------
        directory:
            Root directory to walk.
        max_files:
            Maximum number of Go files to scan (safety limit).

        Returns
        -------
        dict
            Summary dict with keys:
            ``files_scanned``, ``total_findings``, ``severity_counts``,
            ``findings``, ``scanner``.
        """
        root = Path(directory)
        all_findings: List[Dict[str, Any]] = []
        files_scanned = 0
        severity_counts: Dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

        for go_file in self._iter_go_files(root, max_files):
            file_findings = self.scan_file(str(go_file))
            all_findings.extend(file_findings)
            files_scanned += 1
            for f in file_findings:
                sev = f.get("severity", "INFO")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "files_scanned": files_scanned,
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "findings": all_findings,
            "scanner": "go",
        }

    def pattern_count(self) -> int:
        """Return the total number of vulnerability patterns registered."""
        return len(_PATTERNS)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _iter_go_files(self, root: Path, limit: int):
        """Yield up to *limit* .go files under *root*."""
        count = 0
        for path in root.rglob("*.go"):
            if count >= limit:
                break
            if path.is_file():
                yield path
                count += 1

    @staticmethod
    def _make_finding(
        pattern: _GoPattern,
        file_path: str,
        line_no: int,
        evidence: str,
    ) -> Dict[str, Any]:
        """Build a standardised TythanAI finding dict."""
        return {
            # Identity
            "type": pattern.id,
            "id": pattern.id,
            # Severity / classification
            "severity": pattern.severity,
            "cwe": pattern.cwe,
            # Location
            "file": file_path,
            "line": line_no,
            # Human-readable
            "message": pattern.message,
            "description": pattern.description,
            "evidence": evidence,
            "recommendation": pattern.recommendation,
            # Scanner metadata
            "source": "go_scanner",
            "scanner": "go",
            "confidence": pattern.confidence,
        }
