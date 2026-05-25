"""
Ghost Security — Java SAST Scanner
====================================
Pattern-based static analysis for Java source files (.java).

Covers 12 vulnerability classes including SQL injection, XXE, insecure
deserialization, JNDI injection (Log4Shell), path traversal, hardcoded
credentials, weak cryptography, insecure HTTP redirect, command execution,
null-pointer risk, and missing Spring authorisation.

Usage::

    from scanners.java_scanner import JavaScanner

    scanner = JavaScanner()

    # Scan a single file
    findings = scanner.scan_file("/path/to/Example.java")

    # Scan a whole directory tree
    result = scanner.scan_directory("/path/to/project")
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
class _JavaPattern:
    """Internal representation of a single Java vulnerability pattern."""

    id: str
    severity: str
    cwe: str
    regex: str
    message: str
    description: str
    recommendation: str
    confidence: int = 75
    # Compiled form populated on first use
    _compiled: Optional[re.Pattern[str]] = field(default=None, init=False, repr=False)

    def compiled(self) -> re.Pattern[str]:
        """Return (lazily) the compiled pattern."""
        if self._compiled is None:
            self._compiled = re.compile(self.regex, re.MULTILINE | re.DOTALL)
        return self._compiled


# ---------------------------------------------------------------------------
# Vulnerability patterns
# ---------------------------------------------------------------------------

_PATTERNS: List[_JavaPattern] = [
    _JavaPattern(
        id="JAVA-001",
        severity="CRITICAL",
        cwe="CWE-89",
        regex=r'executeQuery\s*\(\s*".*?\+|executeUpdate\s*\(\s*".*?\+|prepareStatement\s*\(\s*".*?\+',
        message="Potential SQL injection via string concatenation in JDBC call",
        description=(
            "SQL query is built by concatenating a string literal with a variable. "
            "User-controlled input appended to a SQL string allows attackers to "
            "manipulate the query logic, bypass authentication, or exfiltrate data."
        ),
        recommendation=(
            "Use parameterised PreparedStatement with '?' placeholders for all "
            "user-supplied values. Never concatenate untrusted data into SQL strings."
        ),
        confidence=80,
    ),
    _JavaPattern(
        id="JAVA-002",
        severity="HIGH",
        cwe="CWE-611",
        regex=r'DocumentBuilderFactory\.newInstance\(\)(?![\s\S]{0,300}setFeature[\s\S]{0,100}FEATURE_SECURE_PROCESSING)',
        message="XML parsing without disabling external entities (XXE)",
        description=(
            "DocumentBuilderFactory.newInstance() is called without subsequently "
            "disabling external entity processing. An attacker may supply a crafted "
            "XML document that reads local files or initiates server-side requests."
        ),
        recommendation=(
            "Call dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true) and "
            "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true) "
            "immediately after creating the factory."
        ),
        confidence=70,
    ),
    _JavaPattern(
        id="JAVA-003",
        severity="HIGH",
        cwe="CWE-502",
        regex=r'\bnew\s+ObjectInputStream\b',
        message="Insecure deserialization via ObjectInputStream",
        description=(
            "Java's native ObjectInputStream.readObject() deserialises arbitrary "
            "class graphs, which can be exploited via gadget chains to achieve "
            "remote code execution if the input is not from a fully trusted source."
        ),
        recommendation=(
            "Avoid deserialising untrusted data. If required, use a validating "
            "ObjectInputStream subclass (e.g. Apache Commons IO ValidatingObjectInputStream) "
            "that whitelists allowed classes, or switch to a safe serialisation format "
            "such as JSON or Protocol Buffers."
        ),
        confidence=75,
    ),
    _JavaPattern(
        id="JAVA-004",
        severity="CRITICAL",
        cwe="CWE-74",
        regex=r'\bInitialContext\b|\bjndi:|lookup\s*\(',
        message="Potential JNDI injection (Log4Shell / RCE pattern)",
        description=(
            "Use of JNDI InitialContext, a jndi: URI, or a JNDI lookup call "
            "may allow attackers to supply a malicious JNDI URL leading to "
            "remote class loading and arbitrary code execution (Log4Shell, CVE-2021-44228)."
        ),
        recommendation=(
            "Do not pass user-controlled data to JNDI lookups. Upgrade Log4j to "
            ">= 2.17.1 and set log4j2.formatMsgNoLookups=true. Disable JNDI lookups "
            "in the JVM with -Dcom.sun.jndi.rmi.object.trustURLCodebase=false."
        ),
        confidence=70,
    ),
    _JavaPattern(
        id="JAVA-005",
        severity="HIGH",
        cwe="CWE-22",
        regex=r'new\s+File\s*\(\s*(?:request\.|user|input|param)',
        message="Potential path traversal — new File() constructed from user input",
        description=(
            "A File object is constructed using a value that appears to originate "
            "from user input (request parameter, user variable, etc.). An attacker "
            "can supply '../' sequences to access files outside the intended directory."
        ),
        recommendation=(
            "Canonicalise the path with File.getCanonicalPath() and verify it starts "
            "with the expected base directory before use. Reject inputs containing "
            "'..', null bytes, or absolute path separators."
        ),
        confidence=75,
    ),
    _JavaPattern(
        id="JAVA-006",
        severity="HIGH",
        cwe="CWE-798",
        regex=r'(?:password|passwd|secret)\s*=\s*"[^"]{4,}"',
        message="Hardcoded password or secret in source code",
        description=(
            "A password or secret value is hardcoded as a string literal. Anyone "
            "with access to the source code, compiled bytecode, or version control "
            "history can retrieve the credential."
        ),
        recommendation=(
            "Store credentials in environment variables, a secrets manager "
            "(e.g. HashiCorp Vault, AWS Secrets Manager), or an encrypted "
            "configuration file that is excluded from version control."
        ),
        confidence=80,
    ),
    _JavaPattern(
        id="JAVA-007",
        severity="MEDIUM",
        cwe="CWE-330",
        regex=r'\bnew\s+Random\s*\(\s*\)',
        message="Insecure random number generator (java.util.Random) used for security-sensitive purpose",
        description=(
            "java.util.Random is a predictable, non-cryptographically-secure PRNG. "
            "Using it for security tokens, session identifiers, OTPs, or password "
            "reset codes allows attackers to predict future values."
        ),
        recommendation=(
            "Replace with java.security.SecureRandom for any security-sensitive "
            "random value generation. Prefer SecureRandom.getInstanceStrong() where "
            "blocking behaviour is acceptable."
        ),
        confidence=75,
    ),
    _JavaPattern(
        id="JAVA-008",
        severity="MEDIUM",
        cwe="CWE-327",
        regex=r'MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)"',
        message="Use of weak cryptographic hash (MD5 or SHA-1)",
        description=(
            "MD5 and SHA-1 are cryptographically broken and unsuitable for "
            "security purposes such as password hashing, digital signatures, "
            "or integrity verification."
        ),
        recommendation=(
            "Use SHA-256 or SHA-3 for general hashing. For password storage use "
            "BCrypt, SCrypt, or Argon2 via a dedicated password-hashing library."
        ),
        confidence=90,
    ),
    _JavaPattern(
        id="JAVA-009",
        severity="MEDIUM",
        cwe="CWE-601",
        regex=r'sendRedirect\s*\(\s*(?:request\.|param|user|input)',
        message="HTTP redirect destination derived from user input (open redirect)",
        description=(
            "response.sendRedirect() is called with a value that appears to come "
            "from user-controlled input. An attacker can supply an external URL "
            "to redirect victims to a phishing or malware site."
        ),
        recommendation=(
            "Maintain a whitelist of permitted redirect destinations and validate "
            "the target URL against it before redirecting. Reject or encode "
            "URLs that do not begin with an expected path or domain."
        ),
        confidence=75,
    ),
    _JavaPattern(
        id="JAVA-010",
        severity="HIGH",
        cwe="CWE-78",
        regex=r'Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\(',
        message="OS command execution via Runtime.exec or ProcessBuilder",
        description=(
            "Shell commands are executed via Runtime.getRuntime().exec() or "
            "ProcessBuilder. If any part of the command is derived from user "
            "input, an attacker may inject additional commands (command injection)."
        ),
        recommendation=(
            "Avoid executing shell commands. If unavoidable, use a fixed command "
            "array without a shell interpreter (ProcessBuilder with a list, not a "
            "single string) and rigorously validate every argument against an "
            "allowlist of safe values."
        ),
        confidence=75,
    ),
    _JavaPattern(
        id="JAVA-011",
        severity="MEDIUM",
        cwe="CWE-476",
        regex=r'\.get(?:Parameter|Header|Attribute)\s*\([^)]+\)\s*\.',
        message="Null pointer dereference risk — no null check after getParameter/getHeader/getAttribute",
        description=(
            "getParameter(), getHeader(), and getAttribute() return null when the "
            "named value is absent. Chaining a method call directly on the return "
            "value without a null check will throw a NullPointerException when the "
            "parameter is missing, potentially causing a denial of service."
        ),
        recommendation=(
            "Assign the return value to a local variable, check for null (or use "
            "Optional), and handle the absent case before calling any method on it."
        ),
        confidence=70,
    ),
    _JavaPattern(
        id="JAVA-012",
        severity="MEDIUM",
        cwe="CWE-284",
        regex=r'@(?:Get|Post|Put|Delete|Request)Mapping(?![\s\S]{0,200}@PreAuthorize)',
        message="Spring MVC endpoint without @PreAuthorize access control",
        description=(
            "A Spring MVC mapping annotation (@GetMapping, @PostMapping, etc.) was "
            "found without a corresponding @PreAuthorize annotation within the "
            "following 200 characters. The endpoint may be accessible without "
            "authentication or authorisation checks."
        ),
        recommendation=(
            "Annotate each controller method with @PreAuthorize(\"hasRole('ROLE_...')\") "
            "or configure method security globally via a SecurityFilterChain. "
            "Ensure Spring Security's @EnableMethodSecurity is active."
        ),
        confidence=65,
    ),
]

# Build a quick lookup by ID
_PATTERN_BY_ID: Dict[str, _JavaPattern] = {p.id: p for p in _PATTERNS}


# ---------------------------------------------------------------------------
# JavaScanner
# ---------------------------------------------------------------------------

class JavaScanner:
    """Static analysis scanner for Java source files.

    Applies regex-based vulnerability patterns to .java files and returns
    structured finding dicts compatible with the Ghost Security platform.
    """

    _JAVA_EXTENSIONS: Tuple[str, ...] = (".java",)

    def __init__(self) -> None:
        # Pre-compile all patterns once
        for p in _PATTERNS:
            p.compiled()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a single Java file and return a list of finding dicts.

        Parameters
        ----------
        file_path:
            Absolute or relative path to a .java source file.

        Returns
        -------
        list[dict]
            One dict per finding.  Returns an empty list when no issues
            are found or the file cannot be read.
        """
        path = Path(file_path)
        if not path.is_file():
            return []

        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        lines = source.splitlines()
        findings: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, int]] = set()

        for pattern in _PATTERNS:
            for match in pattern.compiled().finditer(source):
                line_no = source[: match.start()].count("\n") + 1
                dedup_key = (pattern.id, line_no)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                raw_line = lines[line_no - 1] if line_no <= len(lines) else ""

                # Skip lines that are pure Java single-line comments
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
        """Recursively scan all .java files in *directory*.

        Parameters
        ----------
        directory:
            Root directory to walk.
        max_files:
            Maximum number of Java files to scan (safety limit).

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

        for java_file in self._iter_java_files(root, max_files):
            file_findings = self.scan_file(str(java_file))
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
            "scanner": "java",
        }

    def pattern_count(self) -> int:
        """Return the total number of vulnerability patterns registered."""
        return len(_PATTERNS)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _iter_java_files(self, root: Path, limit: int):
        """Yield up to *limit* .java files under *root*."""
        count = 0
        for path in root.rglob("*.java"):
            if count >= limit:
                break
            if path.is_file():
                yield path
                count += 1

    @staticmethod
    def _make_finding(
        pattern: _JavaPattern,
        file_path: str,
        line_no: int,
        evidence: str,
    ) -> Dict[str, Any]:
        """Build a standardised Ghost Security finding dict."""
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
            "source": "java_scanner",
            "scanner": "java",
            "confidence": pattern.confidence,
        }
