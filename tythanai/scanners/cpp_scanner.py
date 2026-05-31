"""
TythanAI — C/C++ SAST Scanner

Pattern-based static analysis for C and C++ source files.
Covers memory safety, format strings, integer overflow, race conditions,
dangerous functions, crypto weaknesses, and TON/blockchain-specific patterns.

30+ vulnerability patterns across 8 categories.

Usage:
    from scanners.cpp_scanner import CppScanner
    scanner  = CppScanner()
    findings = scanner.scan_file("/path/to/file.cpp")
    result   = scanner.scan_directory("/path/to/project")
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

# ── Vulnerability pattern definition ─────────────────────────────────────────

@dataclass
class CppPattern:
    id:             str
    category:       str
    severity:       str
    cwe:            str
    regex:          str
    message:        str
    recommendation: str
    # Lines that make the match a false positive (e.g. comments)
    fp_context:     List[str] = field(default_factory=list)
    # If True, the pattern must NOT match this string to fire
    negative_lookahead: Optional[str] = None
    confidence:     int = 80


_PATTERNS: List[CppPattern] = [

    # ── Memory Safety — CWE-120 Buffer Overflow ───────────────────────────────

    CppPattern(
        id="CPP-001", category="Memory Safety", severity="CRITICAL",
        cwe="CWE-120",
        regex=r'\bgets\s*\(',
        message="gets() has no bounds checking — always causes buffer overflow",
        recommendation="Replace with fgets(buf, sizeof(buf), stdin) or getline()",
        confidence=95,
    ),
    CppPattern(
        id="CPP-002", category="Memory Safety", severity="HIGH",
        cwe="CWE-120",
        regex=r'\bstrcpy\s*\(',
        message="strcpy() does not check destination buffer size — use strncpy() or strlcpy()",
        recommendation="Use strncpy(dst, src, sizeof(dst)-1) or strlcpy(dst, src, sizeof(dst))",
        confidence=85,
    ),
    CppPattern(
        id="CPP-003", category="Memory Safety", severity="HIGH",
        cwe="CWE-120",
        regex=r'\bstrcat\s*\(',
        message="strcat() does not check destination buffer size — use strncat()",
        recommendation="Use strncat(dst, src, sizeof(dst)-strlen(dst)-1) or strlcat()",
        confidence=85,
    ),
    CppPattern(
        id="CPP-004", category="Memory Safety", severity="HIGH",
        cwe="CWE-120",
        regex=r'\bsprintf\s*\(',
        message="sprintf() has no bounds checking — use snprintf()",
        recommendation="Replace sprintf(buf, ...) with snprintf(buf, sizeof(buf), ...)",
        confidence=85,
    ),
    CppPattern(
        id="CPP-005", category="Memory Safety", severity="HIGH",
        cwe="CWE-120",
        regex=r'\bvsprintf\s*\(',
        message="vsprintf() has no bounds checking — use vsnprintf()",
        recommendation="Replace vsprintf(buf, fmt, ap) with vsnprintf(buf, size, fmt, ap)",
        confidence=85,
    ),
    CppPattern(
        id="CPP-006", category="Memory Safety", severity="HIGH",
        cwe="CWE-120",
        regex=r'\bscanf\s*\([^)]*"%s"',
        message='scanf("%s") reads unbounded input — use scanf("%Ns", buf) with a field width',
        recommendation="Use scanf(\"%255s\", buf) or fgets() + sscanf()",
        confidence=90,
    ),
    CppPattern(
        id="CPP-007", category="Memory Safety", severity="HIGH",
        cwe="CWE-120",
        regex=r'\bwcscpy\s*\(',
        message="wcscpy() does not check destination size — use wcsncpy()",
        recommendation="Use wcsncpy(dst, src, dst_size) ensuring null termination",
        confidence=80,
    ),
    CppPattern(
        id="CPP-008", category="Memory Safety", severity="HIGH",
        cwe="CWE-126",
        regex=r'\bstrlen\s*\([^)]*\)\s*\+\s*\d',
        message="strlen() + constant before malloc may overflow — use safer size calculation",
        recommendation="Check for integer overflow: if (len > SIZE_MAX - EXTRA) handle_error();",
        confidence=70,
    ),

    # ── Format String — CWE-134 ────────────────────────────────────────────────

    CppPattern(
        id="CPP-010", category="Format String", severity="CRITICAL",
        cwe="CWE-134",
        regex=r'\b(?:printf|fprintf|syslog|wprintf)\s*\(\s*(?:[a-zA-Z_]\w*)\s*[,)]',
        message="printf(user_str) — format string vulnerability if first arg is user-controlled",
        recommendation="Always use printf(\"%s\", str) — never pass user data as format string",
        confidence=75,
    ),
    CppPattern(
        id="CPP-011", category="Format String", severity="HIGH",
        cwe="CWE-134",
        regex=r'\bsnprintf\s*\([^,]+,\s*[^,]+,\s*[a-zA-Z_]\w*\s*[,)]',
        message="snprintf() with variable format string — potential format string attack",
        recommendation="Use a literal format string: snprintf(buf, size, \"%s\", user_str)",
        confidence=65,
    ),

    # ── Command Injection — CWE-78 ────────────────────────────────────────────

    CppPattern(
        id="CPP-020", category="Command Injection", severity="CRITICAL",
        cwe="CWE-78",
        regex=r'\bsystem\s*\(',
        message="system() passes command to shell — dangerous if any argument is user-controlled",
        recommendation="Use execve() with explicit argument array and shell=false",
        confidence=80,
    ),
    CppPattern(
        id="CPP-021", category="Command Injection", severity="CRITICAL",
        cwe="CWE-78",
        regex=r'\bpopen\s*\(',
        message="popen() passes command to shell — use safer alternatives",
        recommendation="Use posix_spawn() or fork()+exec() with explicit argument array",
        confidence=80,
    ),
    CppPattern(
        id="CPP-022", category="Command Injection", severity="HIGH",
        cwe="CWE-78",
        regex=r'\bexecl\s*\([^)]*"[^"]*%[sd]',
        message="execl() with format string in path — potential command injection",
        recommendation="Never use format specifiers in exec() path; validate all inputs",
        confidence=75,
    ),

    # ── Integer Overflow — CWE-190 ────────────────────────────────────────────

    CppPattern(
        id="CPP-030", category="Integer Overflow", severity="HIGH",
        cwe="CWE-190",
        regex=r'\bmalloc\s*\(\s*(?:\w+\s*\*\s*\w+|\w+\s*\+\s*\w+)\s*\)',
        message="malloc() with arithmetic argument — may overflow and allocate too-small buffer",
        recommendation="Check for overflow before allocation: if (a > SIZE_MAX/b) error(); malloc(a*b);",
        confidence=70,
    ),
    CppPattern(
        id="CPP-031", category="Integer Overflow", severity="HIGH",
        cwe="CWE-190",
        regex=r'\bnew\s*\[\s*(?:\w+\s*\*\s*\w+|\w+\s*\+\s*\w+)\s*\]',
        message="new[] with arithmetic size — check for integer overflow before allocation",
        recommendation="Validate: if (n > (SIZE_MAX / sizeof(T))) throw std::bad_alloc();",
        confidence=70,
    ),
    CppPattern(
        id="CPP-032", category="Integer Overflow", severity="MEDIUM",
        cwe="CWE-191",
        regex=r'\b(uint\w*|size_t)\s+\w+\s*=\s*\w+\s*-\s*\w+\s*;',
        message="Unsigned subtraction may wrap — check b >= a before computing a - b",
        recommendation="Check if (b >= a) before computing unsigned a - b; use signed types if underflow possible",
        confidence=60,
    ),

    # ── Use-After-Free / Double-Free — CWE-416 / CWE-415 ─────────────────────

    CppPattern(
        id="CPP-040", category="Memory Management", severity="HIGH",
        cwe="CWE-416",
        regex=r'\bfree\s*\(\s*(\w+)\s*\)\s*;(?:[^;{]*;){0,5}[^{]*\b\1\b',
        message="Variable used after free() — potential use-after-free",
        recommendation="Set pointer to NULL after free(): free(p); p = NULL;",
        confidence=60,
    ),
    CppPattern(
        id="CPP-041", category="Memory Management", severity="MEDIUM",
        cwe="CWE-415",
        regex=r'\bfree\s*\(\s*\w+\s*\)\s*;\s*(?://[^\n]*)?\s*\bfree\s*\(',
        message="Two consecutive free() calls — possible double-free",
        recommendation="Set pointer to NULL after first free(); guard with if (p) before freeing",
        confidence=70,
    ),

    # ── Race Conditions — CWE-362 / TOCTOU ────────────────────────────────────

    CppPattern(
        id="CPP-050", category="Race Condition", severity="HIGH",
        cwe="CWE-362",
        regex=r'\b(?:access|stat|lstat)\s*\([^)]+\)\s*[^;{]*(?:open|fopen|unlink|rename)\s*\(',
        message="TOCTOU: file checked then used — race window between check and use",
        recommendation="Use O_CREAT|O_EXCL for atomic create; use file descriptors not paths for re-access",
        confidence=65,
    ),
    CppPattern(
        id="CPP-051", category="Race Condition", severity="MEDIUM",
        cwe="CWE-362",
        regex=r'\bsignal\s*\([^)]+\)\s*;',
        message="signal() is non-reentrant — use sigaction() for reliable signal handling",
        recommendation="Replace signal() with sigaction() with SA_RESTART and a minimal signal handler",
        confidence=70,
    ),
    CppPattern(
        id="CPP-052", category="Race Condition", severity="MEDIUM",
        cwe="CWE-362",
        regex=r'\btmpnam\s*\(',
        message="tmpnam() has TOCTOU race between name generation and file creation",
        recommendation="Use mkstemp() for atomic temp file creation",
        confidence=90,
    ),
    CppPattern(
        id="CPP-053", category="Race Condition", severity="MEDIUM",
        cwe="CWE-362",
        regex=r'\btempnam\s*\(',
        message="tempnam() has TOCTOU race — use mkstemp() instead",
        recommendation="Use mkstemp() which atomically creates the file",
        confidence=90,
    ),

    # ── Null Pointer Dereference — CWE-476 ────────────────────────────────────

    CppPattern(
        id="CPP-060", category="Null Pointer", severity="HIGH",
        cwe="CWE-476",
        regex=r'\bmalloc\s*\([^)]+\)\s*;\s*(?://[^\n]*)?\s*(?:\*|\w+\s*(?:->|\[))',
        message="malloc() return value used without NULL check — dereference of potential NULL",
        recommendation="Always check: ptr = malloc(n); if (!ptr) { error(); }",
        confidence=65,
    ),
    CppPattern(
        id="CPP-061", category="Null Pointer", severity="MEDIUM",
        cwe="CWE-476",
        regex=r'\b(?:fopen|popen)\s*\([^)]+\)\s*;\s*(?://[^\n]*)?\s*(?:fgets|fread|fwrite|fputs|fprintf)\s*\(',
        message="fopen() return not checked for NULL before use",
        recommendation="Always check: FILE *f = fopen(...); if (!f) { perror(path); return; }",
        confidence=70,
    ),

    # ── Cryptographic Weaknesses — CWE-327/CWE-330 ────────────────────────────

    CppPattern(
        id="CPP-070", category="Cryptography", severity="HIGH",
        cwe="CWE-330",
        regex=r'\brand\s*\(\s*\)|\bsrand\s*\(\s*time',
        message="rand()/srand(time) is not cryptographically secure",
        recommendation="Use getrandom(2) or /dev/urandom for cryptographic randomness",
        confidence=85,
    ),
    CppPattern(
        id="CPP-071", category="Cryptography", severity="HIGH",
        cwe="CWE-327",
        regex=r'\bMD5\b|\bRC4\b|\bDES_\w|\bEVP_des_|\bEVP_rc4\b|\bEVP_md5\b',
        message="Weak/broken cryptographic algorithm (MD5/RC4/DES) — use SHA-256+ or AES-GCM",
        recommendation="Use SHA-256/SHA-3 for hashing; AES-256-GCM for symmetric encryption",
        confidence=85,
    ),
    CppPattern(
        id="CPP-072", category="Cryptography", severity="HIGH",
        cwe="CWE-330",
        regex=r'\bstatic\s+(?:const\s+)?(?:uint8_t|char|unsigned char)\s+\w*(?:iv|nonce|key)\w*\s*\[',
        message="Hardcoded/static IV or nonce in source — IVs must be randomly generated per encryption",
        recommendation="Generate IV with a CSPRNG: RAND_bytes(iv, sizeof(iv)); never hardcode",
        confidence=75,
    ),
    CppPattern(
        id="CPP-073", category="Cryptography", severity="MEDIUM",
        cwe="CWE-760",
        regex=r'memcmp\s*\([^)]*(?:hash|mac|hmac|sig|digest)[^)]*\)',
        message="memcmp() for secret comparison — vulnerable to timing attacks",
        recommendation="Use constant-time comparison: CRYPTO_memcmp() or sodium_memcmp()",
        confidence=70,
    ),

    # ── Path Traversal — CWE-22 ───────────────────────────────────────────────

    CppPattern(
        id="CPP-080", category="Path Traversal", severity="HIGH",
        cwe="CWE-22",
        regex=r'\b(?:fopen|open|stat|access|unlink)\s*\([^)]*(?:argv|getenv|input|user)[^)]*\)',
        message="File operation with user-controlled path — potential path traversal",
        recommendation="Canonicalize with realpath() and verify path starts with allowed prefix",
        confidence=70,
    ),

    # ── TON/Blockchain-Specific Patterns ──────────────────────────────────────

    CppPattern(
        id="CPP-100", category="TON Overlay", severity="HIGH",
        cwe="CWE-400",
        regex=r'duration_\s*==\s*0\s*\)\s*\{\s*return\s+true',
        message="RateLimiterWindow: duration=0 check returns unlimited — ensure rate limiter is configured",
        recommendation="Always set non-zero duration and limit before using the rate limiter",
        confidence=95,
    ),
    CppPattern(
        id="CPP-101", category="TON Overlay", severity="HIGH",
        cwe="CWE-345",
        regex=r'issuer_hash\s*\(\s*\)',
        message="Using certificate->issuer_hash() — verify this is called AFTER signature verification",
        recommendation="Ensure certificate signature is verified before trusting any certificate fields",
        confidence=80,
    ),
    CppPattern(
        id="CPP-102", category="TON ADNL", severity="MEDIUM",
        cwe="CWE-20",
        regex=r'td::BufferSlice\s+\w+\s*=\s*td::BufferSlice\s*\(\s*(?:size|len|n)\s*\)',
        message="BufferSlice allocated with unvalidated size — ensure size is bounds-checked",
        recommendation="Validate size against a maximum: if (size > MAX_PACKET_SIZE) return error;",
        confidence=70,
    ),
    CppPattern(
        id="CPP-103", category="TON TVM", severity="HIGH",
        cwe="CWE-190",
        regex=r'\.fetch_ulong\s*\(\s*(\d+)\s*\)',
        message="TVM cell fetch_ulong with fixed bit count — ensure bit count matches expected format",
        recommendation="Validate remaining bits before fetching; handle cs.size() < n case explicitly",
        confidence=75,
    ),
    CppPattern(
        id="CPP-104", category="TON Validator", severity="HIGH",
        cwe="CWE-362",
        regex=r'td::actor::send_closure[^;]+\bcheck\b[^;]+;[^;]{0,200}td::actor::send_closure',
        message="Multiple send_closure calls — check for TOCTOU in actor state between closures",
        recommendation="Use a single atomic closure or acquire actor lock for multi-step state changes",
        confidence=55,
    ),

    # ── Information Disclosure — CWE-209 ──────────────────────────────────────

    CppPattern(
        id="CPP-090", category="Information Disclosure", severity="MEDIUM",
        cwe="CWE-209",
        regex=r'\bperror\s*\(|\bstrerror\s*\(errno\)',
        message="perror()/strerror(errno) exposes internal error details — sanitize for production",
        recommendation="Log detailed errors to internal log only; return generic error to caller",
        confidence=60,
    ),
    CppPattern(
        id="CPP-091", category="Information Disclosure", severity="LOW",
        cwe="CWE-209",
        regex=r'#define\s+\w*(?:VERSION|BUILD|REVISION)\w*\s+"[0-9]',
        message="Version string in binary — may help attackers identify exact vulnerable version",
        recommendation="Consider stripping version from release builds or using a generic string",
        confidence=50,
    ),
]

# Pre-compile all regexes
_COMPILED: List[Tuple[CppPattern, re.Pattern]] = [
    (p, re.compile(p.regex, re.MULTILINE | re.DOTALL)) for p in _PATTERNS
]

# File extensions this scanner handles
_CPP_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".hxx", ".ipp"}

# Directories to skip
_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv",
              "dist", "build", "third_party", "vendor"}


def _is_comment(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*")


def _get_line_number(content: str, match_start: int) -> int:
    return content[:match_start].count("\n") + 1


class CppScanner:
    """
    C/C++ static analysis scanner using compiled regex patterns.
    Covers memory safety, format strings, command injection, integer overflow,
    race conditions, cryptographic weaknesses, and TON-specific issues.
    """

    def scan_file(self, file_path: str) -> List[Dict]:
        p = Path(file_path)
        if not p.exists() or p.suffix.lower() not in _CPP_EXTENSIONS:
            return []
        try:
            content = p.read_text(errors="replace")
        except Exception:
            return []

        lines   = content.splitlines()
        findings: List[Dict] = []

        seen_keys: set = set()
        for pattern, compiled in _COMPILED:
            for m in compiled.finditer(content):
                line_no = _get_line_number(content, m.start())
                # Skip full-line comments
                line_text = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
                if _is_comment(line_text):
                    continue

                # Skip if the actual match position is inside an inline comment
                match_col = m.start() - content.rfind("\n", 0, m.start()) - 1
                pre_match = line_text[:match_col]
                if "//" in pre_match:
                    continue

                # Deduplicate: same rule + same line fires at most once
                key = (pattern.id, line_no)
                if key in seen_keys:
                    continue
                seen_keys.add(key)

                # Skip if negative lookahead hit
                if pattern.negative_lookahead and re.search(
                    pattern.negative_lookahead, line_text
                ):
                    continue

                snippet = line_text.strip()[:100]
                findings.append({
                    "type":           pattern.category.upper().replace(" ", "_"),
                    "id":             pattern.id,
                    "severity":       pattern.severity,
                    "cwe":            pattern.cwe,
                    "file":           str(p),
                    "line":           line_no,
                    "column":         match_col,
                    "message":        pattern.message,
                    "description":    pattern.message,
                    "evidence":       snippet,
                    "recommendation": pattern.recommendation,
                    "source":         "cpp_scanner",
                    "scanner":        "cpp",
                    "category":       pattern.category,
                    "confidence":     pattern.confidence,
                })

        return findings

    def scan_directory(self, directory: str, max_files: int = 500) -> Dict:
        root = Path(directory)
        all_findings: List[Dict] = []
        scanned = 0

        for p in root.rglob("*"):
            if scanned >= max_files:
                break
            if not p.is_file():
                continue
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            if p.suffix.lower() not in _CPP_EXTENSIONS:
                continue
            all_findings.extend(self.scan_file(str(p)))
            scanned += 1

        # Sort by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_findings.sort(key=lambda f: sev_order.get(f.get("severity", "LOW"), 4))

        sev_counts: Dict[str, int] = {}
        for f in all_findings:
            s = f.get("severity", "MEDIUM")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        return {
            "files_scanned":   scanned,
            "total_findings":  len(all_findings),
            "severity_counts": sev_counts,
            "findings":        all_findings,
            "scanner":         "cpp",
        }

    def supported_extensions(self) -> List[str]:
        return sorted(_CPP_EXTENSIONS)

    def pattern_count(self) -> int:
        return len(_PATTERNS)
