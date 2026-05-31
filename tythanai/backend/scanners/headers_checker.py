"""
backend/scanners/headers_checker.py — FastAPI middleware/config CORS and
security-headers checker (TythanAI).

Analyses Python source files via AST + regex to detect:
  1. No CORSMiddleware in app setup                              — MEDIUM  CWE-942
  2. CORSMiddleware with allow_origins=["*"] + allow_credentials=True — CRITICAL
  3. CORSMiddleware with allow_origins=["*"] without credentials — MEDIUM (LOW if internal)
  4. No security-headers middleware / manual header setting      — MEDIUM
  5. Missing HSTS header for HTTPS services                      — MEDIUM
  6. allow_methods=["*"] with sensitive data endpoints           — LOW
"""
from __future__ import annotations

import ast
import logging
import re
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.headers")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Header names considered "security headers"
_SECURITY_HEADER_NAMES: Set[str] = {
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
}

# Security-headers middleware class names
_SECURITY_HEADERS_MIDDLEWARE: Set[str] = {
    "SecurityHeadersMiddleware",
    "SecureHeadersMiddleware",
    "TrustedHostMiddleware",
    "HTTPSRedirectMiddleware",
}

# Internal/private project markers in source text
_INTERNAL_MARKERS: List[re.Pattern[str]] = [
    re.compile(r"\binternal[-_]only\b", re.IGNORECASE),
    re.compile(r"\binternal\b", re.IGNORECASE),
    re.compile(r"\bintranet\b", re.IGNORECASE),
    re.compile(r"\bnot public\b", re.IGNORECASE),
    re.compile(r"\bprivate\b", re.IGNORECASE),
]

# HTTPS/SSL markers (detect HTTPS services).
# Deliberately excludes "https://" inside CORS allow_origins strings to avoid
# false-positives where origin URLs containing https:// would trigger this check.
_HTTPS_MARKERS: List[re.Pattern[str]] = [
    re.compile(r"\bHTTPS\s*=\s*True\b"),               # HTTPS = True
    re.compile(r"\bSSL\s*=\s*True\b"),                  # SSL = True
    re.compile(r"\bssl_context\b"),                     # ssl_context variable
    re.compile(r"\bssl_keyfile\b", re.IGNORECASE),       # ssl_keyfile / SSL_KEYFILE
    re.compile(r"\bssl_certfile\b", re.IGNORECASE),     # ssl_certfile / SSL_CERTFILE
    re.compile(r"\bssl\.SSLContext\b"),                  # ssl.SSLContext(...)
    re.compile(r"uvicorn.*ssl", re.IGNORECASE),          # uvicorn ssl options
    re.compile(r"--ssl-keyfile", re.IGNORECASE),         # CLI ssl flag
    re.compile(r"BASE_URL\s*=\s*['\"]https://", re.IGNORECASE),  # BASE_URL = "https://..."
    re.compile(r"SERVER_URL\s*=\s*['\"]https://", re.IGNORECASE),
    re.compile(r"API_URL\s*=\s*['\"]https://", re.IGNORECASE),
]

# Sensitive endpoint patterns (for allow_methods=["*"] check)
_SENSITIVE_ROUTE_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"/users?/"),
    re.compile(r"/admin"),
    re.compile(r"/payment"),
    re.compile(r"/account"),
    re.compile(r"/profile"),
    re.compile(r"/secret"),
    re.compile(r"/private"),
    re.compile(r"/data"),
]

# Recommended CORS snippet template
_CORS_RECOMMENDATION = """\
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)"""

# ─────────────────────────────────────────────────────────────────────────────
# File helpers
# ─────────────────────────────────────────────────────────────────────────────


def _is_test_file(path: str) -> bool:
    parts = Path(path).parts
    name = Path(path).name
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or "tests" in parts
        or "test" in parts
        or "conftest" in name
    )


def _read_source(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        logger.warning("Cannot read %s: %s", path, exc)
        return None


def _try_parse(source: str, path: str) -> Optional[ast.Module]:
    try:
        return ast.parse(source, filename=path)
    except SyntaxError as exc:
        logger.warning("Syntax error in %s: %s", path, exc)
        return None


def _source_lines(source: str) -> List[str]:
    return source.splitlines()


def _context_window(lines: List[str], lineno: int, window: int = 3) -> List[str]:
    """Return up to *window* lines above/below *lineno* (1-indexed)."""
    start = max(0, lineno - 1 - window)
    end = min(len(lines), lineno + window)
    return lines[start:end]


def _is_suppressed(context: List[str]) -> bool:
    for line in context:
        low = line.lower()
        if "nosec" in low or "noqa" in low or "audit-ignore" in low:
            return True
    return False


def _is_internal_project(source: str) -> bool:
    """Return True if the source mentions internal/private/intranet markers."""
    for pat in _INTERNAL_MARKERS:
        if pat.search(source):
            return True
    return False


def _has_https_indicators(source: str) -> bool:
    """Return True if the source references HTTPS or SSL configuration."""
    for pat in _HTTPS_MARKERS:
        if pat.search(source):
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# AST helpers
# ─────────────────────────────────────────────────────────────────────────────


def _const_str(node: ast.expr) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _const_bool(node: ast.expr) -> Optional[bool]:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


def _list_str_values(node: ast.expr) -> List[str]:
    """Extract string values from an ast.List node."""
    if not isinstance(node, ast.List):
        return []
    result: List[str] = []
    for elt in node.elts:
        val = _const_str(elt)
        if val is not None:
            result.append(val)
    return result


def _get_name(node: ast.expr) -> str:
    """Best-effort name extraction from a Name or Attribute node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# Middleware call detector
# ─────────────────────────────────────────────────────────────────────────────


class _MiddlewareInfo:
    """Data gathered from a single add_middleware() call or class instantiation."""

    __slots__ = (
        "class_name",
        "lineno",
        "allow_origins",
        "allow_credentials",
        "allow_methods",
        "allow_headers",
        "raw_node",
    )

    def __init__(self) -> None:
        self.class_name: str = ""
        self.lineno: int = 0
        self.allow_origins: List[str] = []
        self.allow_credentials: Optional[bool] = None
        self.allow_methods: List[str] = []
        self.allow_headers: List[str] = []
        self.raw_node: Optional[ast.Call] = None


def _parse_cors_kwargs(call: ast.Call, info: _MiddlewareInfo) -> None:
    """Populate *info* from keyword arguments of a CORSMiddleware call."""
    for kw in call.keywords:
        if kw.arg == "allow_origins":
            info.allow_origins = _list_str_values(kw.value)
        elif kw.arg == "allow_credentials":
            info.allow_credentials = _const_bool(kw.value)
        elif kw.arg == "allow_methods":
            info.allow_methods = _list_str_values(kw.value)
        elif kw.arg == "allow_headers":
            info.allow_headers = _list_str_values(kw.value)


class _MiddlewareVisitor(ast.NodeVisitor):
    """
    Collects information about middleware registrations:
      - app.add_middleware(ClassName, ...)
      - app.add_middleware(ClassName)
    and security header assignments:
      - response.headers["X-Frame-Options"] = ...
      - headers = {"Strict-Transport-Security": ...}
    """

    def __init__(self) -> None:
        self.cors_calls: List[_MiddlewareInfo] = []
        self.security_middleware_found: bool = False
        self.manual_security_headers: Set[str] = set()
        self.has_add_middleware_call: bool = False
        self.all_route_paths: List[str] = []

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        # Pattern: <something>.add_middleware(ClassName, ...)
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "add_middleware"
            and node.args
        ):
            self.has_add_middleware_call = True
            first_arg = node.args[0]
            class_name = _get_name(first_arg)

            if class_name == "CORSMiddleware":
                info = _MiddlewareInfo()
                info.class_name = class_name
                info.lineno = node.lineno
                info.raw_node = node
                _parse_cors_kwargs(node, info)
                self.cors_calls.append(info)

            elif class_name in _SECURITY_HEADERS_MIDDLEWARE:
                self.security_middleware_found = True

        # Pattern: CORSMiddleware(...) used as a direct import/instantiation
        elif isinstance(func, ast.Name) and func.id == "CORSMiddleware":
            info = _MiddlewareInfo()
            info.class_name = "CORSMiddleware"
            info.lineno = node.lineno
            info.raw_node = node
            _parse_cors_kwargs(node, info)
            self.cors_calls.append(info)

        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Detect response.headers["X-Frame-Options"] = ... patterns."""
        # We look for the subscript slice being a string key matching a security header
        slice_node = node.slice
        key = _const_str(slice_node)
        if key and key in _SECURITY_HEADER_NAMES:
            self.manual_security_headers.add(key)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        """Detect dict literals with security-header keys."""
        for k in node.keys:
            if k is not None:
                key = _const_str(k)
                if key and key in _SECURITY_HEADER_NAMES:
                    self.manual_security_headers.add(key)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        """Track route path string constants (for allow_methods=["*"] check)."""
        if isinstance(node.value, str):
            val = node.value
            for pat in _SENSITIVE_ROUTE_PATTERNS:
                if pat.search(val):
                    self.all_route_paths.append(val)
                    break
        self.generic_visit(node)


# ─────────────────────────────────────────────────────────────────────────────
# Check implementations
# ─────────────────────────────────────────────────────────────────────────────


def _check_cors_wildcard_with_credentials(
    info: _MiddlewareInfo,
    source_lines: List[str],
    path: str,
    test_file: bool,
) -> Optional[Finding]:
    """Check 2: allow_origins=["*"] AND allow_credentials=True → CRITICAL."""
    if "*" not in info.allow_origins:
        return None
    if info.allow_credentials is not True:
        return None
    ctx = _context_window(source_lines, info.lineno)
    if _is_suppressed(ctx):
        return None
    return Finding(
        rule_id="HEADERS-CORS-WILDCARD-CREDENTIALS",
        file=path,
        line=info.lineno,
        severity="CRITICAL" if not test_file else "HIGH",
        confidence=0.97,
        cwe_id="CWE-942",
        description=(
            "CORSMiddleware configured with `allow_origins=[\"*\"]` AND "
            "`allow_credentials=True`. Browsers reject this combination per "
            "the CORS spec and it represents a dangerous misconfiguration that "
            "may be exploited to bypass same-origin restrictions."
        ),
        recommendation=_CORS_RECOMMENDATION,
        context_lines=ctx,
        is_test_file=test_file,
        is_suppressed=False,
    )


def _check_cors_wildcard_no_credentials(
    info: _MiddlewareInfo,
    source_lines: List[str],
    path: str,
    test_file: bool,
    is_internal: bool,
) -> Optional[Finding]:
    """Check 3: allow_origins=["*"] without credentials → MEDIUM (LOW if internal)."""
    if "*" not in info.allow_origins:
        return None
    if info.allow_credentials is True:
        return None  # already covered by check 2
    ctx = _context_window(source_lines, info.lineno)
    if _is_suppressed(ctx):
        return None
    severity = "LOW" if is_internal else ("MEDIUM" if not test_file else "LOW")
    return Finding(
        rule_id="HEADERS-CORS-WILDCARD",
        file=path,
        line=info.lineno,
        severity=severity,
        confidence=0.88,
        cwe_id="CWE-942",
        description=(
            "CORSMiddleware configured with `allow_origins=[\"*\"]` — any origin "
            "may read responses from this API. "
            + ("(Downgraded to LOW — project appears to be internal-only.)" if is_internal else "")
        ),
        recommendation=_CORS_RECOMMENDATION,
        context_lines=ctx,
        is_test_file=test_file,
        is_suppressed=False,
    )


def _check_no_cors_middleware(
    has_cors: bool,
    source_lines: List[str],
    path: str,
    test_file: bool,
) -> Optional[Finding]:
    """Check 1: No CORSMiddleware at all."""
    if has_cors:
        return None
    # Only flag files that look like FastAPI app definitions
    source_text = "\n".join(source_lines)
    if "FastAPI" not in source_text and "APIRouter" not in source_text:
        return None
    if "add_middleware" not in source_text and "middleware" not in source_text.lower():
        # Also check if any route decorators present
        if not re.search(r"@(app|router)\.(get|post|put|patch|delete|websocket)\b", source_text):
            return None
    return Finding(
        rule_id="HEADERS-NO-CORS-MIDDLEWARE",
        file=path,
        line=1,
        severity="MEDIUM" if not test_file else "LOW",
        confidence=0.75,
        cwe_id="CWE-942",
        description=(
            "No CORSMiddleware found in this FastAPI application file. "
            "Without explicit CORS configuration the browser's same-origin "
            "policy is the only protection."
        ),
        recommendation=_CORS_RECOMMENDATION,
        context_lines=source_lines[:5] if source_lines else [],
        is_test_file=test_file,
        is_suppressed=False,
    )


def _check_no_security_headers(
    visitor: _MiddlewareVisitor,
    source_lines: List[str],
    path: str,
    test_file: bool,
) -> Optional[Finding]:
    """Check 4: No security-headers middleware or manual security header setting."""
    if visitor.security_middleware_found:
        return None
    # Check if any of the critical security headers are manually set
    required_headers = {
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "Content-Security-Policy",
    }
    has_manual = required_headers & visitor.manual_security_headers
    if has_manual:
        return None
    source_text = "\n".join(source_lines)
    # Only flag FastAPI app files
    if "FastAPI" not in source_text and "APIRouter" not in source_text:
        return None
    if not re.search(r"@(app|router)\.(get|post|put|patch|delete|websocket)\b", source_text):
        if "add_middleware" not in source_text:
            return None
    return Finding(
        rule_id="HEADERS-NO-SECURITY-HEADERS",
        file=path,
        line=1,
        severity="MEDIUM" if not test_file else "LOW",
        confidence=0.72,
        cwe_id="CWE-693",
        description=(
            "No security-headers middleware (e.g., SecurityHeadersMiddleware) found "
            "and none of the critical HTTP security headers "
            "(X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, "
            "Content-Security-Policy) appear to be set manually."
        ),
        recommendation=(
            "Add a security-headers middleware or set headers in a response middleware:\n"
            'response.headers["X-Content-Type-Options"] = "nosniff"\n'
            'response.headers["X-Frame-Options"] = "DENY"\n'
            'response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"\n'
            'response.headers["Content-Security-Policy"] = "default-src \'self\'"'
        ),
        context_lines=source_lines[:5] if source_lines else [],
        is_test_file=test_file,
        is_suppressed=False,
    )


def _check_missing_hsts(
    visitor: _MiddlewareVisitor,
    source: str,
    source_lines: List[str],
    path: str,
    test_file: bool,
) -> Optional[Finding]:
    """Check 5: Missing HSTS header for HTTPS services."""
    if not _has_https_indicators(source):
        return None
    # Check if HSTS is already present
    if "Strict-Transport-Security" in visitor.manual_security_headers:
        return None
    if visitor.security_middleware_found:
        return None
    # Look for any HSTS-like string in source
    if re.search(r"Strict-Transport-Security|max-age=\d+.*includeSubDomains", source):
        return None
    source_text = "\n".join(source_lines)
    if "FastAPI" not in source_text and "APIRouter" not in source_text:
        return None
    return Finding(
        rule_id="HEADERS-MISSING-HSTS",
        file=path,
        line=1,
        severity="MEDIUM" if not test_file else "LOW",
        confidence=0.78,
        cwe_id="CWE-523",
        description=(
            "HTTPS service detected but no Strict-Transport-Security (HSTS) header "
            "configuration found. Without HSTS, clients may connect over HTTP "
            "and be vulnerable to protocol-downgrade attacks."
        ),
        recommendation=(
            'Set the HSTS header in a middleware or response:\n'
            'response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"'
        ),
        context_lines=source_lines[:5] if source_lines else [],
        is_test_file=test_file,
        is_suppressed=False,
    )


def _check_allow_methods_wildcard(
    info: _MiddlewareInfo,
    visitor: _MiddlewareVisitor,
    source_lines: List[str],
    path: str,
    test_file: bool,
) -> Optional[Finding]:
    """Check 6: allow_methods=["*"] with sensitive data endpoints → LOW."""
    if "*" not in info.allow_methods:
        return None
    if not visitor.all_route_paths:
        return None
    ctx = _context_window(source_lines, info.lineno)
    if _is_suppressed(ctx):
        return None
    return Finding(
        rule_id="HEADERS-CORS-WILDCARD-METHODS",
        file=path,
        line=info.lineno,
        severity="LOW",
        confidence=0.70,
        cwe_id="CWE-942",
        description=(
            "CORSMiddleware configured with `allow_methods=[\"*\"]` while sensitive "
            f"endpoints ({', '.join(visitor.all_route_paths[:3])}) are present. "
            "Permitting all HTTP methods (including DELETE, PUT, PATCH) from any origin "
            "increases the attack surface."
        ),
        recommendation=(
            "Restrict CORS methods to only those required:\n"
            '    allow_methods=["GET", "POST"]'
        ),
        context_lines=ctx,
        is_test_file=test_file,
        is_suppressed=False,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


def scan_file(path: str) -> List[Finding]:
    """
    Analyse a single Python file for CORS and security-headers issues.

    Returns a (possibly empty) list of :class:`Finding` objects.
    Unparseable files are logged and return an empty list.
    """
    source = _read_source(path)
    if source is None:
        return []

    tree = _try_parse(source, path)
    if tree is None:
        return []

    test_file = _is_test_file(path)
    lines = _source_lines(source)

    logger.debug("Scanning %s (test_file=%s, lines=%d)", path, test_file, len(lines))

    is_internal = _is_internal_project(source)
    findings: List[Finding] = []

    # Walk the AST collecting middleware info
    visitor = _MiddlewareVisitor()
    visitor.visit(tree)

    has_cors = bool(visitor.cors_calls)

    # Check 1: no CORS middleware
    finding = _check_no_cors_middleware(has_cors, lines, path, test_file)
    if finding is not None:
        findings.append(finding)

    # Checks 2, 3, 6: per CORS call
    for cors_info in visitor.cors_calls:
        # Check 2: wildcard + credentials
        f2 = _check_cors_wildcard_with_credentials(cors_info, lines, path, test_file)
        if f2:
            findings.append(f2)

        # Check 3: wildcard without credentials
        f3 = _check_cors_wildcard_no_credentials(cors_info, lines, path, test_file, is_internal)
        if f3:
            findings.append(f3)

        # Check 6: wildcard methods with sensitive routes
        f6 = _check_allow_methods_wildcard(cors_info, visitor, lines, path, test_file)
        if f6:
            findings.append(f6)

    # Check 4: no security headers middleware
    f4 = _check_no_security_headers(visitor, lines, path, test_file)
    if f4:
        findings.append(f4)

    # Check 5: missing HSTS on HTTPS service
    f5 = _check_missing_hsts(visitor, source, lines, path, test_file)
    if f5:
        findings.append(f5)

    logger.info("scan_file %s → %d finding(s)", path, len(findings))
    return findings


def scan_directory(path: str) -> List[Finding]:
    """
    Recursively scan all ``*.py`` files under *path*.

    Returns a flat list of :class:`Finding` objects from all files.
    """
    results: List[Finding] = []
    root = Path(path)
    if not root.is_dir():
        logger.warning("scan_directory: %s is not a directory", path)
        return results

    for py_file in sorted(root.rglob("*.py")):
        results.extend(scan_file(str(py_file)))

    logger.info("scan_directory %s → %d finding(s) across files", path, len(results))
    return results
