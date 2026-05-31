"""
backend/scanners/auth_checker.py — FastAPI router security checker (TythanAI)

Analyses Python source files via AST to detect:
  1. Unprotected endpoints (missing auth dependency)           — HIGH  CWE-306
  2. IDOR — missing ownership checks on ID-parameterised routes — HIGH  CWE-639
  3. WebSocket routes without auth                             — MEDIUM
  4. JWT algorithm confusion / disabled signature verification  — CRITICAL CWE-347
  5. Missing rate limiting on sensitive auth endpoints         — MEDIUM
"""
from __future__ import annotations

import ast
import logging
import os
import re
from pathlib import Path
from typing import Iterator, List, Optional, Set, Tuple

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.auth")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Auth dependencies accepted as "protected"
_AUTH_DEPS: Set[str] = {
    "auth",
    "get_current_user",
    "verify_token",
    "require_auth",
    "get_current_active_user",
    "authenticate",
    "jwt_required",
    "oauth2_scheme",
}

# Whitelisted public routes (regex patterns against the full route string)
_PUBLIC_ROUTE_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"^/health(?:/.*)?$"),
    re.compile(r"^/docs(?:/.*)?$"),
    re.compile(r"^/openapi\.json$"),
    re.compile(r"^/metrics(?:/.*)?$"),
    re.compile(r"^/redoc(?:/.*)?$"),
    re.compile(r"^/api/v[^/]+/auth/login$"),
    re.compile(r"^/api/v[^/]+/auth/register$"),
    re.compile(r"^/api/v[^/]+/auth/refresh$"),
    re.compile(r"favicon\.ico$"),
]

# Auth endpoints that should have rate limiting
_AUTH_ENDPOINT_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"/login"),
    re.compile(r"/register"),
    re.compile(r"/forgot.?password", re.IGNORECASE),
    re.compile(r"/reset.?password", re.IGNORECASE),
]

# Rate-limiting marker names
_RATE_LIMIT_NAMES: Set[str] = {
    "RateLimiter",
    "rate_limit",
    "Throttle",
    "throttle",
    "limiter",
    "Limiter",
    "slowapi",
    "SlowAPIMiddleware",
    "RateLimit",
}

# Ownership-check keywords in function body.
# ".id" is intentionally broad: user.id, current_user.id, owner.id all satisfy ownership.
_OWNERSHIP_CHECKS: Set[str] = {
    ".owner",
    ".user_id",
    "current_user.id",
    "check_ownership",
    "verify_access",
    "owner_id",
    "user_owns",
    ".id",           # catches user.id == X, current_user.id == X, etc.
}

# JWT-safe usage markers
_JWT_ALGORITHMS_NONE: re.Pattern[str] = re.compile(r"algorithms\s*=\s*\[\"none\"\]", re.IGNORECASE)
_JWT_VERIFY_FALSE: re.Pattern[str] = re.compile(
    r"\"verify_signature\"\s*:\s*False|verify_signature.*False", re.IGNORECASE
)

# ─────────────────────────────────────────────────────────────────────────────
# Helper utilities
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


def _route_is_public(route: str) -> bool:
    """Return True if the route is intentionally public (whitelist match)."""
    if "public" in route.lower():
        return True
    for pat in _PUBLIC_ROUTE_PATTERNS:
        if pat.match(route):
            return True
    return False


def _is_auth_endpoint(route: str) -> bool:
    for pat in _AUTH_ENDPOINT_PATTERNS:
        if pat.search(route):
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# AST helper: extract string value from AST node
# ─────────────────────────────────────────────────────────────────────────────


def _const_str(node: ast.expr) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Check 4: JWT algorithm confusion (file-level scan, no decorator needed)
# ─────────────────────────────────────────────────────────────────────────────


def _check_jwt_calls(
    tree: ast.Module,
    source_lines: List[str],
    path: str,
    test_file: bool,
) -> List[Finding]:
    findings: List[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Match jwt.decode(...)
        func = node.func
        is_jwt_decode = (
            isinstance(func, ast.Attribute)
            and func.attr == "decode"
            and isinstance(func.value, ast.Name)
            and func.value.id == "jwt"
        )
        if not is_jwt_decode:
            continue

        lineno = node.lineno
        ctx = _context_window(source_lines, lineno)

        # Check for nosec/noqa suppression
        if _is_suppressed(ctx):
            continue

        # Reconstruct the raw source line for regex checks
        raw_line = source_lines[lineno - 1] if lineno <= len(source_lines) else ""

        # algorithms=["none"]  or  options={"verify_signature": False}
        kw_names = {kw.arg for kw in node.keywords}
        algorithms_kwarg = next((kw for kw in node.keywords if kw.arg == "algorithms"), None)
        options_kwarg = next((kw for kw in node.keywords if kw.arg == "options"), None)

        is_alg_none = False
        is_verify_false = False

        if algorithms_kwarg is not None:
            # Check for ["none"]
            val = algorithms_kwarg.value
            if isinstance(val, ast.List):
                elts = [_const_str(e) for e in val.elts]
                if "none" in [e.lower() if e else "" for e in elts if e]:
                    is_alg_none = True
        elif "algorithms" not in kw_names:
            # No algorithms kwarg at all → confusion risk
            is_alg_none = True

        if options_kwarg is not None:
            val = options_kwarg.value
            # options={"verify_signature": False}
            if isinstance(val, ast.Dict):
                for k, v in zip(val.keys, val.values):
                    key_str = _const_str(k) if k else None  # type: ignore[arg-type]
                    if key_str == "verify_signature":
                        if isinstance(v, ast.Constant) and v.value is False:
                            is_verify_false = True

        if is_alg_none or is_verify_false:
            severity = "CRITICAL"
            if test_file:
                severity = "HIGH"
            description = (
                "jwt.decode() called without explicit `algorithms=` parameter — "
                "susceptible to algorithm confusion attacks (e.g., RS256→HS256)."
                if is_alg_none and not is_verify_false
                else "jwt.decode() called with `verify_signature=False` — signature "
                "verification disabled, tokens are not authenticated."
            )
            findings.append(
                Finding(
                    rule_id="AUTH-JWT-CONFUSION",
                    file=path,
                    line=lineno,
                    severity=severity,
                    confidence=0.95,
                    cwe_id="CWE-347",
                    description=description,
                    recommendation=(
                        "Always specify `algorithms=[<expected_alg>]` and never set "
                        "`verify_signature=False` in production code."
                    ),
                    context_lines=ctx,
                    is_test_file=test_file,
                    is_suppressed=False,
                )
            )

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Core per-function / per-route analysis
# ─────────────────────────────────────────────────────────────────────────────


class _RouteInfo:
    """Data gathered from a single FastAPI route decorator + function definition."""

    __slots__ = (
        "route_path",
        "lineno",
        "is_websocket",
        "depends_names",
        "has_security_kwarg",
        "param_names",
        "has_optional_user",
        "func_node",
    )

    def __init__(self) -> None:
        self.route_path: str = ""
        self.lineno: int = 0
        self.is_websocket: bool = False
        self.depends_names: Set[str] = set()
        self.has_security_kwarg: bool = False
        self.param_names: Set[str] = set()
        self.has_optional_user: bool = False
        self.func_node: Optional[ast.FunctionDef] = None


def _extract_depends_name(call_node: ast.Call) -> Optional[str]:
    """Given Depends(<expr>), return the name of the dependency argument."""
    if not call_node.args:
        return None
    arg0 = call_node.args[0]
    if isinstance(arg0, ast.Name):
        return arg0.id
    if isinstance(arg0, ast.Attribute):
        return arg0.attr
    return None


def _has_rate_limit(func_node: ast.FunctionDef, decorators: List[ast.expr]) -> bool:
    """Return True if the function or its decorators reference a rate-limit utility."""
    # Check decorator names and caller objects
    for dec in decorators:
        if isinstance(dec, ast.Call):
            f = dec.func
            if isinstance(f, ast.Name):
                name = f.id
            elif isinstance(f, ast.Attribute):
                name = f.attr
                # Also check if the object name itself suggests rate limiting
                # e.g., @limiter.limit("5/minute") — f.value.id == "limiter"
                obj_name = f.value.id if isinstance(f.value, ast.Name) else ""
                if any(rl in obj_name.lower() for rl in ("limit", "rate", "throttle", "slow")):
                    return True
            else:
                name = ""
        elif isinstance(dec, ast.Name):
            name = dec.id
        elif isinstance(dec, ast.Attribute):
            name = dec.attr
        else:
            continue
        if name in _RATE_LIMIT_NAMES:
            return True

    # Check function parameters (injected via Depends) — arg names
    for arg in func_node.args.args + func_node.args.kwonlyargs:
        if any(rl in arg.arg.lower() for rl in ("rate", "limit", "throttle")):
            return True

    # Check default values for Depends(RateLimiter(...)) or Depends(rate_limit)
    all_defaults = list(func_node.args.defaults) + list(func_node.args.kw_defaults)
    for default in all_defaults:
        if default is None:
            continue
        if isinstance(default, ast.Call):
            call_func = default.func
            func_name = (
                call_func.id if isinstance(call_func, ast.Name) else
                (call_func.attr if isinstance(call_func, ast.Attribute) else "")
            )
            if func_name == "Depends" and default.args:
                # Depends(RateLimiter(...)) or Depends(rate_limit)
                dep_arg = default.args[0]
                dep_name = ""
                if isinstance(dep_arg, ast.Call):
                    dep_func = dep_arg.func
                    dep_name = (
                        dep_func.id if isinstance(dep_func, ast.Name) else
                        (dep_func.attr if isinstance(dep_func, ast.Attribute) else "")
                    )
                elif isinstance(dep_arg, ast.Name):
                    dep_name = dep_arg.id
                if dep_name in _RATE_LIMIT_NAMES or any(
                    rl in dep_name.lower() for rl in ("rate", "limit", "throttle")
                ):
                    return True

    return False


def _function_body_text(func_node: ast.FunctionDef) -> str:
    """Collect all Name/Attribute/str constants from function body as text."""
    tokens: List[str] = []
    for node in ast.walk(func_node):
        if isinstance(node, ast.Name):
            tokens.append(node.id)
        elif isinstance(node, ast.Attribute):
            tokens.append(f".{node.attr}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            tokens.append(node.value)
    return " ".join(tokens)


def _analyse_route(
    route: _RouteInfo,
    source_lines: List[str],
    path: str,
    test_file: bool,
    all_decorators: List[ast.expr],
) -> List[Finding]:
    findings: List[Finding] = []

    severity_base = "HIGH" if not test_file else "MEDIUM"

    # ── Check 1: unprotected endpoint ────────────────────────────────────────
    if not _route_is_public(route.route_path) and not route.is_websocket:
        has_auth_dep = any(d in _AUTH_DEPS for d in route.depends_names)
        has_security = route.has_security_kwarg

        if not has_auth_dep and not has_security:
            ctx = _context_window(source_lines, route.lineno)
            if _is_suppressed(ctx):
                pass
            elif route.has_optional_user:
                # Optional[current_user] → needs-review, not hard vulnerability
                findings.append(
                    Finding(
                        rule_id="AUTH-OPTIONAL-USER",
                        file=path,
                        line=route.lineno,
                        severity="LOW",
                        confidence=0.6,
                        cwe_id="CWE-306",
                        description=(
                            f"Endpoint `{route.route_path}` uses Optional auth — unauthenticated "
                            "requests are accepted.  Confirm this is intentional (needs-review)."
                        ),
                        recommendation=(
                            "If authentication is required, use a non-optional dependency such as "
                            "`Depends(get_current_user)` without `Optional`."
                        ),
                        context_lines=ctx,
                        is_test_file=test_file,
                        is_suppressed=False,
                    )
                )
            else:
                findings.append(
                    Finding(
                        rule_id="AUTH-MISSING-DEPENDENCY",
                        file=path,
                        line=route.lineno,
                        severity=severity_base,
                        confidence=0.9,
                        cwe_id="CWE-306",
                        description=(
                            f"Endpoint `{route.route_path}` has no authentication dependency "
                            "(missing `Depends(get_current_user)` or equivalent)."
                        ),
                        recommendation=(
                            "Add `current_user: User = Depends(get_current_user)` to the "
                            "function signature, or declare `security=` in the decorator."
                        ),
                        context_lines=ctx,
                        is_test_file=test_file,
                        is_suppressed=False,
                    )
                )

    # ── Check 2: IDOR ────────────────────────────────────────────────────────
    _IDOR_PATTERN = re.compile(r"\{(user_id|id|item_id|resource_id|object_id)\}", re.IGNORECASE)
    if _IDOR_PATTERN.search(route.route_path) and route.func_node is not None:
        body_text = _function_body_text(route.func_node)
        has_ownership = any(check in body_text for check in _OWNERSHIP_CHECKS)
        if not has_ownership:
            ctx = _context_window(source_lines, route.lineno)
            if not _is_suppressed(ctx):
                findings.append(
                    Finding(
                        rule_id="AUTH-IDOR",
                        file=path,
                        line=route.lineno,
                        severity=severity_base,
                        confidence=0.85,
                        cwe_id="CWE-639",
                        description=(
                            f"Endpoint `{route.route_path}` accepts a user/resource ID parameter "
                            "but the handler does not verify ownership "
                            "(`.owner`, `.user_id`, `current_user.id ==`, "
                            "`check_ownership`, `verify_access`)."
                        ),
                        recommendation=(
                            "Verify that `current_user.id == resource.owner_id` (or equivalent) "
                            "before returning or mutating the resource."
                        ),
                        context_lines=ctx,
                        is_test_file=test_file,
                        is_suppressed=False,
                    )
                )

    # ── Check 3: WebSocket without auth ──────────────────────────────────────
    if route.is_websocket:
        has_auth_dep = any(d in _AUTH_DEPS for d in route.depends_names)
        if not has_auth_dep:
            ctx = _context_window(source_lines, route.lineno)
            if not _is_suppressed(ctx):
                findings.append(
                    Finding(
                        rule_id="AUTH-WEBSOCKET-NO-AUTH",
                        file=path,
                        line=route.lineno,
                        severity="MEDIUM" if not test_file else "LOW",
                        confidence=0.85,
                        cwe_id="CWE-306",
                        description=(
                            f"WebSocket endpoint `{route.route_path}` has no authentication "
                            "dependency in its signature."
                        ),
                        recommendation=(
                            "Pass an auth dependency via `Depends()` in the WebSocket handler "
                            "signature, e.g. `token: str = Depends(verify_token)`."
                        ),
                        context_lines=ctx,
                        is_test_file=test_file,
                        is_suppressed=False,
                    )
                )

    # ── Check 5: missing rate limiting on auth endpoints ─────────────────────
    if _is_auth_endpoint(route.route_path) and route.func_node is not None:
        if not _has_rate_limit(route.func_node, all_decorators):
            ctx = _context_window(source_lines, route.lineno)
            if not _is_suppressed(ctx):
                findings.append(
                    Finding(
                        rule_id="AUTH-NO-RATE-LIMIT",
                        file=path,
                        line=route.lineno,
                        severity="MEDIUM" if not test_file else "LOW",
                        confidence=0.8,
                        cwe_id="CWE-307",
                        description=(
                            f"Auth endpoint `{route.route_path}` has no rate-limiting decorator "
                            "or dependency, enabling brute-force or credential-stuffing attacks."
                        ),
                        recommendation=(
                            "Apply a rate-limiting decorator (e.g., SlowAPI `@limiter.limit(...)`) "
                            "or a `Depends(RateLimiter(...))` dependency."
                        ),
                        context_lines=ctx,
                        is_test_file=test_file,
                        is_suppressed=False,
                    )
                )

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# AST visitor
# ─────────────────────────────────────────────────────────────────────────────

_ROUTE_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "websocket"}
)


class _RouteVisitor(ast.NodeVisitor):
    """Visits every decorated function/async-function and extracts route info."""

    def __init__(self, source_lines: List[str], path: str, test_file: bool) -> None:
        self.source_lines = source_lines
        self.path = path
        self.test_file = test_file
        self.findings: List[Finding] = []

    def _is_route_decorator(self, node: ast.expr) -> Tuple[bool, str, bool]:
        """Returns (is_route, route_path, is_websocket)."""
        if not isinstance(node, ast.Call):
            return False, "", False

        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in _ROUTE_METHODS:
            method = func.attr
            is_ws = method == "websocket"
            route_path = ""
            if node.args:
                route_path = _const_str(node.args[0]) or ""
            return True, route_path, is_ws

        return False, "", False

    def _build_route_info(
        self,
        func_node: ast.FunctionDef,
        decorators: List[ast.expr],
    ) -> Optional[_RouteInfo]:
        """Find the first route decorator on the function and build a _RouteInfo."""
        for dec in decorators:
            is_route, route_path, is_ws = self._is_route_decorator(dec)
            if not is_route:
                continue

            info = _RouteInfo()
            info.route_path = route_path
            info.lineno = func_node.lineno
            info.is_websocket = is_ws
            info.func_node = func_node

            # Inspect function parameters for Depends() and Optional types
            for arg in func_node.args.args + func_node.args.kwonlyargs:
                info.param_names.add(arg.arg)

                # Check annotation for Depends(...)
                annotation = arg.annotation
                if annotation is None:
                    continue

                # Detect Optional[X] annotation
                if isinstance(annotation, ast.Subscript):
                    outer = annotation.value
                    outer_name = (
                        outer.id if isinstance(outer, ast.Name) else
                        (outer.attr if isinstance(outer, ast.Attribute) else "")
                    )
                    if outer_name == "Optional":
                        # Check inner for Depends
                        inner = annotation.slice
                        if isinstance(inner, ast.Call):
                            call_func = inner.func
                            if isinstance(call_func, ast.Name) and call_func.id == "Depends":
                                dep_name = _extract_depends_name(inner)
                                if dep_name:
                                    info.depends_names.add(dep_name)
                                    info.has_optional_user = True

                # Direct call annotation: current_user: User = Depends(get_current_user)
                # The Depends() appears as the default value, not the annotation

            # Check default values for Depends(...)
            all_defaults = list(func_node.args.defaults) + list(func_node.args.kw_defaults)
            for default in all_defaults:
                if default is None:
                    continue
                if isinstance(default, ast.Call):
                    call_func = default.func
                    func_name = (
                        call_func.id if isinstance(call_func, ast.Name) else
                        (call_func.attr if isinstance(call_func, ast.Attribute) else "")
                    )
                    if func_name == "Depends":
                        dep_name = _extract_depends_name(default)
                        if dep_name:
                            info.depends_names.add(dep_name)
                    elif func_name in _RATE_LIMIT_NAMES:
                        pass  # captured separately

            # Check decorator for security= kwarg
            for kw in dec.keywords:
                if kw.arg == "security":
                    info.has_security_kwarg = True

            return info
        return None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._process_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._process_function(node)  # type: ignore[arg-type]
        self.generic_visit(node)

    def _process_function(self, node: ast.FunctionDef) -> None:
        if not node.decorator_list:
            return
        info = self._build_route_info(node, node.decorator_list)
        if info is None:
            return
        route_findings = _analyse_route(
            info, self.source_lines, self.path, self.test_file, node.decorator_list
        )
        self.findings.extend(route_findings)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


def scan_file(path: str) -> List[Finding]:
    """
    Analyse a single Python file for FastAPI auth security issues.

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

    findings: List[Finding] = []

    # Route checks via visitor
    visitor = _RouteVisitor(lines, path, test_file)
    visitor.visit(tree)
    findings.extend(visitor.findings)

    # JWT checks (file-wide)
    findings.extend(_check_jwt_calls(tree, lines, path, test_file))

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
