"""Build Validator — language-specific syntax and import validation.

Uses Python ast module for Python. Regex-based structural checks for
JS, Go, Rust, and Java. No external compiler or build tool required.
"""
from __future__ import annotations

import ast
import re
import time
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Result model (mirrored by VerifiedFixEngine — standalone here for import order)
# ---------------------------------------------------------------------------


@dataclass
class BuildResult:
    language: str
    success: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "language": self.language,
            "success": self.success,
            "errors": self.errors,
            "warnings": self.warnings,
            "duration_ms": self.duration_ms,
        }


# ---------------------------------------------------------------------------
# Language detection
# ---------------------------------------------------------------------------

_PY_INDICATORS = re.compile(r'\bimport\b|\bdef\b|\bclass\b|\bprint\s*\(|\bself\b')
_JS_INDICATORS = re.compile(r'\bvar\b|\blet\b|\bconst\b|\bfunction\b|=>\s*{|require\s*\(|module\.exports')
_GO_INDICATORS = re.compile(r'\bpackage\b.*\n|\bfunc\b\s+\w+\s*\(|\bimport\s+"')
_RUST_INDICATORS = re.compile(r'\bfn\b\s+\w+\s*\(|\blet\s+mut\b|\bimpl\b\s+|\buse\b\s+\w+::')
_JAVA_INDICATORS = re.compile(r'\bpublic\s+class\b|\bprivate\s+\w+\s+\w+\s*;|\bSystem\.out\b|\bvoid\s+main\b')

# Dangerous stdlib modules that indicate potential issues
_DANGEROUS_IMPORTS = {"os", "subprocess", "sys", "ctypes", "socket", "pickle", "marshal"}


def _detect_language(code: str) -> str:
    """Detect programming language from code content heuristics."""
    scores: dict = {"python": 0, "javascript": 0, "go": 0, "rust": 0, "java": 0}
    if _PY_INDICATORS.search(code):
        scores["python"] += 2
    if "def " in code or "import " in code:
        scores["python"] += 1
    if _JS_INDICATORS.search(code):
        scores["javascript"] += 2
    if "=>" in code or "console.log" in code:
        scores["javascript"] += 1
    if _GO_INDICATORS.search(code):
        scores["go"] += 3
    if _RUST_INDICATORS.search(code):
        scores["rust"] += 3
    if _JAVA_INDICATORS.search(code):
        scores["java"] += 3
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "unknown"


# ---------------------------------------------------------------------------
# Python validation
# ---------------------------------------------------------------------------


def _validate_python(code: str) -> BuildResult:
    """Validate Python code using ast.parse()."""
    t = time.monotonic()
    errors: List[str] = []
    warnings: List[str] = []

    # 1. Syntax check
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return BuildResult(
            language="python",
            success=False,
            errors=[f"SyntaxError at line {exc.lineno}: {exc.msg}"],
            duration_ms=round((time.monotonic() - t) * 1000, 2),
        )
    except Exception as exc:
        return BuildResult(
            language="python",
            success=False,
            errors=[f"ParseError: {exc}"],
            duration_ms=round((time.monotonic() - t) * 1000, 2),
        )

    # 2. Import validation — detect obviously wrong import names
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            else:
                names = [node.module] if node.module else []
            for name in names:
                if name and "-" in name:
                    errors.append(f"Invalid import name (contains hyphen): '{name}'")
                elif name and name.startswith(".") and isinstance(node, ast.Import):
                    errors.append(f"Relative import used with 'import' statement: '{name}'")

    # 3. Dangerous patterns warnings
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id == "eval":
                warnings.append(f"eval() call detected at line {getattr(node, 'lineno', '?')}")
            elif isinstance(func, ast.Attribute) and func.attr == "system":
                warnings.append(f"os.system() call detected at line {getattr(node, 'lineno', '?')}")

    duration = round((time.monotonic() - t) * 1000, 2)
    return BuildResult(
        language="python",
        success=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        duration_ms=duration,
    )


# ---------------------------------------------------------------------------
# JavaScript validation
# ---------------------------------------------------------------------------

_JS_UNMATCHED_BRACE = re.compile(r'[{}]')
_JS_SYNTAX_PATTERNS = [
    (re.compile(r'\bfunction\s+\w*\s*\([^)]*\)\s*\{'), "valid function declaration"),
    (re.compile(r'=>\s*[{\w]'), "valid arrow function"),
    (re.compile(r'\bvar\s+\w+\s*='), "valid var declaration"),
    (re.compile(r'\bconst\s+\w+\s*='), "valid const declaration"),
    (re.compile(r'\blet\s+\w+'), "valid let declaration"),
]


def _validate_javascript(code: str) -> BuildResult:
    """Validate JavaScript using structural heuristics (no Node.js required)."""
    t = time.monotonic()
    errors: List[str] = []
    warnings: List[str] = []

    # 1. Brace balance check
    depth = 0
    for i, ch in enumerate(code):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if depth < 0:
            errors.append(f"Unmatched '}}' near position {i}")
            break
    if depth > 0:
        errors.append(f"Unclosed '{{' — {depth} brace(s) not closed")

    # 2. Bracket balance
    parens = code.count("(") - code.count(")")
    if abs(parens) > 0:
        errors.append(f"Unbalanced parentheses: {'+' if parens > 0 else ''}{parens}")

    # 3. Dangerous patterns
    dangerous_js = [
        (re.compile(r'\beval\s*\('), "eval() call detected"),
        (re.compile(r'new\s+Function\s*\('), "new Function() call detected"),
        (re.compile(r'document\.write\s*\('), "document.write() call detected"),
        (re.compile(r'innerHTML\s*='), "innerHTML assignment detected"),
    ]
    for pattern, label in dangerous_js:
        if pattern.search(code):
            warnings.append(label)

    duration = round((time.monotonic() - t) * 1000, 2)
    return BuildResult(
        language="javascript",
        success=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        duration_ms=duration,
    )


# ---------------------------------------------------------------------------
# Go validation (structural)
# ---------------------------------------------------------------------------


def _validate_go(code: str) -> BuildResult:
    """Validate Go code structure without go compiler."""
    t = time.monotonic()
    errors: List[str] = []
    warnings: List[str] = []

    # Package declaration required
    if not re.search(r'^\s*package\s+\w+', code, re.MULTILINE):
        errors.append("Missing 'package' declaration")

    # Brace balance
    depth = sum(1 if c == "{" else (-1 if c == "}" else 0) for c in code)
    if depth != 0:
        errors.append(f"Unbalanced braces: delta={depth:+d}")

    # Check for common Go mistakes
    if re.search(r':=.*:=', code):
        warnings.append("Possible redeclaration with ':='")

    duration = round((time.monotonic() - t) * 1000, 2)
    return BuildResult(
        language="go",
        success=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        duration_ms=duration,
    )


# ---------------------------------------------------------------------------
# Rust validation (structural)
# ---------------------------------------------------------------------------


def _validate_rust(code: str) -> BuildResult:
    """Validate Rust code structure without cargo."""
    t = time.monotonic()
    errors: List[str] = []
    warnings: List[str] = []

    # Brace balance
    depth = sum(1 if c == "{" else (-1 if c == "}" else 0) for c in code)
    if depth != 0:
        errors.append(f"Unbalanced braces: delta={depth:+d}")

    # unsafe block detection
    if re.search(r'\bunsafe\s*\{', code):
        warnings.append("unsafe block detected")

    # unwrap() is a code smell
    unwrap_count = len(re.findall(r'\.unwrap\(\)', code))
    if unwrap_count > 3:
        warnings.append(f"Excessive .unwrap() usage ({unwrap_count} occurrences)")

    duration = round((time.monotonic() - t) * 1000, 2)
    return BuildResult(
        language="rust",
        success=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        duration_ms=duration,
    )


# ---------------------------------------------------------------------------
# Java validation (structural)
# ---------------------------------------------------------------------------


def _validate_java(code: str) -> BuildResult:
    """Validate Java code structure without javac."""
    t = time.monotonic()
    errors: List[str] = []
    warnings: List[str] = []

    # At least one class declaration
    if not re.search(r'\bclass\s+\w+', code):
        errors.append("No class declaration found")

    # Brace balance
    depth = sum(1 if c == "{" else (-1 if c == "}" else 0) for c in code)
    if depth != 0:
        errors.append(f"Unbalanced braces: delta={depth:+d}")

    # String concatenation in SQL — potential injection
    if re.search(r'executeQuery\s*\(.*\+', code):
        warnings.append("Possible SQL injection: string concatenation in executeQuery()")

    duration = round((time.monotonic() - t) * 1000, 2)
    return BuildResult(
        language="java",
        success=len(errors) == 0,
        errors=errors,
        warnings=warnings,
        duration_ms=duration,
    )


# ---------------------------------------------------------------------------
# Main validator
# ---------------------------------------------------------------------------


class BuildValidator:
    """Language-agnostic build/syntax validator. No external tools required."""

    _VALIDATORS = {
        "python": _validate_python,
        "javascript": _validate_javascript,
        "js": _validate_javascript,
        "typescript": _validate_javascript,
        "ts": _validate_javascript,
        "go": _validate_go,
        "rust": _validate_rust,
        "java": _validate_java,
    }

    def validate(self, code: str, language: str = "") -> BuildResult:
        """Validate *code* in the given *language*.

        If *language* is empty, auto-detect from code content.
        """
        if not code or not code.strip():
            return BuildResult(language=language or "unknown", success=True,
                               warnings=["Empty code — nothing to validate"])
        lang = language.lower().strip() if language else _detect_language(code)
        validator = self._VALIDATORS.get(lang)
        if validator:
            return validator(code)
        # Unknown language — treat as valid (no false rejection)
        return BuildResult(language=lang, success=True,
                           warnings=[f"No validator available for language '{lang}'"])

    def validate_python(self, code: str) -> BuildResult:
        return _validate_python(code)

    def validate_javascript(self, code: str) -> BuildResult:
        return _validate_javascript(code)

    def validate_go(self, code: str) -> BuildResult:
        return _validate_go(code)

    def validate_rust(self, code: str) -> BuildResult:
        return _validate_rust(code)

    def validate_java(self, code: str) -> BuildResult:
        return _validate_java(code)

    def detect_language(self, code: str) -> str:
        return _detect_language(code)
