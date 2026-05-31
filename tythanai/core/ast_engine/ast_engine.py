"""
TythanAI — Unified AST Analysis Engine (v13)

Supports:
  * Python  — real ast.parse() with visitor-based pattern detection + taint tracking
  * JS / TS — regex + look-around for contextual precision
  * Solidity — regex + context heuristics
  * Generic  — best-effort regex for unknown types

No external dependencies required (stdlib only).
"""
from __future__ import annotations

import ast
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .source_sink_db import JS_SINKS, JS_SOURCES, PYTHON_SINKS, PYTHON_SOURCES

log = logging.getLogger("ghost.ast_engine")

# ─── Finding dataclass ────────────────────────────────────────────────────────


@dataclass
class Finding:
    rule_id: str
    severity: str          # critical / high / medium / low / info
    category: str          # sql_injection / hardcoded_cred / etc.
    message: str
    file: str
    line: int
    column: int = 0
    snippet: str = ""
    confidence: str = "high"   # high / medium / low
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "confidence": self.confidence,
            "tags": self.tags,
        }


# ─── Language detection ────────────────────────────────────────────────────────

_EXT_MAP: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".sol": "solidity",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
}

_MAX_FILE_BYTES = 5 * 1024 * 1024   # 5 MB safety cap
_SKIP_DIRS = {
    "__pycache__", ".git", "node_modules", "dist", "build",
    ".venv", "venv", ".tox", ".mypy_cache", "site-packages",
}


def _detect_language(path: str) -> str:
    ext = Path(path).suffix.lower()
    return _EXT_MAP.get(ext, "unknown")


# ─── Python AST Visitors ──────────────────────────────────────────────────────


class _SecurityVisitor(ast.NodeVisitor):
    """
    Single-pass AST visitor collecting security findings for a Python file.
    """

    def __init__(self, filepath: str, source_lines: List[str]) -> None:
        self.filepath = filepath
        self.source_lines = source_lines
        self.findings: List[Finding] = []
        # Track imports for context (pickle, yaml, subprocess, etc.)
        self._imports: Dict[str, str] = {}      # alias -> module
        self._from_imports: Dict[str, str] = {} # name -> module

    # ── helpers ────────────────────────────────────────────────────────────────

    def _snippet(self, lineno: int) -> str:
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].rstrip()
        return ""

    def _add(
        self,
        rule_id: str,
        severity: str,
        category: str,
        message: str,
        lineno: int,
        col: int = 0,
        confidence: str = "high",
        tags: Optional[List[str]] = None,
    ) -> None:
        self.findings.append(Finding(
            rule_id=rule_id,
            severity=severity,
            category=category,
            message=message,
            file=self.filepath,
            line=lineno,
            column=col,
            snippet=self._snippet(lineno),
            confidence=confidence,
            tags=tags or [],
        ))

    def _is_constant(self, node: ast.expr) -> bool:
        return isinstance(node, ast.Constant)

    def _is_fstring(self, node: ast.expr) -> bool:
        return isinstance(node, ast.JoinedStr)

    def _has_variable_in_fstring(self, node: ast.JoinedStr) -> bool:
        return any(isinstance(v, ast.FormattedValue) for v in node.values)

    def _is_non_constant(self, node: ast.expr) -> bool:
        return not isinstance(node, (ast.Constant, ast.JoinedStr))

    def _call_name(self, node: ast.Call) -> str:
        """Return dotted name of a call's function, e.g. 'cursor.execute'."""
        func = node.func
        if isinstance(func, ast.Attribute):
            parts: List[str] = []
            cur: ast.expr = func
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        if isinstance(func, ast.Name):
            return func.id
        return ""

    def _first_arg(self, node: ast.Call) -> Optional[ast.expr]:
        return node.args[0] if node.args else None

    # ── import tracking ────────────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            key = alias.asname or alias.name
            self._imports[key] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            key = alias.asname or alias.name
            self._from_imports[key] = module
        self.generic_visit(node)

    # ── SQL injection ──────────────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:  # noqa: C901
        name = self._call_name(node)
        lower = name.lower()

        # SQL injection: cursor.execute(f"...{var}...")
        if lower.endswith(("execute", "executemany", "executescript")):
            arg = self._first_arg(node)
            if arg is not None:
                if self._is_fstring(arg) and self._has_variable_in_fstring(arg):  # type: ignore[arg-type]
                    self._add(
                        "PY-SQL-001", "critical", "sql_injection",
                        f"SQL injection: f-string passed directly to '{name}' — "
                        "use parameterised queries instead.",
                        node.lineno, node.col_offset,
                        tags=["CWE-89", "OWASP-A03"],
                    )
                elif isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                    # "SELECT * FROM t WHERE id=" + user_var
                    if not self._is_constant(arg.right) or not self._is_constant(arg.left):
                        self._add(
                            "PY-SQL-002", "critical", "sql_injection",
                            f"SQL injection: string concatenation passed to '{name}'.",
                            node.lineno, node.col_offset,
                            tags=["CWE-89", "OWASP-A03"],
                        )
                elif isinstance(arg, ast.Name):
                    # variable passed directly (might be tainted)
                    self._add(
                        "PY-SQL-003", "high", "sql_injection",
                        f"Potential SQL injection: variable passed to '{name}' — "
                        "verify parameterisation.",
                        node.lineno, node.col_offset,
                        confidence="medium",
                        tags=["CWE-89", "OWASP-A03"],
                    )

        # eval / exec with non-constant arg
        if name in ("eval", "exec", "compile"):
            arg = self._first_arg(node)
            if arg is not None and not self._is_constant(arg):
                self._add(
                    "PY-EVAL-001", "critical", "code_injection",
                    f"Dynamic code execution via '{name}' with non-constant argument.",
                    node.lineno, node.col_offset,
                    tags=["CWE-94", "OWASP-A03"],
                )

        # pickle.loads / pickle.load with non-literal
        if name in ("pickle.loads", "pickle.load"):
            arg = self._first_arg(node)
            if arg is not None and not self._is_constant(arg):
                self._add(
                    "PY-DESER-001", "critical", "insecure_deserialization",
                    "Insecure deserialization: pickle.loads with untrusted data "
                    "allows arbitrary code execution.",
                    node.lineno, node.col_offset,
                    tags=["CWE-502", "OWASP-A08"],
                )

        # marshal.loads
        if name in ("marshal.loads", "marshal.load"):
            arg = self._first_arg(node)
            if arg is not None and not self._is_constant(arg):
                self._add(
                    "PY-DESER-002", "high", "insecure_deserialization",
                    "marshal.loads with non-literal input may be unsafe.",
                    node.lineno, node.col_offset,
                    tags=["CWE-502"],
                )

        # yaml.load without Loader
        if name == "yaml.load":
            has_loader_kwarg = any(kw.arg == "Loader" for kw in node.keywords)
            if not has_loader_kwarg and len(node.args) < 2:
                self._add(
                    "PY-DESER-003", "high", "insecure_deserialization",
                    "yaml.load() without an explicit Loader is unsafe — "
                    "use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
                    node.lineno, node.col_offset,
                    tags=["CWE-502", "OWASP-A08"],
                )

        # subprocess.Popen / subprocess.run with shell=True and variable input
        if name in (
            "subprocess.Popen", "subprocess.run", "subprocess.call",
            "subprocess.check_output", "subprocess.check_call",
            "Popen", "run",
        ):
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in node.keywords
            )
            if shell_true:
                arg = self._first_arg(node)
                if arg is not None and not self._is_constant(arg):
                    self._add(
                        "PY-CMD-001", "critical", "shell_injection",
                        f"Shell injection: '{name}' called with shell=True and "
                        "a non-constant command string.",
                        node.lineno, node.col_offset,
                        tags=["CWE-78", "OWASP-A03"],
                    )

        self.generic_visit(node)

    # ── Hardcoded credentials ──────────────────────────────────────────────────

    _CRED_NAMES_RE = re.compile(
        r"(password|passwd|secret|api_key|apikey|auth_token|access_token|"
        r"private_key|client_secret|db_pass|db_password|token|credential)",
        re.IGNORECASE,
    )

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                if self._CRED_NAMES_RE.search(target.id):
                    val = node.value
                    if isinstance(val, ast.Constant) and isinstance(val.value, str) and val.value.strip():
                        self._add(
                            "PY-CRED-001", "high", "hardcoded_credential",
                            f"Hardcoded credential assigned to '{target.id}' — "
                            "use environment variables or a secrets manager.",
                            node.lineno, node.col_offset,
                            tags=["CWE-798", "OWASP-A02"],
                        )
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            if self._CRED_NAMES_RE.search(node.target.id):
                val = node.value
                if isinstance(val, ast.Constant) and isinstance(val.value, str) and val.value.strip():
                    self._add(
                        "PY-CRED-001", "high", "hardcoded_credential",
                        f"Hardcoded credential in annotated assignment to "
                        f"'{node.target.id}'.",
                        node.lineno, node.col_offset,
                        tags=["CWE-798", "OWASP-A02"],
                    )
        self.generic_visit(node)


# ─── Regex-based analysers ────────────────────────────────────────────────────


class _RegexAnalyser:
    """
    Pattern-based analyser for JS/TS/Solidity and other text formats.
    Each pattern: (rule_id, severity, category, regex, message, tags)
    """

    def __init__(self, patterns: List[Tuple]) -> None:
        self._patterns = [
            (rid, sev, cat, re.compile(rx, re.MULTILINE), msg, tags)
            for rid, sev, cat, rx, msg, tags in patterns
        ]

    def analyse(self, source: str, filepath: str) -> List[Finding]:
        lines = source.splitlines()
        findings: List[Finding] = []

        for rule_id, severity, category, rx, message, tags in self._patterns:
            for m in rx.finditer(source):
                lineno = source[: m.start()].count("\n") + 1
                col = m.start() - source.rfind("\n", 0, m.start()) - 1
                snippet = lines[lineno - 1].strip() if lineno <= len(lines) else ""
                findings.append(Finding(
                    rule_id=rule_id,
                    severity=severity,
                    category=category,
                    message=message,
                    file=filepath,
                    line=lineno,
                    column=max(0, col),
                    snippet=snippet,
                    confidence="medium",
                    tags=tags,
                ))
        return findings


# JavaScript / TypeScript patterns
_JS_PATTERNS: List[Tuple] = [
    # SQL injection via template literal / concatenation
    (
        "JS-SQL-001", "critical", "sql_injection",
        r'(?:query|execute)\s*\(\s*(?:`[^`]*\$\{|"[^"]*"\s*\+|\'[^\']*\'\s*\+)',
        "Possible SQL injection: dynamic string in query/execute call.",
        ["CWE-89", "OWASP-A03"],
    ),
    # innerHTML XSS
    (
        "JS-XSS-001", "high", "xss",
        r'\.innerHTML\s*(?:\+=|=)\s*(?!["\'`]\s*$)',
        "Potential XSS: assignment to innerHTML with dynamic content.",
        ["CWE-79", "OWASP-A03"],
    ),
    # document.write XSS
    (
        "JS-XSS-002", "high", "xss",
        r'document\.write\s*\(',
        "XSS risk: document.write() with untrusted data.",
        ["CWE-79", "OWASP-A03"],
    ),
    # eval usage
    (
        "JS-EVAL-001", "critical", "code_injection",
        r'\beval\s*\(',
        "Dynamic code execution via eval().",
        ["CWE-94", "OWASP-A03"],
    ),
    # Function constructor
    (
        "JS-EVAL-002", "high", "code_injection",
        r'new\s+Function\s*\(',
        "Dynamic code execution via new Function().",
        ["CWE-94"],
    ),
    # setTimeout/setInterval with string
    (
        "JS-EVAL-003", "medium", "code_injection",
        r'(?:setTimeout|setInterval)\s*\(\s*(?:[`"\']|\w+\s*\+)',
        "Potential code injection in setTimeout/setInterval with string argument.",
        ["CWE-94"],
    ),
    # Hardcoded secrets
    (
        "JS-CRED-001", "high", "hardcoded_credential",
        r'(?:password|apiKey|api_key|secret|token|clientSecret)\s*[:=]\s*["\'](?!(?:process\.env|\$\{)["\'])[^"\']{6,}["\']',
        "Hardcoded credential or secret literal found.",
        ["CWE-798", "OWASP-A02"],
    ),
    # prototype pollution
    (
        "JS-PROTO-001", "high", "prototype_pollution",
        r'__proto__\s*\[|__proto__\s*\.',
        "Potential prototype pollution via __proto__ access.",
        ["CWE-1321"],
    ),
    # open redirect
    (
        "JS-REDIR-001", "medium", "open_redirect",
        r'(?:location\.href|location\.replace|location\.assign)\s*=\s*(?:req\.|request\.|params\.|query\.)',
        "Open redirect: location set from user-controlled input.",
        ["CWE-601"],
    ),
    # child_process exec
    (
        "JS-CMD-001", "critical", "shell_injection",
        r'(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|["\'][^"\']*["\'\s]*\+|\w+\s*\+)',
        "Shell injection via exec/execSync with dynamic command.",
        ["CWE-78", "OWASP-A03"],
    ),
    # SSRF via fetch/axios with variable URL
    (
        "JS-SSRF-001", "high", "ssrf",
        r'(?:fetch|axios\.get|axios\.post|http\.get)\s*\(\s*(?:\w+\s*\+|`[^`]*\$\{)',
        "SSRF risk: HTTP request URL built from dynamic value.",
        ["CWE-918"],
    ),
]

# Solidity patterns
_SOL_PATTERNS: List[Tuple] = [
    # tx.origin authentication
    (
        "SOL-AUTH-001", "critical", "auth_bypass",
        r'\btx\.origin\b',
        "Use of tx.origin for authentication can be exploited by phishing contracts.",
        ["CWE-287", "SWC-115"],
    ),
    # Reentrancy: external call before state change
    (
        "SOL-REENT-001", "critical", "reentrancy",
        r'\.call\{[^}]*\}|\.call\(',
        "Low-level .call() detected — verify state changes occur before external calls (CEI pattern).",
        ["SWC-107", "CWE-841"],
    ),
    # delegatecall
    (
        "SOL-REENT-002", "critical", "reentrancy",
        r'\.delegatecall\(',
        "delegatecall to untrusted contract can corrupt storage.",
        ["SWC-112"],
    ),
    # Integer overflow (Solidity < 0.8.0 without SafeMath)
    (
        "SOL-ARITH-001", "high", "integer_overflow",
        r'pragma solidity\s+(?:\^|>=)\s*0\.[0-7]\.',
        "Solidity < 0.8.0 detected — integer overflow/underflow not protected by default.",
        ["SWC-101", "CWE-190"],
    ),
    # block.timestamp dependence
    (
        "SOL-RAND-001", "medium", "weak_randomness",
        r'\bblock\.timestamp\b',
        "block.timestamp can be manipulated by miners (up to 15s) — do not use for randomness.",
        ["SWC-116"],
    ),
    # Unchecked return value for send/transfer
    (
        "SOL-SEND-001", "high", "unchecked_return",
        r'\.\bsend\s*\(',
        ".send() return value should be checked; prefer .transfer() or .call{value:}.",
        ["SWC-104"],
    ),
    # selfdestruct
    (
        "SOL-DEST-001", "critical", "destructible",
        r'\bselfdestruct\s*\(',
        "selfdestruct() can permanently destroy the contract — ensure proper access control.",
        ["SWC-106"],
    ),
    # Unprotected DELEGATECALL
    (
        "SOL-AUTH-002", "critical", "access_control",
        r'function\s+\w+\s*\([^)]*\)\s*(?:public|external)(?!\s+(?:view|pure|returns))[^{]*\{[^}]*\.delegatecall',
        "Public/external function calling delegatecall without visible access check.",
        ["SWC-112"],
    ),
    # hardcoded ETH address
    (
        "SOL-ADDR-001", "medium", "hardcoded_address",
        r'0x[0-9a-fA-F]{40}\b',
        "Hardcoded Ethereum address — consider using a configurable parameter.",
        ["SWC-131"],
    ),
    # overflow in unchecked block
    (
        "SOL-ARITH-002", "high", "integer_overflow",
        r'\bunchecked\s*\{',
        "unchecked block skips overflow protection — verify arithmetic is safe.",
        ["SWC-101", "CWE-190"],
    ),
]

_js_analyser = _RegexAnalyser(_JS_PATTERNS)
_sol_analyser = _RegexAnalyser(_SOL_PATTERNS)


# ─── Main ASTEngine ───────────────────────────────────────────────────────────


class ASTEngine:
    """
    Unified static analysis engine.

    Usage::

        engine = ASTEngine()
        findings = engine.analyze_file("/path/to/app.py", rules=[])
        report   = engine.analyze_directory("/src", rules=[])
    """

    def __init__(self, max_file_bytes: int = _MAX_FILE_BYTES) -> None:
        self._max_bytes = max_file_bytes

    # ── public API ─────────────────────────────────────────────────────────────

    def analyze_file(self, path: str, rules: List[Any] = None) -> List[dict]:  # type: ignore[assignment]
        """
        Analyse a single file and return a list of Ghost-format finding dicts.

        Parameters
        ----------
        path:  absolute or relative path to the file.
        rules: optional list of rule objects (currently reserved for future
               custom rule injection — built-in rules are always applied).
        """
        rules = rules or []
        lang = _detect_language(path)

        try:
            source = self._read_file(path)
        except (OSError, ValueError) as exc:
            log.warning("ASTEngine: cannot read %s: %s", path, exc)
            return []

        findings: List[Finding] = []

        if lang == "python":
            findings = self._analyse_python(source, path)
        elif lang in ("javascript", "typescript"):
            findings = _js_analyser.analyse(source, path)
        elif lang == "solidity":
            findings = _sol_analyser.analyse(source, path)
        else:
            # Generic best-effort: run both JS and basic credential patterns
            findings = self._analyse_generic(source, path)

        return [f.to_dict() for f in findings]

    def analyze_directory(
        self,
        path: str,
        rules: List[Any] = None,  # type: ignore[assignment]
        extensions: Optional[List[str]] = None,
        recursive: bool = True,
    ) -> dict:
        """
        Walk a directory and analyse all supported files.

        Returns::

            {
                "files_scanned": int,
                "total_findings": int,
                "findings_by_file": {filepath: [finding_dict, ...]},
                "summary": {"critical": int, "high": int, ...},
            }
        """
        rules = rules or []
        results: Dict[str, List[dict]] = {}
        summary: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        files_scanned = 0

        for filepath in self._walk(path, extensions, recursive):
            findings = self.analyze_file(filepath, rules)
            if findings:
                results[filepath] = findings
                for f in findings:
                    sev = f.get("severity", "info")
                    summary[sev] = summary.get(sev, 0) + 1
            files_scanned += 1

        return {
            "files_scanned": files_scanned,
            "total_findings": sum(summary.values()),
            "findings_by_file": results,
            "summary": summary,
        }

    # ── Python analysis ────────────────────────────────────────────────────────

    def _analyse_python(self, source: str, filepath: str) -> List[Finding]:
        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError as exc:
            log.warning("ASTEngine: Python syntax error in %s: %s", filepath, exc)
            return []

        lines = source.splitlines()
        visitor = _SecurityVisitor(filepath, lines)
        visitor.visit(tree)

        # Also run taint tracker
        from .taint_tracker import TaintTracker
        tracker = TaintTracker()
        taint_flows = tracker.track(source)
        taint_findings = [
            Finding(
                rule_id="PY-TAINT-001",
                severity="high",
                category=flow.get("category", "taint_flow"),
                message=flow.get("message", "Tainted data reaches a dangerous sink."),
                file=filepath,
                line=flow.get("sink_line", 0),
                column=0,
                snippet="",
                confidence="medium",
                tags=["CWE-20", "taint"],
            )
            for flow in taint_flows
        ]

        # Deduplicate taint findings that already appear as AST findings
        existing_lines = {f.line for f in visitor.findings}
        unique_taint = [
            f for f in taint_findings if f.line not in existing_lines
        ]

        return visitor.findings + unique_taint

    # ── Generic analysis ───────────────────────────────────────────────────────

    _GENERIC_PATTERNS: List[Tuple] = [
        (
            "GEN-CRED-001", "high", "hardcoded_credential",
            r'(?i)(?:password|passwd|secret|api_key|token)\s*[:=]\s*["\'][^"\']{6,}["\']',
            "Hardcoded credential literal.",
            ["CWE-798"],
        ),
        (
            "GEN-CRED-002", "medium", "hardcoded_credential",
            r'(?i)(?:BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY)',
            "Private key material embedded in source file.",
            ["CWE-321"],
        ),
    ]

    def _analyse_generic(self, source: str, filepath: str) -> List[Finding]:
        analyser = _RegexAnalyser(self._GENERIC_PATTERNS)
        return analyser.analyse(source, filepath)

    # ── File I/O helpers ───────────────────────────────────────────────────────

    def _read_file(self, path: str) -> str:
        fsize = os.path.getsize(path)
        if fsize > self._max_bytes:
            raise ValueError(f"File too large ({fsize} bytes > {self._max_bytes})")
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()

    def _walk(
        self,
        root: str,
        extensions: Optional[List[str]],
        recursive: bool,
    ):
        """Yield file paths to analyse."""
        if extensions:
            exts = {e if e.startswith(".") else "." + e for e in extensions}
        else:
            exts = set(_EXT_MAP.keys())

        if recursive:
            for dirpath, dirnames, filenames in os.walk(root):
                # Prune skip dirs in-place so os.walk doesn't descend into them
                dirnames[:] = [
                    d for d in dirnames
                    if d not in _SKIP_DIRS and not d.startswith(".")
                ]
                for fname in filenames:
                    fpath = os.path.join(dirpath, fname)
                    if Path(fpath).suffix.lower() in exts:
                        yield fpath
        else:
            for fname in os.listdir(root):
                fpath = os.path.join(root, fname)
                if os.path.isfile(fpath) and Path(fpath).suffix.lower() in exts:
                    yield fpath
