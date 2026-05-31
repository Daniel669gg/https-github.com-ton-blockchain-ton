"""
backend/scanners/taint_analyzer.py — Python AST-based taint analyzer (Phase 1)

Sources:
  FastAPI: Query, Path, Body, Header, Request
  os.environ / os.getenv
  open()
  sqlite results (fetchone / fetchall / fetchmany)
  websocket input (ws.receive / websocket.receive_*)

Sinks:
  SQL  : execute, executemany
  Shell: subprocess.*, os.system, os.popen
  Code : eval, exec
  Data : pickle.loads
  Log  : logging.*, logger.*
  Crypto: hashlib.new, Cipher, AES, RSA (tainted key/IV)

Context filters (reduce confidence by 0.3):
  int()  isinstance()  regex validation  Pydantic validation

Parameterized SQL (? or :name placeholders with tuple/dict args) → no finding.
"""
from __future__ import annotations

import ast
import collections
import hashlib
import logging
import math
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.taint")

# ─────────────────────────────────────────────────────────────────────────────
# Source / Sink definitions
# ─────────────────────────────────────────────────────────────────────────────

FASTAPI_SOURCES = {
    "Query", "Path", "Body", "Header", "Request",
    "Depends",
}

ENVIRON_SOURCES = {
    ("os", "environ"),
    ("os", "getenv"),
    ("os.environ", "get"),
}

FILE_SOURCES = {"open"}

SQLITE_SOURCES = {"fetchone", "fetchall", "fetchmany", "execute"}

WS_SOURCES = {
    "receive", "receive_text", "receive_bytes", "receive_json",
}

SQL_SINKS = {"execute", "executemany"}

SHELL_SINKS = {
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "Popen"),
    ("subprocess", "check_output"),
    ("subprocess", "check_call"),
    ("os", "system"),
    ("os", "popen"),
    ("os", "execvp"),
    ("os", "execl"),
}

CODE_SINKS = {"eval", "exec"}

DATA_SINKS = {
    ("pickle", "loads"),
    ("pickle", "load"),
}

LOG_SINKS = {
    "debug", "info", "warning", "error", "critical",
    "exception", "log",
}

CRYPTO_SINKS = {
    ("hashlib", "new"),
    ("Cipher",),
    ("AES",),
    ("RSA",),
}

# Validation patterns that reduce confidence
_VALIDATION_CHECKS = [
    re.compile(r"\bint\s*\("),
    re.compile(r"\bisinstance\s*\("),
    re.compile(r"re\.(match|search|fullmatch|compile)"),
    re.compile(r"\bBaseModel\b"),
    re.compile(r"\bValidator\b"),
    re.compile(r"\bvalidate\b", re.I),
    re.compile(r"\bField\s*\("),
]

# Parameterized SQL patterns — these are safe
_PARAM_SQL_RE = re.compile(
    r"execute\w*\s*\(\s*['\"].*(?:\?|:\w+|%s)['\"].*,\s*(?:\(|\[|\{)",
    re.DOTALL,
)

# ─────────────────────────────────────────────────────────────────────────────
# AST helpers
# ─────────────────────────────────────────────────────────────────────────────

def _attr_chain(node: ast.expr) -> List[str]:
    """Return attribute chain as list e.g. os.path.join → ['os', 'path', 'join']."""
    parts: List[str] = []
    cur: ast.expr = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    parts.reverse()
    return parts


def _call_name(node: ast.Call) -> Tuple[str, ...]:
    """Return the function name as a tuple of parts."""
    chain = _attr_chain(node.func)
    return tuple(chain)


def _node_line(node: ast.AST) -> int:
    return getattr(node, "lineno", 0)


def _source_text(source_lines: List[str], lineno: int, context: int = 2) -> List[str]:
    start = max(0, lineno - context - 1)
    end = min(len(source_lines), lineno + context)
    return source_lines[start:end]

# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TaintedVar:
    name: str
    source_type: str       # e.g. "fastapi_query", "os_environ", "sqlite"
    line: int
    cwe: str = ""


@dataclass
class TaintChain:
    source_name: str
    source_type: str
    source_line: int
    sink_name: str
    sink_type: str         # "sql_injection", "shell_injection", "code_exec", etc.
    sink_line: int
    cwe: str
    confidence: float
    call_chain: List[str]
    vuln_type: str
    is_parameterized: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# Taint visitor
# ─────────────────────────────────────────────────────────────────────────────

class _TaintVisitor(ast.NodeVisitor):
    """
    Single-pass AST visitor that tracks:
    1. Which variables are tainted (come from sources)
    2. Where tainted data reaches sinks
    3. Whether validation/sanitisation is present between source and sink
    """

    def __init__(self, source_lines: List[str]) -> None:
        self._source_lines = source_lines
        self._tainted: Dict[str, TaintedVar] = {}   # var_name → TaintedVar
        self._chains: List[TaintChain] = []
        self._call_graph: Dict[str, List[str]] = {}  # fn_name → called_names
        self._current_fn: Optional[str] = None
        self._validation_lines: Set[int] = set()     # lines with validation present

    # ── Source detection ───────────────────────────────────────────────────────

    def _is_source_call(self, node: ast.Call) -> Optional[Tuple[str, str]]:
        """Return (source_label, cwe) if this call is a taint source."""
        name_parts = _call_name(node)
        last = name_parts[-1] if name_parts else ""
        first = name_parts[0] if name_parts else ""

        # FastAPI parameters
        if last in FASTAPI_SOURCES:
            return (f"fastapi_{last.lower()}", "CWE-20")

        # Flask / Django / aiohttp request sources:
        # request.args.get(), request.form.get(), request.json, etc.
        _FLASK_REQUEST_ATTRS = {"args", "form", "json", "data", "headers", "files", "values", "cookies"}
        if first in ("request", "req") and len(name_parts) >= 2:
            if name_parts[1] in _FLASK_REQUEST_ATTRS or name_parts[1] in ("get_json", "get_data"):
                return ("flask_request", "CWE-20")
        # request["key"] subscript handled via _is_source_attr below

        # os.environ / os.getenv
        if tuple(name_parts[:2]) in ENVIRON_SOURCES or (
            len(name_parts) >= 2 and (name_parts[0], name_parts[1]) in ENVIRON_SOURCES
        ):
            return ("os_environ", "CWE-20")

        # open()
        if last in FILE_SOURCES and len(name_parts) == 1:
            return ("file_open", "CWE-20")

        # sqlite fetch results
        if last in SQLITE_SOURCES:
            return ("sqlite_result", "CWE-89")

        # websocket receive
        if last in WS_SOURCES:
            return ("websocket_input", "CWE-20")

        return None

    def _is_sink_call(
        self, node: ast.Call
    ) -> Optional[Tuple[str, str, str]]:
        """Return (sink_label, vuln_type, cwe) if this call is a taint sink."""
        name_parts = _call_name(node)
        last = name_parts[-1] if name_parts else ""
        pair = tuple(name_parts[:2]) if len(name_parts) >= 2 else ()

        # SQL
        if last in SQL_SINKS:
            return ("sql_sink", "sql_injection", "CWE-89")

        # Shell
        if pair in SHELL_SINKS:
            return ("shell_sink", "shell_injection", "CWE-78")

        # Code exec
        if last in CODE_SINKS and len(name_parts) == 1:
            return ("code_sink", "code_execution", "CWE-95")

        # Pickle
        if pair in DATA_SINKS:
            return ("pickle_sink", "deserialization", "CWE-502")

        # Logging
        if last in LOG_SINKS and len(name_parts) >= 2:
            # only flag if the logger name is recognizable
            if name_parts[0] in ("logger", "logging", "log"):
                return ("log_sink", "log_injection", "CWE-117")

        # Crypto with tainted key/IV
        if pair in CRYPTO_SINKS or (len(name_parts) >= 1 and tuple(name_parts[:1]) in CRYPTO_SINKS):
            return ("crypto_sink", "weak_crypto", "CWE-327")

        return None

    # ── Validation detection ───────────────────────────────────────────────────

    def _check_validation_present(self, lineno: int) -> bool:
        """Check if validation patterns appear in the 3 lines before lineno."""
        start = max(0, lineno - 4)
        end = lineno
        snippet = "\n".join(self._source_lines[start:end])
        return any(p.search(snippet) for p in _VALIDATION_CHECKS)

    # ── Assignment tracking ────────────────────────────────────────────────────

    def _is_chained_source(self, node: ast.Call) -> Optional[Tuple[str, str]]:
        """
        Detect chained source patterns like: open(getenv("X"), "rb").read()
        Returns (source_label, cwe) if any inner call is a taint source.
        """
        # Direct source call
        src = self._is_source_call(node)
        if src:
            return src
        # Chained: something.method() — check the object
        if isinstance(node.func, ast.Attribute):
            obj = node.func.value
            if isinstance(obj, ast.Call):
                src = self._is_chained_source(obj)
                if src:
                    return src
        # Any argument is a source call
        for arg in node.args:
            if isinstance(arg, ast.Call):
                src = self._is_chained_source(arg)
                if src:
                    return src
        return None

    def _is_source_attr(self, node: ast.expr) -> Optional[Tuple[str, str]]:
        """Detect taint from Attribute/Subscript access (request.form["x"], os.environ["K"])."""
        if isinstance(node, ast.Subscript):
            obj = node.value
            if isinstance(obj, ast.Attribute):
                parts = _attr_chain(obj)
                if parts and parts[0] in ("request", "req") and len(parts) >= 2:
                    _REQ_ATTRS = {"args", "form", "json", "data", "headers", "files", "values", "cookies"}
                    if parts[1] in _REQ_ATTRS:
                        return ("flask_request", "CWE-20")
                if len(parts) >= 2 and parts[0] == "os" and parts[1] == "environ":
                    return ("os_environ", "CWE-20")
            if isinstance(obj, ast.Name):
                if obj.id in ("request", "req"):
                    return ("flask_request", "CWE-20")
        if isinstance(node, ast.Attribute):
            parts = _attr_chain(node)
            if parts and parts[0] in ("request", "req") and len(parts) >= 2:
                _REQ_ATTRS = {"args", "form", "json", "data", "headers", "files", "values", "cookies"}
                if parts[1] in _REQ_ATTRS:
                    return ("flask_request", "CWE-20")
        return None

    def visit_Assign(self, node: ast.Assign) -> None:
        tainted_src: Optional[Tuple[str, str]] = None

        if isinstance(node.value, ast.Call):
            tainted_src = self._is_chained_source(node.value)
        elif isinstance(node.value, (ast.Subscript, ast.Attribute)):
            tainted_src = self._is_source_attr(node.value)

        if tainted_src:
            src_label, cwe = tainted_src
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._tainted[target.id] = TaintedVar(
                        name=target.id,
                        source_type=src_label,
                        line=_node_line(node),
                        cwe=cwe,
                    )
                    logger.debug("taint source var=%s at line %d", target.id, _node_line(node))
        else:
            # Propagate taint through BinOp, f-strings, .format() calls, etc.
            # If any name in the RHS is already tainted → LHS becomes tainted too.
            rhs_names = self._extract_names(node.value)
            tainted_rhs = [self._tainted[n] for n in rhs_names if n in self._tainted]
            if tainted_rhs:
                # Inherit source type from the first (highest-line) tainted var
                src_tvar = tainted_rhs[0]
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._tainted[target.id] = TaintedVar(
                            name=target.id,
                            source_type=src_tvar.source_type,
                            line=_node_line(node),
                            cwe=src_tvar.cwe,
                        )
                        logger.debug(
                            "taint propagated via expr to var=%s at line %d",
                            target.id, _node_line(node),
                        )
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            tainted_src: Optional[Tuple[str, str]] = None
            if isinstance(node.value, ast.Call):
                tainted_src = self._is_source_call(node.value)
            elif isinstance(node.value, (ast.Subscript, ast.Attribute)):
                tainted_src = self._is_source_attr(node.value)
            if tainted_src is None:
                rhs_names = self._extract_names(node.value)
                tainted_rhs = [self._tainted[n] for n in rhs_names if n in self._tainted]
                if tainted_rhs:
                    t = tainted_rhs[0]
                    tainted_src = (t.source_type, t.cwe)
            if tainted_src and isinstance(node.target, ast.Name):
                src_label, cwe = tainted_src
                self._tainted[node.target.id] = TaintedVar(
                    name=node.target.id,
                    source_type=src_label,
                    line=_node_line(node),
                    cwe=cwe,
                )
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        prev = self._current_fn
        self._current_fn = node.name

        all_args = node.args.args + node.args.posonlyargs + node.args.kwonlyargs

        # Build (arg, annotation, default) triples
        # Defaults align right with args list
        n_args = len(node.args.args)
        n_defaults = len(node.args.defaults)
        defaults_map: Dict[str, Optional[ast.expr]] = {}
        for i, arg in enumerate(node.args.args):
            offset = i - (n_args - n_defaults)
            defaults_map[arg.arg] = node.args.defaults[offset] if offset >= 0 else None
        for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
            defaults_map[arg.arg] = default

        for arg in all_args:
            tainted_via_annotation = False
            tainted_via_default = False
            source_label = "fastapi_param"
            cwe = "CWE-20"

            # Check annotation
            ann = arg.annotation
            if ann is not None:
                ann_name = ""
                if isinstance(ann, ast.Name):
                    ann_name = ann.id
                elif isinstance(ann, ast.Subscript) and isinstance(ann.value, ast.Name):
                    ann_name = ann.value.id
                if ann_name in FASTAPI_SOURCES:
                    tainted_via_annotation = True
                    source_label = f"fastapi_{ann_name.lower()}"

            # Check default value: Query(...), Path(...), Body(...), etc.
            default = defaults_map.get(arg.arg)
            if default is not None and isinstance(default, ast.Call):
                src = self._is_source_call(default)
                if src:
                    tainted_via_default = True
                    source_label, cwe = src

            if tainted_via_annotation or tainted_via_default:
                self._tainted[arg.arg] = TaintedVar(
                    name=arg.arg,
                    source_type=source_label,
                    line=_node_line(node),
                    cwe=cwe,
                )
                logger.debug("fastapi param tainted: %s at line %d", arg.arg, _node_line(node))

        self.generic_visit(node)
        self._current_fn = prev

    visit_AsyncFunctionDef = visit_FunctionDef

    # ── Sink detection ─────────────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:
        sink_info = self._is_sink_call(node)
        if sink_info:
            sink_label, vuln_type, cwe = sink_info

            # Check for parameterized SQL — skip if safe
            line_text = (
                self._source_lines[_node_line(node) - 1]
                if _node_line(node) <= len(self._source_lines)
                else ""
            )
            if vuln_type == "sql_injection" and self._is_parameterized_sql(node, line_text):
                self.generic_visit(node)
                return

            # Collect tainted arguments
            tainted_args = self._find_tainted_args(node)
            if not tainted_args:
                self.generic_visit(node)
                return

            for tvar in tainted_args:
                validation_present = self._check_validation_present(_node_line(node))
                confidence = self._compute_confidence(
                    tvar, _node_line(node), validation_present
                )

                chain = TaintChain(
                    source_name=tvar.name,
                    source_type=tvar.source_type,
                    source_line=tvar.line,
                    sink_name=sink_label,
                    sink_type=vuln_type,
                    sink_line=_node_line(node),
                    cwe=cwe,
                    confidence=confidence,
                    call_chain=self._build_call_chain(tvar.line, _node_line(node)),
                    vuln_type=vuln_type,
                )
                self._chains.append(chain)
                logger.debug(
                    "taint flow %s→%s (conf=%.2f) at line %d",
                    tvar.source_type, vuln_type, confidence, _node_line(node),
                )

        self.generic_visit(node)

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _is_parameterized_sql(self, node: ast.Call, line_text: str) -> bool:
        """
        Returns True if the execute() call uses parameterized placeholders.
        Checks: second argument is a tuple/list/dict, AND the query string
        contains ? or :name or %s.
        """
        if len(node.args) < 2:
            return False
        second_arg = node.args[1]
        if not isinstance(second_arg, (ast.Tuple, ast.List, ast.Dict, ast.Name)):
            return False
        # Check if query string contains placeholders
        if len(node.args) >= 1:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                query = first_arg.value
                if re.search(r"\?|:\w+|%s", query):
                    return True
        return bool(_PARAM_SQL_RE.search(line_text))

    def _find_tainted_args(self, node: ast.Call) -> List[TaintedVar]:
        """Return list of tainted variables used as arguments to this call."""
        found: List[TaintedVar] = []
        all_args: List[ast.expr] = list(node.args)
        for kw in node.keywords:
            if kw.value:
                all_args.append(kw.value)

        for arg in all_args:
            names = self._extract_names(arg)
            for name in names:
                if name in self._tainted:
                    found.append(self._tainted[name])
        return found

    def _extract_names(self, node: ast.expr) -> List[str]:
        """Recursively extract all Name references from an expression."""
        names: List[str] = []
        if isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, ast.BinOp):
            names.extend(self._extract_names(node.left))
            names.extend(self._extract_names(node.right))
        elif isinstance(node, ast.JoinedStr):  # f-string
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    names.extend(self._extract_names(v.value))
        elif isinstance(node, ast.Call):
            # .format() call: extract both the format string object and the args
            if isinstance(node.func, ast.Attribute):
                names.extend(self._extract_names(node.func.value))
            for a in node.args:
                names.extend(self._extract_names(a))
            for kw in node.keywords:
                names.extend(self._extract_names(kw.value))
        elif isinstance(node, ast.Attribute):
            names.extend(self._extract_names(node.value))
        elif isinstance(node, ast.Subscript):
            names.extend(self._extract_names(node.value))
        return names

    def _compute_confidence(
        self,
        tvar: TaintedVar,
        sink_line: int,
        validation_present: bool,
    ) -> float:
        base = 0.85
        # Reduce if validation/sanitisation detected between source and sink
        if validation_present:
            base -= 0.3
        # Distance penalty: reduce slightly for very distant flows
        distance = abs(sink_line - tvar.line)
        if distance > 100:
            base -= 0.1
        elif distance > 50:
            base -= 0.05
        return max(0.15, min(1.0, round(base, 2)))

    def _build_call_chain(self, source_line: int, sink_line: int) -> List[str]:
        """Return intermediate source lines as the call chain."""
        start = max(0, source_line - 1)
        end = min(len(self._source_lines), sink_line)
        chain = []
        for i, line in enumerate(self._source_lines[start:end], start + 1):
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                chain.append(f"line {start + i}: {stripped[:80]}")
        return chain[:8]


# ─────────────────────────────────────────────────────────────────────────────
# Hardcoded-secrets detection helpers  (CWE-798)
# ─────────────────────────────────────────────────────────────────────────────

# Variable name sub-strings that indicate a credential field.
_SECRET_NAME_KEYWORDS = (
    "password", "passwd", "secret", "token", "api_key", "api_secret",
    "auth_key", "access_key", "private_key", "secret_key", "aws_secret",
)

# Strings that start with these characters are template placeholders, not real
# credentials, and must NOT be flagged.
_TEMPLATE_PREFIXES = ("$", "{", "<", "%")

# Common English words that look like credential names but are not actual
# secrets (e.g. "password_field", "token_endpoint").  If the value is all
# lowercase letters/underscores/hyphens with no digits it is likely a field
# *name*, not a secret *value*.
_ALL_WORD_RE = re.compile(r'^[a-z][a-z_\-]+$')


def _string_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = collections.Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _looks_like_real_credential(value: str) -> bool:
    """Heuristic: True if the string has both digits and letters and len>=12."""
    return (
        len(value) >= 12
        and any(c.isdigit() for c in value)
        and any(c.isalpha() for c in value)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

class TaintAnalyzer:
    """
    Python AST-based taint analyzer.

    Usage::

        analyzer = TaintAnalyzer()
        findings = analyzer.analyze_file("myapp/routes.py")
        all_findings = analyzer.analyze_directory("myapp/")
    """

    def __init__(self, confidence_threshold: float = 0.5) -> None:
        self.confidence_threshold = confidence_threshold

    def analyze_file(self, filepath: str) -> List[Finding]:
        try:
            source = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", filepath, exc)
            return []

        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            logger.debug("Parse error in %s: %s", filepath, exc)
            return []

        source_lines = source.splitlines()
        visitor = _TaintVisitor(source_lines)
        visitor.visit(tree)

        findings: List[Finding] = []
        for chain in visitor._chains:
            if chain.confidence < self.confidence_threshold:
                continue
            if chain.is_parameterized:
                continue

            ctx_start = max(0, chain.source_line - 2)
            ctx_end = min(len(source_lines), chain.sink_line + 1)
            context = source_lines[ctx_start:ctx_end]

            findings.append(Finding(
                rule_id=f"TAINT-{chain.vuln_type.upper().replace('-', '_')}",
                file=filepath,
                line=chain.sink_line,
                severity=self._vuln_severity(chain.vuln_type),
                confidence=chain.confidence,
                cwe_id=chain.cwe,
                description=(
                    f"Tainted data from '{chain.source_type}' (line {chain.source_line}) "
                    f"reaches '{chain.sink_name}' at line {chain.sink_line} "
                    f"without sufficient sanitization."
                ),
                recommendation=self._recommendation(chain.vuln_type),
                sources=[chain.source_type],
                context_lines=context,
            ))

        # CWE-798: scan for hardcoded secrets
        findings.extend(self._scan_hardcoded_secrets(tree, filepath, source_lines))

        return findings

    # ── Hardcoded-secrets scan (CWE-798) ──────────────────────────────────────

    def _scan_hardcoded_secrets(
        self,
        tree: ast.AST,
        filepath: str,
        source_lines: List[str],
    ) -> List[Finding]:
        """Detect hardcoded credentials assigned to suspiciously-named variables.

        Two detection strategies are used:
        1. Variable-name heuristic: variable name contains a keyword like
           ``password``, ``secret``, ``api_key``, etc. AND the value is a
           string literal that is not a template/placeholder.
        2. Entropy heuristic: any string literal of length >= 20 with Shannon
           entropy >= 3.5 bits/char regardless of variable name.

        Rule ID: HARDCODED-SECRET-001  (CWE-798)
        """
        results: List[Finding] = []

        def _check_assign(var_name: str, value_node: ast.expr, lineno: int) -> None:
            if not isinstance(value_node, ast.Constant):
                return
            value = value_node.value
            if not isinstance(value, str):
                return

            # Must be a non-trivial string
            if len(value) < 8:
                return
            # Template/placeholder check — not a real secret
            if value.startswith(_TEMPLATE_PREFIXES):
                return

            var_lower = var_name.lower()

            # Strategy 1: name-based keyword match
            name_matched = any(kw in var_lower for kw in _SECRET_NAME_KEYWORDS)
            if name_matched:
                # Exclude common-word false positives (all-lowercase word strings)
                if _ALL_WORD_RE.match(value):
                    return  # looks like a field-name, not a credential value

                confidence = (
                    0.85 if _looks_like_real_credential(value) else 0.70
                )
                ctx_start = max(0, lineno - 2)
                ctx_end = min(len(source_lines), lineno + 1)
                results.append(Finding(
                    rule_id="HARDCODED-SECRET-001",
                    file=filepath,
                    line=lineno,
                    severity="CRITICAL",
                    confidence=confidence,
                    cwe_id="CWE-798",
                    description=(
                        f"Hardcoded credential in variable '{var_name}' "
                        f"at line {lineno}. Hard-coded secrets must never "
                        f"appear in source code."
                    ),
                    recommendation=(
                        "Store secrets in environment variables or a secrets "
                        "manager (e.g. HashiCorp Vault, AWS Secrets Manager). "
                        "Never commit credentials to source control."
                    ),
                    sources=["hardcoded_literal"],
                    context_lines=source_lines[ctx_start:ctx_end],
                ))
                return  # don't double-report with entropy strategy

            # Strategy 2: entropy-based detection (any variable name)
            if len(value) >= 20 and _string_entropy(value) >= 3.5:
                confidence = 0.70
                ctx_start = max(0, lineno - 2)
                ctx_end = min(len(source_lines), lineno + 1)
                results.append(Finding(
                    rule_id="HARDCODED-SECRET-001",
                    file=filepath,
                    line=lineno,
                    severity="CRITICAL",
                    confidence=confidence,
                    cwe_id="CWE-798",
                    description=(
                        f"High-entropy string literal assigned to '{var_name}' "
                        f"at line {lineno} may be a hardcoded secret."
                    ),
                    recommendation=(
                        "Store secrets in environment variables or a secrets "
                        "manager. Never commit credentials to source control."
                    ),
                    sources=["hardcoded_literal"],
                    context_lines=source_lines[ctx_start:ctx_end],
                ))

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                lineno = getattr(node, "lineno", 0)
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        _check_assign(target.id, node.value, lineno)
                    elif isinstance(target, ast.Attribute):
                        _check_assign(target.attr, node.value, lineno)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                lineno = getattr(node, "lineno", 0)
                if isinstance(node.target, ast.Name):
                    _check_assign(node.target.id, node.value, lineno)

        return results

    def analyze_directory(self, directory: str) -> List[Finding]:
        all_findings: List[Finding] = []
        skip = {"__pycache__", ".venv", "venv", "node_modules", ".git"}
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in skip]
            for fname in files:
                if fname.endswith(".py"):
                    path = os.path.join(root, fname)
                    all_findings.extend(self.analyze_file(path))
        return all_findings

    # ── Private helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _vuln_severity(vuln_type: str) -> str:
        mapping = {
            "sql_injection": "HIGH",
            "shell_injection": "CRITICAL",
            "code_execution": "CRITICAL",
            "deserialization": "HIGH",
            "log_injection": "MEDIUM",
            "weak_crypto": "MEDIUM",
        }
        return mapping.get(vuln_type, "HIGH")

    @staticmethod
    def _recommendation(vuln_type: str) -> str:
        mapping = {
            "sql_injection": (
                "Use parameterized queries (cursor.execute(sql, params)) "
                "or an ORM instead of string interpolation."
            ),
            "shell_injection": (
                "Avoid shell=True; pass arguments as a list; "
                "validate/whitelist all user-supplied input before use."
            ),
            "code_execution": (
                "Remove eval/exec or restrict them to a hardened sandbox; "
                "never pass user-controlled data to them."
            ),
            "deserialization": (
                "Replace pickle with a safe serialization format (json, msgpack). "
                "Never deserialize untrusted data with pickle."
            ),
            "log_injection": (
                "Sanitize log messages; strip newline/CR characters from "
                "user-supplied values before logging."
            ),
            "weak_crypto": (
                "Do not use user-supplied data as cryptographic key/IV material "
                "without proper key derivation (e.g., PBKDF2, scrypt)."
            ),
        }
        return mapping.get(vuln_type, "Validate and sanitize all user-supplied data before use.")
