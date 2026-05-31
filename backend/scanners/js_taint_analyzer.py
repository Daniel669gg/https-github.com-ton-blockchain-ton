"""
backend/scanners/js_taint_analyzer.py — JavaScript/TypeScript taint analyzer.

Uses a 3-phase approach:
1. Function extraction (regex-based AST approximation)
2. Variable assignment tracking within functions
3. Source→Sink taint propagation with sanitizer detection

Better than pure regex but does not require tree-sitter.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.js_taint")

# ---------------------------------------------------------------------------
# Source patterns — user-controlled inputs
# ---------------------------------------------------------------------------

JS_SOURCES: List[str] = [
    r"req\.(?:body|params|query|headers)(?:\[[\"\'][\w]+[\"\']|\.\w+)?",
    r"request\.(?:body|params|query|headers)(?:\[[\"\'][\w]+[\"\']|\.\w+)?",
    r"event\.(?:body|queryStringParameters|pathParameters)",
    r"process\.env\.\w+",
    r"ctx\.(?:request\.body|params|query)",
    r"document\.(?:URL|documentURI|referrer|location)",
    r"location\.(?:href|search|hash|pathname)",
    r"window\.location",
    r"(?:localStorage|sessionStorage)\.getItem\(",
    r"(?:URLSearchParams|FormData)",
]

# Compiled source regexes
_SOURCE_RES: List[re.Pattern[str]] = [re.compile(p) for p in JS_SOURCES]

# ---------------------------------------------------------------------------
# Sink patterns — grouped by vulnerability type
# ---------------------------------------------------------------------------

JS_SINKS: Dict[str, List[str]] = {
    "sql_injection": [
        r"(?:db|pool|conn|connection)\.(?:query|execute)\(",
        r"sequelize\.query\(",
        r"knex\.raw\(",
    ],
    "command_injection": [
        r"(?:exec|execSync)\(",
        r"(?:spawn|spawnSync)\(",
        r"child_process\.",
        r"\beval\(",
        r"new\s+Function\(",
    ],
    "xss": [
        r"innerHTML\s*=",
        r"outerHTML\s*=",
        r"document\.write\(",
        r"\.html\(",
        r"dangerouslySetInnerHTML",
    ],
    "path_traversal": [
        r"fs\.(?:readFile|writeFile|readFileSync|writeFileSync)\(",
        r"path\.join\(",
        r"\brequire\(",
    ],
    "open_redirect": [
        r"res\.redirect\(",
        r"window\.location\.href\s*=",
        r"location\.replace\(",
    ],
    "ssrf": [
        r"(?:axios|fetch|http|https)\.(?:get|post|put|delete|request)\(",
        r"new\s+XMLHttpRequest\(",
    ],
}

# Compiled sink regexes: {vuln_type: [compiled_re, ...]}
_SINK_RES: Dict[str, List[re.Pattern[str]]] = {
    vtype: [re.compile(p) for p in patterns]
    for vtype, patterns in JS_SINKS.items()
}

# CWE mapping
_VULN_CWE: Dict[str, str] = {
    "sql_injection": "CWE-89",
    "command_injection": "CWE-78",
    "xss": "CWE-79",
    "path_traversal": "CWE-22",
    "open_redirect": "CWE-601",
    "ssrf": "CWE-918",
}

_VULN_SEVERITY: Dict[str, str] = {
    "sql_injection": "HIGH",
    "command_injection": "CRITICAL",
    "xss": "HIGH",
    "path_traversal": "HIGH",
    "open_redirect": "MEDIUM",
    "ssrf": "HIGH",
}

# ---------------------------------------------------------------------------
# Sanitizer patterns — break taint flow
# ---------------------------------------------------------------------------

JS_SANITIZERS: List[str] = [
    r"(?:escape|encodeURIComponent|encodeURI)\(",
    r"DOMPurify\.sanitize\(",
    r"(?:parseInt|parseFloat|Number)\(",
    r"validator\.",
    r"\.replace\(/",
    r"\bparameterized\b",
    r"xss\.",
    r"sanitize\(",
]

_SANITIZER_RES: List[re.Pattern[str]] = [re.compile(p) for p in JS_SANITIZERS]

# Assignment detection regexes
_ASSIGN_RE = re.compile(
    r"""
    (?:const|let|var)\s+
    (?:
        \{([^}]+)\}  # destructuring: const {a, b} = ...
        |
        ([A-Za-z_$][\w$]*)  # simple: const x = ...
    )
    \s*=\s*(.+)
    """,
    re.VERBOSE,
)

_SIMPLE_ASSIGN_RE = re.compile(
    r"""
    (?:^|[;\n])\s*
    ([A-Za-z_$][\w$]*)\s*=\s*(.+)
    """,
    re.VERBOSE | re.MULTILINE,
)

# Template literal: backtick strings with ${...}
_TEMPLATE_LITERAL_RE = re.compile(r"`[^`]*\$\{([^}]+)\}[^`]*`")

# Function detection regex
_FUNC_RE = re.compile(
    r"""
    (?:
        (?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*   # named function
        |
        (?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*  # arrow / anon
        (?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>
        |
        ([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{             # method shorthand
    )
    """,
    re.VERBOSE | re.MULTILINE,
)


# ---------------------------------------------------------------------------
# JSTaintAnalyzer
# ---------------------------------------------------------------------------


class JSTaintAnalyzer:
    """Analyzes JavaScript/TypeScript files for taint flows.

    Uses a 3-phase approach (no tree-sitter required):
    1. Function extraction via regex
    2. Source detection and taint variable collection
    3. Fixed-point taint propagation + sink matching
    """

    def analyze_file(self, path: str) -> List[Finding]:
        """Analyze a JS/TS file for taint flows. Returns a list of Finding objects."""
        try:
            code = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", path, exc)
            return []

        findings: List[Finding] = []
        functions = self._extract_functions(code)

        if functions:
            for func in functions:
                func_code = func["body"]
                start_line = func["start_line"]

                sources = self._find_sources(func_code, start_line)
                if not sources:
                    continue

                tainted_vars: Set[str] = {s["var"] for s in sources if s["var"]}
                tainted_vars = self._track_assignments(func_code, tainted_vars)

                func_findings = self._find_sink_violations(
                    func_code, tainted_vars, start_line
                )
                findings.extend(
                    Finding(
                        rule_id=f.rule_id,
                        file=path,
                        line=f.line,
                        severity=f.severity,
                        confidence=f.confidence,
                        cwe_id=f.cwe_id,
                        description=f.description,
                        recommendation=f.recommendation,
                        sources=f.sources,
                        context_lines=f.context_lines,
                    )
                    for f in func_findings
                )
        else:
            # No functions extracted — scan the whole file
            sources = self._find_sources(code, 0)
            if sources:
                tainted_vars = {s["var"] for s in sources if s["var"]}
                tainted_vars = self._track_assignments(code, tainted_vars)
                raw = self._find_sink_violations(code, tainted_vars, 0)
                findings.extend(
                    Finding(
                        rule_id=f.rule_id,
                        file=path,
                        line=f.line,
                        severity=f.severity,
                        confidence=f.confidence,
                        cwe_id=f.cwe_id,
                        description=f.description,
                        recommendation=f.recommendation,
                        sources=f.sources,
                        context_lines=f.context_lines,
                    )
                    for f in raw
                )

        # Deduplicate by (line, rule_id)
        seen: Set[Tuple[int, str]] = set()
        deduped: List[Finding] = []
        for f in findings:
            key = (f.line, f.rule_id)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return deduped

    def _extract_functions(self, code: str) -> List[Dict]:
        """Extract function bodies for per-function analysis.

        Returns list of dicts:
          {"name": str, "start_line": int, "body": str, "params": List[str]}
        """
        results: List[Dict] = []
        lines = code.splitlines()

        # Brace-counting approach to find function boundaries.
        # Handles:
        #   - function foo(args) {
        #   - async function foo(args) {
        #   - function foo(args): ReturnType {       (TypeScript)
        #   - const foo = (args) => {
        #   - foo(args) {                            (method shorthand)
        func_start_re = re.compile(
            r"(?:(?:async\s+)?function\s+\w+\s*\([^)]*\)(?:\s*:\s*\w[\w<>\[\],\s|]*)?|"
            r"(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>|"
            r"\w+\s*\([^)]*\)(?:\s*:\s*\w[\w<>\[\],\s|]*)?)\s*\{"
        )

        i = 0
        while i < len(lines):
            line = lines[i]
            m = func_start_re.search(line)
            if m:
                # Extract function name
                name_m = re.search(
                    r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+))", line
                )
                func_name = (
                    name_m.group(1) or name_m.group(2) if name_m else f"anonymous_{i}"
                )

                # Find matching closing brace
                depth = line.count("{") - line.count("}")
                j = i + 1
                while j < len(lines) and depth > 0:
                    depth += lines[j].count("{") - lines[j].count("}")
                    j += 1

                body = "\n".join(lines[i:j])
                results.append(
                    {
                        "name": func_name,
                        "start_line": i + 1,
                        "body": body,
                        "params": [],
                    }
                )
                i = j
            else:
                i += 1

        return results

    def _find_sources(self, code: str, start_line: int) -> List[Dict]:
        """Find taint sources in code.

        Returns list of {"var": str, "line": int, "pattern": str}.
        """
        results: List[Dict] = []
        lines = code.splitlines()

        for lineno, line in enumerate(lines, start=1):
            for src_re in _SOURCE_RES:
                m = src_re.search(line)
                if not m:
                    continue

                # Try to find the variable this is assigned to
                var_name = self._extract_assigned_var(line)
                results.append(
                    {
                        "var": var_name,
                        "line": start_line + lineno - 1,
                        "pattern": m.group(0),
                    }
                )
                break  # one source per line

        return results

    def _track_assignments(self, code: str, tainted_vars: Set[str]) -> Set[str]:
        """Track taint propagation through assignments.

        Handles:
        - const/let/var x = tainted_y
        - const {field} = tainted_obj (destructuring)
        - Template literals: `SQL ${tainted_var}`
        - String concatenation: "SELECT " + tainted_var
        - Array access: tainted_arr[0]
        """
        tainted = set(tainted_vars)
        changed = True

        while changed:
            changed = False
            for line in code.splitlines():
                line = line.strip()

                # Skip comments
                if line.startswith("//") or line.startswith("*"):
                    continue

                # Destructuring: const {a, b} = tainted_obj
                dest_m = re.match(
                    r"(?:const|let|var)\s+\{([^}]+)\}\s*=\s*([A-Za-z_$][\w$$.]*)",
                    line,
                )
                if dest_m:
                    rhs_var = dest_m.group(2).split(".")[0]
                    if rhs_var in tainted:
                        new_vars = [
                            v.strip().split(":")[0].strip()
                            for v in dest_m.group(1).split(",")
                        ]
                        for nv in new_vars:
                            if nv and nv not in tainted:
                                tainted.add(nv)
                                changed = True
                        continue

                # Simple assignment: const x = ... / let x = ... / var x = ...
                m = re.match(
                    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)", line
                )
                if not m:
                    # Plain assignment without declaration: x = ...
                    m = re.match(r"([A-Za-z_$][\w$]*)\s*=\s*(.+)", line)

                if m:
                    lhs = m.group(1)
                    rhs = m.group(2)
                    if lhs in tainted:
                        continue

                    if self._rhs_is_tainted(rhs, tainted):
                        tainted.add(lhs)
                        changed = True

        return tainted

    def _rhs_is_tainted(self, rhs: str, tainted: Set[str]) -> bool:
        """Return True if any tainted variable appears in rhs."""
        # Template literal: check ${...} expressions
        for tm in _TEMPLATE_LITERAL_RE.finditer(rhs):
            expr = tm.group(1)
            for tv in tainted:
                if re.search(r"\b" + re.escape(tv) + r"\b", expr):
                    return True

        # String concatenation or general expression
        for tv in tainted:
            if re.search(r"\b" + re.escape(tv) + r"\b", rhs):
                return True

        return False

    def _find_sink_violations(
        self,
        code: str,
        tainted_vars: Set[str],
        start_line: int,
    ) -> List[Finding]:
        """Find sinks that receive tainted variables.

        Returns list of Finding objects (with placeholder file="").
        """
        if not tainted_vars:
            return []

        findings: List[Finding] = []
        lines = code.splitlines()

        for lineno, line in enumerate(lines, start=1):
            abs_lineno = start_line + lineno - 1

            # Check if this line has a sanitizer — skip if fully sanitized
            if self._line_is_sanitized(line):
                continue

            for vuln_type, sink_res in _SINK_RES.items():
                for sink_re in sink_res:
                    if not sink_re.search(line):
                        continue

                    # Check if a tainted var is used on this line
                    tainted_hit: Optional[str] = None
                    for tv in tainted_vars:
                        if re.search(r"\b" + re.escape(tv) + r"\b", line):
                            tainted_hit = tv
                            break

                    if tainted_hit is None:
                        # Also check template literals on the line
                        for tm in _TEMPLATE_LITERAL_RE.finditer(line):
                            expr = tm.group(1)
                            for tv in tainted_vars:
                                if re.search(r"\b" + re.escape(tv) + r"\b", expr):
                                    tainted_hit = tv
                                    break
                            if tainted_hit:
                                break

                    if tainted_hit is None:
                        continue

                    ctx_start = max(0, lineno - 2)
                    ctx_end = min(len(lines), lineno + 1)
                    context = lines[ctx_start:ctx_end]

                    findings.append(
                        Finding(
                            rule_id=f"JS-TAINT-{vuln_type.upper()}",
                            file="",  # caller fills in path
                            line=abs_lineno,
                            severity=_VULN_SEVERITY.get(vuln_type, "HIGH"),
                            confidence=0.80,
                            cwe_id=_VULN_CWE.get(vuln_type, "CWE-20"),
                            description=(
                                f"Tainted variable '{tainted_hit}' flows into "
                                f"{vuln_type.replace('_', ' ')} sink."
                            ),
                            recommendation=(
                                "Validate and sanitize all user-controlled input "
                                "before passing it to sensitive operations."
                            ),
                            sources=["js_user_input"],
                            context_lines=context,
                        )
                    )
                    break  # one finding per line per vuln type

        return findings

    def _extract_assigned_var(self, line: str) -> str:
        """Return the variable name being assigned on this line, or ''."""
        # const/let/var x: Type = ...  (TypeScript) or  const/let/var x = ...
        m = re.match(
            r"\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:\s*[\w<>\[\],\s|]+)?\s*=",
            line,
        )
        if m:
            return m.group(1)
        # x = ...
        m = re.match(r"\s*([A-Za-z_$][\w$]*)\s*=\s*[^=]", line)
        if m:
            return m.group(1)
        return ""

    def _line_is_sanitized(self, line: str) -> bool:
        """Return True if a sanitizer wraps the full expression on this line."""
        # Only consider the line sanitized if it appears to be a pure sanitizer call
        # (not just a sanitizer present somewhere on the line alongside a sink)
        sanitizer_call_re = re.compile(
            r"(?:parseInt|parseFloat|Number|encodeURIComponent|encodeURI"
            r"|DOMPurify\.sanitize|validator\.)\s*\("
        )
        # If the entire assignment RHS is wrapped in a sanitizer, consider safe
        m = re.match(
            r"\s*(?:const|let|var\s+)?[A-Za-z_$][\w$]*\s*=\s*"
            r"(?:parseInt|parseFloat|Number|encodeURIComponent|encodeURI"
            r"|DOMPurify\.sanitize|validator\.)\s*\(",
            line,
        )
        return m is not None

    def analyze_directory(self, directory: str) -> List[Finding]:
        """Scan all .js and .ts files recursively under directory."""
        all_findings: List[Finding] = []
        skip = {"node_modules", ".git", "__pycache__", "dist", "build"}

        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d not in skip]
            for fname in files:
                if fname.endswith((".js", ".ts", ".jsx", ".tsx")):
                    path = os.path.join(root, fname)
                    all_findings.extend(self.analyze_file(path))

        return all_findings
