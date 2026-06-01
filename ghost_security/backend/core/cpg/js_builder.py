"""
backend/core/cpg/js_builder.py — JavaScript/TypeScript CPG builder.

Extends the existing JS taint analysis (backend/scanners/js_taint_analyzer.py)
by building a proper CPGNode/CPGEdge graph for JS/TS source code.

Uses regex-based AST approximation (no npm/tree-sitter needed).

Produces a CodePropertyGraph compatible with:
- CPGQueryEngine (run_all_queries)
- InterproceduralDataflow
- AdvancedReachabilityAnalyzer
- SSAConverter

Supports:
- Node.js / Express / Next.js / Fastify / Koa
- TypeScript (same patterns, strips type annotations)
- React (JSX user input via props)
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.core.confidence import Finding
from backend.core.cpg.graph import (
    CPGEdge,
    CPGEdgeType,
    CPGNode,
    CPGNodeType,
    CodePropertyGraph,
)
from backend.scanners.js_taint_analyzer import JSTaintAnalyzer

logger = logging.getLogger("tythanai.js_cpg_builder")

# ---------------------------------------------------------------------------
# Source patterns — user-controlled inputs in JS/TS
# ---------------------------------------------------------------------------

_JS_SOURCES: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(r'req\.(?:body|params|query|headers)(?:\[[\"\'][\w]+[\"\']|\.\w+)?'), 'req.body/params/query', 0.95),
    (re.compile(r'request\.(?:body|params|query|headers)(?:\.\w+)?'), 'request.body/params/query', 0.95),
    (re.compile(r'event\.(?:body|queryStringParameters|pathParameters)'), 'Lambda event', 0.90),
    (re.compile(r'ctx\.(?:request\.body|params|query)'), 'Koa ctx', 0.90),
    (re.compile(r'process\.env\.\w+'), 'process.env', 0.75),
    (re.compile(r'window\.location\.\w+'), 'window.location (DOM XSS)', 0.85),
    (re.compile(r'document\.(?:URL|referrer|cookie)'), 'document.URL/cookie', 0.85),
    (re.compile(r'localStorage\.getItem\s*\('), 'localStorage', 0.70),
    (re.compile(r'URLSearchParams\s*\('), 'URLSearchParams', 0.80),
]

# ---------------------------------------------------------------------------
# Sink patterns — grouped by CWE
# ---------------------------------------------------------------------------

_JS_SINKS: Dict[str, List[Tuple[re.Pattern, str]]] = {
    "CWE-89": [
        (re.compile(r'\.query\s*\(\s*[`"\'][^`"\']*\$\{|[`"\'][^`"\']*\+\s*\w'), 'SQL string interpolation'),
        (re.compile(r'db\.(?:query|execute|run)\s*\('), 'DB query call'),
        (re.compile(r'sequelize\.query\s*\('), 'Sequelize raw query'),
        (re.compile(r'knex\.raw\s*\('), 'Knex raw query'),
        (re.compile(r'mongoose\.(?:find|findOne)\s*\(\{[^}]*\$where'), 'Mongoose $where injection'),
    ],
    "CWE-79": [
        (re.compile(r'innerHTML\s*='), 'innerHTML assignment'),
        (re.compile(r'outerHTML\s*='), 'outerHTML assignment'),
        (re.compile(r'document\.write\s*\('), 'document.write()'),
        (re.compile(r'\.html\s*\([^)]*\+'), 'jQuery .html() with concat'),
        (re.compile(r'dangerouslySetInnerHTML'), 'React dangerouslySetInnerHTML'),
        (re.compile(r'res\.send\s*\('), 'Express res.send()'),
    ],
    "CWE-78": [
        (re.compile(r'exec\s*\(\s*[`"\'][^`"\']*\$\{|exec\s*\([^)]*\+'), 'child_process exec with concat'),
        (re.compile(r'(?:child_process\.|require\(["\']child_process["\']\)\.)(?:exec|execSync|spawn)\s*\('), 'child_process exec/spawn'),
        (re.compile(r'shelljs\.\w+\s*\('), 'shelljs call'),
    ],
    "CWE-22": [
        (re.compile(r'fs\.(?:readFile|writeFile|readFileSync|createReadStream)\s*\('), 'fs file read/write'),
        (re.compile(r'path\.(?:join|resolve)\s*\([^)]*req\.'), 'path.join with req'),
        (re.compile(r'res\.sendFile\s*\('), 'res.sendFile()'),
    ],
    "CWE-918": [
        (re.compile(r'(?:axios|fetch|got|superagent|node-fetch)\s*\.?\s*(?:get|post|request)?\s*\('), 'HTTP client call'),
        (re.compile(r'http\.(?:get|request)\s*\('), 'http.get/request'),
        (re.compile(r'require\(["\']https?["\']\)\.(?:get|request)'), 'https module call'),
    ],
    "CWE-502": [
        (re.compile(r'JSON\.parse\s*\('), 'JSON.parse'),
        (re.compile(r'eval\s*\('), 'eval()'),
        (re.compile(r'Function\s*\('), 'new Function()'),
        (re.compile(r'vm\.runInNewContext\s*\('), 'vm.runInNewContext'),
        (re.compile(r'(?:serialize|deserialize|unserialize)\s*\('), 'serialization call'),
    ],
}

# Flatten sinks for quick-check iteration: (cwe_id, pattern, label)
_JS_SINK_FLAT: List[Tuple[str, re.Pattern, str]] = [
    (cwe, pat, label)
    for cwe, items in _JS_SINKS.items()
    for (pat, label) in items
]

# ---------------------------------------------------------------------------
# Sanitizer patterns — break taint flow, grouped by CWE
# ---------------------------------------------------------------------------

_JS_SANITIZERS: Dict[str, List[Tuple[re.Pattern, str]]] = {
    "CWE-89": [
        (re.compile(r'parameterized|prepare\s*\(|\?\s*,|\$\d+'), 'parameterized query'),
        (re.compile(r'escape\s*\(|escapeId\s*\('), 'mysql.escape()'),
        (re.compile(r'sequelize\.escape|literal\s*\('), 'Sequelize literal()'),
    ],
    "CWE-79": [
        (re.compile(r'DOMPurify\.sanitize\s*\('), 'DOMPurify.sanitize()'),
        (re.compile(r'sanitizeHtml\s*\('), 'sanitize-html'),
        (re.compile(r'encodeURIComponent\s*\(|encodeURI\s*\('), 'encodeURIComponent()'),
        (re.compile(r'textContent\s*='), 'textContent (safe)'),
        (re.compile(r'createTextNode\s*\('), 'createTextNode (safe)'),
    ],
    "CWE-78": [
        (re.compile(r'shellEscape\s*\(|shell-quote'), 'shell-quote/shellEscape'),
        (re.compile(r'spawn\s*\(\s*\w+\s*,\s*\['), 'spawn with array args'),
    ],
    "CWE-22": [
        (re.compile(r'path\.normalize\s*\('), 'path.normalize()'),
        (re.compile(r'\.startsWith\s*\('), '.startsWith() base check'),
        (re.compile(r'realpath\s*\('), 'fs.realpath()'),
    ],
}

# Severity mapping per CWE
_CWE_SEVERITY: Dict[str, str] = {
    "CWE-89": "HIGH",
    "CWE-79": "HIGH",
    "CWE-78": "CRITICAL",
    "CWE-22": "HIGH",
    "CWE-918": "HIGH",
    "CWE-502": "CRITICAL",
}

# Human-readable names per CWE
_CWE_NAMES: Dict[str, str] = {
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-78": "OS Command Injection",
    "CWE-22": "Path Traversal",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-502": "Deserialization of Untrusted Data",
}

# ---------------------------------------------------------------------------
# CPGNode type mapping for JS statement types
# ---------------------------------------------------------------------------

_JS_NODE_TYPE_MAP: Dict[str, CPGNodeType] = {
    "function_decl": CPGNodeType.CFG_ENTRY,
    "arrow_func": CPGNodeType.CFG_ENTRY,
    "assignment": CPGNodeType.DFG_DEF,
    "source": CPGNodeType.DFG_USE,
    "sink": CPGNodeType.DFG_USE,
    "call": CPGNodeType.AST_NODE,
    "return": CPGNodeType.CFG_EXIT,
}

# ---------------------------------------------------------------------------
# Regex helpers for JS parsing
# ---------------------------------------------------------------------------

# Template literals with interpolation
_TEMPLATE_LITERAL_RE = re.compile(r"`[^`]*\$\{([^}]+)\}[^`]*`")

# Assignment: const/let/var x = ... or x = ...
_DECL_ASSIGN_RE = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)(?:\s*:\s*[\w<>\[\],\s|&?]+)?\s*=\s*(.+)"
)
_PLAIN_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_$][\w$]*)\s*=\s*([^=].*)")

# Destructuring: const {a, b} = ...
_DESTRUCT_RE = re.compile(
    r"(?:const|let|var)\s+\{([^}]+)\}\s*=\s*([A-Za-z_$][\w$$.]*)"
)

# Function call: foo(...) or obj.method(...)
_CALL_RE = re.compile(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")

# Return statement
_RETURN_RE = re.compile(r"\breturn\b")

# Control flow
_IF_RE = re.compile(r"^\s*(?:else\s+)?if\s*\(")
_FOR_RE = re.compile(r"^\s*(?:for|while)\s*\(")
_TRY_RE = re.compile(r"^\s*try\s*\{")

# Function boundary detection (for _extract_functions)
_FUNC_START_RE = re.compile(
    r"""
    (?:
        (?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\([^)]*\)
        (?:\s*:\s*[\w<>\[\],\s|&?]+)?                              # optional TS return type
        \s*\{
    |
        (?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*
        (?:async\s*)?(?:\([^)]*\)|\w+)\s*=>\s*\{
    |
        (?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*
        (?:async\s+)?function\s*\([^)]*\)\s*\{
    |
        (?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*
        (?::\s*[\w<>\[\],\s|&?]+)?\s*\{
    )
    """,
    re.VERBOSE | re.MULTILINE,
)

# Arrow function without block body (single-expression arrows are handled inline)
_ARROW_INLINE_RE = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|\w+)\s*=>\s*([^{;][^;]*);?"
)

# TypeScript stripping
_TS_TYPE_ANNOTATION_RE = re.compile(
    r":\s*(?:readonly\s+)?(?:[A-Z][A-Za-z<>\[\],\s|&?]*|[a-z]+(?:\[\])?)"
    r"(?=\s*[,)=;{])"
)
_TS_INTERFACE_RE = re.compile(
    r"(?:export\s+)?interface\s+\w[\w<>,\s]*\s*\{[^}]*\}", re.DOTALL
)
_TS_TYPE_ALIAS_RE = re.compile(
    r"(?:export\s+)?type\s+\w[\w<>,\s]*\s*=\s*[^;]+;"
)
_TS_GENERIC_RE = re.compile(r"<[A-Za-z][\w<>,\s]*>")
_TS_AS_CAST_RE = re.compile(r"\s+as\s+[\w<>\[\]|&]+")
_TS_IMPORT_TYPE_RE = re.compile(r"import\s+type\s+[^;]+;")


# ---------------------------------------------------------------------------
# JSFinding dataclass
# ---------------------------------------------------------------------------

@dataclass
class JSFinding:
    """JS/TS-specific security finding with taint path information."""
    rule_id: str
    file: str
    line: int
    severity: str
    confidence: float
    cwe_id: str
    description: str
    recommendation: str
    source_code: str        # the vulnerable code snippet
    taint_path: List[str]   # variable names in the taint chain


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_node_id(file_path: str, line: int, col: int, suffix: str = "") -> str:
    """Produce a stable, deterministic node ID: sha8(file):line:col[:suffix]."""
    file_hash = hashlib.sha256(file_path.encode()).hexdigest()[:8]
    parts = [file_hash, str(line), str(col)]
    if suffix:
        parts.append(suffix)
    return ":".join(parts)


_edge_counter = 0


def _make_edge_id() -> str:
    global _edge_counter
    _edge_counter += 1
    return f"jse{_edge_counter}"


def _safe_add_edge(cpg: CodePropertyGraph, edge: CPGEdge) -> None:
    """Add an edge, silently skipping if nodes are missing or duplicate."""
    if edge.src_id not in cpg.nodes or edge.dst_id not in cpg.nodes:
        return
    # Check for duplicate
    for existing in cpg._adj.get(edge.src_id, []):
        if existing.dst_id == edge.dst_id and existing.edge_type == edge.edge_type:
            return
    try:
        cpg.add_edge(edge)
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# JSCPGBuilder
# ---------------------------------------------------------------------------


class JSCPGBuilder:
    """
    Builds a CodePropertyGraph from JavaScript/TypeScript source.

    Does not duplicate JSTaintAnalyzer — imports and extends it for CPG output.

    Pipeline:
    1. Extract functions (regex-based)
    2. For each function: extract assignments, calls, sources, sinks
    3. Build CPG nodes for each element
    4. Wire DFG_FLOW edges (assignment -> use)
    5. Wire CFG_NEXT edges (statement order)
    6. Wire CG_CALL edges (function calls)
    7. Mark source nodes with is_taint_source=True
    8. Mark sink nodes with is_taint_sink=True
    """

    def build_source(self, source: str, file_path: str = "<js>") -> CodePropertyGraph:
        """Build CPG from JS/TS source string."""
        stripped = self._strip_typescript(source)
        cpg = CodePropertyGraph()

        functions = self._extract_functions(stripped)

        # Track all function entry nodes for call-graph resolution
        all_func_entries: Dict[str, str] = {}  # func_name -> entry_node_id

        # First pass: build per-function CPG nodes and collect entry IDs
        all_nodes: List[CPGNode] = []
        all_edges: List[CPGEdge] = []

        if functions:
            for func in functions:
                nodes, edges = self._build_function_cpg(func, file_path)
                all_nodes.extend(nodes)
                all_edges.extend(edges)
                # Find the entry node for this function
                for n in nodes:
                    if n.node_type == CPGNodeType.CFG_ENTRY:
                        all_func_entries[func["name"]] = n.node_id
                        break
        else:
            # Treat the whole file as a single synthetic "module" function
            synthetic_func = {
                "name": "__module__",
                "params": [],
                "body": stripped,
                "start_line": 1,
                "end_line": len(stripped.splitlines()),
                "type": "module",
            }
            nodes, edges = self._build_function_cpg(synthetic_func, file_path)
            all_nodes.extend(nodes)
            all_edges.extend(edges)
            for n in nodes:
                if n.node_type == CPGNodeType.CFG_ENTRY:
                    all_func_entries["__module__"] = n.node_id
                    break

        # Add all nodes to CPG first
        for node in all_nodes:
            cpg.add_node(node)

        # Add all intra-function edges
        for edge in all_edges:
            _safe_add_edge(cpg, edge)

        # Second pass: resolve cross-function call edges
        cg_edges = self._resolve_calls(list(cpg.nodes.values()), all_func_entries)
        for edge in cg_edges:
            _safe_add_edge(cpg, edge)

        return cpg

    def build_file(self, file_path: str) -> CodePropertyGraph:
        """Build CPG from a JS/TS file."""
        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", file_path, exc)
            cpg = CodePropertyGraph()
            err_node = CPGNode(
                node_id=_make_node_id(file_path, 0, 0, "parse_error"),
                node_type=CPGNodeType.AST_NODE,
                ast_type="ParseError",
                code=str(exc),
                file=file_path,
                line=0,
                col=0,
                properties={"error": str(exc)},
            )
            cpg.add_node(err_node)
            return cpg
        return self.build_source(source, file_path=os.path.abspath(file_path))

    def _strip_typescript(self, source: str) -> str:
        """Strip TypeScript type annotations for easier parsing."""
        # Remove import type statements
        result = _TS_IMPORT_TYPE_RE.sub("", source)
        # Remove interface definitions
        result = _TS_INTERFACE_RE.sub("", result)
        # Remove type alias declarations
        result = _TS_TYPE_ALIAS_RE.sub("", result)
        # Remove 'as Type' casts
        result = _TS_AS_CAST_RE.sub("", result)
        # Remove generic type parameters like <T>, <K, V> in common positions
        # Only remove when clearly a TS generic (uppercase start or known types)
        result = re.sub(r"<(?:[A-Z]\w*(?:\s*,\s*[A-Z]\w*)*)>", "", result)
        # Remove ': Type' annotations in variable declarations and parameters
        # e.g. const x: string = ..., function f(a: number, b: string): void
        result = re.sub(
            r":\s*(?:string|number|boolean|void|any|never|unknown|object|null|undefined"
            r"|Array|Promise|Record|Map|Set|Function|Symbol|BigInt"
            r"|[A-Z]\w*(?:\[\])*(?:\s*\|\s*[A-Za-z]\w*(?:\[\])*)*)\b",
            "",
            result,
        )
        return result

    def _extract_functions(self, source: str) -> List[Dict]:
        """
        Extract function definitions using regex.

        Returns list of dicts:
          {name, params, body, start_line, end_line, type}

        Handles:
        - function f() { ... }
        - async function f() { ... }
        - const f = () => { ... }
        - const f = async (args) => { ... }
        - class methods: methodName(args) { ... }
        """
        results: List[Dict] = []
        lines = source.splitlines()
        n_lines = len(lines)

        i = 0
        while i < n_lines:
            line = lines[i]
            m = _FUNC_START_RE.search(line)
            if m:
                # Determine function name from whichever group matched
                func_name = (
                    m.group(1)
                    or m.group(2)
                    or m.group(3)
                    or m.group(4)
                    or f"anonymous_{i + 1}"
                )

                # Determine function type
                stripped_line = line.strip()
                if "=>" in stripped_line:
                    func_type = "arrow_func"
                elif "function" in stripped_line:
                    func_type = "function_decl"
                else:
                    func_type = "method"

                # Extract params from the match position
                params = self._extract_params_from_line(line)

                # Brace-count to find closing brace
                depth = line.count("{") - line.count("}")
                j = i + 1
                while j < n_lines and depth > 0:
                    depth += lines[j].count("{") - lines[j].count("}")
                    j += 1

                body = "\n".join(lines[i:j])
                results.append(
                    {
                        "name": func_name,
                        "params": params,
                        "body": body,
                        "start_line": i + 1,
                        "end_line": j,
                        "type": func_type,
                    }
                )
                # Skip past this function body to avoid re-parsing nested funcs at top
                # (they'll be handled via statement extraction)
                i = j
            else:
                i += 1

        return results

    def _extract_params_from_line(self, line: str) -> List[str]:
        """Extract parameter names from a function signature line."""
        m = re.search(r"\(([^)]*)\)", line)
        if not m:
            return []
        raw = m.group(1).strip()
        if not raw:
            return []
        params: List[str] = []
        for p in raw.split(","):
            p = p.strip()
            # Strip default values
            p = re.sub(r"\s*=\s*.*", "", p)
            # Strip TS type annotation
            p = re.sub(r"\s*:.*", "", p)
            # Strip rest spread
            p = p.lstrip(".")
            p = p.strip()
            if p and re.match(r"[A-Za-z_$][\w$]*", p):
                params.append(p)
        return params

    def _extract_statements(self, func_body: str, base_line: int) -> List[Dict]:
        """
        Extract statements from function body.

        Returns: [{type, code, line, var_name, call_name}]
        Types: assignment, call, return, if, for, while, try
        """
        statements: List[Dict] = []
        lines = func_body.splitlines()

        for idx, raw_line in enumerate(lines):
            line = raw_line.strip()
            if not line or line.startswith("//") or line.startswith("*") or line.startswith("/*"):
                continue

            abs_line = base_line + idx
            stmt: Dict[str, Any] = {
                "type": "unknown",
                "code": line,
                "line": abs_line,
                "var_name": None,
                "call_name": None,
            }

            # Return statement
            if _RETURN_RE.match(line):
                stmt["type"] = "return"
                statements.append(stmt)
                continue

            # If/else if
            if _IF_RE.match(line):
                stmt["type"] = "if"
                statements.append(stmt)
                continue

            # For/while loops
            if _FOR_RE.match(line):
                stmt["type"] = "for" if "for" in line[:6] else "while"
                statements.append(stmt)
                continue

            # Try block
            if _TRY_RE.match(line):
                stmt["type"] = "try"
                statements.append(stmt)
                continue

            # Declaration assignment: const/let/var x = ...
            m = _DECL_ASSIGN_RE.match(line)
            if m:
                stmt["type"] = "assignment"
                stmt["var_name"] = m.group(1)
                # Check if this is also a call
                call_m = _CALL_RE.search(m.group(2) if m.group(2) else "")
                if call_m:
                    stmt["call_name"] = call_m.group(1)
                statements.append(stmt)
                continue

            # Plain assignment: x = ...
            m = _PLAIN_ASSIGN_RE.match(line)
            if m:
                stmt["type"] = "assignment"
                stmt["var_name"] = m.group(1)
                call_m = _CALL_RE.search(m.group(2) if m.group(2) else "")
                if call_m:
                    stmt["call_name"] = call_m.group(1)
                statements.append(stmt)
                continue

            # Bare function call
            m = _CALL_RE.match(line)
            if m:
                stmt["type"] = "call"
                stmt["call_name"] = m.group(1)
                statements.append(stmt)
                continue

            # Fallback: generic statement
            stmt["type"] = "call" if "(" in line else "unknown"
            if "(" in line:
                cm = _CALL_RE.search(line)
                if cm:
                    stmt["call_name"] = cm.group(1)
            statements.append(stmt)

        return statements

    def _build_function_cpg(
        self, func: Dict, file_path: str
    ) -> Tuple[List[CPGNode], List[CPGEdge]]:
        """
        Build CPG nodes and edges for one function.
        Returns (nodes, edges).
        """
        nodes: List[CPGNode] = []
        edges: List[CPGEdge] = []

        func_name = func["name"]
        start_line = func["start_line"]
        func_type = func.get("type", "function_decl")

        # --- Synthetic ENTRY node ---
        entry_id = _make_node_id(file_path, start_line, 0, f"ENTRY_{func_name}")
        entry_node = CPGNode(
            node_id=entry_id,
            node_type=CPGNodeType.CFG_ENTRY,
            ast_type="CFG_ENTRY",
            code=f"ENTRY:{func_name}",
            file=file_path,
            line=start_line,
            col=0,
            properties={
                "function": func_name,
                "func_type": func_type,
                "params": func.get("params", []),
                "js_node": True,
            },
        )
        nodes.append(entry_node)

        # --- Synthetic EXIT node ---
        end_line = func.get("end_line", start_line)
        exit_id = _make_node_id(file_path, end_line, 0, f"EXIT_{func_name}")
        exit_node = CPGNode(
            node_id=exit_id,
            node_type=CPGNodeType.CFG_EXIT,
            ast_type="CFG_EXIT",
            code=f"EXIT:{func_name}",
            file=file_path,
            line=end_line,
            col=0,
            properties={
                "function": func_name,
                "js_node": True,
            },
        )
        nodes.append(exit_node)

        # --- Extract statements from function body ---
        stmts = self._extract_statements(func["body"], start_line)

        # Build taint tracking state for DFG edges
        # var_name -> list of def_node_ids (for DFG_FLOW wiring)
        var_defs: Dict[str, List[str]] = {}
        # Track tainted variables for source marking
        tainted_vars: Set[str] = set()

        # Keep track of stmt_nodes for CFG_NEXT wiring
        stmt_nodes: List[CPGNode] = []

        for stmt in stmts:
            stmt_line = stmt["line"]
            stmt_code = stmt["code"]
            stmt_type = stmt["type"]
            var_name = stmt.get("var_name")

            # Classify the statement
            classification, confidence = self._classify_statement(stmt)

            # Determine node type
            node_type = _JS_NODE_TYPE_MAP.get(stmt_type, CPGNodeType.AST_NODE)
            if classification == "source":
                node_type = CPGNodeType.DFG_USE
            elif classification == "sink":
                node_type = CPGNodeType.DFG_USE
            elif classification == "assignment":
                node_type = CPGNodeType.DFG_DEF

            # Build node properties
            props: Dict[str, Any] = {
                "function": func_name,
                "js_node": True,
                "stmt_type": stmt_type,
                "classification": classification,
                "confidence": confidence,
            }
            if var_name:
                props["defines"] = var_name
            if stmt.get("call_name"):
                props["callee"] = stmt["call_name"]

            # Detect CWE for sink/source nodes
            cwe_id = None
            sink_label = None
            source_label = None
            source_confidence = confidence

            # Check if line is a taint source
            for src_pattern, src_label, src_conf in _JS_SOURCES:
                if src_pattern.search(stmt_code):
                    props["is_taint_source"] = True
                    props["source_label"] = src_label
                    source_label = src_label
                    source_confidence = src_conf
                    props["source_confidence"] = src_conf
                    # Mark variable as tainted
                    if var_name:
                        tainted_vars.add(var_name)
                    break

            # Check if line is a sink
            for cwe, sink_pat, label in _JS_SINK_FLAT:
                if sink_pat.search(stmt_code):
                    # Check for sanitizer on same line
                    sanitized = False
                    for san_pat, san_label in _JS_SANITIZERS.get(cwe, []):
                        if san_pat.search(stmt_code):
                            sanitized = True
                            break
                    if not sanitized:
                        props["is_taint_sink"] = True
                        props["sink_cwe"] = cwe
                        props["sink_label"] = label
                        cwe_id = cwe
                        sink_label = label
                    break

            # Build the statement CPG node
            col = len(stmt_code) - len(stmt_code.lstrip())
            nid = _make_node_id(file_path, stmt_line, col, f"{func_name}_{stmt_type}_{stmt_line}")
            stmt_node = CPGNode(
                node_id=nid,
                node_type=node_type,
                ast_type=f"JS_{stmt_type.upper()}",
                code=stmt_code,
                file=file_path,
                line=stmt_line,
                col=col,
                properties=props,
            )
            nodes.append(stmt_node)
            stmt_nodes.append(stmt_node)

            # Track definition sites for DFG edges
            if var_name:
                var_defs.setdefault(var_name, []).append(nid)

        # --- Wire CFG_NEXT edges: ENTRY -> first stmt -> ... -> last stmt -> EXIT ---
        if stmt_nodes:
            # ENTRY -> first statement
            edges.append(CPGEdge(
                edge_id=_make_edge_id(),
                src_id=entry_id,
                dst_id=stmt_nodes[0].node_id,
                edge_type=CPGEdgeType.CFG_NEXT,
                properties={"function": func_name},
            ))
            # Sequential statement linking
            for idx in range(len(stmt_nodes) - 1):
                cur = stmt_nodes[idx]
                nxt = stmt_nodes[idx + 1]
                stmt_type_cur = cur.properties.get("stmt_type", "")

                # If/for/while use branch edges; others use CFG_NEXT
                if stmt_type_cur == "if":
                    edge_type = CPGEdgeType.CFG_BRANCH_TRUE
                else:
                    edge_type = CPGEdgeType.CFG_NEXT

                edges.append(CPGEdge(
                    edge_id=_make_edge_id(),
                    src_id=cur.node_id,
                    dst_id=nxt.node_id,
                    edge_type=edge_type,
                    properties={"function": func_name},
                ))

            # Last statement -> EXIT
            last_stmt = stmt_nodes[-1]
            edges.append(CPGEdge(
                edge_id=_make_edge_id(),
                src_id=last_stmt.node_id,
                dst_id=exit_id,
                edge_type=CPGEdgeType.CFG_NEXT,
                properties={"function": func_name},
            ))
        else:
            # Empty body: ENTRY -> EXIT
            edges.append(CPGEdge(
                edge_id=_make_edge_id(),
                src_id=entry_id,
                dst_id=exit_id,
                edge_type=CPGEdgeType.CFG_NEXT,
                properties={"function": func_name},
            ))

        # --- Wire DFG_FLOW edges ---
        # For each statement node, if its code uses a variable that was defined,
        # add a DFG_FLOW edge from the def site to the use site.
        for stmt_node in stmt_nodes:
            stmt_code = stmt_node.code
            # Find all variable references in this statement
            for var_name, def_ids in var_defs.items():
                if var_name == stmt_node.properties.get("defines"):
                    continue  # skip self-references
                if re.search(r"\b" + re.escape(var_name) + r"\b", stmt_code):
                    for def_id in def_ids:
                        if def_id != stmt_node.node_id:
                            edges.append(CPGEdge(
                                edge_id=_make_edge_id(),
                                src_id=def_id,
                                dst_id=stmt_node.node_id,
                                edge_type=CPGEdgeType.DFG_FLOW,
                                properties={
                                    "var": var_name,
                                    "function": func_name,
                                },
                            ))

            # Also check template literal interpolations
            for tm in _TEMPLATE_LITERAL_RE.finditer(stmt_code):
                expr = tm.group(1)
                for var_name, def_ids in var_defs.items():
                    if re.search(r"\b" + re.escape(var_name) + r"\b", expr):
                        for def_id in def_ids:
                            if def_id != stmt_node.node_id:
                                edges.append(CPGEdge(
                                    edge_id=_make_edge_id(),
                                    src_id=def_id,
                                    dst_id=stmt_node.node_id,
                                    edge_type=CPGEdgeType.DFG_FLOW,
                                    properties={
                                        "var": var_name,
                                        "template_literal": True,
                                        "function": func_name,
                                    },
                                ))

        return nodes, edges

    def _classify_statement(
        self, stmt: Dict, cwe_id: Optional[str] = None
    ) -> Tuple[str, float]:
        """
        Classify a statement as source/sink/sanitizer/assignment/neutral.
        Returns: (classification, confidence)
        """
        code = stmt.get("code", "")

        # Check sources
        for src_pattern, src_label, src_conf in _JS_SOURCES:
            if src_pattern.search(code):
                return ("source", src_conf)

        # Check sinks (filtered by cwe_id if provided)
        sink_cwes = [cwe_id] if cwe_id else list(_JS_SINKS.keys())
        for cwe in sink_cwes:
            for sink_pat, label in _JS_SINKS.get(cwe, []):
                if sink_pat.search(code):
                    # Check if sanitized
                    for san_pat, _ in _JS_SANITIZERS.get(cwe, []):
                        if san_pat.search(code):
                            return ("sanitized", 0.50)
                    return ("sink", 0.85)

        # Assignment
        if stmt.get("type") == "assignment":
            return ("assignment", 0.90)

        # Generic call
        if stmt.get("type") == "call":
            return ("call", 0.70)

        # Return
        if stmt.get("type") == "return":
            return ("return", 0.80)

        return ("neutral", 0.50)

    def _resolve_calls(
        self, nodes: List[CPGNode], all_functions: Dict[str, str]
    ) -> List[CPGEdge]:
        """
        Resolve function calls within the same file and add CG_CALL edges.
        all_functions: func_name -> entry_node_id
        """
        edges: List[CPGEdge] = []
        seen_pairs: Set[Tuple[str, str]] = set()

        for node in nodes:
            callee = node.properties.get("callee", "")
            if not callee:
                continue

            # Normalize callee: strip method chain prefix (obj.foo -> foo)
            callee_base = callee.split(".")[-1]

            target_id = all_functions.get(callee) or all_functions.get(callee_base)
            if target_id is None:
                continue

            pair = (node.node_id, target_id)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)

            edges.append(CPGEdge(
                edge_id=_make_edge_id(),
                src_id=node.node_id,
                dst_id=target_id,
                edge_type=CPGEdgeType.CG_CALL,
                properties={
                    "callee": callee,
                    "resolved": True,
                },
            ))
            # Reverse return edge
            edges.append(CPGEdge(
                edge_id=_make_edge_id(),
                src_id=target_id,
                dst_id=node.node_id,
                edge_type=CPGEdgeType.CG_RETURN,
                properties={
                    "callee": callee,
                },
            ))

        return edges


# ---------------------------------------------------------------------------
# JSScanner — wraps JSCPGBuilder + JSTaintAnalyzer for full security scanning
# ---------------------------------------------------------------------------


class JSScanner:
    """
    Wraps JSCPGBuilder + JSTaintAnalyzer for JS/TS security scanning.

    Produces findings compatible with Finding model from backend.core.confidence.

    Strategy:
    1. Run JSTaintAnalyzer for taint-flow findings (proven path tracing).
    2. Run JSCPGBuilder to build a CPG.
    3. Walk CPG nodes to detect sink nodes reachable from tainted source nodes
       via DFG_FLOW edges — augmenting taint-analyzer findings with CPG evidence.
    4. Deduplicate and return unified Finding list.
    """

    def __init__(self) -> None:
        self._taint_analyzer = JSTaintAnalyzer()
        self._cpg_builder = JSCPGBuilder()

    def scan_source(self, source: str, file_path: str = "<js>") -> List[Finding]:
        """Scan JS/TS source code, return list of Finding objects."""
        # Phase 1: taint-flow analysis via existing JSTaintAnalyzer
        # JSTaintAnalyzer.analyze_file requires a real file; we use a temp approach:
        # feed source directly via the internal methods.
        taint_findings = self._run_taint_analysis(source, file_path)

        # Phase 2: CPG-based sink detection
        cpg_findings = self._run_cpg_analysis(source, file_path)

        # Merge and deduplicate
        all_findings = taint_findings + cpg_findings
        return self._deduplicate(all_findings)

    def scan_file(self, file_path: str) -> List[Finding]:
        """Scan a JS/TS file."""
        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", file_path, exc)
            return []
        return self.scan_source(source, file_path)

    def scan_directory(
        self,
        root: str,
        extensions: Tuple[str, ...] = (".js", ".ts", ".jsx", ".tsx", ".mjs"),
    ) -> List[Finding]:
        """Scan all JS/TS files in directory."""
        all_findings: List[Finding] = []
        skip_dirs = {"node_modules", ".git", "__pycache__", "dist", "build", ".next", "coverage"}

        for dir_root, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fname in files:
                if any(fname.endswith(ext) for ext in extensions):
                    fpath = os.path.join(dir_root, fname)
                    try:
                        findings = self.scan_file(fpath)
                        all_findings.extend(findings)
                    except Exception as exc:
                        logger.warning("Error scanning %s: %s", fpath, exc)

        return self._deduplicate(all_findings)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_taint_analysis(self, source: str, file_path: str) -> List[Finding]:
        """
        Run JSTaintAnalyzer taint logic directly on the source string,
        using its internal methods (avoids file I/O).
        """
        analyzer = self._taint_analyzer
        findings: List[Finding] = []

        functions = analyzer._extract_functions(source)

        if functions:
            for func in functions:
                func_code = func["body"]
                start_line = func["start_line"]

                sources = analyzer._find_sources(func_code, start_line)
                if not sources:
                    continue

                tainted_vars: Set[str] = {s["var"] for s in sources if s["var"]}
                tainted_vars = analyzer._track_assignments(func_code, tainted_vars)

                raw = analyzer._find_sink_violations(func_code, tainted_vars, start_line)
                for f in raw:
                    findings.append(Finding(
                        rule_id=f.rule_id,
                        file=file_path,
                        line=f.line,
                        severity=f.severity,
                        confidence=f.confidence,
                        cwe_id=f.cwe_id,
                        description=f.description,
                        recommendation=f.recommendation,
                        sources=f.sources,
                        context_lines=f.context_lines,
                    ))
        else:
            # Whole-file analysis
            sources = analyzer._find_sources(source, 1)
            if sources:
                tainted_vars = {s["var"] for s in sources if s["var"]}
                tainted_vars = analyzer._track_assignments(source, tainted_vars)
                raw = analyzer._find_sink_violations(source, tainted_vars, 1)
                for f in raw:
                    findings.append(Finding(
                        rule_id=f.rule_id,
                        file=file_path,
                        line=f.line,
                        severity=f.severity,
                        confidence=f.confidence,
                        cwe_id=f.cwe_id,
                        description=f.description,
                        recommendation=f.recommendation,
                        sources=f.sources,
                        context_lines=f.context_lines,
                    ))

        return findings

    def _run_cpg_analysis(self, source: str, file_path: str) -> List[Finding]:
        """
        Build a CPG and walk it for sink nodes reachable from source nodes
        via DFG_FLOW edges.  Produces additional findings beyond pure taint tracing.
        """
        findings: List[Finding] = []

        try:
            cpg = self._cpg_builder.build_source(source, file_path)
        except Exception as exc:
            logger.warning("CPG build error for %s: %s", file_path, exc)
            return []

        # Find all taint source nodes
        source_nodes = [
            n for n in cpg.nodes.values()
            if n.properties.get("is_taint_source")
        ]

        # Find all sink nodes
        sink_nodes = [
            n for n in cpg.nodes.values()
            if n.properties.get("is_taint_sink")
        ]

        if not source_nodes or not sink_nodes:
            return []

        # For each source, BFS via DFG_FLOW to find reachable sink nodes
        dfg_edge_types = [CPGEdgeType.DFG_FLOW, CPGEdgeType.CFG_NEXT]

        for src_node in source_nodes:
            reachable = cpg.reachable(
                src_node.node_id,
                edge_types=dfg_edge_types,
                max_depth=30,
            )

            for sink_node in sink_nodes:
                if sink_node.node_id not in reachable:
                    continue

                # Avoid duplicate source-sink pair findings
                cwe_id = sink_node.properties.get("sink_cwe", "CWE-20")
                sink_label = sink_node.properties.get("sink_label", "unknown sink")
                src_label = src_node.properties.get("source_label", "user input")
                severity = _CWE_SEVERITY.get(cwe_id, "HIGH")
                cwe_name = _CWE_NAMES.get(cwe_id, cwe_id)

                # Build the taint path (simplified: source var name -> sink)
                src_var = src_node.properties.get("defines", "")
                taint_path = [src_label, sink_label]
                if src_var:
                    taint_path = [src_label, src_var, sink_label]

                findings.append(Finding(
                    rule_id=f"JS-CPG-{cwe_id.replace('-', '_')}",
                    file=file_path,
                    line=sink_node.line,
                    severity=severity,
                    confidence=min(
                        src_node.properties.get("source_confidence", 0.85),
                        0.90,
                    ),
                    cwe_id=cwe_id,
                    description=(
                        f"CPG taint flow: {src_label} reaches {sink_label} "
                        f"({cwe_name}). "
                        f"Source at line {src_node.line}, sink at line {sink_node.line}."
                    ),
                    recommendation=self._get_recommendation(cwe_id),
                    sources=["js_cpg_taint"],
                    context_lines=[sink_node.code],
                ))

        return findings

    def _get_recommendation(self, cwe_id: str) -> str:
        """Return a CWE-specific remediation recommendation."""
        recs: Dict[str, str] = {
            "CWE-89": (
                "Use parameterized queries or prepared statements instead of "
                "string concatenation. Never pass user input directly to SQL queries."
            ),
            "CWE-79": (
                "Sanitize all user-controlled output with DOMPurify.sanitize() "
                "or use textContent instead of innerHTML. Encode output for the correct context."
            ),
            "CWE-78": (
                "Avoid passing user input to shell commands. Use spawn() with an array "
                "of arguments instead of exec() with string concatenation. "
                "Use shell-quote to escape if shell is required."
            ),
            "CWE-22": (
                "Validate and normalize file paths with path.normalize() and verify "
                "they are within an allowed base directory using path.resolve() + startsWith()."
            ),
            "CWE-918": (
                "Validate and allowlist URLs before making server-side HTTP requests. "
                "Never pass raw user input as a URL to HTTP client libraries."
            ),
            "CWE-502": (
                "Avoid deserializing untrusted data. Use JSON.parse() only on validated input. "
                "Never use eval() or new Function() with user-controlled data."
            ),
        }
        return recs.get(
            cwe_id,
            "Validate and sanitize all user-controlled input before passing it to sensitive operations.",
        )

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """Deduplicate findings by (file, line, rule_id)."""
        seen: Set[Tuple[str, int, str]] = set()
        result: List[Finding] = []
        for f in findings:
            key = (f.file, f.line, f.rule_id)
            if key not in seen:
                seen.add(key)
                result.append(f)
        return result
