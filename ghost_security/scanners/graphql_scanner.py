"""
Ghost Security — GraphQL Security Scanner

Scans GraphQL schema files (.graphql, .gql) and server-side code (.py, .js, .ts)
for security misconfigurations including:

Schema rules:
  GQL-001  Sensitive field exposed without auth/deprecated directive
  GQL-002  Mutation without authentication directive
  GQL-003  Subscription without auth directive
  GQL-004  No query depth limiting directive in schema
  GQL-005  Introspection not disabled

Server code rules:
  GQL-010  graphene/strawberry — introspection enabled (Python)
  GQL-011  Apollo Server without depthLimit plugin (JS/TS)
  GQL-012  GraphQL query batching enabled without rate limiting
  GQL-013  Dangerous resolver — SQL/exec with user input
  GQL-014  N+1 query problem without DataLoader
  GQL-015  CSRF protection missing on GraphQL endpoint

Usage:
    from scanners.graphql_scanner import GraphQLScanner
    scanner = GraphQLScanner()
    result  = scanner.scan_directory("/path/to/project")
    # OR
    findings = scanner.scan_file("/path/to/schema.graphql")
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SKIP_DIRS: Set[str] = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", "coverage",
}

_SCHEMA_EXTENSIONS: Set[str] = {".graphql", ".gql"}
_CODE_EXTENSIONS: Set[str] = {".py", ".js", ".ts"}

# Fields whose presence in a GraphQL type is considered sensitive
_SENSITIVE_FIELDS: List[str] = [
    "password", "secret", "token", "apikey", "ssn",
    "creditcard", "dob", "pin",
]

# Auth directives that count as "protected"
_AUTH_DIRECTIVES: List[str] = [
    "@auth", "@authenticated", "@requiresauth", "@hasrole",
    "@isAuthenticated", "@permission",
]

# Depth-limit related tokens we look for anywhere in the schema
_DEPTH_LIMIT_TOKENS: List[str] = [
    "@complexity", "@cost", "maxdepth", "max_depth",
    "depth_limit", "depthlimit", "querydepth",
]

_CONFIDENCE = 72


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _is_comment_line(line: str, ext: str) -> bool:
    """Return True if *line* is a comment line for the given file extension."""
    stripped = line.lstrip()
    if ext in _SCHEMA_EXTENSIONS:
        return stripped.startswith("#")
    if ext == ".py":
        return stripped.startswith("#")
    # JS / TS
    return stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*")


def _evidence(line: str) -> str:
    """Strip a line and cap it at 120 characters for evidence."""
    return line.strip()[:120]


def _make_finding(
    rule_id: str,
    severity: str,
    cwe: str,
    file_path: str,
    line_no: int,
    message: str,
    description: str,
    evidence_text: str,
    recommendation: str,
) -> Dict:
    return {
        "type": "GRAPHQL_ISSUE",
        "id": rule_id,
        "severity": severity,
        "cwe": cwe,
        "file": str(file_path),
        "line": line_no,
        "message": message,
        "description": description,
        "evidence": evidence_text,
        "recommendation": recommendation,
        "source": "graphql_scanner",
        "scanner": "graphql",
        "confidence": _CONFIDENCE,
    }


# ---------------------------------------------------------------------------
# Schema file analysis
# ---------------------------------------------------------------------------

def _analyse_schema(file_path: Path, content: str) -> List[Dict]:
    """Run all GQL-001 … GQL-005 rules on a .graphql/.gql file."""
    findings: List[Dict] = []
    seen: Set[Tuple[str, int]] = set()
    lines = content.splitlines()
    ext = file_path.suffix.lower()
    fp = str(file_path)

    def add(finding: Dict) -> None:
        key = (finding["id"], finding["line"])
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    # --- Pre-scan state ---
    content_lower = content.lower()

    # Track which block type we are in for GQL-002 / GQL-003
    in_mutation = False
    in_subscription = False
    brace_depth = 0          # tracks nesting
    block_start_line = 0
    block_fields: List[Tuple[int, str]] = []  # (lineno, raw_line)

    # GQL-004: depth limit absent — check whole file once
    depth_limit_present = any(tok in content_lower for tok in _DEPTH_LIMIT_TOKENS)

    # GQL-005: introspection not disabled — check whole file once
    introspection_disabled = (
        "disableintrospection" in content_lower
        or "disable_introspection" in content_lower
        or "nointrospection" in content_lower
    )
    introspection_exposed = (
        "__schema" in content or "__type" in content
    )

    for idx, raw_line in enumerate(lines, start=1):
        if _is_comment_line(raw_line, ext):
            continue
        line_lower = raw_line.lower()

        # ----------------------------------------------------------------
        # GQL-001: sensitive field exposed without auth / @deprecated
        # ----------------------------------------------------------------
        for sf in _SENSITIVE_FIELDS:
            # Match field definition: word at start of expression then colon
            pattern = re.compile(
                r'\b' + re.escape(sf) + r'\b', re.IGNORECASE
            )
            if pattern.search(raw_line):
                # Check same line for protective directives
                line_lc = raw_line.lower()
                protected = (
                    "@deprecated" in line_lc
                    or any(d.lower() in line_lc for d in _AUTH_DIRECTIVES)
                )
                if not protected:
                    add(_make_finding(
                        "GQL-001", "MEDIUM", "CWE-284", fp, idx,
                        f"Sensitive field '{sf}' exposed without auth or @deprecated directive",
                        (
                            "A field with a sensitive name is exposed in the schema without an "
                            "authentication directive (@auth, @authenticated, @requiresAuth) or "
                            "@deprecated marker, allowing any caller to query it."
                        ),
                        _evidence(raw_line),
                        (
                            "Add an authentication directive (e.g. @auth) to the field definition "
                            "or mark it @deprecated and remove it. Ensure resolvers enforce "
                            "access control independently as well."
                        ),
                    ))

        # ----------------------------------------------------------------
        # Track type Mutation / Subscription blocks for GQL-002 / GQL-003
        # ----------------------------------------------------------------
        open_braces = raw_line.count("{")
        close_braces = raw_line.count("}")

        # Detect block entry
        if re.search(r'\btype\s+Mutation\b', raw_line, re.IGNORECASE):
            in_mutation = True
            in_subscription = False
            brace_depth = 0
            block_start_line = idx
            block_fields = []
        elif re.search(r'\btype\s+Subscription\b', raw_line, re.IGNORECASE):
            in_subscription = True
            in_mutation = False
            brace_depth = 0
            block_start_line = idx
            block_fields = []

        if in_mutation or in_subscription:
            brace_depth += open_braces - close_braces
            if brace_depth > 0 or open_braces > 0:
                block_fields.append((idx, raw_line))

            if brace_depth <= 0 and (open_braces > 0 or idx > block_start_line):
                # Block ended — evaluate fields
                block_type = "Mutation" if in_mutation else "Subscription"
                rule = "GQL-002" if in_mutation else "GQL-003"
                severity = "HIGH" if in_mutation else "MEDIUM"

                for field_lineno, field_line in block_fields:
                    fl_lower = field_line.lower().strip()
                    # Skip blank / brace-only lines and the type declaration itself
                    if not fl_lower or fl_lower in {"{", "}"} or "type mutation" in fl_lower or "type subscription" in fl_lower:
                        continue
                    # Is it a real field declaration? (contains colon or parenthesis)
                    if ":" not in field_line and "(" not in field_line:
                        continue
                    has_auth = any(d.lower() in fl_lower for d in _AUTH_DIRECTIVES)
                    if not has_auth:
                        add(_make_finding(
                            rule, severity, "CWE-284", fp, field_lineno,
                            f"{block_type} field lacks authentication directive",
                            (
                                f"A {block_type} resolver is defined without an authentication "
                                f"directive, meaning any unauthenticated caller can invoke it and "
                                f"mutate or stream server-side data."
                            ),
                            _evidence(field_line),
                            (
                                f"Add @auth or @authenticated to every {block_type} field, "
                                f"and verify that the server-side resolver also enforces "
                                f"authentication independently."
                            ),
                        ))

                in_mutation = False
                in_subscription = False
                block_fields = []
                brace_depth = 0

    # GQL-004: depth limiting absent from entire schema
    if not depth_limit_present:
        add(_make_finding(
            "GQL-004", "MEDIUM", "CWE-400", fp, 1,
            "No query depth limiting directive found in schema",
            (
                "The schema does not reference @complexity, @cost, or any maxDepth directive. "
                "Without depth limiting, malicious clients can craft deeply-nested queries that "
                "cause exponential resolver execution and denial-of-service."
            ),
            "(absent — no depth-limit token found in schema)",
            (
                "Add a query-complexity or depth-limit library (e.g. graphql-depth-limit, "
                "graphene-query-cost) and annotate expensive fields with @complexity/@cost. "
                "Reject queries that exceed a configured threshold."
            ),
        ))

    # GQL-005: introspection exposed / not disabled
    if introspection_exposed and not introspection_disabled:
        add(_make_finding(
            "GQL-005", "MEDIUM", "CWE-200", fp, 1,
            "GraphQL introspection not disabled — schema fully exposed",
            (
                "The schema references __schema or __type but does not explicitly disable "
                "introspection. In production, introspection allows attackers to enumerate the "
                "entire API surface, aiding targeted attacks."
            ),
            "(introspection fields present without disableIntrospection setting)",
            (
                "Disable introspection in production environments. Most frameworks support a "
                "disableIntrospection option or a NoSchemaIntrospectionCustomRule. "
                "Allow introspection only in development/staging behind authentication."
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# Server code analysis
# ---------------------------------------------------------------------------

# Compiled patterns for code rules — defined once at module load
_CODE_RULES: List[Tuple[str, re.Pattern, str, str, str, str, str]] = []


def _build_code_rules() -> None:
    """Populate _CODE_RULES list (called once on import)."""
    rules: List[Tuple[str, str, str, str, str, str, str]] = [
        # (id, raw_pattern, severity, cwe, message, description, recommendation)
        (
            "GQL-010",
            r'(?:graphene\.Schema|strawberry\.Schema)\s*\(',
            "MEDIUM", "CWE-200",
            "graphene/strawberry Schema instantiated — introspection likely enabled",
            (
                "A graphene or strawberry Schema is created without passing "
                "introspection=False. By default introspection is enabled, "
                "exposing the full schema to any client including attackers."
            ),
            (
                "Pass introspection=False to the Schema constructor in production: "
                "graphene.Schema(..., introspection=False). "
                "Guard via environment variable so development keeps introspection enabled."
            ),
        ),
        (
            "GQL-011",
            r'new\s+ApolloServer\s*\(',
            "MEDIUM", "CWE-400",
            "Apollo Server instantiated without graphql-depth-limit plugin",
            (
                "An ApolloServer is created but no depthLimit or graphql-depth-limit "
                "plugin import is detected nearby. Without depth limiting, clients can "
                "send arbitrarily deep queries causing exponential resolver load."
            ),
            (
                "Install graphql-depth-limit and add it as a validation rule: "
                "new ApolloServer({ validationRules: [depthLimit(10)], ... }). "
                "Combine with query complexity analysis for defence in depth."
            ),
        ),
        (
            "GQL-012",
            r'(?:allow_batching\s*=\s*True|batching\s*:\s*true)',
            "MEDIUM", "CWE-400",
            "GraphQL query batching enabled — rate limiting required",
            (
                "Query batching is explicitly enabled. Batching allows a single HTTP "
                "request to contain many operations, multiplying server load and "
                "bypassing per-request rate limits."
            ),
            (
                "Disable batching if not required, or pair it with per-operation "
                "rate limiting and query complexity scoring to prevent abuse."
            ),
        ),
        (
            "GQL-013",
            r'(?:def\s+resolve_\w+[^)]*\).*execute\s*\(|resolver\s*\(.*db\.query)',
            "HIGH", "CWE-89",
            "Dangerous resolver — raw SQL or exec call with potential user input",
            (
                "A GraphQL resolver passes arguments directly to execute() or db.query() "
                "without visible parameterisation. If user-controlled GraphQL arguments "
                "are concatenated into the query string, SQL injection is possible."
            ),
            (
                "Always use parameterised queries / prepared statements. "
                "Pass values as bind parameters, never by string concatenation. "
                "Use an ORM where possible and validate/whitelist all input fields."
            ),
        ),
        (
            "GQL-014",
            r'(?:for\s+\w+\s+in\s+.*resolve_|queryset\.filter\s*\(.*\)\s*for\b)',
            "LOW", "CWE-400",
            "Potential N+1 query in resolver — DataLoader not detected",
            (
                "A loop containing a database access pattern was found inside or adjacent "
                "to a resolver. Without a DataLoader (or equivalent batching), each parent "
                "object triggers a separate DB round-trip, causing N+1 performance issues "
                "that attackers can exploit to degrade service."
            ),
            (
                "Refactor using DataLoader (Python: strawberry-django DataLoader, "
                "graphene-django BatchLoader) to batch and cache DB calls per request. "
                "Profile resolver execution under load to confirm the fix."
            ),
        ),
        (
            "GQL-015",
            r'(?:graphql_view|GraphQLView|graphql_sync|graphql_wsgi)',
            "MEDIUM", "CWE-352",
            "GraphQL endpoint defined — CSRF protection should be verified",
            (
                "A GraphQL endpoint is registered but no explicit CSRF decorator "
                "(@csrf_exempt / @csrf_protect) or csrfToken header check is visible "
                "on the same line or in the nearby scope. GraphQL over POST/GET may be "
                "vulnerable to cross-site request forgery."
            ),
            (
                "For cookie-based authentication, enforce CSRF tokens on the GraphQL "
                "endpoint. In Django use @csrf_protect or require X-CSRFToken headers. "
                "For Bearer-token auth CSRF is less critical but defence-in-depth is recommended."
            ),
        ),
    ]

    for rule_id, raw_pat, sev, cwe, msg, desc, rec in rules:
        _CODE_RULES.append((rule_id, re.compile(raw_pat, re.IGNORECASE | re.DOTALL), sev, cwe, msg, desc, rec))


_build_code_rules()

# Supplementary single-line pattern for GQL-013 (single-line form)
_GQL013_SINGLE = re.compile(
    r'def\s+resolve_\w+.*\bexecute\s*\(', re.IGNORECASE
)

# Pattern to detect Apollo depth-limit import presence in the file
_DEPTH_LIMIT_IMPORT = re.compile(
    r'(?:depthLimit|graphql-depth-limit|depth_limit)', re.IGNORECASE
)

# GraphQL library fingerprints for _is_graphql_code
_GQL_IMPORT_PATTERNS = re.compile(
    r'''(?x)
    import\s+(?:graphql|graphene|strawberry|ariadne)       |
    from\s+(?:graphql|graphene|strawberry|ariadne)\s+import |
    require\s*\(\s*['"]graphql['"]                          |
    require\s*\(\s*['"]@apollo/server['"]                   |
    require\s*\(\s*['"]apollo-server                        |
    from\s+['"]@apollo/server['"]                           |
    from\s+['"]apollo-server                                |
    from\s+['"]graphql['"]                                  |
    ApolloServer                                            |
    GraphQLSchema                                           |
    buildSchema
    ''',
    re.IGNORECASE,
)


def _analyse_code(file_path: Path, content: str) -> List[Dict]:
    """Run GQL-010 … GQL-015 rules on server code files."""
    findings: List[Dict] = []
    seen: Set[Tuple[str, int]] = set()
    lines = content.splitlines()
    ext = file_path.suffix.lower()
    fp = str(file_path)
    is_js = ext in {".js", ".ts"}

    # Pre-scan: does the file contain a depth-limit import? (for GQL-011)
    has_depth_limit = bool(_DEPTH_LIMIT_IMPORT.search(content))

    def add(finding: Dict) -> None:
        key = (finding["id"], finding["line"])
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    for idx, raw_line in enumerate(lines, start=1):
        if _is_comment_line(raw_line, ext):
            continue

        for rule_id, pattern, severity, cwe, message, description, recommendation in _CODE_RULES:
            if not pattern.search(raw_line):
                continue

            # --- Rule-specific suppressions / extra checks ---

            if rule_id == "GQL-010":
                # Only flag Python files; suppress if introspection=False on same line
                if is_js:
                    continue
                if "introspection=false" in raw_line.lower() or "introspection = false" in raw_line.lower():
                    continue

            elif rule_id == "GQL-011":
                # Only flag JS/TS files; suppress if depth limit imported in file
                if not is_js:
                    continue
                if has_depth_limit:
                    continue

            elif rule_id == "GQL-012":
                pass  # applies to all, no extra guard

            elif rule_id == "GQL-013":
                # Check the line more carefully: want resolve_ AND execute( on same/nearby line
                # Already matched by pattern; flag it
                pass

            elif rule_id == "GQL-014":
                # Only flag Python files
                if is_js:
                    continue
                # Suppress if DataLoader appears anywhere in the file
                if "dataloader" in content.lower():
                    continue

            elif rule_id == "GQL-015":
                # Only flag Python files (Django/Flask GraphQL views)
                if is_js:
                    continue
                # Suppress if csrf_protect or csrf_exempt appears anywhere in file
                if re.search(r'csrf_(?:protect|exempt)', content, re.IGNORECASE):
                    continue

            add(_make_finding(
                rule_id, severity, cwe, fp, idx,
                message, description,
                _evidence(raw_line),
                recommendation,
            ))

    return findings


# ---------------------------------------------------------------------------
# Public scanner class
# ---------------------------------------------------------------------------

class GraphQLScanner:
    """
    Ghost Security GraphQL security scanner.

    Analyses GraphQL schema files and server-side GraphQL code for
    security misconfigurations across 15 distinct rules.
    """

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Scan a single file and return a list of finding dicts.

        Schema files (.graphql, .gql) → schema rules GQL-001..GQL-005.
        Code files (.py, .js, .ts) that look like GraphQL code → GQL-010..GQL-015.
        Returns an empty list for unrecognised or unreadable files.
        """
        path = Path(file_path)
        ext = path.suffix.lower()

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        if ext in _SCHEMA_EXTENSIONS:
            return _analyse_schema(path, content)

        if ext in _CODE_EXTENSIONS and self._is_graphql_code(content):
            return _analyse_code(path, content)

        return []

    def scan_directory(self, directory: str) -> Dict:
        """
        Recursively scan all eligible files under *directory*.

        Returns a summary dict with keys:
          files_scanned, schema_files, server_files,
          total_findings, findings, scanner
        """
        root = Path(directory)
        findings: List[Dict] = []
        schema_files = 0
        server_files = 0
        files_scanned = 0

        for file_path in self._iter_files(root):
            ext = file_path.suffix.lower()
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            file_findings: List[Dict] = []

            if ext in _SCHEMA_EXTENSIONS:
                file_findings = _analyse_schema(file_path, content)
                schema_files += 1
                files_scanned += 1
            elif ext in _CODE_EXTENSIONS and self._is_graphql_code(content):
                file_findings = _analyse_code(file_path, content)
                server_files += 1
                files_scanned += 1

            findings.extend(file_findings)

        return {
            "files_scanned": files_scanned,
            "schema_files": schema_files,
            "server_files": server_files,
            "total_findings": len(findings),
            "findings": findings,
            "scanner": "graphql",
        }

    @staticmethod
    def _is_graphql_code(content: str) -> bool:
        """
        Return True if *content* appears to be GraphQL server code.

        Checks for imports/requires of graphql, graphene, strawberry, ariadne,
        apollo-server, or usage of GraphQLSchema / buildSchema / ApolloServer.
        """
        return bool(_GQL_IMPORT_PATTERNS.search(content))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _iter_files(root: Path):
        """Yield all scannable files under *root*, skipping ignored directories."""
        all_exts = _SCHEMA_EXTENSIONS | _CODE_EXTENSIONS
        for item in root.rglob("*"):
            if any(skip in item.parts for skip in _SKIP_DIRS):
                continue
            if item.is_file() and item.suffix.lower() in all_exts:
                yield item
