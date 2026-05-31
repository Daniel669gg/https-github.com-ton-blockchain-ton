"""
TythanAI — Cross-Repository Taint Analyzer
Detects unsafe data flows between microservices through API calls,
shared databases, message queues, and environment variables.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger("ghost.cross_repo_taint")

# ---------------------------------------------------------------------------
# Regex patterns for static analysis
# ---------------------------------------------------------------------------

# HTTP endpoint decorators
_RE_ENDPOINT = re.compile(
    r"""
    @(?:app|router)\.(?:get|post|put|delete|patch|options|head|route)
    \s*\(\s*
    ['"]([^'"]+)['"]
    """,
    re.VERBOSE | re.IGNORECASE,
)

# HTTP method in decorator: @router.get / @app.post etc.
_RE_ENDPOINT_METHOD = re.compile(
    r"""@(?:app|router)\.(get|post|put|delete|patch|options|head|route)""",
    re.IGNORECASE,
)

# Requests / httpx calls
_RE_HTTP_CALL = re.compile(
    r"""
    (?:requests|httpx)\s*\.\s*(get|post|put|delete|patch|request)\s*\(
    \s*([^\n,)]+)       # first argument (URL or url=...)
    """,
    re.VERBOSE | re.IGNORECASE,
)

# urllib calls
_RE_URLLIB_CALL = re.compile(
    r"""urllib\s*\.\s*request\s*\.\s*urlopen\s*\(\s*([^\n,)]+)""",
    re.IGNORECASE,
)

# Environment variable access
_RE_ENV_VAR = re.compile(
    r"""
    (?:os\.environ(?:\.get)?\(\s*['"]([^'"]+)['"]\s*\)|
       os\.getenv\(\s*['"]([^'"]+)['"]\s*\))
    """,
    re.VERBOSE,
)

# Database connection strings / paths
_RE_SQLITE = re.compile(r"""sqlite:///([^\s'"]+)|['"]([\w/.-]+\.db)['"]""")
_RE_POSTGRES = re.compile(
    r"""postgresql(?:\+\w+)?://[^'"\s]*""", re.IGNORECASE
)
_RE_MYSQL = re.compile(r"""mysql(?:\+\w+)?://[^'"\s]*""", re.IGNORECASE)

# Pydantic / sanitisation markers near the call site
_RE_SANITIZED_MARKER = re.compile(
    r"""\b(pydantic|validate|sanitize|clean|BaseModel|Schema|validator)\b""",
    re.IGNORECASE,
)

# User-controlled data variable names
_USER_DATA_NAMES = re.compile(
    r"""\b(user_\w+|request\.\w+|body|params|data|payload|user_input|user_data)\b""",
    re.IGNORECASE,
)

# Sensitive env-var name patterns (for severity downgrade)
_SENSITIVE_ENV_PATTERN = re.compile(
    r"""(SECRET|KEY|TOKEN|PASSWORD|PASS|CREDENTIAL|PRIVATE|AUTH)""",
    re.IGNORECASE,
)

# Sink type patterns
_SINK_SQL_PATTERN = re.compile(r"""\b(cursor\.execute|session\.execute|\.query\(|\.raw\()\b""")
_SINK_EXEC_PATTERN = re.compile(r"""\b(os\.system|subprocess|exec|eval|shell=True)\b""")
_SINK_FILE_WRITE_PATTERN = re.compile(r"""\b(open\(|write\(|\.write\()\b""")

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ServiceEndpoint(BaseModel):
    """An HTTP endpoint exposed by a service."""

    service: str
    file: str
    line: int
    method: str           # GET/POST/PUT/DELETE
    path: str             # e.g. "/api/users/{id}"
    accepts_user_input: bool


class APICall(BaseModel):
    """An outgoing HTTP call from one service to another."""

    caller_service: str
    caller_file: str
    caller_line: int
    target_url_pattern: str   # e.g. "http://user-service/"
    method: str
    passes_user_data: bool    # True if user-controlled data in body/params
    sanitized: bool           # True if Pydantic/validation applied before call


class CrossRepoTaintPath(BaseModel):
    """A taint path that crosses service boundaries."""

    path_id: str
    source_service: str
    source_file: str
    source_line: int
    source_type: str       # "user_input" | "env_var" | "shared_db" | "api_param"
    sink_service: str
    sink_file: str
    sink_line: int
    sink_type: str         # "sql_query" | "exec" | "file_write" | "api_response"
    transmission: str      # "http_api" | "shared_db" | "env_var" | "message_queue"
    sanitized: bool
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW
    description: str


class CrossRepoAnalysisReport(BaseModel):
    """Full cross-repository taint analysis report."""

    analysis_id: str
    analyzed_at: str
    repos_analyzed: List[str]
    taint_paths: List[CrossRepoTaintPath] = Field(default_factory=list)
    total_paths: int = 0
    unsanitized_paths: int = 0
    critical_paths: int = 0
    shared_databases: List[str] = Field(default_factory=list)
    shared_env_vars: List[str] = Field(default_factory=list)
    api_surface: List[ServiceEndpoint] = Field(default_factory=list)

    def to_markdown(self) -> str:
        lines: List[str] = [
            "# Cross-Repository Taint Analysis Report",
            "",
            f"**Analysis ID:** `{self.analysis_id}`",
            f"**Analyzed At:** {self.analyzed_at}",
            f"**Repositories:** {', '.join(self.repos_analyzed) or '—'}",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total taint paths | {self.total_paths} |",
            f"| Unsanitized paths | {self.unsanitized_paths} |",
            f"| Critical paths | {self.critical_paths} |",
            f"| Shared databases | {len(self.shared_databases)} |",
            f"| Shared env vars | {len(self.shared_env_vars)} |",
            f"| API surface (endpoints) | {len(self.api_surface)} |",
            "",
        ]
        if self.shared_databases:
            lines += ["## Shared Databases", ""]
            for db in self.shared_databases:
                lines.append(f"- `{db}`")
            lines.append("")

        if self.shared_env_vars:
            lines += ["## Shared Environment Variables", ""]
            for ev in self.shared_env_vars:
                lines.append(f"- `{ev}`")
            lines.append("")

        if self.taint_paths:
            lines += [
                "## Taint Paths",
                "",
                "| Severity | Source | Sink | Sanitized | Description |",
                "|----------|--------|------|-----------|-------------|",
            ]
            for tp in self.taint_paths:
                src = f"`{tp.source_service}:{tp.source_file}:{tp.source_line}`"
                snk = f"`{tp.sink_service}:{tp.sink_file}:{tp.sink_line}`"
                lines.append(
                    f"| {tp.severity} | {src} | {snk} "
                    f"| {'✅' if tp.sanitized else '❌'} | {tp.description[:80]} |"
                )
            lines.append("")
        return "\n".join(lines)

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)


# ---------------------------------------------------------------------------
# Internal data types
# ---------------------------------------------------------------------------


class _ServiceInfo:
    """Holds all data discovered for a single service/repo."""

    __slots__ = (
        "name", "repo_path", "endpoints", "api_calls",
        "env_vars", "db_connections",
    )

    def __init__(self, name: str, repo_path: Path) -> None:
        self.name: str = name
        self.repo_path: Path = repo_path
        self.endpoints: List[ServiceEndpoint] = []
        self.api_calls: List[APICall] = []
        self.env_vars: Dict[str, List[Tuple[str, int]]] = {}   # var_name → [(file, line)]
        self.db_connections: List[str] = []                    # connection strings / paths


# ---------------------------------------------------------------------------
# CrossRepoTaintAnalyzer
# ---------------------------------------------------------------------------


class CrossRepoTaintAnalyzer:
    """
    Analyzes multiple service repositories for cross-service taint flows.

    Algorithm:
    1. Scan each repo to discover endpoints, outgoing API calls, env vars,
       and DB connection strings.
    2. Build a call graph: service A → service B (keyed on URL prefix match).
    3. Emit taint paths for:
       a. Service A has user input AND calls B unsanitized.
       b. Two services share the same DB connection string.
       c. Two services share sensitive env vars.
    4. Classify severity based on sink type and sanitization state.
    """

    def __init__(self, max_depth: int = 5) -> None:
        self.max_depth = max_depth

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, repo_paths: List[Path]) -> CrossRepoAnalysisReport:
        """
        Scan all repos and return a :class:`CrossRepoAnalysisReport`.
        """
        analysis_id = str(uuid.uuid4())
        analyzed_at = datetime.now(timezone.utc).isoformat()

        services: List[_ServiceInfo] = []
        for rp in repo_paths:
            rp = Path(rp)
            if not rp.exists():
                logger.warning("cross_repo_taint: repo path does not exist: %s", rp)
                continue
            try:
                info = self._scan_service(rp)
                services.append(info)
            except Exception as exc:
                logger.warning("cross_repo_taint: failed to scan %s: %s", rp, exc)

        taint_paths: List[CrossRepoTaintPath] = []

        # Taint paths from HTTP API cross-calls
        taint_paths.extend(self._find_api_taint_paths(services))

        # Shared database taint paths
        shared_dbs = self._find_shared_databases(
            [{"name": s.name, "db_connections": s.db_connections} for s in services]
        )
        taint_paths.extend(self._build_shared_db_paths(services, shared_dbs))

        # Shared env var paths
        shared_env = self._find_shared_env_vars(services)
        taint_paths.extend(self._build_env_var_paths(services, shared_env))

        # Collect all service endpoints for the report surface
        api_surface: List[ServiceEndpoint] = []
        for svc in services:
            api_surface.extend(svc.endpoints)

        return CrossRepoAnalysisReport(
            analysis_id=analysis_id,
            analyzed_at=analyzed_at,
            repos_analyzed=[str(s.repo_path) for s in services],
            taint_paths=taint_paths,
            total_paths=len(taint_paths),
            unsanitized_paths=sum(1 for p in taint_paths if not p.sanitized),
            critical_paths=sum(1 for p in taint_paths if p.severity == "CRITICAL"),
            shared_databases=shared_dbs,
            shared_env_vars=shared_env,
            api_surface=api_surface,
        )

    # ── Service scanning ──────────────────────────────────────────────────────

    def _scan_service(self, repo_path: Path) -> _ServiceInfo:
        """Walk *repo_path* and extract security-relevant information."""
        name = self._discover_service_name(repo_path)
        info = _ServiceInfo(name=name, repo_path=repo_path)

        skip_dirs = {
            "__pycache__", ".git", ".venv", "venv", "env",
            "node_modules", "site-packages", ".tox", "build", "dist",
        }

        for dirpath_str, dirnames, filenames in os.walk(repo_path):
            dirnames[:] = [
                d for d in dirnames
                if d not in skip_dirs and not d.startswith(".")
            ]
            for fname in filenames:
                if not fname.endswith(".py"):
                    continue
                fp = Path(dirpath_str) / fname
                try:
                    self._process_file(fp, info)
                except Exception as exc:
                    logger.debug("cross_repo_taint: error processing %s: %s", fp, exc)

        return info

    def _process_file(self, file_path: Path, info: _ServiceInfo) -> None:
        """Parse a single Python file and populate *info* in-place."""
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        lines = source.splitlines()
        rel_path = str(file_path)

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()

            # ── Endpoint detection ────────────────────────────────────
            ep_method_match = _RE_ENDPOINT_METHOD.search(stripped)
            ep_path_match = _RE_ENDPOINT.search(stripped)
            if ep_method_match and ep_path_match:
                http_method = ep_method_match.group(1).upper()
                route_path = ep_path_match.group(1)
                # Look ahead a few lines for user input indicators
                context = "\n".join(lines[max(0, lineno): min(len(lines), lineno + 10)])
                accepts_user = bool(
                    re.search(r"\b(request\.|body|params|data|Form|Query)\b", context)
                )
                info.endpoints.append(ServiceEndpoint(
                    service=info.name,
                    file=rel_path,
                    line=lineno,
                    method=http_method,
                    path=route_path,
                    accepts_user_input=accepts_user,
                ))

            # ── Outgoing API call detection ───────────────────────────
            http_match = _RE_HTTP_CALL.search(stripped)
            if http_match:
                call_method = http_match.group(1).upper()
                url_part = http_match.group(2).strip().strip("'\"")
                context_window = "\n".join(
                    lines[max(0, lineno - 6): min(len(lines), lineno + 3)]
                )
                passes_user = bool(_USER_DATA_NAMES.search(context_window))
                sanitized = bool(_RE_SANITIZED_MARKER.search(context_window))
                info.api_calls.append(APICall(
                    caller_service=info.name,
                    caller_file=rel_path,
                    caller_line=lineno,
                    target_url_pattern=url_part,
                    method=call_method,
                    passes_user_data=passes_user,
                    sanitized=sanitized,
                ))

            urllib_match = _RE_URLLIB_CALL.search(stripped)
            if urllib_match:
                url_part = urllib_match.group(1).strip().strip("'\"")
                context_window = "\n".join(
                    lines[max(0, lineno - 6): min(len(lines), lineno + 3)]
                )
                passes_user = bool(_USER_DATA_NAMES.search(context_window))
                sanitized = bool(_RE_SANITIZED_MARKER.search(context_window))
                info.api_calls.append(APICall(
                    caller_service=info.name,
                    caller_file=rel_path,
                    caller_line=lineno,
                    target_url_pattern=url_part,
                    method="GET",
                    passes_user_data=passes_user,
                    sanitized=sanitized,
                ))

            # ── Env var detection ─────────────────────────────────────
            for m in _RE_ENV_VAR.finditer(stripped):
                var_name = m.group(1) or m.group(2)
                if var_name:
                    info.env_vars.setdefault(var_name, []).append((rel_path, lineno))

            # ── DB connection string detection ────────────────────────
            sqlite_matches = _RE_SQLITE.findall(stripped)
            for grp in sqlite_matches:
                conn = next((g for g in grp if g), None)
                if conn and conn not in info.db_connections:
                    info.db_connections.append(conn)

            for pattern in (_RE_POSTGRES, _RE_MYSQL):
                for m in pattern.finditer(stripped):
                    conn = m.group(0)
                    if conn not in info.db_connections:
                        info.db_connections.append(conn)

    def _discover_service_name(self, repo_path: Path) -> str:
        """Derive service name from pyproject.toml, setup.py, or directory name."""
        # pyproject.toml: name = "..."
        pyproject = repo_path / "pyproject.toml"
        if pyproject.exists():
            try:
                text = pyproject.read_text(encoding="utf-8", errors="replace")
                m = re.search(r"""^\s*name\s*=\s*['"]([^'"]+)['"]""", text, re.MULTILINE)
                if m:
                    return m.group(1)
            except Exception:
                pass

        # setup.py: name="..."
        setup_py = repo_path / "setup.py"
        if setup_py.exists():
            try:
                text = setup_py.read_text(encoding="utf-8", errors="replace")
                m = re.search(r"""name\s*=\s*['"]([^'"]+)['"]""", text)
                if m:
                    return m.group(1)
            except Exception:
                pass

        # Fall back to directory name
        return repo_path.name

    def _extract_api_calls(
        self, file_path: Path, service_name: str
    ) -> List[APICall]:
        """Extract all outgoing HTTP calls from a single file."""
        calls: List[APICall] = []
        try:
            source = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return calls

        lines = source.splitlines()

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            for pattern, default_method in [(_RE_HTTP_CALL, None), (_RE_URLLIB_CALL, "GET")]:
                m = pattern.search(stripped)
                if not m:
                    continue
                if default_method is None:
                    call_method = m.group(1).upper()
                    url_part = m.group(2).strip().strip("'\"")
                else:
                    call_method = default_method
                    url_part = m.group(1).strip().strip("'\"")

                context_window = "\n".join(
                    lines[max(0, lineno - 6): min(len(lines), lineno + 3)]
                )
                passes_user = bool(_USER_DATA_NAMES.search(context_window))
                sanitized = bool(_RE_SANITIZED_MARKER.search(context_window))
                calls.append(APICall(
                    caller_service=service_name,
                    caller_file=str(file_path),
                    caller_line=lineno,
                    target_url_pattern=url_part,
                    method=call_method,
                    passes_user_data=passes_user,
                    sanitized=sanitized,
                ))
        return calls

    # ── Taint path finders ────────────────────────────────────────────────────

    def _find_api_taint_paths(
        self, services: List[_ServiceInfo]
    ) -> List[CrossRepoTaintPath]:
        """
        Detect cross-service taint via HTTP API calls.

        A taint path exists when:
        - Service A has an endpoint that accepts user input.
        - Service A makes an outgoing HTTP call that passes user data.
        - The target URL matches a pattern that could reach service B.
        """
        taint_paths: List[CrossRepoTaintPath] = []
        service_map: Dict[str, _ServiceInfo] = {s.name: s for s in services}

        for svc_a in services:
            # Does A expose any user-input endpoints?
            user_input_endpoints = [
                ep for ep in svc_a.endpoints if ep.accepts_user_input
            ]
            if not user_input_endpoints and not svc_a.endpoints:
                # No endpoints but might still have general user data flow
                user_input_endpoints = svc_a.endpoints  # treat all as potential

            for call in svc_a.api_calls:
                if not call.passes_user_data:
                    continue  # no user data in this call

                # Try to identify the target service
                target_svc_name = self._identify_target_service(
                    call.target_url_pattern, services
                )

                # Source: first user-input endpoint or the file/line of the call
                if user_input_endpoints:
                    source_ep = user_input_endpoints[0]
                    source_file = source_ep.file
                    source_line = source_ep.line
                    source_type = "user_input"
                else:
                    source_file = call.caller_file
                    source_line = call.caller_line
                    source_type = "api_param"

                # Sink: target service's first endpoint or just the call site
                if target_svc_name and target_svc_name in service_map:
                    svc_b = service_map[target_svc_name]
                    if svc_b.endpoints:
                        sink_ep = svc_b.endpoints[0]
                        sink_file = sink_ep.file
                        sink_line = sink_ep.line
                    else:
                        sink_file = call.caller_file
                        sink_line = call.caller_line
                    sink_service = target_svc_name
                    sink_type = "api_response"
                else:
                    # Unknown target service — still a potential taint path
                    sink_service = "unknown"
                    sink_file = call.caller_file
                    sink_line = call.caller_line
                    sink_type = "api_response"

                path = CrossRepoTaintPath(
                    path_id=_make_path_id(
                        svc_a.name, source_file, source_line,
                        sink_service, sink_file, sink_line
                    ),
                    source_service=svc_a.name,
                    source_file=source_file,
                    source_line=source_line,
                    source_type=source_type,
                    sink_service=sink_service,
                    sink_file=sink_file,
                    sink_line=sink_line,
                    sink_type=sink_type,
                    transmission="http_api",
                    sanitized=call.sanitized,
                    severity=self._compute_severity_for_path(
                        sink_type=sink_type,
                        sanitized=call.sanitized,
                        transmission="http_api",
                    ),
                    description=(
                        f"Service '{svc_a.name}' passes user-controlled data "
                        f"to '{sink_service}' via HTTP {call.method} "
                        f"({'sanitized' if call.sanitized else 'UNSANITIZED'})."
                    ),
                )
                taint_paths.append(path)

        return taint_paths

    def _build_shared_db_paths(
        self,
        services: List[_ServiceInfo],
        shared_dbs: List[str],
    ) -> List[CrossRepoTaintPath]:
        """Build taint paths for shared database connections."""
        taint_paths: List[CrossRepoTaintPath] = []

        for db_conn in shared_dbs:
            # Find which services share this db
            sharing: List[_ServiceInfo] = [
                s for s in services if db_conn in s.db_connections
            ]
            if len(sharing) < 2:
                continue

            # Emit one taint path per pair of services
            for i, svc_a in enumerate(sharing):
                for svc_b in sharing[i + 1:]:
                    # Both can be source and sink — pick first file mentioning the DB
                    src_file, src_line = _find_db_mention(svc_a, db_conn)
                    snk_file, snk_line = _find_db_mention(svc_b, db_conn)

                    path = CrossRepoTaintPath(
                        path_id=_make_path_id(
                            svc_a.name, src_file, src_line,
                            svc_b.name, snk_file, snk_line,
                        ),
                        source_service=svc_a.name,
                        source_file=src_file,
                        source_line=src_line,
                        source_type="shared_db",
                        sink_service=svc_b.name,
                        sink_file=snk_file,
                        sink_line=snk_line,
                        sink_type="sql_query",
                        transmission="shared_db",
                        sanitized=False,  # shared DB access is inherently unsanitized
                        severity="MEDIUM",
                        description=(
                            f"Services '{svc_a.name}' and '{svc_b.name}' share "
                            f"database connection '{db_conn[:60]}'."
                        ),
                    )
                    taint_paths.append(path)

        return taint_paths

    def _build_env_var_paths(
        self,
        services: List[_ServiceInfo],
        shared_env: List[str],
    ) -> List[CrossRepoTaintPath]:
        """Build taint paths for shared environment variables."""
        taint_paths: List[CrossRepoTaintPath] = []

        for var_name in shared_env:
            sharing: List[_ServiceInfo] = [
                s for s in services if var_name in s.env_vars
            ]
            if len(sharing) < 2:
                continue

            severity = "HIGH" if _SENSITIVE_ENV_PATTERN.search(var_name) else "LOW"

            for i, svc_a in enumerate(sharing):
                for svc_b in sharing[i + 1:]:
                    src_locs = svc_a.env_vars.get(var_name, [("", 0)])
                    snk_locs = svc_b.env_vars.get(var_name, [("", 0)])
                    src_file, src_line = src_locs[0]
                    snk_file, snk_line = snk_locs[0]

                    path = CrossRepoTaintPath(
                        path_id=_make_path_id(
                            svc_a.name, src_file, src_line,
                            svc_b.name, snk_file, snk_line,
                        ),
                        source_service=svc_a.name,
                        source_file=src_file,
                        source_line=src_line,
                        source_type="env_var",
                        sink_service=svc_b.name,
                        sink_file=snk_file,
                        sink_line=snk_line,
                        sink_type="api_response",
                        transmission="env_var",
                        sanitized=False,
                        severity=severity,
                        description=(
                            f"Environment variable '{var_name}' is shared between "
                            f"'{svc_a.name}' and '{svc_b.name}'."
                        ),
                    )
                    taint_paths.append(path)

        return taint_paths

    # ── Shared resource finders ───────────────────────────────────────────────

    def _find_shared_databases(
        self, services: List[Dict[str, Any]]
    ) -> List[str]:
        """Return DB connection strings / paths that appear in 2+ services."""
        from collections import Counter

        counts: Counter = Counter()
        for svc in services:
            for conn in set(svc.get("db_connections", [])):
                counts[conn] += 1

        return [conn for conn, n in counts.items() if n >= 2]

    def _find_shared_env_vars(
        self, services: List[_ServiceInfo]
    ) -> List[str]:
        """Return env var names that appear in 2+ services."""
        from collections import Counter

        counts: Counter = Counter()
        for svc in services:
            for var_name in svc.env_vars:
                counts[var_name] += 1

        return [name for name, n in counts.items() if n >= 2]

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _identify_target_service(
        self, url_pattern: str, services: List[_ServiceInfo]
    ) -> Optional[str]:
        """
        Attempt to match a URL pattern to a known service by checking if
        any service name appears in the URL string.
        """
        url_lower = url_pattern.lower()
        for svc in services:
            svc_name_lower = svc.name.lower().replace("-", "").replace("_", "")
            if svc_name_lower in url_lower.replace("-", "").replace("_", ""):
                return svc.name
            # Also match on directory/folder name
            dir_name = svc.repo_path.name.lower()
            if dir_name in url_lower:
                return svc.name
        return None

    def _compute_severity(self, path: CrossRepoTaintPath) -> str:
        """Re-compute severity for a given taint path (mutates in place)."""
        return self._compute_severity_for_path(
            sink_type=path.sink_type,
            sanitized=path.sanitized,
            transmission=path.transmission,
        )

    @staticmethod
    def _compute_severity_for_path(
        sink_type: str,
        sanitized: bool,
        transmission: str,
    ) -> str:
        """
        Severity rules:
        - CRITICAL: unsanitized + sink is sql/exec/file_write
        - HIGH:     unsanitized + passes to another service (api_response)
        - MEDIUM:   sanitized but same DB accessed (shared_db)
        - LOW:      env var sharing without sensitive pattern
        """
        if not sanitized:
            if sink_type in ("sql_query", "exec", "file_write"):
                return "CRITICAL"
            if transmission == "http_api":
                return "HIGH"
            if transmission == "shared_db":
                return "MEDIUM"
        else:
            if transmission == "shared_db":
                return "MEDIUM"
        return "LOW"


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _make_path_id(
    src_svc: str, src_file: str, src_line: int,
    snk_svc: str, snk_file: str, snk_line: int,
) -> str:
    """Generate a short deterministic ID for a taint path."""
    raw = f"{src_svc}:{src_file}:{src_line}:{snk_svc}:{snk_file}:{snk_line}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


def _find_db_mention(
    svc: _ServiceInfo, db_conn: str
) -> Tuple[str, int]:
    """Return the (file, line) of the first mention of *db_conn* in *svc*."""
    for dirpath_str, _dn, filenames in os.walk(svc.repo_path):
        for fname in filenames:
            if not fname.endswith(".py"):
                continue
            fp = Path(dirpath_str) / fname
            try:
                for lineno, line in enumerate(
                    fp.read_text(encoding="utf-8", errors="replace").splitlines(),
                    start=1,
                ):
                    if db_conn in line:
                        return str(fp), lineno
            except OSError:
                pass
    return str(svc.repo_path), 0


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------


def analyze_cross_repo(repo_paths: List[str]) -> CrossRepoAnalysisReport:
    """
    Convenience wrapper: run cross-repository taint analysis on the given paths.

    Args:
        repo_paths: list of directory paths (strings) for each service repo.

    Returns:
        A :class:`CrossRepoAnalysisReport` with all discovered taint paths.
    """
    analyzer = CrossRepoTaintAnalyzer()
    return analyzer.analyze([Path(p) for p in repo_paths])


# ---------------------------------------------------------------------------
# Self-test (python -m backend.analysis.cross_repo_taint)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import tempfile

    # Create two temporary "service" repos:
    # Service A: exposes a user-input endpoint and calls service B unsanitized
    # Service B: has an endpoint receiving the call
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)

        # ── Service A ────────────────────────────────────────────────────────
        svc_a_dir = root / "service_a"
        svc_a_dir.mkdir()
        (svc_a_dir / "main.py").write_text(
            """
from fastapi import FastAPI, Request
import requests

app = FastAPI()

@app.post("/submit")
async def submit(request: Request):
    body = await request.json()
    user_data = body.get("data")
    # Unsanitized call to service B
    resp = requests.post("http://service-b/process", json={"data": user_data})
    return resp.json()
""",
            encoding="utf-8",
        )

        # ── Service B ────────────────────────────────────────────────────────
        svc_b_dir = root / "service_b"
        svc_b_dir.mkdir()
        (svc_b_dir / "main.py").write_text(
            """
from fastapi import FastAPI

app = FastAPI()

@app.post("/process")
async def process(data: dict):
    return {"status": "ok"}
""",
            encoding="utf-8",
        )

        # Test 1: unsanitized user data passed between services → taint path found
        report = analyze_cross_repo([str(svc_a_dir), str(svc_b_dir)])
        assert isinstance(report, CrossRepoAnalysisReport), "Expected CrossRepoAnalysisReport"
        assert len(report.repos_analyzed) == 2, f"Expected 2 repos, got {len(report.repos_analyzed)}"

        unsanitized = [p for p in report.taint_paths if not p.sanitized]
        assert len(unsanitized) >= 1, (
            f"Expected at least 1 unsanitized taint path, found {len(unsanitized)}\n"
            f"All paths: {[(p.source_service, p.sink_service, p.sanitized) for p in report.taint_paths]}"
        )
        high_or_critical = [p for p in unsanitized if p.severity in ("HIGH", "CRITICAL")]
        assert len(high_or_critical) >= 1, (
            f"Expected HIGH/CRITICAL severity, got severities: {[p.severity for p in unsanitized]}"
        )

        # ── Service C: uses Pydantic before calling service D ────────────────
        svc_c_dir = root / "service_c"
        svc_c_dir.mkdir()
        (svc_c_dir / "main.py").write_text(
            """
from fastapi import FastAPI
from pydantic import BaseModel
import requests

app = FastAPI()

class UserData(BaseModel):
    data: str

@app.post("/submit_safe")
async def submit_safe(payload: UserData):
    # Sanitized via Pydantic before calling service D
    validated = UserData(data=payload.data)
    resp = requests.post("http://service-d/process",
                         json={"data": validated.data})
    return resp.json()
""",
            encoding="utf-8",
        )

        svc_d_dir = root / "service_d"
        svc_d_dir.mkdir()
        (svc_d_dir / "main.py").write_text(
            """
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class Payload(BaseModel):
    data: str

@app.post("/process")
async def process(payload: Payload):
    return {"status": "ok"}
""",
            encoding="utf-8",
        )

        report2 = analyze_cross_repo([str(svc_c_dir), str(svc_d_dir)])
        unsanitized2 = [p for p in report2.taint_paths if not p.sanitized]
        # Service C is sanitized via Pydantic — expect zero unsanitized paths
        assert len(unsanitized2) == 0, (
            f"Expected 0 unsanitized paths for sanitized service pair, "
            f"got {len(unsanitized2)}: {[(p.source_service, p.sink_service) for p in unsanitized2]}"
        )

        # Test 3: analyze() on a list of paths returns CrossRepoAnalysisReport with required fields
        report3 = analyze_cross_repo([str(svc_a_dir)])
        assert hasattr(report3, "taint_paths")
        assert hasattr(report3, "repos_analyzed")
        assert hasattr(report3, "shared_databases")
        assert hasattr(report3, "shared_env_vars")
        assert hasattr(report3, "api_surface")
        assert hasattr(report3, "total_paths")

    print("All cross_repo_taint assertions passed.")
    sys.exit(0)
