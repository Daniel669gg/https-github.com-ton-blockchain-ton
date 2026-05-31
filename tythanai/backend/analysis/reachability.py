"""
backend/analysis/reachability.py
Reachability Analysis: entrypoint discovery, attack path construction, sink scoring.

Walks Python source files to discover HTTP routes, CLI commands, and WebSocket
handlers, then estimates whether each Finding is reachable from an internet-facing
entrypoint and assigns a reachability score.
"""
from __future__ import annotations

import ast
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.reachability")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class EntryPoint(BaseModel):
    """A discovered application entry-point (route, CLI command, WebSocket, ...)."""

    file: str
    line: int
    name: str
    type: str           # HTTP_ROUTE / CLI_COMMAND / WEBSOCKET / PUBSUB / SCHEDULED / IMPORT_HOOK
    method: str = ""    # GET / POST / PUT / DELETE / PATCH / OPTIONS / HEAD (HTTP only)
    path: str = ""      # URL pattern (HTTP only)


class AttackPath(BaseModel):
    """
    A single attack path from an internet-facing entrypoint to a vulnerable sink.
    """

    entry: EntryPoint
    steps: List[str] = Field(default_factory=list)  # ["file:line:func", ...]
    sink_file: str
    sink_line: int
    sink_type: str
    reachability_score: float                       # 0.0–1.0, higher = more reachable
    cwe_ids: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Regex patterns for entrypoint detection
# ---------------------------------------------------------------------------

# Flask / Blueprint route decorator: @app.route("/path") or @bp.route(...)
_FLASK_ROUTE_RE = re.compile(
    r"""@\s*\w+\.route\s*\(\s*["']([^"']+)["']""",
    re.MULTILINE,
)

# FastAPI: @router.get("/path"), @app.post(...), @router.delete(...), etc.
_FASTAPI_METHOD_RE = re.compile(
    r"""@\s*\w+\.(get|post|put|delete|patch|options|head|websocket)\s*\(\s*["']([^"']+)["']""",
    re.MULTILINE | re.IGNORECASE,
)

# Django urls.py path(...) and re_path(...)
_DJANGO_PATH_RE = re.compile(
    r"""(?:re_path|path)\s*\(\s*["']([^"']+)["']""",
    re.MULTILINE,
)

# Click / Typer command decorators
_CLICK_CMD_RE = re.compile(r"@\s*(?:click|typer)\s*\.\s*command\s*\(", re.MULTILINE)

# argparse usage
_ARGPARSE_RE = re.compile(r"argparse\s*\.\s*ArgumentParser\s*\(", re.MULTILINE)

# WebSocket decorators: @websocket(...) or `async def websocket_endpoint`
_WEBSOCKET_DECORATOR_RE = re.compile(r"@\s*\w*[Ww]ebsocket\w*\s*\(", re.MULTILINE)
_WEBSOCKET_FUNC_RE = re.compile(r"async\s+def\s+websocket_endpoint\b", re.MULTILINE)


# ---------------------------------------------------------------------------
# HTTP method helpers
# ---------------------------------------------------------------------------

_HTTP_METHODS: Set[str] = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}


def _flask_method_from_decorator(decorator_text: str) -> str:
    """Extract method from Flask route decorator (defaults to GET)."""
    m = re.search(r"methods\s*=\s*\[([^\]]+)\]", decorator_text, re.IGNORECASE)
    if m:
        methods_str = m.group(1).upper()
        for method in _HTTP_METHODS:
            if method in methods_str:
                return method
    return "GET"


# ---------------------------------------------------------------------------
# Line→function name mapping helper
# ---------------------------------------------------------------------------

def _build_line_to_func(tree: ast.AST) -> Dict[int, str]:
    """Return a mapping of line → enclosing function name from an AST."""
    mapping: Dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name: str = node.name
            for lineno in range(node.lineno, getattr(node, "end_lineno", node.lineno) + 1):
                mapping[lineno] = func_name
    return mapping


# ---------------------------------------------------------------------------
# Reachability Analyzer
# ---------------------------------------------------------------------------

class ReachabilityAnalyzer:
    """
    Discovers entrypoints in a Python project and constructs attack paths
    linking internet-facing entrypoints to vulnerable sinks (findings).
    """

    # Base reachability scores by entry-point type
    _BASE_SCORES: Dict[str, float] = {
        "HTTP_ROUTE": 0.8,
        "WEBSOCKET": 0.7,
        "CLI_COMMAND": 0.4,
        "SCHEDULED": 0.2,
        "PUBSUB": 0.2,
        "IMPORT_HOOK": 0.1,
    }

    # ------------------------------------------------------------------
    # Entrypoint discovery
    # ------------------------------------------------------------------

    def discover_entrypoints(self, project_root: str) -> List[EntryPoint]:
        """
        Walk all ``.py`` files under *project_root* and detect:

        - Flask / Blueprint HTTP routes
        - FastAPI HTTP routes and websocket endpoints
        - Django ``path`` / ``re_path`` entries in ``urls.py``
        - Click / Typer commands
        - ``argparse.ArgumentParser`` instantiations
        - ``@websocket(...)`` decorators and ``async def websocket_endpoint``
        """
        root = Path(project_root).resolve()
        if not root.exists():
            logger.warning("discover_entrypoints: root does not exist: %s", root)
            return []

        entrypoints: List[EntryPoint] = []
        skip_dirs = {
            "__pycache__", ".git", ".venv", "venv", "env",
            "node_modules", "site-packages", ".tox", "build", "dist",
        }

        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames
                if d not in skip_dirs and not d.startswith(".")
            ]
            for fname in filenames:
                if not fname.endswith(".py"):
                    continue
                fpath = os.path.join(dirpath, fname)
                eps = self._extract_entrypoints_from_file(fpath, fname)
                entrypoints.extend(eps)

        logger.info(
            "discover_entrypoints: found %d entrypoints in %s",
            len(entrypoints),
            project_root,
        )
        return entrypoints

    def _extract_entrypoints_from_file(
        self,
        fpath: str,
        fname: str,
    ) -> List[EntryPoint]:
        """Parse a single file and extract all entrypoints from it."""
        try:
            source = Path(fpath).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.debug("Cannot read %s: %s", fpath, exc)
            return []

        try:
            tree = ast.parse(source, filename=fpath)
        except SyntaxError:
            # Unparseable file – fall back to regex-only detection
            tree = None

        line_to_func: Dict[int, str] = {}
        if tree is not None:
            line_to_func = _build_line_to_func(tree)

        entrypoints: List[EntryPoint] = []
        lines = source.splitlines()

        # ── Flask routes ────────────────────────────────────────────────────────
        for m in _FLASK_ROUTE_RE.finditer(source):
            lineno = source[: m.start()].count("\n") + 1
            url_path = m.group(1)
            # The full decorator text (up to end of line or closing paren)
            dec_text = lines[lineno - 1] if lineno <= len(lines) else ""
            http_method = _flask_method_from_decorator(dec_text)
            func_name = line_to_func.get(lineno, "")
            # Look ahead up to 3 lines to find the actual function name
            if not func_name:
                for offset in range(1, 4):
                    next_line = lines[lineno - 1 + offset] if lineno - 1 + offset < len(lines) else ""
                    func_m = re.match(r"\s*(?:async\s+)?def\s+(\w+)", next_line)
                    if func_m:
                        func_name = func_m.group(1)
                        break
            entrypoints.append(
                EntryPoint(
                    file=fpath,
                    line=lineno,
                    name=func_name or f"route_{lineno}",
                    type="HTTP_ROUTE",
                    method=http_method,
                    path=url_path,
                )
            )

        # ── FastAPI routes & websockets ─────────────────────────────────────────
        for m in _FASTAPI_METHOD_RE.finditer(source):
            method_name = m.group(1).upper()
            url_path = m.group(2)
            lineno = source[: m.start()].count("\n") + 1
            func_name = line_to_func.get(lineno, "")
            if not func_name:
                for offset in range(1, 4):
                    next_line = lines[lineno - 1 + offset] if lineno - 1 + offset < len(lines) else ""
                    func_m = re.match(r"\s*(?:async\s+)?def\s+(\w+)", next_line)
                    if func_m:
                        func_name = func_m.group(1)
                        break
            ep_type = "WEBSOCKET" if method_name == "WEBSOCKET" else "HTTP_ROUTE"
            entrypoints.append(
                EntryPoint(
                    file=fpath,
                    line=lineno,
                    name=func_name or f"endpoint_{lineno}",
                    type=ep_type,
                    method="" if ep_type == "WEBSOCKET" else method_name,
                    path=url_path,
                )
            )

        # ── Django urls.py ──────────────────────────────────────────────────────
        if fname in ("urls.py",) or fpath.endswith("urls.py"):
            for m in _DJANGO_PATH_RE.finditer(source):
                lineno = source[: m.start()].count("\n") + 1
                url_path = m.group(1)
                entrypoints.append(
                    EntryPoint(
                        file=fpath,
                        line=lineno,
                        name=f"django_url_{lineno}",
                        type="HTTP_ROUTE",
                        method="GET",
                        path=url_path,
                    )
                )

        # ── Click / Typer CLI commands ──────────────────────────────────────────
        for m in _CLICK_CMD_RE.finditer(source):
            lineno = source[: m.start()].count("\n") + 1
            func_name = line_to_func.get(lineno, "")
            if not func_name:
                for offset in range(1, 4):
                    next_line = lines[lineno - 1 + offset] if lineno - 1 + offset < len(lines) else ""
                    func_m = re.match(r"\s*(?:async\s+)?def\s+(\w+)", next_line)
                    if func_m:
                        func_name = func_m.group(1)
                        break
            entrypoints.append(
                EntryPoint(
                    file=fpath,
                    line=lineno,
                    name=func_name or f"cli_cmd_{lineno}",
                    type="CLI_COMMAND",
                )
            )

        # ── argparse ────────────────────────────────────────────────────────────
        for m in _ARGPARSE_RE.finditer(source):
            lineno = source[: m.start()].count("\n") + 1
            entrypoints.append(
                EntryPoint(
                    file=fpath,
                    line=lineno,
                    name=f"argparse_{lineno}",
                    type="CLI_COMMAND",
                )
            )

        # ── WebSocket decorators ────────────────────────────────────────────────
        for m in _WEBSOCKET_DECORATOR_RE.finditer(source):
            lineno = source[: m.start()].count("\n") + 1
            func_name = line_to_func.get(lineno, "")
            if not func_name:
                for offset in range(1, 4):
                    next_line = lines[lineno - 1 + offset] if lineno - 1 + offset < len(lines) else ""
                    func_m = re.match(r"\s*(?:async\s+)?def\s+(\w+)", next_line)
                    if func_m:
                        func_name = func_m.group(1)
                        break
            entrypoints.append(
                EntryPoint(
                    file=fpath,
                    line=lineno,
                    name=func_name or f"ws_{lineno}",
                    type="WEBSOCKET",
                )
            )

        # ── async def websocket_endpoint ────────────────────────────────────────
        for m in _WEBSOCKET_FUNC_RE.finditer(source):
            lineno = source[: m.start()].count("\n") + 1
            func_m2 = re.match(r"\s*async\s+def\s+(\w+)", lines[lineno - 1])
            func_name = func_m2.group(1) if func_m2 else "websocket_endpoint"
            entrypoints.append(
                EntryPoint(
                    file=fpath,
                    line=lineno,
                    name=func_name,
                    type="WEBSOCKET",
                )
            )

        return entrypoints

    # ------------------------------------------------------------------
    # Reachability scoring
    # ------------------------------------------------------------------

    def compute_reachability(
        self,
        entry: EntryPoint,
        call_graph: dict,
        findings: List[Finding],
    ) -> float:
        """
        Compute a reachability score (0.0–1.0) for a given *entry* point.

        Score components:

        - Base score by entry type (HTTP_ROUTE=0.8, WEBSOCKET=0.7, …)
        - +0.1 if the HTTP method is GET (typically no auth body)
        - +0.1 if any finding lives in a file reachable via the call graph
        """
        base = self._BASE_SCORES.get(entry.type, 0.2)

        if entry.type == "HTTP_ROUTE" and entry.method.upper() == "GET":
            base += 0.1

        # Check whether any finding is in a file referenced by the call graph
        if findings:
            reachable_files = self._reachable_files(entry, call_graph)
            finding_files = {f.file for f in findings}
            if reachable_files & finding_files:
                base += 0.1

        return min(1.0, round(base, 4))

    @staticmethod
    def _reachable_files(entry: EntryPoint, call_graph: dict) -> Set[str]:
        """
        Return the set of files reachable from *entry* in *call_graph*.

        *call_graph* is expected to be a dict mapping ``"file::func"`` keys to
        lists of ``"file::func"`` callees (as produced by
        :py:class:`~backend.analysis.callgraph.CallGraphBuilder`).  If the
        call graph is empty or the entry is not present, only the entry's own
        file is returned.
        """
        reachable: Set[str] = {entry.file}
        if not call_graph:
            return reachable

        start_key = f"{entry.file}::{entry.name}"
        queue = [start_key]
        visited: Set[str] = {start_key}

        while queue:
            node = queue.pop()
            file_part = node.split("::")[0] if "::" in node else node
            reachable.add(file_part)
            for callee in call_graph.get(node, []):
                if callee not in visited:
                    visited.add(callee)
                    queue.append(callee)

        return reachable

    # ------------------------------------------------------------------
    # Attack path construction
    # ------------------------------------------------------------------

    def build_attack_paths(
        self,
        project_root: str,
        findings: List[Finding],
        call_graph: Optional[dict] = None,
    ) -> List[AttackPath]:
        """
        Discover entrypoints, correlate them with *findings*, and return
        :py:class:`AttackPath` objects for findings reachable from an HTTP
        or WebSocket entrypoint.

        Results are sorted by ``reachability_score`` descending.
        """
        if call_graph is None:
            call_graph = {}

        entrypoints = self.discover_entrypoints(project_root)
        http_entries = [
            ep for ep in entrypoints
            if ep.type in ("HTTP_ROUTE", "WEBSOCKET")
        ]

        if not http_entries:
            logger.info("build_attack_paths: no HTTP entrypoints found in %s", project_root)
            return []

        # Build a file→entrypoints index for fast lookup
        ep_by_file: Dict[str, List[EntryPoint]] = {}
        for ep in http_entries:
            ep_by_file.setdefault(ep.file, []).append(ep)

        paths: List[AttackPath] = []

        for finding in findings:
            # Find the best entrypoint for this finding
            entry = self._best_entry_for_finding(
                finding, http_entries, ep_by_file, call_graph
            )
            if entry is None:
                continue

            score = self.compute_reachability(entry, call_graph, [finding])
            step = f"{finding.file}:{finding.line}:{finding.rule_id}"

            paths.append(
                AttackPath(
                    entry=entry,
                    steps=[step],
                    sink_file=finding.file,
                    sink_line=finding.line,
                    sink_type=finding.rule_id,
                    reachability_score=score,
                    cwe_ids=[finding.cwe_id] if finding.cwe_id else [],
                )
            )

        paths.sort(key=lambda p: p.reachability_score, reverse=True)
        logger.info(
            "build_attack_paths: %d attack paths constructed from %d findings",
            len(paths),
            len(findings),
        )
        return paths

    def _best_entry_for_finding(
        self,
        finding: Finding,
        http_entries: List[EntryPoint],
        ep_by_file: Dict[str, List[EntryPoint]],
        call_graph: dict,
    ) -> Optional[EntryPoint]:
        """
        Return the most relevant HTTP entrypoint for *finding*, or ``None``
        if no reachable entrypoint is found.

        Priority:
        1. Same file as the finding.
        2. Reachable via the call graph.
        3. Any HTTP entrypoint (proximity fallback).
        """
        # 1. Same file
        if finding.file in ep_by_file:
            return ep_by_file[finding.file][0]

        # 2. Call-graph reachability
        if call_graph:
            for ep in http_entries:
                reachable = self._reachable_files(ep, call_graph)
                if finding.file in reachable:
                    return ep

        # 3. Proximity fallback: pick the entrypoint in the nearest directory
        finding_parts = Path(finding.file).parts
        best_ep: Optional[EntryPoint] = None
        best_common = -1
        for ep in http_entries:
            ep_parts = Path(ep.file).parts
            common = sum(
                1
                for a, b in zip(finding_parts, ep_parts)
                if a == b
            )
            if common > best_common:
                best_common = common
                best_ep = ep

        return best_ep


    # ------------------------------------------------------------------
    # Reachability scoring by file / finding
    # ------------------------------------------------------------------

    def build_reachability_matrix(self, project_root: str) -> Dict[str, float]:
        """
        Maps each Python file path to its maximum reachability score.

        Algorithm:
        1. Discover all entrypoints and assign base scores by type.
        2. For each entrypoint, parse its imports and propagate the score
           to every file it imports (direct and transitive), with a small
           decay factor per hop.
        3. The file that contains the entrypoint itself gets the full base
           score; imported files receive base × decay^hop.

        Returns ``{"/absolute/path/to/file.py": max_score, ...}``
        """
        root = Path(project_root).resolve()
        if not root.exists():
            return {}

        entrypoints = self.discover_entrypoints(project_root)
        if not entrypoints:
            return {}

        # Build a map: module-name-fragment → absolute file path
        file_index = self._build_file_index(root)

        matrix: Dict[str, float] = {}

        for ep in entrypoints:
            base = self._BASE_SCORES.get(ep.type, 0.2)
            # HTTP GET is slightly more reachable
            if ep.type == "HTTP_ROUTE" and ep.method.upper() == "GET":
                base = min(1.0, base + 0.05)

            self._propagate_score(
                start_file=ep.file,
                score=base,
                file_index=file_index,
                matrix=matrix,
                visited=set(),
                decay=0.85,
                hop=0,
                max_hops=3,
            )

        return matrix

    def _build_file_index(self, root: Path) -> Dict[str, str]:
        """Return a mapping of module-name-fragments to absolute file paths."""
        index: Dict[str, str] = {}
        skip_dirs = {
            "__pycache__", ".git", ".venv", "venv", "env",
            "node_modules", "site-packages", ".tox", "build", "dist",
        }
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]
            for fname in filenames:
                if not fname.endswith(".py"):
                    continue
                fpath = os.path.join(dirpath, fname)
                # Index by stem (e.g. "utils") and by relative dotted path
                stem = Path(fname).stem
                rel = Path(fpath).relative_to(root)
                dotted = str(rel).replace(os.sep, ".").removesuffix(".py")
                index[stem] = fpath
                index[dotted] = fpath
                # Also index by last two path components for disambiguation
                parts = Path(dotted).parts
                if len(parts) >= 2:
                    index[".".join(parts[-2:])] = fpath
        return index

    def _parse_imports(self, file_path: str) -> List[str]:
        """Return a list of module name fragments imported by *file_path*."""
        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        imports: List[str] = []
        # `import X` and `import X.Y.Z`
        for m in re.finditer(r"^\s*import\s+([\w\.]+)", source, re.MULTILINE):
            imports.append(m.group(1))
        # `from X import Y` and `from X.Y import Z`
        for m in re.finditer(r"^\s*from\s+([\w\.]+)\s+import", source, re.MULTILINE):
            imports.append(m.group(1))
        return imports

    def _propagate_score(
        self,
        start_file: str,
        score: float,
        file_index: Dict[str, str],
        matrix: Dict[str, float],
        visited: Set[str],
        decay: float,
        hop: int,
        max_hops: int,
    ) -> None:
        """Recursively propagate *score* from *start_file* to its imports."""
        if hop > max_hops or start_file in visited:
            return
        visited.add(start_file)

        current_score = round(score * (decay ** hop), 4)
        if current_score > matrix.get(start_file, 0.0):
            matrix[start_file] = current_score

        if hop >= max_hops:
            return

        for module_fragment in self._parse_imports(start_file):
            # Try resolving the module to a file path
            target = self._resolve_module(module_fragment, file_index)
            if target and target not in visited:
                self._propagate_score(
                    start_file=target,
                    score=score,
                    file_index=file_index,
                    matrix=matrix,
                    visited=visited,
                    decay=decay,
                    hop=hop + 1,
                    max_hops=max_hops,
                )

    @staticmethod
    def _resolve_module(fragment: str, file_index: Dict[str, str]) -> Optional[str]:
        """Attempt to map a module name fragment to a file path."""
        if fragment in file_index:
            return file_index[fragment]
        # Try the last component only (e.g. "os.path" → "path")
        last = fragment.split(".")[-1]
        return file_index.get(last)

    def score_findings_by_reachability(
        self,
        findings: List[Finding],
        project_root: str,
    ) -> List[Tuple[Finding, float]]:
        """
        Compute a reachability score (0.0–1.0) for each finding.

        Scoring logic:
        - Consult the reachability matrix for the finding's file.
        - If the file is not directly in the matrix, check whether it is
          imported by a high-reachability module (inherits parent score).
        - Findings in files with no reachability signal default to 0.05.

        Returns a list of ``(finding, score)`` tuples sorted by score descending.
        """
        matrix = self.build_reachability_matrix(project_root)

        scored: List[Tuple[Finding, float]] = []
        for finding in findings:
            score = matrix.get(finding.file)
            if score is None:
                # Default: very low reachability — not reachable from any known entry
                score = 0.05
            scored.append((finding, round(score, 4)))

        scored.sort(key=lambda t: t[1], reverse=True)
        return scored

    def generate_reachability_report(
        self,
        project_root: str,
        findings: List[Finding],
    ) -> Dict[str, Any]:
        """
        Generate a structured reachability report for *project_root*.

        Returns a dict with keys:
        - ``entrypoints_discovered``: list of EntryPoint dicts
        - ``reachability_matrix``: file → score mapping
        - ``findings_by_reachability``: list of {finding, reachability_score, tier}
        - ``high_priority_count``: count where score >= 0.7
        - ``medium_priority_count``: count where 0.4 <= score < 0.7
        - ``low_priority_count``: count where score < 0.4
        - ``fp_reduction_estimate``: human-readable FP reduction estimate
        """
        entrypoints = self.discover_entrypoints(project_root)
        matrix = self.build_reachability_matrix(project_root)
        scored = self.score_findings_by_reachability(findings, project_root)

        findings_by_reachability: List[Dict[str, Any]] = []
        high = medium = low = 0

        for finding, rs in scored:
            if rs >= 0.7:
                tier = "HIGH"
                high += 1
            elif rs >= 0.4:
                tier = "MEDIUM"
                medium += 1
            else:
                tier = "LOW"
                low += 1

            findings_by_reachability.append(
                {
                    "finding": finding.model_dump(),
                    "reachability_score": rs,
                    "tier": tier,
                }
            )

        total = len(scored)
        low_pct = round((low / total * 100) if total else 0.0, 1)
        fp_estimate = f"{low_pct}% of findings are low-reachability (likely FP)"

        return {
            "entrypoints_discovered": [ep.model_dump() for ep in entrypoints],
            "reachability_matrix": matrix,
            "findings_by_reachability": findings_by_reachability,
            "high_priority_count": high,
            "medium_priority_count": medium,
            "low_priority_count": low,
            "fp_reduction_estimate": fp_estimate,
        }


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

def analyze_reachability(
    project_root: str,
    findings: List[Finding],
) -> List[AttackPath]:
    """
    Convenience wrapper: construct a :py:class:`ReachabilityAnalyzer` and
    return attack paths sorted by reachability score.
    """
    return ReachabilityAnalyzer().build_attack_paths(project_root, findings)


def score_by_reachability(
    project_root: str,
    findings: List[Finding],
) -> List[Tuple[Finding, float]]:
    """Return (finding, reachability_score) tuples sorted by score descending."""
    return ReachabilityAnalyzer().score_findings_by_reachability(findings, project_root)
