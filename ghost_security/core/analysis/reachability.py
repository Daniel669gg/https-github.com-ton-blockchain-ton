"""
Ghost Security Platform — Reachability Analyzer

Two-pronged reachability analysis:

A) DEPENDENCY REACHABILITY — for OSV / dependency findings:
   Checks whether vulnerable functions from a dependency package are actually
   imported and called in non-test project code.

B) CODE REACHABILITY — for SAST findings:
   Checks whether the file/function containing the finding is reachable from
   an application entry point (Flask route, Django view, FastAPI endpoint, etc.)

Typical noise reduction: 40-70% of dependency CVEs are not reachable.
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Known-dangerous functions per package
# Empty list means "any usage of this package is a concern"
# ---------------------------------------------------------------------------
KNOWN_DANGEROUS_FUNCTIONS: Dict[str, List[str]] = {
    "requests": ["get", "post", "put", "delete", "request", "Session"],
    "pyyaml": ["load"],                          # yaml.load without Loader
    "pickle": ["loads", "load"],
    "subprocess": ["call", "run", "Popen", "check_output"],
    "paramiko": ["exec_command", "connect"],
    "cryptography": [],                          # safe library, just check usage
    "jinja2": ["Template", "from_string"],
    "flask": ["render_template_string"],
    "django": ["RawSQL", "extra", "raw"],
    "sqlalchemy": ["text", "execute"],
    "pymysql": ["execute", "executemany"],
    "psycopg2": ["execute", "executemany"],
    "lxml": ["fromstring", "parse"],
    "defusedxml": [],                            # safe
    "numpy": [],
    "pillow": ["open"],                          # PIL.Image.open with untrusted input
}

# pip package name → importable module name(s)
_PIP_TO_IMPORT: Dict[str, List[str]] = {
    "pyyaml": ["yaml"],
    "pillow": ["PIL", "pil", "image"],
    "beautifulsoup4": ["bs4"],
    "scikit-learn": ["sklearn"],
    "scikit_learn": ["sklearn"],
    "opencv-python": ["cv2"],
    "python-dateutil": ["dateutil"],
    "pymysql": ["pymysql"],
    "psycopg2": ["psycopg2"],
    "psycopg2-binary": ["psycopg2"],
    "sqlalchemy": ["sqlalchemy"],
    "flask": ["flask"],
    "django": ["django"],
    "jinja2": ["jinja2"],
    "paramiko": ["paramiko"],
    "cryptography": ["cryptography"],
    "lxml": ["lxml"],
    "defusedxml": ["defusedxml"],
    "numpy": ["numpy", "np"],
    "requests": ["requests"],
    "subprocess": ["subprocess"],
    "pickle": ["pickle"],
}

# Severity ordering for upgrades/downgrades
_SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _adjust_severity(severity: str, delta: int) -> str:
    """Shift a severity level up (delta>0) or down (delta<0), clamped to valid range."""
    sev = severity.upper()
    try:
        idx = _SEV_ORDER.index(sev)
    except ValueError:
        idx = 2  # default MEDIUM
    new_idx = max(0, min(len(_SEV_ORDER) - 1, idx + delta))
    return _SEV_ORDER[new_idx]


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class ReachabilityResult:
    """
    Outcome of reachability analysis for a single finding.

    status:
        REACHABLE            — vulnerable code is actively used / entry-point exposed
        NOT_REACHABLE        — code path cannot be reached (not imported, test file, etc.)
        POTENTIALLY_REACHABLE — indirect call chain; needs manual review
        UNKNOWN              — insufficient information to determine reachability

    confidence: 0-100 integer expressing certainty of the determination.
    reason: human-readable explanation.
    entry_points: list of "file:function" strings that are application entry points.
    call_chain: simplified chain from entry point to the vulnerable site.
    """
    status: str                              # REACHABLE | NOT_REACHABLE | POTENTIALLY_REACHABLE | UNKNOWN
    confidence: int                          # 0-100
    reason: str
    entry_points: List[str] = field(default_factory=list)   # e.g. ["routes.py:search_view"]
    call_chain: List[str] = field(default_factory=list)     # simplified path


# ---------------------------------------------------------------------------
# Internal index types
# ---------------------------------------------------------------------------
@dataclass
class _FileInfo:
    path: str                           # absolute path
    imports: Set[str]                   # normalized package/module names imported
    function_defs: List[str]            # function names defined in this file
    calls: Set[str]                     # function/method calls made
    route_functions: List[str]          # function names decorated as routes/views
    has_main: bool                      # has if __name__ == "__main__": or def main()
    is_test: bool                       # is a test file


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------
class ReachabilityAnalyzer:
    """
    Analyzes whether vulnerable code in a finding is actually reachable
    from the application's entry points.

    Usage::

        analyzer = ReachabilityAnalyzer("/path/to/project")
        result   = analyzer.analyze_finding(finding_dict)
        findings = analyzer.analyze_all(list_of_findings)
        stats    = analyzer.summary(findings)
    """

    def __init__(self, project_root: str, max_files: int = 150) -> None:
        self.project_root = str(Path(project_root).resolve())
        self.max_files = max_files
        self._index: Optional[Dict[str, _FileInfo]] = None  # path -> _FileInfo
        self._entry_points: Optional[List[Tuple[str, str, int]]] = None  # (file, func, line)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_finding(self, finding: Dict) -> ReachabilityResult:
        """
        Analyze a single finding dict and return a ReachabilityResult.

        Dispatches to dependency reachability (type=="DEPENDENCY" or has "package")
        or code reachability (SAST — has "file" key).
        """
        self._ensure_index()

        finding_type = (finding.get("type") or "").upper()
        has_package = bool(finding.get("package") or finding.get("name"))
        has_file = bool(finding.get("file"))

        if finding_type == "DEPENDENCY" or (has_package and not has_file):
            return self._analyze_dependency(finding)
        elif has_file:
            return self._analyze_sast(finding)
        else:
            return ReachabilityResult(
                status="UNKNOWN",
                confidence=0,
                reason="Finding has neither a package nor a file reference; cannot determine reachability",
            )

    def analyze_all(self, findings: List[Dict]) -> List[Dict]:
        """
        Enrich each finding with reachability fields:
            reachability_status, reachability_reason, reachability_confidence,
            effective_severity

        MEDIUM → HIGH if REACHABLE.
        HIGH/CRITICAL → one step down if NOT_REACHABLE.

        Returns a new list of dicts (originals are not mutated).
        """
        self._ensure_index()
        enriched: List[Dict] = []

        for finding in findings:
            f = dict(finding)
            result = self.analyze_finding(f)

            f["reachability_status"] = result.status
            f["reachability_reason"] = result.reason
            f["reachability_confidence"] = result.confidence

            orig_sev = (f.get("severity") or "MEDIUM").upper()
            if result.status == "REACHABLE" and orig_sev == "MEDIUM":
                f["effective_severity"] = "HIGH"
            elif result.status == "NOT_REACHABLE" and orig_sev in ("HIGH", "CRITICAL"):
                f["effective_severity"] = _adjust_severity(orig_sev, -1)
            else:
                f["effective_severity"] = orig_sev

            enriched.append(f)

        return enriched

    def summary(self, findings: List[Dict]) -> Dict:
        """
        Return aggregated reachability statistics over an already-enriched
        list of findings (output of analyze_all).

        Keys: reachable, not_reachable, potentially_reachable, unknown,
              total, noise_reduction (percentage string).
        """
        counts: Dict[str, int] = {
            "reachable": 0,
            "not_reachable": 0,
            "potentially_reachable": 0,
            "unknown": 0,
        }
        for f in findings:
            status = (f.get("reachability_status") or "UNKNOWN").lower()
            key = status if status in counts else "unknown"
            counts[key] += 1

        total = len(findings)
        suppressed = counts["not_reachable"]
        noise_pct = f"{suppressed / total * 100:.0f}%" if total else "0%"

        return {
            **counts,
            "total": total,
            "noise_reduction": noise_pct,
        }

    # ------------------------------------------------------------------
    # Index building
    # ------------------------------------------------------------------

    def _ensure_index(self) -> None:
        if self._index is None:
            self._build_index()

    def _build_index(self) -> None:
        """
        Walk all .py files in the project (up to max_files), extract:
          - imports
          - function definitions
          - call expressions
          - route/view decorators (Flask/Django/FastAPI)
          - main() / __main__ markers
        """
        root = Path(self.project_root)
        skip_dirs = {
            ".git", "__pycache__", "node_modules", ".venv", "venv",
            "env", ".env", "dist", "build", ".eggs", ".tox",
        }

        index: Dict[str, _FileInfo] = {}
        count = 0

        for fpath in sorted(root.rglob("*.py")):
            if count >= self.max_files:
                break
            # Skip hidden/vendor directories
            if any(part in skip_dirs or part.startswith(".") for part in fpath.parts):
                continue

            try:
                source = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            rel = str(fpath.relative_to(root))
            info = self._parse_file(str(fpath), rel, source)
            index[rel] = info
            count += 1

        self._index = index
        self._entry_points = self._find_entry_points()

    def _parse_file(self, abs_path: str, rel_path: str, source: str) -> _FileInfo:
        imports: Set[str] = set()
        func_defs: List[str] = []
        calls: Set[str] = set()
        route_functions: List[str] = []
        has_main = False

        # Quick text-level checks (fast, before AST)
        is_test = self._is_test_file(rel_path)

        # Detect main guard via text (ast may fail on broken files)
        if '__name__' in source and '__main__' in source:
            has_main = True

        try:
            tree = ast.parse(source, filename=abs_path)
        except SyntaxError:
            # Fall back to regex-based extraction
            for m in re.finditer(r"^import\s+([\w.]+)", source, re.MULTILINE):
                imports.add(m.group(1).split(".")[0].lower())
            for m in re.finditer(r"^from\s+([\w.]+)\s+import", source, re.MULTILINE):
                imports.add(m.group(1).split(".")[0].lower())
            return _FileInfo(
                path=abs_path,
                imports=imports,
                function_defs=func_defs,
                calls=calls,
                route_functions=route_functions,
                has_main=has_main,
                is_test=is_test,
            )

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0].lower())
                    imports.add(alias.name.lower())

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split(".")[0].lower())
                    imports.add(node.module.lower())
                for alias in node.names:
                    imports.add(alias.name.lower())

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_defs.append(node.name)
                # Check decorators for route patterns
                for dec in node.decorator_list:
                    dec_src = ast.unparse(dec) if hasattr(ast, "unparse") else ""
                    if self._is_route_decorator(dec, dec_src):
                        route_functions.append(node.name)
                        break
                # Detect main()
                if node.name == "main":
                    has_main = True

            elif isinstance(node, ast.Call):
                # Collect all call names/attrs
                if isinstance(node.func, ast.Attribute):
                    obj = ""
                    if isinstance(node.func.value, ast.Name):
                        obj = node.func.value.id
                    calls.add(f"{obj}.{node.func.attr}".strip(".").lower())
                    calls.add(node.func.attr.lower())
                elif isinstance(node.func, ast.Name):
                    calls.add(node.func.id.lower())

        return _FileInfo(
            path=abs_path,
            imports=imports,
            function_defs=func_defs,
            calls=calls,
            route_functions=route_functions,
            has_main=has_main,
            is_test=is_test,
        )

    @staticmethod
    def _is_route_decorator(node: ast.expr, unparsed: str) -> bool:
        """Return True if an AST decorator node looks like a route/view decorator."""
        # Flask: @app.route, @blueprint.route
        # FastAPI: @router.get, @router.post, @app.get, etc.
        # Django: handled via urlpatterns, not decorators — but @login_required etc.
        route_patterns = [
            r"\.route\s*\(",          # Flask/Blueprint
            r"\.(get|post|put|delete|patch|options|head)\s*\(",  # FastAPI
            r"^app\.(get|post|put|delete|patch)\s*\(",           # Express-style
            r"@api_view",
            r"csrf_exempt",
        ]
        # Check via unparsed string
        for pat in route_patterns:
            if re.search(pat, unparsed, re.IGNORECASE):
                return True

        # Also check the raw AST node type
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                attr = node.func.attr.lower()
                if attr in ("route", "get", "post", "put", "delete", "patch", "options"):
                    return True
        return False

    def _find_entry_points(self) -> List[Tuple[str, str, int]]:
        """
        Collect application entry points as (relative_file, func_name, line_placeholder).

        Entry point types:
          - Flask/FastAPI/Blueprint route-decorated functions
          - Django urlpatterns view functions (detected by name convention)
          - def main() in any file
          - Files named wsgi.py, asgi.py, manage.py
        """
        eps: List[Tuple[str, str, int]] = []
        if self._index is None:
            return eps

        for rel_path, info in self._index.items():
            if info.is_test:
                continue

            # Route-decorated functions
            for func in info.route_functions:
                eps.append((rel_path, func, 0))

            # main() entry points
            if info.has_main:
                eps.append((rel_path, "__main__", 0))

            # Django view convention: views.py or views/ package
            fname = Path(rel_path).name
            if fname in ("views.py", "urls.py", "wsgi.py", "asgi.py", "manage.py"):
                for func in info.function_defs:
                    if not func.startswith("_"):
                        eps.append((rel_path, func, 0))

        return eps

    # ------------------------------------------------------------------
    # Dependency reachability (OSV / package findings)
    # ------------------------------------------------------------------

    def _analyze_dependency(self, finding: Dict) -> ReachabilityResult:
        """
        For a dependency finding, determine if the dangerous functions for
        that package are actually called in non-test project code.
        """
        pkg_raw = (finding.get("package") or finding.get("name") or "").strip()
        pkg_key = pkg_raw.lower().replace("-", "_")
        pkg_lower = pkg_raw.lower()

        # Resolve to importable names
        import_aliases: Set[str] = {pkg_lower, pkg_key}
        for k in (pkg_key, pkg_lower):
            for alias in _PIP_TO_IMPORT.get(k, []):
                import_aliases.add(alias.lower())

        # Gather non-test file infos
        if self._index is None:
            return ReachabilityResult(
                status="UNKNOWN", confidence=20,
                reason="Project index not built",
            )

        non_test_infos = [
            info for info in self._index.values() if not info.is_test
        ]

        # Check if package is imported at all
        importing_files: List[str] = []
        for info in non_test_infos:
            if any(alias in info.imports for alias in import_aliases):
                importing_files.append(Path(info.path).name)

        if not importing_files:
            return ReachabilityResult(
                status="NOT_REACHABLE",
                confidence=90,
                reason=f"Package '{pkg_raw}' is not imported in any non-test source file",
            )

        # Get known-dangerous functions for this package
        dangerous_fns = KNOWN_DANGEROUS_FUNCTIONS.get(
            pkg_lower,
            KNOWN_DANGEROUS_FUNCTIONS.get(pkg_key, None),
        )

        # Package known but no dangerous functions → just being used is enough
        if dangerous_fns is not None and len(dangerous_fns) == 0:
            return ReachabilityResult(
                status="REACHABLE",
                confidence=75,
                reason=f"Package '{pkg_raw}' is imported in: {', '.join(importing_files[:3])}; any usage may be affected",
                entry_points=[f"{f}:import" for f in importing_files[:5]],
            )

        # Unknown package — imported but no function map → UNKNOWN
        if dangerous_fns is None:
            return ReachabilityResult(
                status="UNKNOWN",
                confidence=40,
                reason=f"Package '{pkg_raw}' is imported in {len(importing_files)} file(s) but dangerous function signatures are not catalogued",
                entry_points=[f"{f}:import" for f in importing_files[:5]],
            )

        # Check if any dangerous function is called in non-test code
        called_fns: List[str] = []
        call_files: List[str] = []
        for info in non_test_infos:
            # Only check files that import this package
            if not any(alias in info.imports for alias in import_aliases):
                continue
            for fn in dangerous_fns:
                fn_lower = fn.lower()
                if fn_lower in info.calls or f"{pkg_key}.{fn_lower}" in info.calls:
                    called_fns.append(fn)
                    call_files.append(Path(info.path).name)

        if called_fns:
            unique_fns = list(dict.fromkeys(called_fns))[:5]
            unique_files = list(dict.fromkeys(call_files))[:5]
            return ReachabilityResult(
                status="REACHABLE",
                confidence=85,
                reason=(
                    f"Dangerous function(s) {unique_fns} from '{pkg_raw}' "
                    f"called in non-test code: {', '.join(unique_files)}"
                ),
                entry_points=[f"{f}:{fn}" for f, fn in zip(unique_files, unique_fns)],
                call_chain=[f"import {pkg_raw}", f"call {unique_fns[0]}"],
            )

        return ReachabilityResult(
            status="NOT_REACHABLE",
            confidence=70,
            reason=(
                f"Package '{pkg_raw}' is imported ({', '.join(importing_files[:3])}) "
                f"but dangerous function(s) {dangerous_fns[:3]} are never called in non-test code"
            ),
        )

    # ------------------------------------------------------------------
    # SAST / code reachability
    # ------------------------------------------------------------------

    def _analyze_sast(self, finding: Dict) -> ReachabilityResult:
        """
        For a SAST finding with a file path, determine whether that file/function
        is reachable from an entry point.
        """
        finding_file_raw = finding.get("file") or ""
        finding_func = finding.get("function") or finding.get("func") or ""

        # Normalize to relative path within project root
        finding_file = self._normalize_path(finding_file_raw)

        if self._index is None:
            return ReachabilityResult(
                status="UNKNOWN", confidence=10,
                reason="Project index not built",
            )

        # Test file → immediately NOT_REACHABLE
        if self._is_test_file(finding_file):
            return ReachabilityResult(
                status="NOT_REACHABLE",
                confidence=95,
                reason=f"Finding is in a test file: {finding_file}",
            )

        info = self._index.get(finding_file)

        # If the file isn't in the index, it's outside project or too many files were skipped
        if info is None:
            # Check by basename match
            basename = Path(finding_file).name
            matches = [
                (rel, inf) for rel, inf in self._index.items()
                if Path(rel).name == basename
            ]
            if not matches:
                return ReachabilityResult(
                    status="UNKNOWN",
                    confidence=20,
                    reason=f"File '{finding_file}' not found in project index",
                )
            finding_file, info = matches[0]

        # Collect entry points
        eps = self._entry_points or []
        ep_strs = [f"{ep[0]}:{ep[1]}" for ep in eps]

        # Is the finding file itself an entry-point file?
        file_eps = [ep for ep in eps if ep[0] == finding_file]

        # Is the finding function a route/view directly?
        if finding_func and finding_func in info.route_functions:
            return ReachabilityResult(
                status="REACHABLE",
                confidence=95,
                reason=f"Finding is inside a route/view function '{finding_func}' in {finding_file}",
                entry_points=[f"{finding_file}:{finding_func}"],
                call_chain=[f"{finding_file}:{finding_func}"],
            )

        # Is the file a known entry-point file (views, routes)?
        fname = Path(finding_file).name
        if fname in ("views.py", "routes.py", "urls.py", "handlers.py", "endpoints.py"):
            return ReachabilityResult(
                status="REACHABLE",
                confidence=80,
                reason=f"Finding is in an entry-point module: {fname}",
                entry_points=ep_strs[:5],
                call_chain=[finding_file, finding_func or "(file-level)"],
            )

        # If the file has route functions but the finding function is a helper →
        # POTENTIALLY_REACHABLE
        if info.route_functions:
            return ReachabilityResult(
                status="POTENTIALLY_REACHABLE",
                confidence=60,
                reason=(
                    f"File '{finding_file}' contains route(s) "
                    f"{info.route_functions[:3]} and the finding may be called from them"
                ),
                entry_points=[f"{finding_file}:{r}" for r in info.route_functions[:3]],
                call_chain=[f"{finding_file}:{info.route_functions[0]}", "→", finding_func or "(unknown)"],
            )

        # Check if anything in the index calls functions from this file
        if finding_func:
            callers = self._find_callers(finding_func, finding_file)
            if callers:
                # Are any callers entry points?
                caller_ep_overlap = [c for c in callers if any(c[0] == ep[0] for ep in eps)]
                if caller_ep_overlap:
                    return ReachabilityResult(
                        status="POTENTIALLY_REACHABLE",
                        confidence=70,
                        reason=f"Function '{finding_func}' is called from entry-point file(s): {[c[0] for c in caller_ep_overlap[:2]]}",
                        entry_points=ep_strs[:5],
                        call_chain=[f"{caller_ep_overlap[0][0]}:{caller_ep_overlap[0][1]}", "→", f"{finding_file}:{finding_func}"],
                    )
                return ReachabilityResult(
                    status="POTENTIALLY_REACHABLE",
                    confidence=45,
                    reason=f"Function '{finding_func}' is called from other files but no direct entry-point chain found",
                    entry_points=ep_strs[:5],
                    call_chain=[f"{callers[0][0]}:{callers[0][1]}", "→", f"{finding_file}:{finding_func}"],
                )

        # File exists in project, is imported somewhere?
        importers = self._find_importers(finding_file)
        if importers:
            return ReachabilityResult(
                status="POTENTIALLY_REACHABLE",
                confidence=40,
                reason=f"Module '{finding_file}' is imported by {importers[:3]} but full call chain not traced",
                entry_points=ep_strs[:5],
            )

        return ReachabilityResult(
            status="UNKNOWN",
            confidence=25,
            reason=f"Could not determine reachability of '{finding_file}'; not imported or called from any traced path",
        )

    # ------------------------------------------------------------------
    # Helper utilities
    # ------------------------------------------------------------------

    def _normalize_path(self, file_path: str) -> str:
        """Convert absolute or project-relative path to a relative key."""
        p = Path(file_path)
        root = Path(self.project_root)
        try:
            return str(p.relative_to(root))
        except ValueError:
            pass
        # If it's already relative, return as-is
        return file_path

    def _find_callers(
        self, func_name: str, defined_in: str
    ) -> List[Tuple[str, str]]:
        """
        Return list of (rel_path, func_name) from files that call `func_name`.
        Simple heuristic: check if any file's call set contains the function name.
        """
        if self._index is None:
            return []
        callers: List[Tuple[str, str]] = []
        fn_lower = func_name.lower()
        for rel, info in self._index.items():
            if rel == defined_in:
                continue
            if fn_lower in info.calls:
                callers.append((rel, func_name))
        return callers

    def _find_importers(self, finding_file: str) -> List[str]:
        """Return list of relative paths that import the module at finding_file."""
        if self._index is None:
            return []
        # Derive module name from path: "app/utils/helper.py" → "app.utils.helper"
        module_dots = finding_file.replace(os.sep, ".").replace("/", ".").removesuffix(".py")
        module_last = Path(finding_file).stem.lower()

        importers: List[str] = []
        for rel, info in self._index.items():
            if rel == finding_file:
                continue
            if module_dots.lower() in info.imports or module_last in info.imports:
                importers.append(rel)
        return importers

    @staticmethod
    def _is_test_file(path: str) -> bool:
        """
        Return True if the path looks like a test file.

        Heuristics:
          - any path component is "test" or "tests" or "testing"
          - filename starts with "test_" or ends with "_test.py"
          - filename is "conftest.py"
        """
        parts = Path(path).parts
        for part in parts:
            if part.lower() in ("test", "tests", "testing", "spec", "specs"):
                return True
        fname = Path(path).name.lower()
        return (
            fname.startswith("test_")
            or fname.endswith("_test.py")
            or fname == "conftest.py"
            or fname.startswith("spec_")
        )


# ---------------------------------------------------------------------------
# Incremental extensions (Phase 6)
# ---------------------------------------------------------------------------

import hashlib as _hashlib


def _file_sha(path: str) -> str:
    try:
        return _hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16]
    except OSError:
        return ""


# Monkey-patch incremental methods onto ReachabilityAnalyzer so the
# existing class is EXTENDED, not replaced.

def _incremental_init_patch(self) -> None:
    """Call after __init__ to enable incremental mode."""
    if not hasattr(self, "_index_sha"):
        self._index_sha: dict = {}    # filepath → SHA at last parse
        self._index_mtime: dict = {}  # filepath → mtime at last parse


def _invalidate_file(self, filepath: str) -> bool:
    """
    Remove one file from the reachability index.
    Returns True if the file was present and was removed.
    """
    fp = str(Path(filepath).resolve())
    _incremental_init_patch(self)
    if self._index is None:
        return False
    rel = os.path.relpath(fp, self.project_root)
    removed = False
    for key in (fp, rel):
        if key in self._index:
            del self._index[key]
            self._index_sha.pop(key, None)
            self._index_mtime.pop(key, None)
            removed = True
    return removed


def _update_file(self, filepath: str) -> bool:
    """
    Re-parse a single file and update the reachability index.
    Returns True if the file's content changed and index was updated.
    """
    fp  = str(Path(filepath).resolve())
    _incremental_init_patch(self)
    new_sha = _file_sha(fp)
    if not new_sha:
        return False
    rel = os.path.relpath(fp, self.project_root)
    old_sha = self._index_sha.get(fp) or self._index_sha.get(rel)
    if old_sha == new_sha:
        return False

    # Parse the file
    try:
        source = Path(fp).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False

    file_info = self._parse_file(fp, rel, source)   # type: ignore[attr-defined]
    if self._index is None:
        self._index = {}
    self._index[rel] = file_info
    self._index_sha[rel] = new_sha
    return True


def _invalidate_files(self, filepaths: list) -> int:
    """Invalidate multiple files. Returns count removed."""
    return sum(1 for fp in filepaths if self.invalidate_file(fp))


def _update_files(self, filepaths: list) -> int:
    """Update multiple files. Returns count that actually changed."""
    return sum(1 for fp in filepaths if self.update_file(fp))


def _parse_file(self, abs_path: str, rel_path: str, source: str) -> "_FileInfo":
    """Parse a single file into a _FileInfo. Extracted so it can be called
    both from _build_index and from update_file."""
    imports: Set[str] = set()
    func_defs: List[str] = []
    calls: Set[str] = set()
    route_funcs: List[str] = []
    has_main = False

    try:
        tree = ast.parse(source, filename=abs_path)
    except SyntaxError:
        return _FileInfo(
            path=abs_path, imports=imports, function_defs=func_defs,
            calls=calls, route_functions=route_funcs,
            has_main=False, is_test=self._is_test_file(abs_path),
        )

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0].lower())
            else:
                if node.module:
                    imports.add(node.module.split(".")[0].lower())

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_defs.append(node.name)
            if node.name in ("main",):
                has_main = True
            for dec in node.decorator_list:
                dec_name = ""
                if isinstance(dec, ast.Name):
                    dec_name = dec.id
                elif isinstance(dec, ast.Attribute):
                    dec_name = dec.attr
                elif isinstance(dec, ast.Call):
                    if isinstance(dec.func, ast.Name):
                        dec_name = dec.func.id
                    elif isinstance(dec.func, ast.Attribute):
                        dec_name = dec.func.attr
                if any(k in dec_name.lower() for k in ("route", "get", "post", "put", "delete", "patch", "view")):
                    route_funcs.append(node.name)

        elif isinstance(node, ast.Call):
            callee = ""
            if isinstance(node.func, ast.Name):
                callee = node.func.id
            elif isinstance(node.func, ast.Attribute):
                callee = node.func.attr
            if callee:
                calls.add(callee)

    # Check for __name__ == "__main__"
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            for comp in ast.walk(node):
                if isinstance(comp, ast.Constant) and comp.value == "__main__":
                    has_main = True

    return _FileInfo(
        path=abs_path, imports=imports, function_defs=func_defs,
        calls=calls, route_functions=route_funcs,
        has_main=has_main, is_test=self._is_test_file(abs_path),
    )


# Attach methods to class
ReachabilityAnalyzer.invalidate_file  = _invalidate_file   # type: ignore[attr-defined]
ReachabilityAnalyzer.update_file      = _update_file        # type: ignore[attr-defined]
ReachabilityAnalyzer.invalidate_files = _invalidate_files   # type: ignore[attr-defined]
ReachabilityAnalyzer.update_files     = _update_files       # type: ignore[attr-defined]
ReachabilityAnalyzer._parse_file      = _parse_file         # type: ignore[attr-defined]
