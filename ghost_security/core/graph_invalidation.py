"""
Ghost Security Platform — Symbol Impact Analysis & Graph Invalidation Engine
Phase 6, Parts 1 & 2.

PART 1: SymbolExtractor — extract function/class/method symbols from Python
        source using ast, compute per-symbol body hashes.
        SymbolDiff — compare two symbol maps to find what changed.
        ImpactSet  — set of symbols impacted by a change.

PART 2: GraphNodeDependency — tracks which symbols a graph node depends on.
        GraphInvalidationManager — central manager; on file change computes the
        minimal set of graph nodes that must be invalidated.

Standalone module — intentionally imports nothing from backend.* to avoid
circular imports.
"""
from __future__ import annotations

import ast
import hashlib
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Entry-point decorator keywords (case-insensitive substring match)
# ---------------------------------------------------------------------------
_ENTRY_KEYWORDS: Set[str] = {
    "route", "endpoint", "get", "post", "put", "delete", "patch", "view",
}


# ===========================================================================
# PART 1 — Symbol Impact Analysis
# ===========================================================================


@dataclass
class SymbolInfo:
    """Describes a single symbol (function / class / method) in a file."""

    name: str               # plain name (e.g. "my_method")
    kind: str               # "function" | "class" | "method"
    lineno: int
    end_lineno: int
    parent: str = ""        # enclosing class name (for methods)
    signature: str = ""     # hash of the function's argument signature
    body_hash: str = ""     # SHA-256[:16] of the symbol's source lines
    is_entry: bool = False  # True when decorated as a route / endpoint

    @property
    def qualified_name(self) -> str:
        """Return 'ClassName.method_name' or just 'function_name'."""
        if self.parent:
            return f"{self.parent}.{self.name}"
        return self.name


# ---------------------------------------------------------------------------

def _hash_text(text: str) -> str:
    """Return the first 16 hex characters of SHA-256(text)."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _sig_hash(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Hash a function's argument list as a lightweight signature."""
    try:
        args = ast.unparse(node.args)
    except Exception:
        args = str([a.arg for a in node.args.args])
    return _hash_text(args)


def _decorator_is_entry(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if any decorator name matches an entry-point keyword."""
    for dec in node.decorator_list:
        # Collect all identifiers referenced in the decorator expression.
        dec_names: List[str] = []
        if isinstance(dec, ast.Name):
            dec_names.append(dec.id)
        elif isinstance(dec, ast.Attribute):
            dec_names.append(dec.attr)
            if isinstance(dec.value, ast.Name):
                dec_names.append(dec.value.id)
        elif isinstance(dec, ast.Call):
            func = dec.func
            if isinstance(func, ast.Name):
                dec_names.append(func.id)
            elif isinstance(func, ast.Attribute):
                dec_names.append(func.attr)
                if isinstance(func.value, ast.Name):
                    dec_names.append(func.value.id)
        for dname in dec_names:
            if any(kw in dname.lower() for kw in _ENTRY_KEYWORDS):
                return True
    return False


class _SymbolVisitor(ast.NodeVisitor):
    """
    Single-pass AST visitor that collects SymbolInfo for every
    function, async function, and class in a module.

    Tracks a class stack so that methods are attributed to their
    enclosing class.
    """

    def __init__(self, source_lines: List[str]) -> None:
        self._lines = source_lines
        self._class_stack: List[str] = []
        self.symbols: Dict[str, SymbolInfo] = {}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _body_hash(self, node: ast.AST) -> str:
        lineno: int = node.lineno          # type: ignore[attr-defined]
        end_lineno: int = node.end_lineno  # type: ignore[attr-defined]
        body_lines = self._lines[lineno - 1 : end_lineno]
        return _hash_text("".join(body_lines))

    def _register(self, info: SymbolInfo) -> None:
        qname = info.qualified_name
        # Last write wins (handles redefinitions, keeps final one).
        self.symbols[qname] = info

    # ------------------------------------------------------------------
    # Visitors
    # ------------------------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        parent = ".".join(self._class_stack) if self._class_stack else ""
        qname_parts = self._class_stack + [node.name]
        qualified = ".".join(qname_parts)

        info = SymbolInfo(
            name=node.name,
            kind="class",
            lineno=node.lineno,
            end_lineno=node.end_lineno,
            parent=parent,
            body_hash=self._body_hash(node),
        )
        self.symbols[qualified] = info

        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def _visit_func(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        parent = self._class_stack[-1] if self._class_stack else ""
        kind = "method" if self._class_stack else "function"

        # Build qualified name using only the *immediate* class parent
        # (not the full class stack) to match the SymbolInfo.qualified_name
        # property: "ClassName.method" rather than "A.B.method".
        info = SymbolInfo(
            name=node.name,
            kind=kind,
            lineno=node.lineno,
            end_lineno=node.end_lineno,
            parent=parent,
            signature=_sig_hash(node),
            body_hash=self._body_hash(node),
            is_entry=_decorator_is_entry(node),
        )
        self._register(info)

        # Do NOT call generic_visit so that nested functions are visited
        # with the class_stack intact but are treated as separate symbols.
        # We manually walk the body.
        for child in ast.walk(node):
            if child is node:
                continue
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._visit_func(child)
            # Nested classes inside a function are unusual but handle them.
            elif isinstance(child, ast.ClassDef):
                self.visit_ClassDef(child)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node)


class SymbolExtractor:
    """Extracts SymbolInfo from a Python source file using the ast module."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self, filepath: str) -> Dict[str, SymbolInfo]:
        """
        Parse *filepath* and return a dict: qualified_name → SymbolInfo.

        Returns an empty dict on any read / parse error.
        """
        try:
            source = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return {}
        return self.extract_from_source(source, filepath=filepath)

    def extract_from_source(
        self,
        source: str,
        filepath: str = "",
    ) -> Dict[str, SymbolInfo]:
        """
        Parse *source* directly and return qualified_name → SymbolInfo.

        *filepath* is used only for error messages.
        """
        try:
            tree = ast.parse(source, filename=filepath or "<string>")
        except SyntaxError:
            return {}

        lines = source.splitlines(keepends=True)
        # Ensure lines are accessible even for single-line files.
        if not lines:
            return {}

        visitor = _SymbolVisitor(lines)
        visitor.visit(tree)
        return visitor.symbols


# ---------------------------------------------------------------------------


@dataclass
class SymbolDiff:
    """Result of comparing two symbol maps (before → after)."""

    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    modified: List[str] = field(default_factory=list)
    unchanged: List[str] = field(default_factory=list)

    @classmethod
    def compute(
        cls,
        before: Dict[str, SymbolInfo],
        after: Dict[str, SymbolInfo],
    ) -> "SymbolDiff":
        """Compare two symbol maps and classify each symbol."""
        before_keys = set(before.keys())
        after_keys = set(after.keys())

        added = sorted(after_keys - before_keys)
        removed = sorted(before_keys - after_keys)

        modified: List[str] = []
        unchanged: List[str] = []
        for key in sorted(before_keys & after_keys):
            if before[key].body_hash != after[key].body_hash:
                modified.append(key)
            else:
                unchanged.append(key)

        return cls(
            added=added,
            removed=removed,
            modified=modified,
            unchanged=unchanged,
        )

    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.modified)


# ---------------------------------------------------------------------------


@dataclass
class ImpactSet:
    """Set of symbols impacted by a change, with rationale."""

    directly_changed: Set[str] = field(default_factory=set)
    callers: Set[str] = field(default_factory=set)
    entrypoints: Set[str] = field(default_factory=set)

    @property
    def all_symbols(self) -> Set[str]:
        return self.directly_changed | self.callers | self.entrypoints

    def is_empty(self) -> bool:
        return len(self.all_symbols) == 0

    def to_dict(self) -> dict:
        return {
            "directly_changed": sorted(self.directly_changed),
            "callers": sorted(self.callers),
            "entrypoints": sorted(self.entrypoints),
            "all_symbols": sorted(self.all_symbols),
            "total_impacted": len(self.all_symbols),
        }


# ===========================================================================
# PART 2 — Graph Invalidation Engine
# ===========================================================================


@dataclass
class GraphNodeDependency:
    """Tracks which symbols and files a graph node was built from."""

    node_id: str
    graph_type: str                                  # "call_graph" | "knowledge_graph" | …
    dependent_symbols: Set[str] = field(default_factory=set)
    dependent_files: Set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------


class GraphInvalidationManager:
    """
    Central manager for symbol-level graph invalidation.

    Workflow
    --------
    1. As graph nodes are built, call ``register_dependency`` to record
       which source symbols each node depends on.
    2. When files change, call ``compute_impact`` to determine which
       symbols were modified / added / removed.
    3. Call ``invalidate_for_impact`` to get the mapping
       ``{graph_type → set of node_ids}`` that must be rebuilt.
    """

    def __init__(self) -> None:
        # graph_type → { node_id → GraphNodeDependency }
        self._deps: Dict[str, Dict[str, GraphNodeDependency]] = defaultdict(dict)

        # symbol → { graph_type → set[node_id] }
        self._symbol_to_nodes: Dict[str, Dict[str, Set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )

        # filepath → last-known symbol map
        self._file_symbols: Dict[str, Dict[str, SymbolInfo]] = {}

        # simple stats
        self._invalidation_count: int = 0
        self._start_time: float = time.time()

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_dependency(
        self,
        node_id: str,
        graph_type: str,
        symbols: Set[str],
        files: Set[str],
    ) -> None:
        """
        Record that *node_id* in *graph_type* was built from *symbols*
        (qualified names) and *files* (absolute paths).
        """
        dep = self._deps[graph_type].get(node_id)
        if dep is None:
            dep = GraphNodeDependency(
                node_id=node_id,
                graph_type=graph_type,
            )
            self._deps[graph_type][node_id] = dep

        dep.dependent_symbols.update(symbols)
        dep.dependent_files.update(files)

        # Maintain reverse index
        for sym in symbols:
            self._symbol_to_nodes[sym][graph_type].add(node_id)

    # ------------------------------------------------------------------
    # Impact computation
    # ------------------------------------------------------------------

    def compute_impact(self, changed_files: List[str]) -> ImpactSet:
        """
        Given a list of *changed_files*, compute the full ImpactSet.

        For each file:
          - before = cached symbol map (or empty if first seen)
          - after  = freshly extracted symbol map
          - diff   = SymbolDiff.compute(before, after)
          - directly_changed += modified + added + removed

        Also marks entry-point symbols that were directly changed.
        Updates internal symbol cache.
        """
        directly_changed: Set[str] = set()
        entrypoints: Set[str] = set()
        extractor = SymbolExtractor()

        for filepath in changed_files:
            before = self._file_symbols.get(filepath, {})
            after = extractor.extract(filepath)

            diff = SymbolDiff.compute(before, after)

            changed_here = set(diff.modified) | set(diff.added) | set(diff.removed)
            directly_changed.update(changed_here)

            # Detect entry points among the changed symbols in the 'after' map
            for qname in changed_here:
                info = after.get(qname) or before.get(qname)
                if info and info.is_entry:
                    entrypoints.add(qname)

            # Update the cache with the latest state
            self._file_symbols[filepath] = after

        return ImpactSet(
            directly_changed=directly_changed,
            callers=set(),
            entrypoints=entrypoints,
        )

    # ------------------------------------------------------------------
    # Invalidation
    # ------------------------------------------------------------------

    def invalidate_for_impact(
        self,
        impact: ImpactSet,
        graph_types: Optional[List[str]] = None,
    ) -> Dict[str, Set[str]]:
        """
        Given an *ImpactSet*, return ``{graph_type → set[node_id]}`` for
        every node that depends on at least one impacted symbol.

        *graph_types* limits the search to specific graph types when
        provided; otherwise all registered graph types are searched.
        """
        to_invalidate: Dict[str, Set[str]] = defaultdict(set)
        target_types: Set[str] = (
            set(graph_types) if graph_types else set(self._deps.keys())
        )

        for sym in impact.all_symbols:
            if sym not in self._symbol_to_nodes:
                continue
            for gtype, node_ids in self._symbol_to_nodes[sym].items():
                if gtype in target_types:
                    to_invalidate[gtype].update(node_ids)

        # Also scan by file for nodes that declared file-level deps
        impacted_files = self._files_for_symbols(impact.all_symbols)
        for gtype in target_types:
            for node_id, dep in self._deps[gtype].items():
                if dep.dependent_files & impacted_files:
                    to_invalidate[gtype].add(node_id)

        if to_invalidate:
            self._invalidation_count += 1

        return dict(to_invalidate)

    # ------------------------------------------------------------------
    # File symbol update
    # ------------------------------------------------------------------

    def update_file_symbols(self, filepath: str) -> SymbolDiff:
        """
        Re-extract symbols for *filepath*, compute diff vs. cached state,
        update internal cache, and return the SymbolDiff.
        """
        before = self._file_symbols.get(filepath, {})
        after = SymbolExtractor().extract(filepath)
        diff = SymbolDiff.compute(before, after)
        self._file_symbols[filepath] = after
        return diff

    # ------------------------------------------------------------------
    # Call-graph-aware impact extension
    # ------------------------------------------------------------------

    def get_call_graph_impact(
        self,
        impact: ImpactSet,
        call_graph: dict,
    ) -> ImpactSet:
        """
        Extend *impact* with transitive callers found in *call_graph*.

        *call_graph* is the dict returned by ``CallGraphGenerator.build()``,
        which has a ``"nodes"`` key containing a list of node dicts each
        with ``"qualified"``, ``"called_by"``, and ``"calls"`` fields.

        The method walks up to 5 hops of the caller graph, adding every
        caller of a directly-changed symbol to ``impact.callers``.  The
        original ``impact`` object is mutated in place and also returned.
        """
        nodes: List[dict] = call_graph.get("nodes", [])
        if not nodes:
            return impact

        # Build lookup: qualified_name → node dict
        node_map: Dict[str, dict] = {
            n["qualified"]: n for n in nodes if "qualified" in n
        }

        # Also build a short-name index for fuzzy matching
        # (the call_graph uses module-qualified names like "auth.login"
        #  while our symbol map may just say "login").
        short_to_qualified: Dict[str, List[str]] = defaultdict(list)
        for qname in node_map:
            parts = qname.rsplit(".", 1)
            short = parts[-1] if len(parts) > 1 else qname
            short_to_qualified[short].append(qname)

        def resolve_symbol(sym: str) -> Set[str]:
            """Map a symbol name to all matching qualified names in the call graph."""
            if sym in node_map:
                return {sym}
            # Try suffix match: "MyClass.method" → ends with ".method"
            candidates: Set[str] = set()
            for qname in node_map:
                if qname.endswith(f".{sym}") or qname == sym:
                    candidates.add(qname)
            return candidates

        # Seed the frontier with call-graph nodes that correspond to
        # directly-changed symbols.
        frontier: Set[str] = set()
        for sym in impact.directly_changed:
            frontier.update(resolve_symbol(sym))

        visited: Set[str] = set(frontier)
        new_callers: Set[str] = set()

        for _hop in range(5):
            next_frontier: Set[str] = set()
            for qname in frontier:
                node = node_map.get(qname)
                if not node:
                    continue
                for caller_qname in node.get("called_by", []):
                    if caller_qname not in visited:
                        visited.add(caller_qname)
                        next_frontier.add(caller_qname)
                        new_callers.add(caller_qname)
            if not next_frontier:
                break
            frontier = next_frontier

        impact.callers.update(new_callers)

        # Propagate entry-point detection to newly found callers
        for qname in new_callers:
            node = node_map.get(qname)
            if node and node.get("is_entry"):
                impact.entrypoints.add(qname)

        return impact

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        total_nodes = sum(len(v) for v in self._deps.values())
        total_symbols = len(self._symbol_to_nodes)
        total_files = len(self._file_symbols)
        total_symbols_tracked = sum(
            len(sym_map)
            for sym_map in self._file_symbols.values()
        )
        uptime = time.time() - self._start_time

        return {
            "graph_types_registered": list(self._deps.keys()),
            "total_graph_nodes": total_nodes,
            "unique_symbols_indexed": total_symbols,
            "files_tracked": total_files,
            "total_symbols_tracked": total_symbols_tracked,
            "invalidation_count": self._invalidation_count,
            "uptime_seconds": round(uptime, 2),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _files_for_symbols(self, symbols: Set[str]) -> Set[str]:
        """Return the set of files whose symbol maps contain any of *symbols*."""
        files: Set[str] = set()
        for filepath, sym_map in self._file_symbols.items():
            if symbols & set(sym_map.keys()):
                files.add(filepath)
        return files


# ===========================================================================
# PART 8 — Dependency Impact Analysis
# ===========================================================================


@dataclass
class DependencyImpact:
    """Result of analysing what a dependency change affects."""
    package_name:      str
    old_version:       str
    new_version:       str
    affected_cves:     List[str]    = field(default_factory=list)
    affected_files:    List[str]    = field(default_factory=list)
    reachable_files:   List[str]    = field(default_factory=list)
    affected_symbols:  Set[str]     = field(default_factory=set)
    risk_level:        str          = "UNKNOWN"  # CRITICAL / HIGH / MEDIUM / LOW / NONE

    def to_dict(self) -> dict:
        return {
            "package":          self.package_name,
            "old_version":      self.old_version,
            "new_version":      self.new_version,
            "affected_cves":    self.affected_cves,
            "affected_files":   self.affected_files,
            "reachable_files":  self.reachable_files,
            "affected_symbols": sorted(self.affected_symbols),
            "risk_level":       self.risk_level,
        }


class DependencyImpactAnalyzer:
    """
    Determines the impact of a dependency change on the project.

    When a package version changes (e.g. requests 2.28 → 2.29):
      1. Finds all project files that import the package.
      2. Identifies symbols that call the package's changed API.
      3. Maps affected symbols to known CVE IDs from existing findings.
      4. Returns a DependencyImpact summary.
    """

    # pip name → possible import names
    _PIP_TO_IMPORT: Dict[str, List[str]] = {
        "requests":      ["requests"],
        "pyyaml":        ["yaml"],
        "flask":         ["flask"],
        "django":        ["django"],
        "fastapi":       ["fastapi"],
        "sqlalchemy":    ["sqlalchemy"],
        "pillow":        ["PIL"],
        "numpy":         ["numpy", "np"],
        "cryptography":  ["cryptography"],
        "paramiko":      ["paramiko"],
        "jinja2":        ["jinja2"],
        "lxml":          ["lxml"],
        "urllib3":       ["urllib3"],
        "certifi":       ["certifi"],
        "setuptools":    ["setuptools", "pkg_resources"],
    }

    def __init__(self, project_root: str) -> None:
        self.project_root = str(Path(project_root).resolve())
        self._extractor   = SymbolExtractor()

    def analyze(
        self,
        package_name:  str,
        old_version:   str,
        new_version:   str,
        findings:      Optional[List[dict]] = None,
    ) -> DependencyImpact:
        """
        Analyse the impact of a dependency version change.

        Parameters
        ----------
        package_name : pip package name (e.g. "requests")
        old_version  : previous version string
        new_version  : new version string
        findings     : existing scan findings (to correlate CVEs)
        """
        import_names = self._PIP_TO_IMPORT.get(
            package_name.lower().replace("-", "_"),
            [package_name.lower()],
        )

        # 1. Find files that import this package
        affected_files:  List[str] = []
        reachable_files: List[str] = []
        affected_symbols: Set[str] = set()

        root = Path(self.project_root)
        _SKIP = {"__pycache__", ".git", "node_modules", ".venv", "venv"}

        for py_file in root.rglob("*.py"):
            if any(s in py_file.parts for s in _SKIP):
                continue
            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            source_lower = source.lower()
            if not any(imp in source_lower for imp in import_names):
                continue

            fpath = str(py_file)
            affected_files.append(fpath)

            # Extract symbols that reference the package
            try:
                syms = self._extractor.extract_from_source(source, fpath)
                for sym_name, sym_info in syms.items():
                    # Check if the symbol's body references the import
                    # (we do a simple substring check on the body hash being non-trivial)
                    if any(imp in source[sym_info.lineno:sym_info.end_lineno + 1].lower()
                           for imp in import_names):
                        affected_symbols.add(sym_name)
            except Exception:
                pass

            # Reachable files: not test files, has route or main
            fname = py_file.name.lower()
            is_test = fname.startswith("test_") or fname.endswith("_test.py")
            if not is_test:
                reachable_files.append(fpath)

        # 2. Correlate with findings to find affected CVEs
        affected_cves: List[str] = []
        if findings:
            affected_set = set(affected_files)
            for f in findings:
                ffile = f.get("file", "")
                if ffile in affected_set:
                    cve = f.get("cve_id") or f.get("cve") or ""
                    if cve and cve not in affected_cves:
                        affected_cves.append(cve)
                # Also check by package name in finding description
                desc = (f.get("description", "") + f.get("message", "")).lower()
                if package_name.lower() in desc:
                    cve = f.get("cve_id") or f.get("cve") or ""
                    if cve and cve not in affected_cves:
                        affected_cves.append(cve)

        # 3. Compute risk level
        if len(reachable_files) == 0:
            risk = "NONE"
        elif any(c for c in affected_cves):
            risk = "HIGH"
        elif len(reachable_files) > 5:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        return DependencyImpact(
            package_name     = package_name,
            old_version      = old_version,
            new_version      = new_version,
            affected_cves    = affected_cves,
            affected_files   = affected_files,
            reachable_files  = reachable_files,
            affected_symbols = affected_symbols,
            risk_level       = risk,
        )


# ===========================================================================
# PART 9 — Monorepo Support
# ===========================================================================


@dataclass
class MonorepoModule:
    """One sub-project within a monorepo."""
    name:       str
    path:       str          # absolute path to module root
    language:   str          # "python", "javascript", "solidity", etc.
    has_git:    bool         # is it its own git repo?
    manifest:   str          # path to package.json / pyproject.toml / Cargo.toml / etc.
    depth:      int          # nesting depth from monorepo root


class MonorepoDetector:
    """
    Detects whether a directory is a monorepo and enumerates its sub-modules.

    Detection heuristics:
      - Python packages: pyproject.toml / setup.py / setup.cfg in sub-directories
      - Node packages:   package.json with "name" field in sub-directories
      - Rust crates:     Cargo.toml in sub-directories
      - Solidity:        hardhat.config.js / foundry.toml
      - Top-level workspaces: package.json with "workspaces", pyproject.toml with
        [tool.setuptools.packages.find]

    Respects max_depth to avoid scanning deep vendor trees.
    """

    _MANIFESTS = {
        "pyproject.toml":  "python",
        "setup.py":        "python",
        "setup.cfg":       "python",
        "package.json":    "javascript",
        "Cargo.toml":      "rust",
        "go.mod":          "go",
        "hardhat.config.js": "solidity",
        "foundry.toml":    "solidity",
        "pom.xml":         "java",
        "build.gradle":    "java",
    }

    def __init__(self, root: str, max_depth: int = 4) -> None:
        self.root      = str(Path(root).resolve())
        self.max_depth = max_depth

    def detect(self) -> List[MonorepoModule]:
        """Return list of detected sub-modules. Empty if not a monorepo."""
        modules: List[MonorepoModule] = []
        root_path = Path(self.root)
        _SKIP = {"__pycache__", ".git", "node_modules", ".venv", "venv",
                 "dist", "build", ".eggs", ".tox", "vendor"}

        for dirpath, dirnames, filenames in os.walk(self.root):
            # Compute depth
            rel = os.path.relpath(dirpath, self.root)
            depth = 0 if rel == "." else len(Path(rel).parts)
            if depth > self.max_depth:
                dirnames[:] = []
                continue
            if depth == 0:
                # Skip pruned directories at root
                dirnames[:] = [d for d in dirnames if d not in _SKIP]
                continue

            # Check for manifest files
            for manifest_name, language in self._MANIFESTS.items():
                if manifest_name in filenames:
                    manifest_path = os.path.join(dirpath, manifest_name)
                    module_name   = Path(dirpath).name

                    # For package.json: skip if no "name" key (could be a config)
                    if manifest_name == "package.json":
                        try:
                            import json as _j
                            pkg = _j.loads(Path(manifest_path).read_text())
                            if "name" not in pkg:
                                continue
                            module_name = pkg.get("name", module_name)
                        except Exception:
                            pass

                    has_git = (Path(dirpath) / ".git").exists()

                    modules.append(MonorepoModule(
                        name     = module_name,
                        path     = dirpath,
                        language = language,
                        has_git  = has_git,
                        manifest = manifest_path,
                        depth    = depth,
                    ))
                    # Only one manifest per directory
                    break

            # Prune skip dirs
            dirnames[:] = [d for d in dirnames if d not in _SKIP]

        return modules

    def is_monorepo(self) -> bool:
        """Return True if ≥ 2 sub-modules are found (indicating a monorepo)."""
        return len(self.detect()) >= 2

    def get_changed_modules(
        self,
        changed_files: List[str],
        modules: Optional[List[MonorepoModule]] = None,
    ) -> List[MonorepoModule]:
        """
        Given a list of changed files, return which modules they belong to.
        """
        if modules is None:
            modules = self.detect()
        affected: List[MonorepoModule] = []
        for m in modules:
            m_path = str(Path(m.path).resolve())
            if any(str(Path(f).resolve()).startswith(m_path) for f in changed_files):
                affected.append(m)
        return affected
