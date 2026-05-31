"""Intra- and inter-file call graph builder."""
from __future__ import annotations

import ast
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger("tythanai.callgraph")

# Directories / packages that we should not attempt to resolve as project-local
_STDLIB_SKIP: Set[str] = {
    "os", "sys", "re", "io", "abc", "ast", "copy", "math", "time", "json",
    "enum", "uuid", "hmac", "hmac", "html", "http", "hashlib", "base64",
    "string", "struct", "socket", "select", "signal", "shutil", "logging",
    "pathlib", "typing", "inspect", "functools", "itertools", "operator",
    "collections", "contextlib", "dataclasses", "threading", "multiprocessing",
    "subprocess", "tempfile", "textwrap", "traceback", "warnings", "weakref",
    "urllib", "email", "xml", "csv", "random", "secrets", "decimal", "fractions",
    "numbers", "statistics", "datetime", "calendar", "locale", "gettext",
    "argparse", "configparser", "pprint", "pickle", "copyreg", "shelve",
    "sqlite3", "zlib", "gzip", "bz2", "lzma", "zipfile", "tarfile",
    "unittest", "doctest", "pdb", "profile", "timeit", "trace",
    # Popular third-party packages that are never "project-local"
    "pydantic", "fastapi", "starlette", "uvicorn", "sqlalchemy", "alembic",
    "celery", "redis", "aioredis", "httpx", "requests", "aiohttp",
    "click", "rich", "typer", "flask", "django", "tornado",
    "numpy", "pandas", "scipy", "sklearn", "torch", "tensorflow",
    "pytest", "hypothesis", "coverage",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class CallEdge(BaseModel):
    """A directed call edge in the call graph."""

    caller_file: str
    caller_func: str
    callee_file: str            # empty string if unresolved / external
    callee_func: str
    call_line: int
    arg_positions: List[int] = Field(default_factory=list)


class FunctionSig(BaseModel):
    """Signature of a function extracted from an AST."""

    name: str
    file: str
    params: List[str] = Field(default_factory=list)
    return_tainted: bool = False


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _attr_chain(node: ast.expr) -> List[str]:
    """Flatten an attribute chain to a list, e.g. ``a.b.c`` → ``['a','b','c']``."""
    parts: List[str] = []
    cur: ast.expr = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    parts.reverse()
    return parts


def _call_func_name(node: ast.Call) -> Tuple[str, ...]:
    """Return the callee name as a tuple of name parts."""
    return tuple(_attr_chain(node.func))


def _extract_params(func_node: ast.FunctionDef) -> List[str]:
    """Return all parameter names (positional, kw-only, *args, **kwargs)."""
    args = func_node.args
    params = (
        [a.arg for a in args.posonlyargs]
        + [a.arg for a in args.args]
        + [a.arg for a in args.kwonlyargs]
    )
    if args.vararg:
        params.append(args.vararg.arg)
    if args.kwarg:
        params.append(args.kwarg.arg)
    # Drop 'self' and 'cls' for clarity
    return [p for p in params if p not in ("self", "cls")]


def _is_tainted_return(
    func_node: ast.FunctionDef,
    params: List[str],
) -> bool:
    """
    Heuristic: return True if any ``return`` statement in *func_node* carries
    a value that references at least one of the function's *params*.
    """
    param_set = set(params)
    for node in ast.walk(func_node):
        if isinstance(node, ast.Return) and node.value is not None:
            for n in ast.walk(node.value):
                if isinstance(n, ast.Name) and n.id in param_set:
                    return True
    return False


# ---------------------------------------------------------------------------
# Per-file extraction
# ---------------------------------------------------------------------------

class _FileAnalyzer:
    """
    Analyse a single Python file:
    - collect ``FunctionSig`` for every function definition
    - collect ``CallEdge`` for every call made within function bodies
    - build an import alias map for cross-file resolution
    """

    def __init__(self, filepath: str, root: Path) -> None:
        self.filepath = filepath
        self.root = root
        self.sigs: List[FunctionSig] = []
        self.raw_edges: List[_RawEdge] = []   # resolved later
        # alias → module_path  (e.g. "np" → "numpy", "ta" → "taint_analyzer")
        self._import_aliases: Dict[str, str] = {}
        # from X import Y  → Y is accessible as bare name, maps to module X
        self._from_imports: Dict[str, str] = {}

    def run(self) -> None:
        try:
            source = Path(self.filepath).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("CallGraphBuilder: cannot read %s: %s", self.filepath, exc)
            return

        try:
            tree = ast.parse(source, filename=self.filepath)
        except SyntaxError as exc:
            logger.debug("CallGraphBuilder: syntax error in %s: %s", self.filepath, exc)
            return

        self._collect_imports(tree)
        self._collect_funcs(tree)

    def _collect_imports(self, tree: ast.Module) -> None:
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    key = alias.asname if alias.asname else alias.name
                    self._import_aliases[key] = alias.name
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    key = alias.asname if alias.asname else alias.name
                    self._from_imports[key] = module

    def _collect_funcs(self, tree: ast.Module) -> None:
        # Walk top-level and nested function defs
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params = _extract_params(node)  # type: ignore[arg-type]
                return_tainted = _is_tainted_return(node, params)  # type: ignore[arg-type]
                sig = FunctionSig(
                    name=node.name,
                    file=self.filepath,
                    params=params,
                    return_tainted=return_tainted,
                )
                self.sigs.append(sig)
                self._collect_calls_in_func(node)

    def _collect_calls_in_func(
        self,
        func_node: ast.FunctionDef,
    ) -> None:
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                parts = _call_func_name(node)
                if not parts:
                    continue
                # Figure out argument positions that are Name references
                arg_positions: List[int] = []
                for i, arg in enumerate(node.args):
                    if isinstance(arg, ast.Name):
                        arg_positions.append(i)

                self.raw_edges.append(_RawEdge(
                    caller_file=self.filepath,
                    caller_func=func_node.name,
                    callee_parts=parts,
                    call_line=getattr(node, "lineno", 0),
                    arg_positions=arg_positions,
                    import_aliases=self._import_aliases,
                    from_imports=self._from_imports,
                ))


class _RawEdge:
    """Unresolved call edge — resolved into ``CallEdge`` once all files are parsed."""

    __slots__ = (
        "caller_file", "caller_func", "callee_parts",
        "call_line", "arg_positions",
        "import_aliases", "from_imports",
    )

    def __init__(
        self,
        *,
        caller_file: str,
        caller_func: str,
        callee_parts: Tuple[str, ...],
        call_line: int,
        arg_positions: List[int],
        import_aliases: Dict[str, str],
        from_imports: Dict[str, str],
    ) -> None:
        self.caller_file = caller_file
        self.caller_func = caller_func
        self.callee_parts = callee_parts
        self.call_line = call_line
        self.arg_positions = arg_positions
        self.import_aliases = import_aliases
        self.from_imports = from_imports


# ---------------------------------------------------------------------------
# CallGraphBuilder
# ---------------------------------------------------------------------------

class CallGraphBuilder:
    """
    Build an intra- and inter-file call graph for all Python files found
    under a *root_path* directory.

    Usage::

        builder = CallGraphBuilder()
        functions, edges = builder.build("/path/to/project")
    """

    def build(
        self,
        root_path: str,
        max_depth: int = 5,
    ) -> Tuple[Dict[str, FunctionSig], List[CallEdge]]:
        """
        Walk all ``.py`` files under *root_path* and build the call graph.

        Returns:
            A tuple ``(functions_map, edges)`` where:

            - *functions_map*: ``{qualified_name → FunctionSig}`` with keys
              in the form ``"<filepath>::<func_name>"``.
            - *edges*: list of ``CallEdge`` objects.

        *max_depth* limits how deeply nested sub-directories are scanned;
        stdlib/site-packages are never followed.
        """
        root = Path(root_path).resolve()
        if not root.exists():
            logger.warning("CallGraphBuilder.build: root path does not exist: %s", root)
            return {}, []

        py_files = self._collect_py_files(root, max_depth)
        logger.info("CallGraphBuilder: scanning %d Python files under %s", len(py_files), root)

        # Phase 1: parse every file
        analyzers: List[_FileAnalyzer] = []
        for fp in py_files:
            fa = _FileAnalyzer(str(fp), root)
            fa.run()
            analyzers.append(fa)

        # Phase 2: build the functions map
        functions_map: Dict[str, FunctionSig] = {}
        # Index: (file, func_name) → FunctionSig
        func_index: Dict[Tuple[str, str], FunctionSig] = {}
        # Index: func_name → list of files where it is defined
        name_to_files: Dict[str, List[str]] = {}
        for fa in analyzers:
            for sig in fa.sigs:
                key = f"{sig.file}::{sig.name}"
                functions_map[key] = sig
                func_index[(sig.file, sig.name)] = sig
                name_to_files.setdefault(sig.name, []).append(sig.file)

        # Phase 3: resolve raw edges → CallEdge
        edges: List[CallEdge] = []
        for fa in analyzers:
            for raw in fa.raw_edges:
                edge = self._resolve_edge(raw, fa.filepath, func_index, name_to_files, root)
                if edge is not None:
                    edges.append(edge)

        logger.info(
            "CallGraphBuilder: %d functions, %d edges",
            len(functions_map), len(edges),
        )
        return functions_map, edges

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_py_files(root: Path, max_depth: int) -> List[Path]:
        """Return all .py files under *root* up to *max_depth* directory levels."""
        skip_dirs = {
            "__pycache__", ".git", ".venv", "venv", "env",
            "node_modules", "site-packages", ".tox", "build", "dist",
        }
        results: List[Path] = []
        root_parts_len = len(root.parts)

        for dirpath, dirnames, filenames in os.walk(root):
            cur_path = Path(dirpath)
            depth = len(cur_path.parts) - root_parts_len
            if depth > max_depth:
                dirnames.clear()
                continue
            # Prune unwanted subdirectories in-place
            dirnames[:] = [
                d for d in dirnames
                if d not in skip_dirs and not d.startswith(".")
            ]
            for fname in filenames:
                if fname.endswith(".py"):
                    results.append(cur_path / fname)

        return sorted(results)

    def _resolve_edge(
        self,
        raw: _RawEdge,
        caller_file: str,
        func_index: Dict[Tuple[str, str], FunctionSig],
        name_to_files: Dict[str, List[str]],
        root: Path,
    ) -> Optional[CallEdge]:
        """
        Attempt to resolve *raw* to a ``CallEdge``.

        Resolution priority:
        1. Bare name call → look up same file first, then any file in project.
        2. Module.func call → resolve module alias to a file, then look up func.
        3. Unresolved (external / stdlib) → skip.
        """
        parts = raw.callee_parts
        if not parts:
            return None

        callee_func = parts[-1]

        # 1. Single-name call (e.g. ``helper(x)``)
        if len(parts) == 1:
            # Same file first
            if (caller_file, callee_func) in func_index:
                return CallEdge(
                    caller_file=caller_file,
                    caller_func=raw.caller_func,
                    callee_file=caller_file,
                    callee_func=callee_func,
                    call_line=raw.call_line,
                    arg_positions=raw.arg_positions,
                )
            # from-import: the function may be imported from another module
            if callee_func in raw.from_imports:
                module = raw.from_imports[callee_func]
                if not self._is_external(module):
                    callee_file = self._resolve_module_to_file(module, root, caller_file)
                    if callee_file:
                        return CallEdge(
                            caller_file=caller_file,
                            caller_func=raw.caller_func,
                            callee_file=callee_file,
                            callee_func=callee_func,
                            call_line=raw.call_line,
                            arg_positions=raw.arg_positions,
                        )
            # Any file in project
            if callee_func in name_to_files:
                files = name_to_files[callee_func]
                # Prefer same file
                best_file = next((f for f in files if f == caller_file), files[0])
                return CallEdge(
                    caller_file=caller_file,
                    caller_func=raw.caller_func,
                    callee_file=best_file,
                    callee_func=callee_func,
                    call_line=raw.call_line,
                    arg_positions=raw.arg_positions,
                )
            return None  # not a project function

        # 2. Dotted call (e.g. ``module.helper(x)`` or ``obj.method(x)``)
        obj_name = parts[0]

        # Check if obj_name is a known import alias
        module_str: Optional[str] = raw.import_aliases.get(obj_name) or raw.from_imports.get(obj_name)
        if module_str and not self._is_external(module_str):
            callee_file = self._resolve_module_to_file(module_str, root, caller_file)
            if callee_file and (callee_file, callee_func) in func_index:
                return CallEdge(
                    caller_file=caller_file,
                    caller_func=raw.caller_func,
                    callee_file=callee_file,
                    callee_func=callee_func,
                    call_line=raw.call_line,
                    arg_positions=raw.arg_positions,
                )

        # obj.method — look for callee_func in same file (could be self.helper)
        if (caller_file, callee_func) in func_index:
            return CallEdge(
                caller_file=caller_file,
                caller_func=raw.caller_func,
                callee_file=caller_file,
                callee_func=callee_func,
                call_line=raw.call_line,
                arg_positions=raw.arg_positions,
            )

        return None  # unresolvable

    @staticmethod
    def _is_external(module: str) -> bool:
        """Return True if *module* looks like a stdlib or third-party package."""
        top = module.split(".")[0]
        return top in _STDLIB_SKIP

    @staticmethod
    def _resolve_module_to_file(
        module: str,
        root: Path,
        caller_file: str,
    ) -> Optional[str]:
        """
        Try to map a Python module name (e.g. ``backend.scanners.taint_analyzer``)
        to an absolute file path under *root*.
        """
        rel_path = module.replace(".", os.sep) + ".py"
        candidate = root / rel_path
        if candidate.exists():
            return str(candidate)

        # Also try relative to caller's directory
        caller_dir = Path(caller_file).parent
        candidate2 = caller_dir / rel_path
        if candidate2.exists():
            return str(candidate2)

        # Search anywhere under root
        for found in root.rglob(Path(rel_path).name):
            return str(found)

        return None
