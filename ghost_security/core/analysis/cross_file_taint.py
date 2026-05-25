"""
Ghost Security — Cross-File Taint Analysis

Tracks tainted data flow ACROSS multiple Python files:
  user_input → function call in routes.py
             → function in service.py
             → SQL query in db.py
             → CRITICAL finding

Algorithm:
  1. Index all Python files: parse imports, function defs, function calls
  2. Build inter-file call graph
  3. Run taint propagation: if a function receives tainted arg, mark its
     callees as receiving tainted data
  4. Report taint flows that cross ≥ 2 files before reaching a sink

Usage:
    from core.analysis.cross_file_taint import CrossFileTaintAnalyzer
    analyzer = CrossFileTaintAnalyzer("/path/to/project")
    findings = analyzer.analyze()
"""
from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv",
              "dist", "build", "migrations"}

# ── Sources of untrusted input ────────────────────────────────────────────────
_SOURCES: Set[str] = {
    "request.args", "request.form", "request.json", "request.data",
    "request.cookies", "request.headers", "request.files",
    "request.GET", "request.POST", "request.body",
    "sys.argv", "input", "os.environ.get", "environ.get",
    "socket.recv", "socket.recvfrom",
}

# ── Dangerous sinks ────────────────────────────────────────────────────────────
_SINK_INFO: Dict[str, Dict] = {
    "execute":           {"cwe": "CWE-89",  "sev": "CRITICAL", "name": "SQL execute()"},
    "executemany":       {"cwe": "CWE-89",  "sev": "CRITICAL", "name": "SQL executemany()"},
    "raw":               {"cwe": "CWE-89",  "sev": "CRITICAL", "name": "Django .raw()"},
    "eval":              {"cwe": "CWE-95",  "sev": "CRITICAL", "name": "eval()"},
    "exec":              {"cwe": "CWE-95",  "sev": "CRITICAL", "name": "exec()"},
    "system":            {"cwe": "CWE-78",  "sev": "CRITICAL", "name": "os.system()"},
    "popen":             {"cwe": "CWE-78",  "sev": "CRITICAL", "name": "popen()"},
    "subprocess.run":    {"cwe": "CWE-78",  "sev": "CRITICAL", "name": "subprocess.run()"},
    "subprocess.call":   {"cwe": "CWE-78",  "sev": "CRITICAL", "name": "subprocess.call()"},
    "pickle.loads":      {"cwe": "CWE-502", "sev": "CRITICAL", "name": "pickle.loads()"},
    "yaml.load":         {"cwe": "CWE-502", "sev": "HIGH",     "name": "yaml.load()"},
    "open":              {"cwe": "CWE-22",  "sev": "HIGH",     "name": "open()"},
    "render_template_string": {"cwe": "CWE-94", "sev": "CRITICAL", "name": "SSTI"},
    "Markup":            {"cwe": "CWE-79",  "sev": "HIGH",     "name": "Markup()"},
    "redirect":          {"cwe": "CWE-601", "sev": "MEDIUM",   "name": "redirect()"},
    "send_file":         {"cwe": "CWE-22",  "sev": "HIGH",     "name": "send_file()"},
}


@dataclass
class FunctionDef:
    name:     str
    file:     str
    line:     int
    args:     List[str] = field(default_factory=list)
    module:   str = ""


@dataclass
class CallSite:
    caller_func: str
    caller_file: str
    caller_line: int
    callee_name: str
    args:        List[str] = field(default_factory=list)


@dataclass
class TaintFlow:
    source_type: str
    source_file: str
    source_line: int
    sink_type:   str
    sink_file:   str
    sink_line:   int
    path:        List[str]   # ["file1.py:func_a", "file2.py:func_b"]
    variable:    str
    severity:    str
    cwe:         str
    cross_file:  bool = True

    def to_dict(self) -> Dict:
        return {
            "type":        "CROSS_FILE_TAINT",
            "id":          f"TAINT-XFILE-{self.sink_type.upper().replace('.','_')}",
            "severity":    self.severity,
            "cwe":         self.cwe,
            "file":        self.sink_file,
            "line":        self.sink_line,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "message":     (
                f"Cross-file taint: user input from {Path(self.source_file).name}:{self.source_line}"
                f" reaches {self.sink_type} in {Path(self.sink_file).name}:{self.sink_line}"
            ),
            "description": (
                f"Tainted user input flows through {len(self.path)} function(s) across files "
                f"before reaching dangerous sink '{self.sink_type}'"
            ),
            "evidence":    " → ".join(self.path[-4:]),
            "recommendation": _SINK_INFO.get(self.sink_type, {}).get("fix",
                              "Validate and sanitize user input before passing to external functions"),
            "source":      "cross_file_taint",
            "scanner":     "taint",
            "category":    "Dataflow",
            "confidence":  72,
            "taint_path":  self.path,
            "variable":    self.variable,
        }


class _FileIndex:
    """AST index for one Python source file."""

    def __init__(self, file_path: str) -> None:
        self.path      = file_path
        self.module    = _path_to_module(file_path)
        self.functions: Dict[str, FunctionDef] = {}   # name → def
        self.calls:     List[CallSite]         = []
        self.imports:   Dict[str, str]         = {}   # local_name → module
        self.taint_sources: List[Tuple[str, int]] = []  # (var_name, line)
        self._parse()

    def _parse(self) -> None:
        try:
            source = Path(self.path).read_text(errors="replace")
            tree   = ast.parse(source, filename=self.path)
        except Exception:
            return
        _Visitor(self).visit(tree)


class _Visitor(ast.NodeVisitor):
    def __init__(self, index: _FileIndex) -> None:
        self.idx   = index
        self._func_stack: List[str] = ["<module>"]

    def _current_func(self) -> str:
        return self._func_stack[-1]

    def visit_FunctionDef(self, node):
        args = [a.arg for a in node.args.args]
        fdef = FunctionDef(
            name=node.name, file=self.idx.path, line=node.lineno,
            args=args, module=self.idx.module,
        )
        self.idx.functions[node.name] = fdef
        self._func_stack.append(node.name)
        self.generic_visit(node)
        self._func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Import(self, node):
        for alias in node.names:
            local = alias.asname or alias.name
            self.idx.imports[local] = alias.name

    def visit_ImportFrom(self, node):
        if node.module:
            for alias in node.names:
                local = alias.asname or alias.name
                self.idx.imports[local] = f"{node.module}.{alias.name}"

    def visit_Assign(self, node):
        # Detect taint sources
        rhs = ast.unparse(node.value) if hasattr(ast, "unparse") else ""
        if any(src in rhs for src in _SOURCES):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.idx.taint_sources.append((target.id, node.lineno))
        self.generic_visit(node)

    def visit_Call(self, node):
        callee = ""
        if isinstance(node.func, ast.Name):
            callee = node.func.id
        elif isinstance(node.func, ast.Attribute):
            callee = node.func.attr

        if callee:
            arg_strs = []
            for a in node.args:
                try:
                    arg_strs.append(ast.unparse(a) if hasattr(ast, "unparse") else "")
                except Exception:
                    arg_strs.append("")

            self.idx.calls.append(CallSite(
                caller_func=self._current_func(),
                caller_file=self.idx.path,
                caller_line=node.lineno,
                callee_name=callee,
                args=arg_strs,
            ))
        self.generic_visit(node)


def _path_to_module(path: str) -> str:
    """Convert file path to dotted module name."""
    p = Path(path)
    parts = list(p.with_suffix("").parts)
    try:
        # Find first non-directory component
        return ".".join(parts[-3:])
    except Exception:
        return p.stem


class CrossFileTaintAnalyzer:
    """
    Performs inter-procedural taint analysis across all Python files
    in a project directory.
    """

    def __init__(self, project_root: str, max_files: int = 200) -> None:
        self.root      = Path(project_root)
        self.max_files = max_files
        self._indexes: Dict[str, _FileIndex] = {}
        self._built    = False

    def analyze(self) -> List[Dict]:
        """Run full cross-file taint analysis. Returns list of Ghost findings."""
        self._build_index()
        flows = self._propagate()
        return [f.to_dict() for f in flows]

    # ── Index building ────────────────────────────────────────────────────────

    def _build_index(self) -> None:
        if self._built:
            return
        count = 0
        for p in self.root.rglob("*.py"):
            if count >= self.max_files:
                break
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            idx = _FileIndex(str(p))
            self._indexes[str(p)] = idx
            count += 1
        self._built = True

    # ── Taint propagation ─────────────────────────────────────────────────────

    def _propagate(self) -> List[TaintFlow]:
        """
        BFS-based inter-procedural propagation.
        State: set of (file, func, var) that are currently tainted.
        """
        # Build lookup maps
        func_lookup: Dict[str, List[FunctionDef]] = defaultdict(list)
        for idx in self._indexes.values():
            for fname, fdef in idx.functions.items():
                func_lookup[fname].append(fdef)

        flows: List[TaintFlow] = []
        seen_flows: Set[Tuple] = set()

        # Seed: all taint sources across all files
        # Each worklist item: (tainted_var, file, line, call_path)
        worklist: List[Tuple[str, str, int, List[str]]] = []
        for idx in self._indexes.values():
            for var, line in idx.taint_sources:
                worklist.append((var, idx.path, line, [f"{Path(idx.path).name}:{line}"]))

        visited: Set[Tuple[str, str, int]] = set()
        max_iters = 5000
        iterations = 0

        while worklist and iterations < max_iters:
            iterations += 1
            var, cur_file, cur_line, path = worklist.pop(0)

            state_key = (var, cur_file, cur_line)
            if state_key in visited:
                continue
            visited.add(state_key)

            idx = self._indexes.get(cur_file)
            if not idx:
                continue

            # Check if var flows into a sink in this file
            for call in idx.calls:
                if call.caller_line < cur_line - 50:  # only forward calls
                    continue
                # Is var used in arguments?
                var_in_args = any(var in arg for arg in call.args)
                if not var_in_args:
                    continue

                callee = call.callee_name

                # Sink check
                for sink_key, sink_info in _SINK_INFO.items():
                    if sink_key in callee or callee.endswith(sink_key.split(".")[-1]):
                        flow_key = (cur_file, callee, call.caller_line)
                        if flow_key in seen_flows:
                            continue
                        seen_flows.add(flow_key)

                        sink_path = path + [f"{Path(cur_file).name}:{call.caller_line}→{callee}"]
                        cross = len({p.split(":")[0] for p in sink_path}) > 1
                        if cross:  # Only report cross-file flows
                            flows.append(TaintFlow(
                                source_type=path[0].split(":")[0] if path else "user_input",
                                source_file=cur_file,
                                source_line=cur_line,
                                sink_type=callee,
                                sink_file=call.caller_file,
                                sink_line=call.caller_line,
                                path=sink_path,
                                variable=var,
                                severity=sink_info.get("sev", "HIGH"),
                                cwe=sink_info.get("cwe", "CWE-20"),
                            ))
                        break

                # Propagate into callee function (inter-procedural)
                if len(path) >= 6:  # depth limit
                    continue
                for fdef in func_lookup.get(callee, []):
                    if fdef.file == cur_file:
                        continue  # same-file handled by single-file taint
                    new_path = path + [f"{Path(fdef.file).name}:{fdef.line}:{callee}()"]
                    # Propagate with first arg (simplified)
                    new_var = fdef.args[0] if fdef.args else var
                    worklist.append((new_var, fdef.file, fdef.line, new_path))

        # Deduplicate
        seen: Set[Tuple] = set()
        unique: List[TaintFlow] = []
        for f in flows:
            key = (f.source_file, f.sink_file, f.sink_line, f.sink_type)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique
