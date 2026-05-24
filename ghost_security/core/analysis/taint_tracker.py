"""
Ghost Security — AST Dataflow / Taint Tracker
Real AST-based taint propagation for Python source code.
Tracks data from untrusted sources → dangerous sinks.
"""
import ast, re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class TaintFlow:
    source_type: str
    source_line: int
    sink_type:   str
    sink_line:   int
    variable:    str
    path:        List[str] = field(default_factory=list)
    severity:    str = "HIGH"
    cwe:         str = ""
    description: str = ""

    def to_dict(self):
        return {"type":"TAINT_FLOW","id":f"TAINT-{self.sink_type.upper()}",
                "severity":self.severity,"source_type":self.source_type,
                "source_line":self.source_line,"sink_type":self.sink_type,
                "sink_line":self.sink_line,"variable":self.variable,
                "description":self.description,"cwe":self.cwe,
                "recommendation":SINK_INFO.get(self.sink_type,{}).get("fix","Validate input before use"),
                "source":"taint_tracker","category":"Dataflow"}

# Untrusted input sources
SOURCES = {
    "request.args","request.form","request.json","request.data",
    "request.cookies","request.headers","request.files",
    "flask.request","fastapi.Request",
    "input(","sys.argv","os.environ.get","environ.get",
    "request.GET","request.POST","request.body",
    "socket.recv","socket.recvfrom",
}

# Dangerous sinks with metadata
SINK_INFO = {
    "subprocess": {"cwe":"CWE-78",  "sev":"CRITICAL","fix":"Use shlex.split + shell=False; never interpolate user input"},
    "os.system":  {"cwe":"CWE-78",  "sev":"CRITICAL","fix":"Replace with subprocess.run(..., shell=False)"},
    "eval":       {"cwe":"CWE-95",  "sev":"CRITICAL","fix":"Never eval() user input; use ast.literal_eval for data"},
    "exec":       {"cwe":"CWE-95",  "sev":"CRITICAL","fix":"Never exec() user input"},
    "sql":        {"cwe":"CWE-89",  "sev":"CRITICAL","fix":"Use parameterised queries / ORM"},
    "open":       {"cwe":"CWE-22",  "sev":"HIGH",    "fix":"Validate path with os.path.abspath and a whitelist"},
    "pickle":     {"cwe":"CWE-502", "sev":"CRITICAL","fix":"Never deserialise untrusted data with pickle"},
    "yaml.load":  {"cwe":"CWE-502", "sev":"HIGH",    "fix":"Use yaml.safe_load() instead"},
    "render_template_string":{"cwe":"CWE-94","sev":"CRITICAL","fix":"Never render user input as a template"},
    "redirect":   {"cwe":"CWE-601", "sev":"MEDIUM",  "fix":"Validate redirect URL against an allowlist"},
    "logging":    {"cwe":"CWE-117", "sev":"LOW",     "fix":"Sanitise user data before logging"},
    "hashlib":    {"cwe":"CWE-327", "sev":"MEDIUM",  "fix":"Use strong hash (sha256+) with salt for passwords"},
}


class TaintTracker(ast.NodeVisitor):
    """
    Single-file taint analysis via Python AST walk.
    Tracks variable assignments from tainted sources through
    the call graph to dangerous sinks.
    """

    def __init__(self):
        self._tainted:  Dict[str, int] = {}   # var_name → line where tainted
        self._flows:    List[TaintFlow] = []
        self._filename: str = "<unknown>"

    def analyze_file(self, file_path: str) -> List[Dict]:
        p = Path(file_path)
        if p.suffix != ".py":
            return []
        try:
            tree = ast.parse(p.read_text(errors="replace"), filename=str(p))
        except SyntaxError:
            return []
        self._filename = str(p)
        self._tainted  = {}
        self._flows    = []
        self.visit(tree)
        return [f.to_dict() for f in self._flows]

    def analyze_code(self, code: str, filename: str = "<snippet>") -> List[Dict]:
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return []
        self._filename = filename
        self._tainted  = {}
        self._flows    = []
        self.visit(tree)
        return [f.to_dict() for f in self._flows]

    # ── AST visitors ─────────────────────────────────────────────────────────

    def visit_Assign(self, node):
        # Check if RHS is a tainted source or tainted variable
        source = self._get_taint_source(node.value)
        if source:
            for target in node.targets:
                name = self._get_name(target)
                if name:
                    self._tainted[name] = node.lineno
        # Propagate taint through assignments
        else:
            taint_line = self._is_tainted_expr(node.value)
            if taint_line is not None:
                for target in node.targets:
                    name = self._get_name(target)
                    if name:
                        self._tainted[name] = node.lineno
        self.generic_visit(node)

    def visit_Call(self, node):
        call_str = self._ast_to_str(node)
        sink = self._identify_sink(call_str)
        if sink:
            for arg in node.args:
                taint_line = self._is_tainted_expr(arg)
                if taint_line is not None:
                    info = SINK_INFO.get(sink, {})
                    self._flows.append(TaintFlow(
                        source_type="user_input", source_line=taint_line,
                        sink_type=sink, sink_line=node.lineno,
                        variable=self._ast_to_str(arg)[:50],
                        severity=info.get("sev","HIGH"), cwe=info.get("cwe","CWE-20"),
                        description=f"Tainted user input flows into {sink}() — {info.get('cwe','')}",
                    ))
        self.generic_visit(node)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_taint_source(self, node) -> Optional[str]:
        s = self._ast_to_str(node)
        for src in SOURCES:
            if src in s:
                return src
        return None

    def _is_tainted_expr(self, node) -> Optional[int]:
        """Return the taint line if this expression uses a tainted variable."""
        names = self._collect_names(node)
        for name in names:
            if name in self._tainted:
                return self._tainted[name]
        return None

    def _collect_names(self, node) -> Set[str]:
        names = set()
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(self._ast_to_str(node))
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                names.add(child.id)
        return names

    def _identify_sink(self, call_str: str) -> Optional[str]:
        for sink in SINK_INFO:
            if sink in call_str:
                return sink
        return None

    @staticmethod
    def _get_name(node) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{TaintTracker._ast_to_str.__func__(TaintTracker, node)}"
        return None

    @staticmethod
    def _ast_to_str(node) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return ""
