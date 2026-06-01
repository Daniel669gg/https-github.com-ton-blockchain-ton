"""Reachable CVE Analyzer — link vulnerable dependency CVEs to CPG call paths."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ReachableCVE:
    """A CVE enriched with reachability information from CPG analysis."""
    cve_id: str
    package_name: str
    installed_version: str
    severity: str = "UNKNOWN"
    is_reachable: bool = False
    reachability_score: float = 0.0   # 0.0-1.0
    call_path: List[str] = field(default_factory=list)
    vulnerable_function: str = ""
    sink_type: str = ""               # exec/sql/file/network/deserialization
    justification: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "severity": self.severity,
            "is_reachable": self.is_reachable,
            "reachability_score": self.reachability_score,
            "call_path": self.call_path,
            "vulnerable_function": self.vulnerable_function,
            "sink_type": self.sink_type,
            "justification": self.justification,
            "evidence": self.evidence,
        }


@dataclass
class ReachabilityAnalysisResult:
    """Aggregated result of reachable CVE analysis."""
    total_cves_analyzed: int = 0
    total_reachable: int = 0
    total_not_reachable: int = 0
    reachable_cves: List[ReachableCVE] = field(default_factory=list)
    not_reachable_cves: List[ReachableCVE] = field(default_factory=list)
    analysis_errors: List[str] = field(default_factory=list)

    @property
    def all_cves(self) -> List[ReachableCVE]:
        return self.reachable_cves + self.not_reachable_cves

    @property
    def reachable_critical(self) -> List[ReachableCVE]:
        return [r for r in self.reachable_cves if r.severity in ("CRITICAL", "HIGH")]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_cves_analyzed": self.total_cves_analyzed,
            "total_reachable": self.total_reachable,
            "total_not_reachable": self.total_not_reachable,
            "reachable_cves": [r.to_dict() for r in self.reachable_cves],
            "not_reachable_cves": [r.to_dict() for r in self.not_reachable_cves],
            "analysis_errors": self.analysis_errors,
        }


# ---------------------------------------------------------------------------
# Package → module import name mapping
# ---------------------------------------------------------------------------

_PYPI_TO_IMPORT: Dict[str, str] = {
    "pyyaml": "yaml",
    "pillow": "PIL",
    "scikit-learn": "sklearn",
    "beautifulsoup4": "bs4",
    "python-dateutil": "dateutil",
    "typing-extensions": "typing_extensions",
    "requests": "requests",
    "flask": "flask",
    "django": "django",
    "numpy": "numpy",
    "pandas": "pandas",
    "sqlalchemy": "sqlalchemy",
    "cryptography": "cryptography",
    "paramiko": "paramiko",
    "lxml": "lxml",
    "urllib3": "urllib3",
    "jinja2": "jinja2",
    "werkzeug": "werkzeug",
    "setuptools": "setuptools",
    "pip": "pip",
    "celery": "celery",
    "redis": "redis",
    "pymongo": "pymongo",
    "psycopg2": "psycopg2",
    "pydantic": "pydantic",
    "httpx": "httpx",
    "aiohttp": "aiohttp",
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "starlette": "starlette",
    "click": "click",
    "boto3": "boto3",
    "botocore": "botocore",
}

# CWE → sink type mapping
_CWE_TO_SINK: Dict[str, str] = {
    "CWE-78":  "exec",
    "CWE-77":  "exec",
    "CWE-89":  "sql",
    "CWE-502": "deserialization",
    "CWE-20":  "input_validation",
    "CWE-22":  "file",
    "CWE-79":  "html",
    "CWE-918": "network",
    "CWE-611": "xml",
    "CWE-94":  "code_injection",
    "CWE-476": "null_deref",
    "CWE-400": "resource_exhaustion",
    "CWE-200": "info_disclosure",
}

# Dangerous functions per module
_DANGEROUS_FUNCTIONS: Dict[str, List[Tuple[str, str]]] = {
    "yaml":     [("load", "deserialization"), ("safe_load", "deserialization")],
    "pickle":   [("load", "deserialization"), ("loads", "deserialization"), ("unpickle", "deserialization")],
    "marshal":  [("load", "deserialization"), ("loads", "deserialization")],
    "subprocess": [("call", "exec"), ("run", "exec"), ("Popen", "exec"), ("check_output", "exec")],
    "os":       [("system", "exec"), ("popen", "exec"), ("execv", "exec"), ("execve", "exec")],
    "shutil":   [("rmtree", "file"), ("copyfile", "file")],
    "requests": [("get", "network"), ("post", "network"), ("put", "network"), ("delete", "network")],
    "urllib":   [("urlopen", "network"), ("urlretrieve", "network")],
    "sqlite3":  [("execute", "sql"), ("executemany", "sql")],
    "lxml":     [("fromstring", "xml"), ("parse", "xml")],
    "jinja2":   [("Template", "template"), ("from_string", "template")],
    "paramiko": [("exec_command", "exec"), ("connect", "network")],
    "PIL":      [("open", "file"), ("Image", "file")],
    "flask":    [("render_template_string", "template")],
}


# ---------------------------------------------------------------------------
# Source code reachability helpers
# ---------------------------------------------------------------------------

_IMPORT_PATTERN = re.compile(
    r"^\s*(?:import\s+(\S+)|from\s+(\S+)\s+import\s+(.+))",
    re.MULTILINE,
)

_CALL_PATTERN = re.compile(r"(\w+)\.(\w+)\s*\(")


def _extract_imports(source: str) -> Dict[str, str]:
    """Return {alias: module} from import statements in *source*."""
    aliases: Dict[str, str] = {}
    for m in _IMPORT_PATTERN.finditer(source):
        if m.group(1):
            mod = m.group(1).split(".")[0]
            aliases[mod] = mod
        elif m.group(2) and m.group(3):
            mod = m.group(2).split(".")[0]
            for name in m.group(3).split(","):
                name = name.strip()
                if name:
                    aliases[name] = mod
    return aliases


def _find_calls_to_package(source: str, module_name: str) -> List[Tuple[str, str]]:
    """Return [(func_name, context_line)] where module_name.func_name is called."""
    results: List[Tuple[str, str]] = []
    for m in _CALL_PATTERN.finditer(source):
        obj, func = m.group(1), m.group(2)
        if obj.lower() == module_name.lower():
            # Find the line containing this call
            start = source.rfind("\n", 0, m.start()) + 1
            end = source.find("\n", m.end())
            line = source[start: end if end >= 0 else len(source)].strip()
            results.append((func, line))
    return results


def _score_sink_reachability(calls: List[Tuple[str, str]], module: str) -> Tuple[float, str, str]:
    """Return (score, vulnerable_function, sink_type) from observed calls."""
    dangerous = _DANGEROUS_FUNCTIONS.get(module, [])
    dangerous_map = {fn: st for fn, st in dangerous}

    best_score = 0.0
    best_func = ""
    best_sink = ""

    for func, _line in calls:
        if func in dangerous_map:
            sink = dangerous_map[func]
            # Higher score for execution sinks
            score = {
                "exec": 0.95,
                "deserialization": 0.9,
                "sql": 0.85,
                "code_injection": 0.9,
                "file": 0.7,
                "network": 0.6,
                "xml": 0.65,
                "template": 0.7,
                "input_validation": 0.5,
                "info_disclosure": 0.4,
                "null_deref": 0.3,
                "resource_exhaustion": 0.3,
                "html": 0.5,
            }.get(sink, 0.5)
            if score > best_score:
                best_score = score
                best_func = func
                best_sink = sink

    return best_score, best_func, best_sink


# ---------------------------------------------------------------------------
# CPG-based reachability
# ---------------------------------------------------------------------------

def _cpg_reachability(
    cpg: Any, module_name: str
) -> Tuple[bool, float, List[str]]:
    """Check CPG nodes for usage of *module_name* taint sources."""
    try:
        if cpg is None:
            return False, 0.0, []
        nodes = cpg.nodes if isinstance(cpg.nodes, dict) else {}
        matching_nodes = []
        for nid, node in nodes.items():
            props = getattr(node, "properties", {}) or {}
            label = getattr(node, "label", "") or ""
            code = props.get("code", "") or props.get("source", "") or label
            if module_name.lower() in code.lower():
                is_source = props.get("is_taint_source", False)
                is_sink = props.get("is_taint_sink", False)
                matching_nodes.append((nid, is_source, is_sink))

        if not matching_nodes:
            return False, 0.0, []

        # Check if any matching node is a taint source that reaches a sink
        for nid, is_source, is_sink in matching_nodes:
            if is_source or is_sink:
                # Try to find a path
                path = _bfs_path_to_sink(cpg, nid)
                if path:
                    return True, 0.8, path

        # Found in CPG but no confirmed taint path
        return True, 0.4, [n[0] for n in matching_nodes[:3]]

    except Exception as exc:
        logger.debug("CPG reachability check failed: %s", exc)
        return False, 0.0, []


def _bfs_path_to_sink(cpg: Any, start_id: str, max_depth: int = 8) -> List[str]:
    """BFS from *start_id* to find a path reaching any taint sink."""
    try:
        visited = {start_id}
        queue = [[start_id]]
        adj = getattr(cpg, "_adj", {})

        while queue:
            path = queue.pop(0)
            if len(path) > max_depth:
                break
            current = path[-1]
            for edge in adj.get(current, []):
                nxt = getattr(edge, "target", None)
                if nxt is None or nxt in visited:
                    continue
                visited.add(nxt)
                new_path = path + [nxt]
                # Check if target is a sink
                nodes = cpg.nodes if isinstance(cpg.nodes, dict) else {}
                node = nodes.get(nxt)
                if node:
                    props = getattr(node, "properties", {}) or {}
                    if props.get("is_taint_sink", False):
                        return new_path
                queue.append(new_path)
    except Exception as exc:
        logger.debug("BFS path search failed: %s", exc)
    return []


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------


class ReachableCVEAnalyzer:
    """Determines which CVEs in vulnerable dependencies are reachable from application code."""

    def analyze(
        self,
        dep_result: Any,  # DependencyAnalysisResult from dependency_taint.py
        cpg: Optional[Any] = None,  # CodePropertyGraph, optional
        source_code: str = "",
    ) -> ReachabilityAnalysisResult:
        """
        Analyze reachability for all CVEs found in *dep_result*.

        Parameters
        ----------
        dep_result : DependencyAnalysisResult
            Output of DependencyTaintAnalyzer.analyze_manifest().
        cpg : CodePropertyGraph, optional
            If provided, CPG-based path tracing is used to confirm reachability.
        source_code : str
            Source code to analyze for import and call patterns.

        Returns
        -------
        ReachabilityAnalysisResult
        """
        result = ReachabilityAnalysisResult()

        # Extract package info from dep_result
        vulnerable_packages = getattr(dep_result, "vulnerable_packages", [])
        if not vulnerable_packages:
            # Try alternate attributes
            vulnerable_packages = getattr(dep_result, "vulnerabilities", []) or []

        # Parse source code imports once
        source_imports = _extract_imports(source_code) if source_code else {}

        for pkg_vuln in vulnerable_packages:
            pkg_name = getattr(pkg_vuln, "package_name", "") or \
                       getattr(pkg_vuln, "name", "")
            installed_version = getattr(pkg_vuln, "installed_version", "") or \
                                getattr(pkg_vuln, "version", "")

            # Get CVEs for this package
            cve_list = getattr(pkg_vuln, "cve_records", []) or \
                       getattr(pkg_vuln, "vulnerabilities", []) or []

            if not cve_list:
                # Package has vulns but listed differently — use vuln object itself
                cve_list = [pkg_vuln]

            for cve_obj in cve_list:
                cve_id = getattr(cve_obj, "cve_id", "") or \
                         getattr(cve_obj, "id", "")
                severity = getattr(cve_obj, "severity", "UNKNOWN")
                cwe_ids = getattr(cve_obj, "cwe_ids", []) or []

                if not cve_id:
                    continue

                # Determine import module name
                module_name = _PYPI_TO_IMPORT.get(pkg_name.lower(), pkg_name.lower())

                # Determine sink type from CWE
                sink_type = ""
                for cwe in cwe_ids:
                    sink_type = _CWE_TO_SINK.get(cwe, "")
                    if sink_type:
                        break

                result.total_cves_analyzed += 1

                # 1. Check CPG if provided
                cpg_reachable, cpg_score, cpg_path = False, 0.0, []
                if cpg is not None:
                    cpg_reachable, cpg_score, cpg_path = _cpg_reachability(cpg, module_name)

                # 2. Check source code for import + dangerous call patterns
                src_reachable = False
                src_score = 0.0
                vuln_func = ""
                src_sink = sink_type
                evidence: List[str] = []

                if source_code:
                    is_imported = module_name in source_imports or \
                                  pkg_name.lower() in source_code.lower() or \
                                  module_name.lower() in source_code.lower()

                    if is_imported:
                        calls = _find_calls_to_package(source_code, module_name)
                        if calls:
                            src_score, vuln_func, detected_sink = _score_sink_reachability(calls, module_name)
                            if detected_sink:
                                src_sink = detected_sink
                            src_reachable = src_score >= 0.4
                            evidence = [f"{module_name}.{fn}()" for fn, _ in calls[:5]]

                # Combine signals
                is_reachable = cpg_reachable or src_reachable
                final_score = max(cpg_score, src_score)
                call_path = cpg_path or ([f"{module_name}.{vuln_func}()"] if vuln_func else [])

                justification = (
                    f"Module '{module_name}' is imported and '{vuln_func}' is called in application code."
                    if is_reachable and vuln_func else
                    f"Module '{module_name}' is imported but no dangerous API calls detected."
                    if src_reachable else
                    f"Module '{module_name}' does not appear to be used in the analyzed source code."
                )

                rc = ReachableCVE(
                    cve_id=cve_id,
                    package_name=pkg_name,
                    installed_version=installed_version,
                    severity=severity,
                    is_reachable=is_reachable,
                    reachability_score=round(final_score, 4),
                    call_path=call_path,
                    vulnerable_function=vuln_func,
                    sink_type=src_sink or sink_type,
                    justification=justification,
                    evidence=evidence,
                )

                if is_reachable:
                    result.reachable_cves.append(rc)
                    result.total_reachable += 1
                else:
                    result.not_reachable_cves.append(rc)
                    result.total_not_reachable += 1

        return result

    def is_package_reachable(
        self,
        package_name: str,
        cpg: Any,
        source_code: str = "",
    ) -> Tuple[bool, float, List[str]]:
        """Check if a specific package is reachable in the CPG or source code.

        Returns (is_reachable, score, call_path).
        """
        module_name = _PYPI_TO_IMPORT.get(package_name.lower(), package_name.lower())

        cpg_reach, cpg_score, cpg_path = _cpg_reachability(cpg, module_name)
        if cpg_reach:
            return True, cpg_score, cpg_path

        if source_code:
            imports = _extract_imports(source_code)
            if module_name in imports or package_name.lower() in source_code.lower():
                calls = _find_calls_to_package(source_code, module_name)
                if calls:
                    score, func, _ = _score_sink_reachability(calls, module_name)
                    return score >= 0.3, score, [f"{module_name}.{func}()"] if func else []
                return True, 0.3, [f"import {module_name}"]

        return False, 0.0, []

    def get_vulnerable_function_paths(
        self,
        package_name: str,
        cpg: Any,
    ) -> List[List[str]]:
        """Return all paths from entry points to *package_name* dangerous functions."""
        module_name = _PYPI_TO_IMPORT.get(package_name.lower(), package_name.lower())
        paths: List[List[str]] = []

        try:
            nodes = cpg.nodes if isinstance(cpg.nodes, dict) else {}
            for nid, node in nodes.items():
                props = getattr(node, "properties", {}) or {}
                label = getattr(node, "label", "") or ""
                code = props.get("code", "") or label
                if module_name.lower() in code.lower() and props.get("is_taint_source", False):
                    path = _bfs_path_to_sink(cpg, nid)
                    if path:
                        paths.append(path)
        except Exception as exc:
            logger.debug("get_vulnerable_function_paths failed: %s", exc)

        return paths
