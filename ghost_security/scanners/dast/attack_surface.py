"""
TythanAI DAST — Attack Surface Mapper

Builds a complete attack surface map from two sources:
  1. Static analysis of source code (Flask/Django/FastAPI route decorators, AST)
  2. Live HTTP crawling (link extraction from HTML responses)

Output: AttackSurface with Endpoint inventory — each endpoint has:
  - URL, method, handler name, file + line, auth_required flag,
    parameters, accepts_user_input, potential_risk_level
"""
from __future__ import annotations

import ast
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class Endpoint:
    url:             str            # full URL or path template
    path:            str            # path without base URL
    method:          str            # HTTP method (GET/POST/etc.)
    handler:         str            # function name that handles it
    source_file:     str = ""       # source file where route is defined
    source_line:     int = 0
    auth_required:   Optional[bool] = None  # None = unknown
    parameters:      List[str] = field(default_factory=list)
    accepts_body:    bool = False
    risk_level:      str = "UNKNOWN"  # CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
    discovery_method: str = "static"  # static | crawl | spec


@dataclass
class AttackSurface:
    base_url:       str
    endpoints:      List[Endpoint]
    total_endpoints: int
    public_endpoints: int           # auth_required == False
    admin_endpoints: int
    high_risk_endpoints: int
    discovery_sources: List[str]    # ["static", "crawl", "spec"]


# ── Route pattern detection ───────────────────────────────────────────────────

# Flask patterns
_FLASK_ROUTE  = re.compile(
    r'@(?:\w+\.)?(?:app|blueprint|bp|api)\.route\(\s*["\']([^"\']+)["\'][^)]*\)',
)
_FLASK_METHOD = re.compile(r'methods\s*=\s*\[([^\]]+)\]')
# FastAPI patterns
_FASTAPI_ROUTE = re.compile(
    r'@(?:\w+\.)?(?:router|app)\.(get|post|put|patch|delete|head|options)'
    r'\(\s*["\']([^"\']+)["\']',
)
# Django urlpatterns
_DJANGO_PATH = re.compile(
    r'(?:path|re_path|url)\(\s*["\']([^"\']+)["\']'
    r'\s*,\s*(\w+(?:\.\w+)*)\s*(?:,|\))',
)

_AUTH_DECORATORS = re.compile(
    r'@\s*(?:login_required|require_auth|authenticate|jwt_required|'
    r'token_required|permission_required|staff_member_required)',
)
_ADMIN_PATHS = re.compile(
    r'/(admin|internal|management|config|debug|actuator|metrics|'
    r'health|system|console|api/admin)',
    re.I,
)
_SENSITIVE_PARAMS = re.compile(
    r'(?:id|user_?id|account|file|path|url|redirect|target|cmd|exec|query)',
    re.I,
)
_LINK_HREF = re.compile(r'href=["\']([^"\']+)["\']', re.I)
_LINK_SRC  = re.compile(r'src=["\']([^"\']+)["\']', re.I)
_LINK_ACTION = re.compile(r'action=["\']([^"\']+)["\']', re.I)


def _risk_level(path: str, method: str, auth_required: Optional[bool],
                params: List[str]) -> str:
    if _ADMIN_PATHS.search(path):
        return "CRITICAL" if auth_required is False else "HIGH"
    if method in ("DELETE", "PUT", "PATCH"):
        return "HIGH" if auth_required is False else "MEDIUM"
    if any(_SENSITIVE_PARAMS.search(p) for p in params):
        return "MEDIUM"
    if method == "POST":
        return "MEDIUM" if auth_required is False else "LOW"
    return "LOW"


# ── Static route extractor ────────────────────────────────────────────────────

class _StaticRouteExtractor:
    """Extract route definitions from Python source files via AST and regex."""

    def extract(self, project_root: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        for py_file in Path(project_root).rglob("*.py"):
            if any(skip in py_file.parts
                   for skip in ("__pycache__", ".venv", "venv",
                                "node_modules", ".git", "test")):
                continue
            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            endpoints += self._extract_from_source(source, str(py_file))
        return endpoints

    def _extract_from_source(self, source: str,
                              filepath: str) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        lines = source.splitlines()

        # Flask routes via regex (handles multiline decorators)
        for lineno, line in enumerate(lines, 1):
            m = _FLASK_ROUTE.search(line)
            if m:
                path = m.group(1)
                methods_m = _FLASK_METHOD.search(line)
                methods = (
                    [x.strip().strip("'\"").upper()
                     for x in methods_m.group(1).split(",")]
                    if methods_m else ["GET"]
                )
                # Look ahead for function name and auth decorator
                handler, auth_req, params = self._look_ahead(
                    lines, lineno - 1, path
                )
                for method in methods:
                    endpoints.append(Endpoint(
                        url=path, path=path, method=method,
                        handler=handler, source_file=filepath,
                        source_line=lineno, auth_required=auth_req,
                        parameters=params, accepts_body=(method in ("POST", "PUT", "PATCH")),
                        risk_level=_risk_level(path, method, auth_req, params),
                        discovery_method="static",
                    ))

            # FastAPI routes
            fa = _FASTAPI_ROUTE.search(line)
            if fa:
                method, path = fa.group(1).upper(), fa.group(2)
                handler, auth_req, params = self._look_ahead(
                    lines, lineno - 1, path
                )
                endpoints.append(Endpoint(
                    url=path, path=path, method=method,
                    handler=handler, source_file=filepath,
                    source_line=lineno, auth_required=auth_req,
                    parameters=params, accepts_body=(method in ("POST", "PUT", "PATCH")),
                    risk_level=_risk_level(path, method, auth_req, params),
                    discovery_method="static",
                ))

        # Django urlpatterns via AST
        try:
            tree = ast.parse(source, filename=filepath)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign):
                    continue
                if not any(isinstance(t, ast.Name) and t.id == "urlpatterns"
                           for t in node.targets):
                    continue
                if not isinstance(node.value, ast.List):
                    continue
                for elt in node.value.elts:
                    if not isinstance(elt, ast.Call):
                        continue
                    if not elt.args:
                        continue
                    first = elt.args[0]
                    path_val = (
                        first.s if isinstance(first, ast.Constant) else
                        first.value if hasattr(first, "value") else ""
                    )
                    if not path_val:
                        continue
                    path_str = "/" + path_val.lstrip("/")
                    handler_name = ""
                    if len(elt.args) >= 2:
                        a = elt.args[1]
                        if isinstance(a, ast.Attribute):
                            handler_name = a.attr
                        elif isinstance(a, ast.Name):
                            handler_name = a.id
                    endpoints.append(Endpoint(
                        url=path_str, path=path_str, method="GET",
                        handler=handler_name, source_file=filepath,
                        source_line=node.lineno,
                        risk_level=_risk_level(path_str, "GET", None, []),
                        discovery_method="static",
                    ))
        except SyntaxError:
            pass

        return endpoints

    @staticmethod
    def _look_ahead(lines: List[str], start_lineno: int,
                    path: str) -> Tuple[str, Optional[bool], List[str]]:
        """
        Scan lines after a route decorator to find:
          - function name (def ...)
          - auth decorator (@login_required etc.)
          - path parameters ({param} or <param>)
        Returns (handler_name, auth_required, params).
        """
        handler   = ""
        auth_req: Optional[bool] = None
        params    = re.findall(r"\{(\w+)\}|<(?:[a-z:]+:)?(\w+)>", path)
        flat_params = [p[0] or p[1] for p in params]

        for i in range(start_lineno, min(start_lineno + 6, len(lines))):
            line = lines[i].strip()
            if _AUTH_DECORATORS.search(line):
                auth_req = True
            m = re.match(r"async\s+def\s+(\w+)|def\s+(\w+)", line)
            if m:
                handler = m.group(1) or m.group(2)
                # scan function signature for extra params
                sig_m = re.search(r"def\s+\w+\s*\(([^)]+)\)", line)
                if sig_m:
                    for arg in sig_m.group(1).split(","):
                        arg = arg.strip().split(":")[0].split("=")[0].strip()
                        if arg and arg not in ("self", "request", "req", "cls"):
                            if _SENSITIVE_PARAMS.search(arg):
                                flat_params.append(arg)
                break

        return handler, auth_req, flat_params


# ── Live crawler ──────────────────────────────────────────────────────────────

class _LiveCrawler:
    """
    Crawl a live application to discover endpoints via link extraction.
    Only follows links within the same host.
    """

    def __init__(self, base_url: str, max_urls: int = 100, timeout: int = 8):
        self._base    = base_url.rstrip("/")
        self._max     = max_urls
        self._timeout = timeout
        parsed        = urllib.parse.urlparse(base_url)
        self._host    = parsed.netloc

    def crawl(self) -> List[Endpoint]:
        visited: Set[str] = set()
        queue:   List[str] = [self._base + "/"]
        found:   List[Endpoint] = []

        while queue and len(visited) < self._max:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)

            try:
                result = self._fetch(url)
                if result is None:
                    continue
                status, body_text = result

                path = urllib.parse.urlparse(url).path or "/"
                method = "GET"
                found.append(Endpoint(
                    url=url, path=path, method=method,
                    handler="", source_file="",
                    risk_level=_risk_level(path, method, None, []),
                    discovery_method="crawl",
                ))

                for new_url in self._extract_links(url, body_text):
                    if new_url not in visited:
                        queue.append(new_url)

            except Exception:
                continue

        # Detect forms → POST endpoints
        for url in list(visited)[:20]:
            try:
                result = self._fetch(url)
                if result is None:
                    continue
                _, body_text = result
                for action in _LINK_ACTION.findall(body_text):
                    action_url = self._resolve(url, action)
                    if action_url:
                        path = urllib.parse.urlparse(action_url).path or "/"
                        found.append(Endpoint(
                            url=action_url, path=path, method="POST",
                            handler="", source_file="",
                            accepts_body=True,
                            risk_level=_risk_level(path, "POST", None, []),
                            discovery_method="crawl",
                        ))
            except Exception:
                continue

        return found

    def _fetch(self, url: str) -> Optional[Tuple[int, str]]:
        try:
            context: Optional[ssl.SSLContext] = None
            if url.startswith("https"):
                context = ssl.create_default_context()
            req = urllib.request.Request(
                url, headers={"User-Agent": "TythanAI-SecurityScanner/6.5",
                              "Accept": "text/html,*/*"},
            )
            with urllib.request.urlopen(req, timeout=self._timeout,
                                        context=context) as r:  # type: ignore[arg-type]
                body = r.read(65536).decode("utf-8", errors="replace")
                return r.status, body
        except urllib.error.HTTPError as e:
            body = e.read(4096).decode("utf-8", errors="replace")
            return e.code, body
        except Exception:
            return None

    def _extract_links(self, base: str, html: str) -> List[str]:
        links: List[str] = []
        for pattern in (_LINK_HREF, _LINK_SRC):
            for href in pattern.findall(html):
                resolved = self._resolve(base, href)
                if resolved:
                    links.append(resolved)
        return links

    def _resolve(self, base: str, href: str) -> Optional[str]:
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            return None
        resolved = urllib.parse.urljoin(base, href)
        parsed   = urllib.parse.urlparse(resolved)
        if parsed.netloc != self._host:
            return None
        # Drop query and fragment to avoid crawling the same page many times
        clean = urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, "", "", "")
        )
        return clean


# ── AttackSurfaceMapper ───────────────────────────────────────────────────────

class AttackSurfaceMapper:
    """
    Orchestrates attack surface discovery using:
      - Static route extraction from project source
      - Live crawling of running application
      - OpenAPI spec endpoint enumeration
    """

    def __init__(self, base_url: str = "", project_root: str = "",
                 openapi_spec: Optional[dict] = None,
                 crawl_live: bool = False,
                 max_crawl_urls: int = 100):
        self._base_url    = base_url
        self._project_root = project_root
        self._spec         = openapi_spec
        self._crawl_live   = crawl_live
        self._max_crawl    = max_crawl_urls

    def map(self) -> AttackSurface:
        endpoints: List[Endpoint] = []
        sources:   List[str]      = []

        # 1. Static analysis of source code
        if self._project_root:
            extractor = _StaticRouteExtractor()
            static_eps = extractor.extract(self._project_root)
            # Attach base_url if provided
            if self._base_url:
                for ep in static_eps:
                    ep.url = self._base_url.rstrip("/") + ep.path
            endpoints += static_eps
            if static_eps:
                sources.append("static")

        # 2. OpenAPI spec endpoints
        if self._spec:
            spec_eps = self._from_spec(self._spec)
            endpoints += spec_eps
            if spec_eps:
                sources.append("spec")

        # 3. Live crawl
        if self._crawl_live and self._base_url:
            crawler  = _LiveCrawler(self._base_url, self._max_crawl)
            live_eps = crawler.crawl()
            endpoints += live_eps
            if live_eps:
                sources.append("crawl")

        # Deduplicate by (method, path)
        seen: Set[Tuple[str, str]] = set()
        unique: List[Endpoint]     = []
        for ep in endpoints:
            key = (ep.method, ep.path)
            if key not in seen:
                seen.add(key)
                unique.append(ep)

        public_count = sum(1 for e in unique if e.auth_required is False)
        admin_count  = sum(1 for e in unique if _ADMIN_PATHS.search(e.path))
        high_risk    = sum(1 for e in unique
                          if e.risk_level in ("CRITICAL", "HIGH"))

        return AttackSurface(
            base_url=self._base_url,
            endpoints=unique,
            total_endpoints=len(unique),
            public_endpoints=public_count,
            admin_endpoints=admin_count,
            high_risk_endpoints=high_risk,
            discovery_sources=sources,
        )

    def _from_spec(self, spec: dict) -> List[Endpoint]:
        endpoints: List[Endpoint] = []
        base = self._base_url.rstrip("/") if self._base_url else ""
        for path, path_item in spec.get("paths", {}).items():
            if not isinstance(path_item, dict):
                continue
            for method in ("get", "post", "put", "patch", "delete",
                           "head", "options"):
                op = path_item.get(method)
                if not isinstance(op, dict):
                    continue
                params = [
                    p.get("name", "") for p in op.get("parameters", [])
                    if isinstance(p, dict)
                ]
                has_security = bool(op.get("security")) or bool(spec.get("security"))
                full_url = base + path
                endpoints.append(Endpoint(
                    url=full_url,
                    path=path,
                    method=method.upper(),
                    handler=op.get("operationId", ""),
                    auth_required=has_security if has_security else None,
                    parameters=params,
                    accepts_body=(method in ("post", "put", "patch")),
                    risk_level=_risk_level(path, method.upper(),
                                           has_security if has_security else None,
                                           params),
                    discovery_method="spec",
                ))
        return endpoints

    def to_attack_graph_nodes(self, surface: AttackSurface) -> List[dict]:
        """
        Convert AttackSurface to node dicts compatible with AttackGraphBuilder.
        Each endpoint becomes a SOURCE node with properties.
        """
        nodes: List[dict] = []
        for ep in surface.endpoints:
            nodes.append({
                "node_type":      "ENDPOINT",
                "id":             f"ep:{ep.method}:{ep.path}",
                "label":          f"{ep.method} {ep.path}",
                "url":            ep.url,
                "path":           ep.path,
                "method":         ep.method,
                "handler":        ep.handler,
                "source_file":    ep.source_file,
                "source_line":    ep.source_line,
                "auth_required":  ep.auth_required,
                "risk_level":     ep.risk_level,
                "discovery":      ep.discovery_method,
            })
        return nodes
