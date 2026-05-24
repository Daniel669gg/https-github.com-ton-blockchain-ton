"""
Ghost Security Platform — Dependency Reachability Analyzer
Устраняет ~70% шума: CVE в зависимости НЕ считается опасным,
если уязвимая функция не импортируется и не вызывается в коде проекта.

Алгоритм:
  1. Парсим зависимости + их CVE (уже есть в dep_scanner)
  2. Для каждого CVE знаем уязвимую функцию/модуль (из базы)
  3. Проверяем реальные import/from/call в исходниках проекта
  4. Если уязвимый путь не достигается → severity DOWNGRADE → "DEP_UNREACHABLE"
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ── База: пакет → уязвимые символы ───────────────────────────────────────────
# Формат: "package" → [(cve_id, [module.symbol, ...], description)]
# Если символы пустые — уязвимость на уровне импорта самого пакета
_VULN_SYMBOLS: Dict[str, List[Tuple[str, List[str], str]]] = {
    "pyyaml": [
        ("CVE-2020-14343", ["yaml.load", "yaml.full_load", "yaml.unsafe_load"],
         "RCE via yaml.load() with untrusted input — safe only if Loader=yaml.SafeLoader"),
    ],
    "requests": [
        ("CVE-2023-32681", ["requests.get", "requests.post", "requests.request", "requests.Session"],
         "Sensitive headers leaked on redirect — affects all requests with auth headers"),
    ],
    "urllib3": [
        ("CVE-2024-37891", ["urllib3.request", "urllib3.PoolManager", "urllib3.HTTPConnectionPool"],
         "Proxy-Authorization not stripped on cross-origin redirect"),
    ],
    "pillow": [
        ("CVE-2023-50447", ["PIL.Image.open", "Image.open"],
         "Arbitrary code execution via crafted image file"),
        ("CVE-2023-44271", ["PIL.ImageFont.truetype", "ImageFont.truetype"],
         "Uncontrolled memory consumption via crafted font"),
    ],
    "cryptography": [
        ("CVE-2024-26130", ["cryptography.hazmat.primitives.serialization.pkcs12.load_pkcs12",
                            "load_pkcs12"],
         "NULL pointer dereference in PKCS12 parsing"),
    ],
    "lxml": [
        ("CVE-2022-2309", ["lxml.etree.parse", "lxml.etree.fromstring", "etree.parse"],
         "NULL pointer dereference via malformed XML"),
    ],
    "jinja2": [
        ("CVE-2024-34064", ["jinja2.Markup", "Markup", "jinja2.filters.xmlattr"],
         "XSS via xmlattr filter — only if xmlattr filter used in templates"),
    ],
    "paramiko": [
        ("CVE-2023-48795", ["paramiko.Transport", "paramiko.SSHClient"],
         "Terrapin SSH prefix truncation attack — affects all SSH connections"),
    ],
    "celery": [
        ("CVE-2021-23727", ["celery.app.task", "celery.Task", "@app.task", "@shared_task"],
         "Code injection via task header — only if accepting tasks from untrusted sources"),
    ],
    "jsonwebtoken": [
        ("CVE-2022-23529", ["jwt.verify", "jsonwebtoken.verify"],
         "RCE via secretOrPublicKey — only if secretOrPublicKey accepts objects"),
        ("CVE-2022-23541", ["jwt.verify", "jsonwebtoken.decode"],
         "Algorithm confusion — only if algorithm not pinned in verify()"),
    ],
    "lodash": [
        ("CVE-2021-23337", ["_.template", "lodash.template"],
         "Command injection via template — only if _.template() used with user input"),
    ],
    "axios": [
        ("CVE-2023-45857", ["axios.get", "axios.post", "axios.request", "axios.create"],
         "CSRF token leak — affects all axios requests with xsrfCookieName set"),
    ],
    "mysql2": [
        ("CVE-2024-21508", ["mysql2.createConnection", "mysql2.createPool", "createConnection"],
         "RCE via object parameter — only if query parameters can be objects"),
    ],
    "tough-cookie": [
        ("CVE-2023-26136", ["tough-cookie.CookieJar", "CookieJar", "tough_cookie"],
         "Prototype pollution — affects all CookieJar usage"),
    ],
    "next": [
        ("CVE-2024-34351", ["next/server", "NextResponse", "NextRequest"],
         "SSRF via Host header — affects Next.js API routes using server actions"),
        ("CVE-2024-46982", [], "Cache poisoning RCE — affects all Next.js deployments"),
    ],
    "werkzeug": [
        ("CVE-2024-34069", ["werkzeug.debug.DebuggedApplication", "DebuggedApplication"],
         "RCE via debugger PIN — only if debug mode enabled in production"),
    ],
    "setuptools": [
        ("CVE-2024-6345", ["setuptools.package_index", "PackageIndex"],
         "RCE via malicious package URL — only if installing packages at runtime"),
    ],
    "twisted": [
        ("CVE-2024-41671", ["twisted.web", "twisted.protocols.http"],
         "Request smuggling — affects all Twisted HTTP servers"),
    ],
    "gunicorn": [
        ("CVE-2024-1135", [],
         "HTTP request smuggling — affects all Gunicorn HTTP deployments"),
    ],
    "waitress": [
        ("CVE-2024-49768", [],
         "Request smuggling — affects all Waitress deployments"),
    ],
    "fastapi": [
        ("CVE-2024-24762", ["fastapi.UploadFile", "File(", "Form("],
         "DoS via multipart/form-data — only if file upload endpoints exist"),
    ],
    "aiohttp": [
        ("CVE-2024-23334", ["aiohttp.web.static", "app.router.add_static"],
         "Path traversal — only if serving static files via aiohttp"),
    ],
    "httpx": [
        ("CVE-2021-41945", ["httpx.get", "httpx.post", "httpx.Client", "httpx.AsyncClient"],
         "CRLF injection via crafted URL — affects all httpx requests"),
    ],
    "semver": [
        ("CVE-2022-25883", ["semver.satisfies", "semver.validRange"],
         "ReDoS — only if processing user-supplied version strings"),
    ],
    "moment": [
        ("CVE-2022-31129", ["moment(", "moment.utc(", "moment.parseZone("],
         "ReDoS — only if parsing user-supplied date strings"),
    ],
    "braces": [
        ("CVE-2024-4068", ["braces(", "braces.expand"],
         "ReDoS — only if expanding user-supplied glob patterns"),
    ],
    "protobufjs": [
        ("CVE-2023-36665", ["protobuf.load", "protobuf.parse", "Root.fromJSON"],
         "Prototype pollution via JSON — only if loading user-controlled protobuf schemas"),
    ],
}


@dataclass
class ReachabilityResult:
    package:     str
    cve_id:      str
    reachable:   bool
    reason:      str
    evidence:    List[str]  = field(default_factory=list)  # строки кода где найдено
    files:       List[str]  = field(default_factory=list)
    original_sev: str       = "HIGH"
    effective_sev: str      = "HIGH"

    def to_dict(self) -> dict:
        return {
            "package":      self.package,
            "cve_id":       self.cve_id,
            "reachable":    self.reachable,
            "reason":       self.reason,
            "evidence":     self.evidence[:5],
            "files":        self.files,
            "original_sev": self.original_sev,
            "effective_sev":self.effective_sev,
            "downgraded":   not self.reachable,
        }


class ReachabilityAnalyzer:
    """
    Определяет, реально ли достигается уязвимая функция зависимости
    из кода проекта.

    Использование:
        analyzer = ReachabilityAnalyzer("/path/to/project")
        results  = analyzer.analyze(dep_findings)
        filtered = analyzer.filter_unreachable(dep_findings)
    """

    _SRC_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}

    def __init__(self, project_root: str) -> None:
        self.root = Path(project_root)
        self._import_cache: Optional[Set[str]] = None
        self._call_cache:   Optional[Set[str]] = None
        self._src_lines:    Optional[List[str]] = None

    # ── Публичный API ─────────────────────────────────────────────────────────

    def analyze(self, dep_findings: List[dict]) -> List[ReachabilityResult]:
        """Анализирует список dep findings. Возвращает ReachabilityResult для каждого CVE."""
        self._build_cache()
        results: List[ReachabilityResult] = []

        for finding in dep_findings:
            pkg = (finding.get("package") or finding.get("name") or "").lower()
            cve = finding.get("cve_id") or finding.get("cve") or ""
            sev = (finding.get("severity") or "HIGH").upper()

            result = self._check_package(pkg, cve, sev)
            results.append(result)

        return results

    def filter_unreachable(self, dep_findings: List[dict]) -> Tuple[List[dict], List[dict]]:
        """
        Разделяет findings на реальные угрозы и недостижимые.
        Returns: (reachable_findings, unreachable_findings)
        Unreachable findings сохраняются, но severity даунгрейдится.
        """
        results = self.analyze(dep_findings)
        reachable:   List[dict] = []
        unreachable: List[dict] = []

        for finding, result in zip(dep_findings, results):
            f = dict(finding)
            if result.reachable:
                f["reachability"] = "REACHABLE"
                f["reachability_evidence"] = result.evidence[:3]
                reachable.append(f)
            else:
                f["reachability"]       = "UNREACHABLE"
                f["reachability_reason"] = result.reason
                # Даунгрейд severity
                original_sev = f.get("severity", "HIGH").upper()
                f["original_severity"]  = original_sev
                f["severity"]           = self._downgrade(original_sev)
                f["message"] = (
                    f.get("message") or f.get("cve_id") or ""
                ) + f" [NOT REACHABLE: {result.reason}]"
                unreachable.append(f)

        return reachable, unreachable

    def stats(self, dep_findings: List[dict]) -> dict:
        """Краткая статистика по reachability."""
        reachable, unreachable = self.filter_unreachable(dep_findings)
        return {
            "total":         len(dep_findings),
            "reachable":     len(reachable),
            "unreachable":   len(unreachable),
            "noise_reduced": f"{len(unreachable)/max(len(dep_findings),1)*100:.0f}%",
            "packages_used": len({
                f.get("package") or f.get("name") for f in reachable
            }),
        }

    # ── Кэш исходников ────────────────────────────────────────────────────────

    def _build_cache(self) -> None:
        if self._import_cache is not None:
            return

        imports: Set[str] = set()
        calls:   Set[str] = set()
        lines:   List[str] = []

        skip = {".git", "__pycache__", "node_modules", ".venv", "venv",
                "dist", "build", ".eggs"}

        for fpath in self.root.rglob("*"):
            if not fpath.is_file():
                continue
            if any(p in fpath.parts for p in skip):
                continue
            if fpath.suffix not in self._SRC_EXTS:
                continue
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            lines.extend(text.splitlines())

            if fpath.suffix == ".py":
                self._extract_python(text, imports, calls)
            else:
                self._extract_js(text, imports, calls)

        self._import_cache = imports
        self._call_cache   = calls
        self._src_lines    = lines

    @staticmethod
    def _extract_python(text: str, imports: Set[str], calls: Set[str]) -> None:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            # import yaml / import pyyaml
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0].lower())
                    imports.add(alias.name.lower())
            # from PIL import Image
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split(".")[0].lower())
                    imports.add(node.module.lower())
                for alias in node.names:
                    calls.add(alias.name.lower())
            # yaml.load(...)
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    calls.add(f"{node.func.value.id if isinstance(node.func.value, ast.Name) else ''}.{node.func.attr}".strip(".").lower())
                    calls.add(node.func.attr.lower())
                elif isinstance(node.func, ast.Name):
                    calls.add(node.func.id.lower())

    @staticmethod
    def _extract_js(text: str, imports: Set[str], calls: Set[str]) -> None:
        # require('pkg')
        for m in re.finditer(r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)""", text):
            pkg = m.group(1).split("/")[0].lstrip("@").lower()
            imports.add(pkg)

        # import ... from 'pkg'
        for m in re.finditer(r"""from\s+['"]([^'"]+)['"]""", text):
            pkg = m.group(1).split("/")[0].lstrip("@").lower()
            imports.add(pkg)

        # import 'pkg'
        for m in re.finditer(r"""import\s+['"]([^'"]+)['"]""", text):
            pkg = m.group(1).split("/")[0].lstrip("@").lower()
            imports.add(pkg)

        # function calls: foo.bar(
        for m in re.finditer(r"([\w$]+)(?:\.([\w$]+))?\s*\(", text):
            calls.add(m.group(1).lower())
            if m.group(2):
                calls.add(f"{m.group(1)}.{m.group(2)}".lower())

    # ── Проверка достижимости ─────────────────────────────────────────────────

    def _check_package(self, pkg: str, cve: str, sev: str) -> ReachabilityResult:
        # 1. Пакет вообще импортируется?
        pkg_key  = pkg.replace("-", "_").lower()
        # resolve pip-name → actual import names
        import_names = [pkg_key, pkg.lower()] + _PIP_TO_IMPORT.get(pkg_key, _PIP_TO_IMPORT.get(pkg.lower(), []))
        imported = any(
            name in self._import_cache or
            any(name in imp for imp in self._import_cache)
            for name in import_names
        )

        if not imported:
            return ReachabilityResult(
                package=pkg, cve_id=cve, reachable=False,
                reason="package not imported in project code",
                original_sev=sev, effective_sev=self._downgrade(sev),
            )

        # 2. Есть ли запись в базе уязвимых символов?
        vuln_entries = _VULN_SYMBOLS.get(pkg_key, _VULN_SYMBOLS.get(pkg.lower(), []))
        entry = next((e for e in vuln_entries if e[0] == cve), None)

        if entry is None:
            # Неизвестный CVE — пакет импортирован, считаем reachable
            return ReachabilityResult(
                package=pkg, cve_id=cve, reachable=True,
                reason="package imported; no symbol-level data for this CVE",
                original_sev=sev, effective_sev=sev,
            )

        _, symbols, desc = entry

        # 3. Нет конкретных символов — достаточно самого импорта
        if not symbols:
            return ReachabilityResult(
                package=pkg, cve_id=cve, reachable=True,
                reason=desc,
                evidence=[f"import {pkg}"],
                original_sev=sev, effective_sev=sev,
            )

        # 4. Ищем уязвимые символы в коде
        evidence = []
        files    = []
        for sym in symbols:
            sym_lower = sym.lower().replace("-", "_")
            # Проверяем по кэшу вызовов
            if sym_lower in self._call_cache:
                evidence.append(f"call: {sym}")
            # Grep по строкам исходников
            for i, line in enumerate(self._src_lines or []):
                if sym_lower in line.lower():
                    evidence.append(f"line {i+1}: {line.strip()[:80]}")
                    break

        if evidence:
            return ReachabilityResult(
                package=pkg, cve_id=cve, reachable=True,
                reason=desc,
                evidence=evidence[:5],
                original_sev=sev, effective_sev=sev,
            )

        return ReachabilityResult(
            package=pkg, cve_id=cve, reachable=False,
            reason=f"vulnerable symbol(s) not called: {', '.join(symbols[:3])}",
            original_sev=sev, effective_sev=self._downgrade(sev),
        )

    @staticmethod
    def _downgrade(sev: str) -> str:
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        idx   = order.index(sev) if sev in order else 2
        return order[max(0, idx - 1)]

# ── pip name → import name mapping ────────────────────────────────────────────
_PIP_TO_IMPORT: Dict[str, List[str]] = {
    "pyyaml":          ["yaml"],
    "pillow":          ["PIL", "pil"],
    "beautifulsoup4":  ["bs4"],
    "scikit-learn":    ["sklearn"],
    "scikit_learn":    ["sklearn"],
    "opencv-python":   ["cv2"],
    "python-dateutil": ["dateutil"],
    "google-auth":     ["google.auth", "google_auth"],
    "sqlalchemy":      ["sqlalchemy", "flask_sqlalchemy"],
    "mysqlclient":     ["MySQLdb"],
    "psycopg2":        ["psycopg2"],
    "pycryptodome":    ["Crypto"],
    "jsonwebtoken":    ["jwt"],
    "path-to-regexp":  ["pathToRegexp", "path_to_regexp"],
    "tough-cookie":    ["tough_cookie", "toughCookie"],
    "node-fetch":      ["node_fetch", "nodeFetch"],
    "cross-fetch":     ["cross_fetch", "crossFetch"],
}
