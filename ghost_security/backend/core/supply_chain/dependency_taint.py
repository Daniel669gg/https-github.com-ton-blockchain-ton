"""
backend/core/supply_chain/dependency_taint.py — Dependency-level taint analysis.

Extends existing supply_chain.py scanner with:
1. Manifest parsing (requirements.txt, pyproject.toml, package.json, Pipfile, go.mod)
2. Known vulnerable package database (OWASP + major CVEs, embedded — no network)
3. Taint source generation: vulnerable package import → CPG taint source node
4. Import-to-usage tracking: find where vulnerable packages are used in code
5. Integration with CPG: add taint source nodes for vulnerable imports

Does NOT recreate SupplyChainScanner — imports it and extends it.
"""
from __future__ import annotations

import json
import logging
import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Import existing scanners (extend, not recreate)
from backend.scanners.supply_chain import (
    SupplyChainScanner as _BaseSupplyChainScanner,
    _parse_requirements_txt,
    _parse_package_json,
    _package_imported,
)

# CPG integration
from backend.core.cpg.graph import (
    CodePropertyGraph,
    CPGNode,
    CPGNodeType,
    CPGEdge,
    CPGEdgeType,
)

# Finding model
from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.supply_chain.taint")


# ---------------------------------------------------------------------------
# PART 1: Known Vulnerable Package Database (embedded, no network)
# ---------------------------------------------------------------------------

@dataclass
class VulnerablePackage:
    """Describes a known-vulnerable package version range."""
    name: str
    ecosystem: str                  # "pypi", "npm", "go", "cargo"
    vulnerable_range: str           # e.g. ">=1.0,<1.5.3" or "<2.1.0"
    fixed_version: str              # first safe version
    cve_ids: List[str]
    cwe_ids: List[str]
    severity: str                   # CRITICAL/HIGH/MEDIUM/LOW
    cvss_v3: float
    description: str
    exploit_available: bool
    affected_functions: List[str]   # specific vulnerable functions, if known


# fmt: off
KNOWN_VULNERABLE_PACKAGES: Dict[str, List[VulnerablePackage]] = {

    # ── PyPI ──────────────────────────────────────────────────────────────────

    "requests": [
        VulnerablePackage(
            name="requests",
            ecosystem="pypi",
            vulnerable_range="<2.20.0",
            fixed_version="2.20.0",
            cve_ids=["CVE-2018-18074"],
            cwe_ids=["CWE-601"],
            severity="HIGH",
            cvss_v3=6.1,
            description=(
                "requests < 2.20.0 sends HTTP Authorization header on redirects to "
                "different hosts, enabling SSRF-assisted credential theft."
            ),
            exploit_available=True,
            affected_functions=["requests.get", "requests.post", "requests.Session.send"],
        ),
    ],

    "urllib3": [
        VulnerablePackage(
            name="urllib3",
            ecosystem="pypi",
            vulnerable_range="<1.24.2",
            fixed_version="1.24.2",
            cve_ids=["CVE-2019-11324"],
            cwe_ids=["CWE-113"],
            severity="HIGH",
            cvss_v3=7.5,
            description=(
                "urllib3 < 1.24.2 does not validate HTTPS certificates when connecting "
                "to HTTPS URLs via CONNECT proxies, allowing CRLF injection."
            ),
            exploit_available=True,
            affected_functions=["urllib3.PoolManager.urlopen", "urllib3.ProxyManager.urlopen"],
        ),
    ],

    "django": [
        VulnerablePackage(
            name="django",
            ecosystem="pypi",
            vulnerable_range=">=2.0,<2.2.28",
            fixed_version="2.2.28",
            cve_ids=["CVE-2022-28346"],
            cwe_ids=["CWE-89"],
            severity="CRITICAL",
            cvss_v3=9.8,
            description=(
                "Django < 2.2.28, < 3.2.13, < 4.0.4 has a SQL injection vulnerability "
                "in QuerySet.annotate(), aggregate(), and extra() via crafted column aliases."
            ),
            exploit_available=True,
            affected_functions=["QuerySet.annotate", "QuerySet.aggregate", "QuerySet.extra"],
        ),
        VulnerablePackage(
            name="django",
            ecosystem="pypi",
            vulnerable_range=">=3.0,<3.2.13",
            fixed_version="3.2.13",
            cve_ids=["CVE-2022-28346"],
            cwe_ids=["CWE-89"],
            severity="CRITICAL",
            cvss_v3=9.8,
            description=(
                "Django < 3.2.13 SQL injection via QuerySet.annotate(), aggregate(), extra()."
            ),
            exploit_available=True,
            affected_functions=["QuerySet.annotate", "QuerySet.aggregate", "QuerySet.extra"],
        ),
        VulnerablePackage(
            name="django",
            ecosystem="pypi",
            vulnerable_range=">=4.0,<4.0.4",
            fixed_version="4.0.4",
            cve_ids=["CVE-2022-28346"],
            cwe_ids=["CWE-89"],
            severity="CRITICAL",
            cvss_v3=9.8,
            description=(
                "Django < 4.0.4 SQL injection via QuerySet.annotate(), aggregate(), extra()."
            ),
            exploit_available=True,
            affected_functions=["QuerySet.annotate", "QuerySet.aggregate", "QuerySet.extra"],
        ),
    ],

    "flask": [
        VulnerablePackage(
            name="flask",
            ecosystem="pypi",
            vulnerable_range="<1.0",
            fixed_version="1.0",
            cve_ids=["CVE-2018-1000656"],
            cwe_ids=["CWE-22"],
            severity="HIGH",
            cvss_v3=7.5,
            description=(
                "Flask < 1.0 is vulnerable to a path traversal attack through the "
                "send_from_directory() function when used with untrusted user input."
            ),
            exploit_available=True,
            affected_functions=["flask.send_from_directory", "flask.send_file"],
        ),
    ],

    "pyyaml": [
        VulnerablePackage(
            name="pyyaml",
            ecosystem="pypi",
            vulnerable_range="<5.4",
            fixed_version="5.4",
            cve_ids=["CVE-2020-14343"],
            cwe_ids=["CWE-502"],
            severity="CRITICAL",
            cvss_v3=9.8,
            description=(
                "PyYAML < 5.4 allows arbitrary code execution via yaml.load() with "
                "untrusted input when no Loader is specified (defaults to full YAML loader)."
            ),
            exploit_available=True,
            affected_functions=["yaml.load", "yaml.full_load"],
        ),
    ],

    "pillow": [
        VulnerablePackage(
            name="pillow",
            ecosystem="pypi",
            vulnerable_range="<9.0.1",
            fixed_version="9.0.1",
            cve_ids=["CVE-2022-22817"],
            cwe_ids=["CWE-77"],
            severity="CRITICAL",
            cvss_v3=9.8,
            description=(
                "Pillow < 9.0.1 PIL.ImageMath.eval() allows arbitrary code execution "
                "through expression injection."
            ),
            exploit_available=True,
            affected_functions=["PIL.ImageMath.eval", "Image.eval"],
        ),
    ],

    "cryptography": [
        VulnerablePackage(
            name="cryptography",
            ecosystem="pypi",
            vulnerable_range="<41.0.0",
            fixed_version="41.0.0",
            cve_ids=["CVE-2023-49083"],
            cwe_ids=["CWE-476"],
            severity="HIGH",
            cvss_v3=7.5,
            description=(
                "cryptography < 41.0.0 contains a NULL pointer dereference in "
                "PKCS12 parsing that may cause a denial of service via crafted input."
            ),
            exploit_available=False,
            affected_functions=["load_pkcs12", "serialization.pkcs12.load_key_and_certificates"],
        ),
    ],

    "paramiko": [
        VulnerablePackage(
            name="paramiko",
            ecosystem="pypi",
            vulnerable_range="<2.10.1",
            fixed_version="2.10.1",
            cve_ids=["CVE-2022-24302"],
            cwe_ids=["CWE-362"],
            severity="MEDIUM",
            cvss_v3=5.9,
            description=(
                "paramiko < 2.10.1 has a timing attack vulnerability in the handling "
                "of SSH private key file creation, allowing key enumeration."
            ),
            exploit_available=False,
            affected_functions=["paramiko.RSAKey.generate", "paramiko.ECDSAKey.generate"],
        ),
    ],

    "jinja2": [
        VulnerablePackage(
            name="jinja2",
            ecosystem="pypi",
            vulnerable_range="<2.11.3",
            fixed_version="2.11.3",
            cve_ids=["CVE-2020-28493"],
            cwe_ids=["CWE-400"],
            severity="MEDIUM",
            cvss_v3=5.3,
            description=(
                "Jinja2 < 2.11.3 ReDoS vulnerability in the urlize filter allows "
                "denial of service via specially crafted input."
            ),
            exploit_available=False,
            affected_functions=["jinja2.filters.do_urlize", "Environment.from_string"],
        ),
    ],

    "werkzeug": [
        VulnerablePackage(
            name="werkzeug",
            ecosystem="pypi",
            vulnerable_range="<2.3.8",
            fixed_version="2.3.8",
            cve_ids=["CVE-2023-46136"],
            cwe_ids=["CWE-22"],
            severity="HIGH",
            cvss_v3=8.1,
            description=(
                "Werkzeug < 2.3.8 allows arbitrary file write through a path traversal "
                "vulnerability in the multipart/form-data parser."
            ),
            exploit_available=True,
            affected_functions=["werkzeug.formparser.MultiPartParser.parse"],
        ),
    ],

    "lxml": [
        VulnerablePackage(
            name="lxml",
            ecosystem="pypi",
            vulnerable_range="<4.9.3",
            fixed_version="4.9.3",
            cve_ids=["CVE-2022-2309"],
            cwe_ids=["CWE-91"],
            severity="HIGH",
            cvss_v3=7.5,
            description=(
                "lxml < 4.9.3 is vulnerable to XPath injection via crafted XPath "
                "expressions, potentially exposing sensitive XML document content."
            ),
            exploit_available=True,
            affected_functions=["lxml.etree.XPath", "lxml.etree._Element.xpath"],
        ),
    ],

    "aiohttp": [
        VulnerablePackage(
            name="aiohttp",
            ecosystem="pypi",
            vulnerable_range="<3.9.0",
            fixed_version="3.9.0",
            cve_ids=["CVE-2023-49082"],
            cwe_ids=["CWE-113"],
            severity="MEDIUM",
            cvss_v3=5.4,
            description=(
                "aiohttp < 3.9.0 is vulnerable to CRLF injection in HTTP request "
                "headers, allowing HTTP response splitting."
            ),
            exploit_available=False,
            affected_functions=["aiohttp.ClientSession.request", "aiohttp.ClientSession.get"],
        ),
    ],

    "sqlalchemy": [
        VulnerablePackage(
            name="sqlalchemy",
            ecosystem="pypi",
            vulnerable_range="<1.4.0",
            fixed_version="1.4.0",
            cve_ids=["CVE-2019-7164"],
            cwe_ids=["CWE-89"],
            severity="HIGH",
            cvss_v3=8.1,
            description=(
                "SQLAlchemy < 1.4.0 allows SQL injection via format strings in certain "
                "column name expressions. Use parameterized queries to mitigate."
            ),
            exploit_available=True,
            affected_functions=["text()", "engine.execute", "connection.execute"],
        ),
    ],

    # ── npm ───────────────────────────────────────────────────────────────────

    "lodash": [
        VulnerablePackage(
            name="lodash",
            ecosystem="npm",
            vulnerable_range="<4.17.21",
            fixed_version="4.17.21",
            cve_ids=["CVE-2021-23337"],
            cwe_ids=["CWE-77"],
            severity="HIGH",
            cvss_v3=7.2,
            description=(
                "lodash < 4.17.21 command injection via template() function. "
                "The template function allows arbitrary code execution via crafted "
                "template strings."
            ),
            exploit_available=True,
            affected_functions=["_.template", "_.merge", "_.set"],
        ),
    ],

    "axios": [
        VulnerablePackage(
            name="axios",
            ecosystem="npm",
            vulnerable_range="<0.21.2",
            fixed_version="0.21.2",
            cve_ids=["CVE-2021-3749"],
            cwe_ids=["CWE-918"],
            severity="HIGH",
            cvss_v3=7.5,
            description=(
                "axios < 0.21.2 SSRF vulnerability — insufficient URL validation allows "
                "an attacker to make requests to unintended internal services."
            ),
            exploit_available=True,
            affected_functions=["axios.get", "axios.post", "axios.request"],
        ),
    ],

    "express": [
        VulnerablePackage(
            name="express",
            ecosystem="npm",
            vulnerable_range="<4.18.2",
            fixed_version="4.18.2",
            cve_ids=["CVE-2022-24999"],
            cwe_ids=["CWE-601"],
            severity="HIGH",
            cvss_v3=7.5,
            description=(
                "express < 4.18.2 open redirect via qs library parsing, allowing "
                "attackers to redirect users to arbitrary external URLs."
            ),
            exploit_available=True,
            affected_functions=["res.redirect", "express.Router"],
        ),
    ],

    "node-fetch": [
        VulnerablePackage(
            name="node-fetch",
            ecosystem="npm",
            vulnerable_range="<2.6.7",
            fixed_version="2.6.7",
            cve_ids=["CVE-2022-0235"],
            cwe_ids=["CWE-918"],
            severity="HIGH",
            cvss_v3=8.8,
            description=(
                "node-fetch < 2.6.7 SSRF vulnerability — forwards sensitive request "
                "headers to third-party redirected URLs."
            ),
            exploit_available=True,
            affected_functions=["fetch"],
        ),
    ],

    "moment": [
        VulnerablePackage(
            name="moment",
            ecosystem="npm",
            vulnerable_range="<2.29.4",
            fixed_version="2.29.4",
            cve_ids=["CVE-2022-31129"],
            cwe_ids=["CWE-400"],
            severity="HIGH",
            cvss_v3=7.5,
            description=(
                "moment < 2.29.4 ReDoS vulnerability. Parsing strings in specific "
                "ISO 8601 formats can cause excessive backtracking, leading to DoS."
            ),
            exploit_available=False,
            affected_functions=["moment", "moment.utc", "moment.parseZone"],
        ),
    ],

    "jsonwebtoken": [
        VulnerablePackage(
            name="jsonwebtoken",
            ecosystem="npm",
            vulnerable_range="<9.0.0",
            fixed_version="9.0.0",
            cve_ids=["CVE-2022-23529"],
            cwe_ids=["CWE-287"],
            severity="HIGH",
            cvss_v3=7.6,
            description=(
                "jsonwebtoken < 9.0.0 algorithm confusion attack — secretOrPublicKey "
                "parameter is not validated, allowing attackers to forge tokens."
            ),
            exploit_available=True,
            affected_functions=["jwt.verify", "jwt.decode"],
        ),
    ],

    "serialize-javascript": [
        VulnerablePackage(
            name="serialize-javascript",
            ecosystem="npm",
            vulnerable_range="<6.0.0",
            fixed_version="6.0.0",
            cve_ids=["CVE-2020-7763"],
            cwe_ids=["CWE-79"],
            severity="MEDIUM",
            cvss_v3=6.1,
            description=(
                "serialize-javascript < 6.0.0 XSS vulnerability — special HTML "
                "characters in serialized strings are not properly escaped."
            ),
            exploit_available=True,
            affected_functions=["serialize"],
        ),
    ],
}
# fmt: on


# ---------------------------------------------------------------------------
# PART 2: Installed Package & Manifest Parser
# ---------------------------------------------------------------------------

@dataclass
class InstalledPackage:
    """Represents a package found in a dependency manifest."""
    name: str
    version: str            # exact or range string (e.g. "==2.1.0", "^4.17.0")
    ecosystem: str          # "pypi" or "npm"
    is_dev: bool            # dev/test dependency
    manifest_file: str      # absolute path to manifest
    line: int               # 1-based line in manifest file (0 if unknown)


class ManifestParser:
    """Parses dependency manifests and returns installed packages with versions."""

    # Manifest filename → parser method name
    _MANIFEST_NAMES: Dict[str, str] = {
        "requirements.txt": "_parse_requirements_txt_file",
        "requirements-dev.txt": "_parse_requirements_txt_file",
        "requirements_dev.txt": "_parse_requirements_txt_file",
        "pyproject.toml": "_parse_pyproject_toml_file",
        "package.json": "_parse_package_json_file",
        "Pipfile": "_parse_pipfile_file",
        "go.mod": "_parse_go_mod_file",
    }

    def parse(self, manifest_path: str) -> List[InstalledPackage]:
        """Auto-detect manifest type and parse."""
        path = Path(manifest_path)
        if not path.exists():
            logger.warning("Manifest not found: %s", manifest_path)
            return []

        filename = path.name
        method_name = self._MANIFEST_NAMES.get(filename)
        if method_name is None:
            # Try matching by suffix patterns
            if filename.startswith("requirements") and filename.endswith(".txt"):
                method_name = "_parse_requirements_txt_file"
            else:
                logger.warning("Unknown manifest type: %s", filename)
                return []

        try:
            content = path.read_text(errors="replace")
            parser_method = getattr(self, method_name)
            packages = parser_method(content)
            for pkg in packages:
                pkg.manifest_file = str(manifest_path)
            return packages
        except Exception as exc:
            logger.warning("Error parsing %s: %s", manifest_path, exc)
            return []

    def parse_requirements_txt(self, content: str) -> List[InstalledPackage]:
        """Parse requirements.txt format: package==version, package>=version, etc."""
        packages: List[InstalledPackage] = []
        for lineno, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            # Skip comments, blank lines, options
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Skip VCS/URL requirements
            if line.startswith(("git+", "http://", "https://", "file://")):
                continue
            # name op version (optional extras and env markers)
            m = re.match(
                r"^([A-Za-z0-9_.\-]+)"        # package name
                r"(?:\[.*?\])?"                # optional extras [...]
                r"\s*([><=!~^]+\s*[\d.]+(?:\.\*)?)?"  # optional version spec
                r"(?:\s*[,;].*)?$",            # optional extras/markers
                line,
            )
            if not m:
                continue
            name = m.group(1).strip()
            ver_spec = (m.group(2) or "").strip()
            # Extract just the version number from spec like "==2.0.1" → "2.0.1"
            ver_match = re.search(r"[\d][.\d]*", ver_spec)
            version = ver_match.group(0) if ver_match else ""
            packages.append(InstalledPackage(
                name=name.lower(),
                version=version,
                ecosystem="pypi",
                is_dev=False,
                manifest_file="",
                line=lineno,
            ))
        return packages

    # Internal alias used by parse()
    def _parse_requirements_txt_file(self, content: str) -> List[InstalledPackage]:
        return self.parse_requirements_txt(content)

    def parse_pyproject_toml(self, content: str) -> List[InstalledPackage]:
        """Parse pyproject.toml [tool.poetry.dependencies] and [project.dependencies]."""
        packages: List[InstalledPackage] = []

        # [project] dependencies (PEP 621 format)
        proj_deps_match = re.search(
            r"^\[project\].*?^dependencies\s*=\s*\[(.*?)\]",
            content,
            re.DOTALL | re.MULTILINE,
        )
        if proj_deps_match:
            deps_block = proj_deps_match.group(1)
            for lineno, raw in enumerate(deps_block.splitlines(), start=1):
                dep = raw.strip().strip('"').strip("'").strip(",").strip()
                if not dep or dep.startswith("#"):
                    continue
                m = re.match(
                    r"^([A-Za-z0-9_.\-]+)(?:\[.*?\])?\s*([><=!~^,\s\d.]+)?", dep
                )
                if not m:
                    continue
                name = m.group(1).lower()
                ver_spec = (m.group(2) or "").strip()
                ver_match = re.search(r"[\d][.\d]*", ver_spec)
                version = ver_match.group(0) if ver_match else ""
                packages.append(InstalledPackage(
                    name=name, version=version, ecosystem="pypi",
                    is_dev=False, manifest_file="", line=lineno,
                ))

        # [tool.poetry.dependencies] (Poetry format)
        poetry_deps_match = re.search(
            r"^\[tool\.poetry\.dependencies\](.*?)(?=^\[|\Z)",
            content,
            re.DOTALL | re.MULTILINE,
        )
        if poetry_deps_match:
            block = poetry_deps_match.group(1)
            for lineno, raw in enumerate(block.splitlines(), start=1):
                raw = raw.strip()
                if not raw or raw.startswith("#") or raw.startswith("["):
                    continue
                m = re.match(
                    r'^([A-Za-z0-9_.\-]+)\s*=\s*["\^~>=<\s]*([\d][.\d]*)', raw
                )
                if m:
                    packages.append(InstalledPackage(
                        name=m.group(1).lower(),
                        version=m.group(2),
                        ecosystem="pypi",
                        is_dev=False,
                        manifest_file="",
                        line=lineno,
                    ))

        # [tool.poetry.dev-dependencies] (Poetry dev deps)
        poetry_dev_match = re.search(
            r"^\[tool\.poetry\.dev-dependencies\](.*?)(?=^\[|\Z)",
            content,
            re.DOTALL | re.MULTILINE,
        )
        if poetry_dev_match:
            block = poetry_dev_match.group(1)
            for lineno, raw in enumerate(block.splitlines(), start=1):
                raw = raw.strip()
                if not raw or raw.startswith("#") or raw.startswith("["):
                    continue
                m = re.match(
                    r'^([A-Za-z0-9_.\-]+)\s*=\s*["\^~>=<\s]*([\d][.\d]*)', raw
                )
                if m:
                    packages.append(InstalledPackage(
                        name=m.group(1).lower(),
                        version=m.group(2),
                        ecosystem="pypi",
                        is_dev=True,
                        manifest_file="",
                        line=lineno,
                    ))

        return packages

    def _parse_pyproject_toml_file(self, content: str) -> List[InstalledPackage]:
        return self.parse_pyproject_toml(content)

    def parse_package_json(self, content: str) -> List[InstalledPackage]:
        """Parse package.json dependencies and devDependencies."""
        packages: List[InstalledPackage] = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse package.json: %s", exc)
            return []

        for name, version_spec in data.get("dependencies", {}).items():
            ver_clean = str(version_spec).lstrip("^~>=< ").split(" ")[0]
            packages.append(InstalledPackage(
                name=name.lower(),
                version=ver_clean,
                ecosystem="npm",
                is_dev=False,
                manifest_file="",
                line=0,
            ))

        for name, version_spec in data.get("devDependencies", {}).items():
            ver_clean = str(version_spec).lstrip("^~>=< ").split(" ")[0]
            packages.append(InstalledPackage(
                name=name.lower(),
                version=ver_clean,
                ecosystem="npm",
                is_dev=True,
                manifest_file="",
                line=0,
            ))

        return packages

    def _parse_package_json_file(self, content: str) -> List[InstalledPackage]:
        return self.parse_package_json(content)

    def parse_pipfile(self, content: str) -> List[InstalledPackage]:
        """Parse Pipfile [packages] section."""
        packages: List[InstalledPackage] = []
        in_packages = False
        in_dev = False
        lineno = 0

        for raw in content.splitlines():
            lineno += 1
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            # Section headers
            if line == "[packages]":
                in_packages = True
                in_dev = False
                continue
            if line == "[dev-packages]":
                in_packages = True
                in_dev = True
                continue
            if line.startswith("["):
                in_packages = False
                in_dev = False
                continue

            if not in_packages:
                continue

            # Parse: name = "version" or name = "*" or name = {version = ">=x"}
            m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*"([^"]*)"', line)
            if m:
                name = m.group(1).lower()
                ver_spec = m.group(2)
                ver_match = re.search(r"[\d][.\d]*", ver_spec)
                version = ver_match.group(0) if ver_match else ""
                packages.append(InstalledPackage(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    is_dev=in_dev,
                    manifest_file="",
                    line=lineno,
                ))
            else:
                # name = "*" format
                m2 = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*\*', line)
                if m2:
                    packages.append(InstalledPackage(
                        name=m2.group(1).lower(),
                        version="",
                        ecosystem="pypi",
                        is_dev=in_dev,
                        manifest_file="",
                        line=lineno,
                    ))

        return packages

    def _parse_pipfile_file(self, content: str) -> List[InstalledPackage]:
        return self.parse_pipfile(content)

    def parse_go_mod(self, content: str) -> List[InstalledPackage]:
        """Parse go.mod require block."""
        packages: List[InstalledPackage] = []
        lineno = 0
        in_require = False

        for raw in content.splitlines():
            lineno += 1
            line = raw.strip()
            if not line or line.startswith("//"):
                continue

            if line.startswith("require ("):
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue

            # Single-line require: require github.com/foo/bar v1.2.3
            m_single = re.match(r"^require\s+(\S+)\s+v([\d][.\d\w-]*)", line)
            if m_single:
                packages.append(InstalledPackage(
                    name=m_single.group(1),
                    version=m_single.group(2),
                    ecosystem="go",
                    is_dev=False,
                    manifest_file="",
                    line=lineno,
                ))
                continue

            if in_require:
                m = re.match(r"(\S+)\s+v([\d][.\d\w-]*)", line)
                if m:
                    packages.append(InstalledPackage(
                        name=m.group(1),
                        version=m.group(2),
                        ecosystem="go",
                        is_dev=False,
                        manifest_file="",
                        line=lineno,
                    ))

        return packages

    def _parse_go_mod_file(self, content: str) -> List[InstalledPackage]:
        return self.parse_go_mod(content)


# ---------------------------------------------------------------------------
# PART 3: Version Checker
# ---------------------------------------------------------------------------

class VersionChecker:
    """Checks whether an installed package version falls in a vulnerable range."""

    def is_vulnerable(self, package: InstalledPackage) -> Optional[VulnerablePackage]:
        """Return VulnerablePackage if the package is vulnerable, else None."""
        # Normalize ecosystem for DB lookup
        eco_map = {"pypi": "pypi", "npm": "npm", "go": "go", "cargo": "cargo"}
        pkg_eco = eco_map.get(package.ecosystem.lower(), package.ecosystem.lower())

        # Look up by normalized name
        pkg_name = package.name.lower().replace("_", "-")
        # Try canonical name first, then normalized
        candidates = (
            KNOWN_VULNERABLE_PACKAGES.get(package.name.lower(), [])
            or KNOWN_VULNERABLE_PACKAGES.get(pkg_name, [])
        )

        if not candidates:
            return None

        pkg_version = package.version
        if not pkg_version:
            return None

        for vuln in candidates:
            if vuln.ecosystem != pkg_eco:
                continue
            try:
                if self._version_in_range(pkg_version, vuln.vulnerable_range):
                    return vuln
            except Exception as exc:
                logger.debug(
                    "Version check failed for %s %s: %s",
                    package.name, pkg_version, exc,
                )

        return None

    def _parse_version(self, version_str: str) -> Tuple[int, ...]:
        """Parse version string to comparable tuple. e.g. '2.1.3' → (2, 1, 3)"""
        # Strip leading 'v' (Go versions)
        version_str = version_str.lstrip("v").strip()
        # Take only the numeric part (stop at '-' for pre-release like 1.2.3-rc1)
        numeric_part = re.split(r"[-+]", version_str)[0]
        parts = re.findall(r"\d+", numeric_part)
        if not parts:
            return (0,)
        return tuple(int(p) for p in parts)

    def _version_in_range(self, version: str, range_spec: str) -> bool:
        """
        Check if version falls in range_spec.
        Range spec examples: ">=1.0,<1.5.3", "<2.1.0", "==1.2.3", ">=2.0"
        """
        try:
            v = self._parse_version(version)
        except Exception:
            return False

        # Split on comma for compound ranges like ">=1.0,<2.0"
        clauses = [c.strip() for c in range_spec.split(",")]

        for clause in clauses:
            clause = clause.strip()
            if not clause:
                continue

            m = re.match(r"^([><=!~^]{1,2})\s*([\d][.\d]*(?:[.\d])*)$", clause)
            if not m:
                # Try without operator — treat bare version as "=="
                m2 = re.match(r"^([\d][.\d]*)$", clause)
                if m2:
                    bound = self._parse_version(m2.group(1))
                    if not (v == bound):
                        return False
                continue

            op = m.group(1)
            bound = self._parse_version(m.group(2))

            # Pad shorter tuple to same length for comparison
            max_len = max(len(v), len(bound))
            v_pad = v + (0,) * (max_len - len(v))
            b_pad = bound + (0,) * (max_len - len(bound))

            if op == "<":
                if not (v_pad < b_pad):
                    return False
            elif op == "<=":
                if not (v_pad <= b_pad):
                    return False
            elif op == ">":
                if not (v_pad > b_pad):
                    return False
            elif op == ">=":
                if not (v_pad >= b_pad):
                    return False
            elif op == "==":
                if not (v_pad == b_pad):
                    return False
            elif op == "!=":
                if not (v_pad != b_pad):
                    return False
            else:
                # Unknown operator — skip clause (don't fail safe)
                logger.debug("Unknown version operator %r in range %r", op, range_spec)

        return True


# ---------------------------------------------------------------------------
# PART 4: Import Tracker
# ---------------------------------------------------------------------------

@dataclass
class ImportUsage:
    """Represents an import of a (potentially vulnerable) package in source code."""
    package_name: str
    alias: str                       # local name used in code (import x as alias / const alias = require('pkg'))
    line: int                        # line of the import statement
    usage_lines: List[int]           # lines where the alias/package is referenced
    vulnerable_calls: List[str]      # specific vulnerable function calls found


class ImportTracker:
    """
    Scans Python/JS source code to find where vulnerable packages are imported and used.
    Returns locations in source code where the vulnerable package is accessed.
    """

    def find_python_imports(
        self, source_code: str, package_name: str
    ) -> List[ImportUsage]:
        """Find Python import statements for package_name."""
        usages: List[ImportUsage] = []
        lines = source_code.splitlines()
        pkg_normalized = package_name.replace("-", "_").lower()

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()

            # "import package" or "import package as alias"
            m = re.match(
                rf"^import\s+{re.escape(pkg_normalized)}"
                rf"(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?",
                stripped,
                re.IGNORECASE,
            )
            if m:
                alias = m.group(1) if m.group(1) else pkg_normalized
                usages.append(ImportUsage(
                    package_name=package_name,
                    alias=alias,
                    line=lineno,
                    usage_lines=self._find_usage_lines(lines, alias, lineno),
                    vulnerable_calls=[],
                ))
                continue

            # "from package import X" or "from package.sub import X"
            m2 = re.match(
                rf"^from\s+{re.escape(pkg_normalized)}"
                rf"(?:\.[A-Za-z0-9_.]+)?\s+import\s+(.+)$",
                stripped,
                re.IGNORECASE,
            )
            if m2:
                import_names_raw = m2.group(1)
                # Parse "foo, bar as baz, qux"
                import_names = self._parse_import_names(import_names_raw)
                for orig, alias in import_names:
                    usages.append(ImportUsage(
                        package_name=package_name,
                        alias=alias,
                        line=lineno,
                        usage_lines=self._find_usage_lines(lines, alias, lineno),
                        vulnerable_calls=[],
                    ))

        return usages

    def find_js_imports(
        self, source_code: str, package_name: str
    ) -> List[ImportUsage]:
        """Find JS require() and import statements for package_name."""
        usages: List[ImportUsage] = []
        lines = source_code.splitlines()
        pkg_escaped = re.escape(package_name)

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()

            # const x = require('pkg') or var x = require("pkg")
            m = re.match(
                rf"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)"
                rf"\s*=\s*require\(['\"]"
                rf"{pkg_escaped}"
                rf"(?:/[^'\"]+)?['\"]\)",
                stripped,
            )
            if m:
                alias = m.group(1)
                usages.append(ImportUsage(
                    package_name=package_name,
                    alias=alias,
                    line=lineno,
                    usage_lines=self._find_usage_lines(lines, alias, lineno),
                    vulnerable_calls=[],
                ))
                continue

            # import x from 'pkg' or import { x, y } from 'pkg'
            m2 = re.match(
                rf"^import\s+(.+?)\s+from\s+['\"]"
                rf"{pkg_escaped}"
                rf"(?:/[^'\"]+)?['\"]",
                stripped,
            )
            if m2:
                import_clause = m2.group(1).strip()
                # Default import: "x" or "* as x" or "{ x, y as z }"
                if import_clause.startswith("{"):
                    # Named imports
                    named = import_clause.strip("{}").strip()
                    for part in named.split(","):
                        part = part.strip()
                        as_m = re.match(r"(\w+)\s+as\s+(\w+)", part)
                        alias = as_m.group(2) if as_m else part
                        if alias:
                            usages.append(ImportUsage(
                                package_name=package_name,
                                alias=alias,
                                line=lineno,
                                usage_lines=self._find_usage_lines(lines, alias, lineno),
                                vulnerable_calls=[],
                            ))
                elif import_clause.startswith("*"):
                    as_m = re.match(r"\*\s+as\s+(\w+)", import_clause)
                    alias = as_m.group(1) if as_m else package_name
                    usages.append(ImportUsage(
                        package_name=package_name,
                        alias=alias,
                        line=lineno,
                        usage_lines=self._find_usage_lines(lines, alias, lineno),
                        vulnerable_calls=[],
                    ))
                else:
                    alias = import_clause.strip()
                    usages.append(ImportUsage(
                        package_name=package_name,
                        alias=alias,
                        line=lineno,
                        usage_lines=self._find_usage_lines(lines, alias, lineno),
                        vulnerable_calls=[],
                    ))

        return usages

    def find_vulnerable_calls(
        self,
        source_code: str,
        package_name: str,
        affected_functions: List[str],
    ) -> List[ImportUsage]:
        """Find calls to specifically vulnerable functions of the package."""
        if not affected_functions:
            return []

        usages: List[ImportUsage] = []
        lines = source_code.splitlines()

        for lineno, line in enumerate(lines, start=1):
            found_calls: List[str] = []
            for func in affected_functions:
                # Strip module prefix if present (e.g. "yaml.load" → search for "yaml.load(" in code)
                if "." in func:
                    pattern = re.escape(func) + r"\s*\("
                else:
                    # Bare function name — match with word boundary
                    pattern = r"\b" + re.escape(func) + r"\s*\("

                if re.search(pattern, line):
                    found_calls.append(func)

            if found_calls:
                usages.append(ImportUsage(
                    package_name=package_name,
                    alias=package_name,
                    line=lineno,
                    usage_lines=[lineno],
                    vulnerable_calls=found_calls,
                ))

        return usages

    # ── Internal helpers ────────────────────────────────────────────────────

    @staticmethod
    def _find_usage_lines(
        lines: List[str], identifier: str, import_line: int
    ) -> List[int]:
        """Find all lines (after import) where identifier is referenced."""
        if not identifier:
            return []
        pattern = re.compile(r"\b" + re.escape(identifier) + r"\b")
        usage_lines: List[int] = []
        for lineno, line in enumerate(lines, start=1):
            if lineno == import_line:
                continue
            if pattern.search(line):
                usage_lines.append(lineno)
        return usage_lines[:50]  # cap at 50 to avoid enormous lists

    @staticmethod
    def _parse_import_names(names_str: str) -> List[Tuple[str, str]]:
        """
        Parse import name list like "foo, bar as baz, qux" into [(orig, alias), ...].
        Also handles parenthesized imports: "(foo, bar as baz)".
        """
        names_str = names_str.strip().strip("()")
        result: List[Tuple[str, str]] = []
        for part in names_str.split(","):
            part = part.strip()
            if not part:
                continue
            m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)", part)
            if m:
                result.append((m.group(1), m.group(2)))
            else:
                m2 = re.match(r"([A-Za-z_][A-Za-z0-9_*]*)", part)
                if m2:
                    result.append((m2.group(1), m2.group(1)))
        return result


# ---------------------------------------------------------------------------
# PART 5: DependencyTaintAnalyzer — main entry point
# ---------------------------------------------------------------------------

@dataclass
class DependencyAnalysisResult:
    """Aggregated result of dependency taint analysis."""
    vulnerable_packages: List[Tuple[InstalledPackage, VulnerablePackage]]
    import_usages: Dict[str, List[ImportUsage]]       # pkg_name → usages in code
    total_dependencies: int
    total_vulnerable: int
    critical_count: int
    high_count: int
    manifests_found: List[str]
    analysis_errors: List[str]


# Severity ordering for comparison
_SEV_ORDER: Dict[str, int] = {
    "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0
}

# Manifest filenames to search for
_MANIFEST_FILENAMES: Set[str] = {
    "requirements.txt", "requirements-dev.txt", "requirements_dev.txt",
    "pyproject.toml", "package.json", "Pipfile", "go.mod",
}

# Directories to skip when walking the project tree
_SKIP_DIRS: Set[str] = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".eggs", "dist", "build", ".tox", ".mypy_cache",
}


class DependencyTaintAnalyzer:
    """
    Main entry point for supply chain taint analysis.

    Workflow:
    1. Parse manifests in project root
    2. Check each dependency against KNOWN_VULNERABLE_PACKAGES
    3. Find where vulnerable packages are imported in source
    4. Generate CPG taint source nodes for each vulnerable import
    5. Generate Finding objects for vulnerable dependencies
    6. Return combined result
    """

    def __init__(self) -> None:
        self._manifest_parser = ManifestParser()
        self._version_checker = VersionChecker()
        self._import_tracker = ImportTracker()

    # ── Public API ──────────────────────────────────────────────────────────

    def analyze_project(
        self,
        root_dir: str,
        source_files: Optional[List[str]] = None,
    ) -> DependencyAnalysisResult:
        """
        Full supply chain analysis of a project directory.
        Finds manifests, checks vulns, tracks imports, generates findings.
        """
        root = Path(root_dir)
        manifests_found: List[str] = []
        all_packages: List[InstalledPackage] = []
        errors: List[str] = []

        # Discover manifests
        for dirpath, dirnames, filenames in os.walk(str(root)):
            # Prune skipped directories in-place
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fname in filenames:
                if fname in _MANIFEST_FILENAMES:
                    manifest_path = os.path.join(dirpath, fname)
                    manifests_found.append(manifest_path)
                    try:
                        pkgs = self._manifest_parser.parse(manifest_path)
                        all_packages.extend(pkgs)
                    except Exception as exc:
                        errors.append(f"Error parsing {manifest_path}: {exc}")

        # Collect source files if not provided
        if source_files is None:
            source_files = self._collect_source_files(root_dir)

        return self._run_analysis(
            all_packages, source_files, manifests_found, errors
        )

    def analyze_manifest(
        self, manifest_path: str, source_code: str = ""
    ) -> DependencyAnalysisResult:
        """Analyze a single manifest file."""
        errors: List[str] = []
        try:
            packages = self._manifest_parser.parse(manifest_path)
        except Exception as exc:
            errors.append(f"Error parsing {manifest_path}: {exc}")
            packages = []

        source_files: List[str] = []
        if source_code:
            # Write to a temp analysis structure
            source_files = ["<inline>"]

        result = self._run_analysis(
            packages,
            source_files,
            [manifest_path],
            errors,
            inline_source=source_code,
        )
        return result

    def generate_cpg_taint_nodes(
        self, result: "DependencyAnalysisResult", cpg: CodePropertyGraph
    ) -> List[CPGNode]:
        """
        Add CPG nodes for vulnerable package imports as taint sources.
        These nodes integrate with InterproceduralDataflow and CPGQueryEngine.
        """
        added_nodes: List[CPGNode] = []

        for installed_pkg, vuln_pkg in result.vulnerable_packages:
            pkg_name = installed_pkg.name
            usages = result.import_usages.get(pkg_name, [])

            if usages:
                # Create taint source node for each import usage found
                for usage in usages:
                    node_id = f"supply-chain-taint-{pkg_name}-{usage.line}-{uuid.uuid4().hex[:8]}"
                    node = CPGNode(
                        node_id=node_id,
                        node_type=CPGNodeType.DFG_DEF,
                        ast_type="Import",
                        code=f"import {pkg_name} as {usage.alias}",
                        file=installed_pkg.manifest_file,
                        line=usage.line,
                        col=0,
                        properties={
                            "taint_source": True,
                            "taint_kind": "supply_chain_vuln",
                            "package_name": pkg_name,
                            "package_version": installed_pkg.version,
                            "cve_ids": vuln_pkg.cve_ids,
                            "cwe_ids": vuln_pkg.cwe_ids,
                            "severity": vuln_pkg.severity,
                            "cvss_v3": vuln_pkg.cvss_v3,
                            "fixed_version": vuln_pkg.fixed_version,
                            "alias": usage.alias,
                            "vulnerable_calls": usage.vulnerable_calls,
                            "exploit_available": vuln_pkg.exploit_available,
                            "description": vuln_pkg.description,
                        },
                    )
                    cpg.add_node(node)
                    added_nodes.append(node)

                    # Create DFG_USE nodes for each usage line
                    for use_line in usage.usage_lines[:10]:
                        use_node_id = (
                            f"supply-chain-use-{pkg_name}-{use_line}-{uuid.uuid4().hex[:8]}"
                        )
                        use_node = CPGNode(
                            node_id=use_node_id,
                            node_type=CPGNodeType.DFG_USE,
                            ast_type="Name",
                            code=usage.alias,
                            file=installed_pkg.manifest_file,
                            line=use_line,
                            col=0,
                            properties={
                                "taint_propagated": True,
                                "taint_source_id": node_id,
                                "package_name": pkg_name,
                            },
                        )
                        cpg.add_node(use_node)
                        added_nodes.append(use_node)

                        # Add DFG edge: taint source → use
                        try:
                            edge = CPGEdge(
                                edge_id=f"dfg-{node_id}-{use_node_id}",
                                src_id=node_id,
                                dst_id=use_node_id,
                                edge_type=CPGEdgeType.DFG_FLOW,
                                properties={
                                    "taint_kind": "supply_chain_vuln",
                                    "package": pkg_name,
                                },
                            )
                            cpg.add_edge(edge)
                        except ValueError as exc:
                            logger.debug("Could not add DFG edge: %s", exc)
            else:
                # No direct import found — still create a manifest-level taint node
                node_id = (
                    f"supply-chain-manifest-{pkg_name}-{uuid.uuid4().hex[:8]}"
                )
                node = CPGNode(
                    node_id=node_id,
                    node_type=CPGNodeType.DFG_DEF,
                    ast_type="Import",
                    code=f"# {pkg_name}=={installed_pkg.version} (manifest)",
                    file=installed_pkg.manifest_file,
                    line=installed_pkg.line,
                    col=0,
                    properties={
                        "taint_source": True,
                        "taint_kind": "supply_chain_vuln",
                        "package_name": pkg_name,
                        "package_version": installed_pkg.version,
                        "cve_ids": vuln_pkg.cve_ids,
                        "cwe_ids": vuln_pkg.cwe_ids,
                        "severity": vuln_pkg.severity,
                        "cvss_v3": vuln_pkg.cvss_v3,
                        "fixed_version": vuln_pkg.fixed_version,
                        "not_imported_in_code": True,
                        "exploit_available": vuln_pkg.exploit_available,
                        "description": vuln_pkg.description,
                    },
                )
                cpg.add_node(node)
                added_nodes.append(node)

        logger.info(
            "Generated %d CPG taint nodes for %d vulnerable packages",
            len(added_nodes),
            result.total_vulnerable,
        )
        return added_nodes

    def generate_findings(
        self, result: "DependencyAnalysisResult"
    ) -> List[Finding]:
        """Convert vulnerable dependency detections to Finding objects."""
        findings: List[Finding] = []

        for installed_pkg, vuln_pkg in result.vulnerable_packages:
            pkg_name = installed_pkg.name
            pkg_version = installed_pkg.version
            usages = result.import_usages.get(pkg_name, [])

            # Base severity from vuln DB
            severity = vuln_pkg.severity

            # Downgrade if dev dependency
            if installed_pkg.is_dev:
                sev_ord = _SEV_ORDER.get(severity, 2)
                if sev_ord > _SEV_ORDER["MEDIUM"]:
                    severity = "MEDIUM"

            # Downgrade to INFO if not actually imported in code
            if not usages:
                severity = "INFO"

            # Build context lines: first few usage lines' content
            context_lines: List[str] = []
            for usage in usages[:3]:
                context_lines.append(
                    f"Line {usage.line}: import {pkg_name} as {usage.alias}"
                )

            # Gather all vulnerable calls across usages
            all_vuln_calls: List[str] = []
            for usage in usages:
                all_vuln_calls.extend(usage.vulnerable_calls)

            cwe_id = vuln_pkg.cwe_ids[0] if vuln_pkg.cwe_ids else ""
            cve_str = ", ".join(vuln_pkg.cve_ids)

            rec_parts = [
                f"Upgrade {pkg_name} to >= {vuln_pkg.fixed_version}.",
            ]
            if vuln_pkg.affected_functions:
                rec_parts.append(
                    f"Audit calls to: {', '.join(vuln_pkg.affected_functions[:5])}."
                )
            if vuln_pkg.exploit_available:
                rec_parts.append("Public exploit available — treat as urgent.")

            finding = Finding(
                rule_id=f"SC-TAINT-{vuln_pkg.cve_ids[0] if vuln_pkg.cve_ids else pkg_name.upper()}",
                file=installed_pkg.manifest_file or "<unknown>",
                line=installed_pkg.line,
                severity=severity,
                confidence=self._confidence_score(vuln_pkg, usages, installed_pkg),
                cwe_id=cwe_id,
                description=(
                    f"Vulnerable dependency: {pkg_name}=={pkg_version} "
                    f"({cve_str}). {vuln_pkg.description}"
                ),
                recommendation=" ".join(rec_parts),
                sources=vuln_pkg.cve_ids,
                context_lines=context_lines,
                is_test_file=False,
                is_suppressed=False,
                # Extra fields via model_config extra="allow"
                package_name=pkg_name,
                package_version=pkg_version,
                fixed_version=vuln_pkg.fixed_version,
                cve_ids=vuln_pkg.cve_ids,
                cvss_v3=vuln_pkg.cvss_v3,
                exploit_available=vuln_pkg.exploit_available,
                is_dev_dependency=installed_pkg.is_dev,
                import_usages_count=len(usages),
                vulnerable_calls_found=all_vuln_calls[:10],
                ecosystem=installed_pkg.ecosystem,
            )
            findings.append(finding)

        return findings

    # ── Internal helpers ────────────────────────────────────────────────────

    def _run_analysis(
        self,
        packages: List[InstalledPackage],
        source_files: List[str],
        manifests_found: List[str],
        errors: List[str],
        inline_source: str = "",
    ) -> DependencyAnalysisResult:
        """Core analysis: check versions, track imports."""
        vulnerable: List[Tuple[InstalledPackage, VulnerablePackage]] = []
        import_usages: Dict[str, List[ImportUsage]] = {}
        critical_count = 0
        high_count = 0

        for pkg in packages:
            vuln = self._version_checker.is_vulnerable(pkg)
            if vuln is None:
                continue

            vulnerable.append((pkg, vuln))

            if vuln.severity == "CRITICAL":
                critical_count += 1
            elif vuln.severity == "HIGH":
                high_count += 1

            # Track imports across source files
            pkg_usages: List[ImportUsage] = []
            if inline_source:
                pkg_usages.extend(
                    self._track_imports_in_source(inline_source, pkg.name, vuln, "<inline>")
                )
            else:
                for src_file in source_files:
                    try:
                        src_text = Path(src_file).read_text(errors="replace")
                        pkg_usages.extend(
                            self._track_imports_in_source(src_text, pkg.name, vuln, src_file)
                        )
                    except OSError as exc:
                        logger.debug("Cannot read source file %s: %s", src_file, exc)

            if pkg_usages:
                import_usages[pkg.name] = pkg_usages

        return DependencyAnalysisResult(
            vulnerable_packages=vulnerable,
            import_usages=import_usages,
            total_dependencies=len(packages),
            total_vulnerable=len(vulnerable),
            critical_count=critical_count,
            high_count=high_count,
            manifests_found=manifests_found,
            analysis_errors=errors,
        )

    def _track_imports_in_source(
        self,
        source: str,
        pkg_name: str,
        vuln: VulnerablePackage,
        source_file: str,
    ) -> List[ImportUsage]:
        """Find imports and vulnerable function calls in source text."""
        usages: List[ImportUsage] = []

        if vuln.ecosystem == "pypi":
            found = self._import_tracker.find_python_imports(source, pkg_name)
        elif vuln.ecosystem == "npm":
            found = self._import_tracker.find_js_imports(source, pkg_name)
        else:
            found = []

        # Also search for specific vulnerable function calls
        vuln_call_usages = self._import_tracker.find_vulnerable_calls(
            source, pkg_name, vuln.affected_functions
        )

        # Merge vulnerable call info into import usages
        vuln_call_lines: Dict[int, List[str]] = {}
        for vc in vuln_call_usages:
            for line in vc.usage_lines:
                vuln_call_lines.setdefault(line, []).extend(vc.vulnerable_calls)
            if vc.line not in vuln_call_lines:
                vuln_call_lines[vc.line] = vc.vulnerable_calls

        for usage in found:
            # Annotate with any vulnerable calls found at usage lines
            calls_found: List[str] = []
            for ul in usage.usage_lines:
                calls_found.extend(vuln_call_lines.get(ul, []))
            # Also check direct call lines
            calls_found.extend(vuln_call_lines.get(usage.line, []))
            usage.vulnerable_calls = list(dict.fromkeys(calls_found))  # dedup, preserve order
            usages.append(usage)

        return usages

    @staticmethod
    def _collect_source_files(root_dir: str) -> List[str]:
        """Walk root_dir and collect Python + JS/TS source files."""
        source_files: List[str] = []
        source_extensions = {".py", ".js", ".ts", ".jsx", ".tsx"}

        for dirpath, dirnames, filenames in os.walk(root_dir):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fname in filenames:
                if any(fname.endswith(ext) for ext in source_extensions):
                    source_files.append(os.path.join(dirpath, fname))

        return source_files

    @staticmethod
    def _confidence_score(
        vuln: VulnerablePackage,
        usages: List[ImportUsage],
        pkg: InstalledPackage,
    ) -> float:
        """
        Compute confidence score for a finding:
        - Base: 0.75 if version is pinned (exact), 0.60 if range/unknown
        - +0.15 if package is actually imported in source
        - +0.05 if vulnerable function calls found
        - -0.15 for dev dependency
        - +0.05 if exploit available
        """
        base = 0.75 if pkg.version else 0.60
        if usages:
            base += 0.15
        if any(u.vulnerable_calls for u in usages):
            base += 0.05
        if pkg.is_dev:
            base -= 0.15
        if vuln.exploit_available:
            base += 0.05
        return min(max(base, 0.0), 1.0)
