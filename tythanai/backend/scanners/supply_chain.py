"""
backend/scanners/supply_chain.py — Supply Chain Scanner (Phase 1)

Supports:
  requirements.txt  pyproject.toml  package.json  go.mod  Cargo.toml

Checks:
  1. OSV (https://api.osv.dev)
  2. GitHub Security Advisories (via osv.dev GitHub ecosystem)
  3. Typosquatting detection (Levenshtein distance ≤ 2 vs popular packages)

Context rules:
  - Vulnerable dep not imported in AST → severity downgraded to INFO
  - Dev dependencies → severity capped at MEDIUM
  - Disputed vulnerabilities → no severity upgrade; marked "disputed"
"""
from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel

logger = logging.getLogger("tythanai.supply_chain")

# ─────────────────────────────────────────────────────────────────────────────
# Popular package lists for typosquatting detection
# ─────────────────────────────────────────────────────────────────────────────

_POPULAR_PYPI = {
    "requests", "numpy", "pandas", "flask", "django", "fastapi",
    "sqlalchemy", "pydantic", "boto3", "pytest", "setuptools", "pip",
    "cryptography", "httpx", "aiohttp", "celery", "redis", "uvicorn",
    "starlette", "click", "rich", "typer", "httpcore", "anyio",
    "pillow", "scipy", "matplotlib", "tensorflow", "torch", "sklearn",
    "scikit-learn", "paramiko", "fabric", "invoke", "black", "mypy",
    "pylint", "flake8", "bandit", "semgrep", "jinja2", "werkzeug",
}

_POPULAR_NPM = {
    "react", "lodash", "express", "axios", "moment", "vue",
    "angular", "jquery", "webpack", "babel", "eslint", "typescript",
    "next", "nuxt", "gatsby", "rollup", "vite", "jest",
    "mocha", "chai", "sinon", "prettier", "tailwindcss", "bootstrap",
}

_POPULAR_GO = {
    "github.com/gin-gonic/gin", "github.com/gorilla/mux",
    "github.com/stretchr/testify", "github.com/go-chi/chi",
    "github.com/labstack/echo", "golang.org/x/crypto",
    "github.com/spf13/cobra", "github.com/spf13/viper",
}

_POPULAR_CARGO = {
    "serde", "tokio", "reqwest", "anyhow", "thiserror",
    "rand", "log", "clap", "hyper", "actix-web",
    "axum", "rocket", "diesel", "sqlx", "uuid",
}

# ─────────────────────────────────────────────────────────────────────────────
# Levenshtein distance
# ─────────────────────────────────────────────────────────────────────────────

def _levenshtein(s1: str, s2: str) -> int:
    if s1 == s2:
        return 0
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(
                prev[j + 1] + 1,
                curr[j] + 1,
                prev[j] + (0 if c1 == c2 else 1),
            ))
        prev = curr
    return prev[-1]


def _check_typosquatting(
    name: str, popular: Set[str], max_dist: int = 2
) -> Optional[str]:
    """
    Return the popular package name if `name` is within Levenshtein distance
    of `max_dist`, or None if no match.
    """
    name_lower = name.lower()
    # Exact match is fine
    if name_lower in popular:
        return None
    for pop in popular:
        dist = _levenshtein(name_lower, pop)
        if 0 < dist <= max_dist:
            return pop
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Package file parsers
# ─────────────────────────────────────────────────────────────────────────────

class Package(BaseModel):
    name: str
    version: str = ""
    ecosystem: str = "PyPI"
    is_dev: bool = False
    source_file: str = ""


def _parse_requirements_txt(filepath: str) -> List[Package]:
    packages = []
    text = Path(filepath).read_text(errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # name==version or name>=version etc.
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*[=><!~^]+\s*([^\s;]+)", line)
        if m:
            packages.append(Package(
                name=m.group(1).lower(),
                version=m.group(2).strip(),
                ecosystem="PyPI",
                source_file=filepath,
            ))
        else:
            m2 = re.match(r"^([A-Za-z0-9_.\-]+)", line)
            if m2:
                packages.append(Package(
                    name=m2.group(1).lower(),
                    ecosystem="PyPI",
                    source_file=filepath,
                ))
    return packages


def _parse_pyproject_toml(filepath: str) -> List[Package]:
    packages = []
    text = Path(filepath).read_text(errors="replace")

    # [project] dependencies
    dep_section = re.search(
        r"\[project\].*?dependencies\s*=\s*\[(.*?)\]", text, re.DOTALL
    )
    if dep_section:
        for dep in dep_section.group(1).split(","):
            dep = dep.strip().strip('"').strip("'")
            m = re.match(r"^([A-Za-z0-9_.\-]+)", dep)
            if m:
                packages.append(Package(
                    name=m.group(1).lower(), ecosystem="PyPI", source_file=filepath
                ))

    # [project.optional-dependencies] or [tool.poetry.dev-dependencies]
    dev_section = re.search(
        r"\[(?:project\.optional-dependencies|tool\.poetry\.dev-dependencies)\].*?\n(.*?)(?=\n\[|\Z)",
        text, re.DOTALL,
    )
    if dev_section:
        for line in dev_section.group(1).splitlines():
            m = re.match(r"\s*([A-Za-z0-9_.\-]+)\s*=", line)
            if m:
                packages.append(Package(
                    name=m.group(1).lower(), ecosystem="PyPI",
                    is_dev=True, source_file=filepath,
                ))
    return packages


def _parse_package_json(filepath: str) -> List[Package]:
    packages = []
    try:
        data = json.loads(Path(filepath).read_text(errors="replace"))
    except json.JSONDecodeError:
        return []

    for name, version in data.get("dependencies", {}).items():
        ver = version.lstrip("^~>=<").split(" ")[0]
        packages.append(Package(
            name=name, version=ver, ecosystem="npm",
            source_file=filepath,
        ))
    for name, version in data.get("devDependencies", {}).items():
        ver = version.lstrip("^~>=<").split(" ")[0]
        packages.append(Package(
            name=name, version=ver, ecosystem="npm",
            is_dev=True, source_file=filepath,
        ))
    return packages


def _parse_go_mod(filepath: str) -> List[Package]:
    packages = []
    text = Path(filepath).read_text(errors="replace")
    for line in text.splitlines():
        m = re.match(r"\s+([^\s]+)\s+v([^\s]+)", line)
        if m:
            packages.append(Package(
                name=m.group(1), version=m.group(2),
                ecosystem="Go", source_file=filepath,
            ))
    return packages


def _parse_cargo_toml(filepath: str) -> List[Package]:
    packages = []
    text = Path(filepath).read_text(errors="replace")
    in_dev = False
    for line in text.splitlines():
        if re.match(r"\[dev-dependencies\]", line):
            in_dev = True
            continue
        if re.match(r"\[dependencies\]", line):
            in_dev = False
            continue
        if line.startswith("["):
            in_dev = False
        m = re.match(r'([A-Za-z0-9_.\-]+)\s*=\s*"([^"]+)"', line)
        if m:
            packages.append(Package(
                name=m.group(1), version=m.group(2),
                ecosystem="crates.io", is_dev=in_dev, source_file=filepath,
            ))
    return packages


_PARSERS: Dict[str, Any] = {
    "requirements.txt": _parse_requirements_txt,
    "pyproject.toml": _parse_pyproject_toml,
    "package.json": _parse_package_json,
    "go.mod": _parse_go_mod,
    "Cargo.toml": _parse_cargo_toml,
}

_POPULAR_BY_ECOSYSTEM: Dict[str, Set[str]] = {
    "PyPI": _POPULAR_PYPI,
    "npm": _POPULAR_NPM,
    "Go": _POPULAR_GO,
    "crates.io": _POPULAR_CARGO,
}

# ─────────────────────────────────────────────────────────────────────────────
# OSV lookup
# ─────────────────────────────────────────────────────────────────────────────

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

def _osv_lookup(packages: List[Package]) -> Dict[str, List[Dict]]:
    """
    Returns mapping: package_name → list of OSV vulnerability dicts.
    """
    if not packages:
        return {}

    queries = []
    for p in packages:
        q: Dict[str, Any] = {
            "package": {"name": p.name, "ecosystem": p.ecosystem}
        }
        if p.version:
            q["version"] = p.version
        queries.append(q)

    payload = json.dumps({"queries": queries}).encode()
    try:
        req = urllib.request.Request(
            _OSV_BATCH_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read())
        results = data.get("results", [])
        mapping: Dict[str, List[Dict]] = {}
        for i, res in enumerate(results):
            if i < len(packages):
                vulns = res.get("vulns", [])
                if vulns:
                    mapping[packages[i].name] = vulns
        return mapping
    except Exception as exc:
        logger.warning("OSV lookup failed: %s", exc)
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# Severity capping helpers
# ─────────────────────────────────────────────────────────────────────────────

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

def _cap_severity(sev: str, max_sev: str) -> str:
    if _SEV_ORDER.get(sev, 0) > _SEV_ORDER.get(max_sev, 0):
        return max_sev
    return sev


def _osv_severity(vuln: Dict) -> str:
    """Extract highest severity from OSV vuln dict."""
    sev_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM",
               "MEDIUM": "MEDIUM", "LOW": "LOW"}
    sev = "MEDIUM"
    for sv in vuln.get("severity", []):
        score = sv.get("score", "")
        # CVSS string e.g. "CVSS:3.1/AV:N/..."
        if "AV:N" in score and "C:H" in score:
            sev = "CRITICAL"
        elif "AV:N" in score:
            sev = max(sev, "HIGH", key=lambda s: _SEV_ORDER.get(s, 0))
    # Also check database_specific
    sev_str = vuln.get("database_specific", {}).get("severity", "")
    if sev_str.upper() in sev_map:
        candidate = sev_map[sev_str.upper()]
        if _SEV_ORDER.get(candidate, 0) > _SEV_ORDER.get(sev, 0):
            sev = candidate
    return sev


def _is_disputed(vuln: Dict) -> bool:
    ids = vuln.get("aliases", []) + [vuln.get("id", "")]
    details = vuln.get("details", "").lower()
    return "disputed" in details or any("DISPUTED" in str(i).upper() for i in ids)


# ─────────────────────────────────────────────────────────────────────────────
# AST import check
# ─────────────────────────────────────────────────────────────────────────────

def _package_imported(directory: str, package_name: str) -> bool:
    safe_name = re.escape(package_name.replace("-", "_"))
    pattern = re.compile(
        rf"^\s*(import\s+{safe_name}|from\s+{safe_name}\s+import)",
        re.MULTILINE | re.IGNORECASE,
    )
    skip = {"__pycache__", ".venv", "venv", "node_modules"}
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in skip]
        for fname in files:
            if not fname.endswith(".py"):
                continue
            try:
                text = Path(os.path.join(root, fname)).read_text(errors="replace")
                if pattern.search(text):
                    return True
            except OSError:
                pass
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Main scanner
# ─────────────────────────────────────────────────────────────────────────────

class SupplyChainScanner:
    """
    Scans dependency files for known vulnerabilities (OSV) and typosquatting.
    Applies context rules (AST usage, dev deps, disputed status).
    """

    def scan(self, directory: str) -> Dict[str, Any]:
        packages = self._collect_packages(directory)
        if not packages:
            return {"findings": [], "packages_scanned": 0, "typosquatting": []}

        # OSV lookup
        vuln_map = _osv_lookup(packages)

        findings: List[Dict[str, Any]] = []
        typosquat_alerts: List[Dict[str, Any]] = []

        for pkg in packages:
            # ── Typosquatting check ───────────────────────────────────────
            popular = _POPULAR_BY_ECOSYSTEM.get(pkg.ecosystem, set())
            similar = _check_typosquatting(pkg.name, popular)
            if similar:
                typosquat_alerts.append({
                    "package": pkg.name,
                    "similar_to": similar,
                    "ecosystem": pkg.ecosystem,
                    "source_file": pkg.source_file,
                    "severity": "HIGH",
                    "description": (
                        f"Package '{pkg.name}' is similar to popular package '{similar}' "
                        f"(Levenshtein distance ≤ 2). Possible typosquatting attack."
                    ),
                })

            # ── OSV vulnerabilities ───────────────────────────────────────
            for vuln in vuln_map.get(pkg.name, []):
                disputed = _is_disputed(vuln)
                base_sev = _osv_severity(vuln)

                # Dev dep cap
                if pkg.is_dev:
                    base_sev = _cap_severity(base_sev, "MEDIUM")

                # Disputed: do not upgrade severity
                if disputed and _SEV_ORDER.get(base_sev, 0) > _SEV_ORDER.get("MEDIUM", 0):
                    base_sev = "MEDIUM"

                # AST context: if not imported, downgrade to INFO
                ast_used = _package_imported(directory, pkg.name)
                if not ast_used:
                    base_sev = "INFO"

                finding: Dict[str, Any] = {
                    "package": pkg.name,
                    "version": pkg.version,
                    "ecosystem": pkg.ecosystem,
                    "is_dev": pkg.is_dev,
                    "source_file": pkg.source_file,
                    "vuln_id": vuln.get("id", ""),
                    "aliases": vuln.get("aliases", [])[:3],
                    "severity": base_sev,
                    "disputed": disputed,
                    "summary": vuln.get("summary", "")[:200],
                    "details": vuln.get("details", "")[:400],
                    "fixed_in": self._extract_fixed(vuln),
                    "references": [
                        r.get("url", "")
                        for r in vuln.get("references", [])[:2]
                    ],
                    "ast_imported": ast_used,
                    "rule_id": f"SUPPLY-CHAIN-{vuln.get('id', 'UNKNOWN')}",
                    "cwe_id": "",
                }
                if not ast_used:
                    finding["_note"] = "Package installed but not imported in source — severity downgraded"
                if disputed:
                    finding["_note"] = finding.get("_note", "") + " [disputed]"

                findings.append(finding)

        # Add typosquatting as findings
        for ts in typosquat_alerts:
            findings.append({
                "rule_id": "SUPPLY-CHAIN-TYPOSQUATTING",
                "cwe_id": "CWE-1357",
                **ts,
            })

        return {
            "findings": findings,
            "packages_scanned": len(packages),
            "typosquatting": typosquat_alerts,
            "vuln_packages": list(vuln_map.keys()),
        }

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _collect_packages(self, directory: str) -> List[Package]:
        packages: List[Package] = []
        root = Path(directory)
        for fname, parser in _PARSERS.items():
            for match in root.rglob(fname):
                # Skip venv directories
                if any(p in match.parts for p in (".venv", "venv", "node_modules", "__pycache__")):
                    continue
                try:
                    pkgs = parser(str(match))
                    packages.extend(pkgs)
                    logger.debug("Parsed %s: %d packages", match, len(pkgs))
                except Exception as exc:
                    logger.warning("Failed to parse %s: %s", match, exc)
        return packages

    @staticmethod
    def _extract_fixed(vuln: Dict) -> str:
        """Extract the fixed version string from OSV vuln."""
        for aff in vuln.get("affected", []):
            for rng in aff.get("ranges", []):
                for event in rng.get("events", []):
                    fixed = event.get("fixed")
                    if fixed:
                        return str(fixed)
        return ""
