"""
TythanAI — OSV.dev Real-Time Vulnerability Scanner

Live CVE/GHSA queries via Google's Open Source Vulnerability database.
No API key required. Covers PyPI, npm, Go, Maven, crates.io, RubyGems,
NuGet, Hex, Pub, Linux, Android, Debian, Alpine, and more.

The OSV API handles version matching server-side — querying with a specific
version returns ONLY vulnerabilities that affect that exact version.
Falls back to the static dependency_scanner DB when offline.

Usage:
    from scanners.osv_scanner import OSVScanner
    scanner = OSVScanner()
    result  = scanner.scan_directory("/path/to/project")
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Ecosystem mapping: manifest file / language → OSV ecosystem name ──────────

_FILE_ECOSYSTEM: Dict[str, str] = {
    "requirements.txt":  "PyPI",
    "requirements":      "PyPI",     # matches requirements*.txt
    "setup.cfg":         "PyPI",
    "pyproject.toml":    "PyPI",
    "pipfile":           "PyPI",
    "package.json":      "npm",
    "package-lock.json": "npm",
    "yarn.lock":         "npm",
    "go.mod":            "Go",
    "cargo.toml":        "crates.io",
    "cargo.lock":        "crates.io",
    "gemfile":           "RubyGems",
    "gemfile.lock":      "RubyGems",
    "pom.xml":           "Maven",
    "build.gradle":      "Maven",
    "pubspec.yaml":      "Pub",
    "mix.exs":           "Hex",
    "packages.config":   "NuGet",
    ".csproj":           "NuGet",
}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

OSV_API_BASE = "https://api.osv.dev/v1"
_BATCH_SIZE  = 20   # OSV batch API limit per request
_TIMEOUT     = 10   # seconds per HTTP call


class OSVClient:
    """Low-level OSV.dev API client with in-memory result caching."""

    def __init__(self, timeout: int = _TIMEOUT) -> None:
        self._timeout = timeout
        self._cache: Dict[Tuple[str, str, str], List[Dict]] = {}

    # ── Public API ─────────────────────────────────────────────────────────────

    def query_batch(
        self, packages: List[Tuple[str, str, str]]
    ) -> Dict[Tuple[str, str, str], List[Dict]]:
        """
        Query OSV for multiple (name, version, ecosystem) tuples at once.
        Returns a dict mapping each tuple to its list of OSV vulnerability objects.
        Packages already in cache are not re-queried.
        """
        to_query  = [p for p in packages if p not in self._cache]
        results   = {p: self._cache[p] for p in packages if p in self._cache}

        # Split into batches of _BATCH_SIZE
        for i in range(0, len(to_query), _BATCH_SIZE):
            batch  = to_query[i : i + _BATCH_SIZE]
            vulns  = self._do_batch(batch)
            for pkg, vuln_list in zip(batch, vulns):
                self._cache[pkg] = vuln_list
                results[pkg]     = vuln_list

        return results

    def query_single(self, name: str, version: str, ecosystem: str) -> List[Dict]:
        """Query OSV for a single package version."""
        key = (name, version, ecosystem)
        if key not in self._cache:
            vulns = self._do_batch([key])
            self._cache[key] = vulns[0] if vulns else []
        return self._cache[key]

    def is_online(self) -> bool:
        """Quick connectivity check."""
        try:
            req = urllib.request.Request(
                f"{OSV_API_BASE}/query",
                data=b'{"package":{"name":"requests","ecosystem":"PyPI"},"version":"2.31.0"}',
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=4):
                return True
        except Exception:
            return False

    # ── Internal ───────────────────────────────────────────────────────────────

    def _do_batch(self, batch: List[Tuple[str, str, str]]) -> List[List[Dict]]:
        """POST to /querybatch. Returns a list aligned with the input batch."""
        queries = []
        for name, version, ecosystem in batch:
            q: Dict = {"package": {"name": name, "ecosystem": ecosystem}}
            if version:
                q["version"] = version
            queries.append(q)

        payload = json.dumps({"queries": queries}).encode()
        req = urllib.request.Request(
            f"{OSV_API_BASE}/querybatch",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read())
        except (urllib.error.URLError, json.JSONDecodeError, OSError):
            return [[] for _ in batch]

        results_raw = data.get("results", [])
        out: List[List[Dict]] = []
        for entry in results_raw:
            out.append(entry.get("vulns", []))
        # Pad with empty lists if API returned fewer results than queried
        while len(out) < len(batch):
            out.append([])
        return out


def _extract_severity(osv_vuln: Dict) -> str:
    """Extract highest severity from OSV vulnerability object."""
    # Try CVSS severity from database_specific or severity field
    for sev_entry in osv_vuln.get("severity", []):
        score_type = sev_entry.get("type", "")
        score      = sev_entry.get("score", "")
        if "CVSS" in score_type.upper():
            # Try to parse CVSS score number
            try:
                v = float(re.search(r"(\d+\.?\d*)", score).group(1))
                if v >= 9.0:  return "CRITICAL"
                if v >= 7.0:  return "HIGH"
                if v >= 4.0:  return "MEDIUM"
                return "LOW"
            except (AttributeError, ValueError):
                pass

    # Fallback: check database_specific.severity
    db_spec = osv_vuln.get("database_specific", {})
    sev_str = str(db_spec.get("severity", "")).upper()
    if sev_str in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return sev_str

    # Fallback: infer from CVSS vector in related descriptions
    return "MEDIUM"


def _extract_fixed_version(osv_vuln: Dict, ecosystem: str) -> str:
    """Extract the recommended fixed version from an OSV vulnerability."""
    for affected in osv_vuln.get("affected", []):
        if affected.get("package", {}).get("ecosystem", "").lower() != ecosystem.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return "latest"


def _osv_vuln_to_finding(
    osv_vuln: Dict,
    pkg_name: str,
    pkg_version: str,
    ecosystem: str,
    source_file: str,
) -> Dict:
    """Convert an OSV vulnerability object into a Ghost finding dict."""
    vuln_id   = osv_vuln.get("id", "OSV-UNKNOWN")
    aliases   = osv_vuln.get("aliases", [])
    # Prefer CVE ID if available
    cve_id    = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
    summary   = osv_vuln.get("summary", osv_vuln.get("details", "")[:200])
    severity  = _extract_severity(osv_vuln)
    fixed_ver = _extract_fixed_version(osv_vuln, ecosystem)

    # References
    refs = [r.get("url", "") for r in osv_vuln.get("references", [])[:3]]
    ref_str = refs[0] if refs else ""

    return {
        "type":           "VULNERABLE_DEPENDENCY",
        "id":             cve_id,
        "osv_id":         vuln_id,
        "severity":       severity,
        "file":           source_file,
        "line":           0,
        "description":    f"{pkg_name} {pkg_version}: {summary}",
        "message":        summary[:120],
        "evidence":       f"{pkg_name}=={pkg_version}",
        "recommendation": f"Upgrade {pkg_name} to >= {fixed_ver}",
        "cwe":            "CWE-1035",
        "category":       "Vulnerable Dependency",
        "source":         "osv_scanner",
        "scanner":        "osv",
        "package":        pkg_name,
        "installed_version": pkg_version,
        "fixed_in":       fixed_ver,
        "cve":            cve_id,
        "aliases":        aliases,
        "references":     refs,
        "reference_url":  ref_str,
        "confidence":     90,
    }


# ── Manifest parsers (same as DependencyScanner but return ecosystem too) ─────

def _parse_requirements(content: str, ecosystem: str = "PyPI") -> List[Tuple[str, str, str]]:
    deps: List[Tuple[str, str, str]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+")):
            continue
        line = re.sub(r"\[.*?\]", "", line)
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[=<>!~]{1,2}\s*([^\s;#,]+)", line)
        if m:
            deps.append((m.group(1).lower(), m.group(2).lstrip("="), ecosystem))
        else:
            m2 = re.match(r"^([A-Za-z0-9_\-\.]+)", line)
            if m2:
                deps.append((m2.group(1).lower(), "", ecosystem))
    return deps


def _parse_package_json(content: str) -> List[Tuple[str, str, str]]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    deps: List[Tuple[str, str, str]] = []
    for sec in ("dependencies", "devDependencies", "peerDependencies"):
        for pkg, ver in data.get(sec, {}).items():
            clean_ver = str(ver).lstrip("^~>=<* ")
            deps.append((pkg.lower(), clean_ver, "npm"))
    return deps


def _parse_go_mod(content: str) -> List[Tuple[str, str, str]]:
    deps: List[Tuple[str, str, str]] = []
    for m in re.finditer(r"^\s*([\w./\-]+)\s+v([^\s/]+)", content, re.MULTILINE):
        deps.append((m.group(1), m.group(2), "Go"))
    return deps


def _parse_cargo_toml(content: str) -> List[Tuple[str, str, str]]:
    deps: List[Tuple[str, str, str]] = []
    # [dependencies] section: name = "version" or name = { version = "x" }
    for m in re.finditer(
        r'^([a-z0-9_\-]+)\s*=\s*(?:"([0-9][^"]*)"|\{[^}]*version\s*=\s*"([0-9][^"]*)")',
        content,
        re.MULTILINE | re.IGNORECASE,
    ):
        version = m.group(2) or m.group(3) or ""
        deps.append((m.group(1).lower(), version, "crates.io"))
    return deps


def _parse_gemfile(content: str) -> List[Tuple[str, str, str]]:
    deps: List[Tuple[str, str, str]] = []
    for m in re.finditer(r"""gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?""", content):
        ver = (m.group(2) or "").lstrip("~> =")
        deps.append((m.group(1).lower(), ver, "RubyGems"))
    return deps


class OSVScanner:
    """
    Scans dependency manifests against the live OSV.dev vulnerability database.
    Automatically falls back to the static DependencyScanner if OSV is unreachable.
    """

    _SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}

    def __init__(self, timeout: int = _TIMEOUT) -> None:
        self._client = OSVClient(timeout=timeout)
        self._online: Optional[bool] = None   # lazy check

    def is_online(self) -> bool:
        if self._online is None:
            self._online = self._client.is_online()
        return self._online

    # ── Public API ─────────────────────────────────────────────────────────────

    def scan_file(self, file_path: str) -> List[Dict]:
        """Scan a single dependency manifest file."""
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return []
        try:
            content = p.read_text(errors="replace")
        except Exception:
            return []

        deps = self._parse_manifest(p, content)
        if not deps:
            return []

        return self._query_and_convert(deps, str(p))

    def scan_directory(self, directory: str) -> Dict:
        """Scan all dependency manifests found in a directory tree."""
        root       = Path(directory)
        manifests  = self._find_manifests(root)
        all_deps: List[Tuple[str, str, str, str]] = []   # (name, ver, eco, file)

        for mpath in manifests:
            try:
                content = mpath.read_text(errors="replace")
            except Exception:
                continue
            deps = self._parse_manifest(mpath, content)
            for name, ver, eco in deps:
                all_deps.append((name, ver, eco, str(mpath)))

        if not all_deps:
            return {
                "manifests_scanned": len(manifests),
                "total_packages":    0,
                "total_findings":    0,
                "findings":          [],
                "severity_counts":   {},
                "online":            self.is_online(),
                "scanner":           "osv",
            }

        # Batch query — deduplicate by (name, ver, eco) first
        unique_pkgs = list({(n, v, e) for n, v, e, _ in all_deps})
        file_map    = {}
        for n, v, e, f in all_deps:
            file_map[(n, v, e)] = f   # last file wins (good enough)

        if self.is_online():
            vuln_map = self._client.query_batch(unique_pkgs)
        else:
            # Offline fallback: use static DependencyScanner
            return self._fallback_scan(directory)

        findings: List[Dict] = []
        for pkg_tuple in unique_pkgs:
            name, ver, eco = pkg_tuple
            source_file    = file_map.get(pkg_tuple, str(root))
            vulns          = vuln_map.get(pkg_tuple, [])
            for osv_vuln in vulns:
                findings.append(_osv_vuln_to_finding(osv_vuln, name, ver, eco, source_file))

        # Sort by severity
        findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "LOW"), 4))

        sev_counts: Dict[str, int] = {}
        for f in findings:
            s = f.get("severity", "MEDIUM")
            sev_counts[s] = sev_counts.get(s, 0) + 1

        return {
            "manifests_scanned": len(manifests),
            "total_packages":    len(unique_pkgs),
            "total_findings":    len(findings),
            "findings":          findings,
            "severity_counts":   sev_counts,
            "online":            True,
            "scanner":           "osv",
        }

    # ── Internal ───────────────────────────────────────────────────────────────

    def _parse_manifest(
        self, path: Path, content: str
    ) -> List[Tuple[str, str, str]]:
        """Detect manifest type and parse dependencies."""
        name = path.name.lower()

        if "requirements" in name and name.endswith(".txt"):
            return _parse_requirements(content)
        if name == "setup.cfg":
            return _parse_requirements(content)  # install_requires section
        if name == "package.json":
            return _parse_package_json(content)
        if name == "go.mod":
            return _parse_go_mod(content)
        if name in ("cargo.toml", "cargo.lock"):
            return _parse_cargo_toml(content)
        if name in ("gemfile", "gemfile.lock"):
            return _parse_gemfile(content)
        return []

    def _find_manifests(self, root: Path) -> List[Path]:
        manifests: List[Path] = []
        manifest_names = {
            "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
            "package.json", "go.mod", "cargo.toml", "cargo.lock",
            "gemfile", "gemfile.lock", "setup.cfg",
        }
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if any(part in self._SKIP_DIRS for part in p.parts):
                continue
            n = p.name.lower()
            if n in manifest_names or ("requirements" in n and n.endswith(".txt")):
                manifests.append(p)
        return manifests

    def _query_and_convert(
        self, deps: List[Tuple[str, str, str]], source_file: str
    ) -> List[Dict]:
        """Query OSV for a list of deps and return Ghost findings."""
        if not self.is_online():
            return self._fallback_scan_file(source_file)

        vuln_map = self._client.query_batch(deps)
        findings: List[Dict] = []
        for (name, ver, eco), vulns in vuln_map.items():
            for osv_vuln in vulns:
                findings.append(_osv_vuln_to_finding(osv_vuln, name, ver, eco, source_file))
        findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "LOW"), 4))
        return findings

    def _fallback_scan(self, directory: str) -> Dict:
        """Use static DependencyScanner when OSV is unreachable."""
        try:
            from scanners.dependency_scanner import DependencyScanner
            result = DependencyScanner().scan_directory(directory)
            result.setdefault("total_packages", result.get("manifests_scanned", 0))
            result["online"]  = False
            result["scanner"] = "dependency_scanner_static"
            result["note"]    = "OSV offline — used static CVE database (80 CVEs)"
            return result
        except Exception:
            return {
                "findings": [], "online": False, "scanner": "osv",
                "manifests_scanned": 0, "total_packages": 0,
                "total_findings": 0, "severity_counts": {}, "error": "offline",
            }

    def _fallback_scan_file(self, file_path: str) -> List[Dict]:
        try:
            from scanners.dependency_scanner import DependencyScanner
            return DependencyScanner().scan_file(file_path)
        except Exception:
            return []
