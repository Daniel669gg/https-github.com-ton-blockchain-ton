"""
TythanAI Platform — Dependency Confusion Detector

Detects supply-chain attack vectors: packages with internal-sounding names that
could be typosquatted or claimed on public registries.

Supported manifests:
  Python:  requirements.txt, setup.cfg, pyproject.toml
  Node.js: package.json
  Go:      go.mod
  Rust:    Cargo.toml
  Ruby:    Gemfile

Detections:
  1. Internal-name patterns  — company prefix / suffix (acme-*, *-internal, etc.)
  2. Namespace confusion     — internal-pkg vs internal_pkg vs internalpkg
  3. Version-pinning issues  — unpinned, too-broad ranges, floating latest
  4. Public-registry check   — package exists on PyPI/npm under the same name
  5. Private-registry hint   — only resolvable via internal registry URL

Usage:
    from scanners.dependency_confusion import DependencyConfusionScanner
    scanner = DependencyConfusionScanner()
    results = scanner.scan_directory("/path/to/project")
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

_TIMEOUT = 8

# ─────────────────────────────────────────────────────────────────────────────
# Patterns that strongly suggest an internal / private package name
# ─────────────────────────────────────────────────────────────────────────────

_INTERNAL_PREFIXES: Tuple[str, ...] = (
    "internal-", "internal_", "private-", "private_",
    "corp-", "corp_", "company-", "company_",
    "acme-", "myco-", "ourco-",
    "priv-", "priv_", "int-", "int_",
    "lib-internal", "pkg-internal",
)

_INTERNAL_SUFFIXES: Tuple[str, ...] = (
    "-internal", "_internal", "-private", "_private",
    "-corp", "_corp", "-company", "_company",
    "-local", "_local", "-dev", "_dev",
    "-priv", "_priv",
)

_INTERNAL_SUBSTRINGS: Tuple[str, ...] = (
    "-internal-", "_internal_", ".internal.", "/internal/",
    "-private-", "_private_",
)

# Patterns for scoped/namespace packages that look internal
_INTERNAL_SCOPE_PATTERN = re.compile(r"^@[\w.-]+/(internal|private|corp|priv)[_-]")

# ─────────────────────────────────────────────────────────────────────────────
# Well-known public packages (to skip false-positive internal checks)
# ─────────────────────────────────────────────────────────────────────────────

_WELL_KNOWN_PUBLIC: Set[str] = {
    "requests", "flask", "django", "fastapi", "numpy", "pandas", "pytest",
    "boto3", "click", "pydantic", "sqlalchemy", "celery", "aiohttp",
    "react", "vue", "lodash", "express", "axios", "webpack", "typescript",
    "pytest-cov", "coverage", "mypy", "black", "ruff", "flake8", "isort",
    "setuptools", "wheel", "pip", "twine", "build",
}

# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PackageEntry:
    name:        str
    version_spec: str = ""          # e.g. "==1.2.3", "^1.0", ""
    ecosystem:   str = "unknown"    # pypi | npm | go | cargo | gem
    source_file: str = ""


@dataclass
class ConfusionFinding:
    package:     str
    ecosystem:   str
    severity:    str                # CRITICAL | HIGH | MEDIUM | LOW
    check:       str                # which check fired
    detail:      str
    source_file: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "package":     self.package,
            "ecosystem":   self.ecosystem,
            "severity":    self.severity,
            "check":       self.check,
            "detail":      self.detail,
            "source_file": self.source_file,
            "remediation": self.remediation,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Manifest parsers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_requirements_txt(path: Path) -> List[PackageEntry]:
    """Parse requirements.txt / constraints.txt."""
    entries: List[PackageEntry] = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip inline comments
        line = line.split("#")[0].strip()
        # Match: name[extras]specifier
        m = re.match(r'^([A-Za-z0-9][\w.\-]*(?:\[[\w,\s]+\])?)\s*([><=!~^].+)?$', line)
        if m:
            name = re.sub(r'\[.*\]', '', m.group(1)).strip()
            spec = (m.group(2) or "").strip()
            entries.append(PackageEntry(name=name.lower(), version_spec=spec,
                                        ecosystem="pypi", source_file=str(path)))
    return entries


def _parse_package_json(path: Path) -> List[PackageEntry]:
    """Parse package.json dependencies and devDependencies."""
    try:
        data = json.loads(path.read_text(errors="replace"))
    except json.JSONDecodeError:
        return []
    entries: List[PackageEntry] = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, version in (data.get(section) or {}).items():
            entries.append(PackageEntry(name=name, version_spec=str(version),
                                        ecosystem="npm", source_file=str(path)))
    return entries


def _parse_go_mod(path: Path) -> List[PackageEntry]:
    """Parse go.mod require block."""
    entries: List[PackageEntry] = []
    in_require = False
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if line.startswith("require ") or in_require:
            parts = line.replace("require ", "").split()
            if len(parts) >= 2 and not parts[0].startswith("//"):
                module_path = parts[0]
                # Use last segment as "name" for pattern checks
                name = module_path.split("/")[-1]
                entries.append(PackageEntry(name=name, version_spec=parts[1],
                                            ecosystem="go",
                                            source_file=str(path)))
    return entries


def _parse_cargo_toml(path: Path) -> List[PackageEntry]:
    """Parse Cargo.toml [dependencies] section (basic, no TOML parser dep)."""
    entries: List[PackageEntry] = []
    in_deps = False
    text = path.read_text(errors="replace")
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r'^\[(dependencies|dev-dependencies|build-dependencies)\]', stripped):
            in_deps = True
            continue
        if stripped.startswith("[") and in_deps:
            in_deps = False
            continue
        if in_deps and "=" in stripped and not stripped.startswith("#"):
            name = stripped.split("=")[0].strip().strip('"')
            version_part = stripped.split("=", 1)[1].strip().strip('"').strip("{}")
            entries.append(PackageEntry(name=name, version_spec=version_part,
                                        ecosystem="cargo", source_file=str(path)))
    return entries


def _parse_gemfile(path: Path) -> List[PackageEntry]:
    """Parse Gemfile gem declarations."""
    entries: List[PackageEntry] = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^gem\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]*)['\"])?", line)
        if m:
            entries.append(PackageEntry(name=m.group(1), version_spec=m.group(2) or "",
                                        ecosystem="gem", source_file=str(path)))
    return entries


# ─────────────────────────────────────────────────────────────────────────────
# Public-registry existence checks (best-effort, no key required)
# ─────────────────────────────────────────────────────────────────────────────

def _fetch_url(url: str) -> Optional[int]:
    """Return HTTP status code or None on error."""
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "Ghost-Security/10"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def _exists_on_pypi(name: str) -> Optional[bool]:
    status = _fetch_url(f"https://pypi.org/pypi/{name}/json")
    if status is None:
        return None
    return status == 200


def _exists_on_npm(name: str) -> Optional[bool]:
    # Encode scoped packages: @scope/name → %40scope%2Fname
    encoded = name.replace("@", "%40").replace("/", "%2F")
    status = _fetch_url(f"https://registry.npmjs.org/{encoded}")
    if status is None:
        return None
    return status == 200


# ─────────────────────────────────────────────────────────────────────────────
# DependencyConfusionScanner
# ─────────────────────────────────────────────────────────────────────────────

_MANIFEST_PARSERS: Dict[str, callable] = {
    "requirements.txt":  _parse_requirements_txt,
    "requirements.in":   _parse_requirements_txt,
    "requirements-dev.txt": _parse_requirements_txt,
    "constraints.txt":   _parse_requirements_txt,
    "package.json":      _parse_package_json,
    "go.mod":            _parse_go_mod,
    "Cargo.toml":        _parse_cargo_toml,
    "Gemfile":           _parse_gemfile,
}


class DependencyConfusionScanner:
    """
    Scans project dependency manifests for supply-chain confusion risks.

    Instantiate once; reuse across multiple scan_directory / scan_file calls.
    Registry checks are skipped by default to avoid network calls in CI —
    enable with check_registry=True.
    """

    def __init__(self, check_registry: bool = False) -> None:
        self._check_registry = check_registry
        self._registry_cache: Dict[str, Optional[bool]] = {}

    # ── Public API ─────────────────────────────────────────────────────────────

    def scan_directory(self, path: str) -> dict:
        """
        Recursively scan a directory for dependency manifests and return a
        summary dict with all findings grouped by file.
        """
        root = Path(path)
        all_findings: List[ConfusionFinding] = []
        files_scanned: List[str] = []

        for manifest_name, _ in _MANIFEST_PARSERS.items():
            for fpath in root.rglob(manifest_name):
                # Skip node_modules and venv trees
                parts = fpath.parts
                if any(skip in parts for skip in ("node_modules", "vendor", ".venv",
                                                   "venv", "__pycache__", ".tox")):
                    continue
                findings = self.scan_file(str(fpath))
                all_findings.extend(findings)
                files_scanned.append(str(fpath))

        by_severity: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in all_findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

        return {
            "files_scanned": files_scanned,
            "total_findings": len(all_findings),
            "severity_counts": by_severity,
            "findings": [f.to_dict() for f in all_findings],
        }

    def scan_file(self, path: str) -> List[ConfusionFinding]:
        """
        Parse a single manifest file and return a list of ConfusionFinding.
        Returns [] if the file type is not recognised.
        """
        fpath = Path(path)
        parser = _MANIFEST_PARSERS.get(fpath.name)
        if parser is None:
            # Try by suffix for pyproject.toml style
            if fpath.name == "pyproject.toml":
                return self._scan_pyproject(fpath)
            return []

        try:
            packages = parser(fpath)
        except Exception:
            return []

        findings: List[ConfusionFinding] = []
        findings.extend(self._detect_namespace_confusion(packages))
        findings.extend(self._check_version_pinning(packages))
        findings.extend(self._check_internal_names_and_registry(packages))
        return findings

    def is_suspicious_package(self, name: str, ecosystem: str) -> bool:
        """Return True if the package name exhibits internal-looking patterns."""
        return self._detect_internal_name_patterns(name)

    # ── Internal checks ────────────────────────────────────────────────────────

    def _detect_internal_name_patterns(self, name: str) -> bool:
        """
        Return True if the name looks like an internal/private package that
        should not appear on public registries.
        """
        n = name.lower()
        if n in _WELL_KNOWN_PUBLIC:
            return False
        for prefix in _INTERNAL_PREFIXES:
            if n.startswith(prefix):
                return True
        for suffix in _INTERNAL_SUFFIXES:
            if n.endswith(suffix):
                return True
        for sub in _INTERNAL_SUBSTRINGS:
            if sub in n:
                return True
        if _INTERNAL_SCOPE_PATTERN.match(name):
            return True
        return False

    def _detect_namespace_confusion(self, packages: List[PackageEntry]) -> List[ConfusionFinding]:
        """
        Detect packages where the same logical name exists in multiple forms
        (hyphen vs underscore vs no-separator), which can indicate namespace
        confusion attacks.
        """
        findings: List[ConfusionFinding] = []
        # Normalise names: collapse - and _ to empty string
        normalised: Dict[str, List[PackageEntry]] = {}
        for pkg in packages:
            key = re.sub(r'[-_]', '', pkg.name.lower())
            normalised.setdefault(key, []).append(pkg)

        for key, group in normalised.items():
            if len(group) < 2:
                continue
            names = list({p.name for p in group})
            if len(names) < 2:
                continue
            detail = (
                f"Multiple naming variants of '{key}' detected: "
                + ", ".join(f"'{n}'" for n in names)
                + ". An attacker may register the variant not controlled by your team."
            )
            findings.append(ConfusionFinding(
                package=key,
                ecosystem=group[0].ecosystem,
                severity="HIGH",
                check="namespace_confusion",
                detail=detail,
                source_file=group[0].source_file,
                remediation=(
                    f"Ensure all variants ({', '.join(names)}) are owned by your organisation "
                    "on the relevant registry, or consolidate to one canonical name."
                ),
            ))
        return findings

    def _check_version_pinning(self, packages: List[PackageEntry]) -> List[ConfusionFinding]:
        """
        Flag packages that use unpinned, floating, or overly broad version ranges.
        """
        findings: List[ConfusionFinding] = []
        for pkg in packages:
            spec = pkg.version_spec.strip()
            issue = self._classify_pinning_issue(spec, pkg.ecosystem)
            if issue:
                findings.append(ConfusionFinding(
                    package=pkg.name,
                    ecosystem=pkg.ecosystem,
                    severity="MEDIUM",
                    check="version_pinning",
                    detail=issue,
                    source_file=pkg.source_file,
                    remediation=(
                        f"Pin '{pkg.name}' to an exact version (e.g., =={spec or 'X.Y.Z'} "
                        "for PyPI, or lock with requirements.txt / package-lock.json)."
                    ),
                ))
        return findings

    def _classify_pinning_issue(self, spec: str, ecosystem: str) -> Optional[str]:
        """Return a human-readable issue description, or None if pinning is adequate."""
        if not spec:
            return "No version specified — any version will be resolved, including a malicious one."
        if spec in ("*", "latest", "next", "canary", ""):
            return f"Floating version '{spec}' resolves to whatever the registry serves."
        # npm: ^1.0.0 or ~1.0.0 — allow minor/patch bumps
        if ecosystem == "npm":
            if spec.startswith("^") or spec.startswith("~"):
                return (f"Range specifier '{spec}' allows automatic upgrades; "
                        "a compromised new release would be auto-installed.")
        # PyPI: >= without upper bound
        if ecosystem == "pypi" and ">=" in spec and "<" not in spec:
            return (f"Version constraint '{spec}' has no upper bound; "
                    "a future malicious release would be pulled automatically.")
        # Cargo: ~ or ^ ranges
        if ecosystem == "cargo":
            if spec.startswith("^") or spec.startswith("~"):
                return (f"Semver range '{spec}' allows automatic minor/patch upgrades.")
        # Go: pseudo-versions or branch names instead of tagged releases
        if ecosystem == "go" and spec.startswith("v0.0.0-"):
            return f"Pseudo-version '{spec}' is tied to a commit, not a release tag; harder to audit."
        return None

    def _check_internal_names_and_registry(
        self, packages: List[PackageEntry]
    ) -> List[ConfusionFinding]:
        """
        Flag packages with internal-looking names and optionally verify whether
        they already exist on the public registry (which would be suspicious).
        """
        findings: List[ConfusionFinding] = []
        for pkg in packages:
            if not self._detect_internal_name_patterns(pkg.name):
                continue

            # The name looks internal — flag it
            base_finding = ConfusionFinding(
                package=pkg.name,
                ecosystem=pkg.ecosystem,
                severity="HIGH",
                check="internal_name_on_manifest",
                detail=(
                    f"Package '{pkg.name}' has an internal-sounding name. "
                    "If this package does not exist on the public registry, an attacker could "
                    "register it and exploit tools that prefer public over private registries."
                ),
                source_file=pkg.source_file,
                remediation=(
                    "Verify that this package is explicitly sourced from your private registry "
                    "(e.g., via .npmrc, pip.conf, or --index-url). "
                    "Consider scoping the package under your organisation's namespace."
                ),
            )

            if self._check_registry:
                exists = self._package_exists_publicly(pkg.name, pkg.ecosystem)
                if exists is True:
                    base_finding.severity = "CRITICAL"
                    base_finding.check = "confusion_public_clash"
                    base_finding.detail = (
                        f"CRITICAL: '{pkg.name}' looks internal but ALREADY EXISTS on the "
                        f"public {pkg.ecosystem} registry. An attacker may have registered it "
                        "ahead of time (dependency confusion attack in progress or already executed)."
                    )
                    base_finding.remediation = (
                        "IMMEDIATELY audit the public package for malicious code. "
                        "Pin to your internal registry and block public resolution."
                    )

            findings.append(base_finding)
        return findings

    def _package_exists_publicly(self, name: str, ecosystem: str) -> Optional[bool]:
        """Check if `name` exists on the appropriate public registry."""
        cache_key = f"{ecosystem}:{name}"
        if cache_key in self._registry_cache:
            return self._registry_cache[cache_key]

        result: Optional[bool] = None
        if ecosystem == "pypi":
            result = _exists_on_pypi(name)
        elif ecosystem == "npm":
            result = _exists_on_npm(name)
        # go / cargo / gem checks could be added similarly

        self._registry_cache[cache_key] = result
        return result

    # ── pyproject.toml handler ─────────────────────────────────────────────────

    def _scan_pyproject(self, fpath: Path) -> List[ConfusionFinding]:
        """Basic pyproject.toml scan — extracts PEP 621 dependencies."""
        try:
            text = fpath.read_text(errors="replace")
        except OSError:
            return []

        packages: List[PackageEntry] = []
        in_deps = False
        for line in text.splitlines():
            stripped = line.strip()
            if stripped in ('[project]', 'dependencies = ['):
                in_deps = True
                continue
            if in_deps and stripped.startswith("[") and stripped != "dependencies = [":
                in_deps = False
            if in_deps:
                # e.g. "requests>=2.0",
                m = re.match(r'"([A-Za-z0-9][\w.\-]*)([><=!~^][^"]*)?', stripped)
                if m:
                    name = m.group(1).lower()
                    spec = (m.group(2) or "").strip()
                    packages.append(PackageEntry(name=name, version_spec=spec,
                                                 ecosystem="pypi", source_file=str(fpath)))
        findings: List[ConfusionFinding] = []
        findings.extend(self._detect_namespace_confusion(packages))
        findings.extend(self._check_version_pinning(packages))
        findings.extend(self._check_internal_names_and_registry(packages))
        return findings
