"""
TythanAI — License Compliance Scanner v1.0

Scans project dependency manifests and classifies each dependency's license
against a risk taxonomy relevant to commercial SaaS companies.

Risk taxonomy:
  BLOCKED        (CRITICAL) — viral in commercial SaaS: AGPL-3.0, SSPL-1.0, BUSL-1.1, Commons-Clause
  COPYLEFT_STRONG (HIGH)   — requires open-sourcing linked code: GPL-2.0, GPL-3.0
  COPYLEFT_WEAK   (MEDIUM) — requires sharing modifications: LGPL-*, MPL-2.0, EPL-2.0
  PERMISSIVE      (INFO)   — safe for commercial use: MIT, Apache-2.0, BSD-*, ISC, etc.
  UNKNOWN         (MEDIUM) — no license info found

Usage:
    from scanners.license_scanner import LicenseScanner
    scanner = LicenseScanner()
    report  = scanner.scan_directory("/path/to/project")
    print(report["risk_counts"])
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Risk taxonomy
# ---------------------------------------------------------------------------

BLOCKED         = "BLOCKED"
COPYLEFT_STRONG = "COPYLEFT_STRONG"
COPYLEFT_WEAK   = "COPYLEFT_WEAK"
PERMISSIVE      = "PERMISSIVE"
UNKNOWN         = "UNKNOWN"

_RISK_SEVERITY: Dict[str, str] = {
    BLOCKED:         "CRITICAL",
    COPYLEFT_STRONG: "HIGH",
    COPYLEFT_WEAK:   "MEDIUM",
    PERMISSIVE:      "INFO",
    UNKNOWN:         "MEDIUM",
}

_RISK_DESCRIPTION: Dict[str, str] = {
    BLOCKED: (
        "This license forbids use in closed-source commercial SaaS products. "
        "Shipping this dependency may require open-sourcing your entire platform "
        "or obtaining a commercial license from the copyright holder."
    ),
    COPYLEFT_STRONG: (
        "Strong copyleft: any code statically or dynamically linked to this "
        "library must be released under the same license. This is incompatible "
        "with proprietary commercial software unless you obtain a dual license."
    ),
    COPYLEFT_WEAK: (
        "Weak copyleft: modifications to the library itself must be shared, but "
        "your application code is not automatically affected. Evaluate carefully "
        "for static linking scenarios."
    ),
    PERMISSIVE: (
        "Permissive license — safe for commercial use with attribution. "
        "Ensure license notices are included in your distribution."
    ),
    UNKNOWN: (
        "No license information could be determined from the manifest. "
        "Treat as proprietary until legal clearance is obtained."
    ),
}

_RISK_RECOMMENDATION: Dict[str, str] = {
    BLOCKED: (
        "Remove or replace this dependency immediately. If no alternative exists, "
        "obtain a commercial license from the copyright holder before shipping."
    ),
    COPYLEFT_STRONG: (
        "Replace with a permissively-licensed alternative or obtain a commercial "
        "dual-license from the project maintainers."
    ),
    COPYLEFT_WEAK: (
        "Prefer dynamic linking to limit copyleft scope. Consult legal counsel "
        "before shipping. Consider replacing with a permissively-licensed alternative."
    ),
    PERMISSIVE: (
        "Include the license notice in your product's open-source disclosures."
    ),
    UNKNOWN: (
        "Investigate the package's license before use. Check the upstream repository, "
        "PyPI/npm registry, or contact the maintainer."
    ),
}

# Normalized SPDX id → risk level
_LICENSE_RISK: Dict[str, str] = {
    # ── BLOCKED ───────────────────────────────────────────────────────────────
    "AGPL-3.0":        BLOCKED,
    "AGPL-3.0-only":   BLOCKED,
    "AGPL-3.0-or-later": BLOCKED,
    "SSPL-1.0":        BLOCKED,
    "BUSL-1.1":        BLOCKED,
    "Commons-Clause":  BLOCKED,
    # ── COPYLEFT_STRONG ───────────────────────────────────────────────────────
    "GPL-2.0":         COPYLEFT_STRONG,
    "GPL-2.0-only":    COPYLEFT_STRONG,
    "GPL-2.0-or-later": COPYLEFT_STRONG,
    "GPL-3.0":         COPYLEFT_STRONG,
    "GPL-3.0-only":    COPYLEFT_STRONG,
    "GPL-3.0-or-later": COPYLEFT_STRONG,
    # ── COPYLEFT_WEAK ─────────────────────────────────────────────────────────
    "LGPL-2.1":        COPYLEFT_WEAK,
    "LGPL-2.1-only":   COPYLEFT_WEAK,
    "LGPL-2.1-or-later": COPYLEFT_WEAK,
    "LGPL-3.0":        COPYLEFT_WEAK,
    "LGPL-3.0-only":   COPYLEFT_WEAK,
    "LGPL-3.0-or-later": COPYLEFT_WEAK,
    "MPL-2.0":         COPYLEFT_WEAK,
    "EPL-2.0":         COPYLEFT_WEAK,
    "EPL-1.0":         COPYLEFT_WEAK,
    "EUPL-1.1":        COPYLEFT_WEAK,
    "EUPL-1.2":        COPYLEFT_WEAK,
    # ── PERMISSIVE ────────────────────────────────────────────────────────────
    "MIT":             PERMISSIVE,
    "MIT-0":           PERMISSIVE,
    "Apache-2.0":      PERMISSIVE,
    "BSD-2-Clause":    PERMISSIVE,
    "BSD-3-Clause":    PERMISSIVE,
    "BSD-4-Clause":    PERMISSIVE,
    "ISC":             PERMISSIVE,
    "Unlicense":       PERMISSIVE,
    "CC0-1.0":         PERMISSIVE,
    "0BSD":            PERMISSIVE,
    "WTFPL":           PERMISSIVE,
    "Zlib":            PERMISSIVE,
    "PSF-2.0":         PERMISSIVE,
    "Python-2.0":      PERMISSIVE,
    "Artistic-2.0":    PERMISSIVE,
    "BlueOak-1.0.0":   PERMISSIVE,
}

# ---------------------------------------------------------------------------
# License normalisation
# ---------------------------------------------------------------------------

# Patterns for common verbose license strings → SPDX short identifier
_NORMALIZE_MAP: List[Tuple[re.Pattern, str]] = [
    # AGPL — must come before GPL patterns to avoid partial match
    (re.compile(r"agpl[\s\-\.]*v?\.?\s*3", re.I),         "AGPL-3.0"),
    (re.compile(r"affero.*general.*public.*3", re.I),      "AGPL-3.0"),
    # LGPL — must come before GPL to avoid catching "lgpl" with the GPL rule
    (re.compile(r"lgpl[\s\-\.]*v?\.?\s*2\.?1.*or.?later", re.I), "LGPL-2.1-or-later"),
    (re.compile(r"lgpl[\s\-\.]*v?\.?\s*2\.?1", re.I),    "LGPL-2.1"),
    (re.compile(r"lgpl[\s\-\.]*v?\.?\s*3.*or.?later", re.I),     "LGPL-3.0-or-later"),
    (re.compile(r"lgpl[\s\-\.]*v?\.?\s*3", re.I),         "LGPL-3.0"),
    (re.compile(r"lesser\s+general\s+public.*2\.?1", re.I), "LGPL-2.1"),
    (re.compile(r"lesser\s+general\s+public.*3", re.I),   "LGPL-3.0"),
    # GPL
    (re.compile(r"\bgpl[\s\-\.]*v?\.?\s*2.*or.?later", re.I), "GPL-2.0-or-later"),
    (re.compile(r"\bgpl[\s\-\.]*v?\.?\s*2", re.I),        "GPL-2.0"),
    (re.compile(r"\bgpl[\s\-\.]*v?\.?\s*3.*or.?later", re.I), "GPL-3.0-or-later"),
    (re.compile(r"\bgpl[\s\-\.]*v?\.?\s*3", re.I),        "GPL-3.0"),
    (re.compile(r"\bgnu\s+general\s+public.*v?\.?\s*3", re.I), "GPL-3.0"),
    (re.compile(r"\bgnu\s+general\s+public.*v?\.?\s*2", re.I), "GPL-2.0"),
    # MPL / EPL / EUPL
    (re.compile(r"mpl.?2\.?0", re.I),                 "MPL-2.0"),
    (re.compile(r"mozilla\s+public.*2", re.I),         "MPL-2.0"),
    (re.compile(r"epl.?2\.?0", re.I),                 "EPL-2.0"),
    (re.compile(r"epl.?1\.?0", re.I),                 "EPL-1.0"),
    (re.compile(r"eupl.?1\.2", re.I),                  "EUPL-1.2"),
    (re.compile(r"eupl.?1\.1", re.I),                  "EUPL-1.1"),
    # SSPL / BUSL / Commons-Clause
    (re.compile(r"sspl", re.I),                        "SSPL-1.0"),
    (re.compile(r"busl", re.I),                        "BUSL-1.1"),
    (re.compile(r"commons.?clause", re.I),             "Commons-Clause"),
    # Permissive
    (re.compile(r"\bmit\b", re.I),                     "MIT"),
    (re.compile(r"apache.?2\.?0", re.I),               "Apache-2.0"),
    (re.compile(r"apache\s+license.*2", re.I),         "Apache-2.0"),
    (re.compile(r"bsd.?2", re.I),                      "BSD-2-Clause"),
    (re.compile(r"bsd.?3", re.I),                      "BSD-3-Clause"),
    (re.compile(r"bsd.?4", re.I),                      "BSD-4-Clause"),
    (re.compile(r"\bisc\b", re.I),                     "ISC"),
    (re.compile(r"unlicense", re.I),                   "Unlicense"),
    (re.compile(r"cc0", re.I),                         "CC0-1.0"),
    (re.compile(r"public\s+domain", re.I),             "CC0-1.0"),
    (re.compile(r"\bzlib\b", re.I),                    "Zlib"),
    (re.compile(r"python\s+software\s+foundation", re.I), "PSF-2.0"),
    (re.compile(r"\bpsf\b", re.I),                    "PSF-2.0"),
]


def _normalize_license(s: str) -> str:
    """
    Normalize a free-form license string to an SPDX short identifier.

    Examples:
        "MIT License"               → "MIT"
        "Apache License 2.0"        → "Apache-2.0"
        "GNU General Public License v3" → "GPL-3.0"
        "AGPL v3"                   → "AGPL-3.0"

    Returns the original string stripped if no pattern matches.
    """
    if not s:
        return ""
    s = s.strip()
    # Exact match first (already an SPDX id)
    if s in _LICENSE_RISK:
        return s
    for pattern, spdx_id in _NORMALIZE_MAP:
        if pattern.search(s):
            return spdx_id
    # Remove common suffixes and retry exact match
    cleaned = re.sub(r"\s*(license|licence|version|v\.?)\s*", " ", s, flags=re.I).strip()
    if cleaned in _LICENSE_RISK:
        return cleaned
    return s.strip()


# ---------------------------------------------------------------------------
# Per-ecosystem parsers
# ---------------------------------------------------------------------------

def _parse_package_json_license(file_path: str) -> Optional[str]:
    """Read the 'license' field from a package.json file."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
        lic = data.get("license") or data.get("licenses")
        if isinstance(lic, list):
            # Some older packages use [{"type": "MIT", ...}]
            types = [
                (item.get("type") or item) if isinstance(item, dict) else item
                for item in lic
            ]
            return " OR ".join(str(t) for t in types if t)
        return str(lic) if lic else None
    except Exception:
        return None


def _parse_cargo_toml_license(file_path: str) -> Optional[str]:
    """Read the 'license' field from a Cargo.toml [package] section."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        # Find the [package] section and look for license =
        in_package = False
        for line in content.splitlines():
            stripped = line.strip()
            if re.match(r"^\[package\]", stripped):
                in_package = True
                continue
            if in_package and re.match(r"^\[", stripped):
                break  # entered a different section
            if in_package:
                m = re.match(r'^license\s*=\s*["\']([^"\']+)["\']', stripped)
                if m:
                    return m.group(1)
        return None
    except Exception:
        return None


def _parse_go_mod_license(file_path: str) -> Optional[str]:
    """
    go.mod doesn't carry license data; scan for a LICENSE file in the same
    directory and read the first line to guess the license type.
    """
    try:
        go_dir = Path(file_path).parent
        for candidate in ("LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE", "COPYING"):
            lpath = go_dir / candidate
            if lpath.exists():
                first_lines = lpath.read_text(encoding="utf-8", errors="replace")[:500]
                # Heuristic extraction of license type from file header
                for line in first_lines.splitlines():
                    line = line.strip()
                    if line:
                        return line  # return first non-empty line for normalisation
                return None
        return None
    except Exception:
        return None


def _parse_setup_py_license(file_path: str) -> Optional[str]:
    """Extract the license= argument from a setup() call in setup.py."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        m = re.search(r"license\s*=\s*['\"]([^'\"]+)['\"]", content, re.I)
        return m.group(1) if m else None
    except Exception:
        return None


def _parse_setup_cfg_license(file_path: str) -> Optional[str]:
    """Read license= from the [metadata] section of setup.cfg."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        in_metadata = False
        for line in content.splitlines():
            stripped = line.strip()
            if re.match(r"^\[metadata\]", stripped, re.I):
                in_metadata = True
                continue
            if in_metadata and re.match(r"^\[", stripped):
                break
            if in_metadata:
                m = re.match(r"^license\s*=\s*(.+)", stripped, re.I)
                if m:
                    return m.group(1).strip()
        return None
    except Exception:
        return None


def _parse_pyproject_toml_license(file_path: str) -> Optional[str]:
    """
    Read license from pyproject.toml.
    Supports both [project] (PEP 621) and [tool.poetry] styles.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()

        # Try [project] section (PEP 621): license = {text = "MIT"} or license = "MIT"
        # Look for [project] block
        project_block = re.search(
            r"\[project\](.*?)(?=^\[|\Z)", content, re.S | re.M
        )
        if project_block:
            block = project_block.group(1)
            # license = {text = "..."}
            m = re.search(r'license\s*=\s*\{[^}]*text\s*=\s*["\']([^"\']+)["\']', block, re.I)
            if m:
                return m.group(1)
            # license = {file = "..."} — skip, we'd need to read another file
            # license = "MIT" (inline string)
            m = re.search(r'^license\s*=\s*["\']([^"\']+)["\']', block, re.M | re.I)
            if m:
                return m.group(1)

        # Try [tool.poetry] section
        poetry_block = re.search(
            r"\[tool\.poetry\](.*?)(?=^\[|\Z)", content, re.S | re.M
        )
        if poetry_block:
            block = poetry_block.group(1)
            m = re.search(r'^license\s*=\s*["\']([^"\']+)["\']', block, re.M | re.I)
            if m:
                return m.group(1)

        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Cargo.toml dependency extraction
# ---------------------------------------------------------------------------

def _extract_cargo_packages(file_path: str) -> List[Tuple[str, str]]:
    """
    Parse Cargo.toml and return list of (name, version) for each dependency.
    Handles both simple string and table-style entries.
    """
    packages: List[Tuple[str, str]] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()

        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if re.match(r"^\[(dependencies|dev-dependencies|build-dependencies)\]", stripped, re.I):
                in_deps = True
                continue
            if stripped.startswith("[") and in_deps:
                in_deps = False

            if not in_deps or not stripped or stripped.startswith("#"):
                continue

            # name = "version"
            m = re.match(r'^([a-zA-Z0-9_\-]+)\s*=\s*"([^"]*)"', stripped)
            if m:
                packages.append((m.group(1), m.group(2).lstrip("^~><=! ")))
                continue

            # name = { version = "...", ... }
            m = re.match(r'^([a-zA-Z0-9_\-]+)\s*=\s*\{', stripped)
            if m:
                name = m.group(1)
                vm = re.search(r'version\s*=\s*"([^"]*)"', stripped)
                version = vm.group(1).lstrip("^~><=! ") if vm else ""
                packages.append((name, version))
    except Exception:
        pass
    return packages


# ---------------------------------------------------------------------------
# Main Scanner class
# ---------------------------------------------------------------------------

class LicenseScanner:
    """
    Scans project dependency manifests and classifies license risk.

    Supported manifests:
        package.json, Cargo.toml, setup.py, setup.cfg, pyproject.toml
        (requirements.txt is detected but skipped — PyPI metadata lookup required)
    """

    _SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv",
                  "vendor", "third_party", "dist", "build", ".tox"}

    def scan_directory(self, directory: str) -> Dict:
        """
        Walk a project directory, find manifest files, extract packages and
        license data, and classify each by risk level.

        Returns a report dict with keys:
            files_scanned    — number of manifest files processed
            packages_found   — total packages extracted across all manifests
            findings         — list of BLOCKED and COPYLEFT-level findings
            license_summary  — {license_name: count} across all packages
            risk_counts      — {BLOCKED|COPYLEFT_STRONG|COPYLEFT_WEAK|PERMISSIVE|UNKNOWN: N}
            scanner          — "license"
        """
        root = Path(directory)
        files_scanned = 0
        all_package_records: List[Dict] = []  # {name, version, license, risk, file}

        target_names = {
            "package.json", "cargo.toml", "setup.py",
            "setup.cfg", "pyproject.toml",
        }

        for dirpath, dirnames, filenames in os.walk(root):
            # Prune skipped directories in-place to avoid descending into them
            dirnames[:] = [
                d for d in dirnames
                if d not in self._SKIP_DIRS and not d.startswith(".")
            ]
            for fname in filenames:
                if fname.lower() not in target_names:
                    continue
                file_path = os.path.join(dirpath, fname)
                fname_lower = fname.lower()

                records: List[Dict] = []
                if fname_lower == "package.json":
                    records = self._records_from_package_json(file_path)
                elif fname_lower == "cargo.toml":
                    records = self._records_from_cargo_toml(file_path)
                elif fname_lower == "pyproject.toml":
                    records = self._records_from_pyproject_toml(file_path)
                elif fname_lower == "setup.py":
                    records = self._records_from_setup_py(file_path)
                elif fname_lower == "setup.cfg":
                    records = self._records_from_setup_cfg(file_path)

                if records:
                    files_scanned += 1
                    all_package_records.extend(records)

        # Build aggregates
        license_summary: Dict[str, int] = {}
        risk_counts: Dict[str, int] = {
            BLOCKED: 0, COPYLEFT_STRONG: 0, COPYLEFT_WEAK: 0,
            PERMISSIVE: 0, UNKNOWN: 0,
        }
        findings: List[Dict] = []

        for rec in all_package_records:
            lic_key = rec["license_normalized"] or "UNKNOWN"
            license_summary[lic_key] = license_summary.get(lic_key, 0) + 1
            risk = rec["risk"]
            risk_counts[risk] = risk_counts.get(risk, 0) + 1

            # Only emit findings for actionable risk levels
            if risk in (BLOCKED, COPYLEFT_STRONG, COPYLEFT_WEAK):
                findings.append(self._make_finding(rec))

        return {
            "files_scanned":   files_scanned,
            "packages_found":  len(all_package_records),
            "findings":        findings,
            "license_summary": license_summary,
            "risk_counts":     risk_counts,
            "scanner":         "license",
        }

    # ── Public per-file scan helpers ──────────────────────────────────────────

    def scan_package_json(self, file_path: str) -> List[Dict]:
        """Return license findings for a single package.json file."""
        return [
            self._make_finding(r)
            for r in self._records_from_package_json(file_path)
            if r["risk"] in (BLOCKED, COPYLEFT_STRONG, COPYLEFT_WEAK)
        ]

    def scan_cargo_toml(self, file_path: str) -> List[Dict]:
        """Return license findings for a single Cargo.toml file."""
        return [
            self._make_finding(r)
            for r in self._records_from_cargo_toml(file_path)
            if r["risk"] in (BLOCKED, COPYLEFT_STRONG, COPYLEFT_WEAK)
        ]

    def scan_pyproject_toml(self, file_path: str) -> List[Dict]:
        """Return license findings for a single pyproject.toml file."""
        return [
            self._make_finding(r)
            for r in self._records_from_pyproject_toml(file_path)
            if r["risk"] in (BLOCKED, COPYLEFT_STRONG, COPYLEFT_WEAK)
        ]

    # ── Internal record builders ───────────────────────────────────────────────

    def _classify(self, raw_license: Optional[str]) -> Tuple[str, str]:
        """
        Returns (normalized_license, risk_level).
        """
        if not raw_license or not raw_license.strip():
            return ("", UNKNOWN)
        normalized = _normalize_license(raw_license)
        risk = _LICENSE_RISK.get(normalized, UNKNOWN)
        return (normalized, risk)

    def _make_record(
        self,
        name: str,
        version: str,
        raw_license: Optional[str],
        file_path: str,
    ) -> Dict:
        """Build an internal package record dict."""
        norm, risk = self._classify(raw_license)
        return {
            "name":               name,
            "version":            version or "unknown",
            "license_raw":        raw_license or "",
            "license_normalized": norm,
            "risk":               risk,
            "file":               file_path,
        }

    def _make_finding(self, rec: Dict) -> Dict:
        """Convert an internal package record to a Ghost finding dict."""
        risk  = rec["risk"]
        norm  = rec["license_normalized"] or rec["license_raw"] or "UNKNOWN"
        sev   = _RISK_SEVERITY[risk]
        name  = rec["name"]
        ver   = rec["version"]
        file_ = rec["file"]

        # finding id: LIC-BLOCKED, LIC-COPYLEFT_STRONG, LIC-COPYLEFT_WEAK
        if risk == BLOCKED:
            finding_id = "LIC-BLOCKED"
        elif risk in (COPYLEFT_STRONG, COPYLEFT_WEAK):
            finding_id = f"LIC-COPYLEFT"
        else:
            finding_id = f"LIC-{risk}"

        return {
            "type":            "LICENSE_RISK",
            "id":              finding_id,
            "severity":        sev,
            "cwe":             "CWE-1104",
            "file":            file_,
            "line":            0,
            "message":         f"Package {name} uses {norm} — {risk}",
            "description":     _RISK_DESCRIPTION[risk],
            "evidence":        f"{name}=={ver} [{norm}]",
            "recommendation":  _RISK_RECOMMENDATION[risk],
            "source":          "license_scanner",
            "scanner":         "license",
            "confidence":      85,
            "package":         name,
            "version":         ver,
            "license":         norm,
            "risk_level":      risk,
        }

    # ── Per-manifest record builders ──────────────────────────────────────────

    def _records_from_package_json(self, file_path: str) -> List[Dict]:
        """Extract package + license records from package.json."""
        records: List[Dict] = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except Exception:
            return records

        # Root package itself
        root_name    = data.get("name", Path(file_path).parent.name)
        root_version = data.get("version", "unknown")
        root_license = data.get("license") or data.get("licenses")
        if isinstance(root_license, list):
            root_license = " OR ".join(
                (item.get("type") if isinstance(item, dict) else str(item))
                for item in root_license
            )
        if root_license:
            records.append(self._make_record(root_name, root_version, str(root_license), file_path))

        # Dependencies listed in the manifest (no license info available here —
        # we'd need node_modules/<pkg>/package.json, so we skip version-only deps)
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for pkg_name, ver_spec in data.get(section, {}).items():
                # Attempt to read installed license from node_modules
                nm_pkg_json = (
                    Path(file_path).parent / "node_modules" / pkg_name / "package.json"
                )
                pkg_license: Optional[str] = None
                if nm_pkg_json.exists():
                    pkg_license = _parse_package_json_license(str(nm_pkg_json))
                records.append(
                    self._make_record(
                        pkg_name,
                        str(ver_spec).lstrip("^~>=<! "),
                        pkg_license,
                        file_path,
                    )
                )
        return records

    def _records_from_cargo_toml(self, file_path: str) -> List[Dict]:
        """Extract package + license records from Cargo.toml."""
        records: List[Dict] = []
        # Root package license
        root_license = _parse_cargo_toml_license(file_path)
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            root_name_m    = re.search(r'^\s*name\s*=\s*"([^"]+)"', content, re.M)
            root_version_m = re.search(r'^\s*version\s*=\s*"([^"]+)"', content, re.M)
            root_name    = root_name_m.group(1)    if root_name_m    else Path(file_path).parent.name
            root_version = root_version_m.group(1) if root_version_m else "unknown"
        except Exception:
            root_name, root_version = Path(file_path).parent.name, "unknown"

        if root_license:
            records.append(self._make_record(root_name, root_version, root_license, file_path))

        # Dependency packages (Cargo.lock would give exact versions; here we use Cargo.toml)
        for dep_name, dep_version in _extract_cargo_packages(file_path):
            # Check if a Cargo.lock exists for exact version
            records.append(self._make_record(dep_name, dep_version, None, file_path))

        return records

    def _records_from_pyproject_toml(self, file_path: str) -> List[Dict]:
        """Extract package + license records from pyproject.toml."""
        records: List[Dict] = []
        raw_license = _parse_pyproject_toml_license(file_path)

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()

            # Project name and version from [project] or [tool.poetry]
            project_block = re.search(r"\[project\](.*?)(?=^\[|\Z)", content, re.S | re.M)
            poetry_block  = re.search(r"\[tool\.poetry\](.*?)(?=^\[|\Z)", content, re.S | re.M)

            name, version = "", ""
            for block in filter(None, [project_block, poetry_block]):
                b = block.group(1)
                nm = re.search(r'^name\s*=\s*["\']([^"\']+)["\']', b, re.M)
                vm = re.search(r'^version\s*=\s*["\']([^"\']+)["\']', b, re.M)
                if nm and not name:
                    name = nm.group(1)
                if vm and not version:
                    version = vm.group(1)

            name    = name    or Path(file_path).parent.name
            version = version or "unknown"

            if raw_license:
                records.append(self._make_record(name, version, raw_license, file_path))

            # Dependencies from [project].dependencies (PEP 621 format)
            if project_block:
                block_text = project_block.group(1)
                dep_section = re.search(
                    r"^dependencies\s*=\s*\[(.*?)\]", block_text, re.S | re.M
                )
                if dep_section:
                    for dep_raw in re.findall(r'"([^"]+)"', dep_section.group(1)):
                        dep_m = re.match(r"([A-Za-z0-9_\-\.]+)(.*)", dep_raw)
                        if dep_m:
                            dep_name = dep_m.group(1)
                            dep_ver  = re.sub(r"[^0-9\.]", "", dep_m.group(2)).strip(".") or "unknown"
                            records.append(self._make_record(dep_name, dep_ver, None, file_path))

            # Dependencies from [tool.poetry.dependencies]
            poetry_deps_block = re.search(
                r"\[tool\.poetry\.dependencies\](.*?)(?=^\[|\Z)", content, re.S | re.M
            )
            if poetry_deps_block:
                for line in poetry_deps_block.group(1).splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    dep_m = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*["\^~]?([0-9][^"\s]*)', stripped)
                    if dep_m:
                        records.append(
                            self._make_record(dep_m.group(1), dep_m.group(2), None, file_path)
                        )

        except Exception:
            pass

        return records

    def _records_from_setup_py(self, file_path: str) -> List[Dict]:
        """Extract package + license record from setup.py."""
        raw_license = _parse_setup_py_license(file_path)
        if not raw_license:
            return []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            name_m    = re.search(r'name\s*=\s*["\']([^"\']+)["\']', content)
            version_m = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
            name    = name_m.group(1)    if name_m    else Path(file_path).parent.name
            version = version_m.group(1) if version_m else "unknown"
        except Exception:
            name, version = Path(file_path).parent.name, "unknown"
        return [self._make_record(name, version, raw_license, file_path)]

    def _records_from_setup_cfg(self, file_path: str) -> List[Dict]:
        """Extract package + license record from setup.cfg."""
        raw_license = _parse_setup_cfg_license(file_path)
        if not raw_license:
            return []
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            name_m    = re.search(r"^name\s*=\s*(.+)", content, re.M)
            version_m = re.search(r"^version\s*=\s*(.+)", content, re.M)
            name    = name_m.group(1).strip()    if name_m    else Path(file_path).parent.name
            version = version_m.group(1).strip() if version_m else "unknown"
        except Exception:
            name, version = Path(file_path).parent.name, "unknown"
        return [self._make_record(name, version, raw_license, file_path)]
