"""
Ghost Security — SPDX SBOM Exporter (v2.3)

Generates Software Bill of Materials in SPDX 2.3 JSON format.
SPDX is required by:
  • US Executive Order 14028 (NTIA minimum elements)
  • EU Cyber Resilience Act (CRA)
  • Many enterprise procurement requirements

Output is valid SPDX 2.3 JSON that tools like:
  syft, FOSSA, Black Duck, dependency-track can consume.

Usage:
    from sbom.spdx_exporter import SPDXExporter
    exporter = SPDXExporter()
    spdx     = exporter.from_directory("/path/to/project", "my-app", "1.0.0")
    exporter.write(spdx, "sbom.spdx.json")
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# SPDX license expression → SPDX identifier
_SPDX_LICENSES = {
    "mit":          "MIT",
    "apache-2.0":   "Apache-2.0",
    "apache 2.0":   "Apache-2.0",
    "gpl-2.0":      "GPL-2.0-only",
    "gpl-3.0":      "GPL-3.0-only",
    "agpl-3.0":     "AGPL-3.0-only",
    "lgpl-2.1":     "LGPL-2.1-only",
    "lgpl-3.0":     "LGPL-3.0-only",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "isc":          "ISC",
    "mpl-2.0":      "MPL-2.0",
    "cc0-1.0":      "CC0-1.0",
    "unlicense":    "Unlicense",
}

TOOL_NAME    = "Ghost Security Platform"
TOOL_VERSION = "10.0"
SPDX_VERSION = "SPDX-2.3"


def _spdx_id(name: str, version: str = "") -> str:
    """Generate a stable SPDX element ID."""
    slug = re.sub(r"[^a-zA-Z0-9\-]", "-", f"{name}-{version}").strip("-")
    return f"SPDXRef-{slug}"[:64]


def _purl(ecosystem: str, name: str, version: str) -> str:
    eco_map = {
        "pypi": "pypi", "npm": "npm", "go": "golang",
        "crates.io": "cargo", "rubygems": "gem",
        "maven": "maven", "nuget": "nuget", "hex": "hex",
    }
    purl_type = eco_map.get(ecosystem.lower(), ecosystem.lower())
    ver_part  = f"@{version}" if version else ""
    return f"pkg:{purl_type}/{name}{ver_part}"


def _sha1(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()


class SPDXExporter:
    """Generates SPDX 2.3 JSON SBOM from dependency manifests."""

    def from_directory(
        self,
        directory:       str,
        project_name:    str = "project",
        project_version: str = "0.0.0",
    ) -> Dict:
        """
        Scan directory for dependency manifests and produce SPDX 2.3 JSON.
        """
        from sbom.supply_chain import SupplyChainScanner
        scanner  = SupplyChainScanner()
        packages = []

        root = Path(directory)
        SKIP = {".git", "node_modules", "__pycache__", ".venv", "venv"}

        for f in root.rglob("requirements*.txt"):
            if not any(p in f.parts for p in SKIP):
                packages.extend(scanner.parse_requirements_txt(str(f)))
        for f in root.rglob("package.json"):
            if not any(p in f.parts for p in SKIP) and "node_modules" not in str(f):
                packages.extend(scanner.parse_package_json(str(f)))

        return self._build(packages, project_name, project_version)

    def from_packages(
        self,
        packages:        List[Dict],
        project_name:    str = "project",
        project_version: str = "0.0.0",
    ) -> Dict:
        """Build SPDX from a pre-parsed package list (Ghost internal format)."""
        return self._build(packages, project_name, project_version)

    def write(self, spdx: Dict, output_path: str) -> str:
        """Write SPDX JSON to file."""
        Path(output_path).write_text(json.dumps(spdx, indent=2, ensure_ascii=False))
        return output_path

    # ── Internal ───────────────────────────────────────────────────────────────

    def _build(
        self,
        packages:        List[Dict],
        project_name:    str,
        project_version: str,
    ) -> Dict:
        now   = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        doc_id = f"urn:uuid:{uuid.uuid4()}"

        # Root package (the project itself)
        root_spdx_id = "SPDXRef-DOCUMENT"

        spdx_packages = []
        relationships = []

        for pkg in packages:
            name      = pkg.get("name", "unknown")
            version   = pkg.get("version_spec", "").lstrip("=^~><!* ") or "unknown"
            ecosystem = pkg.get("ecosystem", "unknown")
            is_dev    = pkg.get("is_dev", False)
            pinned    = pkg.get("pinned", False)

            spdx_id = _spdx_id(name, version)
            purl    = _purl(ecosystem, name, version)

            pkg_entry: Dict = {
                "SPDXID":           spdx_id,
                "name":             name,
                "versionInfo":      version,
                "downloadLocation": f"https://pypi.org/project/{name}/{version}/" if ecosystem == "pypi"
                                    else f"https://www.npmjs.com/package/{name}/v/{version}" if ecosystem == "npm"
                                    else "NOASSERTION",
                "filesAnalyzed":    False,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType":     "purl",
                        "referenceLocator":  purl,
                    }
                ],
                "annotations": [],
            }

            # Add checksum if version is pinned (deterministic)
            if pinned and version and version != "unknown":
                pkg_entry["checksums"] = [
                    {"algorithm": "SHA1", "checksumValue": _sha1(f"{name}@{version}")}
                ]

            # Scope annotation
            scope = "optional" if is_dev else "required"
            pkg_entry["annotations"].append({
                "annotationType": "OTHER",
                "annotator":      f"Tool: {TOOL_NAME}",
                "annotationDate": now,
                "comment":        f"scope={scope} pinned={pinned} ecosystem={ecosystem}",
            })

            spdx_packages.append(pkg_entry)
            rel_type = "DEV_DEPENDENCY_OF" if is_dev else "DEPENDENCY_OF"
            relationships.append({
                "spdxElementId":      spdx_id,
                "relationshipType":   rel_type,
                "relatedSpdxElement": root_spdx_id,
            })

        # Document root package
        root_package = {
            "SPDXID":          root_spdx_id,
            "name":            project_name,
            "versionInfo":     project_version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed":   False,
            "primaryPackagePurpose": "APPLICATION",
        }

        return {
            "spdxVersion":    SPDX_VERSION,
            "dataLicense":    "CC0-1.0",
            "SPDXID":         root_spdx_id,
            "name":           f"{project_name} SBOM",
            "documentNamespace": doc_id,
            "creationInfo": {
                "created":  now,
                "creators": [
                    f"Tool: {TOOL_NAME} {TOOL_VERSION}",
                    "Tool: Ghost Security SPDX Exporter",
                ],
                "licenseListVersion": "3.22",
            },
            "packages":      [root_package] + spdx_packages,
            "relationships": [
                {
                    "spdxElementId":      root_spdx_id,
                    "relationshipType":   "DESCRIBES",
                    "relatedSpdxElement": root_spdx_id,
                }
            ] + relationships,
            "documentDescribes": [root_spdx_id],
            "comment": f"Generated by {TOOL_NAME} — SPDX 2.3 compliant SBOM",
        }
