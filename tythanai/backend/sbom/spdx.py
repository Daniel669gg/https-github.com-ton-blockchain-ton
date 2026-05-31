"""SPDX 2.3 SBOM generator (tag-value and JSON formats)."""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SPDX field ordering for tag-value output
# ---------------------------------------------------------------------------

_DOC_FIELDS = [
    "SPDXVersion",
    "DataLicense",
    "SPDXID",
    "DocumentName",
    "DocumentNamespace",
    "Creator",
    "Created",
]

_PKG_FIELDS = [
    "PackageName",
    "SPDXID",
    "PackageVersion",
    "PackageDownloadLocation",
    "FilesAnalyzed",
    "PackageLicenseConcluded",
    "PackageLicenseDeclared",
    "PackageCopyrightText",
]

_REL_FIELDS = ["Relationship"]


def _spdxid_from_name(name: str) -> str:
    """Generate a valid SPDX element identifier from a package name."""
    safe = re.sub(r"[^A-Za-z0-9\-\.]", "-", name).strip("-")
    return f"SPDXRef-{safe}"


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


class SPDXGenerator:
    """Generates SPDX 2.3 documents from project dependency manifests."""

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def generate(self, project_path: str) -> Dict[str, Any]:
        """Scan *project_path* and return an SPDX 2.3 document as a dict."""
        root = Path(project_path)
        project_name = root.name or "unknown-project"
        namespace = (
            f"https://ghost-security.io/spdx/{project_name}-{uuid.uuid4()}"
        )
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        packages = self._collect_packages(root)

        spdx_packages = []
        relationships: List[Dict[str, Any]] = []

        # Document-level DESCRIBES relationships
        for pkg_name, version in packages:
            spdx_id = _spdxid_from_name(f"{pkg_name}-{version}" if version else pkg_name)
            spdx_packages.append(
                {
                    "SPDXID": spdx_id,
                    "name": pkg_name,
                    "versionInfo": version or "NOASSERTION",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                }
            )
            relationships.append(
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": spdx_id,
                }
            )

        doc: Dict[str, Any] = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "creationInfo": {
                "created": now_iso,
                "creators": ["Tool: ghost-security-3.0"],
                "licenseListVersion": "3.20",
            },
            "name": project_name,
            "dataLicense": "CC0-1.0",
            "documentNamespace": namespace,
            "packages": spdx_packages,
            "relationships": relationships,
        }
        return doc

    def to_tag_value(self, doc: Dict[str, Any]) -> str:
        """Convert an SPDX document dict to SPDX tag-value (text) format."""
        lines: List[str] = []

        # Document header
        creation = doc.get("creationInfo", {})
        lines.append(f"SPDXVersion: {doc.get('spdxVersion', 'SPDX-2.3')}")
        lines.append(f"DataLicense: {doc.get('dataLicense', 'CC0-1.0')}")
        lines.append("")
        lines.append(f"SPDXID: {doc.get('SPDXID', 'SPDXRef-DOCUMENT')}")
        lines.append(f"DocumentName: {doc.get('name', '')}")
        lines.append(f"DocumentNamespace: {doc.get('documentNamespace', '')}")
        lines.append("")

        for creator in creation.get("creators", []):
            lines.append(f"Creator: {creator}")
        lines.append(f"Created: {creation.get('created', '')}")
        if creation.get("licenseListVersion"):
            lines.append(f"LicenseListVersion: {creation['licenseListVersion']}")
        lines.append("")

        # Packages
        for pkg in doc.get("packages", []):
            lines.append("##### Package")
            lines.append(f"PackageName: {pkg.get('name', '')}")
            lines.append(f"SPDXID: {pkg.get('SPDXID', '')}")
            if pkg.get("versionInfo"):
                lines.append(f"PackageVersion: {pkg['versionInfo']}")
            lines.append(f"PackageDownloadLocation: {pkg.get('downloadLocation', 'NOASSERTION')}")
            lines.append(
                f"FilesAnalyzed: {'true' if pkg.get('filesAnalyzed') else 'false'}"
            )
            lines.append(f"PackageLicenseConcluded: {pkg.get('licenseConcluded', 'NOASSERTION')}")
            lines.append(f"PackageLicenseDeclared: {pkg.get('licenseDeclared', 'NOASSERTION')}")
            lines.append(f"PackageCopyrightText: {pkg.get('copyrightText', 'NOASSERTION')}")
            lines.append("")

        # Relationships
        for rel in doc.get("relationships", []):
            element = rel.get("spdxElementId", "")
            rel_type = rel.get("relationshipType", "")
            related = rel.get("relatedSpdxElement", "")
            lines.append(f"Relationship: {element} {rel_type} {related}")

        return "\n".join(lines)

    def to_json(self, doc: Dict[str, Any]) -> str:
        """Return the SPDX document as an indented JSON string."""
        return json.dumps(doc, indent=2)

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _collect_packages(self, root: Path) -> List[Tuple[str, str]]:
        """Walk common dependency files and collect (name, version) pairs."""
        # Import here to avoid a circular dependency at module level.
        from ghost_security.backend.sbom.cyclonedx import CycloneDXGenerator  # type: ignore[import]

        gen = CycloneDXGenerator()
        packages: List[Tuple[str, str]] = []
        seen: set[Tuple[str, str]] = set()

        def _add(items: List[Tuple[str, str]]) -> None:
            for item in items:
                if item not in seen:
                    seen.add(item)
                    packages.append(item)

        req = root / "requirements.txt"
        if req.exists():
            _add(gen.parse_requirements(str(req)))

        pyproject = root / "pyproject.toml"
        if pyproject.exists():
            _add(gen.parse_pyproject_toml(str(pyproject)))

        pkg_json = root / "package.json"
        if pkg_json.exists():
            _add(gen._parse_package_json(str(pkg_json)))  # noqa: SLF001

        go_mod = root / "go.mod"
        if go_mod.exists():
            _add(gen._parse_go_mod(str(go_mod)))  # noqa: SLF001

        cargo_toml = root / "Cargo.toml"
        if cargo_toml.exists():
            _add(gen._parse_cargo_toml(str(cargo_toml)))  # noqa: SLF001

        pom_xml = root / "pom.xml"
        if pom_xml.exists():
            _add(gen._parse_pom_xml(str(pom_xml)))  # noqa: SLF001

        return packages


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------


def generate_spdx(project_path: str, fmt: str = "json") -> str:
    """Generate an SPDX 2.3 document for *project_path*.

    Args:
        project_path: Filesystem path to the project root.
        fmt: Output format — ``"json"`` (default) or ``"tag-value"``.

    Returns:
        The SPDX document as a string in the requested format.
    """
    gen = SPDXGenerator()
    doc = gen.generate(project_path)
    if fmt == "tag-value":
        return gen.to_tag_value(doc)
    return gen.to_json(doc)
