"""CycloneDX 1.4 SBOM generator (JSON format)."""

from __future__ import annotations

import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


class ComponentType(str, Enum):
    LIBRARY = "library"
    APPLICATION = "application"
    FRAMEWORK = "framework"
    CONTAINER = "container"
    DEVICE = "device"
    FILE = "file"


class HashAlg(str, Enum):
    MD5 = "MD5"
    SHA1 = "SHA-1"
    SHA256 = "SHA-256"
    SHA512 = "SHA-512"


class Hash(BaseModel):
    alg: HashAlg
    content: str


class License(BaseModel):
    id: str = ""
    name: str = ""
    url: str = ""


class ExternalRef(BaseModel):
    type: str
    url: str
    comment: str = ""


class Component(BaseModel):
    type: ComponentType = ComponentType.LIBRARY
    bom_ref: str = ""       # unique ID
    name: str
    version: str = ""
    group: str = ""
    purl: str = ""          # package URL
    description: str = ""
    licenses: List[License] = Field(default_factory=list)
    hashes: List[Hash] = Field(default_factory=list)
    external_refs: List[ExternalRef] = Field(default_factory=list)
    vulnerabilities: List[str] = Field(default_factory=list)  # CVE IDs


class CycloneDXBOM(BaseModel):
    bom_format: str = "CycloneDX"
    spec_version: str = "1.4"
    serial_number: str = ""     # urn:uuid:...
    version: int = 1
    metadata: Dict[str, Any] = Field(default_factory=dict)
    components: List[Component] = Field(default_factory=list)
    dependencies: List[Dict[str, Any]] = Field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Ecosystem → PURL type mapping
# ---------------------------------------------------------------------------

_PURL_TYPE: Dict[str, str] = {
    "pypi": "pypi",
    "npm": "npm",
    "go": "golang",
    "cargo": "cargo",
    "maven": "maven",
    "gradle": "maven",
    "rubygems": "gem",
    "nuget": "nuget",
}

# ---------------------------------------------------------------------------
# Dependency file parsers
# ---------------------------------------------------------------------------


def _strip_markers(spec: str) -> str:
    """Remove environment markers (PEP 508) from a dependency spec."""
    # e.g. 'requests>=2.0; python_version>"3"' → 'requests>=2.0'
    return spec.split(";")[0].strip()


_VERSION_RE = re.compile(
    r"^([A-Za-z0-9_\-\.\[\]]+?)"   # package name (+ optional extras)
    r"\s*(?:==|>=|<=|~=|!=|>|<)\s*"
    r"([A-Za-z0-9_\-\.]+)"         # version
    r".*$"
)

_NAME_ONLY_RE = re.compile(r"^([A-Za-z0-9_\-\.]+(?:\[.*?\])?)$")


def _normalize_pkg_name(raw: str) -> str:
    """Strip extras from package name: requests[security] → requests."""
    return re.sub(r"\[.*?\]", "", raw).strip()


class CycloneDXGenerator:
    """Generates CycloneDX 1.4 SBOMs by scanning common dependency manifests."""

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def generate(self, project_path: str, include_dev: bool = False) -> CycloneDXBOM:
        """Scan *project_path* for dependency manifests and build a BOM."""
        root = Path(project_path)
        components: List[Component] = []
        seen: set[str] = set()   # (name, version) dedup key

        # --- Python ---
        for fname in ("requirements.txt",):
            req_file = root / fname
            if req_file.exists():
                for name, version in self.parse_requirements(str(req_file)):
                    key = f"pypi:{name.lower()}:{version}"
                    if key not in seen:
                        seen.add(key)
                        components.append(self._make_component(name, version, "pypi"))

        if include_dev:
            dev_req = root / "requirements-dev.txt"
            if dev_req.exists():
                for name, version in self.parse_requirements(str(dev_req)):
                    key = f"pypi:{name.lower()}:{version}"
                    if key not in seen:
                        seen.add(key)
                        components.append(self._make_component(name, version, "pypi"))

        pyproject = root / "pyproject.toml"
        if pyproject.exists():
            for name, version in self.parse_pyproject_toml(str(pyproject)):
                key = f"pypi:{name.lower()}:{version}"
                if key not in seen:
                    seen.add(key)
                    components.append(self._make_component(name, version, "pypi"))

        setup_cfg = root / "setup.cfg"
        if setup_cfg.exists():
            for name, version in self._parse_setup_cfg(str(setup_cfg)):
                key = f"pypi:{name.lower()}:{version}"
                if key not in seen:
                    seen.add(key)
                    components.append(self._make_component(name, version, "pypi"))

        # --- Node.js ---
        pkg_json = root / "package.json"
        if pkg_json.exists():
            for name, version in self._parse_package_json(str(pkg_json), include_dev):
                key = f"npm:{name.lower()}:{version}"
                if key not in seen:
                    seen.add(key)
                    components.append(self._make_component(name, version, "npm"))

        # --- Go ---
        go_mod = root / "go.mod"
        if go_mod.exists():
            for name, version in self._parse_go_mod(str(go_mod)):
                key = f"go:{name.lower()}:{version}"
                if key not in seen:
                    seen.add(key)
                    components.append(self._make_component(name, version, "go"))

        # --- Rust ---
        cargo_toml = root / "Cargo.toml"
        if cargo_toml.exists():
            for name, version in self._parse_cargo_toml(str(cargo_toml)):
                key = f"cargo:{name.lower()}:{version}"
                if key not in seen:
                    seen.add(key)
                    components.append(self._make_component(name, version, "cargo"))

        # --- Java (Maven / Gradle) ---
        pom_xml = root / "pom.xml"
        if pom_xml.exists():
            for name, version in self._parse_pom_xml(str(pom_xml)):
                key = f"maven:{name.lower()}:{version}"
                if key not in seen:
                    seen.add(key)
                    components.append(self._make_component(name, version, "maven"))

        build_gradle = root / "build.gradle"
        if not build_gradle.exists():
            build_gradle = root / "build.gradle.kts"
        if build_gradle.exists():
            for name, version in self._parse_build_gradle(str(build_gradle)):
                key = f"maven:{name.lower()}:{version}"
                if key not in seen:
                    seen.add(key)
                    components.append(self._make_component(name, version, "gradle"))

        # Build BOM
        now_iso = datetime.now(timezone.utc).isoformat()
        metadata: Dict[str, Any] = {
            "timestamp": now_iso,
            "tools": [{"vendor": "ghost-security", "name": "ghost-security", "version": "3.0"}],
            "component": {
                "type": "application",
                "name": root.name,
                "version": "",
            },
        }

        serial = f"urn:uuid:{uuid.uuid4()}"
        bom = CycloneDXBOM(
            serial_number=serial,
            metadata=metadata,
            components=components,
        )
        return bom

    def generate_purl(self, ecosystem: str, name: str, version: str) -> str:
        """Generate a Package URL (PURL) string for the given ecosystem."""
        eco_lower = ecosystem.lower()
        purl_type = _PURL_TYPE.get(eco_lower, eco_lower)

        if eco_lower == "go":
            # Go packages use module path, no need to lower-case
            encoded_name = name
        else:
            encoded_name = name.lower() if eco_lower in ("pypi", "npm") else name

        if version:
            return f"pkg:{purl_type}/{encoded_name}@{version}"
        return f"pkg:{purl_type}/{encoded_name}"

    def to_json(self, bom: CycloneDXBOM) -> str:
        """Serialise a CycloneDXBOM to a CycloneDX 1.4 compliant JSON string."""
        doc: Dict[str, Any] = {
            "bomFormat": bom.bom_format,
            "specVersion": bom.spec_version,
            "serialNumber": bom.serial_number,
            "version": bom.version,
            "metadata": bom.metadata,
            "components": [self._component_to_dict(c) for c in bom.components],
        }
        if bom.dependencies:
            doc["dependencies"] = bom.dependencies
        if bom.vulnerabilities:
            doc["vulnerabilities"] = bom.vulnerabilities
        return json.dumps(doc, indent=2)

    # ------------------------------------------------------------------ #
    # Manifest parsers                                                     #
    # ------------------------------------------------------------------ #

    def parse_requirements(self, path: str) -> List[Tuple[str, str]]:
        """Parse a pip requirements.txt file.

        Handles:
          - ``package==version``
          - ``package>=version`` (version extracted as-is)
          - ``package[extras]==version``
          - Comments (#), blank lines, ``-r`` includes (skipped), URLs (skipped)
        """
        results: List[Tuple[str, str]] = []
        try:
            with open(path, encoding="utf-8") as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    line = _strip_markers(line)
                    m = _VERSION_RE.match(line)
                    if m:
                        raw_name = m.group(1)
                        version = m.group(2)
                        results.append((_normalize_pkg_name(raw_name), version))
                    else:
                        # Name-only (no version pin)
                        m2 = _NAME_ONLY_RE.match(line)
                        if m2:
                            results.append((_normalize_pkg_name(m2.group(1)), ""))
        except OSError as exc:
            logger.warning("Cannot read requirements file %s: %s", path, exc)
        return results

    def parse_pyproject_toml(self, path: str) -> List[Tuple[str, str]]:
        """Parse dependency specs from pyproject.toml.

        Handles both ``[project.dependencies]`` (PEP 621) and
        ``[tool.poetry.dependencies]`` sections.
        """
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                logger.warning("tomllib/tomli not available; cannot parse pyproject.toml")
                return []

        results: List[Tuple[str, str]] = []
        try:
            with open(path, "rb") as fh:
                data = tomllib.load(fh)
        except (OSError, Exception) as exc:  # noqa: BLE001
            logger.warning("Cannot parse pyproject.toml %s: %s", path, exc)
            return results

        # PEP 621: [project] dependencies = ["requests>=2.28", ...]
        project_deps = data.get("project", {}).get("dependencies", [])
        for dep in project_deps:
            line = _strip_markers(str(dep))
            m = _VERSION_RE.match(line)
            if m:
                results.append((_normalize_pkg_name(m.group(1)), m.group(2)))
            else:
                m2 = _NAME_ONLY_RE.match(line)
                if m2:
                    results.append((_normalize_pkg_name(m2.group(1)), ""))

        # Poetry: [tool.poetry.dependencies] = {requests = "^2.28"}
        poetry_deps = (
            data.get("tool", {}).get("poetry", {}).get("dependencies", {})
        )
        for pkg_name, spec in poetry_deps.items():
            if pkg_name.lower() == "python":
                continue
            if isinstance(spec, str):
                # Strip leading ^, ~, >=, etc.
                version = re.sub(r"^[\^~>=<!\*]+", "", spec).split(",")[0].strip()
                results.append((pkg_name, version))
            elif isinstance(spec, dict):
                version = re.sub(
                    r"^[\^~>=<!\*]+",
                    "",
                    str(spec.get("version", "")),
                ).split(",")[0].strip()
                results.append((pkg_name, version))

        return results

    # ------------------------------------------------------------------ #
    # Private parsers                                                      #
    # ------------------------------------------------------------------ #

    def _parse_setup_cfg(self, path: str) -> List[Tuple[str, str]]:
        """Parse install_requires from setup.cfg."""
        import configparser

        results: List[Tuple[str, str]] = []
        cfg = configparser.ConfigParser()
        try:
            cfg.read(path, encoding="utf-8")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cannot parse setup.cfg %s: %s", path, exc)
            return results

        raw = cfg.get("options", "install_requires", fallback="")
        for line in raw.splitlines():
            line = _strip_markers(line.strip())
            if not line:
                continue
            m = _VERSION_RE.match(line)
            if m:
                results.append((_normalize_pkg_name(m.group(1)), m.group(2)))
            else:
                m2 = _NAME_ONLY_RE.match(line)
                if m2:
                    results.append((_normalize_pkg_name(m2.group(1)), ""))
        return results

    def _parse_package_json(
        self, path: str, include_dev: bool = False
    ) -> List[Tuple[str, str]]:
        """Parse dependencies (and optionally devDependencies) from package.json."""
        results: List[Tuple[str, str]] = []
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Cannot parse package.json %s: %s", path, exc)
            return results

        sections = ["dependencies"]
        if include_dev:
            sections.append("devDependencies")

        for section in sections:
            for name, spec in data.get(section, {}).items():
                # Spec: "^1.2.3", "~1.2", "1.2.3", etc.
                version = re.sub(r"^[\^~>=<!\*]+", "", str(spec)).strip()
                results.append((name, version))
        return results

    def _parse_go_mod(self, path: str) -> List[Tuple[str, str]]:
        """Parse require directives from go.mod."""
        results: List[Tuple[str, str]] = []
        _require_re = re.compile(r"^\s*([^\s]+)\s+(v[^\s]+)")
        in_require = False
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    stripped = line.strip()
                    if stripped.startswith("require ("):
                        in_require = True
                        continue
                    if in_require and stripped == ")":
                        in_require = False
                        continue
                    if in_require:
                        m = _require_re.match(line)
                        if m:
                            results.append((m.group(1), m.group(2)))
                    elif stripped.startswith("require "):
                        # Single-line: require github.com/foo/bar v1.2.3
                        rest = stripped[len("require "):].strip()
                        m = re.match(r"([^\s]+)\s+(v[^\s]+)", rest)
                        if m:
                            results.append((m.group(1), m.group(2)))
        except OSError as exc:
            logger.warning("Cannot parse go.mod %s: %s", path, exc)
        return results

    def _parse_cargo_toml(self, path: str) -> List[Tuple[str, str]]:
        """Parse [dependencies] from Cargo.toml."""
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                logger.warning("tomllib/tomli not available; cannot parse Cargo.toml")
                return []

        results: List[Tuple[str, str]] = []
        try:
            with open(path, "rb") as fh:
                data = tomllib.load(fh)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cannot parse Cargo.toml %s: %s", path, exc)
            return results

        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            for name, spec in data.get(section, {}).items():
                if isinstance(spec, str):
                    version = re.sub(r"^[\^~>=<!\*]+", "", spec).strip()
                    results.append((name, version))
                elif isinstance(spec, dict):
                    version = re.sub(
                        r"^[\^~>=<!\*]+",
                        "",
                        str(spec.get("version", "")),
                    ).strip()
                    results.append((name, version))
        return results

    def _parse_pom_xml(self, path: str) -> List[Tuple[str, str]]:
        """Parse <dependency> elements from a Maven pom.xml."""
        import xml.etree.ElementTree as ET

        results: List[Tuple[str, str]] = []
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            # Handle namespaced Maven POMs
            ns = ""
            if root.tag.startswith("{"):
                ns = root.tag.split("}")[0] + "}"

            for dep in root.iter(f"{ns}dependency"):
                group_id = dep.findtext(f"{ns}groupId", "")
                artifact_id = dep.findtext(f"{ns}artifactId", "")
                version = dep.findtext(f"{ns}version", "")
                if artifact_id:
                    name = f"{group_id}:{artifact_id}" if group_id else artifact_id
                    # Strip property references like ${spring.version}
                    if version and version.startswith("${"):
                        version = ""
                    results.append((name, version))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cannot parse pom.xml %s: %s", path, exc)
        return results

    def _parse_build_gradle(self, path: str) -> List[Tuple[str, str]]:
        """Parse dependency strings from build.gradle / build.gradle.kts."""
        results: List[Tuple[str, str]] = []
        # Match: implementation 'group:artifact:version'
        dep_re = re.compile(
            r"""(?:implementation|api|compile|runtimeOnly|testImplementation)\s*['"(]"""
            r"""([A-Za-z0-9\.\-_]+):([A-Za-z0-9\.\-_]+):([A-Za-z0-9\.\-_]+)['")]"""
        )
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    m = dep_re.search(line)
                    if m:
                        group_id, artifact_id, version = m.group(1), m.group(2), m.group(3)
                        name = f"{group_id}:{artifact_id}"
                        results.append((name, version))
        except OSError as exc:
            logger.warning("Cannot parse build.gradle %s: %s", path, exc)
        return results

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _make_component(self, name: str, version: str, ecosystem: str) -> Component:
        purl = self.generate_purl(ecosystem, name, version)
        bom_ref = f"{ecosystem}-{name}-{version}" if version else f"{ecosystem}-{name}"
        return Component(
            name=name,
            version=version,
            purl=purl,
            bom_ref=bom_ref,
        )

    @staticmethod
    def _component_to_dict(c: Component) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "type": c.type.value,
            "bom-ref": c.bom_ref,
            "name": c.name,
        }
        if c.version:
            d["version"] = c.version
        if c.group:
            d["group"] = c.group
        if c.purl:
            d["purl"] = c.purl
        if c.description:
            d["description"] = c.description
        if c.licenses:
            d["licenses"] = [
                {"license": {k: v for k, v in lic.model_dump().items() if v}}
                for lic in c.licenses
            ]
        if c.hashes:
            d["hashes"] = [
                {"alg": h.alg.value, "content": h.content} for h in c.hashes
            ]
        if c.external_refs:
            d["externalReferences"] = [
                {
                    "type": ref.type,
                    "url": ref.url,
                    **({"comment": ref.comment} if ref.comment else {}),
                }
                for ref in c.external_refs
            ]
        return d


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------


def generate_cyclonedx(project_path: str, include_dev: bool = False) -> str:
    """Generate a CycloneDX 1.4 JSON SBOM for the project at *project_path*."""
    gen = CycloneDXGenerator()
    bom = gen.generate(project_path, include_dev)
    return gen.to_json(bom)
