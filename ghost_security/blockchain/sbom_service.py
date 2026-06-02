"""
TythanAI Phase 10 — Blockchain SBOM as a Service

Wraps the Phase 8 TON SBOM builder and adds:
  - SPDX 2.3 export
  - CycloneDX 1.4 export
  - EU CRA / NIST compliance summary
  - Multi-project batch processing
  - REST-style service interface (no HTTP server required — call programmatically
    or wrap in FastAPI/Flask)

Usage:
    svc = BlockchainSBOMService()
    report = svc.generate("/path/to/ton/project")
    spdx_json   = svc.export_spdx(report)
    cdx_json    = svc.export_cyclonedx(report)
    compliance  = svc.compliance_summary(report)
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Phase 8 SBOM builder
try:
    from blockchain.ton.ton_sbom import BlockchainSBOM, SBOMEntry  # type: ignore
    _HAS_PHASE8 = True
except ImportError:
    _HAS_PHASE8 = False


# ─── Data models ─────────────────────────────────────────────────────────────

@dataclass
class SBOMComponent:
    name:        str
    version:     str = ""
    type:        str = "library"          # library | framework | contract | tool
    language:    str = "unknown"          # FunC | Tolk | Tact | Solidity | Python | …
    file_path:   str = ""
    checksums:   Dict[str, str] = field(default_factory=dict)
    licenses:    List[str] = field(default_factory=list)
    supplier:    str = ""
    description: str = ""
    purl:        str = ""                 # Package URL (pkg:...)
    cpe:         str = ""
    properties:  Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name":        self.name,
            "version":     self.version,
            "type":        self.type,
            "language":    self.language,
            "file_path":   self.file_path,
            "checksums":   self.checksums,
            "licenses":    self.licenses,
            "supplier":    self.supplier,
            "description": self.description,
            "purl":        self.purl,
        }


@dataclass
class BlockchainSBOMReport:
    project_name:    str
    project_path:    str
    generated_at:    str
    schema_version:  str = "1.0"
    components:      List[SBOMComponent] = field(default_factory=list)
    dependencies:    List[Dict[str, Any]] = field(default_factory=list)   # {from, to}
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    metadata:        Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "schema_version":  self.schema_version,
            "project_name":    self.project_name,
            "project_path":    self.project_path,
            "generated_at":    self.generated_at,
            "component_count": len(self.components),
            "components":      [c.to_dict() for c in self.components],
            "dependencies":    self.dependencies,
            "vulnerabilities": self.vulnerabilities,
            "metadata":        self.metadata,
        }


# ─── File hash helpers ───────────────────────────────────────────────────────

def _sha256(path: str) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except Exception:
        return ""


def _md5(path: str) -> str:
    try:
        return hashlib.md5(Path(path).read_bytes(), usedforsecurity=False).hexdigest()
    except Exception:
        return ""


# ─── Language detector ───────────────────────────────────────────────────────

_EXT_LANG: Dict[str, str] = {
    ".fc":    "FunC",
    ".func":  "FunC",
    ".tolk":  "Tolk",
    ".tact":  "Tact",
    ".sol":   "Solidity",
    ".vy":    "Vyper",
    ".py":    "Python",
    ".ts":    "TypeScript",
    ".js":    "JavaScript",
    ".rs":    "Rust",
    ".go":    "Go",
}

_CONTRACT_EXTS = {".fc", ".func", ".tolk", ".tact", ".sol", ".vy"}


def _detect_language(path: str) -> str:
    return _EXT_LANG.get(Path(path).suffix.lower(), "unknown")


# ─── Simple SBOM builder (no Phase 8 required) ───────────────────────────────

_IMPORT_PATTERNS = [
    re.compile(r'#include\s+"([^"]+)"'),           # FunC
    re.compile(r'import\s+"([^"]+)"'),             # Tact/Tolk
    re.compile(r'^import\s+\S+\s+from\s+"([^"]+)"', re.MULTILINE),  # TS/JS
    re.compile(r'^import\s+"([^"]+)"', re.MULTILINE),
]

_LICENSE_HINTS = re.compile(
    r'(MIT|Apache-2\.0|GPL-[23]\.0|BSL-1\.1|LGPL|MPL-2\.0|ISC|BSD)',
    re.I,
)


def _extract_imports(content: str) -> List[str]:
    imports = []
    for pat in _IMPORT_PATTERNS:
        imports.extend(pat.findall(content))
    return list(dict.fromkeys(imports))


def _detect_license(content: str) -> List[str]:
    return list(dict.fromkeys(_LICENSE_HINTS.findall(content)))


def _build_purl(name: str, version: str, ecosystem: str) -> str:
    if not ecosystem or ecosystem == "unknown":
        return ""
    clean = name.lstrip("@").replace("/", "%2F")
    ver = f"@{version}" if version else ""
    return f"pkg:{ecosystem}/{clean}{ver}"


def _scan_project_files(root: Path) -> List[SBOMComponent]:
    components: List[SBOMComponent] = []
    seen: set = set()

    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if "__pycache__" in str(p) or p.suffix.lower() not in _EXT_LANG:
            continue

        rel = str(p.relative_to(root))
        if rel in seen:
            continue
        seen.add(rel)

        content = p.read_text(errors="replace")
        lang    = _detect_language(str(p))
        ctype   = "contract" if p.suffix.lower() in _CONTRACT_EXTS else "library"
        licenses = _detect_license(content)

        sha = _sha256(str(p))
        md  = _md5(str(p))

        comp = SBOMComponent(
            name=p.stem,
            version="",
            type=ctype,
            language=lang,
            file_path=rel,
            checksums={"SHA-256": sha, "MD5": md} if sha else {},
            licenses=licenses,
        )

        # Build import-based dependency edges (stored in properties for now)
        imports = _extract_imports(content)
        if imports:
            comp.properties["imports"] = imports

        components.append(comp)

    return components


def _build_dependency_edges(components: List[SBOMComponent]) -> List[Dict[str, Any]]:
    name_map = {c.name: c for c in components}
    edges = []
    for comp in components:
        for imp in comp.properties.get("imports", []):
            imp_name = Path(imp).stem
            if imp_name in name_map and imp_name != comp.name:
                edges.append({"from": comp.name, "to": imp_name})
    return edges


# ─── SPDX 2.3 exporter ───────────────────────────────────────────────────────

def _to_spdx(report: BlockchainSBOMReport) -> dict:
    packages = []
    for comp in report.components:
        sha = comp.checksums.get("SHA-256", "")
        pkg: Dict[str, Any] = {
            "SPDXID":            f"SPDXRef-{comp.name.replace(' ', '-')}",
            "name":              comp.name,
            "versionInfo":       comp.version or "NOASSERTION",
            "downloadLocation":  "NOASSERTION",
            "filesAnalyzed":     True,
            "packageVerificationCode": {"packageVerificationCodeValue": sha} if sha else {},
            "licenseConcluded":  comp.licenses[0] if comp.licenses else "NOASSERTION",
            "licenseDeclared":   comp.licenses[0] if comp.licenses else "NOASSERTION",
            "copyrightText":     "NOASSERTION",
        }
        packages.append(pkg)

    return {
        "spdxVersion":       "SPDX-2.3",
        "dataLicense":       "CC0-1.0",
        "SPDXID":            "SPDXRef-DOCUMENT",
        "name":              report.project_name,
        "documentNamespace": f"https://tythanai.com/sbom/{report.project_name}",
        "creationInfo": {
            "created":  report.generated_at,
            "creators": ["Tool: TythanAI BlockchainSBOMService v1.0"],
        },
        "packages": packages,
        "relationships": [
            {
                "spdxElementId":      "SPDXRef-DOCUMENT",
                "relationshipType":   "DESCRIBES",
                "relatedSpdxElement": f"SPDXRef-{c.name.replace(' ', '-')}",
            }
            for c in report.components
        ],
    }


# ─── CycloneDX 1.4 exporter ──────────────────────────────────────────────────

def _to_cyclonedx(report: BlockchainSBOMReport) -> dict:
    components = []
    for comp in report.components:
        cdx_comp: Dict[str, Any] = {
            "type":     comp.type,
            "bom-ref":  f"ref-{comp.name}",
            "name":     comp.name,
            "version":  comp.version or "",
            "description": comp.description,
        }
        if comp.purl:
            cdx_comp["purl"] = comp.purl
        if comp.licenses:
            cdx_comp["licenses"] = [{"license": {"id": lic}} for lic in comp.licenses]
        if comp.checksums:
            cdx_comp["hashes"] = [
                {"alg": alg, "content": val}
                for alg, val in comp.checksums.items()
            ]
        components.append(cdx_comp)

    deps = [
        {
            "ref":     f"ref-{edge['from']}",
            "dependsOn": [f"ref-{edge['to']}"],
        }
        for edge in report.dependencies
    ]

    return {
        "bomFormat":   "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{hashlib.md5(report.project_name.encode(), usedforsecurity=False).hexdigest()}",
        "version":     1,
        "metadata": {
            "timestamp": report.generated_at,
            "tools": [{"vendor": "TythanAI", "name": "BlockchainSBOMService", "version": "1.0"}],
            "component": {
                "type":    "application",
                "name":    report.project_name,
                "version": "",
            },
        },
        "components":   components,
        "dependencies": deps,
    }


# ─── Compliance summary ───────────────────────────────────────────────────────

def _compliance_summary(report: BlockchainSBOMReport) -> dict:
    total = len(report.components)
    licensed = sum(1 for c in report.components if c.licenses)
    hashed   = sum(1 for c in report.components if c.checksums)
    vulns    = len(report.vulnerabilities)

    eu_cra_score = 0
    if total > 0:
        eu_cra_score += 30 if licensed / total >= 0.8 else int(30 * licensed / total)
        eu_cra_score += 30 if hashed / total >= 0.8 else int(30 * hashed / total)
        eu_cra_score += 40 if vulns == 0 else max(0, 40 - vulns * 5)

    nist_controls = {
        "identify":   "SBOM generated" if total > 0 else "No components found",
        "protect":    f"{licensed}/{total} components have license information",
        "detect":     f"{vulns} known vulnerabilities found",
        "respond":    "Remediation data available in vulnerability entries",
        "recover":    "Dependency graph available for impact analysis",
    }

    return {
        "eu_cra": {
            "score":  eu_cra_score,
            "max":    100,
            "status": "COMPLIANT" if eu_cra_score >= 70 else "PARTIAL" if eu_cra_score >= 40 else "NON_COMPLIANT",
            "notes": [
                f"{licensed}/{total} components have declared licenses",
                f"{hashed}/{total} components have integrity checksums",
                f"{vulns} known vulnerability entries",
            ],
        },
        "nist_ssdf": nist_controls,
    }


# ─── BlockchainSBOMService ───────────────────────────────────────────────────

class BlockchainSBOMService:
    """
    Blockchain SBOM generation and export service.

    Supports TON (FunC/Tolk/Tact), Solidity, and mixed projects.
    Produces SPDX 2.3 and CycloneDX 1.4 compatible output.
    """

    def generate(self, project_path: str, project_name: Optional[str] = None) -> BlockchainSBOMReport:
        """Scan a project directory and generate a full SBOM report."""
        root = Path(project_path)
        name = project_name or root.name
        now  = datetime.now(timezone.utc).isoformat()

        # Prefer Phase 8 builder if available
        if _HAS_PHASE8:
            try:
                phase8 = BlockchainSBOM()
                raw = phase8.build(project_path)
                return self._from_phase8(raw, name, project_path, now)
            except Exception:
                pass

        # Fallback: built-in scanner
        components = _scan_project_files(root)
        deps       = _build_dependency_edges(components)

        return BlockchainSBOMReport(
            project_name=name,
            project_path=project_path,
            generated_at=now,
            components=components,
            dependencies=deps,
            metadata={
                "builder": "TythanAI BlockchainSBOMService",
                "phase8_available": _HAS_PHASE8,
            },
        )

    def _from_phase8(self, raw: Any, name: str, path: str, now: str) -> BlockchainSBOMReport:
        """Convert Phase 8 BlockchainSBOM output to BlockchainSBOMReport."""
        components = []
        entries = raw if isinstance(raw, list) else (raw.get("entries") or [])
        for entry in entries:
            if hasattr(entry, "__dict__"):
                entry = entry.__dict__
            components.append(SBOMComponent(
                name=entry.get("name", "unknown"),
                version=entry.get("version", ""),
                type="contract",
                language=entry.get("language", "unknown"),
                file_path=entry.get("file", ""),
            ))
        return BlockchainSBOMReport(
            project_name=name,
            project_path=path,
            generated_at=now,
            components=components,
            metadata={"builder": "TythanAI Phase8 BlockchainSBOM"},
        )

    def export_spdx(self, report: BlockchainSBOMReport) -> str:
        """Export report as SPDX 2.3 JSON string."""
        return json.dumps(_to_spdx(report), indent=2)

    def export_cyclonedx(self, report: BlockchainSBOMReport) -> str:
        """Export report as CycloneDX 1.4 JSON string."""
        return json.dumps(_to_cyclonedx(report), indent=2)

    def compliance_summary(self, report: BlockchainSBOMReport) -> dict:
        """Return EU CRA and NIST SSDF compliance summary."""
        return _compliance_summary(report)

    def generate_all(self, root_directory: str) -> List[BlockchainSBOMReport]:
        """
        Find all sub-projects (directories with .fc/.sol files) and generate
        a separate SBOM for each.
        """
        root = Path(root_directory)
        project_roots: set = set()
        for ext in ("*.fc", "*.func", "*.tolk", "*.sol", "*.tact"):
            for p in root.rglob(ext):
                project_roots.add(str(p.parent))

        return [self.generate(pr) for pr in sorted(project_roots)]
