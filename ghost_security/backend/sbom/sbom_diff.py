"""SBOM Diff Engine — compare two CycloneDX BOM snapshots."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.sbom.cyclonedx import CycloneDXBOM, Component

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class DiffType:
    ADDED = "added"
    REMOVED = "removed"
    UPGRADED = "upgraded"
    DOWNGRADED = "downgraded"
    VULN_ADDED = "vulnerability_added"
    UNCHANGED = "unchanged"


@dataclass
class ComponentDiff:
    name: str
    diff_type: str  # DiffType constant
    old_version: Optional[str] = None
    new_version: Optional[str] = None
    old_vulnerabilities: List[str] = field(default_factory=list)
    new_vulnerabilities: List[str] = field(default_factory=list)
    new_vuln_ids: List[str] = field(default_factory=list)   # CVEs only in new
    fixed_vuln_ids: List[str] = field(default_factory=list) # CVEs only in old
    risk_delta: float = 0.0   # positive = increased risk

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "diff_type": self.diff_type,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "old_vulnerabilities": self.old_vulnerabilities,
            "new_vulnerabilities": self.new_vulnerabilities,
            "new_vuln_ids": self.new_vuln_ids,
            "fixed_vuln_ids": self.fixed_vuln_ids,
            "risk_delta": self.risk_delta,
        }


@dataclass
class SBOMDiffResult:
    added: List[ComponentDiff] = field(default_factory=list)
    removed: List[ComponentDiff] = field(default_factory=list)
    upgraded: List[ComponentDiff] = field(default_factory=list)
    downgraded: List[ComponentDiff] = field(default_factory=list)
    vuln_added: List[ComponentDiff] = field(default_factory=list)
    unchanged: List[ComponentDiff] = field(default_factory=list)
    total_added: int = 0
    total_removed: int = 0
    total_upgraded: int = 0
    total_downgraded: int = 0
    new_vulnerabilities: List[str] = field(default_factory=list)   # CVEs new in right BOM
    fixed_vulnerabilities: List[str] = field(default_factory=list) # CVEs only in left BOM
    risk_delta: float = 0.0   # aggregate risk change
    old_component_count: int = 0
    new_component_count: int = 0
    generated_at: str = ""
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "generated_at": self.generated_at,
            "old_component_count": self.old_component_count,
            "new_component_count": self.new_component_count,
            "total_added": self.total_added,
            "total_removed": self.total_removed,
            "total_upgraded": self.total_upgraded,
            "total_downgraded": self.total_downgraded,
            "new_vulnerabilities": self.new_vulnerabilities,
            "fixed_vulnerabilities": self.fixed_vulnerabilities,
            "risk_delta": self.risk_delta,
            "added": [c.to_dict() for c in self.added],
            "removed": [c.to_dict() for c in self.removed],
            "upgraded": [c.to_dict() for c in self.upgraded],
            "downgraded": [c.to_dict() for c in self.downgraded],
            "vuln_added": [c.to_dict() for c in self.vuln_added],
            "unchanged": [c.to_dict() for c in self.unchanged],
        }


# ---------------------------------------------------------------------------
# Version comparison helpers
# ---------------------------------------------------------------------------

def _parse_version(version: str) -> Tuple[int, ...]:
    """Parse a version string into a tuple of ints for comparison."""
    if not version:
        return (0,)
    parts = []
    for seg in version.strip().split("."):
        seg = seg.split("-")[0].split("+")[0]  # strip pre-release
        try:
            parts.append(int(seg))
        except ValueError:
            parts.append(0)
    return tuple(parts) if parts else (0,)


def _version_direction(old: str, new: str) -> str:
    """Return 'upgraded', 'downgraded', or 'unchanged'."""
    if not old or not new or old == new:
        return DiffType.UNCHANGED
    ov = _parse_version(old)
    nv = _parse_version(new)
    # Pad to same length
    maxlen = max(len(ov), len(nv))
    ov = ov + (0,) * (maxlen - len(ov))
    nv = nv + (0,) * (maxlen - len(nv))
    if nv > ov:
        return DiffType.UPGRADED
    if nv < ov:
        return DiffType.DOWNGRADED
    return DiffType.UNCHANGED


def _vuln_risk_weight(cve_id: str) -> float:
    """Estimate risk weight for a CVE ID (static heuristic)."""
    # Heuristic: no network call, use CVE year + sequence as rough proxy
    try:
        parts = cve_id.split("-")
        if len(parts) >= 3:
            seq = int(parts[2])
            # Higher sequence numbers tend to be more recent; cap risk at 0.9
            return min(0.5 + seq / 20000.0, 0.9)
    except (ValueError, IndexError):
        pass
    return 0.5


# ---------------------------------------------------------------------------
# Diff engine
# ---------------------------------------------------------------------------


class SBOMDiffEngine:
    """Compare two CycloneDX BOM objects and produce a structured SBOMDiffResult."""

    def diff(
        self,
        old_bom: CycloneDXBOM,
        new_bom: CycloneDXBOM,
    ) -> SBOMDiffResult:
        """Compute the diff between *old_bom* and *new_bom*."""
        result = SBOMDiffResult(
            generated_at=datetime.now(timezone.utc).isoformat(),
            old_component_count=len(old_bom.components),
            new_component_count=len(new_bom.components),
        )

        # Index by component name (case-insensitive)
        old_map: Dict[str, Component] = {c.name.lower(): c for c in old_bom.components}
        new_map: Dict[str, Component] = {c.name.lower(): c for c in new_bom.components}

        old_keys = set(old_map.keys())
        new_keys = set(new_map.keys())

        # ── Added components ──────────────────────────────────────────────────
        for key in sorted(new_keys - old_keys):
            comp = new_map[key]
            vuln_risk = sum(_vuln_risk_weight(v) for v in comp.vulnerabilities)
            diff = ComponentDiff(
                name=comp.name,
                diff_type=DiffType.ADDED,
                new_version=comp.version,
                new_vulnerabilities=list(comp.vulnerabilities),
                new_vuln_ids=list(comp.vulnerabilities),
                risk_delta=vuln_risk,
            )
            result.added.append(diff)
            result.new_vulnerabilities.extend(comp.vulnerabilities)

        # ── Removed components ────────────────────────────────────────────────
        for key in sorted(old_keys - new_keys):
            comp = old_map[key]
            vuln_risk = -sum(_vuln_risk_weight(v) for v in comp.vulnerabilities)
            diff = ComponentDiff(
                name=comp.name,
                diff_type=DiffType.REMOVED,
                old_version=comp.version,
                old_vulnerabilities=list(comp.vulnerabilities),
                fixed_vuln_ids=list(comp.vulnerabilities),
                risk_delta=vuln_risk,
            )
            result.removed.append(diff)
            result.fixed_vulnerabilities.extend(comp.vulnerabilities)

        # ── Changed components ────────────────────────────────────────────────
        for key in sorted(old_keys & new_keys):
            old_comp = old_map[key]
            new_comp = new_map[key]
            direction = _version_direction(old_comp.version, new_comp.version)

            old_vulns = set(old_comp.vulnerabilities)
            new_vulns = set(new_comp.vulnerabilities)
            new_vuln_ids = sorted(new_vulns - old_vulns)
            fixed_vuln_ids = sorted(old_vulns - new_vulns)

            risk_delta = sum(_vuln_risk_weight(v) for v in new_vuln_ids) - \
                         sum(_vuln_risk_weight(v) for v in fixed_vuln_ids)

            # Determine overall diff type
            if direction == DiffType.UNCHANGED and not new_vuln_ids and not fixed_vuln_ids:
                diff_type = DiffType.UNCHANGED
            elif new_vuln_ids and direction == DiffType.UNCHANGED:
                diff_type = DiffType.VULN_ADDED
            else:
                diff_type = direction

            diff = ComponentDiff(
                name=new_comp.name,
                diff_type=diff_type,
                old_version=old_comp.version,
                new_version=new_comp.version,
                old_vulnerabilities=sorted(old_vulns),
                new_vulnerabilities=sorted(new_vulns),
                new_vuln_ids=new_vuln_ids,
                fixed_vuln_ids=fixed_vuln_ids,
                risk_delta=risk_delta,
            )

            if diff_type == DiffType.UPGRADED:
                result.upgraded.append(diff)
            elif diff_type == DiffType.DOWNGRADED:
                result.downgraded.append(diff)
            elif diff_type == DiffType.VULN_ADDED:
                result.vuln_added.append(diff)
            else:
                result.unchanged.append(diff)

            result.new_vulnerabilities.extend(new_vuln_ids)
            result.fixed_vulnerabilities.extend(fixed_vuln_ids)

        # ── Aggregate counts ──────────────────────────────────────────────────
        result.total_added = len(result.added)
        result.total_removed = len(result.removed)
        result.total_upgraded = len(result.upgraded)
        result.total_downgraded = len(result.downgraded)
        result.risk_delta = round(
            sum(d.risk_delta for d in result.added + result.removed +
                result.upgraded + result.downgraded + result.vuln_added), 4
        )

        # Deduplicate vulnerability lists
        result.new_vulnerabilities = sorted(set(result.new_vulnerabilities))
        result.fixed_vulnerabilities = sorted(set(result.fixed_vulnerabilities))

        result.summary = (
            f"SBOM diff: +{result.total_added} added, -{result.total_removed} removed, "
            f"{result.total_upgraded} upgraded, {result.total_downgraded} downgraded; "
            f"{len(result.new_vulnerabilities)} new CVEs, "
            f"{len(result.fixed_vulnerabilities)} resolved CVEs; "
            f"risk delta={result.risk_delta:+.2f}"
        )

        return result

    def diff_json(self, old_json: str, new_json: str) -> SBOMDiffResult:
        """Parse two CycloneDX JSON strings and diff them."""
        old_bom = self._from_json(old_json)
        new_bom = self._from_json(new_json)
        return self.diff(old_bom, new_bom)

    @staticmethod
    def _from_json(raw: str) -> CycloneDXBOM:
        """Parse a CycloneDX JSON string into a CycloneDXBOM object."""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.warning("Invalid CycloneDX JSON: %s", exc)
            return CycloneDXBOM()

        from backend.sbom.cyclonedx import Component, ComponentType
        components: List[Component] = []
        for c in data.get("components", []):
            vulns = []
            for v in c.get("vulnerabilities", []):
                if isinstance(v, str):
                    vulns.append(v)
                elif isinstance(v, dict):
                    vid = v.get("id", "")
                    if vid:
                        vulns.append(vid)
            components.append(
                Component(
                    name=c.get("name", ""),
                    version=c.get("version", ""),
                    purl=c.get("purl", ""),
                    vulnerabilities=vulns,
                )
            )
        return CycloneDXBOM(components=components)

    def to_markdown(self, result: SBOMDiffResult) -> str:
        """Render *result* as a human-readable Markdown report."""
        lines = [
            "# SBOM Diff Report",
            "",
            f"**Generated:** {result.generated_at}",
            f"**Summary:** {result.summary}",
            f"**Risk delta:** {result.risk_delta:+.2f}",
            "",
        ]

        def _section(title: str, items: List[ComponentDiff], icon: str) -> None:
            if not items:
                return
            lines.append(f"## {icon} {title} ({len(items)})")
            lines.append("")
            lines.append("| Component | Old Version | New Version | New CVEs | Fixed CVEs |")
            lines.append("|-----------|-------------|-------------|----------|------------|")
            for d in items:
                lines.append(
                    f"| {d.name} | {d.old_version or '—'} | {d.new_version or '—'} "
                    f"| {', '.join(d.new_vuln_ids) or '—'} "
                    f"| {', '.join(d.fixed_vuln_ids) or '—'} |"
                )
            lines.append("")

        _section("Added", result.added, "➕")
        _section("Removed", result.removed, "➖")
        _section("Upgraded", result.upgraded, "⬆️")
        _section("Downgraded", result.downgraded, "⬇️")
        _section("New Vulnerabilities (same version)", result.vuln_added, "⚠️")

        if result.new_vulnerabilities:
            lines.append(f"## New CVEs Introduced ({len(result.new_vulnerabilities)})")
            lines.append("")
            for cve in result.new_vulnerabilities:
                lines.append(f"- {cve}")
            lines.append("")

        if result.fixed_vulnerabilities:
            lines.append(f"## CVEs Resolved ({len(result.fixed_vulnerabilities)})")
            lines.append("")
            for cve in result.fixed_vulnerabilities:
                lines.append(f"- {cve}")
            lines.append("")

        return "\n".join(lines)

    def to_json(self, result: SBOMDiffResult) -> str:
        """Serialise *result* to JSON."""
        return json.dumps(result.to_dict(), indent=2)
