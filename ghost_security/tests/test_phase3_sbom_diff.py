"""
tests/test_phase3_sbom_diff.py — Phase 3 SBOM Diff Engine tests.
20 tests covering ComponentDiff, SBOMDiffResult, version comparison, and export formats.
"""
import sys
import pathlib
import json

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.sbom.sbom_diff import (
    SBOMDiffEngine, SBOMDiffResult, ComponentDiff, DiffType,
)
from backend.sbom.cyclonedx import CycloneDXBOM, Component


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_bom(components):
    """Build a CycloneDXBOM from a list of (name, version, vulns) tuples."""
    comps = []
    for item in components:
        if len(item) == 2:
            name, version = item
            vulns = []
        else:
            name, version, vulns = item
        comps.append(Component(name=name, version=version, vulnerabilities=vulns))
    return CycloneDXBOM(components=comps)


_BOM_V1 = _make_bom([
    ("requests", "2.19.0", ["CVE-2018-18074"]),
    ("pyyaml", "5.3.1", ["CVE-2020-14343"]),
    ("flask", "1.0.0"),
    ("removed-pkg", "1.0.0"),
])

_BOM_V2 = _make_bom([
    ("requests", "2.28.0"),              # upgraded + vuln fixed
    ("pyyaml", "5.3.1", ["CVE-2020-14343"]),  # unchanged with vuln
    ("flask", "2.0.0"),                  # upgraded
    ("new-pkg", "0.1.0", ["CVE-2023-9999"]),  # added with vuln
])


# ─────────────────────────────────────────────────────────────────────────────
# Import / instantiation
# ─────────────────────────────────────────────────────────────────────────────

class TestImports:
    def test_sbom_diff_engine_importable(self):
        assert SBOMDiffEngine is not None

    def test_sbom_diff_result_importable(self):
        assert SBOMDiffResult is not None

    def test_component_diff_importable(self):
        assert ComponentDiff is not None

    def test_diff_type_has_added(self):
        assert hasattr(DiffType, "ADDED") or DiffType.ADDED == "added"

    def test_engine_instantiable(self):
        eng = SBOMDiffEngine()
        assert eng is not None


# ─────────────────────────────────────────────────────────────────────────────
# diff() method
# ─────────────────────────────────────────────────────────────────────────────

class TestDiff:
    def test_diff_returns_result(self):
        eng = SBOMDiffEngine()
        result = eng.diff(_BOM_V1, _BOM_V2)
        assert isinstance(result, SBOMDiffResult)

    def test_diff_detects_added(self):
        eng = SBOMDiffEngine()
        result = eng.diff(_BOM_V1, _BOM_V2)
        added_names = [c.name.lower() for c in result.added]
        assert any("new-pkg" in n for n in added_names)

    def test_diff_detects_removed(self):
        eng = SBOMDiffEngine()
        result = eng.diff(_BOM_V1, _BOM_V2)
        removed_names = [c.name.lower() for c in result.removed]
        assert any("removed-pkg" in n for n in removed_names)

    def test_diff_detects_upgraded(self):
        eng = SBOMDiffEngine()
        result = eng.diff(_BOM_V1, _BOM_V2)
        upgraded_names = [c.name.lower() for c in result.upgraded]
        assert any("requests" in n or "flask" in n for n in upgraded_names)

    def test_diff_counts_are_correct(self):
        eng = SBOMDiffEngine()
        result = eng.diff(_BOM_V1, _BOM_V2)
        assert result.total_added >= 1
        assert result.total_removed >= 1

    def test_diff_detects_new_vulnerabilities(self):
        eng = SBOMDiffEngine()
        result = eng.diff(_BOM_V1, _BOM_V2)
        assert "CVE-2023-9999" in result.new_vulnerabilities

    def test_diff_detects_fixed_vulnerabilities(self):
        eng = SBOMDiffEngine()
        result = eng.diff(_BOM_V1, _BOM_V2)
        assert "CVE-2018-18074" in result.fixed_vulnerabilities

    def test_diff_has_summary(self):
        eng = SBOMDiffEngine()
        result = eng.diff(_BOM_V1, _BOM_V2)
        assert isinstance(result.summary, str)
        assert len(result.summary) > 0

    def test_diff_identical_boms(self):
        eng = SBOMDiffEngine()
        result = eng.diff(_BOM_V1, _BOM_V1)
        assert result.total_added == 0
        assert result.total_removed == 0

    def test_diff_empty_boms(self):
        eng = SBOMDiffEngine()
        result = eng.diff(CycloneDXBOM(), CycloneDXBOM())
        assert result.total_added == 0
        assert result.total_removed == 0


# ─────────────────────────────────────────────────────────────────────────────
# diff_json()
# ─────────────────────────────────────────────────────────────────────────────

class TestDiffJson:
    def _make_json(self, components):
        comps = []
        for item in components:
            if len(item) == 2:
                name, version = item
                comps.append({"name": name, "version": version})
            else:
                name, version, vulns = item
                comps.append({"name": name, "version": version, "vulnerabilities": vulns})
        return json.dumps({"components": comps})

    def test_diff_json_returns_result(self):
        old_json = self._make_json([("requests", "2.19.0", ["CVE-2018-18074"])])
        new_json = self._make_json([("requests", "2.28.0")])
        eng = SBOMDiffEngine()
        result = eng.diff_json(old_json, new_json)
        assert isinstance(result, SBOMDiffResult)

    def test_diff_json_detects_upgrade(self):
        old_json = self._make_json([("flask", "1.0.0")])
        new_json = self._make_json([("flask", "2.0.0")])
        result = SBOMDiffEngine().diff_json(old_json, new_json)
        assert result.total_upgraded >= 1

    def test_diff_json_invalid_json_no_crash(self):
        result = SBOMDiffEngine().diff_json("{bad json", '{"components":[]}')
        assert isinstance(result, SBOMDiffResult)


# ─────────────────────────────────────────────────────────────────────────────
# Export formats
# ─────────────────────────────────────────────────────────────────────────────

class TestExports:
    def _make_result(self):
        return SBOMDiffEngine().diff(_BOM_V1, _BOM_V2)

    def test_to_json_returns_string(self):
        result = self._make_result()
        j = SBOMDiffEngine().to_json(result)
        assert isinstance(j, str)

    def test_to_json_is_valid_json(self):
        result = self._make_result()
        j = SBOMDiffEngine().to_json(result)
        data = json.loads(j)
        assert isinstance(data, dict)

    def test_to_markdown_returns_string(self):
        result = self._make_result()
        md = SBOMDiffEngine().to_markdown(result)
        assert isinstance(md, str)
        assert len(md) > 10

    def test_to_dict_has_required_keys(self):
        result = self._make_result()
        d = result.to_dict()
        assert "added" in d
        assert "removed" in d
        assert "upgraded" in d
        assert "new_vulnerabilities" in d
        assert "fixed_vulnerabilities" in d
