"""Tests for CVE intelligence, CycloneDX SBOM, SPDX, and VEX modules.

All tests are offline — no real HTTP calls are made. httpx.AsyncClient is
mocked where the async code path requires it.
"""

from __future__ import annotations

import json
import sys
import os

# Ensure the project root is on the path so imports resolve correctly.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import pytest

from ghost_security.backend.sbom.cyclonedx import CycloneDXGenerator, generate_cyclonedx
from ghost_security.backend.sbom.spdx import SPDXGenerator, generate_spdx
from ghost_security.backend.sbom.vex import VEXGenerator, VEXStatus

# ---------------------------------------------------------------------------
# Test 1: parse_requirements
# ---------------------------------------------------------------------------


def test_parse_requirements(tmp_path):
    """CycloneDXGenerator.parse_requirements handles a variety of formats."""
    content = (
        "# a comment\n"
        "requests==2.28.2\n"
        "flask>=2.0.0\n"
        "numpy==1.24.0\n"
        "Pillow[jpeg]==9.4.0\n"  # extras
        "boto3>=1.26.0  # inline comment\n"
        "-r other-requirements.txt\n"   # should be skipped
        "\n"
        "setuptools\n"   # name-only
        "Django~=4.2.0\n"
        "some-pkg; python_version>='3.8'\n"  # environment marker, name-only result
    )
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(content, encoding="utf-8")

    gen = CycloneDXGenerator()
    results = gen.parse_requirements(str(req_file))
    result_map = {name: version for name, version in results}

    assert "requests" in result_map
    assert result_map["requests"] == "2.28.2"

    assert "flask" in result_map
    assert result_map["flask"] == "2.0.0"

    assert "numpy" in result_map
    assert result_map["numpy"] == "1.24.0"

    # Extras should be stripped from the package name
    assert "Pillow" in result_map
    assert result_map["Pillow"] == "9.4.0"

    assert "boto3" in result_map

    # Name-only entry
    assert "setuptools" in result_map
    assert result_map["setuptools"] == ""

    # ~= version operator
    assert "Django" in result_map
    assert result_map["Django"] == "4.2.0"

    # -r line should NOT be included
    assert all("-r" not in name for name, _ in results)


# ---------------------------------------------------------------------------
# Test 2: generate_purl
# ---------------------------------------------------------------------------


def test_generate_purl():
    """CycloneDXGenerator.generate_purl returns correctly formatted PURLs."""
    gen = CycloneDXGenerator()

    assert gen.generate_purl("pypi", "requests", "2.28.0") == "pkg:pypi/requests@2.28.0"
    assert gen.generate_purl("PyPI", "Flask", "2.3.0") == "pkg:pypi/flask@2.3.0"
    assert gen.generate_purl("npm", "lodash", "4.17.21") == "pkg:npm/lodash@4.17.21"
    assert gen.generate_purl("go", "github.com/gin-gonic/gin", "v1.9.0") == (
        "pkg:golang/github.com/gin-gonic/gin@v1.9.0"
    )
    assert gen.generate_purl("cargo", "serde", "1.0.160") == "pkg:cargo/serde@1.0.160"

    # Version-less PURL
    assert gen.generate_purl("pypi", "some-lib", "") == "pkg:pypi/some-lib"


# ---------------------------------------------------------------------------
# Test 3: CycloneDX JSON structure
# ---------------------------------------------------------------------------


def test_cyclonedx_json_structure(tmp_path):
    """generate_cyclonedx returns valid JSON with required top-level fields."""
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.28.2\nflask==2.3.0\n", encoding="utf-8")

    json_str = generate_cyclonedx(str(tmp_path))
    doc = json.loads(json_str)

    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.4"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert "metadata" in doc
    assert "components" in doc
    assert isinstance(doc["components"], list)

    # metadata should have a timestamp
    assert "timestamp" in doc["metadata"]

    # tools should mention ghost-security
    tools = doc["metadata"].get("tools", [])
    assert any("ghost-security" in t.get("name", "") for t in tools)

    # All components must have name and type
    for comp in doc["components"]:
        assert "name" in comp
        assert "type" in comp


# ---------------------------------------------------------------------------
# Test 4: SPDX tag-value output
# ---------------------------------------------------------------------------


def test_spdx_tag_value(tmp_path):
    """SPDXGenerator.to_tag_value output includes mandatory SPDX header tags."""
    req = tmp_path / "requirements.txt"
    req.write_text("httpx==0.24.0\nscipy==1.11.0\n", encoding="utf-8")

    gen = SPDXGenerator()
    doc = gen.generate(str(tmp_path))
    tag_value = gen.to_tag_value(doc)

    assert "SPDXVersion: SPDX-2.3" in tag_value
    assert "DataLicense: CC0-1.0" in tag_value
    assert "SPDXID: SPDXRef-DOCUMENT" in tag_value
    assert "DocumentNamespace:" in tag_value
    assert "Creator:" in tag_value
    assert "Created:" in tag_value
    assert "PackageName: httpx" in tag_value
    assert "PackageName: scipy" in tag_value
    assert "Relationship:" in tag_value


# ---------------------------------------------------------------------------
# Test 5: VEX statement creation and JSON output
# ---------------------------------------------------------------------------


def test_vex_statement():
    """VEXGenerator creates a valid statement and serialises to CycloneDX VEX JSON."""
    gen = VEXGenerator()
    stmt = gen.create_statement(
        cve_id="CVE-2023-1234",
        product="requests@2.28.0",
        status=VEXStatus.AFFECTED,
        action_statement="Upgrade to requests>=2.31.0",
        impact_statement="Remote code execution via malformed URL.",
    )

    assert stmt.vulnerability_id == "CVE-2023-1234"
    assert stmt.product == "requests@2.28.0"
    assert stmt.status == VEXStatus.AFFECTED
    assert stmt.timestamp != ""

    from ghost_security.backend.sbom.vex import VEXDocument

    doc = VEXDocument(
        id="urn:uuid:test-id-001",
        timestamp=stmt.timestamp,
        statements=[stmt],
    )
    json_str = gen.to_json(doc)
    parsed = json.loads(json_str)

    assert parsed["bomFormat"] == "CycloneDX"
    assert parsed["specVersion"] == "1.4"
    vulns = parsed["vulnerabilities"]
    assert len(vulns) == 1
    assert vulns[0]["id"] == "CVE-2023-1234"
    assert vulns[0]["analysis"]["state"] == "affected"
    assert "response" in vulns[0]["analysis"]


# ---------------------------------------------------------------------------
# Test 6: CycloneDX component count
# ---------------------------------------------------------------------------


def test_cyclonedx_component_count(tmp_path):
    """A requirements.txt with exactly 3 packages produces exactly 3 BOM components."""
    req = tmp_path / "requirements.txt"
    req.write_text(
        "requests==2.28.2\nflask==2.3.0\nnumpy==1.24.0\n",
        encoding="utf-8",
    )

    gen = CycloneDXGenerator()
    bom = gen.generate(str(tmp_path))

    assert len(bom.components) == 3

    names = {c.name for c in bom.components}
    assert "requests" in names
    assert "flask" in names
    assert "numpy" in names

    # Each component should have a PURL
    for comp in bom.components:
        assert comp.purl.startswith("pkg:pypi/")
