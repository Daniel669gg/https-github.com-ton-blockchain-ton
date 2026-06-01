"""
tests/test_phase1_dependency_taint.py — Tests for backend/core/supply_chain/dependency_taint.py
20 tests covering the embedded vuln DB, manifest parsing, version checking,
import tracking, and CPG taint node generation.
"""
import sys
import pathlib
import json

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.supply_chain import (
    KNOWN_VULNERABLE_PACKAGES, VulnerablePackage, InstalledPackage,
    ImportUsage, ManifestParser, VersionChecker, ImportTracker,
    DependencyTaintAnalyzer, DependencyAnalysisResult,
)
from backend.core.cpg.graph import CodePropertyGraph


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _pkg(name: str, version: str, ecosystem: str = "pypi") -> InstalledPackage:
    return InstalledPackage(
        name=name, version=version, ecosystem=ecosystem,
        is_dev=False, manifest_file="requirements.txt", line=1,
    )


# ─────────────────────────────────────────────────────────────────────────────
# KNOWN_VULNERABLE_PACKAGES database
# ─────────────────────────────────────────────────────────────────────────────

class TestVulnDatabase:
    def test_db_has_sufficient_pypi_entries(self):
        all_pkgs = [v for vulns in KNOWN_VULNERABLE_PACKAGES.values() for v in vulns]
        pypi = [v for v in all_pkgs if v.ecosystem == "pypi"]
        assert len(pypi) >= 5

    def test_db_has_npm_entries(self):
        all_pkgs = [v for vulns in KNOWN_VULNERABLE_PACKAGES.values() for v in vulns]
        npm = [v for v in all_pkgs if v.ecosystem == "npm"]
        assert len(npm) >= 3

    def test_every_entry_has_real_cve(self):
        import re
        cve_re = re.compile(r"^CVE-\d{4}-\d+$")
        for pkg_name, vulns in KNOWN_VULNERABLE_PACKAGES.items():
            for v in vulns:
                cves = v.cve_ids if hasattr(v, "cve_ids") else [v.cve_id]
                for cve in cves:
                    assert cve_re.match(cve), f"{pkg_name}: bad CVE '{cve}'"

    def test_every_entry_has_valid_severity(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for pkg_name, vulns in KNOWN_VULNERABLE_PACKAGES.items():
            for v in vulns:
                assert v.severity in valid, f"{pkg_name}: bad severity '{v.severity}'"

    def test_every_entry_has_cwe(self):
        for pkg_name, vulns in KNOWN_VULNERABLE_PACKAGES.items():
            for v in vulns:
                cwes = v.cwe_ids if hasattr(v, "cwe_ids") else [v.cwe_id]
                for cwe in cwes:
                    assert cwe.startswith("CWE-"), f"{pkg_name}: bad CWE '{cwe}'"

    def test_pyyaml_critical_rce_in_db(self):
        assert "pyyaml" in KNOWN_VULNERABLE_PACKAGES
        pyyaml_vulns = KNOWN_VULNERABLE_PACKAGES["pyyaml"]
        assert any(v.severity == "CRITICAL" for v in pyyaml_vulns)

    def test_lodash_in_db_npm(self):
        assert "lodash" in KNOWN_VULNERABLE_PACKAGES
        lodash_vulns = KNOWN_VULNERABLE_PACKAGES["lodash"]
        assert any(v.ecosystem == "npm" for v in lodash_vulns)


# ─────────────────────────────────────────────────────────────────────────────
# ManifestParser
# ─────────────────────────────────────────────────────────────────────────────

class TestManifestParser:
    def setup_method(self):
        self.parser = ManifestParser()

    def test_requirements_txt_pinned(self):
        content = "requests==2.19.0\npyyaml==5.3.1\nflask==0.12\n"
        pkgs = self.parser.parse_requirements_txt(content)
        names = {p.name for p in pkgs}
        assert "requests" in names and "pyyaml" in names

    def test_requirements_txt_version_extracted(self):
        content = "requests==2.19.0\n"
        pkgs = self.parser.parse_requirements_txt(content)
        assert pkgs[0].version == "2.19.0"

    def test_requirements_txt_skips_comments(self):
        content = "# comment\nrequests==2.19.0\n# another\n"
        pkgs = self.parser.parse_requirements_txt(content)
        assert len(pkgs) == 1

    def test_requirements_txt_skips_options(self):
        content = "-r other.txt\n--index-url https://pypi.org\nrequests==2.0\n"
        pkgs = self.parser.parse_requirements_txt(content)
        assert len(pkgs) == 1

    def test_package_json_parsed(self):
        content = json.dumps({
            "dependencies": {"lodash": "^4.17.0", "axios": "1.5.0"},
            "devDependencies": {"jest": "29.0.0"},
        })
        pkgs = self.parser.parse_package_json(content)
        names = {p.name for p in pkgs}
        assert "lodash" in names
        assert "axios" in names

    def test_package_json_dev_flag_set(self):
        content = json.dumps({
            "dependencies": {"axios": "1.5.0"},
            "devDependencies": {"jest": "29.0.0"},
        })
        pkgs = self.parser.parse_package_json(content)
        dev = {p.name for p in pkgs if p.is_dev}
        assert "jest" in dev

    def test_pyproject_toml_poetry_format(self):
        content = (
            "[tool.poetry.dependencies]\n"
            "python = \"^3.9\"\n"
            "pyyaml = \"5.3.1\"\n"
            "requests = \"^2.19\"\n"
        )
        pkgs = self.parser.parse_pyproject_toml(content)
        names = {p.name for p in pkgs}
        assert len(names) >= 1  # at least one parsed (python excluded)


# ─────────────────────────────────────────────────────────────────────────────
# VersionChecker
# ─────────────────────────────────────────────────────────────────────────────

class TestVersionChecker:
    def setup_method(self):
        self.checker = VersionChecker()

    def test_pyyaml_534_vulnerable(self):
        """pyyaml 5.3.4 is below the <5.4 threshold."""
        vuln = self.checker.is_vulnerable(_pkg("pyyaml", "5.3.4"))
        assert vuln is not None
        cves = vuln.cve_ids if hasattr(vuln, "cve_ids") else [vuln.cve_id]
        assert any("CVE" in c for c in cves)

    def test_pyyaml_541_safe(self):
        """pyyaml 5.4.1 is at/above fix version."""
        vuln = self.checker.is_vulnerable(_pkg("pyyaml", "5.4.1"))
        assert vuln is None

    def test_lodash_41720_vulnerable(self):
        vuln = self.checker.is_vulnerable(_pkg("lodash", "4.17.20", "npm"))
        assert vuln is not None

    def test_lodash_41721_safe(self):
        vuln = self.checker.is_vulnerable(_pkg("lodash", "4.17.21", "npm"))
        assert vuln is None

    def test_unknown_package_none(self):
        vuln = self.checker.is_vulnerable(_pkg("totally_unknown_xyz", "1.0.0"))
        assert vuln is None

    def test_empty_version_none(self):
        vuln = self.checker.is_vulnerable(_pkg("pyyaml", ""))
        assert vuln is None


# ─────────────────────────────────────────────────────────────────────────────
# ImportTracker
# ─────────────────────────────────────────────────────────────────────────────

class TestImportTracker:
    def setup_method(self):
        self.tracker = ImportTracker()

    def test_find_python_import(self):
        src = "import yaml\ndata = yaml.load(open('f.yaml'))\n"
        # ImportTracker matches by import module name, not PyPI package name
        usages = self.tracker.find_python_imports(src, "yaml")
        assert len(usages) >= 1
        assert usages[0].package_name == "yaml"

    def test_find_python_from_import(self):
        src = "from flask import Flask, request\napp = Flask(__name__)\n"
        usages = self.tracker.find_python_imports(src, "flask")
        assert len(usages) >= 1

    def test_find_js_require_import(self):
        src = "const _ = require('lodash');\nconst x = _.merge({}, user);\n"
        usages = self.tracker.find_js_imports(src, "lodash")
        assert len(usages) >= 1

    def test_find_js_esm_import(self):
        src = "import axios from 'axios';\nconst r = await axios.get(url);\n"
        usages = self.tracker.find_js_imports(src, "axios")
        assert len(usages) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# DependencyTaintAnalyzer integration
# ─────────────────────────────────────────────────────────────────────────────

class TestDependencyTaintAnalyzer:
    def test_analyze_manifest_returns_result(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("pyyaml==5.3.1\nrequests==2.19.0\n")
        result = DependencyTaintAnalyzer().analyze_manifest(str(req))
        assert isinstance(result, DependencyAnalysisResult)

    def test_vulnerable_packages_detected(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("pyyaml==5.3.1\n")
        result = DependencyTaintAnalyzer().analyze_manifest(str(req))
        assert result.total_vulnerable >= 1
        assert result.critical_count >= 1

    def test_safe_packages_not_flagged(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("pyyaml==5.4.1\nlodash==4.17.21\n")
        result = DependencyTaintAnalyzer().analyze_manifest(str(req))
        assert result.total_vulnerable == 0

    def test_generate_cpg_taint_nodes(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("pyyaml==5.3.1\n")
        src = "import yaml\ndata = yaml.load(open('config.yaml'))\n"
        result = DependencyTaintAnalyzer().analyze_manifest(str(req), source_code=src)
        cpg = CodePropertyGraph()
        added = DependencyTaintAnalyzer().generate_cpg_taint_nodes(result, cpg)
        assert isinstance(added, list)

    def test_analysis_result_counts(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("pyyaml==5.3.1\nrequests==2.19.0\nflask==2.3.0\n")
        result = DependencyTaintAnalyzer().analyze_manifest(str(req))
        assert result.total_dependencies >= 2
        assert isinstance(result.analysis_errors, list)
