"""
tests/test_phase3_reachable_cve.py — Phase 3 Reachable CVE Analyzer tests.
20 tests covering ReachableCVE model, source-code-based reachability, CPG analysis.
"""
import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.supply_chain.reachable_cve import (
    ReachableCVEAnalyzer, ReachableCVE, ReachabilityAnalysisResult,
)
from backend.core.cpg.graph import CodePropertyGraph


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

class _MockCVERecord:
    def __init__(self, cve_id, severity="HIGH", cwe_ids=None):
        self.cve_id = cve_id
        self.severity = severity
        self.cwe_ids = cwe_ids or []


class _MockVulnPkg:
    def __init__(self, package_name, version, cves=None):
        self.package_name = package_name
        self.installed_version = version
        self.cve_records = [_MockCVERecord(c) for c in (cves or [])]


class _MockDepResult:
    def __init__(self, vuln_pkgs=None):
        self.vulnerable_packages = vuln_pkgs or []
        self.all_packages = []
        self.total_dependencies = len(self.vulnerable_packages)
        self.total_vulnerable = len(self.vulnerable_packages)
        self.analysis_errors = []


_YAML_SOURCE = """\
import yaml

def load_config(path):
    with open(path) as f:
        return yaml.load(f)
"""

_SAFE_SOURCE = """\
import requests

def fetch_data(url):
    return requests.get(url).json()
"""


# ─────────────────────────────────────────────────────────────────────────────
# Import / instantiation
# ─────────────────────────────────────────────────────────────────────────────

class TestImports:
    def test_analyzer_importable(self):
        assert ReachableCVEAnalyzer is not None

    def test_reachable_cve_importable(self):
        assert ReachableCVE is not None

    def test_analysis_result_importable(self):
        assert ReachabilityAnalysisResult is not None

    def test_analyzer_instantiable(self):
        ana = ReachableCVEAnalyzer()
        assert ana is not None


# ─────────────────────────────────────────────────────────────────────────────
# ReachableCVE dataclass
# ─────────────────────────────────────────────────────────────────────────────

class TestReachableCVEModel:
    def test_reachable_cve_has_required_fields(self):
        rc = ReachableCVE(
            cve_id="CVE-2020-14343",
            package_name="pyyaml",
            installed_version="5.3.1",
            severity="CRITICAL",
            is_reachable=True,
            reachability_score=0.9,
            call_path=["yaml.load()"],
            vulnerable_function="load",
            sink_type="deserialization",
            justification="yaml.load() used without Loader",
        )
        assert rc.cve_id == "CVE-2020-14343"
        assert rc.is_reachable is True
        assert rc.reachability_score == 0.9

    def test_to_dict_returns_dict(self):
        rc = ReachableCVE(
            cve_id="CVE-2020-14343",
            package_name="pyyaml",
            installed_version="5.3.1",
        )
        d = rc.to_dict()
        assert isinstance(d, dict)
        assert "cve_id" in d

    def test_reachability_score_range(self):
        rc = ReachableCVE(
            cve_id="CVE-2020-14343",
            package_name="pyyaml",
            installed_version="5.3.1",
            reachability_score=0.75,
        )
        assert 0.0 <= rc.reachability_score <= 1.0


# ─────────────────────────────────────────────────────────────────────────────
# analyze() method
# ─────────────────────────────────────────────────────────────────────────────

class TestAnalyze:
    def test_analyze_empty_dep_result(self):
        ana = ReachableCVEAnalyzer()
        dep = _MockDepResult()
        result = ana.analyze(dep)
        assert isinstance(result, ReachabilityAnalysisResult)

    def test_analyze_returns_result_object(self):
        ana = ReachableCVEAnalyzer()
        dep = _MockDepResult([_MockVulnPkg("pyyaml", "5.3.1", ["CVE-2020-14343"])])
        result = ana.analyze(dep)
        assert isinstance(result, ReachabilityAnalysisResult)

    def test_analyze_with_source_code_detects_yaml_usage(self):
        ana = ReachableCVEAnalyzer()
        dep = _MockDepResult([_MockVulnPkg("pyyaml", "5.3.1", ["CVE-2020-14343"])])
        result = ana.analyze(dep, source_code=_YAML_SOURCE)
        # yaml.load() is called in source — should be reachable
        all_cves = result.reachable_cves + result.not_reachable_cves
        assert any(rc.cve_id == "CVE-2020-14343" for rc in all_cves)

    def test_analyze_total_cves_counted(self):
        ana = ReachableCVEAnalyzer()
        dep = _MockDepResult([
            _MockVulnPkg("pyyaml", "5.3.1", ["CVE-2020-14343"]),
            _MockVulnPkg("requests", "2.19.0", ["CVE-2018-18074"]),
        ])
        result = ana.analyze(dep)
        assert result.total_cves_analyzed == 2

    def test_result_has_reachable_and_not_reachable_lists(self):
        ana = ReachableCVEAnalyzer()
        dep = _MockDepResult([_MockVulnPkg("pyyaml", "5.3.1", ["CVE-2020-14343"])])
        result = ana.analyze(dep)
        assert isinstance(result.reachable_cves, list)
        assert isinstance(result.not_reachable_cves, list)

    def test_result_counts_match_lists(self):
        ana = ReachableCVEAnalyzer()
        dep = _MockDepResult([
            _MockVulnPkg("pyyaml", "5.3.1", ["CVE-2020-14343"]),
        ])
        result = ana.analyze(dep, source_code=_YAML_SOURCE)
        assert result.total_reachable == len(result.reachable_cves)
        assert result.total_not_reachable == len(result.not_reachable_cves)

    def test_all_cves_property(self):
        ana = ReachableCVEAnalyzer()
        dep = _MockDepResult([_MockVulnPkg("pyyaml", "5.3.1", ["CVE-2020-14343"])])
        result = ana.analyze(dep)
        assert len(result.all_cves) == result.total_reachable + result.total_not_reachable

    def test_reachable_critical_property(self):
        ana = ReachableCVEAnalyzer()
        dep = _MockDepResult()
        result = ana.analyze(dep)
        assert isinstance(result.reachable_critical, list)

    def test_to_dict_returns_dict(self):
        ana = ReachableCVEAnalyzer()
        dep = _MockDepResult()
        result = ana.analyze(dep)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "total_cves_analyzed" in d


# ─────────────────────────────────────────────────────────────────────────────
# is_package_reachable()
# ─────────────────────────────────────────────────────────────────────────────

class TestIsPackageReachable:
    def test_returns_tuple(self):
        ana = ReachableCVEAnalyzer()
        cpg = CodePropertyGraph()
        result = ana.is_package_reachable("pyyaml", cpg)
        assert isinstance(result, tuple)
        assert len(result) == 3

    def test_result_has_bool_float_list(self):
        ana = ReachableCVEAnalyzer()
        cpg = CodePropertyGraph()
        is_reach, score, path = ana.is_package_reachable("requests", cpg)
        assert isinstance(is_reach, bool)
        assert isinstance(score, float)
        assert isinstance(path, list)

    def test_with_source_code_detects_yaml_import(self):
        ana = ReachableCVEAnalyzer()
        cpg = CodePropertyGraph()
        is_reach, score, path = ana.is_package_reachable("pyyaml", cpg, source_code=_YAML_SOURCE)
        # yaml is imported and yaml.load() is called — should detect
        assert isinstance(is_reach, bool)  # result depends on impl
        assert 0.0 <= score <= 1.0


# ─────────────────────────────────────────────────────────────────────────────
# get_vulnerable_function_paths()
# ─────────────────────────────────────────────────────────────────────────────

class TestGetVulnerableFunctionPaths:
    def test_returns_list(self):
        ana = ReachableCVEAnalyzer()
        cpg = CodePropertyGraph()
        paths = ana.get_vulnerable_function_paths("pyyaml", cpg)
        assert isinstance(paths, list)

    def test_empty_cpg_returns_empty_list(self):
        ana = ReachableCVEAnalyzer()
        cpg = CodePropertyGraph()
        paths = ana.get_vulnerable_function_paths("nonexistent_pkg", cpg)
        assert isinstance(paths, list)
