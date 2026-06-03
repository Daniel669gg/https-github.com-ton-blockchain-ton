# TythanAI Security Platform — Community Edition
# Copyright (c) 2026 TythanAI Labs
# Licensed under the Business Source License 1.1 (see LICENSE).

"""
tests/test_community_edition.py — Community Edition test suite.

Covers: gates, scanner, report (SARIF + HTML), CLI integration.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# ─── gates ────────────────────────────────────────────────────────────────────

from community.gates import (
    COMMUNITY_LIMITS,
    PREMIUM_FEATURES,
    GatedResult,
    gate,
    is_premium,
)


class TestGates:
    def test_all_premium_keys_present(self):
        expected = {
            "autopr", "dast", "cpg_taint", "ai_fix", "rules_marketplace",
            "saas_dashboard", "webhooks", "economic_risk", "sbom_compliance",
            "p2p_consensus", "full_ruleset", "code_quality_adv", "multi_agent",
        }
        assert expected.issubset(set(PREMIUM_FEATURES.keys()))

    def test_gate_returns_gated_result(self):
        g = gate("autopr")
        assert isinstance(g, GatedResult)
        assert g.is_gated is True
        assert g.feature_key == "autopr"

    def test_gated_result_title_contains_premium(self):
        g = gate("dast")
        assert "PREMIUM" in g.title or "DAST" in g.title.upper()

    def test_gated_result_upgrade_message_contains_url(self):
        g = gate("cpg_taint")
        assert "tythanai.io" in g.upgrade_message

    def test_gated_result_to_dict(self):
        g = gate("ai_fix")
        d = g.to_dict()
        assert d["gated"] is True
        assert d["feature"] == "ai_fix"
        assert "upgrade_url" in d

    def test_is_premium_true_for_known_feature(self):
        assert is_premium("autopr") is True
        assert is_premium("dast") is True

    def test_is_premium_false_for_unknown(self):
        assert is_premium("sast") is False
        assert is_premium("sca") is False

    def test_community_limits_present(self):
        assert COMMUNITY_LIMITS["max_rules"] <= 500
        assert COMMUNITY_LIMITS["web3_rules_per_chain"] <= 5
        assert COMMUNITY_LIMITS["max_files"] > 0


# ─── scanner ──────────────────────────────────────────────────────────────────

from community.scanner import CommunityScanner, ScanResult, _normalise


class TestScanResult:
    def _make(self, findings: list) -> ScanResult:
        r = ScanResult(target="/tmp/test")
        r.sast_findings = findings
        return r

    def test_total_counts_all_sources(self):
        r = ScanResult(target="/tmp/x")
        r.sast_findings    = [{"severity": "HIGH"}]
        r.sca_findings     = [{"severity": "MEDIUM"}]
        r.secrets_findings = [{"severity": "CRITICAL"}]
        assert r.total == 3

    def test_by_severity_counts(self):
        r = self._make([
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
        ])
        s = r.by_severity
        assert s["CRITICAL"] == 1
        assert s["HIGH"] == 2
        assert s["MEDIUM"] == 1
        assert s["LOW"] == 0

    def test_risk_score_critical(self):
        r = self._make([{"severity": "CRITICAL"}, {"severity": "CRITICAL"}])
        assert r.risk_score() == min(100, 50)

    def test_risk_score_empty_is_zero(self):
        r = self._make([])
        assert r.risk_score() == 0

    def test_risk_level_clean_when_no_findings(self):
        r = self._make([])
        assert r.risk_level() == "CLEAN"

    def test_risk_level_high_for_high_score(self):
        r = self._make([{"severity": "CRITICAL"}, {"severity": "CRITICAL"}])
        assert r.risk_level() in ("CRITICAL", "HIGH")

    def test_risk_level_medium(self):
        r = self._make([{"severity": "MEDIUM"}, {"severity": "LOW"}])
        level = r.risk_level()
        assert level in ("MEDIUM", "LOW")

    def test_risk_score_capped_at_100(self):
        findings = [{"severity": "CRITICAL"}] * 10
        r = self._make(findings)
        assert r.risk_score() == 100


class TestNormalise:
    def test_dict_passthrough(self):
        f = {"severity": "HIGH", "title": "Test", "file": "foo.py", "line": 5}
        result = _normalise(f, source="sast")
        assert result["severity"] == "HIGH"
        assert result["source"] == "sast"

    def test_sets_default_severity(self):
        f = {"title": "Something"}
        result = _normalise(f, source="sca")
        assert result["severity"] == "INFO"

    def test_sets_default_title_from_message(self):
        f = {"message": "Dangerous call"}
        result = _normalise(f, source="secrets")
        assert result["title"] == "Dangerous call"

    def test_object_with_to_dict(self):
        class Fake:
            def to_dict(self):
                return {"severity": "LOW", "title": "x"}
        result = _normalise(Fake(), source="web3:ton")
        assert result["severity"] == "LOW"
        assert result["source"] == "web3:ton"

    def test_unknown_object_becomes_raw(self):
        result = _normalise(42, source="iac")
        assert "raw" in result
        assert result["severity"] == "INFO"


class TestCommunityScannerOnRealFS:
    """Run the scanner against a tiny synthetic project directory."""

    @pytest.fixture
    def project(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "import os\npassword = 'supersecret'\neval(input())\n"
        )
        (tmp_path / "requirements.txt").write_text("django==3.2.0\npyyaml==5.3.1\n")
        (tmp_path / "infra.tf").write_text(
            'resource "aws_s3_bucket" "b" { bucket = "my-bucket" acl = "public-read" }\n'
        )
        return tmp_path

    def test_scan_returns_scan_result(self, project):
        scanner = CommunityScanner(str(project))
        result = scanner.run()
        assert isinstance(result, ScanResult)

    def test_scan_has_gated_features(self, project):
        scanner = CommunityScanner(str(project))
        result = scanner.run()
        assert len(result.gated_features) >= 5

    def test_gated_features_are_gated_results(self, project):
        scanner = CommunityScanner(str(project))
        result = scanner.run()
        for g in result.gated_features:
            assert g.is_gated is True

    def test_scan_does_not_raise(self, project):
        scanner = CommunityScanner(str(project))
        result = scanner.run(
            sast=True, sca=True, secrets=True, iac=True, web3=True
        )
        assert result is not None

    def test_scan_premium_flags_are_gated(self, project):
        scanner = CommunityScanner(str(project))
        result = scanner.run(autopr=True, dast=True)
        gated_keys = {g.feature_key for g in result.gated_features}
        assert "autopr" in gated_keys
        assert "dast" in gated_keys

    def test_partial_scan_no_web3(self, project):
        scanner = CommunityScanner(str(project))
        result = scanner.run(web3=False)
        assert result.web3_findings == []

    def test_scan_result_target_is_absolute(self, project):
        scanner = CommunityScanner(str(project))
        result = scanner.run()
        assert Path(result.target).is_absolute()


# ─── report ───────────────────────────────────────────────────────────────────

from community.report import to_sarif, to_html, write_sarif, write_html


def _make_result_with_findings() -> ScanResult:
    r = ScanResult(target="/tmp/demo")
    r.sast_findings = [
        {"severity": "HIGH",   "title": "eval() usage",    "file": "app.py", "line": 3,  "rule_id": "PY001", "source": "sast"},
        {"severity": "MEDIUM", "title": "Hardcoded string", "file": "app.py", "line": 1,  "rule_id": "PY002", "source": "sast"},
    ]
    r.sca_findings = [
        {"severity": "CRITICAL", "title": "CVE-2020-14343 pyyaml RCE", "file": "requirements.txt", "line": 2, "source": "sca"},
    ]
    return r


class TestSARIF:
    def test_sarif_schema_present(self):
        r = _make_result_with_findings()
        sarif = to_sarif(r)
        assert "$schema" in sarif
        assert sarif["version"] == "2.1.0"

    def test_sarif_has_runs(self):
        r = _make_result_with_findings()
        sarif = to_sarif(r)
        assert len(sarif["runs"]) == 1

    def test_sarif_results_count(self):
        r = _make_result_with_findings()
        sarif = to_sarif(r)
        assert len(sarif["runs"][0]["results"]) == 3

    def test_sarif_levels(self):
        r = _make_result_with_findings()
        sarif = to_sarif(r)
        levels = {res["level"] for res in sarif["runs"][0]["results"]}
        assert "error" in levels

    def test_sarif_location_structure(self):
        r = _make_result_with_findings()
        sarif = to_sarif(r)
        loc = sarif["runs"][0]["results"][0]["locations"][0]
        assert "physicalLocation" in loc
        assert "region" in loc["physicalLocation"]

    def test_sarif_cap_at_200(self):
        r = ScanResult(target="/tmp/x")
        r.sast_findings = [{"severity": "LOW", "title": f"f{i}"} for i in range(300)]
        sarif = to_sarif(r)
        assert len(sarif["runs"][0]["results"]) == 200

    def test_write_sarif_creates_file(self, tmp_path):
        r = _make_result_with_findings()
        out = str(tmp_path / "out.sarif")
        write_sarif(r, out)
        data = json.loads(Path(out).read_text())
        assert data["version"] == "2.1.0"

    def test_sarif_tool_name(self):
        r = _make_result_with_findings()
        sarif = to_sarif(r)
        assert "TythanAI" in sarif["runs"][0]["tool"]["driver"]["name"]


class TestHTMLReport:
    def test_html_contains_tythanai(self):
        r = _make_result_with_findings()
        h = to_html(r)
        assert "TythanAI" in h

    def test_html_contains_risk_level(self):
        r = _make_result_with_findings()
        h = to_html(r)
        assert r.risk_level() in h

    def test_html_premium_section(self):
        r = _make_result_with_findings()
        h = to_html(r)
        assert "PREMIUM" in h or "Unlock" in h

    def test_html_contains_upgrade_url(self):
        r = _make_result_with_findings()
        h = to_html(r)
        assert "tythanai.io" in h

    def test_html_escapes_xss(self):
        r = ScanResult(target="/tmp/x")
        r.sast_findings = [
            {"severity": "HIGH", "title": "<script>alert(1)</script>",
             "file": "x.py", "line": 1, "source": "sast"}
        ]
        h = to_html(r)
        assert "<script>alert(1)</script>" not in h

    def test_write_html_creates_file(self, tmp_path):
        r = _make_result_with_findings()
        out = str(tmp_path / "report.html")
        write_html(r, out)
        content = Path(out).read_text()
        assert "<!DOCTYPE html>" in content

    def test_html_shows_severity_counts(self):
        r = _make_result_with_findings()
        h = to_html(r)
        assert "CRITICAL" in h
        assert "HIGH" in h

    def test_html_clean_project_shows_no_findings_message(self):
        r = ScanResult(target="/tmp/clean")
        h = to_html(r)
        assert "clean" in h.lower() or "No findings" in h


# ─── CLI integration ──────────────────────────────────────────────────────────

class TestCLI:
    _ROOT = Path(__file__).resolve().parent.parent

    def _run(self, *args, **kwargs):
        cmd = [sys.executable, str(self._ROOT / "tythanai_community_cli.py")] + list(args)
        return subprocess.run(cmd, capture_output=True, text=True,
                              cwd=str(self._ROOT), **kwargs)

    def test_version_exits_0(self):
        r = self._run("version")
        assert r.returncode == 0

    def test_version_output_contains_community(self):
        r = self._run("version")
        assert "Community" in r.stdout

    def test_no_args_exits_0(self):
        r = self._run()
        assert r.returncode == 0

    def test_scan_nonexistent_path_exits_1(self):
        r = self._run("scan", "/nonexistent/path/xyz")
        assert r.returncode == 1

    def test_scan_runs_on_real_directory(self):
        r = self._run("scan", str(self._ROOT), "--no-sast", "--no-sca",
                      "--no-secrets", "--no-iac", "--no-web3", "--quiet")
        assert r.returncode in (0, 1, 2, 3)

    def test_scan_quiet_flag_suppresses_banner(self):
        r = self._run("scan", str(self._ROOT), "--no-sast", "--no-sca",
                      "--no-secrets", "--no-iac", "--no-web3", "--quiet")
        assert "TythanAI" not in r.stdout

    def test_scan_sarif_output(self, tmp_path):
        sarif_path = str(tmp_path / "out.sarif")
        r = self._run("scan", str(self._ROOT), "--no-sast", "--no-sca",
                      "--no-secrets", "--no-iac", "--no-web3",
                      "--sarif", sarif_path, "--quiet")
        assert r.returncode in (0, 1, 2, 3)
        assert Path(sarif_path).exists()
        data = json.loads(Path(sarif_path).read_text())
        assert data["version"] == "2.1.0"

    def test_scan_html_output(self, tmp_path):
        html_path = str(tmp_path / "report.html")
        r = self._run("scan", str(self._ROOT), "--no-sast", "--no-sca",
                      "--no-secrets", "--no-iac", "--no-web3",
                      "--html", html_path, "--quiet")
        assert r.returncode in (0, 1, 2, 3)
        assert Path(html_path).exists()
        assert "TythanAI" in Path(html_path).read_text()

    def test_scan_json_output(self, tmp_path):
        json_path = str(tmp_path / "findings.json")
        r = self._run("scan", str(self._ROOT), "--no-sast", "--no-sca",
                      "--no-secrets", "--no-iac", "--no-web3",
                      "--json", json_path, "--quiet")
        assert r.returncode in (0, 1, 2, 3)
        assert Path(json_path).exists()
        data = json.loads(Path(json_path).read_text())
        assert "findings" in data
        assert "risk_level" in data
        assert "risk_score" in data
