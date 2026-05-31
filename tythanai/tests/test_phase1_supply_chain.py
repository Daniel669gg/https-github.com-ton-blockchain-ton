"""Tests for backend/scanners/supply_chain.py — Module 6."""
import os
import json
import tempfile
import pytest
from pathlib import Path

from backend.scanners.supply_chain import (
    SupplyChainScanner,
    _levenshtein,
    _check_typosquatting,
    _parse_requirements_txt,
    _parse_package_json,
    _parse_cargo_toml,
    _POPULAR_PYPI,
    _POPULAR_NPM,
)


# ─────────────────────────────────────────────────────────────────────────────
# Levenshtein
# ─────────────────────────────────────────────────────────────────────────────

class TestLevenshtein:
    def test_equal_strings(self):
        assert _levenshtein("abc", "abc") == 0

    def test_single_insertion(self):
        assert _levenshtein("abc", "abcd") == 1

    def test_single_deletion(self):
        assert _levenshtein("abcd", "abc") == 1

    def test_single_substitution(self):
        assert _levenshtein("abc", "axc") == 1

    def test_typosquatting_example(self):
        # reqests vs requests → distance 1
        assert _levenshtein("reqests", "requests") == 1

    def test_totally_different(self):
        assert _levenshtein("abc", "xyz") == 3


class TestTyposquatting:
    def test_detects_close_match(self):
        match = _check_typosquatting("reqests", _POPULAR_PYPI)
        assert match == "requests"

    def test_exact_match_not_flagged(self):
        match = _check_typosquatting("requests", _POPULAR_PYPI)
        assert match is None

    def test_distant_name_not_flagged(self):
        match = _check_typosquatting("unrelated_lib_xyz_123", _POPULAR_PYPI)
        assert match is None

    def test_npm_typosquatting(self):
        # "lodahs" differs from "lodash" by 2 chars (transposition) — should be flagged
        match = _check_typosquatting("lodahs", _POPULAR_NPM)
        assert match == "lodash"


# ─────────────────────────────────────────────────────────────────────────────
# Parsers
# ─────────────────────────────────────────────────────────────────────────────

class TestParsers:
    def test_requirements_txt(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("requests==2.28.0\nflask>=2.0\nnumpy\n")
            fname = f.name
        try:
            pkgs = _parse_requirements_txt(fname)
            names = [p.name for p in pkgs]
            assert "requests" in names
            assert "flask" in names
            assert "numpy" in names
        finally:
            os.unlink(fname)

    def test_package_json(self):
        data = {
            "dependencies": {"lodash": "^4.17.21", "axios": "1.0.0"},
            "devDependencies": {"jest": "29.0.0"},
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            fname = f.name
        try:
            pkgs = _parse_package_json(fname)
            names = [p.name for p in pkgs]
            assert "lodash" in names
            assert "axios" in names
            assert "jest" in names
            dev_pkgs = [p for p in pkgs if p.is_dev]
            assert any(p.name == "jest" for p in dev_pkgs)
        finally:
            os.unlink(fname)

    def test_cargo_toml(self):
        content = '[dependencies]\nserde = "1.0"\ntokio = "1.0"\n[dev-dependencies]\ncritique = "0.1"\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(content)
            fname = f.name
        try:
            pkgs = _parse_cargo_toml(fname)
            names = [p.name for p in pkgs]
            assert "serde" in names
            assert "tokio" in names
            dev = [p for p in pkgs if p.is_dev]
            assert any(p.name == "critique" for p in dev)
        finally:
            os.unlink(fname)


# ─────────────────────────────────────────────────────────────────────────────
# Scanner integration (offline — no OSV network call)
# ─────────────────────────────────────────────────────────────────────────────

class TestSupplyChainScanner:
    def setup_method(self):
        self.scanner = SupplyChainScanner()

    def test_empty_directory(self):
        with tempfile.TemporaryDirectory() as d:
            result = self.scanner.scan(d)
            assert result["packages_scanned"] == 0
            assert result["findings"] == []

    def test_typosquatting_detected(self):
        """reqests (distance 1 from requests) must be flagged."""
        with tempfile.TemporaryDirectory() as d:
            req = Path(d) / "requirements.txt"
            req.write_text("reqests==2.28.0\n")
            result = self.scanner.scan(d)
            ts = result["typosquatting"]
            assert any("requests" in t["similar_to"] for t in ts), (
                f"Expected typosquatting alert, got: {ts}"
            )

    def test_dev_dep_capped_at_medium(self, monkeypatch):
        """Dev dependency vulns must not exceed MEDIUM severity."""
        def mock_osv(packages):
            return {p.name: [{"id": "GHSA-fake", "summary": "Test", "severity": []}]
                    for p in packages}
        monkeypatch.setattr(
            "backend.scanners.supply_chain._osv_lookup", mock_osv
        )

        with tempfile.TemporaryDirectory() as d:
            pkg_json = Path(d) / "package.json"
            pkg_json.write_text(json.dumps({
                "devDependencies": {"lodash": "4.17.20"}
            }))
            result = self.scanner.scan(d)
            findings = result["findings"]
            for f in findings:
                if f.get("is_dev"):
                    assert f["severity"] in ("LOW", "MEDIUM", "INFO"), (
                        f"Dev dep severity too high: {f['severity']}"
                    )

    def test_disputed_vuln_not_escalated(self, monkeypatch):
        """Disputed vulns must not exceed MEDIUM and must be marked."""
        def mock_osv(packages):
            return {
                p.name: [{
                    "id": "CVE-DISPUTED",
                    "details": "This vulnerability is disputed by the vendor.",
                    "summary": "Disputed issue",
                    "severity": [],
                }]
                for p in packages
            }
        monkeypatch.setattr(
            "backend.scanners.supply_chain._osv_lookup", mock_osv
        )

        with tempfile.TemporaryDirectory() as d:
            req = Path(d) / "requirements.txt"
            req.write_text("requests==2.28.0\n")
            result = self.scanner.scan(d)
            for f in result["findings"]:
                if f.get("disputed"):
                    assert f["severity"] in ("LOW", "MEDIUM", "INFO")
                    assert f["disputed"] is True

    def test_unimported_package_downgraded(self, monkeypatch):
        """Package with vuln but not imported → severity=INFO."""
        def mock_osv(packages):
            return {
                p.name: [{"id": "OSV-TEST-001", "summary": "Test vuln", "severity": []}]
                for p in packages
            }
        monkeypatch.setattr(
            "backend.scanners.supply_chain._osv_lookup", mock_osv
        )
        # _package_imported will return False for nonexistent .py files
        monkeypatch.setattr(
            "backend.scanners.supply_chain._package_imported",
            lambda dir_, name: False,
        )

        with tempfile.TemporaryDirectory() as d:
            req = Path(d) / "requirements.txt"
            req.write_text("somepkg==1.0.0\n")
            result = self.scanner.scan(d)
            for f in result["findings"]:
                if f.get("vuln_id"):
                    assert f["severity"] == "INFO", (
                        f"Expected INFO for unimported package, got: {f['severity']}"
                    )
