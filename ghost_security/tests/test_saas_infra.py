"""
Tests for Ghost Security Rules CDN (FILE 4 of v10 SaaS infrastructure).

No real network calls — all urllib.request interactions are mocked.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import URLError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from integrations.rules_cdn import RulesCDN, RulesCDNConfig


def _make_http_response(body: bytes) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _sha256(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


REMOTE_MANIFEST_NEW = {
    "version": "2.0.0", "updated_at": "2026-01-01T00:00:00Z",
    "rules": [{"name": "owasp/sqli.yml", "checksum": _sha256(b"sqli rule content v2")},
               {"name": "owasp/xss.yml",  "checksum": _sha256(b"xss rule content")}],
}

REMOTE_MANIFEST_SAME = {
    "version": "1.0.0", "updated_at": "2025-01-01T00:00:00Z",
    "rules": [{"name": "owasp/sqli.yml", "checksum": _sha256(b"sqli rule content v1")}],
}

LOCAL_MANIFEST_V1 = {
    "version": "1.0.0", "updated_at": "2025-01-01T00:00:00Z",
    "rules": [{"name": "owasp/sqli.yml", "checksum": _sha256(b"sqli rule content v1")}],
}


def _cdn_in_tmpdir(tmpdir: str, manifest=None) -> RulesCDN:
    cfg = RulesCDNConfig(local_dir=tmpdir)
    cdn = RulesCDN(cfg)
    if manifest is not None:
        (Path(tmpdir) / ".manifest.json").write_text(json.dumps(manifest))
    return cdn


class TestRulesCDN(unittest.TestCase):

    def test_check_updates_has_update(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir, manifest=LOCAL_MANIFEST_V1)
            remote_body = json.dumps(REMOTE_MANIFEST_NEW).encode()
            with patch("integrations.rules_cdn.urlopen", return_value=_make_http_response(remote_body)):
                result = cdn.check_updates()
        self.assertTrue(result["has_update"])
        self.assertEqual(result["current"], "1.0.0")
        self.assertEqual(result["latest"], "2.0.0")
        self.assertIn("owasp/xss.yml", [r["name"] for r in result["new_rules"]])

    def test_check_updates_no_update(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir, manifest=LOCAL_MANIFEST_V1)
            remote_body = json.dumps(LOCAL_MANIFEST_V1).encode()
            with patch("integrations.rules_cdn.urlopen", return_value=_make_http_response(remote_body)):
                result = cdn.check_updates()
        self.assertFalse(result["has_update"])
        self.assertEqual(result["new_rules"], [])

    def test_download_rules_skips_matching_checksum(self):
        rule_content = b"sqli rule content v1"
        with tempfile.TemporaryDirectory() as tmpdir:
            rule_dir = Path(tmpdir) / "owasp"
            rule_dir.mkdir(parents=True)
            (rule_dir / "sqli.yml").write_bytes(rule_content)
            cdn = _cdn_in_tmpdir(tmpdir, manifest=LOCAL_MANIFEST_V1)
            manifest_body = json.dumps({"version": "1.0.0", "updated_at": "2025-01-01T00:00:00Z",
                                         "rules": [{"name": "owasp/sqli.yml", "checksum": _sha256(rule_content)}]}).encode()
            with patch("integrations.rules_cdn.urlopen", return_value=_make_http_response(manifest_body)):
                result = cdn.download_rules()
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(result["downloaded"], 0)
        self.assertEqual(result["errors"], 0)

    def test_download_rules_fetches_changed(self):
        old_content = b"old sqli rule content"
        new_content = b"new sqli rule content v2"
        with tempfile.TemporaryDirectory() as tmpdir:
            rule_dir = Path(tmpdir) / "owasp"
            rule_dir.mkdir(parents=True)
            rule_file = rule_dir / "sqli.yml"
            rule_file.write_bytes(old_content)
            cdn = _cdn_in_tmpdir(tmpdir, manifest=LOCAL_MANIFEST_V1)
            manifest_updated = {"version": "1.1.0", "updated_at": "2025-06-01T00:00:00Z",
                                 "rules": [{"name": "owasp/sqli.yml", "checksum": _sha256(new_content)}]}
            remote_manifest_body = json.dumps(manifest_updated).encode()
            call_count = [0]
            def fake_urlopen(req, timeout=None):
                if call_count[0] == 0:
                    call_count[0] += 1
                    return _make_http_response(remote_manifest_body)
                call_count[0] += 1
                return _make_http_response(new_content)
            with patch("integrations.rules_cdn.urlopen", side_effect=fake_urlopen):
                result = cdn.download_rules()
            self.assertEqual(result["downloaded"], 1)
            self.assertEqual(result["skipped"], 0)
            self.assertEqual(result["errors"], 0)
            self.assertEqual(result["version"], "1.1.0")
            self.assertEqual(rule_file.read_bytes(), new_content)

    def test_download_rules_force_redownloads_all(self):
        content = b"sqli rule content"
        with tempfile.TemporaryDirectory() as tmpdir:
            rule_dir = Path(tmpdir) / "owasp"
            rule_dir.mkdir(parents=True)
            (rule_dir / "sqli.yml").write_bytes(content)
            cdn = _cdn_in_tmpdir(tmpdir, manifest=LOCAL_MANIFEST_V1)
            manifest_body = json.dumps({"version": "1.0.0", "updated_at": "2025-01-01T00:00:00Z",
                                         "rules": [{"name": "owasp/sqli.yml", "checksum": _sha256(content)}]}).encode()
            responses = iter([_make_http_response(manifest_body), _make_http_response(content)])
            with patch("integrations.rules_cdn.urlopen", side_effect=lambda req, timeout=None: next(responses)):
                result = cdn.download_rules(force=True)
        self.assertEqual(result["downloaded"], 1)
        self.assertEqual(result["skipped"], 0)

    def test_network_error_returns_graceful_check_updates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            with patch("integrations.rules_cdn.urlopen", side_effect=URLError("Connection refused")):
                result = cdn.check_updates()
        self.assertFalse(result["has_update"])
        self.assertIn("error", result)
        self.assertIsInstance(result["error"], str)

    def test_network_error_returns_graceful_download_rules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            with patch("integrations.rules_cdn.urlopen", side_effect=URLError("timeout")):
                result = cdn.download_rules()
        self.assertIn("error", result)
        self.assertEqual(result["downloaded"], 0)

    def test_list_local_rules_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            rules = cdn.list_local_rules()
        self.assertIsInstance(rules, list)
        self.assertEqual(rules, [])

    def test_list_local_rules_returns_installed_rules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sub = Path(tmpdir) / "owasp"
            sub.mkdir()
            (sub / "sqli.yml").write_bytes(b"id: sqli")
            (sub / "xss.yaml").write_bytes(b"id: xss")
            cdn = _cdn_in_tmpdir(tmpdir)
            rules = cdn.list_local_rules()
        self.assertEqual(len(rules), 2)
        names = {r["name"] for r in rules}
        self.assertIn("owasp/sqli.yml", names)
        self.assertIn("owasp/xss.yaml", names)
        for r in rules:
            self.assertIn("size", r)
            self.assertIn("checksum", r)

    def test_compute_sha256(self):
        content = b"hello ghost security"
        expected_hex = hashlib.sha256(content).hexdigest()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yml") as f:
            f.write(content)
            path = f.name
        try:
            cdn = RulesCDN()
            result = cdn._compute_sha256(path)
            self.assertEqual(result, f"sha256:{expected_hex}")
        finally:
            os.unlink(path)

    def test_get_version_no_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            version = cdn.get_version()
        self.assertIsNone(version)

    def test_get_version_with_manifest(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir, manifest=LOCAL_MANIFEST_V1)
            version = cdn.get_version()
        self.assertEqual(version, "1.0.0")

    def test_cache_freshness_recent_check(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            (Path(tmpdir) / ".last_check").write_text(str(time.time() - 5))
            self.assertTrue(cdn._is_cache_fresh())

    def test_cache_freshness_old_check(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            (Path(tmpdir) / ".last_check").write_text(str(time.time() - 2 * 86400))
            self.assertFalse(cdn._is_cache_fresh())

    def test_cache_freshness_no_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            self.assertFalse(cdn._is_cache_fresh())

    def test_fetch_manifest_returns_dict(self):
        manifest = {"version": "3.0.0", "rules": []}
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            with patch("integrations.rules_cdn.urlopen", return_value=_make_http_response(json.dumps(manifest).encode())):
                result = cdn._fetch_manifest()
        self.assertEqual(result["version"], "3.0.0")

    def test_fetch_manifest_invalid_json_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            with patch("integrations.rules_cdn.urlopen", return_value=_make_http_response(b"not json {")):
                result = cdn._fetch_manifest()
        self.assertIsNone(result)

    def test_fetch_manifest_url_error_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            with patch("integrations.rules_cdn.urlopen", side_effect=URLError("dns failure")):
                result = cdn._fetch_manifest()
        self.assertIsNone(result)

    def test_download_rules_saves_manifest(self):
        content = b"rule body"
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            new_manifest = {"version": "5.0.0", "updated_at": "2026-05-01T00:00:00Z",
                            "rules": [{"name": "test.yml", "checksum": _sha256(content)}]}
            manifest_bytes = json.dumps(new_manifest).encode()
            responses = iter([_make_http_response(manifest_bytes), _make_http_response(content)])
            with patch("integrations.rules_cdn.urlopen", side_effect=lambda req, timeout=None: next(responses)):
                cdn.download_rules()
            saved = json.loads((Path(tmpdir) / ".manifest.json").read_text())
            self.assertEqual(saved["version"], "5.0.0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
