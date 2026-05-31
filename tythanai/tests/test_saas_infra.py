"""
Tests for TythanAI Rules CDN (FILE 4 of v10 SaaS infrastructure).

No real network calls — all urllib.request interactions are mocked.

Run:
    python3 -m pytest tests/test_saas_infra.py -v
    # or
    python3 -m unittest tests.test_saas_infra -v
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

# Ensure the repo root is on sys.path so imports work from any cwd.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from integrations.rules_cdn import RulesCDN, RulesCDNConfig


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_http_response(body: bytes) -> MagicMock:
    """Return a mock urllib response whose .read() returns *body*."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _sha256(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


REMOTE_MANIFEST_NEW = {
    "version": "2.0.0",
    "updated_at": "2026-01-01T00:00:00Z",
    "rules": [
        {"name": "owasp/sqli.yml", "checksum": _sha256(b"sqli rule content v2")},
        {"name": "owasp/xss.yml",  "checksum": _sha256(b"xss rule content")},
    ],
}

REMOTE_MANIFEST_SAME = {
    "version": "1.0.0",
    "updated_at": "2025-01-01T00:00:00Z",
    "rules": [
        {"name": "owasp/sqli.yml", "checksum": _sha256(b"sqli rule content v1")},
    ],
}

LOCAL_MANIFEST_V1 = {
    "version": "1.0.0",
    "updated_at": "2025-01-01T00:00:00Z",
    "rules": [
        {"name": "owasp/sqli.yml", "checksum": _sha256(b"sqli rule content v1")},
    ],
}


def _cdn_in_tmpdir(tmpdir: str, manifest: dict | None = None) -> RulesCDN:
    """Return a RulesCDN instance rooted at *tmpdir*, optionally with a local manifest."""
    cfg = RulesCDNConfig(local_dir=tmpdir)
    cdn = RulesCDN(cfg)
    if manifest is not None:
        p = Path(tmpdir) / ".manifest.json"
        p.write_text(json.dumps(manifest))
    return cdn


# ══════════════════════════════════════════════════════════════════════════════
# TestRulesCDN
# ══════════════════════════════════════════════════════════════════════════════

class TestRulesCDN(unittest.TestCase):

    # ── check_updates ─────────────────────────────────────────────────────────

    def test_check_updates_has_update(self):
        """Remote manifest has a newer version → has_update=True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir, manifest=LOCAL_MANIFEST_V1)
            remote_body = json.dumps(REMOTE_MANIFEST_NEW).encode()
            with patch("integrations.rules_cdn.urlopen",
                       return_value=_make_http_response(remote_body)):
                result = cdn.check_updates()

        self.assertTrue(result["has_update"])
        self.assertEqual(result["current"], "1.0.0")
        self.assertEqual(result["latest"], "2.0.0")
        # xss.yml is new in the remote manifest (not present locally)
        new_names = [r["name"] for r in result["new_rules"]]
        self.assertIn("owasp/xss.yml", new_names)

    def test_check_updates_no_update(self):
        """Remote manifest matches local version and checksums → has_update=False."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir, manifest=LOCAL_MANIFEST_V1)
            # Remote is identical to local
            remote_body = json.dumps(LOCAL_MANIFEST_V1).encode()
            with patch("integrations.rules_cdn.urlopen",
                       return_value=_make_http_response(remote_body)):
                result = cdn.check_updates()

        self.assertFalse(result["has_update"])
        self.assertEqual(result["current"], "1.0.0")
        self.assertEqual(result["latest"], "1.0.0")
        self.assertEqual(result["new_rules"], [])

    # ── download_rules ────────────────────────────────────────────────────────

    def test_download_rules_skips_matching_checksum(self):
        """File already present with correct sha256 → counted as skipped."""
        rule_content = b"sqli rule content v1"
        with tempfile.TemporaryDirectory() as tmpdir:
            # Pre-create the local rule file
            rule_dir = Path(tmpdir) / "owasp"
            rule_dir.mkdir(parents=True)
            (rule_dir / "sqli.yml").write_bytes(rule_content)

            cdn = _cdn_in_tmpdir(tmpdir, manifest=LOCAL_MANIFEST_V1)
            # Remote has the same checksum as the locally written file
            manifest_same_checksum = {
                "version": "1.0.0",
                "updated_at": "2025-01-01T00:00:00Z",
                "rules": [
                    {"name": "owasp/sqli.yml",
                     "checksum": _sha256(rule_content)},
                ],
            }
            remote_body = json.dumps(manifest_same_checksum).encode()
            with patch("integrations.rules_cdn.urlopen",
                       return_value=_make_http_response(remote_body)):
                result = cdn.download_rules()

        self.assertEqual(result["skipped"], 1)
        self.assertEqual(result["downloaded"], 0)
        self.assertEqual(result["errors"], 0)

    def test_download_rules_fetches_changed(self):
        """Rule exists locally but checksum differs → downloaded, content updated."""
        old_content = b"old sqli rule content"
        new_content = b"new sqli rule content v2"
        with tempfile.TemporaryDirectory() as tmpdir:
            # Pre-create the rule with OLD content
            rule_dir = Path(tmpdir) / "owasp"
            rule_dir.mkdir(parents=True)
            rule_file = rule_dir / "sqli.yml"
            rule_file.write_bytes(old_content)

            cdn = _cdn_in_tmpdir(tmpdir, manifest=LOCAL_MANIFEST_V1)

            # Remote announces a new checksum
            manifest_updated = {
                "version": "1.1.0",
                "updated_at": "2025-06-01T00:00:00Z",
                "rules": [
                    {"name": "owasp/sqli.yml",
                     "checksum": _sha256(new_content)},
                ],
            }
            remote_manifest_body = json.dumps(manifest_updated).encode()

            call_count = [0]

            def fake_urlopen(req, timeout=None):
                """First call returns manifest, subsequent calls return rule content."""
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
            # The local file must now contain the new content
            self.assertEqual(rule_file.read_bytes(), new_content)

    def test_download_rules_force_redownloads_all(self):
        """With force=True every rule is re-fetched regardless of checksum."""
        content = b"sqli rule content"
        with tempfile.TemporaryDirectory() as tmpdir:
            rule_dir = Path(tmpdir) / "owasp"
            rule_dir.mkdir(parents=True)
            (rule_dir / "sqli.yml").write_bytes(content)

            cdn = _cdn_in_tmpdir(tmpdir, manifest=LOCAL_MANIFEST_V1)

            manifest_body = json.dumps({
                "version": "1.0.0",
                "updated_at": "2025-01-01T00:00:00Z",
                "rules": [{"name": "owasp/sqli.yml",
                            "checksum": _sha256(content)}],
            }).encode()

            responses = iter([
                _make_http_response(manifest_body),
                _make_http_response(content),
            ])

            with patch("integrations.rules_cdn.urlopen",
                       side_effect=lambda req, timeout=None: next(responses)):
                result = cdn.download_rules(force=True)

        self.assertEqual(result["downloaded"], 1)
        self.assertEqual(result["skipped"], 0)

    # ── network errors ────────────────────────────────────────────────────────

    def test_network_error_returns_graceful_check_updates(self):
        """URLError during check_updates → has_update=False and 'error' key set."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            with patch("integrations.rules_cdn.urlopen",
                       side_effect=URLError("Connection refused")):
                result = cdn.check_updates()

        self.assertFalse(result["has_update"])
        self.assertIn("error", result)
        self.assertIsInstance(result["error"], str)
        self.assertTrue(len(result["error"]) > 0)

    def test_network_error_returns_graceful_download_rules(self):
        """URLError during download_rules → error key set, no crash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            with patch("integrations.rules_cdn.urlopen",
                       side_effect=URLError("timeout")):
                result = cdn.download_rules()

        self.assertIn("error", result)
        self.assertEqual(result["downloaded"], 0)

    # ── list_local_rules ──────────────────────────────────────────────────────

    def test_list_local_rules_empty_dir(self):
        """Brand-new temp dir with no rules → empty list returned."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            rules = cdn.list_local_rules()
        self.assertIsInstance(rules, list)
        self.assertEqual(rules, [])

    def test_list_local_rules_returns_installed_rules(self):
        """Dir with two YAML rule files → two entries returned."""
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

    # ── _compute_sha256 ───────────────────────────────────────────────────────

    def test_compute_sha256(self):
        """Known content → correct sha256:<hex> prefix and digest."""
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

    # ── get_version ───────────────────────────────────────────────────────────

    def test_get_version_no_manifest(self):
        """No local manifest file → get_version() returns None gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)  # no manifest written
            version = cdn.get_version()
        self.assertIsNone(version)

    def test_get_version_with_manifest(self):
        """Local manifest present → get_version() returns the version string."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir, manifest=LOCAL_MANIFEST_V1)
            version = cdn.get_version()
        self.assertEqual(version, "1.0.0")

    # ── _is_cache_fresh ───────────────────────────────────────────────────────

    def test_cache_freshness_recent_check(self):
        """Last check recorded just now → _is_cache_fresh() returns True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            # Write a timestamp 5 seconds in the past (well within 24h TTL)
            check_file = Path(tmpdir) / ".last_check"
            check_file.write_text(str(time.time() - 5))
            self.assertTrue(cdn._is_cache_fresh())

    def test_cache_freshness_old_check(self):
        """Last check was 2 days ago → _is_cache_fresh() returns False."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            check_file = Path(tmpdir) / ".last_check"
            check_file.write_text(str(time.time() - 2 * 86400))
            self.assertFalse(cdn._is_cache_fresh())

    def test_cache_freshness_no_file(self):
        """No .last_check file → _is_cache_fresh() returns False."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            self.assertFalse(cdn._is_cache_fresh())

    # ── _fetch_manifest ───────────────────────────────────────────────────────

    def test_fetch_manifest_returns_dict(self):
        """Valid JSON response from remote → parsed dict returned."""
        manifest = {"version": "3.0.0", "rules": []}
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            with patch("integrations.rules_cdn.urlopen",
                       return_value=_make_http_response(json.dumps(manifest).encode())):
                result = cdn._fetch_manifest()
        self.assertEqual(result["version"], "3.0.0")

    def test_fetch_manifest_invalid_json_returns_none(self):
        """Corrupted JSON from remote → returns None without raising."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            with patch("integrations.rules_cdn.urlopen",
                       return_value=_make_http_response(b"not json {")):
                result = cdn._fetch_manifest()
        self.assertIsNone(result)

    def test_fetch_manifest_url_error_returns_none(self):
        """URLError → _fetch_manifest() returns None."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            with patch("integrations.rules_cdn.urlopen",
                       side_effect=URLError("dns failure")):
                result = cdn._fetch_manifest()
        self.assertIsNone(result)

    # ── manifest persistence ──────────────────────────────────────────────────

    def test_download_rules_saves_manifest(self):
        """After download_rules the local .manifest.json is updated with the remote version."""
        content = b"rule body"
        with tempfile.TemporaryDirectory() as tmpdir:
            cdn = _cdn_in_tmpdir(tmpdir)
            new_manifest = {
                "version": "5.0.0",
                "updated_at": "2026-05-01T00:00:00Z",
                "rules": [{"name": "test.yml", "checksum": _sha256(content)}],
            }
            manifest_bytes = json.dumps(new_manifest).encode()

            responses = iter([
                _make_http_response(manifest_bytes),  # manifest fetch
                _make_http_response(content),          # rule file fetch
            ])

            with patch("integrations.rules_cdn.urlopen",
                       side_effect=lambda req, timeout=None: next(responses)):
                cdn.download_rules()

            saved = json.loads((Path(tmpdir) / ".manifest.json").read_text())
            self.assertEqual(saved["version"], "5.0.0")


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    unittest.main(verbosity=2)
