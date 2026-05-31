"""
tests/test_git_secrets.py — Tests for backend/scanners/git_secrets.py

Covers:
  1. True Positive tests (vulnerable patterns MUST trigger)
  2. True Negative tests (safe/placeholder patterns must NOT trigger)
  3. Benchmark test (precision >= 0.85, recall >= 0.80)
"""
from __future__ import annotations

import os
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import List

import pytest

# Ensure the project root is in path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.core.benchmark import BenchmarkRunner, GroundTruthItem
from backend.core.confidence import Finding
from backend.scanners.git_secrets import GitSecretsScanner, _scan_file_content


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def scan_text(content: str, filename: str = "target.py") -> List[Finding]:
    """Scan inline text content as if it were a file."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=os.path.splitext(filename)[1] or ".py",
        delete=False, encoding="utf-8"
    ) as f:
        f.write(content)
        fpath = f.name
    try:
        scanner = GitSecretsScanner()
        return scanner.scan_file(fpath)
    finally:
        os.unlink(fpath)


def has_rule(findings: List[Finding], rule_id: str) -> bool:
    return any(f.rule_id == rule_id for f in findings)


def findings_for(findings: List[Finding], rule_id: str) -> List[Finding]:
    return [f for f in findings if f.rule_id == rule_id]


# ─────────────────────────────────────────────────────────────────────────────
# TRUE POSITIVE tests — must fire
# ─────────────────────────────────────────────────────────────────────────────

class TestTruePositives:

    def test_api_key_real_value(self):
        """Real API key (non-placeholder) must trigger."""
        content = 'API_KEY = "sk-proj-abc123def456ghi789jkl"\n'
        findings = scan_text(content)
        assert has_rule(findings, "SECRET-API-KEY"), (
            f"Expected SECRET-API-KEY for real API key value, got: {[f.rule_id for f in findings]}"
        )

    def test_api_key_with_dash(self):
        """api-key assignment must trigger."""
        content = 'api-key = "abcdefghijklmnopqrstuvwxyz1234"\n'
        findings = scan_text(content)
        assert has_rule(findings, "SECRET-API-KEY")

    def test_api_key_with_colon(self):
        """API key with colon separator must trigger."""
        content = 'apikey: "supersecretapikey12345678901"\n'
        findings = scan_text(content)
        assert has_rule(findings, "SECRET-API-KEY")

    def test_jwt_token(self):
        """Valid JWT token structure must trigger."""
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        content = f'token = "{jwt}"\n'
        findings = scan_text(content)
        assert has_rule(findings, "SECRET-JWT-TOKEN")

    def test_rsa_private_key(self):
        """RSA private key header must trigger CRITICAL."""
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n"
        findings = scan_text(content)
        assert has_rule(findings, "SECRET-PRIVATE-KEY")
        f = findings_for(findings, "SECRET-PRIVATE-KEY")[0]
        # CRITICAL severity (or downgraded if test file, but this is not a test file)
        assert f.severity == "CRITICAL"

    def test_ec_private_key(self):
        """EC private key header must trigger."""
        content = "-----BEGIN EC PRIVATE KEY-----\n...\n"
        findings = scan_text(content)
        assert has_rule(findings, "SECRET-PRIVATE-KEY")

    def test_openssh_private_key(self):
        """OpenSSH private key must trigger."""
        content = "-----BEGIN OPENSSH PRIVATE KEY-----\n...\n"
        findings = scan_text(content)
        assert has_rule(findings, "SECRET-PRIVATE-KEY")

    def test_aws_access_key(self):
        """AWS Access Key ID format AKIA... must trigger CRITICAL."""
        content = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE23"\n'
        findings = scan_text(content)
        assert has_rule(findings, "SECRET-AWS-ACCESS-KEY")

    def test_aws_secret_key_pattern(self):
        """AWS secret key pattern must trigger."""
        content = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY1234"\n'
        findings = scan_text(content)
        assert has_rule(findings, "SECRET-AWS-SECRET")

    def test_eth_private_key_hex(self):
        """Ethereum private key as 64-char hex near 'private_key' must trigger."""
        content = 'private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"\n'
        findings = scan_text(content)
        assert has_rule(findings, "SECRET-ETH-PRIVATE-KEY")

    def test_generic_password_string(self):
        """Hardcoded password string must trigger."""
        content = 'password = "SuperSecret123!"\n'
        findings = scan_text(content)
        assert has_rule(findings, "SECRET-GENERIC-PASSWORD")

    def test_generic_secret_string(self):
        """Hardcoded secret string must trigger."""
        content = 'secret = "my-very-secret-value-42"\n'
        findings = scan_text(content)
        assert has_rule(findings, "SECRET-GENERIC-PASSWORD")

    def test_database_password(self):
        """DB password in config must trigger."""
        content = 'DB_PASSWORD = "prod_db_pass_9xKzm2@!"\n'
        findings = scan_text(content)
        # either generic password or API key rule
        rule_ids = [f.rule_id for f in findings]
        assert any("PASSWORD" in rid or "SECRET" in rid or "API" in rid or "GENERIC" in rid
                   for rid in rule_ids), f"No secret rule fired for DB_PASSWORD, got: {rule_ids}"

    def test_pgp_private_key(self):
        """PGP private key must trigger."""
        content = "-----BEGIN PGP PRIVATE KEY-----\n...\n"
        findings = scan_text(content)
        assert has_rule(findings, "SECRET-PRIVATE-KEY")

    def test_scan_file_method(self):
        """scan_file method works correctly."""
        scanner = GitSecretsScanner()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write('API_KEY = "sk-realkey-1234567890abcdefghij"\n')
            fpath = f.name
        try:
            findings = scanner.scan_file(fpath)
            assert has_rule(findings, "SECRET-API-KEY")
        finally:
            os.unlink(fpath)

    def test_scan_directory_method(self):
        """scan_directory method picks up files."""
        scanner = GitSecretsScanner()
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "secrets.py").write_text(
                'API_KEY = "sk-proj-abc123def456ghi789jkl"\n'
            )
            findings = scanner.scan_directory(tmpdir)
            assert has_rule(findings, "SECRET-API-KEY")

    def test_scan_returns_dict(self):
        """scan() method returns expected dict shape."""
        scanner = GitSecretsScanner()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = scanner.scan(tmpdir)
            assert "findings" in result
            assert "mode" in result
            assert isinstance(result["findings"], list)


# ─────────────────────────────────────────────────────────────────────────────
# TRUE NEGATIVE tests — must NOT fire
# ─────────────────────────────────────────────────────────────────────────────

class TestTrueNegatives:

    def test_placeholder_your_api_key_here(self):
        """Classic 'your_api_key_here' placeholder must NOT trigger."""
        content = 'API_KEY = "your_api_key_here"\n'
        findings = scan_text(content)
        api_findings = findings_for(findings, "SECRET-API-KEY")
        assert not api_findings, f"Expected no findings for placeholder, got: {api_findings}"

    def test_placeholder_xxx(self):
        """xxx placeholder must NOT trigger."""
        content = 'token = "xxxxxxxxxxxxxxxxxxxxxx"\n'
        findings = scan_text(content)
        # should be filtered as placeholder
        jwt_findings = findings_for(findings, "SECRET-JWT-TOKEN")
        api_findings = findings_for(findings, "SECRET-API-KEY")
        assert not jwt_findings and not api_findings

    def test_placeholder_example(self):
        """'example' placeholder must NOT trigger."""
        content = 'API_KEY = "example_api_key_not_real_12345"\n'
        findings = scan_text(content)
        api_findings = findings_for(findings, "SECRET-API-KEY")
        assert not api_findings, f"'example' placeholder should be ignored, got: {api_findings}"

    def test_placeholder_changeme(self):
        """'changeme' placeholder must NOT trigger."""
        content = 'password = "changeme"\n'
        findings = scan_text(content)
        pwd_findings = findings_for(findings, "SECRET-GENERIC-PASSWORD")
        assert not pwd_findings, f"'changeme' placeholder should be ignored"

    def test_env_var_reference(self):
        """Environment variable reference should NOT trigger."""
        content = 'API_KEY = os.environ.get("API_KEY")\n'
        findings = scan_text(content)
        assert not has_rule(findings, "SECRET-API-KEY")

    def test_template_file_ignored(self):
        """Files with 'example' in name must be ignored."""
        scanner = GitSecretsScanner()
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", prefix="config.example",
            delete=False, encoding="utf-8"
        ) as f:
            f.write('API_KEY = "sk-realkey-1234567890abcdefghij"\n')
            fpath = f.name
        try:
            findings = scanner.scan_file(fpath)
            # Template files return empty
            assert not findings, f"Template file should produce no findings, got: {findings}"
        finally:
            os.unlink(fpath)

    def test_test_file_severity_downgraded(self):
        """Findings in test files must have downgraded severity."""
        content = '-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n'
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", prefix="test_",
            delete=False, encoding="utf-8"
        ) as f:
            f.write(content)
            fpath = f.name
        try:
            scanner = GitSecretsScanner()
            findings = scanner.scan_file(fpath)
            if findings:
                pk_findings = findings_for(findings, "SECRET-PRIVATE-KEY")
                if pk_findings:
                    # Should be downgraded from CRITICAL to HIGH
                    assert pk_findings[0].severity != "CRITICAL", (
                        "Test file findings should have downgraded severity"
                    )
                    assert pk_findings[0].is_test_file is True
        finally:
            os.unlink(fpath)

    def test_placeholder_dollar_variable(self):
        """$VARIABLE reference must NOT trigger."""
        content = 'API_KEY = "$API_KEY_FROM_ENV"\n'
        findings = scan_text(content)
        api_findings = findings_for(findings, "SECRET-API-KEY")
        assert not api_findings

    def test_short_password_not_flagged(self):
        """Passwords shorter than 8 chars should not be flagged."""
        content = 'password = "short"\n'
        findings = scan_text(content)
        pwd_findings = findings_for(findings, "SECRET-GENERIC-PASSWORD")
        assert not pwd_findings

    def test_comment_line_not_scanned(self):
        """Lines that are pure comments should not produce findings."""
        content = '# API_KEY = "sk-realkey-1234567890abcdefghij"\n'
        findings = scan_text(content)
        assert not has_rule(findings, "SECRET-API-KEY"), (
            "Commented-out lines should not produce findings"
        )

    def test_placeholder_test_keyword(self):
        """'test' in value must NOT trigger."""
        content = 'api_key = "testkey12345678901234"\n'
        findings = scan_text(content)
        api_findings = findings_for(findings, "SECRET-API-KEY")
        assert not api_findings

    def test_placeholder_fake(self):
        """'fake' in value must NOT trigger."""
        content = 'api_key = "fakeapikey12345678901234"\n'
        findings = scan_text(content)
        api_findings = findings_for(findings, "SECRET-API-KEY")
        assert not api_findings


# ─────────────────────────────────────────────────────────────────────────────
# BENCHMARK test — precision >= 0.85, recall >= 0.80
# ─────────────────────────────────────────────────────────────────────────────

class TestBenchmark:

    def _build_corpus(self) -> tuple:
        """Build a labeled corpus of true positives and true negatives."""
        scanner = GitSecretsScanner()
        all_findings: List[Finding] = []
        ground_truth: List[GroundTruthItem] = []

        with tempfile.TemporaryDirectory() as tmpdir:
            tp_dir = Path(tmpdir) / "tp"
            tp_dir.mkdir()
            tn_dir = Path(tmpdir) / "tn"
            tn_dir.mkdir()

            # ── True Positives ────────────────────────────────────────────────
            tp_cases = [
                ("tp_api_key.py", 'API_KEY = "sk-proj-abc123def456ghi789jkl"\n', "SECRET-API-KEY", 1),
                ("tp_jwt.py", 'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"\n', "SECRET-JWT-TOKEN", 1),
                ("tp_rsa.py", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n", "SECRET-PRIVATE-KEY", 1),
                ("tp_aws.py", 'aws_key = "AKIAIOSFODNN7EXAMPLE23"\n', "SECRET-AWS-ACCESS-KEY", 1),
                ("tp_eth.py", 'private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"\n', "SECRET-ETH-PRIVATE-KEY", 1),
                ("tp_pwd.py", 'password = "SuperSecretProd123!"\n', "SECRET-GENERIC-PASSWORD", 1),
                ("tp_secret.py", 'db_secret = "my-prod-secret-value-42"\n', "SECRET-GENERIC-PASSWORD", 1),
                ("tp_openssh.py", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAA...\n", "SECRET-PRIVATE-KEY", 1),
                ("tp_apikey2.py", 'apikey = "abcdefghijklmnopqrstuvwxyz1234567890"\n', "SECRET-API-KEY", 1),
                ("tp_aws2.py", 'aws_access_key_id = "AKIAIOSFODNN7REALKEY"\n', "SECRET-AWS-ACCESS-KEY", 1),
            ]

            for fname, code, rule_id, line in tp_cases:
                fpath = str(tp_dir / fname)
                Path(fpath).write_text(code, encoding="utf-8")
                file_findings = scanner.scan_file(fpath)
                all_findings.extend(file_findings)
                ground_truth.append(GroundTruthItem(
                    rule_id=rule_id,
                    file=fpath,
                    line=line,
                ))

            # ── True Negatives ─────────────────────────────────────────────
            tn_cases = [
                ("tn_placeholder.py", 'API_KEY = "your_api_key_here"\n'),
                ("tn_env_var.py", 'API_KEY = os.environ["API_KEY"]\n'),
                ("tn_comment.py", '# password = "realpassword123"\n'),
                ("tn_short.py", 'password = "short"\n'),
                ("tn_test.py", 'api_key = "testkey12345678"\n'),
                ("tn_fake.py", 'api_key = "fakekey123456789012345"\n'),
                ("tn_bracket.py", 'token = "${MY_TOKEN}"\n'),
                ("tn_example.py", 'API_KEY = "example_key_12345678901234"\n'),
            ]

            for fname, code in tn_cases:
                fpath = str(tn_dir / fname)
                Path(fpath).write_text(code, encoding="utf-8")
                file_findings = scanner.scan_file(fpath)
                all_findings.extend(file_findings)
                # No ground truth item for TN cases

        return all_findings, ground_truth

    def test_benchmark_precision_recall(self):
        """Scanner must achieve precision >= 0.85 and recall >= 0.80."""
        findings, ground_truth = self._build_corpus()

        runner = BenchmarkRunner(
            precision_threshold=0.85,
            recall_threshold=0.80,
            line_tolerance=2,
        )
        report = runner.evaluate(
            predicted=findings,
            ground_truth=ground_truth,
            module_name="git_secrets",
        )
        print(f"\n{report.summary()}")

        assert report.precision >= 0.85, (
            f"Precision {report.precision:.3f} below threshold 0.85. "
            f"FP={report.false_positives}, TP={report.true_positives}\n"
            f"False positives: {report.details.get('false_positive_findings', [])}"
        )
        assert report.recall >= 0.80, (
            f"Recall {report.recall:.3f} below threshold 0.80. "
            f"FN={report.false_negatives}, TP={report.true_positives}\n"
            f"Missed findings: {report.details.get('missed_findings', [])}"
        )
        assert report.passed, report.summary()
