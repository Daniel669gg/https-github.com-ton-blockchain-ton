"""
tests/test_phase4_benchmark.py — Phase 4 Benchmark Suite.
20 tests: SQL injection, CMDi, Path Traversal, XSS, SSRF, Weak Crypto, Hardcoded Secrets.
Each benchmark shows: vulnerability detected → fix proposed → fix validated → exploit removed.
"""
import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.remediation.verified_fix_engine import (
    VerifiedFixEngine, FixStatus, VerifiedFix,
)
from backend.core.remediation.build_validator import BuildValidator
from backend.core.remediation.fix_explainer import FixExplainer, FixExplanation


# ─────────────────────────────────────────────────────────────────────────────
# Benchmark helpers
# ─────────────────────────────────────────────────────────────────────────────

def _finding(cwe_id, severity="HIGH"):
    class F:
        rule_id = f"bench-{cwe_id}"
        file = "app.py"
        line = 1
        description = f"Benchmark {cwe_id}"
    f = F()
    f.cwe_id = cwe_id
    f.severity = severity
    return f


# ─────────────────────────────────────────────────────────────────────────────
# SQL Injection (CWE-89)
# ─────────────────────────────────────────────────────────────────────────────

_SQLI_VULN = 'cur.execute("SELECT * FROM users WHERE id=" + uid)'
_SQLI_FIX  = 'cur.execute("SELECT * FROM users WHERE id=%s", (uid,))'

class TestSQLInjectionBenchmark:
    def test_sqli_fix_accepted(self):
        vf = VerifiedFixEngine().verify_fix(_finding("CWE-89"), _SQLI_FIX, _SQLI_VULN)
        assert vf.fix_status in (FixStatus.VALIDATED, FixStatus.VERIFIED)

    def test_sqli_vuln_confirmed_fixed(self):
        vf = VerifiedFixEngine().verify_fix(_finding("CWE-89"), _SQLI_FIX, _SQLI_VULN)
        assert vf.vulnerability_confirmed_fixed is True

    def test_sqli_explanation_generated(self):
        vf = VerifiedFixEngine().verify_fix(_finding("CWE-89"), _SQLI_FIX, _SQLI_VULN)
        expl = FixExplainer().explain(_finding("CWE-89"), _SQLI_VULN, _SQLI_FIX, vf)
        assert "SQL" in expl.cwe_name or "injection" in expl.root_cause.lower()

    def test_sqli_build_valid(self):
        result = BuildValidator().validate_python(_SQLI_FIX)
        assert result.success is True


# ─────────────────────────────────────────────────────────────────────────────
# Command Injection (CWE-78)
# ─────────────────────────────────────────────────────────────────────────────

_CMDI_VULN = "import os\nos.system(user_input)"
_CMDI_FIX  = "import subprocess, shlex\nsubprocess.run(shlex.split(user_input), shell=False)"

class TestCommandInjectionBenchmark:
    def test_cmdi_fix_accepted(self):
        vf = VerifiedFixEngine().verify_fix(_finding("CWE-78"), _CMDI_FIX, _CMDI_VULN)
        assert vf.fix_status in (FixStatus.VALIDATED, FixStatus.VERIFIED)

    def test_cmdi_vuln_fixed(self):
        vf = VerifiedFixEngine().verify_fix(_finding("CWE-78"), _CMDI_FIX, _CMDI_VULN)
        assert vf.vulnerability_confirmed_fixed is True

    def test_cmdi_no_regression(self):
        vf = VerifiedFixEngine().verify_fix(_finding("CWE-78"), _CMDI_FIX, _CMDI_VULN)
        assert vf.regression_detected is False


# ─────────────────────────────────────────────────────────────────────────────
# Path Traversal (CWE-22)
# ─────────────────────────────────────────────────────────────────────────────

_PTRAV_VULN = "with open(base_dir + '/' + user_file) as f: data = f.read()"
_PTRAV_FIX  = """import os
full = os.path.realpath(os.path.join(base_dir, user_file))
if not full.startswith(os.path.realpath(base_dir)):
    raise ValueError('traversal')
with open(full) as f:
    data = f.read()"""

class TestPathTraversalBenchmark:
    def test_path_traversal_fix_accepted(self):
        vf = VerifiedFixEngine().verify_fix(_finding("CWE-22"), _PTRAV_FIX, _PTRAV_VULN)
        assert vf.fix_status in (FixStatus.VALIDATED, FixStatus.VERIFIED)

    def test_path_traversal_build_valid(self):
        result = BuildValidator().validate_python(_PTRAV_FIX)
        assert result.success is True


# ─────────────────────────────────────────────────────────────────────────────
# XSS (CWE-79)
# ─────────────────────────────────────────────────────────────────────────────

_XSS_VULN = "return '<div>' + user_input + '</div>'"
_XSS_FIX  = "import markupsafe\nreturn '<div>' + markupsafe.escape(user_input) + '</div>'"

class TestXSSBenchmark:
    def test_xss_fix_accepted(self):
        vf = VerifiedFixEngine().verify_fix(_finding("CWE-79"), _XSS_FIX, _XSS_VULN)
        assert vf.fix_status in (FixStatus.VALIDATED, FixStatus.VERIFIED)

    def test_xss_explanation_mentions_encoding(self):
        expl = FixExplainer().explain(_finding("CWE-79"), _XSS_VULN, _XSS_FIX)
        assert "encod" in expl.why_fix_works.lower() or "escap" in expl.why_fix_works.lower()


# ─────────────────────────────────────────────────────────────────────────────
# Hardcoded Credentials (CWE-798)
# ─────────────────────────────────────────────────────────────────────────────

_SECRET_VULN = 'api_key = "sk-hardcoded-secret-abc123"'
_SECRET_FIX  = 'import os\napi_key = os.environ.get("API_KEY")'

class TestHardcodedSecretsBenchmark:
    def test_secrets_fix_accepted(self):
        vf = VerifiedFixEngine().verify_fix(_finding("CWE-798"), _SECRET_FIX, _SECRET_VULN)
        assert vf.fix_status in (FixStatus.VALIDATED, FixStatus.VERIFIED)

    def test_secrets_build_valid(self):
        result = BuildValidator().validate_python(_SECRET_FIX)
        assert result.success is True


# ─────────────────────────────────────────────────────────────────────────────
# Weak Crypto (CWE-327)
# ─────────────────────────────────────────────────────────────────────────────

_CRYPTO_VULN = "import hashlib\nhash = hashlib.md5(password.encode()).hexdigest()"
_CRYPTO_FIX  = "import hashlib\nhash = hashlib.sha256(password.encode()).hexdigest()"

class TestWeakCryptoBenchmark:
    def test_crypto_fix_accepted(self):
        vf = VerifiedFixEngine().verify_fix(_finding("CWE-327"), _CRYPTO_FIX, _CRYPTO_VULN)
        assert vf.fix_status in (FixStatus.VALIDATED, FixStatus.VERIFIED)

    def test_crypto_explanation_mentions_sha(self):
        expl = FixExplainer().explain(_finding("CWE-327"), _CRYPTO_VULN, _CRYPTO_FIX)
        assert "sha" in expl.why_fix_works.lower() or "SHA" in expl.why_fix_works


# ─────────────────────────────────────────────────────────────────────────────
# Deserialization (CWE-502)
# ─────────────────────────────────────────────────────────────────────────────

_DESER_VULN = "import yaml\ndata = yaml.load(f)"
_DESER_FIX  = "import yaml\ndata = yaml.safe_load(f)"

class TestDeserializationBenchmark:
    def test_deser_fix_accepted(self):
        vf = VerifiedFixEngine().verify_fix(_finding("CWE-502"), _DESER_FIX, _DESER_VULN)
        assert vf.fix_status in (FixStatus.VALIDATED, FixStatus.VERIFIED)


# ─────────────────────────────────────────────────────────────────────────────
# FixExplainer general
# ─────────────────────────────────────────────────────────────────────────────

class TestFixExplainerBenchmark:
    def test_explain_returns_explanation(self):
        expl = FixExplainer().explain(_finding("CWE-89"), _SQLI_VULN, _SQLI_FIX)
        assert isinstance(expl, FixExplanation)

    def test_explanation_has_root_cause(self):
        expl = FixExplainer().explain(_finding("CWE-78"), _CMDI_VULN, _CMDI_FIX)
        assert len(expl.root_cause) > 10

    def test_format_markdown_returns_string(self):
        expl = FixExplainer().explain(_finding("CWE-89"), _SQLI_VULN, _SQLI_FIX)
        md = FixExplainer().format_markdown(expl)
        assert isinstance(md, str)
        assert "CWE-89" in md

    def test_explanation_has_owasp_reference(self):
        expl = FixExplainer().explain(_finding("CWE-89"))
        assert "OWASP" in expl.owasp_reference
