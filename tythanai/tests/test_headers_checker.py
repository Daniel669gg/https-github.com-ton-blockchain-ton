"""
tests/test_headers_checker.py — True-Positive, True-Negative, and Benchmark
tests for backend/scanners/headers_checker.py.

Precision target: >= 0.85
Recall target:    >= 0.80
"""
from __future__ import annotations

import os
import sys
import textwrap
import tempfile
from pathlib import Path
from typing import List

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.scanners.headers_checker import scan_file, scan_directory
from backend.core.confidence import Finding


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _write_tmp(content: str, suffix: str = ".py", prefix: str = "headers_test_") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(textwrap.dedent(content))
    except Exception:
        os.close(fd)
        raise
    return path


def _rule_ids(findings: List[Finding]) -> List[str]:
    return [f.rule_id for f in findings]


def _has_rule(findings: List[Finding], rule_id: str) -> bool:
    return any(f.rule_id == rule_id for f in findings)


def _findings_for_rule(findings: List[Finding], rule_id: str) -> List[Finding]:
    return [f for f in findings if f.rule_id == rule_id]


# ─────────────────────────────────────────────────────────────────────────────
# Check 1 — HEADERS-NO-CORS-MIDDLEWARE
# ─────────────────────────────────────────────────────────────────────────────

class TestNoCORSMiddleware:

    def test_tp_fastapi_app_no_cors(self):
        """True-Positive: FastAPI app with routes but no CORSMiddleware → flagged."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/api/v1/items")
            async def list_items():
                return []
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "HEADERS-NO-CORS-MIDDLEWARE"), (
            "Expected HEADERS-NO-CORS-MIDDLEWARE for FastAPI app without CORS"
        )
        f = _findings_for_rule(findings, "HEADERS-NO-CORS-MIDDLEWARE")[0]
        assert f.severity == "MEDIUM"
        assert f.cwe_id == "CWE-942"
        assert _CORS_SNIPPET_PRESENT(f.recommendation)

    def test_tn_app_with_cors_middleware(self):
        """True-Negative: FastAPI app WITH CORSMiddleware → NOT flagged for missing CORS."""
        code = """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()

            app.add_middleware(
                CORSMiddleware,
                allow_origins=["https://example.com"],
                allow_methods=["GET"],
                allow_headers=["Authorization"],
            )

            @app.get("/api/v1/items")
            async def list_items():
                return []
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "HEADERS-NO-CORS-MIDDLEWARE")

    def test_tn_non_fastapi_file(self):
        """True-Negative: plain Python file with no FastAPI → NOT flagged."""
        code = """\
            def add(a, b):
                return a + b

            class Calculator:
                def multiply(self, x, y):
                    return x * y
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "HEADERS-NO-CORS-MIDDLEWARE")


# ─────────────────────────────────────────────────────────────────────────────
# Check 2 — HEADERS-CORS-WILDCARD-CREDENTIALS
# ─────────────────────────────────────────────────────────────────────────────

class TestCORSWildcardWithCredentials:

    def test_tp_wildcard_with_credentials(self):
        """True-Positive: allow_origins=['*'] + allow_credentials=True → CRITICAL."""
        code = """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()

            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=True,
                allow_methods=["GET", "POST"],
                allow_headers=["*"],
            )
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "HEADERS-CORS-WILDCARD-CREDENTIALS"), (
            "allow_origins=['*'] + allow_credentials=True should be CRITICAL"
        )
        f = _findings_for_rule(findings, "HEADERS-CORS-WILDCARD-CREDENTIALS")[0]
        assert f.severity == "CRITICAL"
        assert f.cwe_id == "CWE-942"
        assert f.confidence >= 0.9
        assert _CORS_SNIPPET_PRESENT(f.recommendation)

    def test_tn_wildcard_no_credentials(self):
        """True-Negative: allow_origins=['*'] but credentials not set to True → not CRITICAL."""
        code = """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()

            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_methods=["GET"],
                allow_headers=["Content-Type"],
            )
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "HEADERS-CORS-WILDCARD-CREDENTIALS"), (
            "Should NOT flag CRITICAL when credentials not explicitly True"
        )

    def test_tn_specific_origin_with_credentials(self):
        """True-Negative: specific origin + credentials → NOT flagged for CRITICAL."""
        code = """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()

            app.add_middleware(
                CORSMiddleware,
                allow_origins=["https://app.example.com"],
                allow_credentials=True,
                allow_methods=["GET", "POST"],
                allow_headers=["Authorization"],
            )
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "HEADERS-CORS-WILDCARD-CREDENTIALS")

    def test_tn_credentials_false_with_wildcard(self):
        """True-Negative: allow_credentials=False with wildcard → NOT flagged as CRITICAL."""
        code = """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()

            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=False,
            )
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "HEADERS-CORS-WILDCARD-CREDENTIALS")


# ─────────────────────────────────────────────────────────────────────────────
# Check 3 — HEADERS-CORS-WILDCARD (without credentials)
# ─────────────────────────────────────────────────────────────────────────────

class TestCORSWildcard:

    def test_tp_wildcard_no_credentials_medium(self):
        """True-Positive: allow_origins=['*'] without credentials → MEDIUM."""
        code = """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()

            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_methods=["GET"],
            )

            @app.get("/api/v1/items")
            async def items():
                return []
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "HEADERS-CORS-WILDCARD"), (
            "allow_origins=['*'] without credentials should be flagged MEDIUM"
        )
        f = _findings_for_rule(findings, "HEADERS-CORS-WILDCARD")[0]
        assert f.severity in {"MEDIUM", "LOW"}
        assert _CORS_SNIPPET_PRESENT(f.recommendation)

    def test_tp_internal_project_downgraded_to_low(self):
        """True-Positive: internal project with wildcard CORS → LOW (downgraded)."""
        code = """\
            # This is an internal-only service for intranet use
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()

            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_methods=["GET"],
            )

            @app.get("/data")
            async def data():
                return {}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        wildcard = _findings_for_rule(findings, "HEADERS-CORS-WILDCARD")
        if wildcard:
            assert wildcard[0].severity == "LOW", (
                "Internal project wildcard CORS should be downgraded to LOW"
            )

    def test_tn_specific_origin(self):
        """True-Negative: specific origin → NOT flagged for wildcard."""
        code = """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()

            app.add_middleware(
                CORSMiddleware,
                allow_origins=["https://example.com", "https://app.example.com"],
                allow_methods=["GET", "POST"],
                allow_headers=["Authorization"],
            )
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "HEADERS-CORS-WILDCARD")


# ─────────────────────────────────────────────────────────────────────────────
# Check 4 — HEADERS-NO-SECURITY-HEADERS
# ─────────────────────────────────────────────────────────────────────────────

class TestNoSecurityHeaders:

    def test_tp_fastapi_no_security_headers(self):
        """True-Positive: FastAPI app with no security headers middleware → MEDIUM."""
        code = """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()

            app.add_middleware(
                CORSMiddleware,
                allow_origins=["https://example.com"],
            )

            @app.get("/api/v1/items")
            async def list_items():
                return []
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "HEADERS-NO-SECURITY-HEADERS"), (
            "Expected HEADERS-NO-SECURITY-HEADERS when no security headers middleware present"
        )
        f = _findings_for_rule(findings, "HEADERS-NO-SECURITY-HEADERS")[0]
        assert f.severity == "MEDIUM"

    def test_tn_security_headers_middleware_present(self):
        """True-Negative: SecurityHeadersMiddleware present → NOT flagged."""
        code = """\
            from fastapi import FastAPI
            from security_headers import SecurityHeadersMiddleware
            app = FastAPI()

            app.add_middleware(SecurityHeadersMiddleware)

            @app.get("/api/v1/items")
            async def list_items():
                return []
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "HEADERS-NO-SECURITY-HEADERS")

    def test_tn_manual_security_headers(self):
        """True-Negative: headers manually set in middleware → NOT flagged."""
        code = """\
            from fastapi import FastAPI, Request, Response
            app = FastAPI()

            @app.middleware("http")
            async def add_security_headers(request: Request, call_next):
                response = await call_next(request)
                response.headers["X-Content-Type-Options"] = "nosniff"
                response.headers["X-Frame-Options"] = "DENY"
                response.headers["Strict-Transport-Security"] = "max-age=31536000"
                response.headers["Content-Security-Policy"] = "default-src 'self'"
                return response

            @app.get("/api/v1/items")
            async def items():
                return []
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "HEADERS-NO-SECURITY-HEADERS")

    def test_tn_non_fastapi_file_no_flag(self):
        """True-Negative: plain utility module not flagged for missing security headers."""
        code = """\
            def compute(x):
                return x * 2
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "HEADERS-NO-SECURITY-HEADERS")


# ─────────────────────────────────────────────────────────────────────────────
# Check 5 — HEADERS-MISSING-HSTS
# ─────────────────────────────────────────────────────────────────────────────

class TestMissingHSTS:

    def test_tp_https_service_no_hsts(self):
        """True-Positive: HTTPS service without HSTS → MEDIUM."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            # SSL configuration
            SSL_KEYFILE = "/etc/ssl/private/server.key"
            SSL_CERTFILE = "/etc/ssl/certs/server.crt"

            @app.get("/api/v1/data")
            async def data():
                return {}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "HEADERS-MISSING-HSTS"), (
            "HTTPS service without HSTS should be flagged"
        )
        f = _findings_for_rule(findings, "HEADERS-MISSING-HSTS")[0]
        assert f.severity == "MEDIUM"
        assert "Strict-Transport-Security" in f.recommendation

    def test_tp_https_url_no_hsts(self):
        """True-Positive: HTTPS URL in config but no HSTS header → flagged."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            BASE_URL = "https://api.example.com"

            @app.get("/api/v1/items")
            async def items():
                return []
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "HEADERS-MISSING-HSTS")

    def test_tn_hsts_present(self):
        """True-Negative: Strict-Transport-Security header is set → NOT flagged."""
        code = """\
            from fastapi import FastAPI, Request
            app = FastAPI()

            # HTTPS / SSL enabled
            HTTPS = True

            @app.middleware("http")
            async def hsts_middleware(request: Request, call_next):
                response = await call_next(request)
                response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
                return response

            @app.get("/api/v1/data")
            async def data():
                return {}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "HEADERS-MISSING-HSTS")

    def test_tn_no_https_indicators(self):
        """True-Negative: no HTTPS indicators → HSTS not flagged."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/api/v1/items")
            async def items():
                return []
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "HEADERS-MISSING-HSTS"), (
            "Should NOT flag HSTS when there are no HTTPS/SSL indicators"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Check 6 — HEADERS-CORS-WILDCARD-METHODS
# ─────────────────────────────────────────────────────────────────────────────

class TestWildcardMethods:

    def test_tp_wildcard_methods_sensitive_routes(self):
        """True-Positive: allow_methods=['*'] with sensitive endpoint → LOW."""
        code = """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()

            app.add_middleware(
                CORSMiddleware,
                allow_origins=["https://example.com"],
                allow_methods=["*"],
            )

            @app.get("/api/v1/users/profile")
            async def profile():
                return {}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "HEADERS-CORS-WILDCARD-METHODS"), (
            "allow_methods=['*'] with sensitive routes should be LOW"
        )
        f = _findings_for_rule(findings, "HEADERS-CORS-WILDCARD-METHODS")[0]
        assert f.severity == "LOW"

    def test_tn_specific_methods(self):
        """True-Negative: specific allow_methods → NOT flagged."""
        code = """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()

            app.add_middleware(
                CORSMiddleware,
                allow_origins=["https://example.com"],
                allow_methods=["GET", "POST"],
            )

            @app.get("/api/v1/users/profile")
            async def profile():
                return {}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "HEADERS-CORS-WILDCARD-METHODS")


# ─────────────────────────────────────────────────────────────────────────────
# Recommendation content checks
# ─────────────────────────────────────────────────────────────────────────────

def _CORS_SNIPPET_PRESENT(recommendation: str) -> bool:
    """Assert the recommendation contains the CORS middleware snippet."""
    return "CORSMiddleware" in recommendation and "allow_origins" in recommendation


class TestRecommendations:

    def test_cors_recommendation_contains_snippet(self):
        """CORS findings include the correct middleware code snippet."""
        code = """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()

            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=True,
            )
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        cors_findings = [
            f for f in findings
            if f.rule_id in {
                "HEADERS-CORS-WILDCARD-CREDENTIALS",
                "HEADERS-CORS-WILDCARD",
                "HEADERS-NO-CORS-MIDDLEWARE",
            }
        ]
        assert cors_findings, "Expected at least one CORS finding"
        for f in cors_findings:
            assert "CORSMiddleware" in f.recommendation, (
                f"CORS finding {f.rule_id} missing CORSMiddleware snippet in recommendation"
            )
            assert "allow_origins" in f.recommendation


# ─────────────────────────────────────────────────────────────────────────────
# Suppression tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSuppression:

    def test_nosec_suppresses_cors_wildcard(self):
        """# nosec comment on CORSMiddleware line suppresses finding."""
        code = """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()

            app.add_middleware(  # nosec
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=True,
            )
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        crit_findings = _findings_for_rule(findings, "HEADERS-CORS-WILDCARD-CREDENTIALS")
        non_suppressed = [f for f in crit_findings if not f.is_suppressed]
        assert len(non_suppressed) == 0, "# nosec should suppress CORS finding"


# ─────────────────────────────────────────────────────────────────────────────
# Test-file handling
# ─────────────────────────────────────────────────────────────────────────────

class TestTestFileHandling:

    def test_test_file_is_marked(self):
        """Findings in test files have is_test_file=True."""
        code = """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()

            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=True,
            )
        """
        path = _write_tmp(code, prefix="test_headers_")
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        for f in findings:
            assert f.is_test_file, f"Finding {f.rule_id} in test file should have is_test_file=True"


# ─────────────────────────────────────────────────────────────────────────────
# scan_directory tests
# ─────────────────────────────────────────────────────────────────────────────

class TestScanDirectory:

    def test_scan_directory_aggregates_findings(self, tmp_path):
        """scan_directory returns findings from all .py files."""
        (tmp_path / "app.py").write_text(textwrap.dedent("""\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()

            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=True,
            )

            @app.get("/api/v1/items")
            async def items():
                return []
        """))
        (tmp_path / "config.py").write_text(textwrap.dedent("""\
            from fastapi import FastAPI
            app = FastAPI()

            SSL_KEYFILE = "/etc/ssl/key.pem"

            @app.get("/data")
            async def data():
                return {}
        """))
        findings = scan_directory(str(tmp_path))
        rule_ids = _rule_ids(findings)
        assert "HEADERS-CORS-WILDCARD-CREDENTIALS" in rule_ids or "HEADERS-CORS-WILDCARD" in rule_ids

    def test_scan_directory_nonexistent(self, tmp_path):
        """scan_directory on non-existent path returns empty list gracefully."""
        nonexistent = str(tmp_path / "nonexistent")
        findings = scan_directory(nonexistent)
        assert findings == []

    def test_scan_directory_empty(self, tmp_path):
        """scan_directory on empty directory returns empty list."""
        findings = scan_directory(str(tmp_path))
        assert findings == []

    def test_scan_file_unparseable(self, tmp_path):
        """Unparseable file returns empty list without raising."""
        bad_file = tmp_path / "bad.py"
        bad_file.write_text("def broken(\n    x\n!!not valid python!!")
        findings = scan_file(str(bad_file))
        assert findings == []

    def test_scan_file_nonexistent(self):
        """Non-existent file returns empty list without raising."""
        findings = scan_file("/nonexistent/path/headers.py")
        assert findings == []


# ─────────────────────────────────────────────────────────────────────────────
# Finding model validation
# ─────────────────────────────────────────────────────────────────────────────

class TestFindingModel:

    def test_findings_have_required_fields(self):
        """All returned findings have populated required fields."""
        code = """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()

            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=True,
            )

            @app.get("/api/v1/items")
            async def items():
                return []
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert findings, "Expected at least one finding"
        for f in findings:
            assert f.rule_id
            assert f.file == path
            assert f.line >= 0
            assert f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
            assert 0.0 <= f.confidence <= 1.0
            assert f.description
            assert f.recommendation

    def test_findings_confidence_range(self):
        """All findings have confidence in [0, 1]."""
        code = """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()

            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=True,
            )
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        for f in findings:
            assert 0.0 <= f.confidence <= 1.0


# ─────────────────────────────────────────────────────────────────────────────
# Benchmark: precision and recall
# ─────────────────────────────────────────────────────────────────────────────

class TestBenchmark:
    """
    Structured benchmark evaluating precision (>= 0.85) and recall (>= 0.80).
    """

    CORPUS = [
        # ── True Positives ────────────────────────────────────────────────
        (
            """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=True,
            )
            """,
            "HEADERS-CORS-WILDCARD-CREDENTIALS",
            "TP: wildcard + credentials CRITICAL",
        ),
        (
            """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
            )
            @app.get("/api/v1/items")
            async def items(): return []
            """,
            "HEADERS-CORS-WILDCARD",
            "TP: wildcard no credentials MEDIUM",
        ),
        (
            """\
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/api/v1/data")
            async def data(): return {}
            """,
            "HEADERS-NO-CORS-MIDDLEWARE",
            "TP: FastAPI app no CORS",
        ),
        (
            """\
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/api/v1/data")
            async def data(): return {}
            """,
            "HEADERS-NO-SECURITY-HEADERS",
            "TP: no security headers",
        ),
        (
            """\
            from fastapi import FastAPI
            app = FastAPI()
            SSL_KEYFILE = "/etc/ssl/key.pem"
            @app.get("/api/v1/data")
            async def data(): return {}
            """,
            "HEADERS-MISSING-HSTS",
            "TP: SSL without HSTS",
        ),
        (
            """\
            from fastapi import FastAPI
            app = FastAPI()
            BASE_URL = "https://api.myapp.com"
            @app.get("/api/v1/data")
            async def data(): return {}
            """,
            "HEADERS-MISSING-HSTS",
            "TP: HTTPS URL without HSTS",
        ),
        (
            """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["https://example.com"],
                allow_methods=["*"],
            )
            @app.get("/api/v1/users/profile")
            async def profile(): return {}
            """,
            "HEADERS-CORS-WILDCARD-METHODS",
            "TP: wildcard methods + sensitive route",
        ),
        # ── True Negatives ────────────────────────────────────────────────
        (
            """\
            from fastapi import FastAPI, Request
            from fastapi.middleware.cors import CORSMiddleware
            from security_headers import SecurityHeadersMiddleware
            app = FastAPI()
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["https://app.example.com"],
                allow_credentials=True,
                allow_methods=["GET", "POST"],
                allow_headers=["Authorization", "Content-Type"],
            )
            app.add_middleware(SecurityHeadersMiddleware)
            """,
            None,
            "TN: specific origin with credentials + security headers",
        ),
        (
            """\
            from fastapi import FastAPI, Request
            from fastapi.middleware.cors import CORSMiddleware
            from security_headers import SecurityHeadersMiddleware
            app = FastAPI()
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["https://example.com"],
                allow_methods=["GET"],
            )
            app.add_middleware(SecurityHeadersMiddleware)
            """,
            None,
            "TN: specific origin no wildcard + security headers",
        ),
        (
            """\
            from fastapi import FastAPI
            from fastapi.middleware.cors import CORSMiddleware
            from security_headers import SecurityHeadersMiddleware
            app = FastAPI()
            app.add_middleware(SecurityHeadersMiddleware)
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["https://app.example.com"],
                allow_methods=["GET", "POST"],
            )
            @app.get("/api/v1/items")
            async def items(): return []
            """,
            None,
            "TN: SecurityHeadersMiddleware + CORSMiddleware present",
        ),
        (
            """\
            from fastapi import FastAPI, Request
            from fastapi.middleware.cors import CORSMiddleware
            app = FastAPI()
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["https://example.com"],
            )
            @app.middleware("http")
            async def add_headers(request: Request, call_next):
                resp = await call_next(request)
                resp.headers["Strict-Transport-Security"] = "max-age=31536000"
                resp.headers["X-Content-Type-Options"] = "nosniff"
                resp.headers["X-Frame-Options"] = "DENY"
                resp.headers["Content-Security-Policy"] = "default-src 'self'"
                return resp
            @app.get("/api/v1/data")
            async def data(): return {}
            """,
            None,
            "TN: manual security headers set + CORS",
        ),
        (
            """\
            from fastapi import FastAPI, Request
            from fastapi.middleware.cors import CORSMiddleware
            from security_headers import SecurityHeadersMiddleware
            app = FastAPI()
            HTTPS = True
            app.add_middleware(SecurityHeadersMiddleware)
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["https://example.com"],
            )
            @app.middleware("http")
            async def hsts(request: Request, call_next):
                resp = await call_next(request)
                resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
                return resp
            @app.get("/data")
            async def data(): return {}
            """,
            None,
            "TN: HTTPS with HSTS header set + security headers",
        ),
        (
            """\
            def pure_function(x):
                return x * 2
            """,
            None,
            "TN: pure Python no FastAPI",
        ),
        (
            """\
            from fastapi import FastAPI, Request
            from fastapi.middleware.cors import CORSMiddleware
            from security_headers import SecurityHeadersMiddleware
            app = FastAPI()
            app.add_middleware(SecurityHeadersMiddleware)
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["https://example.com"],
                allow_methods=["GET", "POST"],
            )
            @app.get("/api/v1/users/profile")
            async def profile(): return {}
            """,
            None,
            "TN: specific methods no wildcard + security headers",
        ),
    ]

    def test_precision_recall(self, tmp_path):
        """
        Precision >= 0.85 and recall >= 0.80 over the labelled corpus.
        """
        tp_count = 0
        tp_hits = 0
        tn_count = 0
        fp_count = 0

        ALL_HEADER_RULES = {
            "HEADERS-NO-CORS-MIDDLEWARE",
            "HEADERS-CORS-WILDCARD-CREDENTIALS",
            "HEADERS-CORS-WILDCARD",
            "HEADERS-NO-SECURITY-HEADERS",
            "HEADERS-MISSING-HSTS",
            "HEADERS-CORS-WILDCARD-METHODS",
        }

        for i, (code, expected_rule, label) in enumerate(self.CORPUS):
            py_file = tmp_path / f"sample_{i}.py"
            py_file.write_text(textwrap.dedent(code))
            findings = scan_file(str(py_file))
            rule_ids_found = _rule_ids(findings)

            if expected_rule is not None:
                tp_count += 1
                if expected_rule in rule_ids_found:
                    tp_hits += 1
                else:
                    print(f"  MISS [{label}]: expected {expected_rule}, got {rule_ids_found}")
            else:
                tn_count += 1
                vuln_findings = [f for f in findings if f.rule_id in ALL_HEADER_RULES]
                if vuln_findings:
                    fp_count += 1
                    print(f"  FP [{label}]: {[f.rule_id for f in vuln_findings]}")

        fn_count = tp_count - tp_hits
        total_flagged = tp_hits + fp_count
        precision = tp_hits / total_flagged if total_flagged > 0 else 1.0
        recall = tp_hits / tp_count if tp_count > 0 else 0.0

        print(
            f"\nBenchmark: TP={tp_count}, TP_hits={tp_hits}, "
            f"FP={fp_count}, FN={fn_count}\n"
            f"Precision={precision:.3f}, Recall={recall:.3f}"
        )

        assert recall >= 0.80, (
            f"Recall {recall:.3f} < 0.80 threshold. Missed {fn_count} true positives."
        )
        assert precision >= 0.85, (
            f"Precision {precision:.3f} < 0.85 threshold. {fp_count} false positives."
        )
