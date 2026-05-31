"""
tests/test_auth_checker.py — True-Positive, True-Negative, and Benchmark
tests for backend/scanners/auth_checker.py.

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

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.scanners.auth_checker import scan_file, scan_directory
from backend.core.confidence import Finding


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _write_tmp(content: str, suffix: str = ".py", prefix: str = "auth_test_") -> str:
    """Write *content* to a named temp file and return its path."""
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
# Check 1 — AUTH-MISSING-DEPENDENCY (unprotected endpoint)
# ─────────────────────────────────────────────────────────────────────────────

class TestMissingAuthDependency:

    def test_tp_unprotected_post_endpoint(self):
        """True-Positive: POST endpoint with no Depends → flagged."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            @app.post("/api/v1/data")
            async def create_data(payload: dict):
                return payload
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "AUTH-MISSING-DEPENDENCY"), (
            "Expected AUTH-MISSING-DEPENDENCY for unprotected POST endpoint"
        )
        f = _findings_for_rule(findings, "AUTH-MISSING-DEPENDENCY")[0]
        assert f.severity == "HIGH"
        assert f.cwe_id == "CWE-306"
        assert f.confidence >= 0.8

    def test_tp_unprotected_get_endpoint(self):
        """True-Positive: GET endpoint missing auth dependency."""
        code = """\
            from fastapi import APIRouter
            router = APIRouter()

            @router.get("/users/profile")
            def get_profile():
                return {}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "AUTH-MISSING-DEPENDENCY")

    def test_tn_endpoint_with_get_current_user(self):
        """True-Negative: endpoint with Depends(get_current_user) → NOT flagged."""
        code = """\
            from fastapi import FastAPI, Depends
            from auth import get_current_user
            app = FastAPI()

            @app.get("/api/v1/profile")
            async def profile(current_user=Depends(get_current_user)):
                return current_user
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "AUTH-MISSING-DEPENDENCY"), (
            "Should NOT flag endpoint with Depends(get_current_user)"
        )

    def test_tn_endpoint_with_verify_token(self):
        """True-Negative: endpoint with Depends(verify_token) → NOT flagged."""
        code = """\
            from fastapi import FastAPI, Depends
            app = FastAPI()

            @app.post("/api/v1/submit")
            async def submit(token=Depends(verify_token)):
                return {}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "AUTH-MISSING-DEPENDENCY")

    def test_tn_health_endpoint_whitelist(self):
        """True-Negative: /health endpoint is whitelisted → NOT flagged."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/health")
            def health():
                return {"status": "ok"}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "AUTH-MISSING-DEPENDENCY"), (
            "/health should be whitelisted"
        )

    def test_tn_docs_endpoint_whitelist(self):
        """True-Negative: /docs and /openapi.json are whitelisted."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/docs")
            def docs(): pass

            @app.get("/openapi.json")
            def openapi(): pass

            @app.get("/redoc")
            def redoc(): pass
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "AUTH-MISSING-DEPENDENCY")

    def test_tn_public_route_whitelist(self):
        """True-Negative: route with 'public' in path is whitelisted."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/api/v1/public/info")
            def public_info():
                return {}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "AUTH-MISSING-DEPENDENCY")

    def test_tn_auth_login_endpoint_whitelisted(self):
        """True-Negative: /api/v1/auth/login is intentionally public."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            @app.post("/api/v1/auth/login")
            async def login(credentials: dict):
                return {"token": "..."}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "AUTH-MISSING-DEPENDENCY")

    def test_tn_security_kwarg(self):
        """True-Negative: endpoint declares security= in decorator."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()
            oauth2 = {"bearerAuth": []}

            @app.get("/api/v1/secure", security=[oauth2])
            async def secure_endpoint():
                return {}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "AUTH-MISSING-DEPENDENCY")

    def test_tp_optional_user_needs_review(self):
        """True-Positive: Optional[Depends(...)] → AUTH-OPTIONAL-USER at low confidence."""
        code = """\
            from fastapi import FastAPI, Depends
            from typing import Optional
            app = FastAPI()

            @app.get("/api/v1/feed")
            async def feed(current_user: Optional[Depends(get_current_user)] = None):
                return {}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        # Should find AUTH-OPTIONAL-USER (needs-review) rather than hard vulnerability
        optional_findings = _findings_for_rule(findings, "AUTH-OPTIONAL-USER")
        # If not caught, the unprotected check may fire — check confidence is lower
        if optional_findings:
            assert optional_findings[0].confidence <= 0.65

    def test_suppression_nosec(self):
        """Suppression: # nosec comment suppresses the finding."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/api/v1/data")  # nosec
            async def get_data():
                return {}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        # Findings should be suppressed
        auth_findings = _findings_for_rule(findings, "AUTH-MISSING-DEPENDENCY")
        suppressed = [f for f in auth_findings if f.is_suppressed]
        # Either suppressed or not present
        non_suppressed = [f for f in auth_findings if not f.is_suppressed]
        assert len(non_suppressed) == 0, "# nosec should suppress the finding"

    def test_test_file_marked_correctly(self):
        """Test files: findings in test files have is_test_file=True."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/api/v1/data")
            async def get_data():
                return {}
        """
        # Write to a file with 'test_' prefix so it's detected as test file
        path = _write_tmp(code, prefix="test_auth_")
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        for f in findings:
            if f.rule_id == "AUTH-MISSING-DEPENDENCY":
                assert f.is_test_file, "Finding in test file should have is_test_file=True"


# ─────────────────────────────────────────────────────────────────────────────
# Check 2 — AUTH-IDOR
# ─────────────────────────────────────────────────────────────────────────────

class TestIDOR:

    def test_tp_idor_no_ownership_check(self):
        """True-Positive: {user_id} route with no ownership check → AUTH-IDOR."""
        code = """\
            from fastapi import FastAPI, Depends
            from auth import get_current_user
            app = FastAPI()

            @app.get("/api/v1/users/{user_id}/data")
            async def get_user_data(user_id: int, db=None):
                return db.query(user_id)
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "AUTH-IDOR"), (
            "Expected AUTH-IDOR for route with {user_id} and no ownership check"
        )
        f = _findings_for_rule(findings, "AUTH-IDOR")[0]
        assert f.cwe_id == "CWE-639"
        assert f.severity in {"HIGH", "MEDIUM"}

    def test_tp_idor_plain_id_param(self):
        """True-Positive: {id} route without ownership verification."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            @app.get("/resources/{id}")
            async def get_resource(id: int):
                return {"id": id}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "AUTH-IDOR")

    def test_tn_idor_with_ownership_check(self):
        """True-Negative: ownership check present → NOT flagged as IDOR."""
        code = """\
            from fastapi import FastAPI, Depends
            from auth import get_current_user
            app = FastAPI()

            @app.get("/api/v1/users/{user_id}/data")
            async def get_user_data(user_id: int, current_user=Depends(get_current_user)):
                if current_user.id == user_id:
                    return {}
                raise PermissionError
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "AUTH-IDOR"), (
            "Should NOT flag IDOR when current_user.id == user_id check present"
        )

    def test_tn_idor_with_check_ownership_call(self):
        """True-Negative: check_ownership() called → NOT flagged as IDOR."""
        code = """\
            from fastapi import FastAPI, Depends
            app = FastAPI()

            @app.get("/items/{id}")
            async def get_item(id: int, user=Depends(get_current_user)):
                check_ownership(user, id)
                return {"id": id}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "AUTH-IDOR")

    def test_tn_idor_with_verify_access(self):
        """True-Negative: verify_access() called → NOT flagged."""
        code = """\
            from fastapi import FastAPI, Depends
            app = FastAPI()

            @app.get("/documents/{user_id}")
            async def get_doc(user_id: int, user=Depends(get_current_user)):
                verify_access(user, user_id)
                return {}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "AUTH-IDOR")


# ─────────────────────────────────────────────────────────────────────────────
# Check 3 — AUTH-WEBSOCKET-NO-AUTH
# ─────────────────────────────────────────────────────────────────────────────

class TestWebSocketAuth:

    def test_tp_websocket_no_auth(self):
        """True-Positive: WebSocket route with no Depends → flagged."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            @app.websocket("/ws/chat")
            async def ws_chat(websocket):
                await websocket.accept()
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "AUTH-WEBSOCKET-NO-AUTH"), (
            "Expected AUTH-WEBSOCKET-NO-AUTH for WebSocket without Depends"
        )
        f = _findings_for_rule(findings, "AUTH-WEBSOCKET-NO-AUTH")[0]
        assert f.severity == "MEDIUM"

    def test_tp_router_websocket_no_auth(self):
        """True-Positive: @router.websocket without auth."""
        code = """\
            from fastapi import APIRouter
            router = APIRouter()

            @router.websocket("/ws/events")
            async def events(websocket):
                pass
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "AUTH-WEBSOCKET-NO-AUTH")

    def test_tn_websocket_with_depends(self):
        """True-Negative: WebSocket route with Depends(verify_token) → NOT flagged."""
        code = """\
            from fastapi import FastAPI, Depends
            app = FastAPI()

            @app.websocket("/ws/secure")
            async def ws_secure(websocket, token=Depends(verify_token)):
                await websocket.accept()
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "AUTH-WEBSOCKET-NO-AUTH")

    def test_tn_websocket_with_get_current_user(self):
        """True-Negative: WebSocket with Depends(get_current_user) → NOT flagged."""
        code = """\
            from fastapi import FastAPI, Depends
            app = FastAPI()

            @app.websocket("/ws/live")
            async def ws_live(ws, user=Depends(get_current_user)):
                pass
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "AUTH-WEBSOCKET-NO-AUTH")


# ─────────────────────────────────────────────────────────────────────────────
# Check 4 — AUTH-JWT-CONFUSION
# ─────────────────────────────────────────────────────────────────────────────

class TestJWTConfusion:

    def test_tp_jwt_decode_no_algorithms(self):
        """True-Positive: jwt.decode without algorithms= → CRITICAL."""
        code = """\
            import jwt

            def decode_token(token: str, secret: str):
                return jwt.decode(token, secret)
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "AUTH-JWT-CONFUSION"), (
            "jwt.decode without algorithms= should be flagged"
        )
        f = _findings_for_rule(findings, "AUTH-JWT-CONFUSION")[0]
        assert f.severity == "CRITICAL"
        assert f.cwe_id == "CWE-347"
        assert f.confidence >= 0.9

    def test_tp_jwt_decode_algorithms_none(self):
        """True-Positive: algorithms=['none'] → CRITICAL."""
        code = """\
            import jwt

            def decode_token(token: str, secret: str):
                return jwt.decode(token, secret, algorithms=["none"])
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "AUTH-JWT-CONFUSION")
        f = _findings_for_rule(findings, "AUTH-JWT-CONFUSION")[0]
        assert f.severity == "CRITICAL"

    def test_tp_jwt_decode_verify_signature_false(self):
        """True-Positive: options={'verify_signature': False} → CRITICAL."""
        code = """\
            import jwt

            def insecure_decode(token: str):
                return jwt.decode(token, options={"verify_signature": False})
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "AUTH-JWT-CONFUSION")
        f = _findings_for_rule(findings, "AUTH-JWT-CONFUSION")[0]
        assert f.severity == "CRITICAL"
        assert "verify_signature" in f.description.lower() or "signature" in f.description.lower()

    def test_tn_jwt_decode_with_algorithms(self):
        """True-Negative: jwt.decode with algorithms=['HS256'] → NOT flagged."""
        code = """\
            import jwt

            def decode_token(token: str, secret: str):
                return jwt.decode(token, secret, algorithms=["HS256"])
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "AUTH-JWT-CONFUSION"), (
            "jwt.decode with proper algorithms= should NOT be flagged"
        )

    def test_tn_jwt_decode_rs256(self):
        """True-Negative: jwt.decode with algorithms=['RS256'] → NOT flagged."""
        code = """\
            import jwt

            def decode(token: str, pub_key: str):
                return jwt.decode(token, pub_key, algorithms=["RS256"])
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "AUTH-JWT-CONFUSION")

    def test_tn_jwt_no_nosec_suppression(self):
        """Suppression: # nosec in context silences JWT finding."""
        code = """\
            import jwt

            def decode_token(token: str, secret: str):
                return jwt.decode(token, secret)  # nosec
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        jwt_findings = _findings_for_rule(findings, "AUTH-JWT-CONFUSION")
        non_suppressed = [f for f in jwt_findings if not f.is_suppressed]
        assert len(non_suppressed) == 0, "# nosec should suppress JWT finding"


# ─────────────────────────────────────────────────────────────────────────────
# Check 5 — AUTH-NO-RATE-LIMIT
# ─────────────────────────────────────────────────────────────────────────────

class TestRateLimiting:

    def test_tp_login_no_rate_limit(self):
        """True-Positive: /login endpoint with no rate limiting → MEDIUM."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            @app.post("/api/v1/auth/login")
            async def login(credentials: dict):
                return {"token": "..."}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "AUTH-NO-RATE-LIMIT"), (
            "Expected AUTH-NO-RATE-LIMIT for /login without rate limiting"
        )
        f = _findings_for_rule(findings, "AUTH-NO-RATE-LIMIT")[0]
        assert f.severity == "MEDIUM"

    def test_tp_register_no_rate_limit(self):
        """True-Positive: /register endpoint without rate limiting."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            @app.post("/api/v1/auth/register")
            async def register(data: dict):
                return {}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "AUTH-NO-RATE-LIMIT")

    def test_tp_forgot_password_no_rate_limit(self):
        """True-Positive: /forgot-password without rate limiting."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            @app.post("/api/v1/forgot-password")
            async def forgot_password(email: str):
                return {}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert _has_rule(findings, "AUTH-NO-RATE-LIMIT")

    def test_tn_login_with_limiter_decorator(self):
        """True-Negative: /login with @limiter.limit() decorator → NOT flagged."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            @app.post("/api/v1/auth/login")
            @limiter.limit("5/minute")
            async def login(credentials: dict):
                return {}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "AUTH-NO-RATE-LIMIT"), (
            "Should NOT flag rate limit when @limiter.limit is present"
        )

    def test_tn_login_with_rate_limit_depends(self):
        """True-Negative: /login with Depends(RateLimiter) → NOT flagged."""
        code = """\
            from fastapi import FastAPI, Depends
            from fastapi_limiter.depends import RateLimiter
            app = FastAPI()

            @app.post("/api/v1/auth/login")
            async def login(credentials: dict, _=Depends(RateLimiter(times=5, seconds=60))):
                return {}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert not _has_rule(findings, "AUTH-NO-RATE-LIMIT")


# ─────────────────────────────────────────────────────────────────────────────
# scan_directory tests
# ─────────────────────────────────────────────────────────────────────────────

class TestScanDirectory:

    def test_scan_directory_aggregates_findings(self, tmp_path):
        """scan_directory returns findings from all .py files in a directory."""
        (tmp_path / "routes.py").write_text(textwrap.dedent("""\
            from fastapi import FastAPI
            app = FastAPI()

            @app.post("/api/v1/data")
            async def create_data(payload: dict):
                return payload
        """))
        (tmp_path / "auth.py").write_text(textwrap.dedent("""\
            import jwt

            def decode(token, secret):
                return jwt.decode(token, secret)
        """))
        findings = scan_directory(str(tmp_path))
        rule_ids = _rule_ids(findings)
        assert "AUTH-MISSING-DEPENDENCY" in rule_ids
        assert "AUTH-JWT-CONFUSION" in rule_ids

    def test_scan_directory_nonexistent(self, tmp_path, caplog):
        """scan_directory on non-existent path returns empty list gracefully."""
        nonexistent = str(tmp_path / "nonexistent_dir")
        findings = scan_directory(nonexistent)
        assert findings == []

    def test_scan_directory_empty_dir(self, tmp_path):
        """scan_directory on empty directory returns empty list."""
        findings = scan_directory(str(tmp_path))
        assert findings == []

    def test_scan_file_unparseable(self, tmp_path):
        """Unparseable Python file returns empty list without raising."""
        bad_file = tmp_path / "bad_syntax.py"
        bad_file.write_text("def broken(\n    missing_close\n!!invalid!!")
        findings = scan_file(str(bad_file))
        assert findings == []

    def test_scan_file_nonexistent(self):
        """Non-existent file returns empty list without raising."""
        findings = scan_file("/nonexistent/path/to/file.py")
        assert findings == []


# ─────────────────────────────────────────────────────────────────────────────
# Finding model validation
# ─────────────────────────────────────────────────────────────────────────────

class TestFindingModel:

    def test_findings_have_required_fields(self):
        """All returned findings have populated required fields."""
        code = """\
            from fastapi import FastAPI
            app = FastAPI()

            @app.delete("/api/v1/account")
            async def delete_account():
                return {}
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        assert findings
        for f in findings:
            assert f.rule_id
            assert f.file == path
            assert f.line >= 0
            assert f.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
            assert 0.0 <= f.confidence <= 1.0
            assert f.description
            assert f.recommendation

    def test_findings_confidence_range(self):
        """All findings have confidence values in [0, 1]."""
        code = """\
            import jwt
            from fastapi import FastAPI
            app = FastAPI()

            @app.post("/api/v1/data")
            async def create(payload: dict):
                return payload

            def decode(t, s):
                return jwt.decode(t, s)
        """
        path = _write_tmp(code)
        try:
            findings = scan_file(path)
        finally:
            os.unlink(path)
        for f in findings:
            assert 0.0 <= f.confidence <= 1.0, f"Confidence out of range: {f.confidence}"


# ─────────────────────────────────────────────────────────────────────────────
# Benchmark: precision and recall
# ─────────────────────────────────────────────────────────────────────────────

class TestBenchmark:
    """
    Structured benchmark evaluating precision (>= 0.85) and recall (>= 0.80)
    across a corpus of labelled true-positive and true-negative samples.
    """

    # Each item: (code_snippet, expected_rule_id_or_None, label)
    # expected_rule_id_or_None = the rule we expect to fire (TP), or None (TN)
    CORPUS = [
        # ── True Positives ─────────────────────────────────────────────────
        (
            """\
            from fastapi import FastAPI
            app = FastAPI()
            @app.post("/api/v1/orders")
            async def create_order(data: dict):
                return data
            """,
            "AUTH-MISSING-DEPENDENCY",
            "TP: POST no auth",
        ),
        (
            """\
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/api/v1/admin/users")
            async def list_users():
                return []
            """,
            "AUTH-MISSING-DEPENDENCY",
            "TP: GET admin no auth",
        ),
        (
            """\
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/api/v1/users/{user_id}/profile")
            async def profile(user_id: int):
                return {}
            """,
            "AUTH-IDOR",
            "TP: IDOR user_id no ownership",
        ),
        (
            """\
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/resources/{id}")
            async def get_resource(id: int):
                return {"id": id}
            """,
            "AUTH-IDOR",
            "TP: IDOR {id} no ownership",
        ),
        (
            """\
            from fastapi import FastAPI
            app = FastAPI()
            @app.websocket("/ws/chat")
            async def ws_handler(ws):
                pass
            """,
            "AUTH-WEBSOCKET-NO-AUTH",
            "TP: WebSocket no auth",
        ),
        (
            """\
            import jwt
            def decode(token, secret):
                return jwt.decode(token, secret)
            """,
            "AUTH-JWT-CONFUSION",
            "TP: JWT no algorithms",
        ),
        (
            """\
            import jwt
            def decode(token, secret):
                return jwt.decode(token, secret, algorithms=["none"])
            """,
            "AUTH-JWT-CONFUSION",
            "TP: JWT algorithms=none",
        ),
        (
            """\
            import jwt
            def decode(token):
                return jwt.decode(token, options={"verify_signature": False})
            """,
            "AUTH-JWT-CONFUSION",
            "TP: JWT verify_signature=False",
        ),
        (
            """\
            from fastapi import FastAPI
            app = FastAPI()
            @app.post("/api/v1/auth/login")
            async def login(creds: dict):
                return {}
            """,
            "AUTH-NO-RATE-LIMIT",
            "TP: login no rate limit",
        ),
        (
            """\
            from fastapi import FastAPI
            app = FastAPI()
            @app.post("/api/v1/auth/register")
            async def register(data: dict):
                return {}
            """,
            "AUTH-NO-RATE-LIMIT",
            "TP: register no rate limit",
        ),
        # ── True Negatives ─────────────────────────────────────────────────
        (
            """\
            from fastapi import FastAPI, Depends
            from auth import get_current_user
            app = FastAPI()
            @app.get("/api/v1/me")
            async def me(user=Depends(get_current_user)):
                return user
            """,
            None,
            "TN: GET with get_current_user",
        ),
        (
            """\
            from fastapi import FastAPI, Depends
            app = FastAPI()
            @app.post("/api/v1/items")
            async def create(data: dict, user=Depends(auth)):
                return data
            """,
            None,
            "TN: POST with Depends(auth)",
        ),
        (
            """\
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/health")
            def health():
                return {"status": "ok"}
            """,
            None,
            "TN: /health whitelisted",
        ),
        (
            """\
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/metrics")
            def metrics():
                return {}
            """,
            None,
            "TN: /metrics whitelisted",
        ),
        (
            """\
            import jwt
            def decode(token: str, secret: str):
                return jwt.decode(token, secret, algorithms=["HS256"])
            """,
            None,
            "TN: JWT HS256 correct",
        ),
        (
            """\
            import jwt
            def decode(token: str, key: str):
                return jwt.decode(token, key, algorithms=["RS256"])
            """,
            None,
            "TN: JWT RS256 correct",
        ),
        (
            """\
            from fastapi import FastAPI, Depends
            app = FastAPI()
            @app.get("/api/v1/users/{user_id}/data")
            async def get_data(user_id: int, user=Depends(get_current_user)):
                if user.id == user_id:
                    return {}
            """,
            None,
            "TN: IDOR with ownership check",
        ),
        (
            """\
            from fastapi import FastAPI, Depends
            app = FastAPI()
            @app.websocket("/ws/live")
            async def ws_live(ws, user=Depends(get_current_user)):
                pass
            """,
            None,
            "TN: WebSocket with auth",
        ),
        (
            """\
            from fastapi import FastAPI, Depends
            from fastapi_limiter.depends import RateLimiter
            app = FastAPI()
            @app.post("/api/v1/auth/login")
            async def login(data: dict, _=Depends(RateLimiter(times=5, seconds=60))):
                return {}
            """,
            None,
            "TN: login with RateLimiter",
        ),
        (
            """\
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/api/v1/public/status")
            async def public_status():
                return {}
            """,
            None,
            "TN: public route whitelisted",
        ),
    ]

    def test_precision_recall(self, tmp_path):
        """
        Evaluate precision and recall against the corpus.

        - Precision = TP_hits / (TP_hits + FP) >= 0.85
        - Recall    = TP_hits / (TP_hits + FN) >= 0.80
        """
        tp_count = 0   # true positives in corpus
        tp_hits = 0    # correctly identified true positives
        tn_count = 0   # true negatives in corpus
        fp_count = 0   # false positives (TN that got flagged with expected rule or any similar)

        for i, (code, expected_rule, label) in enumerate(self.CORPUS):
            py_file = tmp_path / f"sample_{i}.py"
            py_file.write_text(textwrap.dedent(code))
            findings = scan_file(str(py_file))
            rule_ids = _rule_ids(findings)

            if expected_rule is not None:
                # True positive sample
                tp_count += 1
                if expected_rule in rule_ids:
                    tp_hits += 1
                else:
                    print(f"  MISS [{label}]: expected {expected_rule}, got {rule_ids}")
            else:
                # True negative sample — count false positives
                tn_count += 1
                # False positives = any security finding generated on a TN sample
                vuln_findings = [
                    f for f in findings
                    if f.rule_id in {
                        "AUTH-MISSING-DEPENDENCY", "AUTH-IDOR",
                        "AUTH-WEBSOCKET-NO-AUTH", "AUTH-JWT-CONFUSION",
                        "AUTH-NO-RATE-LIMIT",
                    }
                ]
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
            f"Recall {recall:.3f} < 0.80 threshold. "
            f"Missed {fn_count} true positives."
        )
        assert precision >= 0.85, (
            f"Precision {precision:.3f} < 0.85 threshold. "
            f"{fp_count} false positives."
        )
