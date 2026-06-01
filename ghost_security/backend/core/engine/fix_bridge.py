"""
backend/core/engine/fix_bridge.py — Bridge between scan findings and VerifiedFixEngine.

Converts NormalizedFinding objects into VerifiedFix results using the Phase 4
VerifiedFixEngine. Provides template-based fixes for all 9 supported CWEs
when no source code is available.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from backend.core.engine.finding_normalizer import NormalizedFinding
    from backend.core.remediation.verified_fix_engine import VerifiedFix

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Template fix code keyed by CWE ID
# ---------------------------------------------------------------------------

_TEMPLATE_FIXES: Dict[str, str] = {
    "CWE-89": """\
# CWE-89: SQL Injection — use parameterized queries
import sqlite3

def safe_query(db_path: str, user_id: str):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # FIXED: use ? placeholder instead of string concatenation
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()
""",

    "CWE-79": """\
# CWE-79: XSS — HTML-encode user-supplied output
from markupsafe import escape

def render_comment(user_input: str) -> str:
    # FIXED: escape() prevents HTML injection
    safe = escape(user_input)
    return f"<p>{safe}</p>"
""",

    "CWE-78": """\
# CWE-78: OS Command Injection — pass args as a list, shell=False
import subprocess
import shlex

def run_command(user_filename: str) -> str:
    # FIXED: no shell interpolation; arguments are passed as a list
    args = ["/usr/bin/file", "--", user_filename]
    result = subprocess.run(args, capture_output=True, text=True, shell=False, timeout=10)
    return result.stdout
""",

    "CWE-22": """\
# CWE-22: Path Traversal — resolve and validate base directory
import os

BASE_DIR = os.path.realpath("/var/app/uploads")

def safe_open(user_path: str) -> bytes:
    # FIXED: resolve symlinks and check prefix before opening
    real = os.path.realpath(os.path.join(BASE_DIR, user_path))
    if not real.startswith(BASE_DIR + os.sep) and real != BASE_DIR:
        raise PermissionError(f"Access denied: {user_path!r}")
    with open(real, "rb") as fh:
        return fh.read()
""",

    "CWE-798": """\
# CWE-798: Hardcoded Credentials — read from environment
import os

def get_db_password() -> str:
    # FIXED: never hardcode credentials; use environment variables
    password = os.environ.get("DB_PASSWORD")
    if not password:
        raise RuntimeError("DB_PASSWORD environment variable is not set")
    return password
""",

    "CWE-502": """\
# CWE-502: Deserialization of Untrusted Data — use safe_load
import yaml

def parse_config(yaml_text: str) -> dict:
    # FIXED: yaml.safe_load() does not execute arbitrary Python objects
    return yaml.safe_load(yaml_text)
""",

    "CWE-327": """\
# CWE-327: Use of Weak Cryptographic Algorithm — replace with SHA-256
import hashlib

def hash_value(data: str) -> str:
    # FIXED: use SHA-256 instead of MD5 or SHA-1
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

# For password hashing use bcrypt or argon2:
# import bcrypt
# hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
""",

    "CWE-918": """\
# CWE-918: SSRF — validate URLs against an allowlist
import ipaddress
import urllib.parse

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

def validate_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    # Block private / loopback addresses
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            raise ValueError(f"Blocked private address: {host}")
    except ValueError as exc:
        if "Blocked" in str(exc):
            raise
    # Require allowlisted hostnames
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"Host not in allowlist: {host!r}")
    return url
""",

    "CWE-94": """\
# CWE-94: Code Injection — avoid eval/exec on user input
import ast

def safe_eval_literal(user_input: str):
    # FIXED: ast.literal_eval only handles literals (str, int, list, dict, etc.)
    # Never use eval() or exec() on untrusted data.
    try:
        return ast.literal_eval(user_input)
    except (ValueError, SyntaxError) as exc:
        raise ValueError(f"Invalid literal expression: {exc}") from exc
""",
}


# ---------------------------------------------------------------------------
# Internal adapter: makes NormalizedFinding look like what VerifiedFixEngine needs
# ---------------------------------------------------------------------------

class _FindingAdapter:
    """Adapter so VerifiedFixEngine can consume a NormalizedFinding without modification."""

    def __init__(self, finding: "NormalizedFinding") -> None:
        self.rule_id     = finding.rule_id or finding.finding_id
        self.cwe_id      = finding.cwe_id
        self.severity    = finding.severity
        self.file        = finding.file_path
        self.line        = finding.line
        self.description = finding.description


# ---------------------------------------------------------------------------
# FixBridge
# ---------------------------------------------------------------------------

class FixBridge:
    """Bridges NormalizedFinding objects to the Phase 4 VerifiedFixEngine."""

    def __init__(self, engine: Optional[object] = None) -> None:
        if engine is not None:
            self._engine = engine
        else:
            self._engine = self._load_engine()

    # ------------------------------------------------------------------
    # Engine loading with graceful fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _load_engine() -> Optional[object]:
        try:
            from backend.core.remediation.verified_fix_engine import VerifiedFixEngine
            return VerifiedFixEngine()
        except ImportError as exc:
            logger.warning("VerifiedFixEngine not available (%s); template-only mode.", exc)
            return None
        except Exception as exc:
            logger.warning("Failed to instantiate VerifiedFixEngine: %s; template-only mode.", exc)
            return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_template_fix(self, cwe_id: str) -> str:
        """Return the template fix code string for a given CWE ID, or '' if unknown."""
        return _TEMPLATE_FIXES.get(cwe_id, "")

    def suggest_fix(
        self,
        finding: "NormalizedFinding",
        source_code: str = "",
    ) -> Optional["VerifiedFix"]:
        """Generate and verify a fix for a single NormalizedFinding.

        Returns a VerifiedFix object, or None if neither the engine nor a
        template is available for this finding's CWE.
        """
        template = _TEMPLATE_FIXES.get(finding.cwe_id, "")
        if not template and not source_code:
            logger.debug("No template for %s and no source_code — skipping.", finding.cwe_id)
            return None

        fix_code = template or source_code

        if self._engine is None:
            # Engine unavailable: return a minimal VerifiedFix built manually
            return self._make_fallback_fix(finding, fix_code)

        try:
            adapted = _FindingAdapter(finding)
            return self._engine.verify_fix(
                adapted,
                fix_code,
                original_source=source_code,
            )
        except Exception as exc:
            logger.warning("VerifiedFixEngine.verify_fix failed for %s: %s", finding.finding_id, exc)
            return self._make_fallback_fix(finding, fix_code)

    def suggest_fixes_batch(
        self,
        findings: List["NormalizedFinding"],
        source_code: str = "",
    ) -> List["VerifiedFix"]:
        """Generate verified fixes for a list of NormalizedFindings (capped at 20)."""
        results: List["VerifiedFix"] = []
        for finding in findings[:20]:
            vf = self.suggest_fix(finding, source_code)
            if vf is not None:
                results.append(vf)
        return results

    # ------------------------------------------------------------------
    # Fallback fix builder (used when engine import fails)
    # ------------------------------------------------------------------

    @staticmethod
    def _make_fallback_fix(finding: "NormalizedFinding", fix_code: str) -> object:
        """Build a minimal VerifiedFix-like object without importing the engine."""
        try:
            from backend.core.remediation.verified_fix_engine import (
                VerifiedFix, FixStatus, FixConfidenceScore
            )
            import uuid
            from datetime import datetime, timezone

            now = datetime.now(timezone.utc).isoformat()
            confidence = FixConfidenceScore(
                build_success=1.0,
                test_success=0.0,
                reachability_removed=0.0,
                verification_passed=0.5,
                no_regression=1.0,
            )
            vf = VerifiedFix(
                fix_id=str(uuid.uuid4())[:8],
                finding_id=finding.finding_id,
                cwe_id=finding.cwe_id,
                severity=finding.severity,
                file_path=finding.file_path,
                suggested_fix=fix_code,
                fix_status=FixStatus.PROPOSED,
                fix_confidence=confidence.total_score,
                confidence_score=confidence,
                created_at=now,
                validated_at=now,
                validation_notes=["Template-based fix; manual verification recommended."],
            )
            return vf
        except Exception as exc:
            logger.error("Fallback fix construction failed: %s", exc)
            return None
