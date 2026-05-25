"""
Ghost Security — JWT and OAuth 2.0 Misconfiguration Scanner

Scans Python, JavaScript/TypeScript, and Java source files for insecure
JWT usage and OAuth 2.0 anti-patterns including:

JWT rules:
  JWT-001  Algorithm confusion — alg:none / algorithm=None
  JWT-002  PyJWT decode without signature verification
  JWT-003  jsonwebtoken verify with algorithms:["none"]
  JWT-004  Hardcoded / weak JWT secret
  JWT-005  JWT decoded but expiry (exp) not checked
  JWT-006  JWT stored in localStorage (XSS theft vector)
  JWT-007  Symmetric secret used where asymmetric is required

OAuth rules:
  OAUTH-001  OAuth implicit flow (deprecated, token in URL)
  OAUTH-002  PKCE missing in authorization code flow
  OAUTH-003  Open redirect in OAuth callback
  OAUTH-004  OAuth state parameter not validated (CSRF)
  OAUTH-005  Client secret exposed in frontend code

Usage:
    from scanners.jwt_scanner import JWTScanner
    scanner = JWTScanner()
    result  = scanner.scan_directory("/path/to/project")
    # OR
    findings = scanner.scan_file("/path/to/auth.py")
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SKIP_DIRS: Set[str] = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", ".nuxt", "coverage",
}

_CODE_EXTENSIONS: Set[str] = {".py", ".js", ".ts", ".java"}

_CONFIDENCE = 80
_EXP_WINDOW = 10          # lines after jwt.decode() to search for exp check


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _is_comment_line(line: str, ext: str) -> bool:
    """Return True when *line* is a pure comment for the given file extension."""
    stripped = line.lstrip()
    if ext == ".py":
        return stripped.startswith("#")
    if ext == ".java":
        return stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*")
    # JS / TS
    return stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*")


def _evidence(line: str) -> str:
    """Strip and cap line at 120 characters for evidence field."""
    return line.strip()[:120]


def _make_finding(
    rule_id: str,
    severity: str,
    cwe: str,
    file_path: str,
    line_no: int,
    message: str,
    description: str,
    evidence_text: str,
    recommendation: str,
) -> Dict:
    return {
        "type": "JWT_OAUTH_ISSUE",
        "id": rule_id,
        "severity": severity,
        "cwe": cwe,
        "file": str(file_path),
        "line": line_no,
        "message": message,
        "description": description,
        "evidence": evidence_text,
        "recommendation": recommendation,
        "source": "jwt_scanner",
        "scanner": "jwt_oauth",
        "confidence": _CONFIDENCE,
    }


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------
# Each entry: (rule_id, compiled_pattern, severity, cwe, applies_to, message, description, recommendation)
# applies_to: frozenset of extensions that the rule is active for; empty = all

_ALL_EXTS = frozenset(_CODE_EXTENSIONS)
_PY = frozenset({".py"})
_JS = frozenset({".js", ".ts"})
_PY_JS = frozenset({".py", ".js", ".ts"})

_PATTERN_REGISTRY: List[Tuple[str, re.Pattern, str, str, frozenset, str, str, str]] = []


def _register() -> None:
    """Build the compiled pattern registry."""
    raw: List[Tuple[str, str, str, str, frozenset, str, str, str]] = [
        # JWT-001 — alg:none algorithm confusion
        (
            "JWT-001",
            r'(?:alg\s*[=:]\s*["\']none["\']|algorithm\s*[=:]\s*["\']none["\']'
            r'|algorithms\s*=\s*\[\s*["\']none["\'])',
            "CRITICAL", "CWE-347",
            _ALL_EXTS,
            "Algorithm confusion — JWT algorithm set to 'none'",
            (
                "The JWT library is configured to accept the 'none' algorithm. "
                "This disables cryptographic signature verification entirely, "
                "allowing any attacker to forge arbitrary tokens by omitting the signature."
            ),
            (
                "Never accept 'none' as a valid algorithm. Maintain an explicit "
                "allowlist of strong algorithms (RS256, ES256). "
                "In PyJWT pass algorithms=['RS256'] and never pass 'none'."
            ),
        ),
        # JWT-002 — PyJWT verify=False / verify_signature=False
        (
            "JWT-002",
            r'jwt\.decode\s*\([^)]*(?:verify\s*=\s*False'
            r'|options\s*=\s*\{[^}]*["\']verify_signature["\'\s]*:\s*False)',
            "CRITICAL", "CWE-347",
            _PY,
            "PyJWT decode called with signature verification disabled",
            (
                "jwt.decode() is invoked with verify=False or "
                "options={'verify_signature': False}. "
                "This completely disables signature validation, making token forgery trivial."
            ),
            (
                "Remove verify=False and options={'verify_signature': False}. "
                "Always pass the correct secret/public key and an explicit algorithms list. "
                "Use jwt.decode(token, key, algorithms=['RS256'])."
            ),
        ),
        # JWT-003 — jsonwebtoken algorithms:["none"]
        (
            "JWT-003",
            r'jwt\.verify\s*\([^,]+,[^,]+,\s*\{[^}]*algorithms\s*:\s*\[\s*["\']none["\']',
            "CRITICAL", "CWE-347",
            _JS,
            "jsonwebtoken verify accepts 'none' algorithm",
            (
                "jwt.verify() in the jsonwebtoken library is called with "
                "algorithms: ['none'], disabling cryptographic verification "
                "and allowing forged tokens to be accepted."
            ),
            (
                "Set algorithms to a concrete algorithm such as ['RS256'] or ['HS256']. "
                "Never include 'none'. Consider using a security-focused JWT library "
                "that does not accept 'none' by design."
            ),
        ),
        # JWT-004 — hardcoded weak secret
        (
            "JWT-004",
            r'(?:secret\s*[=:]\s*["\'][a-zA-Z0-9]{1,20}["\'].*jwt'
            r'|jwt.*secret\s*[=:]\s*["\'][a-zA-Z0-9]{1,20}["\'])',
            "HIGH", "CWE-798",
            _ALL_EXTS,
            "Hardcoded or weak JWT secret detected",
            (
                "A short, hardcoded string is used as the JWT signing secret. "
                "Hardcoded secrets can be extracted from source code or binaries, "
                "and short secrets are vulnerable to brute-force attacks."
            ),
            (
                "Load the JWT secret from an environment variable or secrets manager "
                "(e.g. AWS Secrets Manager, HashiCorp Vault). "
                "Use a cryptographically random secret of at least 256 bits for HMAC, "
                "or switch to RSA/ECDSA key pairs."
            ),
        ),
        # JWT-006 — localStorage JWT storage
        (
            "JWT-006",
            r'localStorage\.setItem\s*\(\s*["\'](?:token|jwt|access_token|id_token)["\']',
            "HIGH", "CWE-922",
            _JS,
            "JWT stored in localStorage — vulnerable to XSS token theft",
            (
                "A JWT or access token is written to localStorage. "
                "Any XSS vulnerability on the page can read localStorage "
                "and exfiltrate the token, leading to account takeover."
            ),
            (
                "Store tokens in HttpOnly, Secure cookies that JavaScript cannot access. "
                "If localStorage must be used, implement strict CSP and XSS mitigations. "
                "Consider short token lifetimes and refresh token rotation."
            ),
        ),
        # JWT-007 — symmetric secret used in production / public API
        (
            "JWT-007",
            r'(?:HS256.*production|HS512.*public_api|jwt.*secret.*(?:os\.environ|process\.env))',
            "MEDIUM", "CWE-326",
            _ALL_EXTS,
            "Symmetric JWT algorithm in a context requiring asymmetric keys",
            (
                "HS256/HS512 (HMAC) algorithms are used where the token is validated "
                "by third parties or in a production/public-API context. "
                "HMAC secrets must be shared with validators, increasing exposure risk."
            ),
            (
                "Switch to RS256 or ES256 (asymmetric algorithms). "
                "Keep the private key secret and distribute only the public key to validators. "
                "This eliminates the need to share any secret."
            ),
        ),
        # OAUTH-001 — implicit flow
        (
            "OAUTH-001",
            r'(?:response_type\s*[=:]\s*["\']token["\']|grant_type.*implicit)',
            "HIGH", "CWE-287",
            _ALL_EXTS,
            "OAuth implicit flow used — token exposed in URL fragment",
            (
                "The OAuth implicit flow (response_type=token) returns the access token "
                "directly in the URL fragment. This is deprecated (RFC 9700) because tokens "
                "can leak via Referrer headers, browser history, and open redirects."
            ),
            (
                "Replace implicit flow with Authorization Code + PKCE flow. "
                "Use response_type=code and exchange the code server-side for tokens. "
                "Never expose access tokens in URLs."
            ),
        ),
        # OAUTH-002 — PKCE missing
        (
            "OAUTH-002",
            r'grant_type.*authorization_code',
            "HIGH", "CWE-287",
            _ALL_EXTS,
            "Authorization code flow without PKCE — vulnerable to interception",
            (
                "An OAuth authorization code flow is used but no code_verifier or "
                "code_challenge parameter is visible nearby. Without PKCE, a malicious "
                "app that intercepts the authorization code can exchange it for tokens."
            ),
            (
                "Implement PKCE (RFC 7636): generate a cryptographically random "
                "code_verifier, compute code_challenge=S256(code_verifier), send "
                "code_challenge in the authorization request, and send code_verifier "
                "in the token request."
            ),
        ),
        # OAUTH-003 — open redirect in callback
        (
            "OAUTH-003",
            r'redirect_uri\s*[=:+]\s*(?:["\'][^"\']*["\'].*\+|.*\.format\s*\(|.*%s)',
            "HIGH", "CWE-601",
            _ALL_EXTS,
            "OAuth redirect_uri constructed dynamically — open redirect risk",
            (
                "The redirect_uri value is assembled by string concatenation or "
                "string formatting, which can allow an attacker to supply an "
                "arbitrary redirect destination, exfiltrating authorization codes."
            ),
            (
                "Use only pre-registered, whitelisted redirect URIs stored server-side. "
                "Never build redirect_uri from user-supplied input. "
                "Validate the uri strictly against the allowlist before use."
            ),
        ),
        # OAUTH-004 — state param not validated
        (
            "OAUTH-004",
            r'(?:oauth.*callback|authorization_code)',
            "HIGH", "CWE-352",
            _ALL_EXTS,
            "OAuth flow detected — verify state parameter is validated",
            (
                "An OAuth callback or authorization_code exchange is present. "
                "If the 'state' parameter is not validated against the session value, "
                "CSRF attacks can force a victim to bind an attacker-controlled account."
            ),
            (
                "Generate a cryptographically random state value before the authorization "
                "redirect, store it in the session, and verify it matches on callback. "
                "Reject any callback request where state is absent or mismatched."
            ),
        ),
        # OAUTH-005 — client secret in frontend code
        (
            "OAUTH-005",
            r'client_secret\s*[=:]\s*["\'][^"\']{8,}["\']',
            "CRITICAL", "CWE-522",
            _JS,
            "OAuth client_secret hardcoded in frontend code",
            (
                "A client_secret value is hardcoded in JavaScript/TypeScript source. "
                "Frontend code is delivered to browsers and can be read by any user, "
                "exposing the secret and enabling impersonation of the OAuth client."
            ),
            (
                "Client secrets must never appear in frontend code. "
                "Perform the OAuth token exchange server-side only. "
                "For public clients (SPAs, mobile apps) use PKCE without a client_secret."
            ),
        ),
    ]

    for rule_id, raw_pat, sev, cwe, applies, msg, desc, rec in raw:
        _PATTERN_REGISTRY.append(
            (rule_id, re.compile(raw_pat, re.IGNORECASE | re.DOTALL), sev, cwe, applies, msg, desc, rec)
        )


_register()


# ---------------------------------------------------------------------------
# Multi-line checks (JWT-005 and OAUTH-002 PKCE deeper check)
# ---------------------------------------------------------------------------

_JWT_DECODE_RE = re.compile(r'jwt\.decode\s*\(', re.IGNORECASE)
_EXP_CHECK_RE  = re.compile(r'''(?x)
    \b(?:exp|expir(?:ed?|ation|y)|expires_at)\b  |
    verify_exp                                    |
    decode_token\b
''', re.IGNORECASE)

_PKCE_RE = re.compile(r'code_(?:verifier|challenge)', re.IGNORECASE)
_STATE_RE = re.compile(r'\bstate\b', re.IGNORECASE)
_AUTH_CODE_RE = re.compile(r'authorization_code', re.IGNORECASE)


def _check_jwt005(
    lines: List[str], idx: int, ext: str, fp: str
) -> Optional[Dict]:
    """
    JWT-005: jwt.decode() call not followed by exp/expiry check within _EXP_WINDOW lines.
    """
    context = _get_context_lines(lines, idx, window=_EXP_WINDOW)
    if _EXP_CHECK_RE.search(context):
        return None
    return _make_finding(
        "JWT-005", "MEDIUM", "CWE-613", fp, idx + 1,
        "JWT decoded but token expiry (exp) not verified",
        (
            "A jwt.decode() call was found but no expiry check (exp, expires_at, "
            "verify_exp) appears within the following 10 lines. "
            "Tokens without expiry validation remain valid forever after issuance, "
            "enabling session replay after logout or credential rotation."
        ),
        _evidence(lines[idx]),
        (
            "Always validate the exp claim. In PyJWT this is automatic unless you "
            "pass options={'verify_exp': False}. "
            "In jsonwebtoken set clockTolerance and check token.exp explicitly. "
            "Set short token lifetimes (15 min access, 7 day refresh)."
        ),
    )


def _check_oauth002_pkce(
    lines: List[str], idx: int, ext: str, fp: str
) -> Optional[Dict]:
    """
    OAUTH-002 deeper check: look for code_verifier/challenge in ±500-char window.
    """
    # Gather a wide context window — 25 lines each direction
    context = _get_context_lines(lines, idx, window=25)
    if _PKCE_RE.search(context):
        return None   # PKCE found — suppress
    return None       # already flagged by pattern-level match; extra logic reserved


# ---------------------------------------------------------------------------
# Public context helper
# ---------------------------------------------------------------------------

def _get_context_lines(lines: List[str], idx: int, window: int = 10) -> str:
    """
    Return a string containing lines[idx-window : idx+window].

    *idx* is 0-based. Clamps to list bounds automatically.
    """
    start = max(0, idx - window)
    end   = min(len(lines), idx + window + 1)
    return "\n".join(lines[start:end])


# ---------------------------------------------------------------------------
# Core file scanner
# ---------------------------------------------------------------------------

def _scan_file_content(file_path: Path, content: str) -> List[Dict]:
    """
    Apply all JWT/OAuth rules to *content* and return a list of finding dicts.
    """
    findings: List[Dict] = []
    seen: Set[Tuple[str, int]] = set()
    lines = content.splitlines()
    ext = file_path.suffix.lower()
    fp = str(file_path)

    def add(finding: Optional[Dict]) -> None:
        if finding is None:
            return
        key = (finding["id"], finding["line"])
        if key not in seen:
            seen.add(key)
            findings.append(finding)

    # Precompute file-level context for OAUTH-002 / OAUTH-004 state check
    pkce_in_file  = bool(_PKCE_RE.search(content))
    state_in_file = bool(_STATE_RE.search(content))

    for idx, raw_line in enumerate(lines):
        if _is_comment_line(raw_line, ext):
            continue

        # --- Pattern-based rules ---
        for rule_id, pattern, severity, cwe, applies_to, message, description, recommendation in _PATTERN_REGISTRY:
            if ext not in applies_to:
                continue
            if not pattern.search(raw_line):
                continue

            # OAUTH-002: suppress if PKCE found anywhere in file
            if rule_id == "OAUTH-002":
                if pkce_in_file:
                    continue
                # Also suppress if this line already contains code_verifier
                if _PKCE_RE.search(raw_line):
                    continue

            # OAUTH-004: suppress if state validated in file
            if rule_id == "OAUTH-004":
                if state_in_file:
                    continue

            add(_make_finding(
                rule_id, severity, cwe, fp, idx + 1,
                message, description,
                _evidence(raw_line),
                recommendation,
            ))

        # --- JWT-005: multi-line exp check ---
        if ext in {".py", ".js", ".ts"} and _JWT_DECODE_RE.search(raw_line):
            add(_check_jwt005(lines, idx, ext, fp))

    return findings


# ---------------------------------------------------------------------------
# Public scanner class
# ---------------------------------------------------------------------------

class JWTScanner:
    """
    Ghost Security JWT and OAuth 2.0 misconfiguration scanner.

    Applies 12 rules (JWT-001..JWT-007 and OAUTH-001..OAUTH-005) to Python,
    JavaScript, TypeScript, and Java source files.
    """

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Scan a single file and return a list of finding dicts.

        Recognised extensions: .py, .js, .ts, .java
        Files with unrecognised extensions or read errors return [].
        """
        path = Path(file_path)
        if path.suffix.lower() not in _CODE_EXTENSIONS:
            return []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return _scan_file_content(path, content)

    def scan_directory(self, directory: str, max_files: int = 300) -> Dict:
        """
        Recursively scan eligible files under *directory*.

        Parameters
        ----------
        directory : str
            Root path to scan.
        max_files : int
            Maximum number of files to process (default 300).

        Returns
        -------
        dict with keys:
            files_scanned, total_findings, jwt_findings, oauth_findings,
            findings, scanner
        """
        root = Path(directory)
        all_findings: List[Dict] = []
        files_scanned = 0

        for file_path in self._iter_files(root):
            if files_scanned >= max_files:
                break
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            file_findings = _scan_file_content(file_path, content)
            all_findings.extend(file_findings)
            files_scanned += 1

        jwt_findings   = [f for f in all_findings if f["id"].startswith("JWT-")]
        oauth_findings = [f for f in all_findings if f["id"].startswith("OAUTH-")]

        return {
            "files_scanned":  files_scanned,
            "total_findings": len(all_findings),
            "jwt_findings":   len(jwt_findings),
            "oauth_findings": len(oauth_findings),
            "findings":       all_findings,
            "scanner":        "jwt_oauth",
        }

    def pattern_count(self) -> int:
        """Return the number of compiled detection patterns registered."""
        # +1 for the JWT-005 multi-line decode-without-exp check
        return len(_PATTERN_REGISTRY) + 1

    @staticmethod
    def _get_context_lines(lines: List[str], idx: int, window: int = 10) -> str:
        """
        Return a multi-line string spanning lines[idx-window : idx+window].

        *idx* is 0-based; the result is clamped to valid list indices.
        """
        return _get_context_lines(lines, idx, window)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _iter_files(root: Path):
        """Yield all scannable source files under *root*, skipping ignored dirs."""
        for item in root.rglob("*"):
            if any(skip in item.parts for skip in _SKIP_DIRS):
                continue
            if item.is_file() and item.suffix.lower() in _CODE_EXTENSIONS:
                yield item
