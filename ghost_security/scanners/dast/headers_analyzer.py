"""
TythanAI DAST — Security Headers Analyzer

Makes a live HTTP request to a URL and checks all security-relevant response headers:
  CSP, HSTS, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy, Cookie flags (HttpOnly/Secure/SameSite),
  and deprecated/dangerous headers.

Generates findings with severity levels and concrete remediation recommendations.
"""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class HeaderFinding:
    rule_id:        str
    title:          str
    description:    str
    severity:       str          # HIGH | MEDIUM | LOW | INFO
    header:         str
    actual_value:   str          # "" if header absent
    recommendation: str
    cwe:            str = ""
    owasp:          str = "A05:2021 – Security Misconfiguration"
    confidence:     int = 95


@dataclass
class HeadersReport:
    url:            str
    findings:       List[HeaderFinding]
    headers_present: List[str]    # security headers that ARE present + valid
    headers_missing: List[str]    # security headers that are absent/misconfigured
    security_score:  int          # 0-100
    severity_counts: Dict[str, int] = field(default_factory=dict)
    error:           Optional[str] = None


# ── Header rule definitions ───────────────────────────────────────────────────

def _evaluate_headers(url: str, resp_headers: Dict[str, str],
                      set_cookie_list: List[str]) -> Tuple[List[HeaderFinding], List[str], List[str]]:
    """
    Evaluate security headers from an HTTP response.
    Returns (findings, present_headers, missing_headers).
    """
    findings: List[HeaderFinding] = []
    present:  List[str] = []
    missing:  List[str] = []

    # ── 1. Content-Security-Policy ─────────────────────────────────────────
    csp = resp_headers.get("content-security-policy", "")
    if not csp:
        missing.append("Content-Security-Policy")
        findings.append(HeaderFinding(
            rule_id="HDR-CSP-001",
            title="Content-Security-Policy header missing",
            description=(
                "Without CSP, browsers have no restrictions on which resources "
                "can be loaded — XSS exploits can load arbitrary scripts."
            ),
            severity="HIGH",
            header="Content-Security-Policy",
            actual_value="",
            recommendation=(
                "Add: Content-Security-Policy: default-src 'self'; "
                "script-src 'self'; object-src 'none'; base-uri 'self'; "
                "frame-ancestors 'none'"
            ),
            cwe="CWE-1021",
        ))
    else:
        present.append("Content-Security-Policy")
        # Check for unsafe-inline or unsafe-eval
        if "unsafe-inline" in csp:
            findings.append(HeaderFinding(
                rule_id="HDR-CSP-002",
                title="CSP contains 'unsafe-inline' — weakens XSS protection",
                description=(
                    "'unsafe-inline' allows inline scripts/styles, "
                    "defeating the primary XSS mitigation goal of CSP."
                ),
                severity="MEDIUM",
                header="Content-Security-Policy",
                actual_value=csp[:200],
                recommendation=(
                    "Remove 'unsafe-inline'. Use nonces or hashes for "
                    "inline scripts: script-src 'nonce-<random>'."
                ),
                cwe="CWE-79",
            ))
        if "unsafe-eval" in csp:
            findings.append(HeaderFinding(
                rule_id="HDR-CSP-003",
                title="CSP contains 'unsafe-eval' — allows eval() execution",
                description=(
                    "'unsafe-eval' permits eval(), new Function(), and similar "
                    "constructs — code injection vector if user data reaches eval."
                ),
                severity="MEDIUM",
                header="Content-Security-Policy",
                actual_value=csp[:200],
                recommendation="Remove 'unsafe-eval'; refactor code to avoid eval().",
                cwe="CWE-95",
            ))
        if "default-src" not in csp and "script-src" not in csp:
            findings.append(HeaderFinding(
                rule_id="HDR-CSP-004",
                title="CSP missing default-src and script-src directives",
                description=(
                    "CSP without default-src or script-src provides incomplete "
                    "coverage — script sources are unrestricted."
                ),
                severity="MEDIUM",
                header="Content-Security-Policy",
                actual_value=csp[:200],
                recommendation="Add at minimum: default-src 'self'; script-src 'self'",
                cwe="CWE-1021",
            ))

    # ── 2. Strict-Transport-Security (HSTS) ────────────────────────────────
    hsts = resp_headers.get("strict-transport-security", "")
    if not hsts:
        if url.startswith("https"):
            missing.append("Strict-Transport-Security")
            findings.append(HeaderFinding(
                rule_id="HDR-HSTS-001",
                title="Strict-Transport-Security (HSTS) header missing",
                description=(
                    "Without HSTS, browsers may connect over HTTP after the first "
                    "visit, enabling SSL-stripping attacks."
                ),
                severity="HIGH",
                header="Strict-Transport-Security",
                actual_value="",
                recommendation=(
                    "Add: Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains; preload"
                ),
                cwe="CWE-319",
            ))
    else:
        present.append("Strict-Transport-Security")
        max_age = 0
        for part in hsts.split(";"):
            part = part.strip()
            if part.lower().startswith("max-age="):
                try:
                    max_age = int(part.split("=", 1)[1])
                except ValueError:
                    pass
        if max_age < 2592000:  # less than 30 days
            findings.append(HeaderFinding(
                rule_id="HDR-HSTS-002",
                title=f"HSTS max-age too low ({max_age}s < 30 days)",
                description=(
                    f"HSTS max-age={max_age} is below the recommended 1 year. "
                    "Short max-age means users are not protected for long after first visit."
                ),
                severity="LOW",
                header="Strict-Transport-Security",
                actual_value=hsts,
                recommendation="Set max-age to at least 31536000 (1 year).",
                cwe="CWE-319",
            ))

    # ── 3. X-Frame-Options ─────────────────────────────────────────────────
    xfo = resp_headers.get("x-frame-options", "")
    if not xfo:
        # CSP with frame-ancestors is the modern equivalent
        if "frame-ancestors" not in csp:
            missing.append("X-Frame-Options")
            findings.append(HeaderFinding(
                rule_id="HDR-XFO-001",
                title="X-Frame-Options header missing — clickjacking risk",
                description=(
                    "Without X-Frame-Options or CSP frame-ancestors, "
                    "the page can be embedded in iframes — enabling clickjacking."
                ),
                severity="MEDIUM",
                header="X-Frame-Options",
                actual_value="",
                recommendation=(
                    "Add: X-Frame-Options: DENY  (or SAMEORIGIN)  "
                    "and/or CSP: frame-ancestors 'none'"
                ),
                cwe="CWE-1021",
            ))
    else:
        present.append("X-Frame-Options")
        xfo_val = xfo.upper().strip()
        if xfo_val not in ("DENY", "SAMEORIGIN") and not xfo_val.startswith("ALLOW-FROM"):
            findings.append(HeaderFinding(
                rule_id="HDR-XFO-002",
                title="X-Frame-Options has unexpected/invalid value",
                description=f"X-Frame-Options: '{xfo}' is not a standard value.",
                severity="LOW",
                header="X-Frame-Options",
                actual_value=xfo,
                recommendation="Use DENY or SAMEORIGIN.",
                cwe="CWE-1021",
            ))

    # ── 4. X-Content-Type-Options ──────────────────────────────────────────
    xcto = resp_headers.get("x-content-type-options", "")
    if not xcto:
        missing.append("X-Content-Type-Options")
        findings.append(HeaderFinding(
            rule_id="HDR-XCTO-001",
            title="X-Content-Type-Options header missing",
            description=(
                "Without this header, browsers may sniff content-type and "
                "execute scripts served as non-script MIME types (MIME confusion)."
            ),
            severity="LOW",
            header="X-Content-Type-Options",
            actual_value="",
            recommendation="Add: X-Content-Type-Options: nosniff",
            cwe="CWE-430",
        ))
    elif xcto.lower().strip() != "nosniff":
        findings.append(HeaderFinding(
            rule_id="HDR-XCTO-002",
            title="X-Content-Type-Options has incorrect value",
            description=f"Expected 'nosniff', got '{xcto}'.",
            severity="LOW",
            header="X-Content-Type-Options",
            actual_value=xcto,
            recommendation="Set X-Content-Type-Options: nosniff",
            cwe="CWE-430",
        ))
    else:
        present.append("X-Content-Type-Options")

    # ── 5. Referrer-Policy ────────────────────────────────────────────────
    rp = resp_headers.get("referrer-policy", "")
    _SAFE_REFERRER = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    if not rp:
        missing.append("Referrer-Policy")
        findings.append(HeaderFinding(
            rule_id="HDR-RP-001",
            title="Referrer-Policy header missing",
            description=(
                "Without Referrer-Policy, full URLs (including tokens in query "
                "strings) may be sent to third-party sites via the Referer header."
            ),
            severity="LOW",
            header="Referrer-Policy",
            actual_value="",
            recommendation="Add: Referrer-Policy: strict-origin-when-cross-origin",
            cwe="CWE-598",
        ))
    elif rp.lower() not in _SAFE_REFERRER:
        findings.append(HeaderFinding(
            rule_id="HDR-RP-002",
            title=f"Referrer-Policy '{rp}' may leak URL information",
            description=(
                f"Referrer-Policy: '{rp}' may send the full URL to external "
                "sites, exposing session tokens or sensitive query parameters."
            ),
            severity="LOW",
            header="Referrer-Policy",
            actual_value=rp,
            recommendation="Use: strict-origin-when-cross-origin or no-referrer",
            cwe="CWE-598",
        ))
    else:
        present.append("Referrer-Policy")

    # ── 6. Permissions-Policy ────────────────────────────────────────────
    pp = resp_headers.get("permissions-policy", "") or \
         resp_headers.get("feature-policy", "")
    if not pp:
        missing.append("Permissions-Policy")
        findings.append(HeaderFinding(
            rule_id="HDR-PP-001",
            title="Permissions-Policy header missing",
            description=(
                "Without Permissions-Policy, embedded content can access "
                "camera, microphone, geolocation and other browser APIs."
            ),
            severity="LOW",
            header="Permissions-Policy",
            actual_value="",
            recommendation=(
                "Add: Permissions-Policy: camera=(), microphone=(), "
                "geolocation=(), payment=(), usb=()"
            ),
        ))
    else:
        present.append("Permissions-Policy")

    # ── 7. Cookies (Set-Cookie headers) ───────────────────────────────────
    for cookie in set_cookie_list:
        cookie_lower = cookie.lower()
        cookie_name  = cookie.split("=")[0].strip()

        # Detect session/auth cookies by name pattern
        is_auth_cookie = any(kw in cookie_name.lower()
                             for kw in ("session", "token", "auth", "sid",
                                        "jwt", "csrf", "csrf_token"))

        if "httponly" not in cookie_lower and is_auth_cookie:
            findings.append(HeaderFinding(
                rule_id="HDR-COOKIE-001",
                title=f"Session cookie '{cookie_name}' missing HttpOnly flag",
                description=(
                    f"Cookie '{cookie_name}' is accessible via JavaScript. "
                    "XSS can steal this cookie."
                ),
                severity="HIGH",
                header="Set-Cookie",
                actual_value=cookie[:200],
                recommendation=f"Set HttpOnly flag: Set-Cookie: {cookie_name}=...; HttpOnly",
                cwe="CWE-1004",
            ))

        if "secure" not in cookie_lower and url.startswith("https"):
            findings.append(HeaderFinding(
                rule_id="HDR-COOKIE-002",
                title=f"Cookie '{cookie_name}' missing Secure flag",
                description=(
                    f"Cookie '{cookie_name}' can be sent over HTTP. "
                    "An attacker on the network can intercept it."
                ),
                severity="MEDIUM",
                header="Set-Cookie",
                actual_value=cookie[:200],
                recommendation=f"Add Secure flag: Set-Cookie: {cookie_name}=...; Secure",
                cwe="CWE-614",
            ))

        samesite_match = next(
            (p.strip() for p in cookie.split(";")
             if p.strip().lower().startswith("samesite")),
            "",
        )
        if not samesite_match and is_auth_cookie:
            findings.append(HeaderFinding(
                rule_id="HDR-COOKIE-003",
                title=f"Session cookie '{cookie_name}' missing SameSite attribute",
                description=(
                    f"Cookie '{cookie_name}' has no SameSite attribute. "
                    "Cross-site requests will include this cookie — CSRF risk."
                ),
                severity="MEDIUM",
                header="Set-Cookie",
                actual_value=cookie[:200],
                recommendation=(
                    f"Add SameSite: Set-Cookie: {cookie_name}=...; SameSite=Strict"
                ),
                cwe="CWE-352",
            ))
        elif samesite_match.lower() == "samesite=none" and \
                "secure" not in cookie_lower:
            findings.append(HeaderFinding(
                rule_id="HDR-COOKIE-004",
                title=f"Cookie '{cookie_name}' SameSite=None without Secure",
                description=(
                    "SameSite=None requires Secure flag to be effective in "
                    "modern browsers. Without it the attribute is ignored."
                ),
                severity="MEDIUM",
                header="Set-Cookie",
                actual_value=cookie[:200],
                recommendation="Add Secure when SameSite=None: ...; SameSite=None; Secure",
                cwe="CWE-614",
            ))

    # ── 8. Dangerous / information-leaking headers ────────────────────────
    server = resp_headers.get("server", "")
    if server and len(server) > 3:
        findings.append(HeaderFinding(
            rule_id="HDR-INFO-001",
            title=f"Server header reveals technology: '{server}'",
            description=(
                "The Server header discloses web server type and version, "
                "helping attackers fingerprint and target known CVEs."
            ),
            severity="INFO",
            header="Server",
            actual_value=server,
            recommendation="Set Server header to a generic value or remove it entirely.",
            cwe="CWE-200",
        ))

    x_powered = resp_headers.get("x-powered-by", "")
    if x_powered:
        findings.append(HeaderFinding(
            rule_id="HDR-INFO-002",
            title=f"X-Powered-By header leaks technology: '{x_powered}'",
            description=(
                "X-Powered-By discloses the backend framework, aiding "
                "attacker fingerprinting."
            ),
            severity="INFO",
            header="X-Powered-By",
            actual_value=x_powered,
            recommendation="Remove X-Powered-By header in framework/server config.",
            cwe="CWE-200",
        ))

    return findings, present, missing


def _security_score(present: List[str], missing: List[str],
                    findings: List[HeaderFinding]) -> int:
    """
    Score 0-100.
    Start at 100, deduct per missing/misconfigured header.
    """
    score = 100
    deductions = {
        "Content-Security-Policy": 20,
        "Strict-Transport-Security": 15,
        "X-Frame-Options": 10,
        "X-Content-Type-Options": 5,
        "Referrer-Policy": 5,
        "Permissions-Policy": 5,
    }
    for h in missing:
        score -= deductions.get(h, 3)
    # Additional penalty for HIGH findings from misconfigured headers
    for f in findings:
        if f.severity == "HIGH" and f.header not in missing:
            score -= 10
        elif f.severity == "MEDIUM" and f.header not in missing:
            score -= 5
    return max(0, min(100, score))


# ── SecurityHeadersAnalyzer ───────────────────────────────────────────────────

class SecurityHeadersAnalyzer:
    """
    Makes a live GET request to the target URL and analyzes all
    security-relevant response headers and Set-Cookie attributes.
    """

    def __init__(self, timeout: int = 10, follow_redirects: bool = True):
        self._timeout         = timeout
        self._follow_redirects = follow_redirects

    def analyze(self, url: str) -> HeadersReport:
        resp_headers, set_cookie_list, error = self._fetch(url)
        if error:
            return HeadersReport(
                url=url, findings=[], headers_present=[],
                headers_missing=[], security_score=0, error=error,
            )

        findings, present, missing = _evaluate_headers(url, resp_headers,
                                                        set_cookie_list)

        score = _security_score(present, missing, findings)

        counts: Dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        return HeadersReport(
            url=url,
            findings=sorted(findings,
                            key=lambda f: {"HIGH": 0, "MEDIUM": 1,
                                           "LOW": 2, "INFO": 3}.get(f.severity, 4)),
            headers_present=present,
            headers_missing=missing,
            security_score=score,
            severity_counts=counts,
        )

    def _fetch(self, url: str) -> Tuple[Dict[str, str], List[str], Optional[str]]:
        """Return (lowercased_headers, set_cookie_values, error_or_None)."""
        try:
            context: Optional[ssl.SSLContext] = None
            if url.startswith("https"):
                context = ssl.create_default_context()
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "TythanAI-SecurityScanner/6.5",
                         "Accept": "text/html,application/json,*/*"},
            )
            opener = urllib.request.build_opener(
                urllib.request.HTTPRedirectHandler() if self._follow_redirects
                else urllib.request.BaseHandler()
            )
            with opener.open(req, timeout=self._timeout) as resp:
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                # urllib merges multiple Set-Cookie into one; get raw list
                set_cookies = resp.headers.get_all("Set-Cookie") or []
                if not set_cookies:
                    raw = resp.headers.get("Set-Cookie", "")
                    set_cookies = [raw] if raw else []
                return hdrs, set_cookies, None
        except urllib.error.HTTPError as e:
            hdrs = {k.lower(): v for k, v in e.headers.items()}
            set_cookies = e.headers.get_all("Set-Cookie") or []
            return hdrs, set_cookies, None
        except Exception as exc:
            return {}, [], str(exc)

    def to_normalized_findings(self, report: HeadersReport) -> List[dict]:
        """Convert HeaderFinding list to TythanAI internal format."""
        out: List[dict] = []
        for f in report.findings:
            out.append({
                "type":            "DAST_FINDING",
                "source":          "headers_analyzer",
                "severity":        f.severity,
                "rule_id":         f.rule_id,
                "title":           f.title,
                "description":     f.description,
                "evidence":        f.actual_value or f"Missing {f.header}",
                "recommendation":  f.recommendation,
                "cwe":             f.cwe,
                "file":            "",
                "line":            0,
                "url":             report.url,
                "method":          "GET",
                "owasp_category":  f.owasp,
                "confidence":      f.confidence,
                "runtime_verified": True,
                "category":        "DAST",
                "tags":            ["dast", "headers", "misconfiguration",
                                    f.severity.lower()],
            })
        return out
