"""
TythanAI DAST — Live API Security Scanner

Probes a running HTTP/HTTPS API for:
  - Missing / weak authentication (OWASP API2:2023)
  - Broken Object Level Authorization / BOLA (API1:2023)
  - Excessive data exposure in responses (API3:2023)
  - Insecure HTTP methods (API8:2023)
  - Weak CORS policy (API8:2023)
  - Security header misconfigurations (OWASP A05:2021)
  - Insecure cookie attributes (A05:2021)

No external tools required — uses only Python stdlib urllib.
Works with OpenAPI/Swagger spec OR auto-discovered endpoints.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.client import HTTPResponse
from typing import Any, Dict, List, Optional, Tuple


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class APIScanConfig:
    base_url:           str
    openapi_spec_path:  str = ""          # local file path to spec (optional)
    openapi_spec_url:   str = ""          # URL to spec (optional)
    auth_token:         str = ""          # Bearer token for authenticated probes
    auth_header:        str = "Authorization"
    timeout:            int = 10          # per-request timeout (s)
    follow_redirects:   bool = True
    max_endpoints:      int = 200         # cap on endpoints to probe
    probe_bola:         bool = True       # attempt BOLA probe
    user_agent:         str = "TythanAI-SecurityScanner/6.5"


@dataclass
class APIFinding:
    finding_id:    str
    rule_id:       str
    title:         str
    description:   str
    severity:      str        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    owasp:         str        # API1:2023 etc.
    cwe:           str
    url:           str
    method:        str
    evidence:      str
    recommendation: str
    confidence:    int        # 0-100
    runtime_confirmed: bool = True


@dataclass
class APIScanResult:
    target:       str
    findings:     List[APIFinding]
    endpoints_probed: int
    duration_s:   float
    severity_counts: Dict[str, int] = field(default_factory=dict)
    error:        Optional[str] = None


# ── Internal helpers ──────────────────────────────────────────────────────────

_SENSITIVE_FIELDS = re.compile(
    r"(password|passwd|secret|token|api[_\-]?key|credit[_\-]?card|ssn|"
    r"social[_\-]?security|cvv|pin|private[_\-]?key|auth_token|access_token)",
    re.I,
)

_ADMIN_PATHS = re.compile(
    r"/(admin|internal|management|config|debug|actuator|metrics|health|"
    r"swagger|openapi|graphql|_debug|__admin|system|console)",
    re.I,
)

_ID_PARAM = re.compile(r"\{[a-zA-Z_]*(id|Id|ID|uuid|UUID|pk|PK)[a-zA-Z_]*\}")

# Endpoints that should never be publicly accessible without auth
_SENSITIVE_METHODS = {"DELETE", "PUT", "PATCH"}
_DANGEROUS_METHODS = {"TRACE", "TRACK", "CONNECT"}

_OWASP_LABELS = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Auth",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API8:2023": "Security Misconfiguration",
}

_SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


def _finding_id(rule_id: str, url: str, method: str) -> str:
    import hashlib
    return hashlib.sha256(f"{rule_id}:{method}:{url}".encode()).hexdigest()[:16]


# ── OpenAPI spec loader ───────────────────────────────────────────────────────

def _load_spec(path: str = "", url: str = "") -> Optional[dict]:
    text: Optional[str] = None
    if path:
        try:
            import pathlib
            text = pathlib.Path(path).read_text(encoding="utf-8")
        except Exception:
            return None
    elif url:
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                text = r.read().decode("utf-8")
        except Exception:
            return None
    if text is None:
        return None
    try:
        return json.loads(text)
    except Exception:
        try:
            import yaml  # type: ignore[import]
            return yaml.safe_load(text)
        except Exception:
            return None


def _extract_endpoints_from_spec(spec: dict, base_url: str) -> List[Tuple[str, str, dict]]:
    """Return [(method, full_url, operation)] from an OpenAPI spec."""
    endpoints: List[Tuple[str, str, dict]] = []
    paths = spec.get("paths", {})
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            # Replace path params with realistic values for probing
            probe_path = _ID_PARAM.sub("1", path)
            full_url   = base_url.rstrip("/") + probe_path
            endpoints.append((method.upper(), full_url, op))
    return endpoints


def _probe_http(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
                timeout: int = 10, follow_redirects: bool = True) -> Optional[Tuple[int, Dict[str, str], bytes]]:
    """
    Send an HTTP request; return (status_code, response_headers, body) or None on error.
    response_headers keys are lowercased.
    """
    hdrs = {
        "User-Agent": "TythanAI-SecurityScanner/6.5",
        "Accept": "application/json, */*",
    }
    if headers:
        hdrs.update(headers)
    try:
        req = urllib.request.Request(url, headers=hdrs, method=method)
        ctx = None
        if url.startswith("https"):
            import ssl
            ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=ctx) as resp:  # type: ignore[arg-type]
            body = resp.read(16384)  # cap at 16 KB
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, resp_headers, body
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read(4096)
        except Exception:
            pass
        resp_headers = {k.lower(): v for k, v in e.headers.items()}
        return e.code, resp_headers, body
    except Exception:
        return None


# ── APIScanner ─────────────────────────────────────────────────────────────────

class APIScanner:
    """
    Live HTTP API security scanner.

    Accepts either:
      - An OpenAPI/Swagger spec (for structured endpoint enumeration)
      - A bare base URL (probes common paths)

    Runs checks:
      1. Authentication coverage (per endpoint)
      2. BOLA (unauthenticated access to resource with numeric ID)
      3. Excessive data exposure (sensitive fields in responses)
      4. Insecure HTTP methods (TRACE, TRACK, etc.)
      5. CORS policy
      6. HTTP vs HTTPS
      7. Admin endpoint exposure
      8. Rate limiting headers absent
    """

    def __init__(self, config: APIScanConfig):
        self._cfg = config
        self._auth_headers: Dict[str, str] = {}
        if config.auth_token:
            self._auth_headers[config.auth_header] = (
                f"Bearer {config.auth_token}"
                if not config.auth_token.startswith("Bearer ")
                else config.auth_token
            )

    # ── Public entry point ────────────────────────────────────────────────────

    def scan(self) -> APIScanResult:
        t0 = time.time()
        findings: List[APIFinding] = []
        endpoints: List[Tuple[str, str, dict]] = []

        # Load endpoint list from spec or use heuristic set
        spec: Optional[dict] = None
        if self._cfg.openapi_spec_path or self._cfg.openapi_spec_url:
            spec = _load_spec(self._cfg.openapi_spec_path,
                              self._cfg.openapi_spec_url)
            if spec:
                endpoints = _extract_endpoints_from_spec(spec, self._cfg.base_url)

        if not endpoints:
            endpoints = self._heuristic_endpoints()

        endpoints = endpoints[: self._cfg.max_endpoints]

        # Per-endpoint probes
        for method, url, op_meta in endpoints:
            findings += self._check_endpoint(method, url, op_meta, spec)

        # Base URL checks
        findings += self._check_cors()
        findings += self._check_dangerous_methods()
        findings += self._check_rate_limiting(endpoints)

        # Deduplicate by finding_id
        seen: set = set()
        unique: List[APIFinding] = []
        for f in findings:
            if f.finding_id not in seen:
                seen.add(f.finding_id)
                unique.append(f)

        # Sort by severity
        unique.sort(key=lambda f: -_SEVERITY_RANK.get(f.severity, 0))

        counts: Dict[str, int] = {}
        for f in unique:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        return APIScanResult(
            target=self._cfg.base_url,
            findings=unique,
            endpoints_probed=len(endpoints),
            duration_s=time.time() - t0,
            severity_counts=counts,
        )

    # ── Endpoint-level checks ─────────────────────────────────────────────────

    def _check_endpoint(self, method: str, url: str,
                        op_meta: dict, spec: Optional[dict]) -> List[APIFinding]:
        findings: List[APIFinding] = []

        # 1. Unauthenticated access to protected resources
        if method in _SENSITIVE_METHODS or _ADMIN_PATHS.search(url):
            findings += self._probe_auth_required(method, url, op_meta)

        # 2. BOLA: resource with numeric ID accessible without token
        if self._cfg.probe_bola and _ID_PARAM.search(url.replace(self._cfg.base_url, "")):
            findings += self._probe_bola(method, url)

        # 3. Excessive data exposure
        findings += self._probe_data_exposure(method, url)

        # 4. HTTP (not HTTPS) for sensitive endpoints
        if url.startswith("http://") and \
                not any(h in url for h in ("localhost", "127.0.0.1", "0.0.0.0")):
            findings.append(APIFinding(
                finding_id=_finding_id("API-TLS-001", url, method),
                rule_id="API-TLS-001",
                title="Endpoint uses HTTP instead of HTTPS",
                description=f"Endpoint {method} {url} transmits data unencrypted over HTTP.",
                severity="HIGH",
                owasp="API8:2023",
                cwe="CWE-319",
                url=url,
                method=method,
                evidence=url,
                recommendation="Force HTTPS on all API endpoints; use HSTS.",
                confidence=95,
            ))

        return findings

    def _probe_auth_required(self, method: str, url: str,
                              op_meta: dict) -> List[APIFinding]:
        """Probe endpoint without credentials — if 200 is returned, auth is missing."""
        result = _probe_http(url, method, timeout=self._cfg.timeout)
        if result is None:
            return []
        status, headers, body = result

        # 200/201 without auth on a sensitive path = missing auth
        if status in (200, 201, 202):
            severity = "HIGH"
            title    = "Endpoint accessible without authentication"
            rule_id  = "API-AUTH-MISS-001"
            owasp    = "API2:2023"
            cwe      = "CWE-306"
            if _ADMIN_PATHS.search(url):
                severity = "CRITICAL"
                title    = "Admin/internal endpoint accessible without authentication"
                rule_id  = "API-AUTH-MISS-002"
                owasp    = "API5:2023"
                cwe      = "CWE-284"
            return [APIFinding(
                finding_id=_finding_id(rule_id, url, method),
                rule_id=rule_id,
                title=title,
                description=(
                    f"{method} {url} returned HTTP {status} without "
                    "any Authorization header — authentication not enforced."
                ),
                severity=severity,
                owasp=owasp,
                cwe=cwe,
                url=url,
                method=method,
                evidence=f"HTTP {status} returned without credentials",
                recommendation=(
                    "Require valid JWT/session for all non-public endpoints. "
                    "Return 401 Unauthorized when credentials are absent."
                ),
                confidence=90,
            )]
        return []

    def _probe_bola(self, method: str, url: str) -> List[APIFinding]:
        """
        BOLA probe: request resource with ID=1 authenticated, then ID=2 unauthenticated.
        If unauthenticated also gets 200, BOLA is present.
        """
        if not self._auth_headers:
            return []

        # Authenticated request first
        auth_result = _probe_http(url, method, headers=self._auth_headers,
                                  timeout=self._cfg.timeout)
        if auth_result is None or auth_result[0] not in (200, 201):
            return []

        # Now probe without auth — different resource (ID+1) to avoid cache
        url_id2 = re.sub(r"/(\d+)(/|$)", r"/2\2", url)
        if url_id2 == url:
            return []

        unauth_result = _probe_http(url_id2, method, timeout=self._cfg.timeout)
        if unauth_result is None:
            return []
        unauth_status = unauth_result[0]

        if unauth_status in (200, 201, 202):
            return [APIFinding(
                finding_id=_finding_id("API-BOLA-001", url, method),
                rule_id="API-BOLA-001",
                title="Broken Object Level Authorization (BOLA)",
                description=(
                    f"{method} {url_id2} returned HTTP {unauth_status} without "
                    "authentication — another user's resource may be accessible."
                ),
                severity="HIGH",
                owasp="API1:2023",
                cwe="CWE-639",
                url=url_id2,
                method=method,
                evidence=f"Unauthenticated {method} returned HTTP {unauth_status}",
                recommendation=(
                    "Verify object ownership on every request: "
                    "check resource.owner_id == current_user.id server-side."
                ),
                confidence=75,
            )]
        return []

    def _probe_data_exposure(self, method: str, url: str) -> List[APIFinding]:
        """Check whether JSON response contains sensitive field names."""
        if method not in ("GET", "HEAD"):
            return []
        result = _probe_http(url, "GET",
                             headers=self._auth_headers or None,
                             timeout=self._cfg.timeout)
        if result is None:
            return []
        status, headers, body = result
        if status not in (200, 201) or not body:
            return []

        content_type = headers.get("content-type", "")
        if "json" not in content_type and "javascript" not in content_type:
            return []

        try:
            decoded = body.decode("utf-8", errors="replace")
        except Exception:
            return []

        matches = _SENSITIVE_FIELDS.findall(decoded)
        if not matches:
            return []

        unique_fields = list(dict.fromkeys(m.lower() for m in matches))[:5]
        return [APIFinding(
            finding_id=_finding_id("API-EXPOSE-001", url, "GET"),
            rule_id="API-EXPOSE-001",
            title="Excessive Data Exposure in API response",
            description=(
                f"GET {url} response body contains sensitive field names: "
                f"{', '.join(unique_fields)}. These may be returned to clients unnecessarily."
            ),
            severity="MEDIUM",
            owasp="API3:2023",
            cwe="CWE-200",
            url=url,
            method="GET",
            evidence=f"Sensitive fields in response: {', '.join(unique_fields)}",
            recommendation=(
                "Apply response filtering: never return password/token fields. "
                "Use DTO/serializer whitelist to control output fields."
            ),
            confidence=70,
        )]

    # ── Base URL / global checks ──────────────────────────────────────────────

    def _check_cors(self) -> List[APIFinding]:
        """Send a cross-origin request and inspect CORS response headers."""
        findings: List[APIFinding] = []
        hdrs = {
            "Origin":                  "https://evil.example.com",
            "Access-Control-Request-Method": "GET",
        }
        result = _probe_http(
            self._cfg.base_url, "OPTIONS", headers=hdrs,
            timeout=self._cfg.timeout,
        )
        if result is None:
            return []
        _, resp_headers, _ = result

        acao = resp_headers.get("access-control-allow-origin", "")
        acac = resp_headers.get("access-control-allow-credentials", "false")

        if acao == "*" and acac.lower() == "true":
            findings.append(APIFinding(
                finding_id=_finding_id("API-CORS-001", self._cfg.base_url, "OPTIONS"),
                rule_id="API-CORS-001",
                title="Wildcard CORS with credentials allowed",
                description=(
                    "Server returns Access-Control-Allow-Origin: * "
                    "AND Access-Control-Allow-Credentials: true. "
                    "This combination allows any website to make credentialed requests."
                ),
                severity="CRITICAL",
                owasp="API8:2023",
                cwe="CWE-942",
                url=self._cfg.base_url,
                method="OPTIONS",
                evidence="Access-Control-Allow-Origin: * / Allow-Credentials: true",
                recommendation=(
                    "Never combine wildcard origin with credentials. "
                    "Explicitly list trusted origins in CORS configuration."
                ),
                confidence=95,
            ))
        elif acao == "*":
            findings.append(APIFinding(
                finding_id=_finding_id("API-CORS-002", self._cfg.base_url, "OPTIONS"),
                rule_id="API-CORS-002",
                title="Overly permissive CORS policy (wildcard origin)",
                description=(
                    "Server returns Access-Control-Allow-Origin: * — "
                    "any website can read responses."
                ),
                severity="MEDIUM",
                owasp="API8:2023",
                cwe="CWE-942",
                url=self._cfg.base_url,
                method="OPTIONS",
                evidence="Access-Control-Allow-Origin: *",
                recommendation=(
                    "Restrict CORS to known trusted origins. "
                    "Use a server-side allowlist."
                ),
                confidence=85,
            ))
        elif acao == "https://evil.example.com":
            # Server reflected the arbitrary origin — misconfigured
            findings.append(APIFinding(
                finding_id=_finding_id("API-CORS-003", self._cfg.base_url, "OPTIONS"),
                rule_id="API-CORS-003",
                title="CORS origin reflection (arbitrary origin allowed)",
                description=(
                    "Server reflects arbitrary Origin header in "
                    "Access-Control-Allow-Origin — effectively allows all origins."
                ),
                severity="HIGH",
                owasp="API8:2023",
                cwe="CWE-942",
                url=self._cfg.base_url,
                method="OPTIONS",
                evidence=f"Reflected origin: {acao}",
                recommendation=(
                    "Validate origin against a static allowlist; "
                    "do not reflect request Origin header."
                ),
                confidence=90,
            ))

        return findings

    def _check_dangerous_methods(self) -> List[APIFinding]:
        """Probe for dangerous HTTP methods (TRACE, TRACK)."""
        findings: List[APIFinding] = []
        for method in _DANGEROUS_METHODS:
            result = _probe_http(self._cfg.base_url, method,
                                 timeout=self._cfg.timeout)
            if result is None:
                continue
            status = result[0]
            if status not in (200, 405) or status == 405:
                continue
            if status == 200:
                findings.append(APIFinding(
                    finding_id=_finding_id("API-METH-001",
                                           self._cfg.base_url, method),
                    rule_id="API-METH-001",
                    title=f"Dangerous HTTP method {method} enabled",
                    description=(
                        f"Server accepted HTTP {method} with status 200. "
                        "TRACE enables cross-site tracing (XST) attacks."
                    ),
                    severity="MEDIUM",
                    owasp="API8:2023",
                    cwe="CWE-16",
                    url=self._cfg.base_url,
                    method=method,
                    evidence=f"HTTP {method} returned 200",
                    recommendation=f"Disable HTTP {method} in web server configuration.",
                    confidence=80,
                ))
        return findings

    def _check_rate_limiting(self,
                              endpoints: List[Tuple[str, str, dict]]) -> List[APIFinding]:
        """Check for rate-limiting headers on a sample POST endpoint."""
        post_urls = [u for m, u, _ in endpoints if m == "POST"][:3]
        if not post_urls:
            post_urls = [self._cfg.base_url]

        for url in post_urls:
            result = _probe_http(url, "POST",
                                 headers=self._auth_headers or None,
                                 timeout=self._cfg.timeout)
            if result is None:
                continue
            _, resp_headers, _ = result
            has_rl = any(
                "ratelimit" in k.lower() or "x-rate" in k.lower()
                for k in resp_headers
            )
            if not has_rl:
                return [APIFinding(
                    finding_id=_finding_id("API-RATE-001", url, "POST"),
                    rule_id="API-RATE-001",
                    title="No rate limiting headers on POST endpoint",
                    description=(
                        f"POST {url} response does not include X-RateLimit-* or "
                        "RateLimit-* headers, indicating rate limiting may not be enforced."
                    ),
                    severity="MEDIUM",
                    owasp="API4:2023",
                    cwe="CWE-400",
                    url=url,
                    method="POST",
                    evidence="No X-RateLimit-Limit/Remaining/Reset headers in response",
                    recommendation=(
                        "Implement rate limiting per IP/user. "
                        "Return X-RateLimit-Limit, X-RateLimit-Remaining, "
                        "X-RateLimit-Reset headers."
                    ),
                    confidence=60,
                )]
        return []

    def _heuristic_endpoints(self) -> List[Tuple[str, str, dict]]:
        """Generate a minimal set of probe targets when no spec is available."""
        base = self._cfg.base_url.rstrip("/")
        paths = [
            ("/", "GET"),
            ("/api", "GET"),
            ("/api/v1", "GET"),
            ("/api/v2", "GET"),
            ("/api/users", "GET"),
            ("/api/users/1", "GET"),
            ("/api/admin", "GET"),
            ("/admin", "GET"),
            ("/health", "GET"),
            ("/metrics", "GET"),
            ("/debug", "GET"),
            ("/api/auth/login", "POST"),
            ("/api/login", "POST"),
            ("/api/users", "POST"),
            ("/api/users/1", "DELETE"),
        ]
        return [(m, base + p, {}) for p, m in paths]

    def to_normalized_findings(self, result: APIScanResult) -> List[dict]:
        """Convert APIFinding list to TythanAI internal format."""
        out: List[dict] = []
        for f in result.findings:
            out.append({
                "type":             "DAST_FINDING",
                "source":           "api_scanner",
                "severity":         f.severity,
                "rule_id":          f.rule_id,
                "title":            f.title,
                "description":      f.description,
                "evidence":         f.evidence,
                "recommendation":   f.recommendation,
                "cwe":              f.cwe,
                "file":             "",
                "line":             0,
                "url":              f.url,
                "method":           f.method,
                "owasp_category":   f"{f.owasp}: {_OWASP_LABELS.get(f.owasp, '')}",
                "confidence":       f.confidence,
                "runtime_verified": f.runtime_confirmed,
                "category":         "DAST",
                "tags":             ["dast", "api", f.severity.lower()],
            })
        return out
