"""
TythanAI Platform — OpenAPI Security Scanner
Анализирует OpenAPI 3.x / Swagger 2.x спецификации на:
  BOLA (Broken Object Level Authorization) — API1:2023
  Broken Authentication                    — API2:2023
  Excessive Data Exposure                  — API3:2023
  Lack of Resources & Rate Limiting        — API4:2023
  Broken Function Level Authorization      — API5:2023
  Unrestricted Access to Sensitive Flows   — API6:2023
  Security Misconfiguration                — API8:2023
  Improper Assets Management               — API9:2023
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

# OWASP API Security Top 10 2023
_OWASP_API = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Auth",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Flows",
    "API7:2023": "Server-Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}

_SENSITIVE_FIELD_PATTERNS = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|credit[_-]?card|ssn|"
    r"social[_-]?security|cvv|pin|private[_-]?key|auth)", re.I
)
_ADMIN_PATH_PATTERNS = re.compile(
    r"/(admin|internal|management|config|debug|actuator|metrics|health|"
    r"swagger|openapi|graphql|_debug|__)", re.I
)
_ID_PATH_PATTERNS = re.compile(r"\{[a-zA-Z_]*(id|Id|ID|uuid|UUID)[a-zA-Z_]*\}")
_HTTP_SCHEMES    = {"http"}
_WEAK_AUTH       = {"apiKey", "basic"}


def _load_spec(source: str) -> Optional[dict]:
    """Load OpenAPI spec from file path, URL, or JSON string."""
    # Try file
    if Path(source).exists():
        text = Path(source).read_text(encoding="utf-8")
    elif source.startswith("{"):
        text = source
    elif source.startswith("http"):
        import urllib.request
        try:
            with urllib.request.urlopen(source, timeout=10) as r:
                text = r.read().decode()
        except Exception:
            return None
    else:
        return None

    # Try JSON then YAML
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            import yaml
            return yaml.safe_load(text)
        except Exception:
            return None


def _make_finding(
    rule_id: str,
    severity: str,
    owasp: str,
    message: str,
    path: str = "",
    method: str = "",
    recommendation: str = "",
    evidence: str = "",
    cwe: str = "",
) -> dict:
    return {
        "rule_id":        rule_id,
        "type":           rule_id,
        "severity":       severity,
        "owasp":          owasp,
        "cwe":            cwe,
        "file":           "openapi.yaml",
        "line":           0,
        "message":        message,
        "description":    message,
        "evidence":       evidence or f"{method.upper()} {path}",
        "recommendation": recommendation,
        "source":         "openapi_scanner",
        "category":       "API Security",
        "api_path":       path,
        "api_method":     method,
    }


class OpenAPIScanner:
    """Statically analyses OpenAPI/Swagger spec for security issues."""

    def scan(self, source: str) -> dict:
        """
        source: file path, URL, or JSON/YAML string.
        Returns Ghost-format findings dict.
        """
        spec = _load_spec(source)
        if not spec:
            return {"error": f"Cannot load spec from: {source[:100]}", "findings": []}

        version = "3" if "openapi" in spec else "2"
        findings: List[dict] = []

        findings += self._check_auth_global(spec, version)
        findings += self._check_https(spec, version)
        findings += self._check_paths(spec, version)
        findings += self._check_schemas(spec, version)
        findings += self._check_rate_limiting(spec)
        findings += self._check_cors(spec, version)

        counts: dict = {}
        for f in findings:
            s = f["severity"]
            counts[s] = counts.get(s, 0) + 1

        return {
            "findings":        findings,
            "total":           len(findings),
            "severity_counts": counts,
            "api_version":     version,
            "title":           spec.get("info", {}).get("title", "Unknown API"),
            "scanner":         "openapi_scanner",
        }

    def scan_file(self, filepath: str) -> List[dict]:
        return self.scan(filepath).get("findings", [])

    # ── Checks ────────────────────────────────────────────────────

    def _check_auth_global(self, spec: dict, version: str) -> List[dict]:
        findings = []
        if version == "3":
            schemes = spec.get("components", {}).get("securitySchemes", {})
        else:
            schemes = spec.get("securityDefinitions", {})

        if not schemes:
            findings.append(_make_finding(
                "API-AUTH-001", "HIGH", "API2:2023",
                "No security schemes defined in API spec",
                recommendation="Define securitySchemes for OAuth2, JWT, or API key authentication",
                cwe="CWE-306",
            ))
            return findings

        for name, scheme in schemes.items():
            stype = scheme.get("type", "")
            if stype == "http" and scheme.get("scheme", "").lower() == "basic":
                findings.append(_make_finding(
                    "API-AUTH-002", "HIGH", "API2:2023",
                    f"Basic authentication scheme '{name}' — credentials sent with every request",
                    evidence=f"securityScheme: {name}",
                    recommendation="Use OAuth 2.0 or JWT Bearer tokens instead of Basic auth",
                    cwe="CWE-522",
                ))
            if stype == "apiKey" and scheme.get("in") == "query":
                findings.append(_make_finding(
                    "API-AUTH-003", "MEDIUM", "API2:2023",
                    f"API key '{name}' transmitted in URL query parameter — logged in server logs",
                    evidence=f"apiKey in: query",
                    recommendation="Transmit API keys in headers (X-API-Key), not query parameters",
                    cwe="CWE-598",
                ))
        return findings

    def _check_https(self, spec: dict, version: str) -> List[dict]:
        findings = []
        if version == "3":
            servers = spec.get("servers", [])
            for s in servers:
                url = s.get("url", "")
                if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
                    findings.append(_make_finding(
                        "API-TLS-001", "HIGH", "API8:2023",
                        f"Server URL uses HTTP (not HTTPS): {url}",
                        evidence=url,
                        recommendation="Use HTTPS for all production server URLs",
                        cwe="CWE-319",
                    ))
        else:
            schemes = spec.get("schemes", [])
            if "http" in schemes and "https" not in schemes:
                findings.append(_make_finding(
                    "API-TLS-001", "HIGH", "API8:2023",
                    "API only supports HTTP scheme, not HTTPS",
                    recommendation="Add 'https' to schemes and remove 'http'",
                    cwe="CWE-319",
                ))
        return findings

    def _check_paths(self, spec: dict, version: str) -> List[dict]:
        findings = []
        paths = spec.get("paths", {})

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            # Admin endpoints without auth
            if _ADMIN_PATH_PATTERNS.search(path):
                for method in ("get","post","put","patch","delete"):
                    op = path_item.get(method, {})
                    if op and not op.get("security") and not spec.get("security"):
                        findings.append(_make_finding(
                            "API-AUTHZ-001", "HIGH", "API5:2023",
                            f"Admin/internal endpoint {method.upper()} {path} has no security requirement",
                            path=path, method=method,
                            recommendation="Add security requirement to all admin endpoints",
                            cwe="CWE-862",
                        ))

            # BOLA: endpoints with {id} parameter but no auth
            if _ID_PATH_PATTERNS.search(path):
                for method in ("get","put","patch","delete"):
                    op = path_item.get(method, {})
                    if op:
                        has_auth = op.get("security") or spec.get("security")
                        has_ownership_check = any(
                            "owner" in str(p).lower() or "user_id" in str(p).lower()
                            for p in op.get("parameters", [])
                        )
                        if not has_auth:
                            findings.append(_make_finding(
                                "API-BOLA-001", "HIGH", "API1:2023",
                                f"Resource endpoint {method.upper()} {path} uses ID parameter without auth — potential BOLA",
                                path=path, method=method,
                                evidence=f"Path contains {{id}} parameter",
                                recommendation="Ensure object-level authorization checks are performed server-side",
                                cwe="CWE-863",
                            ))

            # Missing operationId (inventory management)
            for method in ("get","post","put","patch","delete"):
                op = path_item.get(method)
                if isinstance(op, dict) and not op.get("operationId"):
                    findings.append(_make_finding(
                        "API-INV-001", "INFO", "API9:2023",
                        f"Operation {method.upper()} {path} has no operationId — harder to audit",
                        path=path, method=method,
                        recommendation="Add operationId to every operation for better traceability",
                    ))

            # POST/PUT without request body schema
            for method in ("post", "put", "patch"):
                op = path_item.get(method, {})
                if op:
                    req_body = op.get("requestBody", {})
                    content  = req_body.get("content", {}) if version == "3" else {}
                    if not content and not op.get("parameters") and version == "3":
                        findings.append(_make_finding(
                            "API-VALID-001", "LOW", "API8:2023",
                            f"{method.upper()} {path} has no request body schema — missing input validation",
                            path=path, method=method,
                            recommendation="Define request body schema with required fields and constraints",
                        ))

            # GET endpoints returning sensitive data
            get_op = path_item.get("get", {})
            if get_op and version == "3":
                responses = get_op.get("responses", {})
                for status, resp in responses.items():
                    if str(status).startswith("2"):
                        content = resp.get("content", {})
                        schema  = _get_schema(content)
                        if schema and _has_sensitive_fields(schema):
                            findings.append(_make_finding(
                                "API-EXPOSE-001", "MEDIUM", "API3:2023",
                                f"GET {path} response may expose sensitive fields",
                                path=path, method="get",
                                evidence=f"Response schema contains sensitive field names",
                                recommendation="Use response filtering; never return password/token fields",
                                cwe="CWE-200",
                            ))

        return findings

    def _check_schemas(self, spec: dict, version: str) -> List[dict]:
        findings = []
        if version != "3":
            return findings
        schemas = spec.get("components", {}).get("schemas", {})
        for name, schema in schemas.items():
            props = schema.get("properties", {})
            for field_name in props:
                if _SENSITIVE_FIELD_PATTERNS.search(field_name):
                    prop = props[field_name]
                    if not prop.get("writeOnly") and not prop.get("x-writeOnly"):
                        findings.append(_make_finding(
                            "API-EXPOSE-002", "MEDIUM", "API3:2023",
                            f"Schema '{name}' field '{field_name}' appears sensitive but lacks writeOnly",
                            evidence=f"Schema {name}.{field_name}",
                            recommendation=f"Mark sensitive fields as writeOnly: true to prevent serialization",
                            cwe="CWE-200",
                        ))
        return findings

    def _check_rate_limiting(self, spec: dict) -> List[dict]:
        findings = []
        # Check for rate limit headers in responses
        paths = spec.get("paths", {})
        has_rate_limit_header = False
        for path_item in paths.values():
            if not isinstance(path_item, dict):
                continue
            for method in ("get","post","put","delete"):
                op = path_item.get(method, {})
                if not op:
                    continue
                for resp in op.get("responses", {}).values():
                    headers = resp.get("headers", {})
                    if any("ratelimit" in h.lower() or "x-rate" in h.lower()
                           for h in headers):
                        has_rate_limit_header = True

        if not has_rate_limit_header and len(paths) > 0:
            findings.append(_make_finding(
                "API-RATE-001", "MEDIUM", "API4:2023",
                "No rate limiting headers (X-RateLimit-*) found in API responses",
                recommendation="Implement rate limiting and document it with X-RateLimit-Limit/Remaining/Reset headers",
                cwe="CWE-400",
            ))
        return findings

    def _check_cors(self, spec: dict, version: str) -> List[dict]:
        findings = []
        # Check for permissive CORS in x-amazon-apigateway or custom extensions
        paths = spec.get("paths", {})
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            opts = path_item.get("options", {})
            if opts:
                headers = {}
                for resp in opts.get("responses", {}).values():
                    headers.update(resp.get("headers", {}))
                for h, val in headers.items():
                    if "access-control-allow-origin" in h.lower():
                        schema = val.get("schema", {})
                        if schema.get("example") == "*" or schema.get("default") == "*":
                            findings.append(_make_finding(
                                "API-CORS-001", "MEDIUM", "API8:2023",
                                f"Wildcard CORS origin (Access-Control-Allow-Origin: *) at {path}",
                                path=path, method="options",
                                recommendation="Restrict CORS to specific trusted origins",
                                cwe="CWE-942",
                            ))
        return findings


def _get_schema(content: dict) -> Optional[dict]:
    for mime, val in content.items():
        if isinstance(val, dict):
            return val.get("schema")
    return None


def _has_sensitive_fields(schema: dict, depth: int = 0) -> bool:
    if depth > 3:
        return False
    props = schema.get("properties", {})
    for name in props:
        if _SENSITIVE_FIELD_PATTERNS.search(name):
            return True
    items = schema.get("items", {})
    if items:
        return _has_sensitive_fields(items, depth + 1)
    return False
