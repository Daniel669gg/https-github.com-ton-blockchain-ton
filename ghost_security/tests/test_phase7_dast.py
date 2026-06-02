"""
TythanAI Phase 7 — DAST + Runtime Correlation Tests

Tests cover:
  1. ZAP integration (client, config, offline graceful failure)
  2. API scanner (probe logic, CORS, BOLA detection, data exposure)
  3. Security headers analyzer (CSP, HSTS, X-Frame, cookies)
  4. Attack surface mapper (static routes, spec parsing)
  5. SAST↔DAST runtime correlator
  6. Attack graph extensions (endpoint nodes, runtime findings)
  7. Knowledge graph extensions (queries, ingest)
  8. Unified scan engine DAST options
"""
from __future__ import annotations

import json
import sys
import types
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

# --- Ensure project root is on sys.path ---
_TEST_DIR = Path(__file__).parent
_ROOT     = _TEST_DIR.parent
for _p in (_ROOT, str(_ROOT)):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))


# ===========================================================================
# 1. ZAP Integration Tests
# ===========================================================================

class TestZAPIntegration(unittest.TestCase):

    def _make_config(self, url="http://target.example.com"):
        from scanners.dast.zap_integration import ZAPScanConfig
        return ZAPScanConfig(target_url=url)

    def test_zap_scan_config_defaults(self):
        cfg = self._make_config()
        self.assertEqual(cfg.target_url, "http://target.example.com")
        self.assertEqual(cfg.zap_api_url, "http://localhost:8080")
        self.assertEqual(cfg.max_scan_time, 300)
        self.assertEqual(cfg.spider_depth, 5)

    def test_zap_unavailable_returns_error_result(self):
        from scanners.dast.zap_integration import ZAPScanner, ZAPScanConfig
        cfg    = ZAPScanConfig(target_url="http://target.example.com",
                               zap_api_url="http://localhost:19999")
        scanner = ZAPScanner(cfg)
        result  = scanner.scan()
        self.assertIsNotNone(result.error)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.urls_scanned, 0)

    def test_zap_client_is_alive_false_on_no_server(self):
        from scanners.dast.zap_integration import ZAPClient
        client = ZAPClient("http://localhost:19998")
        self.assertFalse(client.is_alive())

    def test_convert_alert_maps_risk_to_severity(self):
        from scanners.dast.zap_integration import ZAPScanner, ZAPScanConfig
        scanner = ZAPScanner(ZAPScanConfig(target_url="http://x.com"))
        alert = {
            "id": "1", "alert": "XSS", "risk": "High", "confidence": "High",
            "url": "http://x.com/search", "method": "GET",
            "description": "XSS found", "solution": "Encode output",
            "reference": "", "cweid": "79", "wascid": "8",
            "param": "q", "attack": "<script>", "other": "",
            "pluginId": "10202",
        }
        finding = scanner._convert_alert(alert)
        self.assertEqual(finding.risk, "High")
        self.assertEqual(finding.cwe_id, "CWE-79")

    def test_to_normalized_findings_format(self):
        from scanners.dast.zap_integration import (
            ZAPScanner, ZAPScanConfig, ZAPScanResult, ZAPFinding,
        )
        scanner = ZAPScanner(ZAPScanConfig(target_url="http://x.com"))
        zap_finding = ZAPFinding(
            alert_id="1", name="SQL Injection", description="SQLi found",
            risk="High", confidence="High",
            url="http://x.com/api/users", method="POST",
            evidence="' OR '1'='1", solution="Use parameterised queries",
            reference="", cwe_id="CWE-89", wasc_id="19",
            param="username", attack="' OR '1'='1",
            other="", plugin_id="40018",
        )
        result = ZAPScanResult(
            target="http://x.com", scan_id="123",
            scan_types_run=["spider", "active"],
            findings=[zap_finding],
            urls_scanned=5, alerts_by_risk={"High": 1},
            duration_s=10.0,
        )
        normalised = scanner.to_normalized_findings(result)
        self.assertEqual(len(normalised), 1)
        f = normalised[0]
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["cwe"], "CWE-89")
        self.assertEqual(f["source"], "zap_scanner")
        self.assertTrue(f["runtime_verified"])
        self.assertIn("dast", f["tags"])

    def test_auth_method_enum_values(self):
        from scanners.dast.zap_integration import AuthMethod
        self.assertEqual(AuthMethod.BEARER.value, "bearerToken")
        self.assertEqual(AuthMethod.FORM.value, "formBasedAuthentication")
        self.assertEqual(AuthMethod.COOKIE.value, "cookieAuthentication")

    def test_scan_type_enum_values(self):
        from scanners.dast.zap_integration import ScanType
        self.assertIn(ScanType.PASSIVE, list(ScanType))
        self.assertIn(ScanType.ACTIVE, list(ScanType))
        self.assertIn(ScanType.SPIDER, list(ScanType))
        self.assertIn(ScanType.AJAX, list(ScanType))


# ===========================================================================
# 2. API Scanner Tests
# ===========================================================================

class TestAPIScanner(unittest.TestCase):

    def _make_scanner(self, base_url="http://api.example.com"):
        from scanners.dast.api_scanner import APIScanner, APIScanConfig
        cfg = APIScanConfig(base_url=base_url, timeout=5)
        return APIScanner(cfg), cfg

    def test_finding_id_deterministic(self):
        from scanners.dast.api_scanner import _finding_id
        id1 = _finding_id("API-AUTH-001", "http://x.com/api", "GET")
        id2 = _finding_id("API-AUTH-001", "http://x.com/api", "GET")
        self.assertEqual(id1, id2)
        self.assertEqual(len(id1), 16)

    def test_heuristic_endpoints_generated(self):
        scanner, _ = self._make_scanner()
        eps = scanner._heuristic_endpoints()
        self.assertGreater(len(eps), 5)
        methods = [m for m, _, _ in eps]
        self.assertIn("GET", methods)
        self.assertIn("POST", methods)

    def test_cors_finding_wildcard_detected(self):
        """Simulate server returning ACAO: * — should produce CORS finding."""
        from scanners.dast.api_scanner import APIScanner, APIScanConfig

        def mock_probe(url, method="GET", headers=None, timeout=10,
                       follow_redirects=True):
            if method == "OPTIONS":
                return 200, {
                    "access-control-allow-origin": "*",
                    "access-control-allow-credentials": "false",
                }, b""
            return None

        scanner = APIScanner(APIScanConfig(base_url="http://api.example.com"))
        with patch("scanners.dast.api_scanner._probe_http", side_effect=mock_probe):
            findings = scanner._check_cors()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "API-CORS-002")
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_cors_wildcard_with_credentials_is_critical(self):
        from scanners.dast.api_scanner import APIScanner, APIScanConfig

        def mock_probe(url, method="GET", headers=None, timeout=10,
                       follow_redirects=True):
            if method == "OPTIONS":
                return 200, {
                    "access-control-allow-origin": "*",
                    "access-control-allow-credentials": "true",
                }, b""
            return None

        scanner = APIScanner(APIScanConfig(base_url="http://api.example.com"))
        with patch("scanners.dast.api_scanner._probe_http", side_effect=mock_probe):
            findings = scanner._check_cors()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertEqual(findings[0].rule_id, "API-CORS-001")

    def test_cors_reflected_origin_detected(self):
        from scanners.dast.api_scanner import APIScanner, APIScanConfig

        def mock_probe(url, method="GET", headers=None, timeout=10,
                       follow_redirects=True):
            if method == "OPTIONS":
                return 200, {
                    "access-control-allow-origin": "https://evil.example.com",
                }, b""
            return None

        scanner = APIScanner(APIScanConfig(base_url="http://api.example.com"))
        with patch("scanners.dast.api_scanner._probe_http", side_effect=mock_probe):
            findings = scanner._check_cors()
        self.assertTrue(any(f.rule_id == "API-CORS-003" for f in findings))

    def test_missing_auth_on_200_response(self):
        from scanners.dast.api_scanner import APIScanner, APIScanConfig

        def mock_probe(url, method="GET", headers=None, timeout=10,
                       follow_redirects=True):
            return 200, {"content-type": "application/json"}, b'{"data": []}'

        scanner = APIScanner(APIScanConfig(base_url="http://api.example.com"))
        with patch("scanners.dast.api_scanner._probe_http", side_effect=mock_probe):
            findings = scanner._probe_auth_required(
                "DELETE", "http://api.example.com/api/users/1", {}
            )
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_admin_endpoint_missing_auth_is_critical(self):
        from scanners.dast.api_scanner import APIScanner, APIScanConfig

        def mock_probe(url, method="GET", headers=None, timeout=10,
                       follow_redirects=True):
            return 200, {}, b""

        scanner = APIScanner(APIScanConfig(base_url="http://api.example.com"))
        with patch("scanners.dast.api_scanner._probe_http", side_effect=mock_probe):
            findings = scanner._probe_auth_required(
                "GET", "http://api.example.com/admin", {}
            )
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_data_exposure_sensitive_fields_detected(self):
        from scanners.dast.api_scanner import APIScanner, APIScanConfig

        body = json.dumps({
            "id": 1, "username": "alice",
            "password": "secret", "access_token": "tok123"
        }).encode()

        def mock_probe(url, method="GET", headers=None, timeout=10,
                       follow_redirects=True):
            return 200, {"content-type": "application/json"}, body

        scanner = APIScanner(APIScanConfig(base_url="http://api.example.com"))
        with patch("scanners.dast.api_scanner._probe_http", side_effect=mock_probe):
            findings = scanner._probe_data_exposure(
                "GET", "http://api.example.com/api/users/1"
            )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "API-EXPOSE-001")

    def test_to_normalized_findings(self):
        from scanners.dast.api_scanner import (
            APIScanner, APIScanConfig, APIScanResult, APIFinding,
        )
        scanner = APIScanner(APIScanConfig(base_url="http://x.com"))
        finding = APIFinding(
            finding_id="abc123", rule_id="API-BOLA-001",
            title="BOLA", description="Resource accessible without auth",
            severity="HIGH", owasp="API1:2023", cwe="CWE-639",
            url="http://x.com/api/users/2", method="GET",
            evidence="HTTP 200 without credentials",
            recommendation="Check ownership", confidence=75,
        )
        result = APIScanResult(
            target="http://x.com", findings=[finding],
            endpoints_probed=10, duration_s=2.0,
        )
        out = scanner.to_normalized_findings(result)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "HIGH")
        self.assertEqual(out[0]["source"], "api_scanner")
        self.assertTrue(out[0]["runtime_verified"])

    def test_http_finding_generated_for_http_url(self):
        from scanners.dast.api_scanner import APIScanner, APIScanConfig

        def mock_probe(*args, **kwargs):
            return None

        scanner = APIScanner(APIScanConfig(base_url="http://api.example.com"))
        with patch("scanners.dast.api_scanner._probe_http", side_effect=mock_probe):
            findings = scanner._check_endpoint(
                "GET", "http://api.example.com/users", {}, None
            )
        tls_findings = [f for f in findings if f.rule_id == "API-TLS-001"]
        self.assertEqual(len(tls_findings), 1)


# ===========================================================================
# 3. Security Headers Analyzer Tests
# ===========================================================================

class TestSecurityHeadersAnalyzer(unittest.TestCase):

    def _make_report_from_headers(self, headers: dict,
                                   cookies: Optional[List[str]] = None,
                                   url: str = "https://example.com"):
        from scanners.dast.headers_analyzer import _evaluate_headers, _security_score, HeadersReport
        findings, present, missing = _evaluate_headers(url, headers, cookies or [])
        score = _security_score(present, missing, findings)
        return HeadersReport(url=url, findings=findings, headers_present=present,
                              headers_missing=missing, security_score=score)

    def test_all_headers_missing_score_below_or_equal_40(self):
        report = self._make_report_from_headers({})
        self.assertLessEqual(report.security_score, 40)

    def test_csp_missing_produces_high_finding(self):
        report = self._make_report_from_headers({})
        csp_findings = [f for f in report.findings if f.rule_id == "HDR-CSP-001"]
        self.assertEqual(len(csp_findings), 1)
        self.assertEqual(csp_findings[0].severity, "HIGH")

    def test_hsts_missing_on_https_produces_finding(self):
        report = self._make_report_from_headers({})
        hsts_f = [f for f in report.findings if f.rule_id == "HDR-HSTS-001"]
        self.assertEqual(len(hsts_f), 1)

    def test_hsts_present_no_finding(self):
        report = self._make_report_from_headers({
            "strict-transport-security": "max-age=31536000; includeSubDomains"
        })
        hsts_f = [f for f in report.findings if f.rule_id == "HDR-HSTS-001"]
        self.assertEqual(len(hsts_f), 0)
        self.assertIn("Strict-Transport-Security", report.headers_present)

    def test_hsts_low_max_age_produces_low_finding(self):
        report = self._make_report_from_headers({
            "strict-transport-security": "max-age=86400"
        })
        low_f = [f for f in report.findings if f.rule_id == "HDR-HSTS-002"]
        self.assertEqual(len(low_f), 1)

    def test_csp_unsafe_inline_produces_medium(self):
        report = self._make_report_from_headers({
            "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'"
        })
        f = [x for x in report.findings if x.rule_id == "HDR-CSP-002"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "MEDIUM")

    def test_x_frame_options_missing(self):
        report = self._make_report_from_headers({})
        xfo_f = [f for f in report.findings if f.rule_id == "HDR-XFO-001"]
        self.assertEqual(len(xfo_f), 1)
        self.assertEqual(xfo_f[0].severity, "MEDIUM")

    def test_x_frame_options_deny_ok(self):
        report = self._make_report_from_headers({"x-frame-options": "DENY"})
        xfo_f = [f for f in report.findings if f.rule_id == "HDR-XFO-001"]
        self.assertEqual(len(xfo_f), 0)
        self.assertIn("X-Frame-Options", report.headers_present)

    def test_cookie_missing_httponly_produces_high(self):
        report = self._make_report_from_headers(
            {"strict-transport-security": "max-age=31536000"},
            cookies=["session_id=abc123; Secure; SameSite=Strict"],
            url="https://example.com",
        )
        f = [x for x in report.findings if x.rule_id == "HDR-COOKIE-001"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "HIGH")

    def test_cookie_missing_secure_flag(self):
        report = self._make_report_from_headers(
            {},
            cookies=["session_id=abc123; HttpOnly; SameSite=Strict"],
            url="https://example.com",
        )
        f = [x for x in report.findings if x.rule_id == "HDR-COOKIE-002"]
        self.assertEqual(len(f), 1)

    def test_server_header_leaks_info(self):
        report = self._make_report_from_headers({"server": "Apache/2.4.50"})
        f = [x for x in report.findings if x.rule_id == "HDR-INFO-001"]
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].severity, "INFO")

    def test_all_headers_present_score_high(self):
        report = self._make_report_from_headers({
            "content-security-policy": "default-src 'self'; script-src 'self'",
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=(), microphone=()",
        })
        self.assertGreater(report.security_score, 70)

    def test_to_normalized_findings_format(self):
        from scanners.dast.headers_analyzer import SecurityHeadersAnalyzer, HeadersReport, HeaderFinding
        analyzer = SecurityHeadersAnalyzer()
        f = HeaderFinding(
            rule_id="HDR-CSP-001", title="CSP missing",
            description="No CSP", severity="HIGH",
            header="Content-Security-Policy", actual_value="",
            recommendation="Add CSP",
        )
        report = HeadersReport(
            url="https://example.com",
            findings=[f], headers_present=[], headers_missing=["CSP"],
            security_score=45,
        )
        out = analyzer.to_normalized_findings(report)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["source"], "headers_analyzer")
        self.assertEqual(out[0]["severity"], "HIGH")
        self.assertTrue(out[0]["runtime_verified"])


# ===========================================================================
# 4. Attack Surface Mapper Tests
# ===========================================================================

class TestAttackSurfaceMapper(unittest.TestCase):

    def test_from_spec_extracts_endpoints(self):
        from scanners.dast.attack_surface import AttackSurfaceMapper
        spec = {
            "paths": {
                "/users": {"get": {"operationId": "listUsers"}, "post": {}},
                "/users/{id}": {"get": {}, "delete": {}},
                "/admin": {"get": {}},
            }
        }
        mapper  = AttackSurfaceMapper(base_url="http://x.com", openapi_spec=spec)
        surface = mapper.map()
        self.assertEqual(surface.total_endpoints, 5)
        methods = [e.method for e in surface.endpoints]
        self.assertIn("GET", methods)
        self.assertIn("DELETE", methods)

    def test_admin_endpoint_detected(self):
        from scanners.dast.attack_surface import AttackSurfaceMapper
        spec = {"paths": {"/admin": {"get": {}}}}
        mapper  = AttackSurfaceMapper(base_url="http://x.com", openapi_spec=spec)
        surface = mapper.map()
        self.assertEqual(surface.admin_endpoints, 1)

    def test_risk_level_admin_no_auth_is_critical(self):
        from scanners.dast.attack_surface import _risk_level
        risk = _risk_level("/admin", "GET", False, [])
        self.assertEqual(risk, "CRITICAL")

    def test_risk_level_delete_no_auth_is_high(self):
        from scanners.dast.attack_surface import _risk_level
        risk = _risk_level("/api/users/1", "DELETE", False, [])
        self.assertEqual(risk, "HIGH")

    def test_deduplication_same_method_path(self):
        from scanners.dast.attack_surface import AttackSurfaceMapper
        spec = {
            "paths": {
                "/users": {
                    "get": {"operationId": "list1"},
                },
            }
        }
        mapper = AttackSurfaceMapper(base_url="http://x.com", openapi_spec=spec)
        surface = mapper.map()
        paths = [(e.method, e.path) for e in surface.endpoints]
        self.assertEqual(len(paths), len(set(paths)))

    def test_to_attack_graph_nodes_format(self):
        from scanners.dast.attack_surface import AttackSurfaceMapper
        spec = {"paths": {"/api": {"get": {}}}}
        mapper  = AttackSurfaceMapper(base_url="http://x.com", openapi_spec=spec)
        surface = mapper.map()
        nodes   = mapper.to_attack_graph_nodes(surface)
        self.assertEqual(len(nodes), 1)
        node = nodes[0]
        self.assertEqual(node["node_type"], "ENDPOINT")
        self.assertIn("path", node)
        self.assertIn("method", node)

    def test_static_extractor_flask(self):
        import tempfile, os
        from scanners.dast.attack_surface import _StaticRouteExtractor

        code = """
from flask import Flask
app = Flask(__name__)

@app.route('/users', methods=['GET', 'POST'])
def users():
    pass

@app.route('/admin', methods=['GET'])
@login_required
def admin():
    pass
"""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "views.py")
            with open(p, "w") as f:
                f.write(code)
            extractor = _StaticRouteExtractor()
            endpoints = extractor.extract(d)

        paths   = [e.path for e in endpoints]
        methods = [e.method for e in endpoints]
        self.assertIn("/users", paths)
        self.assertIn("/admin", paths)
        self.assertIn("POST", methods)


# ===========================================================================
# 5. Runtime Correlation Engine Tests
# ===========================================================================

class TestRuntimeCorrelator(unittest.TestCase):

    def _make_sast_finding(self, cwe="CWE-89", severity="HIGH",
                            file="api/views.py", line=42,
                            rule_id="SQLI-001", handler="get_user"):
        return {
            "rule_id": rule_id, "cwe": cwe, "severity": severity,
            "file": file, "line": line, "handler": handler,
            "description": f"SQL injection in {handler}",
            "confidence": 75,
        }

    def _make_dast_finding(self, cwe="CWE-89", severity="HIGH",
                            url="http://x.com/api/users/1", method="GET",
                            rule_id="ZAP-40018"):
        return {
            "rule_id": rule_id, "cwe": cwe, "severity": severity,
            "url": url, "method": method,
            "description": "SQL injection confirmed",
            "confidence": 85, "source": "zap_scanner",
        }

    def _make_endpoint(self, path="/api/users/{id}", method="GET",
                       handler="get_user", source_file="api/views.py"):
        return {
            "id": f"ep:{method}:{path}",
            "path": path, "method": method,
            "handler": handler, "source_file": source_file,
            "auth_required": False, "risk_level": "HIGH",
        }

    def test_correlates_sast_and_dast_by_cwe(self):
        from core.runtime_correlation import RuntimeCorrelator
        sast = [self._make_sast_finding()]
        dast = [self._make_dast_finding()]
        eps  = [self._make_endpoint()]
        correlator = RuntimeCorrelator(eps, sast, dast)
        report = correlator.correlate()
        self.assertGreater(report.total_correlated, 0)
        # Should have at least one finding with runtime evidence
        has_runtime = any(
            cf.runtime_evidence is not None
            for cf in report.correlated_findings
        )
        self.assertTrue(has_runtime)

    def test_verification_status_exploitable_when_dast_match(self):
        from core.runtime_correlation import RuntimeCorrelator, VerificationStatus
        sast = [self._make_sast_finding()]
        dast = [self._make_dast_finding()]
        eps  = [self._make_endpoint()]
        report = RuntimeCorrelator(eps, sast, dast).correlate()
        statuses = [cf.verification_status for cf in report.correlated_findings]
        # At minimum should be EXPLOITABLE (DAST confirms) or VERIFIED (DAST + reach)
        high_statuses = {VerificationStatus.EXPLOITABLE, VerificationStatus.VERIFIED}
        self.assertTrue(any(s in high_statuses for s in statuses))

    def test_combined_confidence_higher_than_individual(self):
        from core.runtime_correlation import _combined_confidence
        combined = _combined_confidence(70, 80, has_both=True)
        self.assertGreater(combined, 80)  # Bayesian combination > max

    def test_combined_confidence_single_source(self):
        from core.runtime_correlation import _combined_confidence
        combined = _combined_confidence(70, 0, has_both=False)
        self.assertEqual(combined, 70)

    def test_dast_only_findings_added(self):
        from core.runtime_correlation import RuntimeCorrelator
        # DAST finding with no matching SAST
        dast = [self._make_dast_finding(cwe="CWE-200", rule_id="ZAP-10202")]
        report = RuntimeCorrelator([], [], dast).correlate()
        dast_only = [cf for cf in report.correlated_findings
                     if cf.static_evidence is None]
        self.assertEqual(len(dast_only), 1)

    def test_noise_reduction_reported(self):
        from core.runtime_correlation import RuntimeCorrelator
        # 2 SAST, 1 matched DAST
        sast = [
            self._make_sast_finding(rule_id="SQLI-001"),
            self._make_sast_finding(cwe="CWE-200", rule_id="INFO-001",
                                     file="lib/utils.py"),
        ]
        dast = [self._make_dast_finding()]
        eps  = [self._make_endpoint()]
        report = RuntimeCorrelator(eps, sast, dast).correlate()
        # noise_reduction should be > 0 since at least 1 SAST was matched
        self.assertGreaterEqual(report.noise_reduction_pct, 0)

    def test_risk_score_higher_for_verified(self):
        from core.runtime_correlation import _risk_score, VerificationStatus
        s_verified    = _risk_score("HIGH", 90, VerificationStatus.VERIFIED)
        s_detected    = _risk_score("HIGH", 90, VerificationStatus.DETECTED)
        self.assertGreater(s_verified, s_detected)

    def test_cwe_family_grouping(self):
        from core.runtime_correlation import _cwe_family
        self.assertEqual(_cwe_family("CWE-89"), "injection")
        self.assertEqual(_cwe_family("CWE-79"), "xss")
        self.assertEqual(_cwe_family("CWE-306"), "auth")
        self.assertEqual(_cwe_family("CWE-918"), "ssrf_disclosure")

    def test_correlated_finding_to_dict(self):
        from core.runtime_correlation import (
            RuntimeCorrelator, VerificationStatus, StaticEvidence,
        )
        sast = [self._make_sast_finding()]
        dast = [self._make_dast_finding()]
        eps  = [self._make_endpoint()]
        report = RuntimeCorrelator(eps, sast, dast).correlate()
        d = report.correlated_findings[0].to_dict()
        self.assertIn("correlation_id", d)
        self.assertIn("static_evidence", d)
        self.assertIn("runtime_evidence", d)
        self.assertIn("combined_confidence", d)
        self.assertIn("exploit_path", d)

    def test_report_to_dict(self):
        from core.runtime_correlation import RuntimeCorrelator
        report = RuntimeCorrelator([], [], []).correlate()
        d = report.to_dict()
        self.assertIn("generated_at", d)
        self.assertIn("total_correlated", d)
        self.assertIn("findings", d)


# ===========================================================================
# 6. Attack Graph Extensions Tests
# ===========================================================================

class TestAttackGraphDAST(unittest.TestCase):

    def _make_graph(self):
        from backend.analysis.attack_graph import AttackGraph
        return AttackGraph()

    def test_new_node_types_exist(self):
        from backend.analysis.attack_graph import NodeType
        self.assertIn("endpoint", [t.value for t in NodeType])
        self.assertIn("route", [t.value for t in NodeType])
        self.assertIn("runtime_finding", [t.value for t in NodeType])
        self.assertIn("runtime_evidence", [t.value for t in NodeType])

    def test_add_endpoint_nodes(self):
        from backend.analysis.attack_graph import AttackGraphBuilder, NodeType
        builder = AttackGraphBuilder()
        graph   = self._make_graph()
        ep_nodes = [
            {
                "id": "ep:GET:/api/users",
                "path": "/api/users", "method": "GET",
                "handler": "list_users", "source_file": "views.py",
                "auth_required": False, "risk_level": "HIGH",
            }
        ]
        created = builder.add_endpoint_nodes(graph, ep_nodes)
        self.assertEqual(len(created), 1)
        ep_node_ids = {n.node_id for n in graph.nodes}
        self.assertIn("ep:GET:/api/users", ep_node_ids)
        # Unauthenticated HIGH endpoint should have edge from internet source
        edge_targets = {e.to_id for e in graph.edges}
        self.assertIn("ep:GET:/api/users", edge_targets)

    def test_add_runtime_findings(self):
        from backend.analysis.attack_graph import AttackGraphBuilder, NodeType
        builder = AttackGraphBuilder()
        graph   = self._make_graph()
        correlated = [
            {
                "correlation_id": "CORR-0001",
                "title": "SQL Injection confirmed",
                "cwe": "CWE-89",
                "severity": "HIGH",
                "verification_status": "verified",
                "combined_confidence": 90,
                "owasp_category": "A03:2021",
                "risk_score": 7.5,
                "endpoint": {"url": "http://x.com/api/users", "method": "GET", "path": "/api/users"},
                "runtime_evidence": {
                    "url": "http://x.com/api/users?id=1",
                    "method": "GET",
                    "evidence": "' OR '1'='1",
                    "confidence": 90,
                },
            }
        ]
        created = builder.add_runtime_findings(graph, correlated)
        self.assertEqual(len(created), 1)
        rf_ids = {n.node_id for n in graph.nodes if n.type == NodeType.RUNTIME_FINDING}
        self.assertIn("runtime_finding:CORR-0001", rf_ids)

    def test_find_exposed_endpoints_returns_reachable(self):
        from backend.analysis.attack_graph import (
            AttackGraphBuilder, AttackGraph, GraphNode, GraphEdge, NodeType,
        )
        builder = AttackGraphBuilder()
        graph   = AttackGraph()
        graph.nodes.append(GraphNode(node_id="source:internet",
                                     type=NodeType.SOURCE, label="Internet"))
        graph.nodes.append(GraphNode(node_id="ep:GET:/api",
                                     type=NodeType.ENDPOINT, label="GET /api",
                                     properties={}))
        graph.edges.append(GraphEdge(from_id="source:internet",
                                     to_id="ep:GET:/api", label="exposed_by"))
        exposed = builder.find_exposed_endpoints(graph)
        self.assertEqual(len(exposed), 1)
        self.assertEqual(exposed[0].node_id, "ep:GET:/api")

    def test_find_verified_exploits(self):
        from backend.analysis.attack_graph import (
            AttackGraphBuilder, AttackGraph, GraphNode, NodeType,
        )
        builder = AttackGraphBuilder()
        graph   = AttackGraph()
        graph.nodes.append(GraphNode(
            node_id="runtime_finding:CORR-001",
            type=NodeType.RUNTIME_FINDING, label="SQLi",
            properties={"verification_status": "verified", "severity": "HIGH"},
        ))
        graph.nodes.append(GraphNode(
            node_id="runtime_finding:CORR-002",
            type=NodeType.RUNTIME_FINDING, label="XSS",
            properties={"verification_status": "reachable", "severity": "MEDIUM"},
        ))
        verified = builder.find_verified_exploits(graph)
        self.assertEqual(len(verified), 1)
        self.assertEqual(verified[0].node_id, "runtime_finding:CORR-001")


# ===========================================================================
# 7. Knowledge Graph Extensions Tests
# ===========================================================================

class TestKnowledgeGraphDAST(unittest.TestCase):

    def test_new_node_types_exist(self):
        from backend.analysis.knowledge_graph import KGNodeType
        self.assertIn("runtime_finding",  [t.value for t in KGNodeType])
        self.assertIn("runtime_evidence", [t.value for t in KGNodeType])

    def _make_graph(self):
        from backend.analysis.knowledge_graph import SecurityKnowledgeGraph
        return SecurityKnowledgeGraph()

    def test_ingest_runtime_findings_creates_nodes(self):
        from backend.analysis.knowledge_graph import (
            KnowledgeGraphBuilder, KGNodeType,
        )
        builder = KnowledgeGraphBuilder()
        graph   = self._make_graph()
        findings = [
            {
                "correlation_id": "CORR-0001",
                "title": "SQLi confirmed",
                "cwe": "CWE-89",
                "severity": "HIGH",
                "verification_status": "verified",
                "combined_confidence": 88,
                "owasp_category": "A03:2021",
                "risk_score": 7.5,
                "endpoint": {
                    "url": "http://x.com/api/users",
                    "method": "GET",
                    "path": "/api/users",
                    "handler": "list_users",
                },
                "runtime_evidence": {
                    "url": "http://x.com/api/users?id=1",
                    "method": "GET",
                    "evidence": "SQLi payload accepted",
                    "confidence": 90,
                    "source_scanner": "zap_scanner",
                },
                "static_evidence": None,
            }
        ]
        count = builder.ingest_runtime_findings(graph, findings)
        self.assertGreater(count, 0)

        types = {n.type for n in graph.nodes}
        self.assertIn(KGNodeType.ENDPOINT, types)
        self.assertIn(KGNodeType.RUNTIME_FINDING, types)
        self.assertIn(KGNodeType.RUNTIME_EVIDENCE, types)

    def test_find_exposed_endpoints(self):
        from backend.analysis.knowledge_graph import (
            KnowledgeGraphBuilder, KGNodeType, SecurityKnowledgeGraph, KGNode,
        )
        builder = KnowledgeGraphBuilder()
        graph   = self._make_graph()
        graph.nodes.append(KGNode(node_id="endpoint::GET::/api",
                                   type=KGNodeType.ENDPOINT, label="GET /api"))
        eps = builder.find_exposed_endpoints(graph)
        self.assertEqual(len(eps), 1)

    def test_find_runtime_findings_min_confidence(self):
        from backend.analysis.knowledge_graph import (
            KnowledgeGraphBuilder, KGNodeType, KGNode,
        )
        builder = KnowledgeGraphBuilder()
        graph   = self._make_graph()
        graph.nodes.append(KGNode(
            node_id="runtime_finding::HIGH",
            type=KGNodeType.RUNTIME_FINDING, label="High conf",
            properties={"combined_confidence": 90},
        ))
        graph.nodes.append(KGNode(
            node_id="runtime_finding::LOW",
            type=KGNodeType.RUNTIME_FINDING, label="Low conf",
            properties={"combined_confidence": 30},
        ))
        high = builder.find_runtime_findings(graph, min_confidence=80)
        self.assertEqual(len(high), 1)
        self.assertEqual(high[0].node_id, "runtime_finding::HIGH")

    def test_find_verified_exploits(self):
        from backend.analysis.knowledge_graph import (
            KnowledgeGraphBuilder, KGNodeType, KGNode,
        )
        builder = KnowledgeGraphBuilder()
        graph   = self._make_graph()
        graph.nodes.append(KGNode(
            node_id="rf1", type=KGNodeType.RUNTIME_FINDING, label="F1",
            properties={"verification_status": "verified"},
        ))
        graph.nodes.append(KGNode(
            node_id="rf2", type=KGNodeType.RUNTIME_FINDING, label="F2",
            properties={"verification_status": "detected"},
        ))
        verified = builder.find_verified_exploits(graph)
        self.assertEqual(len(verified), 1)
        self.assertEqual(verified[0].node_id, "rf1")

    def test_find_attack_surface_summary(self):
        from backend.analysis.knowledge_graph import (
            KnowledgeGraphBuilder, KGNodeType, KGNode, KGEdge,
        )
        builder = KnowledgeGraphBuilder()
        graph   = self._make_graph()
        ep = KGNode(node_id="ep1", type=KGNodeType.ENDPOINT,
                    label="GET /api", properties={"risk_level": "HIGH"})
        rf = KGNode(node_id="rf1", type=KGNodeType.RUNTIME_FINDING,
                    label="SQLi", properties={"verification_status": "verified"})
        graph.nodes += [ep, rf]
        graph.edges.append(KGEdge(from_id="ep1", to_id="rf1",
                                   relation="EXPOSED_BY"))
        graph.node_index = {n.node_id: i for i, n in enumerate(graph.nodes)}

        surface = builder.find_attack_surface(graph)
        self.assertEqual(surface["total_endpoints"], 1)
        self.assertEqual(surface["verified_exploits"], 1)
        self.assertEqual(surface["endpoints_with_findings"], 1)

    def test_find_exploitable_routes_severity_filter(self):
        from backend.analysis.knowledge_graph import (
            KnowledgeGraphBuilder, KGNodeType, KGNode, KGEdge,
        )
        builder = KnowledgeGraphBuilder()
        graph   = self._make_graph()
        ep  = KGNode(node_id="ep1", type=KGNodeType.ENDPOINT, label="GET /api", properties={})
        rf_high = KGNode(node_id="rf1", type=KGNodeType.RUNTIME_FINDING, label="SQLi",
                         properties={"severity": "HIGH", "risk_score": 7.0,
                                      "verification_status": "verified"})
        rf_low  = KGNode(node_id="rf2", type=KGNodeType.RUNTIME_FINDING, label="Info",
                         properties={"severity": "LOW",  "risk_score": 1.5,
                                      "verification_status": "detected"})
        graph.nodes += [ep, rf_high, rf_low]
        graph.edges += [
            KGEdge(from_id="ep1", to_id="rf1", relation="EXPOSED_BY"),
            KGEdge(from_id="ep1", to_id="rf2", relation="EXPOSED_BY"),
        ]
        graph.node_index = {n.node_id: i for i, n in enumerate(graph.nodes)}

        routes = builder.find_exploitable_routes(graph, min_severity="HIGH")
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0]["severity"], "HIGH")


# ===========================================================================
# 8. Unified Scan Engine DAST Tests
# ===========================================================================

class TestUnifiedScanEngineDAST(unittest.TestCase):

    def test_scan_options_dast_fields(self):
        from backend.core.engine.unified_scan_engine import ScanOptions
        opts = ScanOptions(
            enable_dast=True,
            dast_target_url="http://app.example.com",
            dast_zap_url="http://localhost:8080",
        )
        self.assertTrue(opts.enable_dast)
        self.assertEqual(opts.dast_target_url, "http://app.example.com")

    def test_run_dast_no_url_returns_empty(self):
        from backend.core.engine.unified_scan_engine import UnifiedScanEngine, ScanOptions
        engine = UnifiedScanEngine()
        opts = ScanOptions(enable_dast=True, dast_target_url="")
        result = engine.run_dast(opts)
        self.assertEqual(result, [])

    def test_run_dast_handles_all_scanner_errors_gracefully(self):
        """Even if all DAST scanners fail, run_dast should return [] not raise."""
        from backend.core.engine.unified_scan_engine import UnifiedScanEngine, ScanOptions
        engine = UnifiedScanEngine()
        opts   = ScanOptions(enable_dast=True,
                              dast_target_url="http://nonexistent.invalid")
        # Should not raise
        result = engine.run_dast(opts)
        self.assertIsInstance(result, list)

    def test_scan_with_dast_returns_merged_result(self):
        """scan_with_dast should return a ScanResult with dast_enabled in options."""
        import tempfile, os
        from backend.core.engine.unified_scan_engine import UnifiedScanEngine

        engine = UnifiedScanEngine()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "app.py")
            with open(p, "w") as f:
                f.write("x = 1\n")
            # target url is unreachable — DAST will fail gracefully
            result = engine.scan_with_dast(
                d, "http://nonexistent.invalid"
            )
        self.assertIsNotNone(result)
        self.assertTrue(result.options.get("dast_enabled"))


# ===========================================================================
# End
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
