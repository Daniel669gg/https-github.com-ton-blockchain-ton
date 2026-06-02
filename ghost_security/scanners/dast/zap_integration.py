"""
TythanAI DAST — OWASP ZAP Integration Layer

Full integration with a running OWASP ZAP daemon via its REST API.
Supports: Passive Scan, Active Scan, Spider, AJAX Spider, OpenAPI import,
          Authentication: Form, HTTP Basic, Bearer Token, Cookie Session.

Requirements:
  ZAP daemon running before scan:
  docker run -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable \
    zap.sh -daemon -port 8080 -host 0.0.0.0 -config api.addrs.addr.name=.* \
            -config api.addrs.addr.enabled=true -config api.key=<your-key>
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


# ── Enumerations ──────────────────────────────────────────────────────────────

class AuthMethod(Enum):
    NONE   = "none"
    FORM   = "formBasedAuthentication"
    BASIC  = "httpAuthentication"
    BEARER = "bearerToken"
    COOKIE = "cookieAuthentication"


class ScanType(Enum):
    PASSIVE = "passive"
    ACTIVE  = "active"
    SPIDER  = "spider"
    AJAX    = "ajax_spider"
    API     = "api"


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class ZAPAuthConfig:
    method:         AuthMethod = AuthMethod.NONE
    login_url:      str = ""
    username:       str = ""
    password:       str = ""
    token:          str = ""
    username_field: str = "username"
    password_field: str = "password"
    cookie_name:    str = ""
    cookie_value:   str = ""


@dataclass
class ZAPScanConfig:
    target_url:      str
    zap_api_url:     str           = "http://localhost:8080"
    api_key:         str           = ""
    auth:            ZAPAuthConfig = field(default_factory=ZAPAuthConfig)
    scan_types:      List[ScanType] = field(
        default_factory=lambda: [ScanType.SPIDER, ScanType.PASSIVE, ScanType.ACTIVE]
    )
    openapi_url:     str = ""
    openapi_file:    str = ""
    max_scan_time:   int = 300      # seconds per scan phase
    spider_depth:    int = 5
    active_strength: str = "DEFAULT"  # LOW | DEFAULT | HIGH | INSANE


@dataclass
class ZAPFinding:
    alert_id:   str
    name:       str
    description: str
    risk:       str          # High | Medium | Low | Informational
    confidence: str          # High | Medium | Low | User Confirmed
    url:        str
    method:     str
    evidence:   str
    solution:   str
    reference:  str
    cwe_id:     str
    wasc_id:    str
    param:      str
    attack:     str
    other:      str
    plugin_id:  str


@dataclass
class ZAPScanResult:
    target:         str
    scan_id:        str
    scan_types_run: List[str]
    findings:       List[ZAPFinding]
    urls_scanned:   int
    alerts_by_risk: Dict[str, int]
    duration_s:     float
    error:          Optional[str] = None


# ── Conversion tables ─────────────────────────────────────────────────────────

_RISK_TO_SEVERITY: Dict[str, str] = {
    "High":          "HIGH",
    "Medium":        "MEDIUM",
    "Low":           "LOW",
    "Informational": "INFO",
}

_CONFIDENCE_TO_SCORE: Dict[str, float] = {
    "User Confirmed": 0.95,
    "High":           0.85,
    "Medium":         0.65,
    "Low":            0.40,
}

# ZAP plug-in ID → CWE mapping for common alerts
_PLUGIN_CWE: Dict[str, str] = {
    "10202": "CWE-79",   # XSS
    "10105": "CWE-116",  # HTTPS to HTTP redirect
    "10036": "CWE-693",  # CSP header missing
    "10098": "CWE-942",  # CORS
    "10037": "CWE-693",  # Server leaks info via X-Powered-By
    "10028": "CWE-693",  # Open redirect
    "40018": "CWE-89",   # SQL injection
    "90020": "CWE-78",   # Command injection
    "40003": "CWE-352",  # CSRF
    "10010": "CWE-1021", # X-Frame-Options missing
    "10016": "CWE-693",  # Web browser XSS protection not set
    "10021": "CWE-693",  # X-Content-Type missing
    "10035": "CWE-319",  # Strict-Transport-Security header missing
    "10096": "CWE-16",   # Timestamp disclosure
    "10094": "CWE-200",  # Base64 disclosure
    "10040": "CWE-548",  # Secure pages include mixed content
}


# ── ZAP REST API Client ───────────────────────────────────────────────────────

class ZAPClient:
    """
    Thin ZAP REST API client using only Python stdlib urllib.
    No python-owasp-zap-v2.4 dependency required.
    All ZAP endpoints return JSON with envelope {Result: OK} or {alerts:[...]}.
    """

    def __init__(self, zap_url: str = "http://localhost:8080", api_key: str = ""):
        self._base = zap_url.rstrip("/")
        self._key  = api_key

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _get(self, path: str, params: Optional[Dict[str, str]] = None) -> dict:
        p: Dict[str, str] = dict(params or {})
        if self._key:
            p["apikey"] = self._key
        qs = ("?" + urllib.parse.urlencode(p)) if p else ""
        url = f"{self._base}{path}{qs}"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode("utf-8"))

    def _post(self, path: str, data: Optional[Dict[str, str]] = None) -> dict:
        d: Dict[str, str] = dict(data or {})
        if self._key:
            d["apikey"] = self._key
        payload = urllib.parse.urlencode(d).encode()
        req = urllib.request.Request(
            f"{self._base}{path}",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode("utf-8"))

    # ── Health ────────────────────────────────────────────────────────────────

    def is_alive(self) -> bool:
        try:
            self._get("/JSON/core/view/version/")
            return True
        except Exception:
            return False

    def get_version(self) -> str:
        try:
            return self._get("/JSON/core/view/version/").get("version", "unknown")
        except Exception:
            return "unreachable"

    # ── Session ───────────────────────────────────────────────────────────────

    def new_session(self, name: str = "tythan_scan") -> bool:
        try:
            r = self._post("/JSON/core/action/newSession/",
                           {"name": name, "overwrite": "true"})
            return r.get("Result") == "OK"
        except Exception:
            return False

    # ── Context ───────────────────────────────────────────────────────────────

    def create_context(self, name: str = "tythan_ctx") -> str:
        r = self._post("/JSON/context/action/newContext/", {"contextName": name})
        return str(r.get("contextId", "1"))

    def include_in_context(self, ctx_id: str, regex: str) -> None:
        self._post("/JSON/context/action/includeInContext/",
                   {"contextId": ctx_id, "regex": regex})

    def set_context_in_scope(self, ctx_id: str) -> None:
        self._post("/JSON/context/action/setContextInScope/",
                   {"contextId": ctx_id, "booleanInScope": "true"})

    # ── OpenAPI Import ────────────────────────────────────────────────────────

    def import_openapi_url(self, spec_url: str, target: str = "") -> dict:
        params: Dict[str, str] = {"url": spec_url}
        if target:
            params["target"] = target
        return self._post("/JSON/openapi/action/importUrl/", params)

    def import_openapi_file(self, file_path: str, target: str = "") -> dict:
        params: Dict[str, str] = {"file": file_path}
        if target:
            params["target"] = target
        return self._post("/JSON/openapi/action/importFile/", params)

    # ── Authentication ────────────────────────────────────────────────────────

    def set_form_auth(self, ctx_id: str, login_url: str,
                      username_field: str, password_field: str) -> None:
        login_data = f"{username_field}={{%25username%25}}&{password_field}={{%25password%25}}"
        self._post("/JSON/authentication/action/setAuthenticationMethod/", {
            "contextId":                ctx_id,
            "authMethodName":           "formBasedAuthentication",
            "authMethodConfigParams": (
                f"loginUrl={urllib.parse.quote(login_url, safe='')}"
                f"&loginRequestData={login_data}"
            ),
        })

    def add_user(self, ctx_id: str, username: str, password: str) -> str:
        r = self._post("/JSON/users/action/newUser/",
                       {"contextId": ctx_id, "name": username})
        user_id = str(r.get("userId", "0"))
        creds = (
            f"username={urllib.parse.quote(username, safe='')}"
            f"&password={urllib.parse.quote(password, safe='')}"
        )
        self._post("/JSON/users/action/setAuthenticationCredentials/", {
            "contextId":                    ctx_id,
            "userId":                       user_id,
            "authCredentialsConfigParams":  creds,
        })
        self._post("/JSON/users/action/setUserEnabled/",
                   {"contextId": ctx_id, "userId": user_id, "enabled": "true"})
        return user_id

    def set_forced_user(self, ctx_id: str, user_id: str) -> None:
        self._post("/JSON/forcedUser/action/setForcedUser/",
                   {"contextId": ctx_id, "userId": user_id})
        self._post("/JSON/forcedUser/action/setForcedUserModeEnabled/",
                   {"boolean": "true"})

    def set_bearer_token(self, token: str) -> None:
        """Inject Authorization: Bearer <token> into all outgoing requests."""
        self._post("/JSON/replacer/action/addRule/", {
            "description": "Bearer auth header",
            "enabled":     "true",
            "matchType":   "REQ_HEADER",
            "matchRegex":  "false",
            "matchString": "Authorization",
            "initiators":  "",
            "replacement": f"Bearer {token}",
        })

    def set_cookie_session(self, cookie_name: str, cookie_value: str) -> None:
        """Inject session cookie into all outgoing requests."""
        self._post("/JSON/replacer/action/addRule/", {
            "description": f"Session cookie {cookie_name}",
            "enabled":     "true",
            "matchType":   "REQ_HEADER",
            "matchRegex":  "false",
            "matchString": "Cookie",
            "initiators":  "",
            "replacement": f"{cookie_name}={cookie_value}",
        })

    # ── Spider ────────────────────────────────────────────────────────────────

    def start_spider(self, url: str, ctx_id: str = "", max_depth: int = 5) -> str:
        params: Dict[str, str] = {
            "url":      url,
            "maxDepth": str(max_depth),
            "recurse":  "true",
        }
        if ctx_id:
            params["contextName"] = ctx_id
        r = self._post("/JSON/spider/action/scan/", params)
        return str(r.get("scan", "0"))

    def spider_progress(self, scan_id: str) -> int:
        r = self._get("/JSON/spider/view/status/", {"scanId": scan_id})
        return int(r.get("status", "0"))

    def spider_results(self, scan_id: str) -> List[str]:
        r = self._get("/JSON/spider/view/results/", {"scanId": scan_id})
        return r.get("results", [])

    def start_ajax_spider(self, url: str) -> None:
        self._post("/JSON/ajaxSpider/action/scan/", {"url": url, "inScope": "false"})

    def ajax_spider_status(self) -> str:
        r = self._get("/JSON/ajaxSpider/view/status/")
        return r.get("status", "stopped")

    # ── Passive scan ─────────────────────────────────────────────────────────

    def passive_scan_queue(self) -> int:
        r = self._get("/JSON/pscan/view/recordsToScan/")
        return int(r.get("recordsToScan", "0"))

    def wait_passive_scan(self, timeout: int = 120) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.passive_scan_queue() == 0:
                return
            time.sleep(2)

    # ── Active scan ───────────────────────────────────────────────────────────

    def start_active_scan(self, url: str, ctx_id: str = "",
                          strength: str = "DEFAULT") -> str:
        params: Dict[str, str] = {
            "url":     url,
            "recurse": "true",
        }
        if ctx_id:
            params["contextId"] = ctx_id
        r = self._post("/JSON/ascan/action/scan/", params)
        scan_id = str(r.get("scan", "0"))
        # Set attack strength after initiating
        if strength != "DEFAULT":
            try:
                self._post("/JSON/ascan/action/setScannerAttackStrength/",
                           {"id": scan_id, "attackStrength": strength})
            except Exception:
                pass
        return scan_id

    def active_scan_progress(self, scan_id: str) -> int:
        r = self._get("/JSON/ascan/view/status/", {"scanId": scan_id})
        return int(r.get("status", "0"))

    def wait_active_scan(self, scan_id: str, timeout: int = 300) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.active_scan_progress(scan_id) >= 100:
                return
            time.sleep(3)

    # ── Alerts ────────────────────────────────────────────────────────────────

    def get_alerts(self, base_url: str = "", start: int = 0,
                   count: int = 5000) -> List[dict]:
        params: Dict[str, str] = {"start": str(start), "count": str(count)}
        if base_url:
            params["baseurl"] = base_url
        r = self._get("/JSON/core/view/alerts/", params)
        return r.get("alerts", [])

    def get_urls(self) -> List[str]:
        r = self._get("/JSON/core/view/urls/")
        return r.get("urls", [])

    def get_hosts(self) -> List[str]:
        r = self._get("/JSON/core/view/hosts/")
        return r.get("hosts", [])


# ── ZAP Scan Orchestrator ─────────────────────────────────────────────────────

class ZAPScanner:
    """
    Orchestrates a full DAST scan through OWASP ZAP.

    Phase sequence:
      1. New session  → 2. Context + scope  → 3. OpenAPI import (optional)
      → 4. Auth setup  → 5. Spider  → 6. AJAX spider (optional)
      → 7. Passive scan  → 8. Active scan  → 9. Collect + convert alerts
    """

    def __init__(self, config: ZAPScanConfig):
        self._cfg    = config
        self._client = ZAPClient(config.zap_api_url, config.api_key)

    def check_zap_available(self) -> Tuple[bool, str]:
        if self._client.is_alive():
            return True, self._client.get_version()
        return False, (
            f"ZAP not reachable at {self._cfg.zap_api_url}. "
            "Start ZAP with: docker run -p 8080:8080 ghcr.io/zaproxy/zaproxy:stable "
            "zap.sh -daemon -port 8080 -host 0.0.0.0 -config api.addrs.addr.name=.* "
            "-config api.addrs.addr.enabled=true"
        )

    def scan(self) -> ZAPScanResult:
        t0 = time.time()
        ok, info = self.check_zap_available()
        if not ok:
            return ZAPScanResult(
                target=self._cfg.target_url,
                scan_id="",
                scan_types_run=[],
                findings=[],
                urls_scanned=0,
                alerts_by_risk={},
                duration_s=0.0,
                error=info,
            )

        self._client.new_session(f"tythan_{int(t0)}")

        ctx_id = self._client.create_context()
        self._client.include_in_context(ctx_id,
                                        self._cfg.target_url.rstrip("/") + ".*")
        self._client.set_context_in_scope(ctx_id)

        # OpenAPI import
        if self._cfg.openapi_url:
            self._client.import_openapi_url(self._cfg.openapi_url,
                                            self._cfg.target_url)
        elif self._cfg.openapi_file:
            self._client.import_openapi_file(self._cfg.openapi_file,
                                             self._cfg.target_url)

        # Auth configuration
        self._configure_auth(ctx_id)

        # Execute phases
        scan_types_run: List[str] = []

        if ScanType.SPIDER in self._cfg.scan_types:
            sid = self._client.start_spider(
                self._cfg.target_url, ctx_id, self._cfg.spider_depth,
            )
            self._poll(lambda: self._client.spider_progress(sid),
                       self._cfg.max_scan_time)
            scan_types_run.append("spider")

        if ScanType.AJAX in self._cfg.scan_types:
            self._client.start_ajax_spider(self._cfg.target_url)
            deadline = time.time() + min(self._cfg.max_scan_time, 120)
            while time.time() < deadline:
                if self._client.ajax_spider_status() == "stopped":
                    break
                time.sleep(3)
            scan_types_run.append("ajax_spider")

        if ScanType.PASSIVE in self._cfg.scan_types:
            self._client.wait_passive_scan(self._cfg.max_scan_time)
            scan_types_run.append("passive")

        if ScanType.ACTIVE in self._cfg.scan_types:
            asid = self._client.start_active_scan(
                self._cfg.target_url, ctx_id, self._cfg.active_strength,
            )
            self._client.wait_active_scan(asid, self._cfg.max_scan_time)
            scan_types_run.append("active")

        raw_alerts = self._client.get_alerts(self._cfg.target_url)
        findings   = [self._convert_alert(a) for a in raw_alerts]
        urls       = self._client.get_urls()

        alerts_by_risk: Dict[str, int] = {}
        for f in findings:
            alerts_by_risk[f.risk] = alerts_by_risk.get(f.risk, 0) + 1

        return ZAPScanResult(
            target=self._cfg.target_url,
            scan_id=str(int(t0)),
            scan_types_run=scan_types_run,
            findings=findings,
            urls_scanned=len(urls),
            alerts_by_risk=alerts_by_risk,
            duration_s=time.time() - t0,
        )

    def _configure_auth(self, ctx_id: str) -> None:
        auth = self._cfg.auth
        if auth.method == AuthMethod.FORM and auth.login_url:
            self._client.set_form_auth(
                ctx_id, auth.login_url,
                auth.username_field, auth.password_field,
            )
            if auth.username:
                uid = self._client.add_user(ctx_id, auth.username, auth.password)
                self._client.set_forced_user(ctx_id, uid)
        elif auth.method == AuthMethod.BEARER and auth.token:
            self._client.set_bearer_token(auth.token)
        elif auth.method == AuthMethod.COOKIE and auth.cookie_name:
            self._client.set_cookie_session(auth.cookie_name, auth.cookie_value)

    @staticmethod
    def _poll(progress_fn, timeout: int) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if progress_fn() >= 100:
                return
            time.sleep(3)

    @staticmethod
    def _convert_alert(alert: dict) -> ZAPFinding:
        plugin_id = str(alert.get("pluginId", ""))
        cwe_raw   = str(alert.get("cweid", ""))
        # Normalise to "CWE-NNN" or fall back to plugin lookup
        if cwe_raw and cwe_raw.isdigit() and cwe_raw != "0":
            cwe_id = f"CWE-{cwe_raw}"
        elif cwe_raw and cwe_raw.upper().startswith("CWE-"):
            cwe_id = cwe_raw.upper()
        else:
            cwe_id = _PLUGIN_CWE.get(plugin_id, "")
        return ZAPFinding(
            alert_id=str(alert.get("id", "")),
            name=alert.get("alert", alert.get("name", "")),
            description=alert.get("description", ""),
            risk=alert.get("risk", "Informational"),
            confidence=alert.get("confidence", "Low"),
            url=alert.get("url", ""),
            method=alert.get("method", "GET"),
            evidence=(alert.get("evidence", "") or "")[:500],
            solution=alert.get("solution", ""),
            reference=alert.get("reference", ""),
            cwe_id=cwe_id,
            wasc_id=str(alert.get("wascid", "")),
            param=alert.get("param", ""),
            attack=(alert.get("attack", "") or "")[:200],
            other=(alert.get("other", "") or "")[:200],
            plugin_id=plugin_id,
        )

    def to_normalized_findings(self, result: ZAPScanResult) -> List[dict]:
        """Convert ZAPFinding list to TythanAI internal finding format."""
        out: List[dict] = []
        for f in result.findings:
            cid = f.cwe_id or ""
            cwe = cid if cid.upper().startswith("CWE-") else \
                  (f"CWE-{cid}" if cid.isdigit() else cid)
            conf_pct  = int(_CONFIDENCE_TO_SCORE.get(f.confidence, 0.5) * 100)
            out.append({
                "type":              "DAST_FINDING",
                "source":            "zap_scanner",
                "severity":          _RISK_TO_SEVERITY.get(f.risk, "INFO"),
                "rule_id":           f"ZAP-{f.plugin_id}" if f.plugin_id else "ZAP-UNKNOWN",
                "title":             f.name,
                "description":       f.description,
                "evidence":          f.evidence or f"{f.method} {f.url}",
                "recommendation":    f.solution,
                "cwe":               cwe,
                "file":              "",
                "line":              0,
                "url":               f.url,
                "method":            f.method,
                "param":             f.param,
                "attack":            f.attack,
                "confidence":        conf_pct,
                "runtime_verified":  True,
                "category":          "DAST",
                "tags":              ["dast", "zap", f.risk.lower()],
                "references":        [f.reference] if f.reference else [],
            })
        return out
