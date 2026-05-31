"""
TythanAI — Adversarial Simulator (defensive only)
Tests own FastAPI endpoints with adversarial inputs to verify Pydantic validation.
ONLY runs in ENV=test or ENV=staging. Does not exploit real vulnerabilities.
"""
from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("ghost.adversarial_simulator")

# ---------------------------------------------------------------------------
# Payload libraries
# ---------------------------------------------------------------------------

SQL_INJECTION_PAYLOADS: List[str] = [
    "' OR '1'='1",
    "'; DROP TABLE users--",
    "' UNION SELECT 1,2,3--",
    "1' AND SLEEP(5)--",
    "admin'--",
    "' OR 1=1#",
    "'; EXEC xp_cmdshell('dir')--",
]

XSS_PAYLOADS: List[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg/onload=alert(1)>",
    "';alert(1)//",
    "<iframe src=javascript:alert(1)>",
    '"onmouseover="alert(1)',
]

OVERSIZED_INPUTS: List[Any] = [
    "A" * 10_000,
    "B" * 100_000,
    "C" * 1_000_000,   # 1 MB+
    "\x00" * 1_000,    # null bytes
    "\n" * 10_000,     # newline flood
]

MALFORMED_JSON: List[str] = [
    "{invalid}",
    "{{nested: {}",
    "[1,2,3",
    '{"key": undefined}',
    '{"key": NaN}',
    "null",
    "undefined",
    "",
    "{}",
]

BOUNDARY_VALUES: List[Any] = [
    -1,
    0,
    -2_147_483_648,
    2_147_483_647,
    9_999_999_999,
    None,
    True,
    False,
    [],
    {},
    float("inf"),
]

PATH_TRAVERSAL_PAYLOADS: List[str] = [
    "../../../etc/passwd",
    "..\\..\\windows\\system32",
    "%2e%2e%2f%2e%2e%2f",
    "....//....//etc/passwd",
]

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

_PAYLOAD_TYPE_SQL = "sql_injection"
_PAYLOAD_TYPE_XSS = "xss"
_PAYLOAD_TYPE_OVERSIZED = "oversized"
_PAYLOAD_TYPE_MALFORMED_JSON = "malformed_json"
_PAYLOAD_TYPE_BOUNDARY = "boundary"
_PAYLOAD_TYPE_PATH_TRAVERSAL = "path_traversal"


class AdversarialTestResult(BaseModel):
    """Result of a single adversarial test against one endpoint."""

    endpoint: str
    method: str
    payload_type: str        # e.g. "sql_injection"
    payload: str             # repr of the payload used
    status_code: int
    expected_codes: List[int] = Field(default_factory=lambda: [400, 422, 403])
    passed: bool             # True if status_code in expected_codes
    response_snippet: str    # first 200 chars of response body
    notes: str = ""


class SimulationReport(BaseModel):
    """Aggregated result of an adversarial simulation run."""

    simulation_id: str
    run_at: str
    environment: str
    endpoints_tested: int
    total_tests: int
    passed: int
    failed: int
    failure_rate: float
    failures: List[AdversarialTestResult] = Field(default_factory=list)
    all_results: List[AdversarialTestResult] = Field(default_factory=list)

    def to_markdown(self) -> str:
        lines: List[str] = [
            "# Adversarial Simulation Report",
            "",
            f"**Simulation ID:** `{self.simulation_id}`",
            f"**Run At:** {self.run_at}",
            f"**Environment:** {self.environment}",
            "",
            "## Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Endpoints tested | {self.endpoints_tested} |",
            f"| Total tests | {self.total_tests} |",
            f"| Passed | {self.passed} |",
            f"| Failed | {self.failed} |",
            f"| Failure rate | {self.failure_rate:.1f}% |",
            "",
        ]
        if self.failures:
            lines += [
                "## Failures",
                "",
                "| Endpoint | Method | Payload type | Status code | Notes |",
                "|----------|--------|-------------|-------------|-------|",
            ]
            for r in self.failures:
                lines.append(
                    f"| `{r.endpoint}` | {r.method} | {r.payload_type} "
                    f"| {r.status_code} | {r.notes} |"
                )
            lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# AdversarialSimulator
# ---------------------------------------------------------------------------


class AdversarialSimulator:
    """
    Runs adversarial input tests against own FastAPI endpoints to verify
    that Pydantic validation correctly rejects malformed / malicious payloads.

    Safety constraints:
    - Only runs in ENV=test or ENV=staging (default: test when unset).
    - Never contacts external systems.
    - All HTTP calls are wrapped in try/except — never raises.
    """

    # Endpoints to probe and the field to inject payloads into
    _DEFAULT_ENDPOINTS: List[Dict[str, Any]] = [
        {"path": "/api/v2/scan/taint", "method": "POST", "body_key": "path"},
        {"path": "/api/v2/scan/supply-chain", "method": "POST", "body_key": "path"},
        {"path": "/api/v2/audit/full", "method": "POST", "body_key": "path"},
    ]

    # Codes that indicate validation worked correctly
    _VALID_REJECTION_CODES: List[int] = [400, 422, 403, 404]

    def __init__(
        self,
        app: Any = None,
        base_url: str = "http://testserver",
    ) -> None:
        self._app = app
        self._base_url = base_url.rstrip("/")
        self._client: Any = None  # lazily built

    # ── Environment guard ─────────────────────────────────────────────────────

    def _check_environment(self) -> bool:
        """Return True only when ENV is 'test' or 'staging' (case-insensitive).
        When ENV is not set, default to True (safe for CI).
        """
        env_value = os.environ.get("ENV", "test").lower().strip()
        return env_value in ("test", "staging")

    # ── HTTP client construction ──────────────────────────────────────────────

    def _build_test_client(self, app: Any) -> Any:
        """Build a synchronous test client for the given ASGI app."""
        try:
            from starlette.testclient import TestClient  # type: ignore

            return TestClient(app, raise_server_exceptions=False)
        except ImportError:
            pass
        try:
            import httpx  # type: ignore

            return httpx.Client(app=app, base_url=self._base_url)
        except ImportError:
            pass
        return None

    def _get_client(self, app: Any = None) -> Any:
        """Return a cached client instance, building one if necessary."""
        if self._client is not None:
            return self._client

        target_app = app or self._app
        if target_app is not None:
            self._client = self._build_test_client(target_app)
            return self._client

        # No ASGI app — fall back to a plain requests Session
        try:
            import requests  # type: ignore

            session = requests.Session()
            self._client = session
            return self._client
        except ImportError:
            return None

    # ── Single endpoint test ──────────────────────────────────────────────────

    def test_endpoint(
        self,
        endpoint: str,
        method: str,
        payload: Any,
        payload_type: str,
        expected_codes: Optional[List[int]] = None,
    ) -> AdversarialTestResult:
        """
        Send a single adversarial request to *endpoint* and return the result.

        Never raises — connection errors are returned as status_code=0.
        """
        if expected_codes is None:
            expected_codes = list(self._VALID_REJECTION_CODES)

        payload_repr = repr(payload)[:300]
        url = f"{self._base_url}{endpoint}"

        status_code = 0
        response_snippet = ""
        notes = ""

        client = self._get_client()

        if client is None:
            return AdversarialTestResult(
                endpoint=endpoint,
                method=method,
                payload_type=payload_type,
                payload=payload_repr,
                status_code=0,
                expected_codes=expected_codes,
                passed=False,
                response_snippet="",
                notes="No HTTP client available.",
            )

        try:
            if isinstance(payload, dict):
                body = payload
            elif isinstance(payload, str):
                body = {"path": payload}
            else:
                body = {"path": repr(payload)}

            # Try requests-style first, then httpx, then starlette testclient
            http_method = method.upper()

            if hasattr(client, "request"):
                # requests.Session / httpx.Client
                resp = client.request(
                    http_method,
                    url,
                    json=body,
                    timeout=5,
                )
                status_code = resp.status_code
                try:
                    response_snippet = resp.text[:200]
                except Exception:
                    response_snippet = ""
            else:
                # starlette TestClient
                resp = getattr(client, http_method.lower())(
                    endpoint,
                    json=body,
                )
                status_code = resp.status_code
                try:
                    response_snippet = resp.text[:200]
                except Exception:
                    response_snippet = ""

        except Exception as exc:
            status_code = 0
            notes = f"connection error: {type(exc).__name__}: {exc}"
            logger.debug("Adversarial test connection error (%s %s): %s", method, endpoint, exc)

        # Verdict: 400/422/403/404 → validation worked ✅
        # 500 → server error ❌  (validation failed, unhandled exception)
        # 200 → potentially missing validation ❌
        passed = status_code in expected_codes

        if not passed and not notes:
            if status_code == 500:
                notes = "Server returned 500 — validation likely absent."
            elif status_code == 200:
                notes = "Server returned 200 — payload may have bypassed validation."
            elif status_code == 0:
                notes = "No response received (server not running or unreachable)."
            else:
                notes = f"Unexpected status code {status_code}."

        return AdversarialTestResult(
            endpoint=endpoint,
            method=method,
            payload_type=payload_type,
            payload=payload_repr,
            status_code=status_code,
            expected_codes=expected_codes,
            passed=passed,
            response_snippet=response_snippet,
            notes=notes,
        )

    # ── Bulk run ──────────────────────────────────────────────────────────────

    def run(
        self,
        app: Any = None,
        endpoints: Optional[List[str]] = None,
    ) -> SimulationReport:
        """
        Run all adversarial tests against the configured endpoints.

        If *app* is provided, a TestClient is used; otherwise requests are made
        to ``self._base_url``.  Returns an empty report when the environment
        check fails.
        """
        simulation_id = str(uuid.uuid4())
        run_at = datetime.now(timezone.utc).isoformat()
        environment = os.environ.get("ENV", "test")

        if not self._check_environment():
            logger.warning(
                "AdversarialSimulator: skipped — ENV=%s is not test/staging", environment
            )
            return SimulationReport(
                simulation_id=simulation_id,
                run_at=run_at,
                environment=environment,
                endpoints_tested=0,
                total_tests=0,
                passed=0,
                failed=0,
                failure_rate=0.0,
                failures=[],
                all_results=[],
            )

        # Re-build the client for the provided app if given
        if app is not None:
            self._app = app
            self._client = None  # force rebuild

        # Resolve endpoint specs
        endpoint_specs = []
        if endpoints:
            for ep in endpoints:
                endpoint_specs.append({"path": ep, "method": "POST", "body_key": "path"})
        else:
            endpoint_specs = list(self._DEFAULT_ENDPOINTS)

        # Payload catalogue: (payload_type, iterable of payloads)
        payload_catalogue: List[tuple] = [
            (_PAYLOAD_TYPE_SQL, SQL_INJECTION_PAYLOADS),
            (_PAYLOAD_TYPE_XSS, XSS_PAYLOADS),
            (_PAYLOAD_TYPE_OVERSIZED, [s for s in OVERSIZED_INPUTS if isinstance(s, str)]),
            (_PAYLOAD_TYPE_PATH_TRAVERSAL, PATH_TRAVERSAL_PAYLOADS),
            # Boundary and malformed are passed directly as the path field
            (_PAYLOAD_TYPE_BOUNDARY, [repr(v) for v in BOUNDARY_VALUES]),
        ]

        all_results: List[AdversarialTestResult] = []
        endpoints_set: set = set()

        for spec in endpoint_specs:
            ep_path: str = spec["path"]
            ep_method: str = spec["method"]
            endpoints_set.add(ep_path)

            for ptype, payloads in payload_catalogue:
                for payload in payloads:
                    result = self.test_endpoint(
                        endpoint=ep_path,
                        method=ep_method,
                        payload=payload,
                        payload_type=ptype,
                        expected_codes=list(self._VALID_REJECTION_CODES),
                    )
                    all_results.append(result)

            # Malformed JSON is sent as a raw string body (not wrapped in dict)
            for mjson in MALFORMED_JSON:
                result = self._test_raw_body(
                    endpoint=ep_path,
                    method=ep_method,
                    raw_body=mjson,
                    payload_type=_PAYLOAD_TYPE_MALFORMED_JSON,
                )
                all_results.append(result)

        passed = sum(1 for r in all_results if r.passed)
        failed = len(all_results) - passed
        failure_rate = (failed / max(1, len(all_results))) * 100.0
        failures = [r for r in all_results if not r.passed]

        return SimulationReport(
            simulation_id=simulation_id,
            run_at=run_at,
            environment=environment,
            endpoints_tested=len(endpoints_set),
            total_tests=len(all_results),
            passed=passed,
            failed=failed,
            failure_rate=round(failure_rate, 2),
            failures=failures,
            all_results=all_results,
        )

    def _test_raw_body(
        self,
        endpoint: str,
        method: str,
        raw_body: str,
        payload_type: str,
    ) -> AdversarialTestResult:
        """Send *raw_body* as-is in the HTTP request body (Content-Type: application/json)."""
        url = f"{self._base_url}{endpoint}"
        status_code = 0
        response_snippet = ""
        notes = ""
        expected_codes = list(self._VALID_REJECTION_CODES)

        client = self._get_client()
        if client is None:
            return AdversarialTestResult(
                endpoint=endpoint,
                method=method,
                payload_type=payload_type,
                payload=repr(raw_body)[:300],
                status_code=0,
                expected_codes=expected_codes,
                passed=False,
                response_snippet="",
                notes="No HTTP client available.",
            )

        try:
            raw_bytes = raw_body.encode("utf-8", errors="replace")
            http_method = method.upper()

            if hasattr(client, "request"):
                import requests as _req  # type: ignore

                resp = client.request(
                    http_method,
                    url,
                    data=raw_bytes,
                    headers={"Content-Type": "application/json"},
                    timeout=5,
                )
                status_code = resp.status_code
                response_snippet = resp.text[:200]
            else:
                # starlette TestClient: pass content as bytes
                resp = getattr(client, http_method.lower())(
                    endpoint,
                    content=raw_bytes,
                    headers={"Content-Type": "application/json"},
                )
                status_code = resp.status_code
                try:
                    response_snippet = resp.text[:200]
                except Exception:
                    response_snippet = ""

        except Exception as exc:
            status_code = 0
            notes = f"connection error: {type(exc).__name__}: {exc}"

        passed = status_code in expected_codes

        if not passed and not notes:
            if status_code == 500:
                notes = "Server returned 500 — malformed JSON not caught."
            elif status_code == 200:
                notes = "Server returned 200 — malformed JSON accepted."
            elif status_code == 0:
                notes = "No response (server not running or unreachable)."
            else:
                notes = f"Unexpected status code {status_code}."

        return AdversarialTestResult(
            endpoint=endpoint,
            method=method,
            payload_type=payload_type,
            payload=repr(raw_body)[:300],
            status_code=status_code,
            expected_codes=expected_codes,
            passed=passed,
            response_snippet=response_snippet,
            notes=notes,
        )

    def run_without_app(
        self,
        base_url: str = "http://localhost:8000",
    ) -> SimulationReport:
        """
        Make real HTTP requests to a running server at *base_url*.

        Useful for integration tests when the server is already running.
        """
        # Create a fresh simulator pointed at the live base URL
        live_sim = AdversarialSimulator(app=None, base_url=base_url)
        return live_sim.run()


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------


def run_adversarial_tests(app: Any = None) -> SimulationReport:
    """Convenience wrapper: run adversarial tests against *app* (or localhost)."""
    simulator = AdversarialSimulator(app=app)
    return simulator.run(app=app)


# ---------------------------------------------------------------------------
# Self-test (python -m backend.agents.adversarial_simulator)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    # Test 1: _check_environment returns True when ENV=test
    os.environ["ENV"] = "test"
    sim = AdversarialSimulator()
    assert sim._check_environment() is True, "_check_environment should return True for ENV=test"

    # Test 2: _check_environment returns False for ENV=production
    os.environ["ENV"] = "production"
    assert sim._check_environment() is False, "_check_environment should return False for ENV=production"
    os.environ["ENV"] = "test"

    # Test 3: test_endpoint with no server → status_code=0, passed=False
    sim2 = AdversarialSimulator(app=None, base_url="http://localhost:19999")
    result = sim2.test_endpoint(
        endpoint="/api/v2/scan/taint",
        method="POST",
        payload="' OR 1=1--",
        payload_type="sql_injection",
    )
    assert result.status_code == 0, f"Expected status_code=0, got {result.status_code}"
    assert result.passed is False, "Expected passed=False when no server"

    # Test 4: SimulationReport correctly counts passed/failed
    r1 = AdversarialTestResult(
        endpoint="/ep", method="POST", payload_type="sql_injection",
        payload="x", status_code=422, expected_codes=[400, 422],
        passed=True, response_snippet="", notes="",
    )
    r2 = AdversarialTestResult(
        endpoint="/ep", method="POST", payload_type="xss",
        payload="y", status_code=200, expected_codes=[400, 422],
        passed=False, response_snippet="", notes="",
    )
    report = SimulationReport(
        simulation_id="test", run_at="now", environment="test",
        endpoints_tested=1, total_tests=2,
        passed=1, failed=1,
        failure_rate=50.0,
        failures=[r2],
        all_results=[r1, r2],
    )
    assert report.passed == 1 and report.failed == 1
    assert len(report.failures) == 1
    print("All adversarial_simulator assertions passed.")
    sys.exit(0)
