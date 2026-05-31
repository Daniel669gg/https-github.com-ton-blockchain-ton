"""Tests for backend/agents/adversarial_simulator.py."""
from __future__ import annotations
import sys, pathlib, os
_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.agents.adversarial_simulator import (
    AdversarialSimulator, SimulationReport, AdversarialTestResult,
    SQL_INJECTION_PAYLOADS, XSS_PAYLOADS, OVERSIZED_INPUTS,
    run_adversarial_tests,
)


def test_payload_libraries_populated():
    assert len(SQL_INJECTION_PAYLOADS) >= 5
    assert len(XSS_PAYLOADS) >= 5
    assert len(OVERSIZED_INPUTS) >= 3


def test_check_environment_test_mode():
    os.environ["ENV"] = "test"
    sim = AdversarialSimulator()
    assert sim._check_environment() is True


def test_check_environment_prod_mode():
    os.environ["ENV"] = "production"
    sim = AdversarialSimulator()
    assert sim._check_environment() is False
    # Reset
    os.environ["ENV"] = "test"


def test_check_environment_staging():
    os.environ["ENV"] = "staging"
    sim = AdversarialSimulator()
    assert sim._check_environment() is True
    os.environ["ENV"] = "test"


def test_test_endpoint_no_server():
    """When no server is available, status_code=0, passed=False."""
    os.environ["ENV"] = "test"
    sim = AdversarialSimulator(base_url="http://localhost:19999")
    result = sim.test_endpoint(
        endpoint="/api/v2/scan/taint",
        method="POST",
        payload={"path": "' OR 1=1--"},
        payload_type="sql_injection",
    )
    assert isinstance(result, AdversarialTestResult)
    assert result.status_code == 0 or not result.passed, (
        "Should fail gracefully when server is not running"
    )


def test_run_without_server_returns_report():
    """run() without a server should return a SimulationReport, not crash."""
    os.environ["ENV"] = "test"
    sim = AdversarialSimulator(base_url="http://localhost:19998")
    report = sim.run()
    assert isinstance(report, SimulationReport)
    assert report.simulation_id
    assert isinstance(report.all_results, list)


def test_simulation_report_stats():
    os.environ["ENV"] = "test"
    sim = AdversarialSimulator(base_url="http://localhost:19997")
    report = sim.run()
    # passed + failed must sum to total_tests
    assert report.passed + report.failed == report.total_tests


def test_module_level_function():
    os.environ["ENV"] = "test"
    report = run_adversarial_tests()
    assert isinstance(report, SimulationReport)
