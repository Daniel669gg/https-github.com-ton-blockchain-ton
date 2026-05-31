"""Tests for backend/agents/threat_hunter.py (agent, not SIEM queries)."""
from __future__ import annotations
import sys, pathlib
_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.confidence import Finding
from backend.agents.threat_hunter import ThreatHunterAgent, HuntingReport, Hypothesis


def _high_finding(**kw):
    defaults = dict(rule_id="SQLI-001", file="app.py", line=10,
                    severity="HIGH", cwe_id="CWE-89", description="SQL injection")
    defaults.update(kw)
    return Finding(**defaults)

def _critical_finding(**kw):
    defaults = dict(rule_id="RCE-001", file="cmd.py", line=5,
                    severity="CRITICAL", cwe_id="CWE-78", description="OS command injection")
    defaults.update(kw)
    return Finding(**defaults)


def test_hunt_returns_report():
    agent = ThreatHunterAgent()
    report = agent.hunt([_high_finding()])
    assert isinstance(report, HuntingReport)


def test_high_finding_generates_at_least_2_hypotheses():
    agent = ThreatHunterAgent()
    report = agent.hunt([_high_finding()])
    assert report.hypotheses_generated >= 2, (
        f"Expected >=2 hypotheses for HIGH finding, got {report.hypotheses_generated}"
    )


def test_critical_finding_generates_hypotheses():
    agent = ThreatHunterAgent()
    report = agent.hunt([_critical_finding()])
    assert report.hypotheses_generated >= 1


def test_empty_findings_returns_empty_report():
    agent = ThreatHunterAgent()
    report = agent.hunt([])
    assert isinstance(report, HuntingReport)
    assert report.hypotheses_generated == 0


def test_multiple_findings_aggregate():
    agent = ThreatHunterAgent()
    findings = [_high_finding(), _critical_finding(),
                _high_finding(rule_id="XSS-001", cwe_id="CWE-79", description="XSS")]
    report = agent.hunt(findings)
    assert report.hypotheses_generated >= 4


def test_lotl_patterns_are_list():
    agent = ThreatHunterAgent()
    report = agent.hunt([_high_finding()])
    assert isinstance(report.lotl_patterns, list)


def test_sigma_rules_generated_for_confirmed():
    agent = ThreatHunterAgent()
    findings = [_critical_finding()]
    report = agent.hunt(findings)
    # sigma_rules should be a list (may be empty if nothing confirmed, but must be list)
    assert isinstance(report.sigma_rules, list)


def test_generate_hypotheses_directly():
    agent = ThreatHunterAgent()
    f = _high_finding(rule_id="INJECT-001", cwe_id="CWE-89")
    hypotheses = agent._generate_hypotheses(f)
    assert len(hypotheses) >= 2
    for h in hypotheses:
        assert isinstance(h, Hypothesis)
        assert h.description
        assert 0.0 <= h.confidence <= 1.0
