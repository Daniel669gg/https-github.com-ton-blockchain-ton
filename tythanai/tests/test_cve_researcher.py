"""Tests for backend/intelligence/cve_researcher.py."""
from __future__ import annotations
import sys, pathlib
_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.confidence import Finding
from backend.intelligence.cve_researcher import (
    CVEResearcher, VulnResearchChain, CVEResearchEntry,
    research_cwe, _CVE_KNOWLEDGE_BASE,
)


def _f(cwe="CWE-89", severity="CRITICAL"):
    return Finding(rule_id="SQLI-001", file="app.py", line=10,
                   severity=severity, cwe_id=cwe, description="test")


def test_cwe89_chain_has_cves():
    researcher = CVEResearcher()
    chain = researcher.research_finding(_f("CWE-89"))
    assert isinstance(chain, VulnResearchChain)
    assert len(chain.related_cves) > 0, "CWE-89 should have related CVEs"
    assert chain.cwe_id == "CWE-89"


def test_weaponization_score_range():
    researcher = CVEResearcher()
    chain = researcher.research_finding(_f("CWE-89"))
    assert 0.0 <= chain.weaponization_score <= 1.0, (
        f"weaponization_score out of range: {chain.weaponization_score}"
    )


def test_top_weaponized_sorted():
    researcher = CVEResearcher()
    findings = [_f("CWE-89"), _f("CWE-79"), _f("CWE-502"), _f("CWE-78"), _f("CWE-416")]
    top = researcher.get_top_weaponized(findings, top_n=3)
    assert len(top) <= 3
    # Should be sorted descending by weaponization_score
    scores = [t.weaponization_score for t in top]
    assert scores == sorted(scores, reverse=True), f"Not sorted: {scores}"


def test_estimate_bounty_critical():
    researcher = CVEResearcher()
    f = _f("CWE-89", severity="CRITICAL")
    bounty = researcher.estimate_bounty(f)
    assert isinstance(bounty, str)
    assert "$" in bounty, f"Bounty should contain dollar amount: {bounty}"


def test_research_finding_returns_chain():
    researcher = CVEResearcher()
    chain = researcher.research_finding(_f("CWE-79"))
    assert isinstance(chain, VulnResearchChain)
    assert chain.cwe_id == "CWE-79"
    assert isinstance(chain.recommended_checks, list)
    assert len(chain.recommended_checks) > 0


def test_recommended_checks_present():
    researcher = CVEResearcher()
    chain = researcher.research_finding(_f("CWE-89"))
    assert len(chain.recommended_checks) > 0, "Expected at least 1 recommended check"
    for check in chain.recommended_checks:
        assert isinstance(check, str) and len(check) > 5


def test_module_level_function():
    chain = research_cwe("CWE-89")
    assert chain is not None
    assert isinstance(chain, VulnResearchChain)
    assert len(chain.related_cves) > 0

    # Unknown CWE should return None or a chain with empty cves
    unknown = research_cwe("CWE-9999")
    assert unknown is None or isinstance(unknown, VulnResearchChain)


def test_knowledge_base_covers_key_cwes():
    required = {"CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-798"}
    for cwe in required:
        assert cwe in _CVE_KNOWLEDGE_BASE, f"Missing {cwe} in knowledge base"
        assert len(_CVE_KNOWLEDGE_BASE[cwe]) >= 2, f"Not enough CVEs for {cwe}"
