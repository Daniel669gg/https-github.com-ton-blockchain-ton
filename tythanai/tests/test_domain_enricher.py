"""Tests for backend/agents/domain_enricher.py."""
from __future__ import annotations
import sys, pathlib
_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.confidence import Finding
from backend.agents.domain_enricher import DomainEnricher, EnrichedFinding, DOMAIN_MAP


def _make_finding(**kwargs):
    defaults = dict(rule_id="SQLI-001", file="app.py", line=10, severity="CRITICAL",
                    cwe_id="CWE-89", description="SQL injection")
    defaults.update(kwargs)
    return Finding(**defaults)


def test_sqli_finding_gets_t1190():
    enricher = DomainEnricher()
    f = _make_finding(rule_id="SQLI-001")
    ef = enricher.enrich_finding(f)
    assert isinstance(ef, EnrichedFinding)
    assert "T1190" in ef.attck_ids, f"Expected T1190 in attck_ids, got {ef.attck_ids}"


def test_sqli_finding_gets_d3fend():
    enricher = DomainEnricher()
    f = _make_finding(rule_id="SQLI-001")
    ef = enricher.enrich_finding(f)
    assert len(ef.d3fend_countermeasures) > 0, "Expected D3FEND countermeasures"


def test_sqli_finding_has_verification_steps():
    enricher = DomainEnricher()
    f = _make_finding(rule_id="SQLI-001")
    ef = enricher.enrich_finding(f)
    assert len(ef.skill_verification_steps) > 0, "Expected verification steps"


def test_enrich_preserves_finding_fields():
    enricher = DomainEnricher()
    f = _make_finding(rule_id="XSS-001", severity="HIGH", cwe_id="CWE-79")
    ef = enricher.enrich_finding(f)
    assert ef.rule_id == "XSS-001"
    assert ef.severity == "HIGH"
    assert ef.cwe_id == "CWE-79"


def test_enrich_findings_batch():
    enricher = DomainEnricher()
    findings = [
        _make_finding(rule_id="SQLI-001"),
        _make_finding(rule_id="XSS-001", severity="HIGH", cwe_id="CWE-79"),
        _make_finding(rule_id="AUTH-001", severity="MEDIUM", cwe_id="CWE-287"),
    ]
    enriched = enricher.enrich_findings(findings)
    assert len(enriched) == 3
    for ef in enriched:
        assert isinstance(ef, EnrichedFinding)
        assert len(ef.domains) > 0


def test_domain_map_covers_key_types():
    keys = set(DOMAIN_MAP.keys())
    assert "sqli" in keys or any("sql" in k for k in keys)
    assert "xss" in keys
    assert "crypto" in keys or any("crypt" in k for k in keys)


def test_unknown_rule_id_still_returns_enriched():
    enricher = DomainEnricher()
    f = _make_finding(rule_id="UNKNOWN-999")
    ef = enricher.enrich_finding(f)
    assert isinstance(ef, EnrichedFinding)
    # Should gracefully handle unknown rules (domains may be empty)
    assert isinstance(ef.attck_ids, list)
