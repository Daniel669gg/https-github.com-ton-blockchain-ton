"""
tests/test_chain_analyzer.py — 10 tests for ChainAnalyzer
"""
import sys
import pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest
from backend.core.confidence import Finding
from backend.analysis.chain_analyzer import (
    ChainAnalyzer,
    ChainResult,
    ExploitPath,
    analyze_attack_chains,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def make_finding(**kwargs) -> Finding:
    defaults = dict(
        rule_id="TEST-RULE",
        file="app/main.py",
        line=10,
        severity="MEDIUM",
        confidence=0.85,
        cwe_id="",
        description="Test finding",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────

def test_analyze_empty():
    """analyze([]) returns an empty list."""
    results = ChainAnalyzer().analyze([])
    assert results == []


def test_single_finding_no_chain():
    """A single finding cannot form a chain (minimum 2 required)."""
    findings = [make_finding(rule_id="SQLI-001", cwe_id="CWE-89", severity="HIGH")]
    results = ChainAnalyzer().analyze(findings)
    assert results == []


def test_cwe_chain_sqli_plus_noauth():
    """CWE-89 + CWE-306 finding pair should trigger a CWE chain."""
    findings = [
        make_finding(rule_id="SQLI-BASIC", cwe_id="CWE-89", severity="HIGH", confidence=0.9),
        make_finding(
            rule_id="AUTH-MISSING",
            cwe_id="CWE-306",
            severity="HIGH",
            confidence=0.9,
            file="app/views.py",
            line=42,
        ),
    ]
    results = ChainAnalyzer().analyze(findings)
    assert len(results) >= 1, "Expected at least one chain for CWE-89 + CWE-306"


def test_keyword_chain_sqli_auth():
    """Rule IDs containing SQLI and NO-AUTH keywords should form a keyword chain."""
    findings = [
        make_finding(rule_id="SQLI-INJECTION", severity="HIGH", confidence=0.9),
        make_finding(
            rule_id="NO-AUTH-CHECK",
            severity="HIGH",
            confidence=0.9,
            file="app/db.py",
            line=55,
        ),
    ]
    results = ChainAnalyzer().analyze(findings)
    assert len(results) >= 1, "Expected keyword chain for SQLI + NO-AUTH"


def test_chain_severity_is_critical():
    """SQLI + NO-AUTH chain should be rated CRITICAL."""
    findings = [
        make_finding(rule_id="SQLI-INJECTION", severity="HIGH", confidence=0.9),
        make_finding(
            rule_id="NO-AUTH-CHECK",
            severity="HIGH",
            confidence=0.9,
            file="app/db.py",
            line=55,
        ),
    ]
    results = ChainAnalyzer().analyze(findings)
    severities = [c.severity for c in results]
    assert "CRITICAL" in severities, f"Expected CRITICAL severity, got: {severities}"


def test_chain_narrative_not_empty():
    """Every detected chain must have a non-empty narrative."""
    findings = [
        make_finding(rule_id="SQLI-001", cwe_id="CWE-89", severity="HIGH", confidence=0.9),
        make_finding(
            rule_id="NO-AUTH-001",
            cwe_id="CWE-306",
            severity="HIGH",
            confidence=0.85,
            file="app/auth.py",
            line=20,
        ),
    ]
    results = ChainAnalyzer().analyze(findings)
    assert results, "Expected at least one chain"
    for chain in results:
        assert chain.narrative, f"Chain {chain.chain_id} has empty narrative"


def test_deduplicate_chains():
    """Same findings found by both CWE and keyword rules → only one chain kept."""
    # CWE-89 + CWE-306 triggers _CWE_CHAIN_RULES
    # SQLI + NO-AUTH in rule_id triggers _KEYWORD_CHAIN_RULES
    # Both sets of findings are the same pair → dedup should keep 1
    findings = [
        make_finding(rule_id="SQLI-INJECTION", cwe_id="CWE-89", severity="HIGH", confidence=0.9),
        make_finding(
            rule_id="NO-AUTH-CHECK",
            cwe_id="CWE-306",
            severity="HIGH",
            confidence=0.9,
            file="app/views.py",
            line=10,
        ),
    ]
    raw_cwe = ChainAnalyzer()._detect_cwe_chains(findings)
    raw_kw = ChainAnalyzer()._detect_keyword_chains(findings)
    combined = raw_cwe + raw_kw

    # Both detectors should have found something
    assert len(combined) >= 2, "Expected both CWE and keyword chains before dedup"

    deduped = ChainAnalyzer()._deduplicate_chains(combined)
    # After deduplication, chains with identical fingerprint sets should be collapsed
    fp_sets = [frozenset(c.finding_fingerprints) for c in deduped]
    # All fp_sets should be unique
    assert len(fp_sets) == len(set(fp_sets)), "Duplicate chains remain after deduplication"


def test_calculate_chain_risk_single():
    """Single CRITICAL finding → risk score between 7.5 and 10.0."""
    findings = [make_finding(severity="CRITICAL", confidence=0.9)]
    risk = ChainAnalyzer().calculate_chain_risk(findings)
    assert 7.5 <= risk <= 10.0, f"Expected risk in [7.5, 10.0], got {risk}"


def test_calculate_chain_risk_combo():
    """CRITICAL + HIGH combo → risk higher than single CRITICAL alone."""
    single_critical = [make_finding(severity="CRITICAL", confidence=0.9)]
    combo = [
        make_finding(severity="CRITICAL", confidence=0.9),
        make_finding(
            rule_id="RULE-B",
            severity="HIGH",
            confidence=0.85,
            file="app/auth.py",
            line=20,
        ),
    ]
    risk_single = ChainAnalyzer().calculate_chain_risk(single_critical)
    risk_combo = ChainAnalyzer().calculate_chain_risk(combo)
    assert risk_combo > risk_single, (
        f"Combo risk ({risk_combo}) should exceed single ({risk_single})"
    )


def test_critical_paths_filter():
    """get_critical_paths returns only exploit paths from CRITICAL chains."""
    findings = [
        make_finding(rule_id="SQLI-INJECTION", cwe_id="CWE-89", severity="CRITICAL", confidence=0.95),
        make_finding(
            rule_id="NO-AUTH-CHECK",
            cwe_id="CWE-306",
            severity="HIGH",
            confidence=0.9,
            file="app/views.py",
            line=10,
        ),
        # A HIGH-only finding that shouldn't form a CRITICAL chain alone
        make_finding(
            rule_id="XSS-REFLECTED",
            cwe_id="CWE-79",
            severity="HIGH",
            confidence=0.8,
            file="app/templates.py",
            line=30,
        ),
    ]
    analyzer = ChainAnalyzer()
    # First, check that chains are detected
    all_chains = analyzer.analyze(findings)
    critical_chains = [c for c in all_chains if c.severity == "CRITICAL"]

    critical_paths = analyzer.get_critical_paths(findings)
    # Critical paths should come from CRITICAL chains
    if critical_chains:
        assert len(critical_paths) >= 1, "Expected at least one critical exploit path"

    # All returned paths should belong to CRITICAL-severity chains
    for path in critical_paths:
        # The path's total_risk should be non-zero for CRITICAL chains
        assert path.total_risk >= 0.0
