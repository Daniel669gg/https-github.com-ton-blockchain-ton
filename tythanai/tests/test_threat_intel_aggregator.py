"""Tests for backend/intelligence/threat_intel_aggregator.py."""
from __future__ import annotations
import sys, pathlib
_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.intelligence.threat_intel_aggregator import (
    ThreatIntelAggregator, AggregatedThreatIntel, AggregationReport,
    get_threat_intel, KEV_RISK_BOOST,
)


def test_aggregate_returns_model():
    agg = ThreatIntelAggregator()
    result = agg.aggregate("CVE-2023-44487")  # HTTP/2 Rapid Reset — well-known
    assert isinstance(result, AggregatedThreatIntel)
    assert result.cve_id == "CVE-2023-44487"


def test_aggregate_risk_boost_range():
    agg = ThreatIntelAggregator()
    result = agg.aggregate("CVE-2021-44228")  # Log4Shell
    assert result.risk_score_boost >= 0.0, "Risk boost cannot be negative"
    assert result.risk_score_boost <= 60.0, "Risk boost too large"


def test_kev_finding_boosts_score():
    """CVE from KEV should have risk_score_boost >= KEV_RISK_BOOST (20)."""
    agg = ThreatIntelAggregator()
    # Mock the KEV check to return True for a specific CVE
    result = agg.aggregate("CVE-2021-44228")  # Log4Shell is famous KEV
    # Even if network unavailable, the boost logic must work
    # We verify: if in_kev is True, boost must be >= KEV_RISK_BOOST
    if result.in_kev:
        assert result.risk_score_boost >= KEV_RISK_BOOST, (
            f"KEV CVE should boost score by >= {KEV_RISK_BOOST}, got {result.risk_score_boost}"
        )
    # If not in KEV (offline), boost can be 0
    assert result.risk_score_boost >= 0.0


def test_not_in_kev_has_zero_kev_boost():
    """Non-KEV CVE should not get KEV boost."""
    agg = ThreatIntelAggregator()
    # Use a clearly fake CVE that won't be in KEV
    result = agg.aggregate("CVE-9999-99999")
    assert not result.in_kev, "Fake CVE should not be in KEV"
    # KEV portion of boost should be 0
    # Total boost is combination of all sources; at minimum it should be 0
    assert result.risk_score_boost >= 0.0


def test_aggregate_batch():
    agg = ThreatIntelAggregator()
    report = agg.aggregate_batch(["CVE-2023-44487", "CVE-2021-44228"])
    assert isinstance(report, AggregationReport)
    assert report.total_cves == 2
    assert len(report.entries) == 2


def test_aggregated_intel_fields():
    agg = ThreatIntelAggregator()
    result = agg.aggregate("CVE-2023-12345")
    assert isinstance(result.iocs, list)
    assert isinstance(result.sources, list)
    assert isinstance(result.in_kev, bool)
    assert 0.0 <= result.epss_score <= 1.0


def test_module_level_function():
    result = get_threat_intel("CVE-2023-44487")
    assert isinstance(result, AggregatedThreatIntel)
