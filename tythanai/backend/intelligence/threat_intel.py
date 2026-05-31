"""Threat Intelligence Engine — IOC feeds, threat indicators, reputation data.

Integrates with free/open threat intelligence APIs:
  - AlienVault OTX (API key optional)
  - Abuse.ch URLhaus
  - Abuse.ch MalwareBazaar
  - CIRCL Hash Lookup (no auth required)

All network calls degrade gracefully: a failed feed returns UNKNOWN verdict
rather than raising an exception, so the engine is safe to use in CI pipelines
and offline environments.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import httpx
from pydantic import BaseModel, Field

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.threat_intel")


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"
    EMAIL = "email"
    CVE = "cve"
    YARA = "yara"
    SIGMA = "sigma"


class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────


class IOCRecord(BaseModel):
    """A single Indicator of Compromise with enrichment metadata."""

    ioc_value: str
    ioc_type: IOCType
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    confidence: float = 0.5
    tags: List[str] = Field(default_factory=list)
    source: str = ""           # "alienvault_otx" | "misp" | "virustotal" | "abuse_ch"
    first_seen: str = ""
    last_seen: str = ""
    malware_families: List[str] = Field(default_factory=list)
    threat_actor: str = ""
    description: str = ""
    ttps: List[str] = Field(default_factory=list)   # MITRE ATT&CK TTPs


class ThreatIntelReport(BaseModel):
    """Aggregated threat intelligence result for a queried indicator."""

    query_value: str
    query_type: IOCType
    matches: List[IOCRecord]
    verdict: ThreatLevel
    summary: str
    enrichment: Dict[str, Any] = Field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Regex patterns for IOC extraction
# ─────────────────────────────────────────────────────────────────────────────

_RE_IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
_RE_SHA256 = re.compile(r"\b([a-fA-F0-9]{64})\b")
_RE_SHA1 = re.compile(r"\b([a-fA-F0-9]{40})\b")
_RE_MD5 = re.compile(r"\b([a-fA-F0-9]{32})\b")
_RE_URL = re.compile(r"(https?://[^\s\"'<>]+)", re.IGNORECASE)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|io|gov|edu|co|uk|de|ru|cn|info|biz|xyz|app|dev)\b"
)
_RE_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")

# RFC-1918 + loopback address ranges — flagged as "unexpected" IOCs in code.
_RFC1918_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

# Known malicious / suspicious domain patterns (lightweight local heuristics).
_SUSPICIOUS_TLD_RE = re.compile(
    r"\.(onion|bit|coin|bazar|xyz|top|club|gq|cf|tk|ml|ga)$",
    re.IGNORECASE,
)

# Hash length → IOCType
_HASH_LEN_MAP: Dict[int, IOCType] = {
    32: IOCType.HASH_MD5,
    40: IOCType.HASH_SHA1,
    64: IOCType.HASH_SHA256,
}


# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────


def _detect_ioc_type(value: str) -> IOCType:
    """Auto-detect the IOC type of a string value."""
    value = value.strip()

    # URL first (before domain check)
    if value.startswith(("http://", "https://")):
        return IOCType.URL

    # Email (before domain check)
    if _RE_EMAIL.fullmatch(value):
        return IOCType.EMAIL

    # IPv4
    if _RE_IPV4.fullmatch(value):
        return IOCType.IP

    # Hashes
    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return IOCType.HASH_SHA256
    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return IOCType.HASH_SHA1
    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return IOCType.HASH_MD5

    # CVE
    if re.fullmatch(r"CVE-\d{4}-\d{4,7}", value, re.IGNORECASE):
        return IOCType.CVE

    # Domain (fallback)
    if _RE_DOMAIN.fullmatch(value):
        return IOCType.DOMAIN

    return IOCType.DOMAIN  # best-effort default


def _pulse_to_threat_level(pulse_count: int) -> ThreatLevel:
    """Map AlienVault OTX pulse count to a ThreatLevel."""
    if pulse_count >= 50:
        return ThreatLevel.CRITICAL
    if pulse_count >= 15:
        return ThreatLevel.HIGH
    if pulse_count >= 3:
        return ThreatLevel.MEDIUM
    if pulse_count >= 1:
        return ThreatLevel.LOW
    return ThreatLevel.UNKNOWN


def _is_rfc1918(ip_str: str) -> bool:
    """Return True if the IP address is in an RFC-1918 or loopback range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in network for network in _RFC1918_RANGES)
    except ValueError:
        return False


def _aggregate_verdict(records: List[IOCRecord]) -> ThreatLevel:
    """Return the highest threat level across a list of IOC records."""
    order = {
        ThreatLevel.CRITICAL: 4,
        ThreatLevel.HIGH: 3,
        ThreatLevel.MEDIUM: 2,
        ThreatLevel.LOW: 1,
        ThreatLevel.UNKNOWN: 0,
    }
    if not records:
        return ThreatLevel.UNKNOWN
    return max(records, key=lambda r: order[r.threat_level]).threat_level


def _empty_report(value: str, ioc_type: IOCType, reason: str = "") -> ThreatIntelReport:
    """Build a no-match ThreatIntelReport with UNKNOWN verdict."""
    return ThreatIntelReport(
        query_value=value,
        query_type=ioc_type,
        matches=[],
        verdict=ThreatLevel.UNKNOWN,
        summary=reason or f"No threat intelligence found for {value}",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────────────────────────────────────


class ThreatIntelEngine:
    """Async threat intelligence engine integrating multiple free feeds."""

    ALIENVAULT_OTX_BASE = "https://otx.alienvault.com/api/v1"
    ABUSE_CH_URLHAUS = "https://urlhaus-api.abuse.ch/v1"
    ABUSE_CH_MALWAREBAZAAR = "https://mb-api.abuse.ch/api/v1"
    VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3"
    CIRCL_HASHLOOKUP = "https://hashlookup.circl.lu/lookup"

    def __init__(self, timeout: float = 15.0) -> None:
        self._timeout = httpx.Timeout(timeout)

    # ── AlienVault OTX helpers ────────────────────────────────────────────────

    async def _otx_get(
        self,
        path: str,
        otx_key: str,
        client: httpx.AsyncClient,
    ) -> Optional[Dict[str, Any]]:
        """Perform a single OTX API GET.  Returns None on any failure."""
        url = f"{self.ALIENVAULT_OTX_BASE}/{path}"
        headers = {"X-OTX-API-KEY": otx_key} if otx_key else {}
        try:
            response = await client.get(url, headers=headers)
            if response.status_code != 200:
                logger.debug("OTX %s → HTTP %d", path, response.status_code)
                return None
            return response.json()
        except httpx.HTTPError as exc:
            logger.debug("OTX HTTP error for %s: %s", path, exc)
            return None
        except Exception as exc:   # noqa: BLE001
            logger.debug("OTX unexpected error for %s: %s", path, exc)
            return None

    def _parse_otx_general(
        self, data: Dict[str, Any], ioc_value: str, ioc_type: IOCType
    ) -> IOCRecord:
        """Parse an OTX /general endpoint response into an IOCRecord."""
        pulse_info = data.get("pulse_info", {})
        pulse_count: int = pulse_info.get("count", 0)

        # Collect tags and malware families from pulses
        tags: List[str] = []
        malware_families: List[str] = []
        for pulse in pulse_info.get("pulses", [])[:20]:   # cap at 20
            tags.extend(pulse.get("tags", []))
            for mw in pulse.get("malware_families", []):
                name = mw.get("display_name") or mw.get("id", "")
                if name and name not in malware_families:
                    malware_families.append(name)

        # Deduplicate tags
        tags = list(dict.fromkeys(tags))

        threat_level = _pulse_to_threat_level(pulse_count)

        return IOCRecord(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            threat_level=threat_level,
            confidence=min(1.0, pulse_count / 20),
            tags=tags[:30],
            source="alienvault_otx",
            first_seen=data.get("first_seen", ""),
            last_seen=data.get("last_seen", ""),
            malware_families=malware_families[:10],
            description=f"OTX pulse count: {pulse_count}",
        )

    # ── IP Lookup ─────────────────────────────────────────────────────────────

    async def lookup_ip(self, ip: str, otx_key: str = "") -> ThreatIntelReport:
        """Query threat feeds for an IPv4 address.

        Queries:
          - AlienVault OTX /indicators/IPv4/{ip}/general (if key provided)

        Returns a ThreatIntelReport with UNKNOWN verdict on all failures.
        """
        records: List[IOCRecord] = []

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            if otx_key:
                data = await self._otx_get(
                    f"indicators/IPv4/{ip}/general", otx_key, client
                )
                if data:
                    record = self._parse_otx_general(data, ip, IOCType.IP)
                    records.append(record)

        verdict = _aggregate_verdict(records)
        summary = (
            f"IP {ip}: {verdict.value} threat level"
            f" ({len(records)} feed(s) matched)"
        )

        return ThreatIntelReport(
            query_value=ip,
            query_type=IOCType.IP,
            matches=records,
            verdict=verdict,
            summary=summary,
            enrichment={"is_rfc1918": _is_rfc1918(ip)},
        )

    # ── Domain Lookup ─────────────────────────────────────────────────────────

    async def lookup_domain(self, domain: str, otx_key: str = "") -> ThreatIntelReport:
        """Query threat feeds for a domain name.

        Queries:
          - AlienVault OTX /indicators/domain/{domain}/general (if key provided)
          - URLhaus lookup via POST

        Returns ThreatIntelReport with UNKNOWN on all failures.
        """
        records: List[IOCRecord] = []

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            # OTX domain query
            if otx_key:
                data = await self._otx_get(
                    f"indicators/domain/{domain}/general", otx_key, client
                )
                if data:
                    record = self._parse_otx_general(data, domain, IOCType.DOMAIN)
                    records.append(record)

            # URLhaus host lookup
            try:
                uh_resp = await client.post(
                    f"{self.ABUSE_CH_URLHAUS}/host/",
                    data={"host": domain},
                )
                if uh_resp.status_code == 200:
                    uh_data = uh_resp.json()
                    uh_record = self._parse_urlhaus_host(uh_data, domain, IOCType.DOMAIN)
                    if uh_record:
                        records.append(uh_record)
            except httpx.HTTPError as exc:
                logger.debug("URLhaus domain lookup failed for %s: %s", domain, exc)
            except Exception as exc:  # noqa: BLE001
                logger.debug("URLhaus unexpected error for %s: %s", domain, exc)

        verdict = _aggregate_verdict(records)
        summary = (
            f"Domain {domain}: {verdict.value} threat level"
            f" ({len(records)} feed(s) matched)"
        )

        return ThreatIntelReport(
            query_value=domain,
            query_type=IOCType.DOMAIN,
            matches=records,
            verdict=verdict,
            summary=summary,
        )

    def _parse_urlhaus_host(
        self,
        data: Dict[str, Any],
        value: str,
        ioc_type: IOCType,
    ) -> Optional[IOCRecord]:
        """Parse URLhaus host/url lookup response into an IOCRecord."""
        query_status = data.get("query_status", "")
        if query_status in ("not_found", "no_results"):
            return None
        if query_status != "is_host" and query_status != "ok":
            return None

        url_count: int = len(data.get("urls", []))
        if url_count == 0:
            return None

        # Derive threat level from number of malicious URLs
        if url_count >= 20:
            level = ThreatLevel.HIGH
        elif url_count >= 5:
            level = ThreatLevel.MEDIUM
        else:
            level = ThreatLevel.LOW

        malware_families: List[str] = []
        for url_entry in data.get("urls", [])[:20]:
            mw = url_entry.get("tags") or []
            if isinstance(mw, list):
                malware_families.extend(mw)
        malware_families = list(dict.fromkeys(malware_families))

        return IOCRecord(
            ioc_value=value,
            ioc_type=ioc_type,
            threat_level=level,
            confidence=min(1.0, url_count / 20),
            source="abuse_ch",
            malware_families=malware_families[:10],
            description=f"URLhaus: {url_count} malicious URL(s)",
            first_seen=data.get("firstseen", ""),
            last_seen=data.get("lastseen", ""),
        )

    # ── Hash Lookup ───────────────────────────────────────────────────────────

    async def lookup_hash(self, hash_value: str) -> ThreatIntelReport:
        """Query threat feeds for a file hash (MD5 / SHA-1 / SHA-256).

        Queries:
          - CIRCL Hash Lookup (no auth required)
          - Abuse.ch MalwareBazaar

        Returns ThreatIntelReport with UNKNOWN on all failures.
        """
        hash_lower = hash_value.lower().strip()
        hash_len = len(hash_lower)
        ioc_type = _HASH_LEN_MAP.get(hash_len, IOCType.HASH_SHA256)

        # CIRCL supports sha1 and sha256 natively; normalise endpoint path
        if ioc_type == IOCType.HASH_SHA256:
            circl_path = f"sha256/{hash_lower}"
        elif ioc_type == IOCType.HASH_SHA1:
            circl_path = f"sha1/{hash_lower}"
        else:
            circl_path = f"md5/{hash_lower}"

        records: List[IOCRecord] = []

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            # CIRCL Hash Lookup
            try:
                circl_resp = await client.get(
                    f"{self.CIRCL_HASHLOOKUP}/{circl_path}"
                )
                if circl_resp.status_code == 200:
                    circl_data = circl_resp.json()
                    record = self._parse_circl(circl_data, hash_lower, ioc_type)
                    if record:
                        records.append(record)
            except httpx.HTTPError as exc:
                logger.debug("CIRCL lookup failed for %s: %s", hash_lower, exc)
            except Exception as exc:  # noqa: BLE001
                logger.debug("CIRCL unexpected error for %s: %s", hash_lower, exc)

            # MalwareBazaar
            try:
                mb_resp = await client.post(
                    f"{self.ABUSE_CH_MALWAREBAZAAR}/",
                    data={"query": "get_info", "hash": hash_lower},
                )
                if mb_resp.status_code == 200:
                    mb_data = mb_resp.json()
                    record = self._parse_malwarebazaar(mb_data, hash_lower, ioc_type)
                    if record:
                        records.append(record)
            except httpx.HTTPError as exc:
                logger.debug("MalwareBazaar lookup failed for %s: %s", hash_lower, exc)
            except Exception as exc:  # noqa: BLE001
                logger.debug("MalwareBazaar unexpected error for %s: %s", hash_lower, exc)

        verdict = _aggregate_verdict(records)
        summary = (
            f"Hash {hash_lower[:16]}…: {verdict.value} threat level"
            f" ({len(records)} feed(s) matched)"
        )

        return ThreatIntelReport(
            query_value=hash_lower,
            query_type=ioc_type,
            matches=records,
            verdict=verdict,
            summary=summary,
        )

    def _parse_circl(
        self,
        data: Dict[str, Any],
        hash_value: str,
        ioc_type: IOCType,
    ) -> Optional[IOCRecord]:
        """Parse a CIRCL Hash Lookup response.

        CIRCL returns known-good software hashes (NSRL etc.).  A successful
        lookup means the file is KNOWN, not necessarily malicious.
        """
        if not data:
            return None

        file_name = data.get("FileName", "") or data.get("file_name", "")
        product = data.get("ProductName", "") or data.get("product", "")

        return IOCRecord(
            ioc_value=hash_value,
            ioc_type=ioc_type,
            threat_level=ThreatLevel.LOW,   # CIRCL = known file, low concern
            confidence=0.6,
            source="circl_hashlookup",
            description=f"Known file: {file_name} ({product})".strip(),
        )

    def _parse_malwarebazaar(
        self,
        data: Dict[str, Any],
        hash_value: str,
        ioc_type: IOCType,
    ) -> Optional[IOCRecord]:
        """Parse a MalwareBazaar get_info response."""
        query_status = data.get("query_status", "")
        if query_status == "hash_not_found":
            return None
        if query_status != "ok":
            return None

        sample_list = data.get("data", [])
        if not sample_list:
            return None

        sample = sample_list[0]
        malware_families = []
        if sample.get("signature"):
            malware_families.append(sample["signature"])
        tags = sample.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]

        return IOCRecord(
            ioc_value=hash_value,
            ioc_type=ioc_type,
            threat_level=ThreatLevel.HIGH,   # any MB hit = HIGH
            confidence=0.9,
            source="abuse_ch",
            first_seen=sample.get("first_seen", ""),
            last_seen=sample.get("last_seen", ""),
            malware_families=malware_families,
            tags=tags[:20],
            description=f"MalwareBazaar: {sample.get('file_name', hash_value)}",
        )

    # ── URL Lookup ────────────────────────────────────────────────────────────

    async def lookup_url(self, url: str) -> ThreatIntelReport:
        """Query URLhaus for a URL.

        POST https://urlhaus-api.abuse.ch/v1/url/ with {"url": url}.

        Returns ThreatIntelReport with UNKNOWN on failure.
        """
        records: List[IOCRecord] = []

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            try:
                resp = await client.post(
                    f"{self.ABUSE_CH_URLHAUS}/url/",
                    data={"url": url},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    query_status = data.get("query_status", "")
                    if query_status not in ("not_found", "no_results") and query_status:
                        malware_families: List[str] = []
                        tags = data.get("tags") or []
                        if isinstance(tags, str):
                            tags = [tags]

                        if data.get("url_status") == "online":
                            level = ThreatLevel.HIGH
                        elif data.get("url_status") == "offline":
                            level = ThreatLevel.MEDIUM
                        else:
                            level = ThreatLevel.LOW

                        records.append(
                            IOCRecord(
                                ioc_value=url,
                                ioc_type=IOCType.URL,
                                threat_level=level,
                                confidence=0.85,
                                source="abuse_ch",
                                first_seen=data.get("dateadded", ""),
                                tags=tags[:20],
                                description=(
                                    f"URLhaus: {data.get('url_status', 'unknown')} "
                                    f"({data.get('threat', '')})"
                                ),
                            )
                        )
            except httpx.HTTPError as exc:
                logger.debug("URLhaus URL lookup failed for %s: %s", url, exc)
            except Exception as exc:  # noqa: BLE001
                logger.debug("URLhaus unexpected error for %s: %s", url, exc)

        verdict = _aggregate_verdict(records)
        return ThreatIntelReport(
            query_value=url,
            query_type=IOCType.URL,
            matches=records,
            verdict=verdict,
            summary=f"URL {url[:80]}: {verdict.value} threat level",
        )

    # ── Finding enrichment ────────────────────────────────────────────────────

    async def enrich_finding(self, finding: Finding) -> Dict[str, Any]:
        """Extract IOCs from a Finding and query threat feeds for each.

        Searches finding.description and context_lines for IPs, domains,
        URLs, and file hashes.  Returns an enrichment dict with results
        keyed by IOC value.
        """
        # Collect all text to search
        text_parts = [finding.description] + (finding.context_lines or [])
        full_text = " ".join(text_parts)

        iocs = self._extract_ioc_tuples(full_text)
        enrichment: Dict[str, Any] = {}

        tasks = []
        labels = []

        for ioc_value, ioc_type in iocs[:20]:  # cap concurrent queries
            labels.append(ioc_value)
            if ioc_type == IOCType.IP:
                tasks.append(self.lookup_ip(ioc_value))
            elif ioc_type == IOCType.DOMAIN:
                tasks.append(self.lookup_domain(ioc_value))
            elif ioc_type == IOCType.URL:
                tasks.append(self.lookup_url(ioc_value))
            elif ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
                tasks.append(self.lookup_hash(ioc_value))
            else:
                labels.pop()
                continue

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for label, result in zip(labels, results):
                if isinstance(result, Exception):
                    logger.debug("Enrichment failed for %s: %s", label, result)
                    enrichment[label] = {"error": str(result)}
                else:
                    report: ThreatIntelReport = result
                    enrichment[label] = {
                        "verdict": report.verdict.value,
                        "summary": report.summary,
                        "match_count": len(report.matches),
                    }

        return enrichment

    # ── IOC extraction ────────────────────────────────────────────────────────

    def _extract_ioc_tuples(self, source_code: str) -> List[Tuple[str, IOCType]]:
        """Internal helper: extract (value, type) tuples from arbitrary text."""
        results: List[Tuple[str, IOCType]] = []
        seen: set = set()

        def _add(value: str, ioc_type: IOCType) -> None:
            if value not in seen:
                seen.add(value)
                results.append((value, ioc_type))

        # URLs first (before domain/IP extraction to avoid double-counting)
        for m in _RE_URL.finditer(source_code):
            _add(m.group(1), IOCType.URL)

        # Emails
        for m in _RE_EMAIL.finditer(source_code):
            _add(m.group(0), IOCType.EMAIL)

        # SHA-256 (before shorter hash patterns)
        for m in _RE_SHA256.finditer(source_code):
            _add(m.group(1), IOCType.HASH_SHA256)

        # SHA-1 — must not already be identified as SHA-256 prefix
        for m in _RE_SHA1.finditer(source_code):
            val = m.group(1)
            if val not in seen:
                _add(val, IOCType.HASH_SHA1)

        # MD5
        for m in _RE_MD5.finditer(source_code):
            val = m.group(1)
            if val not in seen:
                _add(val, IOCType.HASH_MD5)

        # IPv4 — strip IPs that are already part of a captured URL
        for m in _RE_IPV4.finditer(source_code):
            ip_val = m.group(1)
            already_in_url = any(
                ip_val in u for (u, t) in results if t == IOCType.URL
            )
            if not already_in_url:
                # Validate each octet
                octets = ip_val.split(".")
                if all(0 <= int(o) <= 255 for o in octets):
                    _add(ip_val, IOCType.IP)

        # Domains — skip those already captured as part of a URL
        for m in _RE_DOMAIN.finditer(source_code):
            dom_val = m.group(0)
            already_in_url = any(
                dom_val in u for (u, t) in results if t == IOCType.URL
            )
            if not already_in_url:
                _add(dom_val, IOCType.DOMAIN)

        return results

    def extract_iocs_from_code(self, source_code: str) -> List[Tuple[str, IOCType]]:
        """Public method: extract (ioc_value, ioc_type) tuples from source code.

        Args:
            source_code: Raw source code or arbitrary text to scan.

        Returns:
            Deduplicated list of (value, IOCType) tuples.
        """
        return self._extract_ioc_tuples(source_code)

    def check_for_suspicious_iocs(self, source_code: str) -> List[IOCRecord]:
        """Perform a local (offline) IOC check on source code.

        Flags:
          - Hardcoded RFC-1918 / loopback IP addresses
          - URLs using suspicious TLDs (.onion, .bazar, etc.)
          - Any hardcoded domain or URL (flagged as UNKNOWN, needs review)
          - Hardcoded hashes (flagged LOW — may be legitimate integrity checks)

        No network calls are made.  All records have threat_level UNKNOWN
        unless a local heuristic applies.

        Args:
            source_code: Raw source code to scan.

        Returns:
            List of IOCRecord objects, possibly empty.
        """
        if not source_code:
            return []

        records: List[IOCRecord] = []
        ioc_tuples = self._extract_ioc_tuples(source_code)

        for ioc_value, ioc_type in ioc_tuples:
            record = self._evaluate_ioc_locally(ioc_value, ioc_type)
            if record:
                records.append(record)

        return records

    def _evaluate_ioc_locally(
        self, ioc_value: str, ioc_type: IOCType
    ) -> Optional[IOCRecord]:
        """Apply local heuristics to an extracted IOC and return an IOCRecord.

        Returns None if the IOC is benign by heuristic (e.g. public resolver IP
        that is explicitly whitelisted for code context).
        """
        if ioc_type == IOCType.IP:
            if _is_rfc1918(ioc_value):
                return IOCRecord(
                    ioc_value=ioc_value,
                    ioc_type=ioc_type,
                    threat_level=ThreatLevel.MEDIUM,
                    confidence=0.5,
                    source="local_heuristic",
                    description=(
                        "Hardcoded private/RFC-1918 IP address found in code. "
                        "May indicate infrastructure exposure or misconfiguration."
                    ),
                    tags=["hardcoded-ip", "rfc1918"],
                )
            # Public IP hardcoded in code — needs review
            return IOCRecord(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                threat_level=ThreatLevel.UNKNOWN,
                confidence=0.4,
                source="local_heuristic",
                description="Hardcoded public IP address in source code.",
                tags=["hardcoded-ip"],
            )

        if ioc_type == IOCType.DOMAIN:
            level = ThreatLevel.UNKNOWN
            tags = ["hardcoded-domain"]
            description = "Hardcoded domain name in source code."

            if _SUSPICIOUS_TLD_RE.search(ioc_value):
                level = ThreatLevel.MEDIUM
                tags.append("suspicious-tld")
                description = (
                    f"Hardcoded domain with suspicious TLD in source code: {ioc_value}"
                )

            return IOCRecord(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                threat_level=level,
                confidence=0.4,
                source="local_heuristic",
                description=description,
                tags=tags,
            )

        if ioc_type == IOCType.URL:
            level = ThreatLevel.UNKNOWN
            tags = ["hardcoded-url"]

            if _SUSPICIOUS_TLD_RE.search(ioc_value):
                level = ThreatLevel.MEDIUM
                tags.append("suspicious-tld")

            return IOCRecord(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                threat_level=level,
                confidence=0.3,
                source="local_heuristic",
                description="Hardcoded URL in source code.",
                tags=tags,
            )

        if ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
            return IOCRecord(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                threat_level=ThreatLevel.UNKNOWN,
                confidence=0.3,
                source="local_heuristic",
                description="Hardcoded hash value in source code — verify it is an integrity check.",
                tags=["hardcoded-hash"],
            )

        if ioc_type == IOCType.EMAIL:
            return IOCRecord(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                threat_level=ThreatLevel.UNKNOWN,
                confidence=0.2,
                source="local_heuristic",
                description="Hardcoded email address in source code.",
                tags=["hardcoded-email"],
            )

        return None


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience functions
# ─────────────────────────────────────────────────────────────────────────────


async def lookup_indicator(
    value: str,
    ioc_type: str = "auto",
    otx_key: str = "",
) -> ThreatIntelReport:
    """Query all relevant threat feeds for a single indicator.

    Args:
        value:    The indicator value (IP, domain, URL, hash).
        ioc_type: ``"auto"`` to detect automatically, or an IOCType enum value.
        otx_key:  Optional AlienVault OTX API key.

    Returns:
        ThreatIntelReport with UNKNOWN verdict if all feeds fail or no matches.
    """
    engine = ThreatIntelEngine()

    if ioc_type == "auto":
        detected = _detect_ioc_type(value)
    else:
        try:
            detected = IOCType(ioc_type)
        except ValueError:
            detected = _detect_ioc_type(value)

    if detected == IOCType.IP:
        return await engine.lookup_ip(value, otx_key=otx_key)
    elif detected in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
        return await engine.lookup_hash(value)
    elif detected == IOCType.URL:
        return await engine.lookup_url(value)
    else:
        return await engine.lookup_domain(value, otx_key=otx_key)


def extract_code_iocs(source_code: str) -> List[IOCRecord]:
    """Perform an offline IOC check on source code, returning IOCRecord objects.

    Args:
        source_code: Raw source code to scan.

    Returns:
        List of IOCRecord objects with local heuristic threat levels.
    """
    return ThreatIntelEngine().check_for_suspicious_iocs(source_code)
