"""
TythanAI — Threat Intel Aggregator
Coordinates CVE intel, KEV status, OTX, EPSS into unified threat picture.
Caches results in SQLite. Boosts risk scores for KEV-listed CVEs.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Resolve Finding import
# ---------------------------------------------------------------------------
try:
    from backend.core.confidence import Finding
except ModuleNotFoundError:
    import importlib.util as _ilu
    import pathlib as _pl

    _root = _pl.Path(__file__).resolve().parents[2]
    _spec = _ilu.spec_from_file_location(
        "confidence", _root / "backend" / "core" / "confidence.py"
    )
    _mod = _ilu.module_from_spec(_spec)  # type: ignore[arg-type]
    _spec.loader.exec_module(_mod)  # type: ignore[union-attr]
    Finding = _mod.Finding

logger = logging.getLogger("ghost.threat_intel_aggregator")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

KEV_RISK_BOOST = 20.0
METASPLOIT_RISK_BOOST = 15.0
HIGH_EPSS_RISK_BOOST = 10.0
NUCLEI_RISK_BOOST = 5.0
KEV_CACHE_HOURS = 24

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class AggregatedThreatIntel(BaseModel):
    cve_id: str
    in_kev: bool                    # CISA Known Exploited Vulnerabilities
    kev_date_added: Optional[str]
    epss_score: float               # 0.0-1.0 probability of exploitation
    cvss_score: float
    otx_pulse_count: int            # AlienVault OTX pulses referencing this CVE
    iocs: List[str]                 # IPs/domains/hashes from OTX
    nuclei_template: bool           # whether Nuclei template exists
    metasploit_module: bool         # whether MSF module exists
    risk_score_boost: float         # added to base risk score
    aggregated_at: str
    sources: List[str]              # which sources contributed


class AggregationReport(BaseModel):
    total_cves: int
    kev_count: int
    high_epss_count: int            # epss > 0.7
    total_risk_boost: float
    entries: List[AggregatedThreatIntel]


# ---------------------------------------------------------------------------
# Main aggregator
# ---------------------------------------------------------------------------


class ThreatIntelAggregator:
    """Coordinates CVEIntelligenceEngine + ThreatIntelEngine into a unified risk picture.

    Caches results in SQLite for KEV_CACHE_HOURS to reduce network calls.
    """

    _KEV_CATALOG_CACHE: Optional[Dict[str, Optional[str]]] = None   # cve_id → date_added
    _KEV_CATALOG_TS: float = 0.0

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or "/tmp/ghost_threat_intel.db"
        self._init_db()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        try:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS threat_intel_cache (
                        cve_id     TEXT PRIMARY KEY,
                        data       TEXT NOT NULL,
                        cached_at  TEXT NOT NULL
                    )
                    """
                )
                conn.commit()
        except sqlite3.Error as exc:
            logger.warning("Could not initialise threat intel cache DB: %s", exc)

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    # ------------------------------------------------------------------
    # Cache helpers
    # ------------------------------------------------------------------

    def _load_from_cache(self, cve_id: str) -> Optional[AggregatedThreatIntel]:
        try:
            with self._get_conn() as conn:
                row = conn.execute(
                    "SELECT data, cached_at FROM threat_intel_cache WHERE cve_id = ?",
                    (cve_id,),
                ).fetchone()

            if row is None:
                return None

            cached_at_str: str = row["cached_at"]
            try:
                cached_at = datetime.fromisoformat(cached_at_str)
                if cached_at.tzinfo is None:
                    cached_at = cached_at.replace(tzinfo=timezone.utc)
            except ValueError:
                return None

            age_hours = (datetime.now(timezone.utc) - cached_at).total_seconds() / 3600
            if age_hours >= KEV_CACHE_HOURS:
                return None

            return AggregatedThreatIntel.model_validate_json(row["data"])

        except (sqlite3.Error, Exception) as exc:
            logger.debug("Cache read error for %s: %s", cve_id, exc)
            return None

    def _save_to_cache(self, intel: AggregatedThreatIntel) -> None:
        try:
            with self._get_conn() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO threat_intel_cache (cve_id, data, cached_at)
                    VALUES (?, ?, ?)
                    """,
                    (
                        intel.cve_id,
                        intel.model_dump_json(),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                conn.commit()
        except sqlite3.Error as exc:
            logger.debug("Cache write error for %s: %s", intel.cve_id, exc)

    # ------------------------------------------------------------------
    # CISA KEV direct check (urllib, no external deps)
    # ------------------------------------------------------------------

    def _check_kev_direct(self, cve_id: str) -> Tuple[bool, Optional[str]]:
        """Fetch CISA KEV catalog with 24h in-process cache.

        Returns (in_kev: bool, date_added: Optional[str]).
        Falls back to (False, None) on any network error.
        """
        import time

        now = time.time()
        catalog = ThreatIntelAggregator._KEV_CATALOG_CACHE
        ts = ThreatIntelAggregator._KEV_CATALOG_TS

        if catalog is None or (now - ts) > KEV_CACHE_HOURS * 3600:
            catalog = self._fetch_kev_catalog()
            ThreatIntelAggregator._KEV_CATALOG_CACHE = catalog
            ThreatIntelAggregator._KEV_CATALOG_TS = now

        date_added = catalog.get(cve_id.upper())
        if date_added is not None:
            return True, date_added
        # Explicit None means key present but no date; '' means not in catalog
        return (cve_id.upper() in catalog), catalog.get(cve_id.upper())

    def _fetch_kev_catalog(self) -> Dict[str, Optional[str]]:
        """Download and parse the CISA KEV JSON. Returns {cve_id: date_added}."""
        catalog: Dict[str, Optional[str]] = {}
        try:
            req = urllib.request.Request(
                CISA_KEV_URL,
                headers={"User-Agent": "TythanAI-ThreatIntelAggregator/1.0"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read()
            data = json.loads(raw)
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cveID", "")
                if cve:
                    catalog[cve.upper()] = vuln.get("dateAdded")
            logger.info("KEV catalog loaded: %d entries", len(catalog))
        except urllib.error.URLError as exc:
            logger.warning("Could not fetch CISA KEV catalog: %s", exc)
        except (json.JSONDecodeError, KeyError, Exception) as exc:  # noqa: BLE001
            logger.warning("Error parsing CISA KEV catalog: %s", exc)
        return catalog

    # ------------------------------------------------------------------
    # Core aggregation
    # ------------------------------------------------------------------

    def aggregate(
        self,
        cve_id: str,
        force_refresh: bool = False,
    ) -> AggregatedThreatIntel:
        """Aggregate threat intel from all available sources for a single CVE ID.

        Returns cached result if < KEV_CACHE_HOURS old and not force_refresh.
        Never raises; falls back gracefully on any source failure.
        """
        cve_id_upper = cve_id.strip().upper()

        if not force_refresh:
            cached = self._load_from_cache(cve_id_upper)
            if cached is not None:
                return cached

        # ── Source 1: CVEIntelligenceEngine (async wrapper) ──────────────────
        cvss_score = 0.0
        epss_score = 0.0
        in_kev_cve_engine = False
        kev_date_cve_engine: Optional[str] = None
        sources_contributed: List[str] = []

        try:
            from backend.intelligence.cve_intel import CVEIntelligenceEngine  # type: ignore
            import asyncio

            async def _fetch() -> None:
                nonlocal cvss_score, epss_score, in_kev_cve_engine, kev_date_cve_engine
                engine = CVEIntelligenceEngine()
                record = await engine.enrich_finding(cve_id_upper)
                if record:
                    cvss_score = max(record.cvss_v3, record.cvss_v2)
                    epss_score = record.epss_score
                    in_kev_cve_engine = record.is_kev
                    kev_date_cve_engine = record.kev_date_added or None

            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # In async context (e.g. FastAPI), create a new thread-based loop
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        future = pool.submit(asyncio.run, _fetch())
                        future.result(timeout=20)
                else:
                    loop.run_until_complete(_fetch())
            except RuntimeError:
                asyncio.run(_fetch())

            sources_contributed.append("nvd_epss_kev")
        except ImportError:
            logger.debug("CVEIntelligenceEngine not available; falling back to direct KEV check")
        except Exception as exc:  # noqa: BLE001
            logger.debug("CVEIntelligenceEngine failed for %s: %s", cve_id_upper, exc)

        # ── Source 2: Direct KEV check (fallback / supplement) ───────────────
        in_kev_direct, kev_date_direct = False, None
        try:
            in_kev_direct, kev_date_direct = self._check_kev_direct(cve_id_upper)
            sources_contributed.append("cisa_kev_direct")
        except Exception as exc:  # noqa: BLE001
            logger.debug("Direct KEV check failed for %s: %s", cve_id_upper, exc)

        # Merge KEV status (either source triggering is enough)
        in_kev = in_kev_cve_engine or in_kev_direct
        kev_date = kev_date_cve_engine or kev_date_direct

        # ── Source 3: ThreatIntelEngine (OTX / IOC data) ─────────────────────
        otx_pulse_count = 0
        iocs: List[str] = []

        try:
            from backend.intelligence.threat_intel import ThreatIntelEngine  # type: ignore
            import asyncio

            async def _fetch_otx() -> None:
                nonlocal otx_pulse_count, iocs
                engine = ThreatIntelEngine(timeout=10.0)
                # Use the public lookup_domain path which handles CVE type as domain fallback
                # More accurately, use the local IOC extractor / indicator lookup
                # ThreatIntelEngine.lookup_indicator is module-level; call per-type here
                try:
                    from backend.intelligence.threat_intel import lookup_indicator  # type: ignore
                    report = await lookup_indicator(cve_id_upper, ioc_type="cve")
                    if report and report.matches:
                        otx_pulse_count = len(report.matches)
                        for match in report.matches[:10]:
                            if match.ioc_value not in iocs:
                                iocs.append(match.ioc_value)
                except Exception:
                    pass

            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        future = pool.submit(asyncio.run, _fetch_otx())
                        future.result(timeout=15)
                else:
                    loop.run_until_complete(_fetch_otx())
            except RuntimeError:
                asyncio.run(_fetch_otx())

            sources_contributed.append("threat_intel_engine")
        except ImportError:
            logger.debug("ThreatIntelEngine not available, skipping OTX enrichment")
        except Exception as exc:  # noqa: BLE001
            logger.debug("ThreatIntelEngine failed for %s: %s", cve_id_upper, exc)

        # ── Nuclei / Metasploit heuristics (lightweight local check) ─────────
        # These are best-effort heuristics; a full implementation would query
        # Nuclei/MSF APIs or check local template/module directories.
        nuclei_template = False
        metasploit_module = False
        # Known KEV CVEs are very likely to have Nuclei templates / MSF modules;
        # use KEV status as a proxy when live lookup is not available.
        if in_kev:
            nuclei_template = True
            metasploit_module = True

        # ── Compute risk score boost ──────────────────────────────────────────
        risk_boost = 0.0
        if in_kev:
            risk_boost += KEV_RISK_BOOST
        if metasploit_module:
            risk_boost += METASPLOIT_RISK_BOOST
        if epss_score > 0.7:
            risk_boost += HIGH_EPSS_RISK_BOOST
        if nuclei_template:
            risk_boost += NUCLEI_RISK_BOOST

        intel = AggregatedThreatIntel(
            cve_id=cve_id_upper,
            in_kev=in_kev,
            kev_date_added=kev_date,
            epss_score=round(epss_score, 6),
            cvss_score=round(cvss_score, 2),
            otx_pulse_count=otx_pulse_count,
            iocs=iocs,
            nuclei_template=nuclei_template,
            metasploit_module=metasploit_module,
            risk_score_boost=risk_boost,
            aggregated_at=datetime.now(timezone.utc).isoformat(),
            sources=list(dict.fromkeys(sources_contributed)),  # preserve order, deduplicate
        )

        self._save_to_cache(intel)
        return intel

    def aggregate_batch(self, cve_ids: List[str]) -> AggregationReport:
        """Aggregate intel for a list of CVE IDs."""
        entries: List[AggregatedThreatIntel] = []
        for cve_id in cve_ids:
            try:
                entry = self.aggregate(cve_id)
                entries.append(entry)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Failed to aggregate intel for %s: %s", cve_id, exc)

        kev_count = sum(1 for e in entries if e.in_kev)
        high_epss_count = sum(1 for e in entries if e.epss_score > 0.7)
        total_risk_boost = sum(e.risk_score_boost for e in entries)

        return AggregationReport(
            total_cves=len(entries),
            kev_count=kev_count,
            high_epss_count=high_epss_count,
            total_risk_boost=round(total_risk_boost, 2),
            entries=entries,
        )

    def enrich_findings_with_boost(
        self,
        findings: List[Finding],
        cve_map: Dict[str, str],
    ) -> List[Tuple[Finding, float]]:
        """Enrich findings with their CVE-based risk score boost.

        Args:
            findings: List of Finding objects.
            cve_map:  {rule_id: cve_id} mapping.

        Returns:
            List of (finding, boost_amount) tuples.
            boost_amount is 0.0 for findings with no CVE mapping.
        """
        results: List[Tuple[Finding, float]] = []
        intel_cache: Dict[str, AggregatedThreatIntel] = {}

        for finding in findings:
            cve_id = cve_map.get(finding.rule_id)
            if not cve_id:
                results.append((finding, 0.0))
                continue

            cve_id_upper = cve_id.strip().upper()
            if cve_id_upper not in intel_cache:
                try:
                    intel_cache[cve_id_upper] = self.aggregate(cve_id_upper)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Failed to enrich %s: %s", cve_id_upper, exc)
                    intel_cache[cve_id_upper] = AggregatedThreatIntel(
                        cve_id=cve_id_upper,
                        in_kev=False,
                        kev_date_added=None,
                        epss_score=0.0,
                        cvss_score=0.0,
                        otx_pulse_count=0,
                        iocs=[],
                        nuclei_template=False,
                        metasploit_module=False,
                        risk_score_boost=0.0,
                        aggregated_at=datetime.now(timezone.utc).isoformat(),
                        sources=[],
                    )

            boost = intel_cache[cve_id_upper].risk_score_boost
            results.append((finding, boost))

        return results

    def get_cached_intel(self, cve_id: str) -> Optional[AggregatedThreatIntel]:
        """Return cached intel for a CVE without triggering a live refresh.

        Returns None if not cached or if the cache entry is expired.
        """
        return self._load_from_cache(cve_id.strip().upper())


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------


def get_threat_intel(cve_id: str) -> AggregatedThreatIntel:
    """Return aggregated threat intel for a single CVE ID.

    Uses a fresh ThreatIntelAggregator instance with the default cache DB.
    """
    return ThreatIntelAggregator().aggregate(cve_id)
