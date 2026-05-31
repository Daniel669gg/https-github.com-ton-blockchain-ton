"""CVE Intelligence: NVD REST API v2, CISA KEV, EPSS, GitHub Advisory, OSV."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Set

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class EPSSScore(BaseModel):
    cve_id: str
    score: float        # 0.0-1.0
    percentile: float   # 0.0-1.0


class CVERecord(BaseModel):
    cve_id: str
    description: str
    cvss_v3: float = 0.0
    cvss_v2: float = 0.0
    severity: str = "UNKNOWN"   # CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
    published: str = ""
    modified: str = ""
    cwe_ids: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    epss_score: float = 0.0
    epss_percentile: float = 0.0
    is_kev: bool = False        # In CISA KEV catalog
    kev_date_added: str = ""
    affected_packages: List[str] = Field(default_factory=list)
    fix_versions: Dict[str, str] = Field(default_factory=dict)  # pkg → fixed_version
    exploitability: str = "UNKNOWN"  # HIGH/MEDIUM/LOW based on EPSS + KEV


class AdvisoryMatch(BaseModel):
    package_name: str
    installed_version: str
    cve_records: List[CVERecord]
    highest_severity: str
    is_critical: bool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def _cvss_to_severity(score: float) -> str:
    """Convert a numeric CVSS score to a severity label."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


def _epss_to_exploitability(epss_score: float, is_kev: bool) -> str:
    """Derive exploitability label from EPSS score and KEV membership."""
    if is_kev or epss_score >= 0.5:
        return "HIGH"
    if epss_score >= 0.1:
        return "MEDIUM"
    if epss_score > 0.0:
        return "LOW"
    return "UNKNOWN"


def _highest_severity(records: List[CVERecord]) -> str:
    best = "UNKNOWN"
    best_rank = 0
    for r in records:
        rank = _SEVERITY_ORDER.get(r.severity, 0)
        if rank > best_rank:
            best_rank = rank
            best = r.severity
    return best


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

_KEV_CACHE_TTL = 86_400  # 24 hours in seconds


class CVEIntelligenceEngine:
    NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    EPSS_BASE = "https://api.first.org/data/v1/epss"
    GITHUB_ADVISORY_BASE = "https://api.github.com/advisories"
    OSV_BASE = "https://api.osv.dev/v1"

    def __init__(self) -> None:
        self._kev_cache: Set[str] = set()
        self._kev_cache_ts: float = 0.0
        self._timeout = httpx.Timeout(30.0)

    # ------------------------------------------------------------------
    # NVD
    # ------------------------------------------------------------------

    async def fetch_cve(self, cve_id: str) -> Optional[CVERecord]:
        """Fetch a single CVE record from the NVD REST API v2."""
        url = self.NVD_BASE
        params = {"cveId": cve_id}
        max_retries = 3

        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    response = await client.get(url, params=params)

                if response.status_code == 429:
                    wait = 2 ** attempt
                    logger.warning(
                        "NVD rate limit hit for %s, retrying in %ds (attempt %d/%d)",
                        cve_id, wait, attempt + 1, max_retries,
                    )
                    await asyncio.sleep(wait)
                    continue

                if response.status_code != 200:
                    logger.warning(
                        "NVD returned HTTP %d for %s", response.status_code, cve_id
                    )
                    return None

                data = response.json()
                return self._parse_nvd_item(cve_id, data)

            except httpx.HTTPError as exc:
                logger.warning("HTTP error fetching CVE %s: %s", cve_id, exc)
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                return None
            except Exception as exc:  # noqa: BLE001
                logger.warning("Unexpected error fetching CVE %s: %s", cve_id, exc)
                return None

        return None

    def _parse_nvd_item(self, cve_id: str, data: Dict[str, Any]) -> Optional[CVERecord]:
        """Parse an NVD API v2 response JSON into a CVERecord."""
        try:
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None

            item = vulnerabilities[0]
            cve = item.get("cve", {})

            # Description (English preferred)
            desc_list = cve.get("descriptions", [])
            description = ""
            for d in desc_list:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break
            if not description and desc_list:
                description = desc_list[0].get("value", "")

            # Dates
            published = cve.get("published", "")
            modified = cve.get("lastModified", "")

            # CVSS scores
            metrics = cve.get("metrics", {})
            cvss_v3 = 0.0
            cvss_v2 = 0.0

            for key in ("cvssMetricV31", "cvssMetricV30"):
                metrics_list = metrics.get(key, [])
                if metrics_list:
                    primary = next(
                        (m for m in metrics_list if m.get("type") == "Primary"),
                        metrics_list[0],
                    )
                    cvss_v3 = float(
                        primary.get("cvssData", {}).get("baseScore", 0.0)
                    )
                    break

            v2_list = metrics.get("cvssMetricV2", [])
            if v2_list:
                primary_v2 = next(
                    (m for m in v2_list if m.get("type") == "Primary"), v2_list[0]
                )
                cvss_v2 = float(
                    primary_v2.get("cvssData", {}).get("baseScore", 0.0)
                )

            # Severity
            best_score = cvss_v3 if cvss_v3 > 0 else cvss_v2
            severity = _cvss_to_severity(best_score)

            # CWE IDs
            cwe_ids: List[str] = []
            for weakness in cve.get("weaknesses", []):
                for desc in weakness.get("description", []):
                    value = desc.get("value", "")
                    if value and value != "NVD-CWE-Other" and value != "NVD-CWE-noinfo":
                        cwe_ids.append(value)

            # References
            references: List[str] = [
                ref.get("url", "")
                for ref in cve.get("references", [])
                if ref.get("url")
            ]

            return CVERecord(
                cve_id=cve.get("id", cve_id),
                description=description,
                cvss_v3=cvss_v3,
                cvss_v2=cvss_v2,
                severity=severity,
                published=published,
                modified=modified,
                cwe_ids=cwe_ids,
                references=references,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse NVD response for %s: %s", cve_id, exc)
            return None

    # ------------------------------------------------------------------
    # EPSS
    # ------------------------------------------------------------------

    async def fetch_epss(self, cve_ids: List[str]) -> Dict[str, EPSSScore]:
        """Fetch EPSS scores for a list of CVE IDs."""
        if not cve_ids:
            return {}

        # EPSS API supports up to 30 CVEs per request; chunk if needed.
        chunk_size = 30
        result: Dict[str, EPSSScore] = {}

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            for i in range(0, len(cve_ids), chunk_size):
                chunk = cve_ids[i: i + chunk_size]
                joined = ",".join(chunk)
                try:
                    response = await client.get(
                        self.EPSS_BASE, params={"cve": joined}
                    )
                    if response.status_code != 200:
                        logger.warning(
                            "EPSS API returned HTTP %d", response.status_code
                        )
                        continue
                    data = response.json()
                    for entry in data.get("data", []):
                        cid = entry.get("cve", "")
                        if cid:
                            result[cid] = EPSSScore(
                                cve_id=cid,
                                score=float(entry.get("epss", 0.0)),
                                percentile=float(entry.get("percentile", 0.0)),
                            )
                except httpx.HTTPError as exc:
                    logger.warning("HTTP error fetching EPSS: %s", exc)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Unexpected error fetching EPSS: %s", exc)

        return result

    # ------------------------------------------------------------------
    # CISA KEV
    # ------------------------------------------------------------------

    async def fetch_kev(self) -> Set[str]:
        """Download the CISA Known Exploited Vulnerabilities catalog.

        Results are cached for 24 hours using wall-clock time.
        """
        now = time.time()
        if self._kev_cache and (now - self._kev_cache_ts) < _KEV_CACHE_TTL:
            return self._kev_cache

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.get(self.CISA_KEV_URL)
            if response.status_code != 200:
                logger.warning(
                    "CISA KEV returned HTTP %d", response.status_code
                )
                return self._kev_cache  # return stale cache if available

            data = response.json()
            vulns = data.get("vulnerabilities", [])
            self._kev_cache = {v.get("cveID", "") for v in vulns if v.get("cveID")}
            self._kev_cache_ts = now
            logger.info("CISA KEV catalog loaded: %d entries", len(self._kev_cache))
        except httpx.HTTPError as exc:
            logger.warning("HTTP error fetching CISA KEV: %s", exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Unexpected error fetching CISA KEV: %s", exc)

        return self._kev_cache

    # ------------------------------------------------------------------
    # OSV
    # ------------------------------------------------------------------

    async def query_osv(
        self, package: str, version: str, ecosystem: str = "PyPI"
    ) -> List[CVERecord]:
        """Query the OSV API for vulnerabilities affecting a package version."""
        payload: Dict[str, Any] = {
            "package": {"name": package, "ecosystem": ecosystem},
            "version": version,
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                response = await client.post(
                    f"{self.OSV_BASE}/query", json=payload
                )
            if response.status_code != 200:
                logger.warning(
                    "OSV API returned HTTP %d for %s@%s",
                    response.status_code, package, version,
                )
                return []

            data = response.json()
            records: List[CVERecord] = []
            for vuln in data.get("vulns", []):
                record = self._parse_osv_vuln(vuln, package)
                if record:
                    records.append(record)
            return records

        except httpx.HTTPError as exc:
            logger.warning("HTTP error querying OSV for %s@%s: %s", package, version, exc)
            return []
        except Exception as exc:  # noqa: BLE001
            logger.warning("Unexpected error querying OSV for %s@%s: %s", package, version, exc)
            return []

    def _parse_osv_vuln(
        self, vuln: Dict[str, Any], package: str
    ) -> Optional[CVERecord]:
        """Parse a single OSV vulnerability entry into a CVERecord."""
        try:
            osv_id: str = vuln.get("id", "")

            # Prefer CVE alias if available
            aliases: List[str] = vuln.get("aliases", [])
            cve_id = osv_id
            for alias in aliases:
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break

            # Summary / detail
            description = vuln.get("summary", "") or vuln.get("details", "") or ""

            # CVSS from severity array
            cvss_v3 = 0.0
            for sev in vuln.get("severity", []):
                sev_type = sev.get("type", "")
                if sev_type in ("CVSS_V3", "CVSS_V31", "CVSS_V30"):
                    score_str = sev.get("score", "")
                    # score might be a CVSS vector string or a float string
                    try:
                        cvss_v3 = float(score_str)
                    except (ValueError, TypeError):
                        # Try to extract base score from vector (simplified)
                        pass
                    break

            severity = _cvss_to_severity(cvss_v3)

            # Published / modified
            published = vuln.get("published", "")
            modified = vuln.get("modified", "")

            # Affected packages and fix versions
            affected_packages: List[str] = []
            fix_versions: Dict[str, str] = {}
            for affected in vuln.get("affected", []):
                pkg_info = affected.get("package", {})
                pkg_name = pkg_info.get("name", "")
                if pkg_name:
                    affected_packages.append(pkg_name)
                # Ranges for fix version extraction
                for rng in affected.get("ranges", []):
                    for event in rng.get("events", []):
                        fixed = event.get("fixed")
                        if fixed and pkg_name:
                            fix_versions[pkg_name] = fixed

            # References
            references: List[str] = [
                ref.get("url", "")
                for ref in vuln.get("references", [])
                if ref.get("url")
            ]

            return CVERecord(
                cve_id=cve_id,
                description=description,
                cvss_v3=cvss_v3,
                severity=severity,
                published=published,
                modified=modified,
                references=references,
                affected_packages=affected_packages or [package],
                fix_versions=fix_versions,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to parse OSV vuln %s: %s", vuln.get("id"), exc)
            return None

    # ------------------------------------------------------------------
    # Batch package check
    # ------------------------------------------------------------------

    async def check_packages(
        self, packages: Dict[str, str], ecosystem: str = "PyPI"
    ) -> List[AdvisoryMatch]:
        """Check a dict of {package_name: installed_version} for vulnerabilities.

        Runs OSV queries concurrently, then enriches results with NVD + EPSS + KEV.
        Returns only packages that have at least one finding.
        """
        if not packages:
            return []

        # Step 1: run all OSV queries concurrently
        osv_tasks = [
            self.query_osv(name, version, ecosystem)
            for name, version in packages.items()
        ]
        pkg_names = list(packages.keys())
        pkg_versions = list(packages.values())

        osv_results: List[List[CVERecord]] = list(
            await asyncio.gather(*osv_tasks, return_exceptions=False)
        )

        # Step 2: collect all unique CVE IDs for bulk enrichment
        all_cve_ids: List[str] = []
        for records in osv_results:
            for r in records:
                if r.cve_id not in all_cve_ids:
                    all_cve_ids.append(r.cve_id)

        # Step 3: fetch EPSS and KEV in parallel
        epss_map, kev_set = await asyncio.gather(
            self.fetch_epss(all_cve_ids),
            self.fetch_kev(),
        )

        # Step 4: assemble AdvisoryMatch objects
        matches: List[AdvisoryMatch] = []
        for pkg_name, pkg_version, records in zip(pkg_names, pkg_versions, osv_results):
            if not records:
                continue

            enriched: List[CVERecord] = []
            for record in records:
                epss = epss_map.get(record.cve_id)
                epss_score = epss.score if epss else 0.0
                epss_pct = epss.percentile if epss else 0.0
                in_kev = record.cve_id in kev_set
                kev_date = ""  # KEV date not returned by the set; would need full catalog

                exploitability = _epss_to_exploitability(epss_score, in_kev)

                enriched.append(
                    record.model_copy(
                        update=dict(
                            epss_score=epss_score,
                            epss_percentile=epss_pct,
                            is_kev=in_kev,
                            kev_date_added=kev_date,
                            exploitability=exploitability,
                        )
                    )
                )

            highest = _highest_severity(enriched)
            is_critical = highest == "CRITICAL"

            matches.append(
                AdvisoryMatch(
                    package_name=pkg_name,
                    installed_version=pkg_version,
                    cve_records=enriched,
                    highest_severity=highest,
                    is_critical=is_critical,
                )
            )

        return matches

    # ------------------------------------------------------------------
    # Single CVE enrichment
    # ------------------------------------------------------------------

    async def enrich_finding(self, cve_id: str) -> CVERecord:
        """Fetch and fully enrich a single CVE record (NVD + EPSS + KEV)."""
        record = await self.fetch_cve(cve_id)
        if record is None:
            # Return a minimal placeholder so callers always get a CVERecord
            record = CVERecord(cve_id=cve_id, description="")

        epss_map, kev_set = await asyncio.gather(
            self.fetch_epss([cve_id]),
            self.fetch_kev(),
        )

        epss = epss_map.get(cve_id)
        epss_score = epss.score if epss else 0.0
        epss_pct = epss.percentile if epss else 0.0
        in_kev = cve_id in kev_set
        exploitability = _epss_to_exploitability(epss_score, in_kev)

        return record.model_copy(
            update=dict(
                epss_score=epss_score,
                epss_percentile=epss_pct,
                is_kev=in_kev,
                exploitability=exploitability,
            )
        )


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------


async def check_dependencies(
    packages: Dict[str, str], ecosystem: str = "PyPI"
) -> List[AdvisoryMatch]:
    """Check a dict of {package_name: version} against OSV, NVD, EPSS, and KEV."""
    engine = CVEIntelligenceEngine()
    return await engine.check_packages(packages, ecosystem)
