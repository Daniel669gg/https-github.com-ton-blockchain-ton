"""
Ghost Security — EPSS + CISA KEV Enricher

Upgrades every CVE finding with:
  • EPSS score (0–1)  — probability this CVE will be exploited in next 30 days
  • EPSS percentile   — how dangerous vs all other CVEs
  • CISA KEV flag     — whether CISA declared it "actively exploited right now"
  • Priority score    — composite score used to sort and triage findings

APIs used (both free, no key):
  • EPSS:     https://api.first.org/data/v1/epss
  • CISA KEV: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Usage:
    from scanners.epss_enricher import EPSSEnricher
    enricher = EPSSEnricher()
    findings = enricher.enrich(findings)   # adds epss_score, kev, priority_score
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Set, Tuple

EPSS_API      = "https://api.first.org/data/v1/epss"
CISA_KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_TIMEOUT      = 10
_BATCH        = 100   # EPSS supports up to 100 CVEs per request


def _fetch_json(url: str, timeout: int = _TIMEOUT) -> Optional[dict]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Ghost-Security/10"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except Exception:
        return None


class EPSSEnricher:
    """
    Enriches findings with EPSS scores and CISA KEV status.
    Results are cached in memory for the lifetime of the object.
    """

    def __init__(self, timeout: int = _TIMEOUT) -> None:
        self._timeout      = timeout
        self._epss_cache:  Dict[str, Tuple[float, float]] = {}  # cve → (score, percentile)
        self._kev_cache:   Optional[Set[str]] = None
        self._online:      Optional[bool] = None

    # ── Public API ─────────────────────────────────────────────────────────────

    def enrich(self, findings: List[Dict]) -> List[Dict]:
        """
        Add EPSS + KEV data to every finding.
        CVE findings get live EPSS scores; non-CVE findings get priority_score
        based on severity + confidence only (epss_score defaults to 0).
        Modifies findings in-place and returns them sorted by priority_score desc.
        """
        cve_ids = self._extract_cves(findings)
        if cve_ids:
            self._fetch_epss(cve_ids)
        kev_set = self._fetch_kev()

        for f in findings:
            cve = self._get_cve(f)
            if cve:
                epss_score, epss_pct = self._epss_cache.get(cve, (0.0, 0.0))
                in_kev = cve in kev_set if kev_set else False
                f["epss_score"]      = round(epss_score, 4)
                f["epss_percentile"] = round(epss_pct, 2)
                f["cisa_kev"]        = in_kev
            else:
                f.setdefault("epss_score", 0.0)
                f.setdefault("epss_percentile", 0.0)
                f.setdefault("cisa_kev", False)
                in_kev     = False
                epss_score = 0.0

            f["priority_score"] = self._priority(f, f.get("epss_score", 0.0), f.get("cisa_kev", False))
            f["exploit_status"] = self._exploit_label(f.get("epss_score", 0.0), f.get("cisa_kev", False))

        # Sort highest priority first
        findings.sort(key=lambda f: f.get("priority_score", 0), reverse=True)
        return findings

    def enrich_one(self, cve: str) -> Dict:
        """Look up a single CVE. Returns enrichment dict."""
        self._fetch_epss([cve])
        kev = self._fetch_kev()
        score, pct = self._epss_cache.get(cve, (0.0, 0.0))
        in_kev     = cve in kev if kev else False
        return {
            "cve":             cve,
            "epss_score":      round(score, 4),
            "epss_percentile": round(pct, 2),
            "cisa_kev":        in_kev,
            "exploit_status":  self._exploit_label(score, in_kev),
        }

    def is_online(self) -> bool:
        if self._online is None:
            data = _fetch_json(f"{EPSS_API}?cve=CVE-2021-44228", timeout=4)
            self._online = data is not None
        return self._online

    # ── Internal ───────────────────────────────────────────────────────────────

    def _extract_cves(self, findings: List[Dict]) -> List[str]:
        seen, result = set(), []
        for f in findings:
            cve = self._get_cve(f)
            if cve and cve not in seen:
                seen.add(cve)
                result.append(cve)
        return result

    @staticmethod
    def _get_cve(f: Dict) -> Optional[str]:
        for key in ("cve", "id", "cve_id", "osv_id"):
            val = str(f.get(key, ""))
            if val.upper().startswith("CVE-"):
                return val.upper()
        return None

    def _fetch_epss(self, cve_ids: List[str]) -> None:
        """Fetch EPSS scores for a list of CVEs, skipping already cached."""
        to_fetch = [c for c in cve_ids if c not in self._epss_cache]
        if not to_fetch:
            return

        for i in range(0, len(to_fetch), _BATCH):
            batch = to_fetch[i : i + _BATCH]
            cve_param = ",".join(batch)
            url  = f"{EPSS_API}?cve={cve_param}&envelope=true"
            data = _fetch_json(url, self._timeout)
            if not data:
                for c in batch:
                    self._epss_cache[c] = (0.0, 0.0)
                continue
            for entry in data.get("data", []):
                cve  = entry.get("cve", "").upper()
                score = float(entry.get("epss", 0))
                pct   = float(entry.get("percentile", 0)) * 100
                self._epss_cache[cve] = (score, pct)
            # Mark unfound as 0
            for c in batch:
                if c not in self._epss_cache:
                    self._epss_cache[c] = (0.0, 0.0)

    def _fetch_kev(self) -> Set[str]:
        if self._kev_cache is not None:
            return self._kev_cache
        data = _fetch_json(CISA_KEV_URL, self._timeout)
        if not data:
            self._kev_cache = set()
            return self._kev_cache
        self._kev_cache = {
            v.get("cveID", "").upper()
            for v in data.get("vulnerabilities", [])
        }
        return self._kev_cache

    @staticmethod
    def _priority(f: Dict, epss: float, kev: bool) -> float:
        """
        Priority score 0–100 combining:
          40% severity, 30% EPSS, 20% KEV bonus, 10% confidence
        """
        sev_map = {"CRITICAL": 10, "HIGH": 7.5, "MEDIUM": 5, "LOW": 2, "INFO": 0.5}
        sev   = sev_map.get(f.get("severity", "LOW"), 2)
        conf  = float(f.get("confidence", 75)) / 100
        score = (sev / 10) * 40 + epss * 30 + (20 if kev else 0) + conf * 10
        return round(score, 2)

    @staticmethod
    def _exploit_label(epss: float, kev: bool) -> str:
        if kev:
            return "🔴 ACTIVELY EXPLOITED (CISA KEV)"
        if epss >= 0.5:
            return f"🟠 HIGH EXPLOIT PROBABILITY ({epss:.0%})"
        if epss >= 0.1:
            return f"🟡 MODERATE EXPLOIT PROBABILITY ({epss:.0%})"
        if epss > 0:
            return f"🟢 LOW EXPLOIT PROBABILITY ({epss:.1%})"
        return "⚪ NO EXPLOIT DATA"
