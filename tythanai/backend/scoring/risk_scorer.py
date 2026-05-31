"""
backend/scoring/risk_scorer.py — Risk Scorer (Phase 1)

Formula (0–100):
  severity score    0–40   (based on severity level)
  EPSS score        0–30   (FIRST EPSS API, CVE-based, cached)
  external exposure 0–20   (heuristic from finding metadata)
  data criticality  0–10   (heuristic from finding metadata)

Reports are sorted by risk_score descending, not by severity.
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
from functools import lru_cache
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, Field

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.risk_scorer")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_BASE: Dict[str, float] = {
    "CRITICAL": 40.0,
    "HIGH": 28.0,
    "MEDIUM": 16.0,
    "LOW": 6.0,
    "INFO": 1.0,
}

_EPSS_API_URL = "https://api.first.org/data/v1/epss"
_EPSS_CACHE_TTL = 3600 * 24         # 24 h

# Patterns that suggest external/internet-facing exposure
_EXPOSURE_PATTERNS = [
    re.compile(r"\bapi\b", re.I),
    re.compile(r"\bhttp\b", re.I),
    re.compile(r"\bendpoint\b", re.I),
    re.compile(r"\bpublic\b", re.I),
    re.compile(r"\bexternal\b", re.I),
    re.compile(r"\binternet\b", re.I),
    re.compile(r"\bwebsocket\b", re.I),
    re.compile(r"\bgrpc\b", re.I),
    re.compile(r"\brouter\b", re.I),
    re.compile(r"\brequest\b", re.I),
]

# Patterns that suggest high data criticality
_CRITICALITY_PATTERNS = [
    re.compile(r"\bpassword\b", re.I),
    re.compile(r"\bsecret\b", re.I),
    re.compile(r"\btoken\b", re.I),
    re.compile(r"\bprivate.key\b", re.I),
    re.compile(r"\bcredit\b", re.I),
    re.compile(r"\bpayment\b", re.I),
    re.compile(r"\bpii\b", re.I),
    re.compile(r"\bpersonal\b", re.I),
    re.compile(r"\bauth\b", re.I),
    re.compile(r"\badmin\b", re.I),
]

# ─────────────────────────────────────────────────────────────────────────────
# EPSS cache
# ─────────────────────────────────────────────────────────────────────────────

class _EpssCache:
    def __init__(self, ttl: int = _EPSS_CACHE_TTL) -> None:
        self._cache: Dict[str, Tuple[float, float]] = {}  # cve → (epss, expires_at)
        self._ttl = ttl

    def get(self, cve: str) -> Optional[float]:
        entry = self._cache.get(cve.upper())
        if entry and time.time() < entry[1]:
            return entry[0]
        return None

    def set(self, cve: str, score: float) -> None:
        self._cache[cve.upper()] = (score, time.time() + self._ttl)

    def size(self) -> int:
        return len(self._cache)


_epss_cache = _EpssCache()


def _fetch_epss(cve_id: str) -> float:
    """
    Fetch EPSS score from FIRST API.
    Returns 0.0 on any failure (network unavailable, CVE not found, etc.).
    Score range: 0.0–1.0 (probability of exploitation in 30 days).
    """
    cached = _epss_cache.get(cve_id)
    if cached is not None:
        return cached

    try:
        import urllib.request
        import json as _json
        url = f"{_EPSS_API_URL}?cve={cve_id}"
        with urllib.request.urlopen(url, timeout=4) as resp:
            data = _json.loads(resp.read())
        score = float(data["data"][0]["epss"])
        _epss_cache.set(cve_id, score)
        return score
    except Exception as exc:
        logger.debug("EPSS fetch failed for %s: %s", cve_id, exc)
        _epss_cache.set(cve_id, 0.0)   # negative cache to avoid hammering
        return 0.0


# ─────────────────────────────────────────────────────────────────────────────
# Score components
# ─────────────────────────────────────────────────────────────────────────────

def _severity_score(severity: str) -> float:
    return _SEVERITY_BASE.get(severity.upper(), 8.0)


def _epss_score(cve_id: str) -> float:
    """Scale EPSS probability (0–1) to 0–30."""
    if not cve_id or not cve_id.upper().startswith("CVE-"):
        return 0.0
    epss = _fetch_epss(cve_id)
    return round(epss * 30.0, 2)


def _exposure_score(finding: Finding) -> float:
    """
    Heuristic external-exposure score 0–20.
    Checks rule_id, description, file path, and extra fields.
    """
    text = " ".join([
        finding.rule_id,
        finding.description,
        finding.file,
        finding.recommendation,
        *finding.sources,
    ]).lower()

    hits = sum(1 for p in _EXPOSURE_PATTERNS if p.search(text))
    # Normalize: 5+ hits → 20, linear below
    return min(hits / 5.0 * 20.0, 20.0)


def _criticality_score(finding: Finding) -> float:
    """
    Heuristic data-criticality score 0–10.
    """
    text = " ".join([
        finding.rule_id,
        finding.description,
        finding.file,
        *finding.sources,
    ]).lower()

    hits = sum(1 for p in _CRITICALITY_PATTERNS if p.search(text))
    return min(hits / 3.0 * 10.0, 10.0)


# ─────────────────────────────────────────────────────────────────────────────
# Risk score result model
# ─────────────────────────────────────────────────────────────────────────────

class RiskScore(BaseModel):
    rule_id: str
    file: str
    line: int
    severity: str
    cwe_id: str
    description: str
    risk_score: float = Field(ge=0.0, le=100.0)
    severity_component: float
    epss_component: float
    exposure_component: float
    criticality_component: float
    cve_id: str = ""
    confidence: float

    def label(self) -> str:
        if self.risk_score >= 75:
            return "CRITICAL_RISK"
        if self.risk_score >= 50:
            return "HIGH_RISK"
        if self.risk_score >= 25:
            return "MEDIUM_RISK"
        return "LOW_RISK"


# ─────────────────────────────────────────────────────────────────────────────
# Risk scorer
# ─────────────────────────────────────────────────────────────────────────────

class RiskScorer:
    """
    Computes risk score for each Finding and returns a sorted report.

    risk_score = severity(0–40) + EPSS(0–30) + exposure(0–20) + criticality(0–10)
    """

    def __init__(self, fetch_epss: bool = True) -> None:
        self._fetch_epss = fetch_epss

    def score(self, finding: Finding, cve_id: str = "") -> RiskScore:
        sev_c = _severity_score(finding.severity)
        epss_c = _epss_score(cve_id) if (self._fetch_epss and cve_id) else 0.0
        exp_c = _exposure_score(finding)
        crit_c = _criticality_score(finding)

        total = min(sev_c + epss_c + exp_c + crit_c, 100.0)

        return RiskScore(
            rule_id=finding.rule_id,
            file=finding.file,
            line=finding.line,
            severity=finding.severity,
            cwe_id=finding.cwe_id,
            description=finding.description,
            risk_score=round(total, 2),
            severity_component=round(sev_c, 2),
            epss_component=round(epss_c, 2),
            exposure_component=round(exp_c, 2),
            criticality_component=round(crit_c, 2),
            cve_id=cve_id,
            confidence=finding.confidence,
        )

    def score_all(
        self,
        findings: Sequence[Finding],
        cve_map: Optional[Dict[str, str]] = None,
    ) -> List[RiskScore]:
        """
        Score all findings and return sorted by risk_score descending.

        cve_map: optional mapping of finding fingerprint → CVE-ID.
        """
        cve_map = cve_map or {}
        scored: List[RiskScore] = []
        for f in findings:
            cve_id = cve_map.get(f.fingerprint(), "")
            rs = self.score(f, cve_id)
            scored.append(rs)
        scored.sort(key=lambda r: r.risk_score, reverse=True)
        return scored

    def build_report(
        self,
        findings: Sequence[Finding],
        cve_map: Optional[Dict[str, str]] = None,
        top_n: int = 20,
    ) -> Dict[str, Any]:
        scored = self.score_all(findings, cve_map)
        label_counts: Dict[str, int] = {}
        for rs in scored:
            lbl = rs.label()
            label_counts[lbl] = label_counts.get(lbl, 0) + 1

        avg = sum(r.risk_score for r in scored) / len(scored) if scored else 0.0

        return {
            "total": len(scored),
            "average_risk_score": round(avg, 2),
            "label_distribution": label_counts,
            "top_findings": [r.model_dump() for r in scored[:top_n]],
            "all_findings_sorted": [r.model_dump() for r in scored],
        }
