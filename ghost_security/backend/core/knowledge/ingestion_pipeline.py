"""Knowledge Ingestion Pipeline — loads CVE/CWE/CAPEC/OWASP/advisory data into SecurityCorpus.

Offline-first: uses embedded static knowledge. Optionally enriches with live NVD/OSV.
Does NOT duplicate cve_enricher.py (finding enrichment) or security_memory.py (findings storage).
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass
class IngestionResult:
    """Summary of a corpus ingestion run."""
    entries_added: int = 0
    entries_updated: int = 0
    entries_skipped: int = 0
    errors: List[str] = field(default_factory=list)
    sources_used: List[str] = field(default_factory=list)
    elapsed_ms: float = 0.0

    def merge(self, other: "IngestionResult") -> "IngestionResult":
        return IngestionResult(
            entries_added=self.entries_added + other.entries_added,
            entries_updated=self.entries_updated + other.entries_updated,
            entries_skipped=self.entries_skipped + other.entries_skipped,
            errors=self.errors + other.errors,
            sources_used=list(set(self.sources_used + other.sources_used)),
        )

    def to_dict(self) -> dict:
        return {
            "entries_added": self.entries_added,
            "entries_updated": self.entries_updated,
            "entries_skipped": self.entries_skipped,
            "errors": self.errors,
            "sources_used": self.sources_used,
            "elapsed_ms": self.elapsed_ms,
        }


# ---------------------------------------------------------------------------
# Ingestion Pipeline
# ---------------------------------------------------------------------------


class CorpusIngestionPipeline:
    """Loads structured knowledge into a SecurityCorpus.

    All embedded ingestion methods work offline. Online methods require network.
    """

    def __init__(self, corpus: Any) -> None:
        """
        Parameters
        ----------
        corpus : SecurityCorpus
            The corpus to ingest into.
        """
        self._corpus = corpus

    # ------------------------------------------------------------------
    # Embedded (offline) ingestion
    # ------------------------------------------------------------------

    def ingest_cwe(self, cwe_id: Optional[str] = None) -> IngestionResult:
        """Ingest CWE entries from embedded corpus.

        If *cwe_id* is provided, ingests only that CWE. Otherwise all.
        """
        from backend.core.knowledge.security_corpus import (
            CWEEntry, CorpusEntryType, VerificationStatus,
            KnowledgeConfidenceScore, _EMBEDDED_CWES,
        )
        t = time.monotonic()
        result = IngestionResult(sources_used=["MITRE CWE (embedded)"])
        now = datetime.now(timezone.utc).isoformat()

        for cwe_data in _EMBEDDED_CWES:
            if cwe_id and cwe_data["cwe_id"] != cwe_id:
                continue
            existing = self._corpus.get(cwe_data["cwe_id"])
            if existing:
                result.entries_skipped += 1
                continue
            entry = CWEEntry(
                entry_id=cwe_data["cwe_id"],
                entry_type=CorpusEntryType.CWE,
                source="MITRE CWE",
                confidence=0.95,
                verification_status=VerificationStatus.VERIFIED,
                tags=["cwe", cwe_data.get("owasp_category", "").lower()],
                created_at=now,
                cwe_id=cwe_data["cwe_id"],
                name=cwe_data["name"],
                description=cwe_data["description"],
                owasp_category=cwe_data.get("owasp_category", ""),
                vulnerability_patterns=cwe_data.get("vulnerability_patterns", []),
                remediation_patterns=cwe_data.get("remediation_patterns", []),
                knowledge_score=KnowledgeConfidenceScore(
                    source_score=0.95, confirmation_count=10,
                    detection_success=0.85, remediation_success=0.80,
                ),
            )
            self._corpus.add(entry)
            result.entries_added += 1

        result.elapsed_ms = round((time.monotonic() - t) * 1000, 2)
        return result

    def ingest_capec(self, capec_id: Optional[str] = None) -> IngestionResult:
        """Ingest CAPEC attack patterns from embedded corpus."""
        from backend.core.knowledge.security_corpus import (
            CAPECEntry, CorpusEntryType, VerificationStatus, _EMBEDDED_CAPEC,
        )
        t = time.monotonic()
        result = IngestionResult(sources_used=["MITRE CAPEC (embedded)"])
        now = datetime.now(timezone.utc).isoformat()

        for capec_data in _EMBEDDED_CAPEC:
            if capec_id and capec_data["capec_id"] != capec_id:
                continue
            existing = self._corpus.get(capec_data["capec_id"])
            if existing:
                result.entries_skipped += 1
                continue
            entry = CAPECEntry(
                entry_id=capec_data["capec_id"],
                entry_type=CorpusEntryType.CAPEC,
                source="MITRE CAPEC",
                confidence=0.90,
                verification_status=VerificationStatus.VERIFIED,
                tags=["capec", "attack-pattern"],
                created_at=now,
                capec_id=capec_data["capec_id"],
                name=capec_data["name"],
                description=capec_data["description"],
                attack_steps=capec_data.get("attack_steps", []),
                related_cwes=capec_data.get("related_cwes", []),
                severity=capec_data.get("severity", "MEDIUM"),
                likelihood=capec_data.get("likelihood", "MEDIUM"),
            )
            self._corpus.add(entry)
            result.entries_added += 1

        result.elapsed_ms = round((time.monotonic() - t) * 1000, 2)
        return result

    def ingest_owasp(self) -> IngestionResult:
        """Ingest OWASP Top 10 2021 entries."""
        from backend.core.knowledge.security_corpus import (
            CorpusEntry, CorpusEntryType, VerificationStatus, _EMBEDDED_OWASP,
        )
        t = time.monotonic()
        result = IngestionResult(sources_used=["OWASP Top 10 2021 (embedded)"])
        now = datetime.now(timezone.utc).isoformat()

        for owasp_data in _EMBEDDED_OWASP:
            cat_id = owasp_data["category_id"]
            existing = self._corpus.get(cat_id)
            if existing:
                result.entries_skipped += 1
                continue
            entry = CorpusEntry(
                entry_id=cat_id,
                entry_type=CorpusEntryType.OWASP,
                source="OWASP Top 10 2021",
                confidence=1.0,
                verification_status=VerificationStatus.VERIFIED,
                tags=["owasp", f"rank-{owasp_data['rank']}"] + owasp_data["cwe_ids"],
                references=["https://owasp.org/Top10/"],
                created_at=now,
            )
            self._corpus.add(entry)
            result.entries_added += 1

        result.elapsed_ms = round((time.monotonic() - t) * 1000, 2)
        return result

    def ingest_cve_from_dict(self, cve_dict: Dict[str, Any]) -> IngestionResult:
        """Ingest a single CVE from a dict (e.g., from NVD/OSV API response)."""
        from backend.core.knowledge.security_corpus import (
            CVEEntry, CorpusEntryType, VerificationStatus, KnowledgeConfidenceScore,
        )
        t = time.monotonic()
        result = IngestionResult(sources_used=["manual"])

        cve_id = cve_dict.get("cve_id", "")
        if not cve_id:
            result.errors.append("Missing cve_id in cve_dict")
            return result

        existing = self._corpus.get(cve_id)
        now = datetime.now(timezone.utc).isoformat()

        epss = float(cve_dict.get("epss_score", 0.0))
        is_kev = bool(cve_dict.get("is_kev", False))
        source_score = 0.9 if is_kev else (0.7 + epss * 0.3)

        entry = CVEEntry(
            entry_id=cve_id,
            entry_type=CorpusEntryType.CVE,
            source=cve_dict.get("source", "NVD"),
            confidence=min(source_score, 1.0),
            verification_status=VerificationStatus.VERIFIED if is_kev else VerificationStatus.PARTIALLY_VERIFIED,
            tags=["cve"] + cve_dict.get("cwe_ids", []),
            references=cve_dict.get("references", []),
            created_at=now,
            cve_id=cve_id,
            description=cve_dict.get("description", ""),
            cvss_v3=float(cve_dict.get("cvss_v3", 0.0)),
            severity=cve_dict.get("severity", "UNKNOWN"),
            cwe_ids=cve_dict.get("cwe_ids", []),
            epss_score=epss,
            is_kev=is_kev,
            published=cve_dict.get("published", ""),
            affected_packages=cve_dict.get("affected_packages", []),
            knowledge_score=KnowledgeConfidenceScore(
                source_score=source_score,
                confirmation_count=2 if is_kev else 1,
                detection_success=0.0,
                remediation_success=0.0,
            ),
        )

        self._corpus.add(entry)
        if existing:
            result.entries_updated += 1
        else:
            result.entries_added += 1

        result.elapsed_ms = round((time.monotonic() - t) * 1000, 2)
        return result

    def ingest_findings(self, findings: List[Any]) -> IngestionResult:
        """Correlate confirmed findings into the corpus as research entries."""
        from backend.core.knowledge.security_corpus import (
            ResearchEntry, CorpusEntryType, VerificationStatus,
        )
        t = time.monotonic()
        result = IngestionResult(sources_used=["findings"])
        now = datetime.now(timezone.utc).isoformat()

        for finding in findings:
            cwe_id = getattr(finding, "cwe_id", "") or (finding.get("cwe_id", "") if isinstance(finding, dict) else "")
            rule_id = getattr(finding, "rule_id", "") or (finding.get("rule_id", "") if isinstance(finding, dict) else "")
            entry_id = f"finding::{rule_id}"

            existing = self._corpus.get(entry_id)
            if existing:
                result.entries_skipped += 1
                continue

            entry = ResearchEntry(
                entry_id=entry_id,
                entry_type=CorpusEntryType.RESEARCH,
                source="confirmed_finding",
                confidence=float(getattr(finding, "confidence", 0.8)),
                verification_status=VerificationStatus.PARTIALLY_VERIFIED,
                tags=["finding", cwe_id.lower(), rule_id],
                created_at=now,
                title=f"Finding: {rule_id}",
                cwe_ids=[cwe_id] if cwe_id else [],
                findings_summary=getattr(finding, "description", ""),
            )
            self._corpus.add(entry)
            result.entries_added += 1

        result.elapsed_ms = round((time.monotonic() - t) * 1000, 2)
        return result

    def run_full_ingestion(self) -> IngestionResult:
        """Run all offline ingestion sources: CWE + CAPEC + OWASP."""
        t = time.monotonic()
        total = IngestionResult()

        for method in (self.ingest_cwe, self.ingest_capec, self.ingest_owasp):
            try:
                r = method()
                total = total.merge(r)
            except Exception as exc:
                total.errors.append(f"{method.__name__}: {exc}")

        total.elapsed_ms = round((time.monotonic() - t) * 1000, 2)
        return total

    # ------------------------------------------------------------------
    # Online enrichment (best-effort, no crash if network unavailable)
    # ------------------------------------------------------------------

    def enrich_cve_from_osv(self, package: str, version: str, ecosystem: str = "PyPI") -> IngestionResult:
        """Attempt OSV.dev query and ingest results. Silently returns empty on network failure."""
        result = IngestionResult(sources_used=["OSV"])
        try:
            import urllib.request
            import json as _json
            payload = _json.dumps({
                "package": {"name": package, "ecosystem": ecosystem},
                "version": version,
            }).encode()
            req = urllib.request.Request(
                "https://api.osv.dev/v1/query",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = _json.loads(resp.read())
            for vuln in data.get("vulns", []):
                aliases = vuln.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id", ""))
                if not cve_id:
                    continue
                r = self.ingest_cve_from_dict({
                    "cve_id": cve_id,
                    "description": vuln.get("summary", ""),
                    "source": "OSV",
                    "affected_packages": [package],
                })
                result = result.merge(r)
        except Exception as exc:
            logger.debug("OSV enrichment failed (offline mode): %s", exc)
        return result
