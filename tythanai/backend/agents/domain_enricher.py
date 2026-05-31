"""
TythanAI — Domain Enricher
Maps security findings to ATT&CK/D3FEND/skill verification steps.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

# ─────────────────────────────────────────────────────────────────────────────
# Resolve Finding import — works in-tree or standalone
# ─────────────────────────────────────────────────────────────────────────────

try:
    from backend.core.confidence import Finding
except ModuleNotFoundError:
    _root = pathlib.Path(__file__).resolve().parents[2]
    _spec = importlib.util.spec_from_file_location(
        "confidence", _root / "backend" / "core" / "confidence.py"
    )
    _mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
    _spec.loader.exec_module(_mod)  # type: ignore[union-attr]
    Finding = _mod.Finding  # type: ignore[misc]

# Resolve SkillsLoader from the same package directory
try:
    from backend.agents.skills_loader import SkillsLoader, SkillMeta
except ModuleNotFoundError:
    _agents_dir = pathlib.Path(__file__).resolve().parent
    _sl_spec = importlib.util.spec_from_file_location(
        "skills_loader", _agents_dir / "skills_loader.py"
    )
    _sl_mod = importlib.util.module_from_spec(_sl_spec)  # type: ignore[arg-type]
    _sl_spec.loader.exec_module(_sl_mod)  # type: ignore[union-attr]
    SkillsLoader = _sl_mod.SkillsLoader  # type: ignore[misc]
    SkillMeta = _sl_mod.SkillMeta  # type: ignore[misc]


# ─────────────────────────────────────────────────────────────────────────────
# Domain mapping  (rule_id keyword → security domains)
# ─────────────────────────────────────────────────────────────────────────────

DOMAIN_MAP: Dict[str, List[str]] = {
    "sqli": ["web-application-security", "threat-hunting"],
    "xss": ["web-application-security"],
    "crypto": ["cryptography"],
    "auth": ["identity-access-management", "zero-trust-architecture"],
    "supply": ["devsecops", "vulnerability-management"],
    "container": ["container-security"],
    "secret": ["devsecops", "identity-access-management"],
    "malware": ["malware-analysis", "digital-forensics"],
    "iac": ["devsecops", "cloud-security"],
    "idor": ["web-application-security", "identity-access-management"],
    "ssrf": ["web-application-security", "api-security"],
    "cors": ["web-application-security", "api-security"],
    "path": ["web-application-security"],
    "deser": ["web-application-security"],
    "xxe": ["web-application-security"],
    "rce": ["web-application-security", "threat-hunting"],
    "cred": ["identity-access-management", "devsecops"],
    "injection": ["web-application-security"],
    # Additional mappings for broader rule_id coverage
    "jwt": ["identity-access-management"],
    "session": ["identity-access-management"],
    "csrf": ["web-application-security"],
    "hash": ["cryptography"],
    "tls": ["cryptography"],
    "ssl": ["cryptography"],
    "k8s": ["container-security"],
    "docker": ["container-security"],
    "s3": ["cloud-security"],
    "iam": ["cloud-security", "identity-access-management"],
    "lambda": ["cloud-security"],
    "rbac": ["identity-access-management", "container-security"],
    "api": ["api-security"],
    "rate": ["api-security"],
    "zero": ["zero-trust-architecture"],
    "lateral": ["threat-hunting"],
    "exfil": ["threat-hunting", "digital-forensics"],
    "persist": ["threat-hunting", "digital-forensics"],
    "priv": ["identity-access-management", "threat-hunting"],
    "log": ["digital-forensics"],
    "forensic": ["digital-forensics"],
    "incident": ["incident-response"],
    "triage": ["incident-response"],
    "sbom": ["devsecops"],
    "sast": ["devsecops"],
    "yara": ["malware-analysis"],
    "sandbox": ["malware-analysis"],
}

# CWE → ATT&CK technique mapping for enrichment fallback
_CWE_TO_ATTCK: Dict[str, List[str]] = {
    "CWE-89": ["T1190"],
    "CWE-79": ["T1059.007", "T1185"],
    "CWE-918": ["T1552.005", "T1190"],
    "CWE-639": ["T1078", "T1212"],
    "CWE-346": ["T1185"],
    "CWE-326": ["T1600"],
    "CWE-327": ["T1600.002", "T1110"],
    "CWE-287": ["T1078", "T1110"],
    "CWE-384": ["T1185", "T1539"],
    "CWE-308": ["T1621"],
    "CWE-269": ["T1078", "T1548"],
    "CWE-798": ["T1552", "T1552.001"],
    "CWE-494": ["T1195.001"],
    "CWE-732": ["T1530"],
    "CWE-649": ["T1600"],
    "CWE-208": ["T1557"],
    "CWE-522": ["T1003"],
    "CWE-915": ["T1190"],
}

# CWE → D3FEND countermeasure mapping
_CWE_TO_D3FEND: Dict[str, List[str]] = {
    "CWE-89": ["D3-DA", "D3-DENCR"],
    "CWE-79": ["D3-DA", "D3-OE"],
    "CWE-918": ["D3-NTA", "D3-DA"],
    "CWE-639": ["D3-HBPI", "D3-UAM"],
    "CWE-346": ["D3-OE", "D3-DA"],
    "CWE-326": ["D3-ECES"],
    "CWE-327": ["D3-ECES", "D3-DENCR"],
    "CWE-287": ["D3-MFA", "D3-UAM"],
    "CWE-384": ["D3-UAM", "D3-OE"],
    "CWE-308": ["D3-MFA"],
    "CWE-269": ["D3-UAM", "D3-HBPI"],
    "CWE-798": ["D3-CRED", "D3-DA"],
    "CWE-494": ["D3-SBOM", "D3-DA"],
    "CWE-732": ["D3-DA", "D3-DENCR"],
    "CWE-649": ["D3-ECES", "D3-NTA"],
    "CWE-208": ["D3-ECES"],
    "CWE-522": ["D3-CRED", "D3-UAM"],
    "CWE-915": ["D3-DA", "D3-HBPI"],
}


def _map_rule_to_domains(rule_id: str) -> List[str]:
    """
    Lowercase rule_id, check each DOMAIN_MAP key as a substring.
    Returns a deduplicated list of matching security domains.
    """
    rule_lower = rule_id.lower()
    domains: List[str] = []
    for keyword, domain_list in DOMAIN_MAP.items():
        if keyword in rule_lower:
            for domain in domain_list:
                if domain not in domains:
                    domains.append(domain)
    return domains


# ─────────────────────────────────────────────────────────────────────────────
# EnrichedFinding model
# ─────────────────────────────────────────────────────────────────────────────

class EnrichedFinding(BaseModel):
    """A security Finding enriched with ATT&CK/D3FEND/skill context."""

    # Original finding fields (mirrored for Pydantic v2 compatibility)
    rule_id: str
    file: str
    line: int = 0
    severity: str = "MEDIUM"
    confidence: float = 0.8
    cwe_id: str = ""
    description: str = ""
    recommendation: str = ""

    # Enrichment fields
    attck_ids: List[str] = Field(default_factory=list)
    d3fend_countermeasures: List[str] = Field(default_factory=list)
    skill_verification_steps: List[str] = Field(default_factory=list)
    skill_reference: str = ""
    domains: List[str] = Field(default_factory=list)

    @classmethod
    def from_finding(
        cls,
        finding: Finding,
        attck_ids: List[str],
        d3fend_countermeasures: List[str],
        skill_verification_steps: List[str],
        skill_reference: str,
        domains: List[str],
    ) -> "EnrichedFinding":
        return cls(
            rule_id=finding.rule_id,
            file=finding.file,
            line=finding.line,
            severity=finding.severity,
            confidence=finding.confidence,
            cwe_id=finding.cwe_id,
            description=finding.description,
            recommendation=getattr(finding, "recommendation", ""),
            attck_ids=attck_ids,
            d3fend_countermeasures=d3fend_countermeasures,
            skill_verification_steps=skill_verification_steps,
            skill_reference=skill_reference,
            domains=domains,
        )


# ─────────────────────────────────────────────────────────────────────────────
# DomainEnricher
# ─────────────────────────────────────────────────────────────────────────────

class DomainEnricher:
    """
    Maps security findings to ATT&CK techniques, D3FEND countermeasures,
    and skill-based verification steps using the embedded SkillsLoader registry.
    """

    def __init__(self) -> None:
        self._loader = SkillsLoader()

    def enrich_finding(self, finding: Finding) -> EnrichedFinding:
        """
        Enrich a single Finding with ATT&CK IDs, D3FEND countermeasures,
        skill verification steps, and domain mapping.

        Guarantees:
        - rule_id containing "sqli" → T1190 in attck_ids, D3-DA in d3fend_countermeasures
        """
        domains = _map_rule_to_domains(finding.rule_id)

        attck_ids: List[str] = []
        d3fend_ids: List[str] = []
        verification_steps: List[str] = []
        skill_reference = ""

        # 1. Collect ATT&CK / D3FEND from best matching skill per domain
        best_skills: List[SkillMeta] = []
        for domain in domains:
            skills = self._loader.search_by_domain(domain)
            if not skills:
                continue
            # Pick the skill whose tags best match the rule_id
            rule_lower = finding.rule_id.lower()
            scored = sorted(
                skills,
                key=lambda s: sum(1 for tag in s.tags if tag in rule_lower),
                reverse=True,
            )
            best = scored[0]
            if best not in best_skills:
                best_skills.append(best)

        for skill in best_skills:
            for tid in skill.mitre_ids:
                if tid not in attck_ids:
                    attck_ids.append(tid)
            for did in skill.d3fend_ids:
                if did not in d3fend_ids:
                    d3fend_ids.append(did)

        # 2. Use verification steps from the highest-priority skill
        if best_skills:
            primary_skill = best_skills[0]
            content = self._loader.load_skill(primary_skill.skill_id)
            if content:
                verification_steps = list(content.verification_steps)
            skill_reference = primary_skill.name

        # 3. Augment with CWE-based ATT&CK / D3FEND if cwe_id is available
        if finding.cwe_id:
            cwe_key = finding.cwe_id.upper().strip()
            for tid in _CWE_TO_ATTCK.get(cwe_key, []):
                if tid not in attck_ids:
                    attck_ids.append(tid)
            for did in _CWE_TO_D3FEND.get(cwe_key, []):
                if did not in d3fend_ids:
                    d3fend_ids.append(did)

        # 4. Guarantee: sqli rule_id must include T1190 and D3-DA
        rule_lower = finding.rule_id.lower()
        if "sqli" in rule_lower or "sql" in rule_lower:
            if "T1190" not in attck_ids:
                attck_ids.insert(0, "T1190")
            if "D3-DA" not in d3fend_ids:
                d3fend_ids.insert(0, "D3-DA")

        # 5. Fallback: if no domains found, use scan_all for context
        if not domains:
            fallback = self._loader.scan_all(
                finding.rule_id + " " + finding.description, top_n=3
            )
            for skill in fallback:
                domains.append(skill.domain)
                for tid in skill.mitre_ids:
                    if tid not in attck_ids:
                        attck_ids.append(tid)
                for did in skill.d3fend_ids:
                    if did not in d3fend_ids:
                        d3fend_ids.append(did)

        # Deduplicate domains
        seen_domains: List[str] = []
        for d in domains:
            if d not in seen_domains:
                seen_domains.append(d)

        return EnrichedFinding.from_finding(
            finding=finding,
            attck_ids=attck_ids,
            d3fend_countermeasures=d3fend_ids,
            skill_verification_steps=verification_steps[:8],  # cap at 8 steps
            skill_reference=skill_reference,
            domains=seen_domains,
        )

    def enrich_findings(self, findings: List[Finding]) -> List[EnrichedFinding]:
        """Enrich a batch of findings."""
        return [self.enrich_finding(f) for f in findings]
