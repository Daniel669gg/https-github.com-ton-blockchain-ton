"""Sigma Detection Rule Generator — converts TythanAI findings to Sigma YAML rules.

Sigma is the standard detection format for SIEM systems (Splunk, Elastic, Chronicle, QRadar).
Rules generated here conform to the Sigma specification:
https://sigmahq.io/sigma-specification/
"""
from __future__ import annotations

import logging
import os
import uuid
from datetime import date
from enum import Enum
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.sigma_generator")


# ─────────────────────────────────────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────────────────────────────────────


class SigmaLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class SigmaStatus(str, Enum):
    STABLE = "stable"
    TEST = "test"
    EXPERIMENTAL = "experimental"


# ─────────────────────────────────────────────────────────────────────────────
# Detection condition helper
# ─────────────────────────────────────────────────────────────────────────────


class SigmaDetectionCondition(BaseModel):
    """Intermediate representation of a Sigma detection block component."""

    keywords: List[str] = Field(default_factory=list)
    patterns: List[str] = Field(default_factory=list)   # regex patterns
    field_mappings: Dict[str, List[str]] = Field(default_factory=dict)  # field: [value1, …]


# ─────────────────────────────────────────────────────────────────────────────
# Core Sigma rule model
# ─────────────────────────────────────────────────────────────────────────────


class SigmaRule(BaseModel):
    """Full Sigma rule representation, ready for serialisation to YAML."""

    title: str
    id: str                              # UUID v4 / v5 string
    status: SigmaStatus = SigmaStatus.EXPERIMENTAL
    description: str
    author: str = "TythanAI Platform"
    date: str = ""                       # YYYY-MM-DD
    modified: str = ""
    tags: List[str] = Field(default_factory=list)      # e.g. attack.T1059.001
    logsource: Dict[str, str] = Field(default_factory=dict)
    detection: Dict[str, Any] = Field(default_factory=dict)
    fields: List[str] = Field(default_factory=list)
    falsepositives: List[str] = Field(default_factory=list)
    level: SigmaLevel = SigmaLevel.MEDIUM
    references: List[str] = Field(default_factory=list)
    mitre_attack: List[str] = Field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Generator
# ─────────────────────────────────────────────────────────────────────────────

# Sigma uses a UUID namespace for deterministic rule IDs.
_SIGMA_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

# Map CWE identifiers to MITRE ATT&CK technique IDs.
# Sources: MITRE ATT&CK + CWE-CAPEC mappings.
_SEVERITY_TO_LEVEL: Dict[str, SigmaLevel] = {
    "CRITICAL": SigmaLevel.CRITICAL,
    "HIGH": SigmaLevel.HIGH,
    "MEDIUM": SigmaLevel.MEDIUM,
    "LOW": SigmaLevel.LOW,
    "INFO": SigmaLevel.INFORMATIONAL,
    "INFORMATIONAL": SigmaLevel.INFORMATIONAL,
}

_RULE_PREFIX_TO_LOGSOURCE: Dict[str, Dict[str, str]] = {
    "PY-":   {"category": "application", "product": "python"},
    "JS-":   {"category": "application", "product": "javascript"},
    "IAC-":  {"category": "cloud", "product": "terraform"},
    "CONT-": {"category": "container", "product": "docker"},
}


class SigmaRuleGenerator:
    """Converts TythanAI Finding objects into Sigma detection rules."""

    # ── CWE → MITRE ATT&CK mapping ──────────────────────────────────────────
    CWE_TO_ATTACK: Dict[str, List[str]] = {
        "CWE-78":   ["T1059.004", "T1059.001"],  # OS Command Injection
        "CWE-89":   ["T1190"],                   # SQL Injection
        "CWE-22":   ["T1083", "T1005"],          # Path Traversal
        "CWE-79":   ["T1059.007"],               # XSS
        "CWE-502":  ["T1059"],                   # Deserialization
        "CWE-798":  ["T1552.001"],               # Hardcoded Credentials in Code
        "CWE-94":   ["T1059"],                   # Code Injection
        "CWE-918":  ["T1090"],                   # SSRF → Proxy
        "CWE-611":  ["T1190"],                   # XXE
        "CWE-327":  ["T1553"],                   # Weak / Broken Cryptography
        "CWE-306":  ["T1078"],                   # Missing Authentication
        "CWE-862":  ["T1078"],                   # Missing Authorization Check
        "CWE-863":  ["T1548"],                   # Incorrect Authorization
        "CWE-352":  ["T1606.001"],               # CSRF
        "CWE-434":  ["T1105"],                   # Unrestricted File Upload
        "CWE-295":  ["T1557"],                   # Improper Certificate Validation
        "CWE-1321": ["T1190"],                   # Prototype Pollution
        "CWE-338":  ["T1552"],                   # Cryptographically Weak PRNG
        "CWE-601":  ["T1550"],                   # Open Redirect
        "CWE-916":  ["T1110"],                   # Weak Password Hash
        "CWE-532":  ["T1552.003"],               # Sensitive Info in Logs
        "CWE-209":  ["T1082"],                   # Error / Exception Detail Disclosure
        "CWE-113":  ["T1190"],                   # HTTP Response Splitting
        "CWE-776":  ["T1499"],                   # XXE Billion Laughs (DoS)
        "CWE-400":  ["T1499"],                   # Uncontrolled Resource Consumption
    }

    # ────────────────────────────────────────────────────────────────────────

    def _logsource_for_rule(self, rule_id: str) -> Dict[str, str]:
        """Derive the logsource block from the rule_id prefix."""
        for prefix, logsource in _RULE_PREFIX_TO_LOGSOURCE.items():
            if rule_id.startswith(prefix):
                return dict(logsource)
        return {"category": "application"}

    def _level_for_severity(self, severity: str) -> SigmaLevel:
        """Map a Finding severity string to a SigmaLevel."""
        return _SEVERITY_TO_LEVEL.get(severity.upper(), SigmaLevel.MEDIUM)

    def _attack_tags_for_cwe(self, cwe_id: str) -> List[str]:
        """Return formatted ATT&CK tags for a CWE identifier."""
        techniques = self.CWE_TO_ATTACK.get(cwe_id, [])
        return [f"attack.{technique}" for technique in techniques]

    def generate_from_finding(self, finding: Finding) -> SigmaRule:
        """Create a Sigma rule from a single TythanAI Finding.

        The rule ID is deterministic: UUID v5 derived from rule_id + file path
        so that the same finding always produces the same rule UUID.
        """
        today = date.today().isoformat()

        # Deterministic UUID from (rule_id, file) pair
        seed = f"{finding.rule_id}:{finding.file}"
        rule_uuid = str(uuid.uuid5(_SIGMA_NAMESPACE, seed))

        # Title — truncate description at 80 chars
        title_suffix = (finding.description[:80]).strip() if finding.description else finding.rule_id
        title = f"TythanAI: {title_suffix}"

        # MITRE ATT&CK tags
        tags = self._attack_tags_for_cwe(finding.cwe_id) if finding.cwe_id else []

        # Log source
        logsource = self._logsource_for_rule(finding.rule_id)

        # Detection block
        detection: Dict[str, Any] = {
            "selection": {
                "file|contains": [finding.file],
            },
            "condition": "selection",
        }

        # References from finding sources
        references = list(finding.sources) if finding.sources else []

        # Sigma level
        level = self._level_for_severity(finding.severity)

        # Build description
        description = finding.description or f"TythanAI detected {finding.rule_id} in {finding.file}"
        if finding.recommendation:
            description = f"{description}. Recommendation: {finding.recommendation}"

        rule = SigmaRule(
            title=title,
            id=rule_uuid,
            status=SigmaStatus.EXPERIMENTAL,
            description=description,
            author="TythanAI Platform",
            date=today,
            modified=today,
            tags=tags,
            logsource=logsource,
            detection=detection,
            fields=["file", "line"],
            falsepositives=["Legitimate use", "Test environments"],
            level=level,
            references=references,
            mitre_attack=[t.replace("attack.", "") for t in tags],
        )

        logger.debug(
            "Generated Sigma rule %s for finding %s in %s",
            rule_uuid, finding.rule_id, finding.file,
        )
        return rule

    def generate_bulk(self, findings: List[Finding]) -> List[SigmaRule]:
        """Generate Sigma rules for a list of findings.

        Deduplicates by (rule_id, file): multiple findings sharing the same
        rule_id and file path collapse into a single Sigma rule.
        """
        seen: Dict[str, SigmaRule] = {}
        for finding in findings:
            dedup_key = f"{finding.rule_id}:{finding.file}"
            if dedup_key in seen:
                logger.debug(
                    "Skipping duplicate finding %s in %s",
                    finding.rule_id, finding.file,
                )
                continue
            rule = self.generate_from_finding(finding)
            seen[dedup_key] = rule

        return list(seen.values())

    def to_yaml(self, rule: SigmaRule) -> str:
        """Serialise a SigmaRule to a well-formatted Sigma YAML string.

        Follows the canonical Sigma field order for readability.
        """
        doc: Dict[str, Any] = {}

        # Sigma canonical field order
        doc["title"] = rule.title
        doc["id"] = rule.id
        doc["status"] = rule.status.value
        doc["description"] = rule.description
        doc["author"] = rule.author
        doc["date"] = rule.date or date.today().isoformat()

        if rule.modified:
            doc["modified"] = rule.modified

        if rule.tags:
            doc["tags"] = rule.tags

        if rule.references:
            doc["references"] = rule.references

        doc["logsource"] = rule.logsource
        doc["detection"] = rule.detection
        doc["fields"] = rule.fields

        doc["falsepositives"] = rule.falsepositives
        doc["level"] = rule.level.value

        # yaml.dump with explicit options for Sigma-compatible output
        return yaml.dump(
            doc,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            indent=4,
        )

    def export_ruleset(
        self,
        findings: List[Finding],
        output_dir: str,
    ) -> List[str]:
        """Export Sigma rules for all findings to severity-partitioned subdirectories.

        Directory layout::

            {output_dir}/
              critical/  <rule-uuid>.yml
              high/      <rule-uuid>.yml
              medium/    <rule-uuid>.yml
              low/       <rule-uuid>.yml
              informational/ <rule-uuid>.yml

        Returns the list of written file paths.
        """
        rules = self.generate_bulk(findings)
        written: List[str] = []

        for rule in rules:
            level_dir = os.path.join(output_dir, rule.level.value)
            os.makedirs(level_dir, exist_ok=True)

            file_path = os.path.join(level_dir, f"{rule.id}.yml")
            try:
                with open(file_path, "w", encoding="utf-8") as fh:
                    fh.write(self.to_yaml(rule))
                written.append(file_path)
                logger.info("Wrote Sigma rule %s → %s", rule.id, file_path)
            except OSError as exc:
                logger.error("Failed to write rule %s to %s: %s", rule.id, file_path, exc)

        return written


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience functions
# ─────────────────────────────────────────────────────────────────────────────


def generate_sigma_rules(findings: List[Finding]) -> List[SigmaRule]:
    """Generate Sigma rules for a list of TythanAI findings.

    Args:
        findings: List of Finding objects from the TythanAI scanner.

    Returns:
        Deduplicated list of SigmaRule objects.
    """
    return SigmaRuleGenerator().generate_bulk(findings)


def export_sigma_ruleset(findings: List[Finding], output_dir: str) -> List[str]:
    """Export Sigma rules to severity-partitioned subdirectories.

    Args:
        findings: List of Finding objects.
        output_dir: Root directory for rule output.

    Returns:
        List of written file paths.
    """
    return SigmaRuleGenerator().export_ruleset(findings, output_dir)
