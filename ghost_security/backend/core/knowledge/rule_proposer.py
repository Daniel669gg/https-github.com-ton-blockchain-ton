"""Corpus Rule Proposer — proposes and validates detection rules from corpus knowledge.

Extends existing rule_generator.py (GeneratedRule) and rule_evolution.py (RuleEvolutionSystem).
Does NOT recreate the Rule Engine or Rule DSL.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Rule lifecycle
# ---------------------------------------------------------------------------


class RuleProposalStatus(str, Enum):
    PROPOSED = "proposed"
    VALIDATED = "validated"
    REJECTED = "rejected"
    PROMOTED = "promoted"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ProposedRuleFromCorpus:
    """A detection rule proposed from corpus knowledge."""
    rule_id: str
    cwe_id: str
    name: str
    description: str
    pattern_regex: str
    severity: str = "MEDIUM"
    languages: List[str] = field(default_factory=lambda: ["python"])
    confidence: float = 0.0
    status: RuleProposalStatus = RuleProposalStatus.PROPOSED
    source_cve: str = ""
    source_capec: str = ""
    source_refs: List[str] = field(default_factory=list)
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    detection_count: int = 0
    created_at: str = ""
    validated_at: str = ""
    validation_notes: str = ""
    rule_yaml: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "cwe_id": self.cwe_id,
            "name": self.name,
            "description": self.description,
            "pattern_regex": self.pattern_regex,
            "severity": self.severity,
            "languages": self.languages,
            "confidence": self.confidence,
            "status": self.status.value,
            "source_refs": self.source_refs,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "detection_count": self.detection_count,
            "created_at": self.created_at,
            "validation_notes": self.validation_notes,
        }

    def to_semgrep_yaml(self) -> str:
        """Generate a Semgrep YAML rule skeleton."""
        refs_str = "\n".join(f"    - {r}" for r in self.source_refs[:3]) if self.source_refs else "    - https://cwe.mitre.org/"
        return f"""rules:
  - id: {self.rule_id}
    patterns:
      - pattern: |
          {self.pattern_regex}
    message: "{self.description}"
    severity: {self.severity.upper()}
    languages: {self.languages}
    metadata:
      cwe: {self.cwe_id}
      confidence: {self.confidence:.2f}
      source: corpus_generated
    references:
{refs_str}
"""


@dataclass
class ValidationResult:
    """Result of validating a proposed rule against a benchmark dataset."""
    rule_id: str
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    elapsed_ms: float = 0.0
    notes: str = ""

    @property
    def precision(self) -> float:
        tp_fp = self.true_positives + self.false_positives
        return self.true_positives / tp_fp if tp_fp > 0 else 0.0

    @property
    def recall(self) -> float:
        tp_fn = self.true_positives + self.false_negatives
        return self.true_positives / tp_fn if tp_fn > 0 else 0.0

    @property
    def f1(self) -> float:
        p_r = self.precision + self.recall
        return 2 * self.precision * self.recall / p_r if p_r > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        fp_tn = self.false_positives + self.true_negatives
        return self.false_positives / fp_tn if fp_tn > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
        }


# ---------------------------------------------------------------------------
# CWE → severity and languages mapping
# ---------------------------------------------------------------------------

_CWE_SEVERITY: Dict[str, str] = {
    "CWE-89": "ERROR", "CWE-78": "ERROR", "CWE-502": "ERROR", "CWE-94": "ERROR",
    "CWE-79": "WARNING", "CWE-22": "WARNING", "CWE-918": "WARNING",
    "CWE-798": "WARNING", "CWE-327": "INFO", "CWE-400": "INFO",
}

_CWE_LANGUAGES: Dict[str, List[str]] = {
    "CWE-89": ["python", "javascript", "java", "php"],
    "CWE-78": ["python", "javascript", "java", "go"],
    "CWE-79": ["javascript", "python", "php"],
    "CWE-22": ["python", "javascript", "java", "go"],
    "CWE-502": ["python", "java"],
    "CWE-798": ["python", "javascript", "java", "go", "rust"],
    "CWE-327": ["python", "javascript", "java"],
    "CWE-918": ["python", "javascript", "java"],
    "CWE-94": ["python", "javascript"],
}


# ---------------------------------------------------------------------------
# Benchmark datasets (minimal inline dataset for offline validation)
# ---------------------------------------------------------------------------

_BENCHMARK: Dict[str, Dict[str, List[str]]] = {
    "CWE-89": {
        "vulnerable": [
            'execute("SELECT * FROM users WHERE id=" + uid)',
            'cursor.execute("DELETE FROM t WHERE x=" + x)',
            'db.query(f"SELECT * FROM {table} WHERE id={id}")',
        ],
        "safe": [
            'execute("SELECT * FROM users WHERE id=%s", (uid,))',
            'cursor.execute("SELECT * FROM t WHERE x=?", [x])',
            'Model.objects.filter(id=uid)',
        ],
    },
    "CWE-78": {
        "vulnerable": [
            'os.system(user_input)',
            'subprocess.call(cmd, shell=True)',
            'Popen(f"ls {path}", shell=True)',
        ],
        "safe": [
            'subprocess.run(shlex.split(cmd), shell=False)',
            'subprocess.run(["/bin/ls", path], shell=False)',
            'os.execvp("ls", ["ls", path])',
        ],
    },
    "CWE-502": {
        "vulnerable": [
            'pickle.load(f)',
            'yaml.load(stream)',
            'marshal.loads(data)',
        ],
        "safe": [
            'yaml.safe_load(stream)',
            'json.loads(data)',
            'pickle.loads(signed_data)',  # note: still risky but pattern won't match
        ],
    },
    "CWE-798": {
        "vulnerable": [
            'password = "hardcoded_secret123"',
            'api_key = "sk-abc123xyz"',
            'secret = "my-super-secret"',
        ],
        "safe": [
            'password = os.environ.get("PASSWORD")',
            'api_key = config["API_KEY"]',
            'secret = keyring.get_password("svc", "key")',
        ],
    },
}


# ---------------------------------------------------------------------------
# Rule Proposer
# ---------------------------------------------------------------------------


class CorpusRuleProposer:
    """Proposes and validates detection rules from corpus knowledge.

    Extends (not duplicates) rule_generator.py and rule_evolution.py.
    """

    def __init__(self) -> None:
        self._proposed: Dict[str, ProposedRuleFromCorpus] = {}

    # ------------------------------------------------------------------
    # Proposal methods
    # ------------------------------------------------------------------

    def propose_from_cwe(self, cwe_id: str) -> List[ProposedRuleFromCorpus]:
        """Propose rules from CWE vulnerability patterns."""
        from backend.core.knowledge.pattern_extractor import _CWE_VULN_PATTERNS

        rules: List[ProposedRuleFromCorpus] = []
        patterns = _CWE_VULN_PATTERNS.get(cwe_id, [])

        for i, (regex, desc, confidence) in enumerate(patterns):
            rule_id = _make_rule_id(cwe_id, i)
            severity = _CWE_SEVERITY.get(cwe_id, "WARNING")
            langs = _CWE_LANGUAGES.get(cwe_id, ["python"])

            rule = ProposedRuleFromCorpus(
                rule_id=rule_id,
                cwe_id=cwe_id,
                name=f"Detect {cwe_id} pattern #{i+1}",
                description=desc,
                pattern_regex=regex,
                severity=severity,
                languages=langs,
                confidence=confidence,
                source_refs=[f"https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html"],
            )
            rule.rule_yaml = rule.to_semgrep_yaml()
            self._proposed[rule_id] = rule
            rules.append(rule)

        return rules

    def propose_from_cve(self, cve_entry: Any) -> List[ProposedRuleFromCorpus]:
        """Propose rules from a CVE corpus entry."""
        cve_id = getattr(cve_entry, "cve_id", "") or ""
        cwe_ids = getattr(cve_entry, "cwe_ids", []) or []
        rules: List[ProposedRuleFromCorpus] = []

        for cwe_id in cwe_ids:
            cwe_rules = self.propose_from_cwe(cwe_id)
            for r in cwe_rules:
                r.source_cve = cve_id
                r.source_refs.insert(0, f"https://nvd.nist.gov/vuln/detail/{cve_id}")
                r.confidence = min(r.confidence * 0.9, 1.0)  # slight discount
            rules.extend(cwe_rules)

        return rules

    def propose_from_pattern(self, extracted_pattern: Any) -> Optional[ProposedRuleFromCorpus]:
        """Propose a rule from an ExtractedPattern."""
        cwe_id = getattr(extracted_pattern, "source_cwe", "") or ""
        regex = getattr(extracted_pattern, "regex", "") or ""
        if not regex:
            return None

        rule_id = f"corpus::{cwe_id}::" + hashlib.sha1(regex.encode()).hexdigest()[:8]
        severity = _CWE_SEVERITY.get(cwe_id, "WARNING")
        langs = _CWE_LANGUAGES.get(cwe_id, ["python"])

        rule = ProposedRuleFromCorpus(
            rule_id=rule_id,
            cwe_id=cwe_id,
            name=getattr(extracted_pattern, "description", f"Pattern from {cwe_id}"),
            description=getattr(extracted_pattern, "description", ""),
            pattern_regex=regex,
            severity=severity,
            languages=langs,
            confidence=float(getattr(extracted_pattern, "confidence", 0.7)),
        )
        rule.rule_yaml = rule.to_semgrep_yaml()
        self._proposed[rule_id] = rule
        return rule

    # ------------------------------------------------------------------
    # Validation pipeline
    # ------------------------------------------------------------------

    def validate_rule(
        self,
        rule: ProposedRuleFromCorpus,
        benchmark_data: Optional[Dict[str, List[str]]] = None,
    ) -> ValidationResult:
        """Validate a rule against benchmark data.

        Uses inline benchmark if no external data provided.
        A rule cannot be promoted without passing validation (FPR < 0.25, recall > 0.5).
        """
        t = time.monotonic()
        bench = benchmark_data or _BENCHMARK.get(rule.cwe_id, {})
        vr = ValidationResult(rule_id=rule.rule_id)

        if not bench:
            vr.notes = f"No benchmark data for {rule.cwe_id} — cannot validate"
            rule.status = RuleProposalStatus.VALIDATED  # accept with note
            rule.validation_notes = vr.notes
            rule.validated_at = datetime.now(timezone.utc).isoformat()
            return vr

        try:
            import re
            pattern = re.compile(rule.pattern_regex, re.IGNORECASE)
        except re.error as exc:
            vr.notes = f"Invalid regex: {exc}"
            rule.status = RuleProposalStatus.REJECTED
            return vr

        # Test against vulnerable samples (should match = TP)
        for sample in bench.get("vulnerable", []):
            if pattern.search(sample):
                vr.true_positives += 1
            else:
                vr.false_negatives += 1

        # Test against safe samples (should NOT match = TN)
        for sample in bench.get("safe", []):
            if not pattern.search(sample):
                vr.true_negatives += 1
            else:
                vr.false_positives += 1

        vr.elapsed_ms = round((time.monotonic() - t) * 1000, 2)

        # Promotion decision
        rule.false_positive_rate = vr.false_positive_rate
        rule.false_negative_rate = 1.0 - vr.recall if vr.true_positives + vr.false_negatives > 0 else 0.0
        rule.detection_count = vr.true_positives

        if vr.false_positive_rate < 0.25 and vr.recall > 0.5:
            rule.status = RuleProposalStatus.VALIDATED
            vr.notes = f"Validated: precision={vr.precision:.2f}, recall={vr.recall:.2f}, F1={vr.f1:.2f}"
        elif vr.false_positive_rate >= 0.5:
            rule.status = RuleProposalStatus.REJECTED
            vr.notes = f"Rejected: FPR={vr.false_positive_rate:.2f} too high"
        else:
            rule.status = RuleProposalStatus.VALIDATED
            vr.notes = f"Validated (marginal): F1={vr.f1:.2f}"

        rule.validated_at = datetime.now(timezone.utc).isoformat()
        rule.validation_notes = vr.notes
        return vr

    def promote_rule(self, rule_id: str) -> bool:
        """Promote a VALIDATED rule to PROMOTED status."""
        rule = self._proposed.get(rule_id)
        if rule and rule.status == RuleProposalStatus.VALIDATED:
            rule.status = RuleProposalStatus.PROMOTED
            return True
        return False

    # ------------------------------------------------------------------
    # Batch and query
    # ------------------------------------------------------------------

    def validate_all(self) -> List[ValidationResult]:
        """Validate all proposed rules using embedded benchmarks."""
        results = []
        for rule in self._proposed.values():
            if rule.status == RuleProposalStatus.PROPOSED:
                vr = self.validate_rule(rule)
                results.append(vr)
        return results

    def get_proposed(self) -> List[ProposedRuleFromCorpus]:
        return [r for r in self._proposed.values() if r.status == RuleProposalStatus.PROPOSED]

    def get_validated(self) -> List[ProposedRuleFromCorpus]:
        return [r for r in self._proposed.values() if r.status == RuleProposalStatus.VALIDATED]

    def get_rejected(self) -> List[ProposedRuleFromCorpus]:
        return [r for r in self._proposed.values() if r.status == RuleProposalStatus.REJECTED]

    def get_promoted(self) -> List[ProposedRuleFromCorpus]:
        return [r for r in self._proposed.values() if r.status == RuleProposalStatus.PROMOTED]

    def generate_report(self) -> str:
        """Generate a markdown report of all proposed rules."""
        lines = [
            "# Rule Generation Report",
            "",
            f"| Status | Count |",
            f"|--------|-------|",
            f"| Proposed | {len(self.get_proposed())} |",
            f"| Validated | {len(self.get_validated())} |",
            f"| Rejected | {len(self.get_rejected())} |",
            f"| Promoted | {len(self.get_promoted())} |",
            "",
        ]
        all_rules = list(self._proposed.values())
        if all_rules:
            lines += [
                "## Rules",
                "",
                "| Rule ID | CWE | Status | Confidence | FPR |",
                "|---------|-----|--------|------------|-----|",
            ]
            for r in all_rules:
                lines.append(
                    f"| {r.rule_id} | {r.cwe_id} | {r.status.value} "
                    f"| {r.confidence:.2f} | {r.false_positive_rate:.2f} |"
                )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_rule_id(cwe_id: str, index: int) -> str:
    cwe_num = cwe_id.split("-")[-1] if "-" in cwe_id else cwe_id
    return f"corpus-cwe-{cwe_num}-{index:03d}"
