"""
TythanAI Platform — Policy-as-Code Engine

Security policies defined in YAML that gate deployments.
Similar in spirit to OPA/Rego but purpose-built for TythanAI findings,
with no external dependencies beyond the standard library + PyYAML.

Policy YAML format:
  name:        "Production Security Gate"
  version:     "1.0"
  enforcement: block   # or warn
  rules:
    - id:          "P001"
      description: "No CRITICAL findings allowed in production"
      condition:
        severity:  CRITICAL
        count:     0
        operator:  max   # 'max' means findings of this kind must be <= count
      action: block
    - id:          "P002"
      description: "No hardcoded secrets"
      condition:
        rule_id_prefix: "SECRET"
        count:          0
        operator:       max
      action: block
    - id:          "P003"
      description: "Max 5 HIGH findings"
      condition:
        severity:  HIGH
        count:     5
        operator:  max
      action: warn

Usage:
    from core.policy.policy_engine import PolicyEngine

    engine = PolicyEngine()
    engine.load_policies("/path/to/policies/")
    result = engine.evaluate(findings)
    print(engine.generate_gate_report(result))
    # result.gate_status -> "PASS" | "FAIL" | "WARN"
"""
from __future__ import annotations

import logging
import os
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:  # pragma: no cover
    _YAML_AVAILABLE = False

logger = logging.getLogger(__name__)

# ── Severity ordering ─────────────────────────────────────────────────────────

_SEV_ORDER: List[str] = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

_SEV_EMOJI: Dict[str, str] = {
    "CRITICAL": "🚨",
    "HIGH":     "⚠️",
    "MEDIUM":   "🔶",
    "LOW":      "🔵",
    "INFO":     "ℹ️",
    "PASS":     "✅",
    "FAIL":     "❌",
    "WARN":     "⚡",
}


# ── Policy data model ─────────────────────────────────────────────────────────

@dataclass
class PolicyCondition:
    """
    Describes what to count and what the threshold is.

    Matching dimensions (at least one required):
      severity        – match findings by severity level (CRITICAL, HIGH, …)
      rule_id_prefix  – match findings whose rule_id starts with this string
      rule_id         – exact rule_id match
      tag             – match findings that carry this tag
      cwe_prefix      – match findings whose cwe starts with this (e.g. "CWE-89")

    Threshold:
      operator        – "max" (default) → actual_count must be <= count
                      – "min"           → actual_count must be >= count
                      – "exact"         → actual_count must be == count
      count           – the threshold integer
    """
    count: int = 0
    operator: str = "max"           # max | min | exact
    severity: str = ""
    rule_id_prefix: str = ""
    rule_id: str = ""
    tag: str = ""
    cwe_prefix: str = ""


@dataclass
class PolicyRule:
    """A single rule inside a policy file."""
    rule_id: str
    description: str
    condition: PolicyCondition
    action: str = "block"           # block | warn
    source_policy: str = ""         # populated after loading


@dataclass
class Policy:
    """Parsed, validated policy loaded from a YAML file."""
    name: str
    version: str
    enforcement: str                # block | warn
    rules: List[PolicyRule] = field(default_factory=list)
    source_file: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


# ── Evaluation result ─────────────────────────────────────────────────────────

@dataclass
class ViolationDetail:
    """Details about a single violated policy rule."""
    rule_id: str
    description: str
    action: str
    policy_name: str
    actual_count: int
    threshold: int
    operator: str
    matching_findings: List[dict] = field(default_factory=list)

    def summary(self) -> str:
        op_text = {"max": "≤", "min": "≥", "exact": "=="}.get(self.operator, self.operator)
        return (
            f"[{self.rule_id}] {self.description} "
            f"(actual={self.actual_count}, required {op_text} {self.threshold})"
        )


@dataclass
class PolicyResult:
    """
    The outcome of evaluating a set of findings against all loaded policies.

    Attributes:
        passed          – True when gate_status is "PASS"
        violated        – list of ViolationDetail for BLOCK-action violations
        warnings        – list of ViolationDetail for WARN-action violations
        blocked_by      – human-readable list of blocking rule descriptions
        gate_status     – "PASS" | "FAIL" | "WARN"
        evaluated_at    – ISO-8601 timestamp
        policies_checked– number of policy files evaluated
        findings_total  – total number of findings evaluated
    """
    passed: bool = True
    violated: List[ViolationDetail] = field(default_factory=list)
    warnings: List[ViolationDetail] = field(default_factory=list)
    blocked_by: List[str] = field(default_factory=list)
    gate_status: str = "PASS"      # PASS | FAIL | WARN
    evaluated_at: str = ""
    policies_checked: int = 0
    findings_total: int = 0

    def __post_init__(self) -> None:
        if not self.evaluated_at:
            self.evaluated_at = datetime.now(timezone.utc).isoformat()


# ── Policy loading helpers ────────────────────────────────────────────────────

def _parse_condition(data: dict) -> PolicyCondition:
    return PolicyCondition(
        count=int(data.get("count", 0)),
        operator=str(data.get("operator", "max")).lower(),
        severity=str(data.get("severity", "")).upper(),
        rule_id_prefix=str(data.get("rule_id_prefix", "")),
        rule_id=str(data.get("rule_id", "")),
        tag=str(data.get("tag", "")),
        cwe_prefix=str(data.get("cwe_prefix", "")),
    )


def _parse_policy(data: dict, source_file: str = "") -> Optional[Policy]:
    """Convert a raw YAML dict into a Policy object. Returns None on error."""
    try:
        name = str(data.get("name", "Unnamed Policy"))
        version = str(data.get("version", "1.0"))
        enforcement = str(data.get("enforcement", "block")).lower()

        rules: List[PolicyRule] = []
        for raw_rule in data.get("rules", []):
            condition_data = raw_rule.get("condition", {})
            condition = _parse_condition(condition_data)
            pr = PolicyRule(
                rule_id=str(raw_rule.get("id", "UNKNOWN")),
                description=str(raw_rule.get("description", "")),
                condition=condition,
                action=str(raw_rule.get("action", enforcement)).lower(),
                source_policy=name,
            )
            rules.append(pr)

        return Policy(
            name=name,
            version=version,
            enforcement=enforcement,
            rules=rules,
            source_file=source_file,
            metadata={k: v for k, v in data.items()
                      if k not in ("name", "version", "enforcement", "rules")},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to parse policy from %s: %s", source_file, exc)
        return None


# ── Main engine ───────────────────────────────────────────────────────────────

class PolicyEngine:
    """
    Policy-as-Code engine for gating deployments based on security findings.

    Lifecycle:
        engine = PolicyEngine()
        n = engine.load_policies("policies/")   # loads all .yaml in dir
        result = engine.evaluate(findings)       # findings: list[dict]
        report = engine.generate_gate_report(result)
        if result.gate_status == "FAIL":
            sys.exit(1)
    """

    def __init__(self) -> None:
        self._policies: List[Policy] = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def load_policies(self, path_or_dir: str) -> int:
        """
        Load policies from a YAML file or all YAML files in a directory.

        Returns the number of policy files successfully loaded.
        Raises RuntimeError if PyYAML is not installed.
        """
        if not _YAML_AVAILABLE:
            raise RuntimeError(
                "PyYAML is required for the policy engine. "
                "Install it with: pip install pyyaml"
            )

        target = Path(path_or_dir)
        loaded = 0

        if target.is_file():
            if self._load_single_file(target):
                loaded += 1
        elif target.is_dir():
            for yaml_file in sorted(target.glob("**/*.yaml")):
                if self._load_single_file(yaml_file):
                    loaded += 1
            for yaml_file in sorted(target.glob("**/*.yml")):
                if self._load_single_file(yaml_file):
                    loaded += 1
        else:
            logger.warning("Policy path does not exist: %s", path_or_dir)

        logger.info("PolicyEngine: loaded %d policy file(s) from %s", loaded, path_or_dir)
        return loaded

    def evaluate(self, findings: List[dict]) -> PolicyResult:
        """
        Evaluate a list of findings (dicts) against all loaded policies.

        Each finding dict is expected to have at minimum:
          - "severity":  str  (CRITICAL | HIGH | MEDIUM | LOW | INFO)
          - "rule_id":   str  (e.g. "GHOST-PY-001" or "SECRET-001")
          - "cwe":       str  (optional)
          - "tags":      list (optional)

        Returns a PolicyResult indicating PASS / FAIL / WARN.
        """
        result = PolicyResult(
            findings_total=len(findings),
            policies_checked=len(self._policies),
        )

        if not self._policies:
            logger.warning("PolicyEngine.evaluate called with no loaded policies; returning PASS")
            return result

        block_violations: List[ViolationDetail] = []
        warn_violations: List[ViolationDetail] = []

        for policy in self._policies:
            for rule in policy.rules:
                matching = [f for f in findings if self._finding_matches_condition(f, rule.condition)]
                actual_count = len(matching)
                violated = self._threshold_violated(actual_count, rule.condition)

                if not violated:
                    continue

                detail = ViolationDetail(
                    rule_id=rule.rule_id,
                    description=rule.description,
                    action=rule.action,
                    policy_name=policy.name,
                    actual_count=actual_count,
                    threshold=rule.condition.count,
                    operator=rule.condition.operator,
                    matching_findings=matching[:10],  # cap at 10 for report size
                )

                if rule.action == "block":
                    block_violations.append(detail)
                else:
                    warn_violations.append(detail)

        result.violated = block_violations
        result.warnings = warn_violations
        result.blocked_by = [v.summary() for v in block_violations]

        if block_violations:
            result.gate_status = "FAIL"
            result.passed = False
        elif warn_violations:
            result.gate_status = "WARN"
            result.passed = True
        else:
            result.gate_status = "PASS"
            result.passed = True

        return result

    def evaluate_finding(self, finding: dict, policy_rule: PolicyRule) -> bool:
        """
        Check whether a single finding matches the condition of a single policy rule.

        Returns True if the finding matches (i.e. it contributes to a potential violation).
        Does NOT check the threshold — use evaluate() for full gate assessment.
        """
        return self._finding_matches_condition(finding, policy_rule.condition)

    def generate_gate_report(self, result: PolicyResult) -> str:
        """
        Generate a human-readable gate report as a multi-line string.

        Suitable for printing to CI logs or writing to a report artifact.
        """
        status_emoji = _SEV_EMOJI.get(result.gate_status, "")
        lines: List[str] = [
            "=" * 72,
            f"  TythanAI Security Gate Report",
            f"  Status : {status_emoji} {result.gate_status}",
            f"  Time   : {result.evaluated_at}",
            f"  Scope  : {result.findings_total} finding(s) | "
            f"{result.policies_checked} policy file(s)",
            "=" * 72,
        ]

        if result.gate_status == "PASS":
            lines.append("")
            lines.append("  All policy rules satisfied. Deployment may proceed.")
            lines.append("")

        if result.violated:
            lines.append("")
            lines.append(f"  BLOCKING VIOLATIONS ({len(result.violated)}):")
            lines.append("  " + "-" * 68)
            for v in result.violated:
                lines.append(f"  [{v.rule_id}] {v.description}")
                lines.append(f"         Policy   : {v.policy_name}")
                op_text = {"max": "≤", "min": "≥", "exact": "=="}.get(v.operator, v.operator)
                lines.append(f"         Threshold: required {op_text} {v.threshold} — actual: {v.actual_count}")
                if v.matching_findings:
                    lines.append("         Samples  :")
                    for mf in v.matching_findings[:3]:
                        rid = mf.get("rule_id", mf.get("id", "?"))
                        sev = mf.get("severity", "?")
                        loc = f"{mf.get('file', '?')}:{mf.get('line', '?')}"
                        lines.append(f"           • [{sev}] {rid} @ {loc}")
                lines.append("")

        if result.warnings:
            lines.append(f"  WARNINGS ({len(result.warnings)}):")
            lines.append("  " + "-" * 68)
            for w in result.warnings:
                lines.append(f"  [{w.rule_id}] {w.description}")
                lines.append(f"         Policy   : {w.policy_name}")
                op_text = {"max": "≤", "min": "≥", "exact": "=="}.get(w.operator, w.operator)
                lines.append(f"         Threshold: required {op_text} {w.threshold} — actual: {w.actual_count}")
                lines.append("")

        lines.append("=" * 72)
        return "\n".join(lines)

    def create_example_policy(self, path: str) -> str:
        """
        Write an example policy YAML file to *path*.

        Returns the path that was written. Creates parent directories as needed.
        """
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_EXAMPLE_POLICY_YAML, encoding="utf-8")
        logger.info("Example policy written to %s", target)
        return str(target)

    @property
    def policies(self) -> List[Policy]:
        """Return a copy of all loaded policies."""
        return list(self._policies)

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _load_single_file(self, path: Path) -> bool:
        """Parse and register a single YAML policy file. Returns True on success."""
        try:
            raw = path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw)
            if not isinstance(data, dict):
                logger.warning("Policy file %s is not a YAML mapping, skipping", path)
                return False
            policy = _parse_policy(data, source_file=str(path))
            if policy is None:
                return False
            self._policies.append(policy)
            logger.debug("Loaded policy '%s' (%d rules) from %s",
                         policy.name, len(policy.rules), path)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Error loading policy file %s: %s", path, exc)
            return False

    @staticmethod
    def _finding_matches_condition(finding: dict, cond: PolicyCondition) -> bool:
        """
        Return True if a finding matches the filter dimensions of a condition.

        A finding must satisfy ALL non-empty dimensions to match.
        """
        # Severity filter
        if cond.severity:
            finding_sev = str(finding.get("severity", "")).upper()
            if finding_sev != cond.severity:
                return False

        # Exact rule_id filter
        if cond.rule_id:
            finding_rid = str(finding.get("rule_id", finding.get("id", "")))
            if finding_rid != cond.rule_id:
                return False

        # rule_id prefix filter (e.g. "SECRET" matches "SECRET-001", "SECRET-AWS")
        if cond.rule_id_prefix:
            finding_rid = str(finding.get("rule_id", finding.get("id", "")))
            if not finding_rid.upper().startswith(cond.rule_id_prefix.upper()):
                return False

        # CWE prefix filter (e.g. "CWE-89" or "CWE-2")
        if cond.cwe_prefix:
            finding_cwe = str(finding.get("cwe", ""))
            if not finding_cwe.upper().startswith(cond.cwe_prefix.upper()):
                return False

        # Tag filter
        if cond.tag:
            finding_tags = finding.get("tags", [])
            if isinstance(finding_tags, str):
                finding_tags = [t.strip() for t in finding_tags.split(",")]
            if cond.tag.lower() not in [str(t).lower() for t in finding_tags]:
                return False

        return True

    @staticmethod
    def _threshold_violated(actual_count: int, cond: PolicyCondition) -> bool:
        """
        Return True when the actual count violates the threshold.

        operator=max  → violated when actual_count > threshold
        operator=min  → violated when actual_count < threshold
        operator=exact → violated when actual_count != threshold
        """
        op = cond.operator
        threshold = cond.count

        if op == "max":
            return actual_count > threshold
        if op == "min":
            return actual_count < threshold
        if op == "exact":
            return actual_count != threshold
        # Unknown operator — treat as max
        logger.warning("Unknown policy operator '%s'; treating as 'max'", op)
        return actual_count > threshold


# ── Example policy YAML content ───────────────────────────────────────────────

_EXAMPLE_POLICY_YAML = textwrap.dedent("""\
    # TythanAI Policy-as-Code — Default Production Gate
    # Format version: 1.0
    #
    # enforcement: block  → the whole gate fails if any 'block' rule is violated
    # enforcement: warn   → violations are reported but do not fail the gate

    name: "Production Security Gate"
    version: "1.0"
    enforcement: block

    rules:
      # ── Blocking rules ───────────────────────────────────────────────────────

      - id: "P001"
        description: "No CRITICAL severity findings allowed in production"
        condition:
          severity: CRITICAL
          count: 0
          operator: max      # actual count must be <= 0
        action: block

      - id: "P002"
        description: "No hardcoded secrets or credentials"
        condition:
          rule_id_prefix: "SECRET"
          count: 0
          operator: max
        action: block

      - id: "P003"
        description: "No SQL injection vulnerabilities"
        condition:
          cwe_prefix: "CWE-89"
          count: 0
          operator: max
        action: block

      - id: "P004"
        description: "No command injection vulnerabilities"
        condition:
          cwe_prefix: "CWE-78"
          count: 0
          operator: max
        action: block

      # ── Warning rules (won't fail the gate but are reported) ─────────────────

      - id: "P005"
        description: "Maximum 5 HIGH severity findings"
        condition:
          severity: HIGH
          count: 5
          operator: max
        action: warn

      - id: "P006"
        description: "Maximum 20 MEDIUM severity findings"
        condition:
          severity: MEDIUM
          count: 20
          operator: max
        action: warn

      - id: "P007"
        description: "No unresolved authentication issues"
        condition:
          cwe_prefix: "CWE-287"
          count: 0
          operator: max
        action: warn
""")
