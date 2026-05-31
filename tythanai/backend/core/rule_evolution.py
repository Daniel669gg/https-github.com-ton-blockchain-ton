"""
backend/core/rule_evolution.py — TythanAI Rule Evolution System

Manages the full lifecycle of auto-generated rules:
    proposed → validated → active → retired
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("tythanai.rule_evolution")

# ---------------------------------------------------------------------------
# Extended schema SQL
# ---------------------------------------------------------------------------

_EVOLUTION_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS proposed_rules (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    proposal_id         TEXT    NOT NULL UNIQUE,
    rule_id             TEXT    NOT NULL,
    name                TEXT,
    description         TEXT,
    pattern_hint        TEXT,
    cwe_id              TEXT,
    severity            TEXT,
    confidence          REAL,
    confirmation_count  INTEGER DEFAULT 0,
    status              TEXT    DEFAULT 'proposed',
    version             INTEGER DEFAULT 1,
    benchmark_precision REAL,
    benchmark_recall    REAL,
    history_json        TEXT    DEFAULT '[]',
    created_at          TEXT    NOT NULL,
    updated_at          TEXT
);

CREATE TABLE IF NOT EXISTS fp_feedback (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id             TEXT,
    finding_fingerprint TEXT,
    rule_id             TEXT,
    file                TEXT,
    line                INTEGER,
    verdict             TEXT,
    created_at          TEXT    NOT NULL
);
"""

_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)

# Synthetic benchmark cases: {cwe_prefix: (tp_patterns, fp_patterns)}
# Used for the mini-benchmark inside validate_rule()
_BENCHMARK_CASES: Dict[str, Dict[str, List[str]]] = {
    "CWE-89": {
        "tp": [
            "query = 'SELECT * FROM users WHERE id=' + user_id",
            "cursor.execute('DELETE FROM logs WHERE user=' + name)",
            "db.query('INSERT INTO events VALUES(' + evt + ')')",
            "sql = f'SELECT * FROM {table} WHERE col={val}'",
            "execute('UPDATE users SET role='+role+' WHERE id='+uid)",
        ],
        "fp": [
            "query = 'SELECT * FROM users WHERE id=?'",
            "cursor.execute('SELECT * FROM table WHERE id = %s', (id,))",
            "# SELECT * FROM users",
            "query = 'SELECT 1'",
            "stmt = db.prepare('SELECT * FROM events WHERE id=?')",
        ],
    },
    "CWE-78": {
        "tp": [
            "os.system('rm -rf ' + user_input)",
            "subprocess.call('ping ' + host, shell=True)",
            "exec_cmd = 'cat ' + filename; os.popen(exec_cmd)",
            "command = 'ls ' + path; subprocess.run(command, shell=True)",
            "os.system(f'chmod {perms} {target_path}')",
        ],
        "fp": [
            "os.system('clear')",
            "subprocess.run(['ls', '-la'], check=True)",
            "# os.system('rm -rf /')",
            "cmd = ['git', 'status']",
            "subprocess.call(['echo', 'hello'])",
        ],
    },
    "CWE-79": {
        "tp": [
            "response.write('<b>' + user_input + '</b>')",
            "html = '<div>' + comment + '</div>'",
            "render_template_string('<h1>' + title + '</h1>')",
            "return f'<p>{message}</p>'",
            "innerHTML = data.userContent",
        ],
        "fp": [
            "response.write(escape(user_input))",
            "html = '<div>' + html.escape(text) + '</div>'",
            "# response.write('<b>' + user_input + '</b>')",
            "return render_template('page.html', title=title)",
            "content = bleach.clean(user_html)",
        ],
    },
    "DEFAULT": {
        "tp": [
            "result = eval(user_input)",
            "exec(code_from_user)",
            "pickle.loads(untrusted_data)",
            "yaml.load(user_data)",
            "deserialize(raw_bytes)",
        ],
        "fp": [
            "result = eval('2 + 2')",
            "exec('print(\"hello\")')",
            "# eval(user_input)",
            "data = json.loads(text)",
            "config = yaml.safe_load(stream)",
        ],
    },
}


def init_evolution_schema(db: Any) -> None:
    """Create proposed_rules table if it does not exist."""
    with db.get_conn() as conn:
        conn.executescript(_EVOLUTION_SCHEMA_SQL)
        conn.commit()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ProposedRule:
    proposal_id: str
    rule_id: str
    name: str
    description: str
    pattern_hint: str
    cwe_id: str
    severity: str
    confidence: float
    confirmation_count: int = 0
    status: str = "proposed"   # proposed | validated | active | retired
    version: int = 1
    created_at: str = ""
    updated_at: str = ""
    history: List[Dict] = field(default_factory=list)
    benchmark_precision: Optional[float] = None
    benchmark_recall: Optional[float] = None


@dataclass
class ValidationResult:
    passed: bool
    rule_id: str
    errors: List[str]
    warnings: List[str]
    estimated_fp_rate: float
    recommendation: str   # "activate" | "revise" | "reject"


@dataclass
class EffectivenessMetrics:
    rule_id: str
    hit_count: int
    fp_count: int
    tp_count: int
    precision: float
    avg_confidence: float
    is_effective: bool   # precision >= 0.90


# ---------------------------------------------------------------------------
# Rule Evolution System
# ---------------------------------------------------------------------------

class RuleEvolutionSystem:
    """Manages full rule lifecycle: proposal → validation → activation."""

    MIN_CONFIRMATIONS: int = 2
    MIN_CONFIDENCE: float = 0.8
    MIN_BENCHMARK_PRECISION: float = 0.90
    MIN_BENCHMARK_RECALL: float = 0.85

    def __init__(
        self,
        db: Optional[Any] = None,
        db_path: str = "data/tythanai.db",
        rules_output_dir: str = "rules/evolved",
    ) -> None:
        if db is not None:
            self.db = db
        else:
            from backend.core.db import Database
            self.db = Database(db_path)
            self.db.init_schema()
        self.rules_output_dir = Path(rules_output_dir)
        init_evolution_schema(self.db)

    # ------------------------------------------------------------------
    # Propose
    # ------------------------------------------------------------------

    def propose_rule(self, finding: Any, source_code_context: str = "") -> ProposedRule:
        """Propose a new rule based on a confirmed finding."""
        now = datetime.now(timezone.utc).isoformat()

        # Generate stable but unique rule_id and proposal_id
        ts_hash = hashlib.sha1(now.encode()).hexdigest()[:8]
        rule_id = f"EVOLVED-{finding.rule_id}-{ts_hash}".upper()
        proposal_id = f"PROP-{hashlib.sha1(f'{finding.rule_id}{now}'.encode()).hexdigest()[:12]}"

        # Generate a meaningful pattern_hint from description and cwe
        pattern_hint = self._derive_pattern_hint(finding)

        # Build the name from the rule_id and CWE
        cwe = getattr(finding, "cwe_id", "") or ""
        name = f"Evolved rule from {finding.rule_id}"
        if cwe:
            name = f"{name} [{cwe}]"

        proposed = ProposedRule(
            proposal_id=proposal_id,
            rule_id=rule_id,
            name=name,
            description=getattr(finding, "description", "") or f"Auto-proposed from {finding.rule_id}",
            pattern_hint=pattern_hint,
            cwe_id=cwe,
            severity=getattr(finding, "severity", "MEDIUM"),
            confidence=getattr(finding, "confidence", 0.8),
            confirmation_count=0,
            status="proposed",
            version=1,
            created_at=now,
            updated_at=now,
            history=[{"event": "proposed", "at": now, "version": 1}],
            benchmark_precision=None,
            benchmark_recall=None,
        )

        self._save_proposed_rule(proposed)
        return proposed

    # ------------------------------------------------------------------
    # Confirm
    # ------------------------------------------------------------------

    def confirm_rule(self, rule_id: str, confirming_finding: Optional[Any] = None) -> ProposedRule:
        """Add one confirmation to a proposed rule.

        If confirmation_count >= MIN_CONFIRMATIONS AND confidence >= MIN_CONFIDENCE,
        the status advances to 'validated' and validate_rule() is called.
        """
        rule = self._load_proposed_rule(rule_id)
        if rule is None:
            raise ValueError(f"Rule not found: {rule_id}")

        if rule.status not in ("proposed",):
            # Already advanced past proposed — still increment counter
            pass

        rule.confirmation_count += 1
        now = datetime.now(timezone.utc).isoformat()
        rule.updated_at = now
        rule.history.append({"event": "confirmed", "at": now, "count": rule.confirmation_count})

        if (
            rule.status == "proposed"
            and rule.confirmation_count >= self.MIN_CONFIRMATIONS
            and rule.confidence >= self.MIN_CONFIDENCE
        ):
            rule.status = "validated"
            rule.history.append({"event": "status_change", "to": "validated", "at": now})
            self._update_proposed_rule(rule)
            # Trigger validation
            self.validate_rule(rule_id)
            # Reload to get updated benchmark scores
            rule = self._load_proposed_rule(rule_id) or rule
        else:
            self._update_proposed_rule(rule)

        return rule

    # ------------------------------------------------------------------
    # Validate
    # ------------------------------------------------------------------

    def validate_rule(self, rule_id: str) -> ValidationResult:
        """Validate a proposed rule before activation."""
        rule = self._load_proposed_rule(rule_id)
        if rule is None:
            return ValidationResult(
                passed=False,
                rule_id=rule_id,
                errors=[f"Rule '{rule_id}' not found in DB"],
                warnings=[],
                estimated_fp_rate=1.0,
                recommendation="reject",
            )

        errors: List[str] = []
        warnings: List[str] = []

        # 1. Rule ID format
        if not rule_id or len(rule_id.strip()) < 3:
            errors.append("Rule ID is too short or empty")

        # 2. Description length
        if not rule.description or len(rule.description.strip()) <= 20:
            errors.append("Description must be more than 20 characters")

        # 3. Severity validity
        if rule.severity.upper() not in _VALID_SEVERITIES:
            errors.append(f"Invalid severity '{rule.severity}'. Must be one of {sorted(_VALID_SEVERITIES)}")

        # 4. CWE ID format
        if rule.cwe_id and not _CWE_RE.match(rule.cwe_id):
            errors.append(f"CWE ID format invalid: '{rule.cwe_id}'. Expected CWE-NNN")

        # 5. Pattern hint
        if not rule.pattern_hint or len(rule.pattern_hint.strip()) < 3:
            errors.append("Pattern hint is empty or too short (< 3 chars)")

        # 6. Confidence check
        if rule.confidence < self.MIN_CONFIDENCE:
            errors.append(
                f"Confidence {rule.confidence:.2f} is below minimum {self.MIN_CONFIDENCE:.2f}"
            )

        # 7. Confirmation count
        if rule.confirmation_count < self.MIN_CONFIRMATIONS:
            errors.append(
                f"Confirmation count {rule.confirmation_count} below minimum {self.MIN_CONFIRMATIONS}"
            )

        # 8. Duplicate active rules
        active_rules = self.list_active_rules()
        for ar in active_rules:
            if ar.rule_id == rule_id:
                warnings.append(f"A rule with id '{rule_id}' is already active")

        if errors:
            # Save validation result without running benchmark
            estimated_fp_rate = 1.0
            result = ValidationResult(
                passed=False,
                rule_id=rule_id,
                errors=errors,
                warnings=warnings,
                estimated_fp_rate=estimated_fp_rate,
                recommendation="reject",
            )
            now = datetime.now(timezone.utc).isoformat()
            rule.history.append({"event": "validation_failed", "errors": errors, "at": now})
            rule.updated_at = now
            self._update_proposed_rule(rule)
            return result

        # Run mini-benchmark on synthetic test cases
        precision, recall, fp_rate = self._run_mini_benchmark(rule)
        rule.benchmark_precision = precision
        rule.benchmark_recall = recall

        benchmark_errors: List[str] = []
        if precision < self.MIN_BENCHMARK_PRECISION:
            benchmark_errors.append(
                f"Benchmark precision {precision:.2f} below minimum {self.MIN_BENCHMARK_PRECISION:.2f}"
            )
        if recall < self.MIN_BENCHMARK_RECALL:
            benchmark_errors.append(
                f"Benchmark recall {recall:.2f} below minimum {self.MIN_BENCHMARK_RECALL:.2f}"
            )

        all_errors = errors + benchmark_errors
        passed = len(all_errors) == 0

        if passed:
            recommendation = "activate"
        elif benchmark_errors and not errors:
            recommendation = "revise"
        else:
            recommendation = "reject"

        now = datetime.now(timezone.utc).isoformat()
        rule.updated_at = now
        rule.history.append(
            {
                "event": "validation_complete",
                "passed": passed,
                "benchmark_precision": precision,
                "benchmark_recall": recall,
                "at": now,
            }
        )
        self._update_proposed_rule(rule)

        return ValidationResult(
            passed=passed,
            rule_id=rule_id,
            errors=all_errors,
            warnings=warnings,
            estimated_fp_rate=fp_rate,
            recommendation=recommendation,
        )

    # ------------------------------------------------------------------
    # Activate
    # ------------------------------------------------------------------

    def activate_rule(self, rule_id: str) -> bool:
        """Activate a validated rule: write YAML file, mark as active in DB."""
        rule = self._load_proposed_rule(rule_id)
        if rule is None:
            logger.error("Cannot activate: rule '%s' not found", rule_id)
            return False

        if rule.status not in ("validated", "proposed"):
            logger.warning(
                "Rule '%s' has status '%s'; expected 'validated'. Proceeding anyway.",
                rule_id,
                rule.status,
            )

        # Generate YAML content
        yaml_content = self._generate_yaml(rule)

        # Write YAML file
        self.rules_output_dir.mkdir(parents=True, exist_ok=True)
        safe_id = re.sub(r"[^a-zA-Z0-9_\-]", "_", rule_id)
        yaml_path = self.rules_output_dir / f"{safe_id}.yaml"
        try:
            yaml_path.write_text(yaml_content, encoding="utf-8")
            logger.info("Wrote evolved rule YAML to %s", yaml_path)
        except OSError as exc:
            logger.error("Failed to write YAML for rule '%s': %s", rule_id, exc)
            return False

        # Update status in DB
        now = datetime.now(timezone.utc).isoformat()
        rule.status = "active"
        rule.version += 1
        rule.updated_at = now
        rule.history.append({"event": "activated", "yaml_path": str(yaml_path), "at": now})
        self._update_proposed_rule(rule)

        # Also register with the main generated_rules table
        try:
            self.db.upsert_generated_rule(
                rule_id=rule_id,
                yaml_content=yaml_content,
                confidence_avg=rule.confidence,
                status="active",
                output_path=str(yaml_path),
            )
        except Exception as exc:
            logger.warning("Could not upsert into generated_rules for '%s': %s", rule_id, exc)

        return True

    # ------------------------------------------------------------------
    # Retire
    # ------------------------------------------------------------------

    def retire_rule(self, rule_id: str, reason: str) -> None:
        """Retire an active rule that's performing poorly."""
        rule = self._load_proposed_rule(rule_id)
        if rule is None:
            raise ValueError(f"Rule '{rule_id}' not found")

        now = datetime.now(timezone.utc).isoformat()
        rule.status = "retired"
        rule.updated_at = now
        rule.history.append({"event": "retired", "reason": reason, "at": now})
        self._update_proposed_rule(rule)
        logger.info("Rule '%s' retired. Reason: %s", rule_id, reason)

    # ------------------------------------------------------------------
    # History & effectiveness
    # ------------------------------------------------------------------

    def get_rule_history(self, rule_id: str) -> List[Dict[str, Any]]:
        """Get full version history for a rule."""
        rule = self._load_proposed_rule(rule_id)
        if rule is None:
            return []
        return rule.history

    def evaluate_effectiveness(self, rule_id: str) -> EffectivenessMetrics:
        """Calculate effectiveness metrics from DB data (findings + fp_feedback)."""
        # Count total findings from findings table
        with self.db.get_conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM findings WHERE rule_id=?", (rule_id,)
            ).fetchone()
            hit_count = int(row["cnt"]) if row else 0

            # Count FP feedback for this rule
            fp_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM fp_feedback WHERE rule_id=? AND verdict='fp'",
                (rule_id,),
            ).fetchone()
            fp_count = int(fp_row["cnt"]) if fp_row else 0

            # Average confidence
            conf_row = conn.execute(
                "SELECT AVG(confidence) AS avg_conf FROM findings WHERE rule_id=?", (rule_id,)
            ).fetchone()
            avg_confidence = float(conf_row["avg_conf"] or 0.0) if conf_row else 0.0

        tp_count = max(0, hit_count - fp_count)
        precision = tp_count / hit_count if hit_count > 0 else 1.0
        is_effective = precision >= 0.90

        return EffectivenessMetrics(
            rule_id=rule_id,
            hit_count=hit_count,
            fp_count=fp_count,
            tp_count=tp_count,
            precision=round(precision, 4),
            avg_confidence=round(avg_confidence, 4),
            is_effective=is_effective,
        )

    # ------------------------------------------------------------------
    # List helpers
    # ------------------------------------------------------------------

    def list_proposed_rules(self) -> List[ProposedRule]:
        """List all rules with status='proposed'."""
        return self._list_rules_by_status("proposed")

    def list_active_rules(self) -> List[ProposedRule]:
        """List all rules with status='active'."""
        return self._list_rules_by_status("active")

    def get_stats(self) -> Dict[str, int]:
        """Returns count of rules per status."""
        with self.db.get_conn() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS cnt FROM proposed_rules GROUP BY status"
            ).fetchall()

        counts: Dict[str, int] = {"proposed": 0, "validated": 0, "active": 0, "retired": 0}
        for row in rows:
            status = row["status"]
            if status in counts:
                counts[status] = int(row["cnt"])
        return counts

    # ------------------------------------------------------------------
    # Internal: DB helpers
    # ------------------------------------------------------------------

    def _save_proposed_rule(self, rule: ProposedRule) -> None:
        with self.db.get_conn() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO proposed_rules
                    (proposal_id, rule_id, name, description, pattern_hint, cwe_id,
                     severity, confidence, confirmation_count, status, version,
                     benchmark_precision, benchmark_recall, history_json,
                     created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    rule.proposal_id,
                    rule.rule_id,
                    rule.name,
                    rule.description,
                    rule.pattern_hint,
                    rule.cwe_id,
                    rule.severity,
                    rule.confidence,
                    rule.confirmation_count,
                    rule.status,
                    rule.version,
                    rule.benchmark_precision,
                    rule.benchmark_recall,
                    json.dumps(rule.history),
                    rule.created_at,
                    rule.updated_at,
                ),
            )
            conn.commit()

    def _update_proposed_rule(self, rule: ProposedRule) -> None:
        with self.db.get_conn() as conn:
            conn.execute(
                """
                UPDATE proposed_rules
                SET name=?, description=?, pattern_hint=?, cwe_id=?, severity=?,
                    confidence=?, confirmation_count=?, status=?, version=?,
                    benchmark_precision=?, benchmark_recall=?, history_json=?,
                    updated_at=?
                WHERE rule_id=?
                """,
                (
                    rule.name,
                    rule.description,
                    rule.pattern_hint,
                    rule.cwe_id,
                    rule.severity,
                    rule.confidence,
                    rule.confirmation_count,
                    rule.status,
                    rule.version,
                    rule.benchmark_precision,
                    rule.benchmark_recall,
                    json.dumps(rule.history),
                    rule.updated_at,
                    rule.rule_id,
                ),
            )
            conn.commit()

    def _load_proposed_rule(self, rule_id: str) -> Optional[ProposedRule]:
        with self.db.get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM proposed_rules WHERE rule_id=?", (rule_id,)
            ).fetchone()
        if row is None:
            return None
        return self._row_to_proposed_rule(dict(row))

    def _list_rules_by_status(self, status: str) -> List[ProposedRule]:
        with self.db.get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM proposed_rules WHERE status=? ORDER BY created_at DESC",
                (status,),
            ).fetchall()
        return [self._row_to_proposed_rule(dict(r)) for r in rows]

    @staticmethod
    def _row_to_proposed_rule(row: Dict[str, Any]) -> ProposedRule:
        try:
            history = json.loads(row.get("history_json") or "[]")
        except json.JSONDecodeError:
            history = []
        return ProposedRule(
            proposal_id=row.get("proposal_id", ""),
            rule_id=row.get("rule_id", ""),
            name=row.get("name", ""),
            description=row.get("description", ""),
            pattern_hint=row.get("pattern_hint", ""),
            cwe_id=row.get("cwe_id", ""),
            severity=row.get("severity", "MEDIUM"),
            confidence=float(row.get("confidence", 0.8)),
            confirmation_count=int(row.get("confirmation_count", 0)),
            status=row.get("status", "proposed"),
            version=int(row.get("version", 1)),
            created_at=row.get("created_at", ""),
            updated_at=row.get("updated_at", ""),
            history=history,
            benchmark_precision=row.get("benchmark_precision"),
            benchmark_recall=row.get("benchmark_recall"),
        )

    # ------------------------------------------------------------------
    # Internal: pattern derivation
    # ------------------------------------------------------------------

    @staticmethod
    def _derive_pattern_hint(finding: Any) -> str:
        """Derive a regex pattern hint from finding attributes."""
        cwe = (getattr(finding, "cwe_id", "") or "").upper()
        desc = (getattr(finding, "description", "") or "").lower()
        rule_id = (getattr(finding, "rule_id", "") or "").lower()

        # Common CWE-based patterns
        cwe_patterns: Dict[str, str] = {
            "CWE-89": r"(execute|query|cursor)\s*\(\s*['\"].*\+",
            "CWE-78": r"(os\.system|subprocess\.(call|run|Popen))\s*\(.*\+",
            "CWE-79": r"(response\.write|render_template_string)\s*\(.*\+",
            "CWE-22": r"(open|Path)\s*\(.*\+.*user",
            "CWE-502": r"(pickle\.loads|yaml\.load|marshal\.loads)\s*\(",
            "CWE-798": r"(password|secret|api_key)\s*=\s*['\"][^'\"]{8,}['\"]",
        }

        for cwe_key, pattern in cwe_patterns.items():
            if cwe_key in cwe:
                return pattern

        # Fallback: derive from description keywords
        if any(kw in desc for kw in ("injection", "sql", "query")):
            return r"(execute|query)\s*\(.*\+"
        if any(kw in desc for kw in ("command", "exec", "shell")):
            return r"(os\.system|subprocess)\s*\(.*\+"
        if any(kw in desc for kw in ("xss", "cross-site", "html")):
            return r"response\.write\s*\(.*\+"
        if any(kw in desc for kw in ("hardcoded", "password", "secret", "credential")):
            return r"(password|secret|token)\s*=\s*['\"][^'\"]+['\"]"
        if any(kw in desc for kw in ("deseriali", "pickle", "marshal")):
            return r"(pickle\.loads|yaml\.load)\s*\("

        # Generic fallback based on rule_id
        base = re.sub(r"[^a-z0-9]", ".", rule_id)
        return f"({base})"

    # ------------------------------------------------------------------
    # Internal: mini benchmark
    # ------------------------------------------------------------------

    def _run_mini_benchmark(self, rule: ProposedRule) -> tuple[float, float, float]:
        """Run synthetic benchmark — returns (precision, recall, fp_rate)."""
        cwe = rule.cwe_id.upper() if rule.cwe_id else ""
        pattern_str = rule.pattern_hint or ""

        # Select benchmark cases matching the CWE
        cases = _BENCHMARK_CASES.get("DEFAULT", {"tp": [], "fp": []})
        for cwe_key, case_data in _BENCHMARK_CASES.items():
            if cwe_key != "DEFAULT" and cwe_key in cwe:
                cases = case_data
                break

        tp_examples = cases.get("tp", [])
        fp_examples = cases.get("fp", [])

        # Try to compile the pattern; fall back to substring match
        try:
            compiled = re.compile(pattern_str, re.IGNORECASE)
            match_fn = lambda text: bool(compiled.search(text))  # noqa: E731
        except re.error:
            # Escape and use substring search
            simple_token = re.sub(r"[\\^$.*+?()[\]{}|]", "", pattern_str).split()[0] if pattern_str else ""
            match_fn = lambda text: simple_token.lower() in text.lower()  # noqa: E731

        # True positives: pattern should match TP examples
        tp_hits = sum(1 for ex in tp_examples if match_fn(ex))
        # False positives: pattern should NOT match FP examples
        fp_hits = sum(1 for ex in fp_examples if match_fn(ex))

        total_tp = len(tp_examples)
        total_fp = len(fp_examples)

        recall = tp_hits / total_tp if total_tp > 0 else 1.0
        # Precision: of what we flagged, how many are TP
        total_flagged = tp_hits + fp_hits
        precision = tp_hits / total_flagged if total_flagged > 0 else 1.0
        fp_rate = fp_hits / total_fp if total_fp > 0 else 0.0

        return round(precision, 4), round(recall, 4), round(fp_rate, 4)

    # ------------------------------------------------------------------
    # Internal: YAML generation
    # ------------------------------------------------------------------

    def _generate_yaml(self, rule: ProposedRule) -> str:
        """Generate Semgrep-compatible YAML content for the rule."""
        severity_map = {
            "CRITICAL": "ERROR",
            "HIGH": "ERROR",
            "MEDIUM": "WARNING",
            "LOW": "INFO",
            "INFO": "INFO",
        }
        semgrep_severity = severity_map.get(rule.severity.upper(), "WARNING")

        cwe_list = f"[{rule.cwe_id}]" if rule.cwe_id else "[]"
        # Escape double quotes in description and pattern_hint for YAML
        safe_desc = rule.description.replace('"', '\\"')
        safe_pattern = rule.pattern_hint.replace('"', '\\"')

        yaml_content = f"""rules:
  - id: {rule.rule_id}
    message: "{safe_desc}"
    languages: [python, javascript, java, go]
    severity: {semgrep_severity}
    metadata:
      cwe: {cwe_list}
      tythanai_evolved: true
      version: {rule.version}
      confidence: {rule.confidence}
      confirmations: {rule.confirmation_count}
    pattern-regex: "{safe_pattern}"
"""
        return yaml_content
