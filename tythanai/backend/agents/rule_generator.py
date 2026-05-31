"""Auto-generates Semgrep YAML rules from confirmed vulnerability patterns."""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
import textwrap
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from pydantic import BaseModel, Field

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.rule_generator")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SEVERITY_MAP: Dict[str, str] = {
    "CRITICAL": "ERROR",
    "HIGH": "ERROR",
    "MEDIUM": "WARNING",
    "LOW": "INFO",
    "INFO": "INFO",
}

_STABLE_THRESHOLD = 3   # confirmations in different scans before → stable
_MIN_CONFIDENCE   = 0.8
_MIN_FILE_COUNT   = 2   # pattern must appear in 2+ different files

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class GeneratedRule(BaseModel):
    """Represents a single auto-generated Semgrep rule."""

    rule_id:      str
    yaml_content: str
    hit_count:    int    = 1
    status:       str    = "draft"   # draft | stable
    created_at:   str    = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    output_path:  str    = ""
    confidence_avg: float = 0.0


# ---------------------------------------------------------------------------
# Pattern builders
# ---------------------------------------------------------------------------

def _pattern_for_taint(finding: Finding) -> str:
    """Derive a Semgrep taint-sink pattern from a finding description."""
    desc = finding.description.lower()
    ctx  = " ".join(finding.context_lines).lower()

    # Try to extract the sink function from context
    func_match = re.search(r"(\w+)\s*\(", ctx)
    if func_match:
        func_name = func_match.group(1)
        # Avoid generic names
        if func_name not in {"if", "for", "while", "return", "print", "len", "str", "int"}:
            return f"{func_name}(...)"

    # Fallback: use rule_id fragments
    parts = finding.rule_id.lower().replace("-", "_").split("_")
    for part in parts:
        if len(part) > 4 and part not in {"rule", "auto", "ghost", "scan"}:
            return f"{part}(...)"

    return "sink_function(...)"


def _pattern_for_auth(finding: Finding) -> str:
    """Pattern for missing authentication dependency in FastAPI."""
    ctx = " ".join(finding.context_lines)
    # Look for route handler without Depends
    func_match = re.search(r"async def (\w+)\s*\(([^)]*)\)", ctx)
    if func_match:
        fname = func_match.group(1)
        return f"async def {fname}(...): ..."
    return "async def $HANDLER(...): ..."


def _pattern_for_crypto(finding: Finding) -> str:
    """Pattern for weak cryptographic algorithm usage."""
    desc = finding.description.lower()
    ctx  = " ".join(finding.context_lines).lower()

    weak_algos = ["md5", "sha1", "des", "rc4", "md4", "sha-1"]
    for algo in weak_algos:
        if algo in desc or algo in ctx:
            clean = algo.replace("-", "")
            return f"hashlib.{clean}(...)"

    # Check context for hashlib / Crypto patterns
    algo_match = re.search(r'hashlib\.(\w+)\s*\(', ctx)
    if algo_match:
        return f"hashlib.{algo_match.group(1)}(...)"

    cipher_match = re.search(r'Cipher\s*\(\s*algorithms\.(\w+)', ctx)
    if cipher_match:
        return f"Cipher(algorithms.{cipher_match.group(1)}(...), ...)"

    return "hashlib.$WEAK_ALGO(...)"


def _build_pattern(finding: Finding) -> str:
    """Route to the appropriate pattern builder based on rule_id prefix."""
    rid = finding.rule_id.lower()
    if any(k in rid for k in ("taint", "injection", "sqli", "xss", "ssrf", "rce", "cmd")):
        return _pattern_for_taint(finding)
    if any(k in rid for k in ("auth", "authn", "authz", "jwt", "session", "token", "missing")):
        return _pattern_for_auth(finding)
    if any(k in rid for k in ("crypto", "hash", "cipher", "weak", "md5", "sha1", "des")):
        return _pattern_for_crypto(finding)
    # Generic: use taint builder as best-effort
    return _pattern_for_taint(finding)


# ---------------------------------------------------------------------------
# ChromaDB deduplication (optional)
# ---------------------------------------------------------------------------

_chroma_collection: Optional[Any] = None
_chroma_available = False


def _try_init_chroma(persist_dir: str = "data/chroma") -> None:
    global _chroma_collection, _chroma_available
    if _chroma_available:
        return
    try:
        import chromadb  # noqa: F401

        client = chromadb.PersistentClient(path=persist_dir)
        _chroma_collection = client.get_or_create_collection(
            name="generated_rules",
            metadata={"hnsw:space": "cosine"},
        )
        _chroma_available = True
        logger.debug("ChromaDB initialised at %s", persist_dir)
    except Exception as exc:
        logger.debug("ChromaDB unavailable (%s) — deduplication skipped", exc)


def _chroma_is_duplicate(rule_id: str, pattern: str, threshold: float = 0.92) -> bool:
    """Return True if a semantically similar rule already exists in ChromaDB."""
    if not _chroma_available or _chroma_collection is None:
        return False
    try:
        results = _chroma_collection.query(
            query_texts=[pattern],
            n_results=1,
            include=["distances"],
        )
        distances = results.get("distances", [[]])
        if distances and distances[0]:
            similarity = 1.0 - distances[0][0]
            return similarity >= threshold
    except Exception as exc:
        logger.debug("ChromaDB query failed: %s", exc)
    return False


def _chroma_add_rule(rule_id: str, pattern: str) -> None:
    if not _chroma_available or _chroma_collection is None:
        return
    try:
        _chroma_collection.upsert(
            ids=[rule_id],
            documents=[pattern],
        )
    except Exception as exc:
        logger.debug("ChromaDB upsert failed: %s", exc)


# ---------------------------------------------------------------------------
# Semgrep validation
# ---------------------------------------------------------------------------

def _validate_with_semgrep(rule_path: str) -> bool:
    """Run `semgrep --validate` on the generated rule file.  Gracefully skips."""
    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        logger.debug("semgrep not found in PATH — skipping validation")
        return True  # treat as valid when tool absent
    try:
        result = subprocess.run(
            [semgrep_bin, "--validate", rule_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            logger.info("semgrep --validate PASSED for %s", rule_path)
            return True
        logger.warning("semgrep --validate FAILED for %s:\n%s", rule_path, result.stderr)
        return False
    except Exception as exc:
        logger.warning("semgrep validation error (%s) — treating as valid", exc)
        return True


# ---------------------------------------------------------------------------
# Rule generator
# ---------------------------------------------------------------------------


class RuleGenerator:
    """Generates Semgrep YAML rules from confirmed vulnerability patterns."""

    def __init__(self, db_path: str = "data/rules.db") -> None:
        from backend.core.db import Database

        self._db = Database(db_path=db_path)
        self._db.init_schema()
        _try_init_chroma()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        findings: List[Finding],
        output_dir: str = "rules/generated",
    ) -> List[GeneratedRule]:
        """
        Generate Semgrep YAML rules from a list of findings.

        Groups findings by (rule_id, severity) where confidence >= 0.8.
        Only generates a rule when the pattern appears in 2+ different files.
        Returns the list of GeneratedRule objects produced or updated.
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # --- filter & group ---
        qualified = [f for f in findings if f.confidence >= _MIN_CONFIDENCE]
        groups: Dict[Tuple[str, str], List[Finding]] = defaultdict(list)
        for f in qualified:
            groups[(f.rule_id, f.severity)].append(f)

        produced: List[GeneratedRule] = []

        for (rule_id, severity), group_findings in groups.items():
            unique_files = {f.file for f in group_findings}
            if len(unique_files) < _MIN_FILE_COUNT:
                logger.debug(
                    "Skipping %s/%s — only in %d file(s)", rule_id, severity, len(unique_files)
                )
                continue

            rule = self._build_rule(rule_id, severity, group_findings, output_path)
            if rule is not None:
                produced.append(rule)

        logger.info("RuleGenerator produced %d rule(s)", len(produced))
        return produced

    def promote_stable_rules(self, rules_dir: str = "rules") -> int:
        """
        Copy rules that have reached stable status into rules_dir.
        Returns the number of rules promoted in this call.
        """
        stable_rows = self._db.list_generated_rules(status="stable")
        dest = Path(rules_dir)
        dest.mkdir(parents=True, exist_ok=True)

        promoted = 0
        for row in stable_rows:
            stored_path = row.get("output_path", "")
            src_path = Path(stored_path) if stored_path else Path("")
            if not src_path.exists():
                # Fallback: reconstruct from rule_id pattern
                src_path = Path("rules/generated") / f"auto_{row['rule_id']}.yaml"
            if not src_path.exists():
                logger.warning("Stable rule file not found: %s", src_path)
                continue
            dest_file = dest / src_path.name
            if dest_file.exists():
                # Already promoted — skip to avoid duplication
                continue
            shutil.copy2(str(src_path), str(dest_file))
            logger.info("Promoted stable rule %s → %s", row["rule_id"], dest_file)
            promoted += 1

        return promoted

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_rule(
        self,
        rule_id: str,
        severity: str,
        findings: List[Finding],
        output_path: Path,
    ) -> Optional[GeneratedRule]:
        """Build (or update) a single GeneratedRule and persist it."""

        pattern       = _build_pattern(findings[0])
        confidence_avg = round(
            sum(f.confidence for f in findings) / len(findings), 4
        )
        rule_hash     = self._hash_rule(rule_id, severity, pattern)
        auto_rule_id  = f"auto_rule_{rule_hash}"

        # ChromaDB dedup
        if _chroma_is_duplicate(auto_rule_id, pattern):
            logger.debug("Skipping duplicate rule %s (ChromaDB)", auto_rule_id)
            return None

        # Get current hit_count without incrementing (to predict new value)
        existing = self._db.get_generated_rule(auto_rule_id)
        pending_hit_count = (existing["hit_count"] + 1) if existing else 1
        status = "stable" if pending_hit_count >= _STABLE_THRESHOLD else "draft"

        # Build YAML with correct hit_count and status before persisting
        file_name = f"auto_{auto_rule_id}.yaml"
        rule_file = output_path / file_name

        yaml_content = self._render_yaml(
            auto_rule_id=auto_rule_id,
            pattern=pattern,
            description=findings[0].description or f"Auto-detected {rule_id}",
            semgrep_severity=_SEVERITY_MAP.get(severity.upper(), "WARNING"),
            confidence_avg=confidence_avg,
            hit_count=pending_hit_count,
            status=status,
            cwe_id=findings[0].cwe_id,
        )

        # Save to disk
        rule_file.write_text(yaml_content, encoding="utf-8")

        # Single upsert (increments hit_count once)
        hit_count = self._db.upsert_generated_rule(
            rule_id=auto_rule_id,
            yaml_content=yaml_content,
            confidence_avg=confidence_avg,
            status=status,
            output_path=str(rule_file),
        )

        _validate_with_semgrep(str(rule_file))
        _chroma_add_rule(auto_rule_id, pattern)

        db_row = self._db.get_generated_rule(auto_rule_id) or {}
        created_at = db_row.get("created_at", datetime.now(timezone.utc).isoformat())

        return GeneratedRule(
            rule_id=auto_rule_id,
            yaml_content=yaml_content,
            hit_count=hit_count,
            status=status,
            created_at=created_at,
            output_path=str(rule_file),
            confidence_avg=confidence_avg,
        )

    @staticmethod
    def _hash_rule(rule_id: str, severity: str, pattern: str) -> str:
        raw = f"{rule_id}:{severity}:{pattern}"
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    @staticmethod
    def _render_yaml(
        auto_rule_id: str,
        pattern: str,
        description: str,
        semgrep_severity: str,
        confidence_avg: float,
        hit_count: int,
        status: str,
        cwe_id: str,
    ) -> str:
        """Render a Semgrep-compatible YAML rule string."""
        rule: Dict[str, Any] = {
            "rules": [
                {
                    "id": auto_rule_id,
                    "pattern": pattern,
                    "message": description,
                    "severity": semgrep_severity,
                    "languages": ["python"],
                    "metadata": {
                        "created_at": datetime.now(timezone.utc).isoformat(),
                        "confidence": confidence_avg,
                        "hit_count": hit_count,
                        "status": status,
                        "cwe": cwe_id,
                        "auto_generated": True,
                    },
                }
            ]
        }
        return yaml.dump(rule, default_flow_style=False, sort_keys=False, allow_unicode=True)
