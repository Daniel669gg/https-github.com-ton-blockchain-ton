"""
TythanAI Platform — Confidence Engine
Statistical confidence scoring, false-positive reduction,
consensus validation, and finding prioritization.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ── Severity weights ───────────────────────────────────────────────────────────
_SEV_WEIGHT = {"CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.2, "INFO": 0.05}

# Known false-positive patterns by rule type
_FP_PATTERNS: Dict[str, List[str]] = {
    "hardcoded_secret": [
        r"(example|placeholder|dummy|fake|test|demo|sample|xxx+|your[-_]?(?:key|api|token|secret)|insert_here|your_api_key)",
        r"<[A-Z_]+>",           # template placeholders
        r"\$\{[^}]+\}",         # env-var references
        r"changeme|replace_me|insert_here",
    ],
    "sql_injection": [
        r"#\s*(nosec|noqa)",    # explicit suppression
        r"self\._db\s*is\s*None",  # guard checks
    ],
    "shell_injection": [
        r"subprocess\.run\([^)]+shell=False",
        r"shlex\.quote",
    ],
}


def _is_likely_fp(finding: dict) -> Tuple[bool, str]:
    """Heuristic false-positive detection. Returns (is_fp, reason)."""
    ftype   = (finding.get("type") or finding.get("id") or "").lower()
    context = finding.get("context") or finding.get("code_snippet") or finding.get("evidence") or ""
    message = finding.get("message") or finding.get("description") or ""
    combined = (context + " " + message).lower()

    # Check FP suppression comments
    if "# nosec" in combined or "# noqa" in combined or "nosec" in combined:
        return True, "nosec/noqa suppression"

    for pattern_type, patterns in _FP_PATTERNS.items():
        if pattern_type not in ftype and pattern_type.split("_")[0] not in ftype:
            continue
        for p in patterns:
            if re.search(p, combined, re.IGNORECASE):
                return True, f"matches fp-pattern: {p}"

    return False, ""


# ── Confidence scoring ─────────────────────────────────────────────────────────

@dataclass
class ConfidenceFactors:
    """Individual factors contributing to the overall confidence score."""
    rule_confidence: float    = 1.0   # base confidence from the scanner rule
    context_quality: float    = 1.0   # how much context was available
    fp_risk:         float    = 0.0   # probability of false positive (0–1)
    consensus_bonus: float    = 0.0   # reward for multi-scanner agreement
    historical_boost: float   = 0.0   # from past confirmed findings of same type

    def final(self) -> float:
        raw = (
            self.rule_confidence * 0.40
            + self.context_quality * 0.25
            + (1.0 - self.fp_risk) * 0.20
            + self.consensus_bonus * 0.10
            + self.historical_boost * 0.05
        )
        return round(max(0.0, min(1.0, raw)), 3)


def _score_finding(finding: dict) -> Tuple[float, ConfidenceFactors]:
    """Compute confidence for a single finding."""
    factors = ConfidenceFactors()

    # Rule confidence — use scanner-provided value if present
    factors.rule_confidence = float(finding.get("confidence", 0.8))

    # Context quality — do we have code context?
    ctx = finding.get("context") or finding.get("code_snippet") or ""
    factors.context_quality = 0.9 if len(ctx) > 20 else (0.6 if ctx else 0.3)

    # False-positive risk
    is_fp, _ = _is_likely_fp(finding)
    factors.fp_risk = 0.85 if is_fp else 0.0

    return factors.final(), factors


# ── Deduplication ─────────────────────────────────────────────────────────────

def _finding_fingerprint(finding: dict) -> str:
    """Stable fingerprint for deduplication."""
    parts = [
        str(finding.get("type") or finding.get("id") or ""),
        str(finding.get("file") or ""),
        str(finding.get("line") or ""),
        str(finding.get("rule_id") or ""),
    ]
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]


# ── Consensus validation ───────────────────────────────────────────────────────

def _consensus_score(fingerprint: str, all_findings: List[dict]) -> float:
    """
    Boost for findings that appear across multiple independent scanners.
    Agreement among N scanners → bonus up to 0.3.
    """
    matches = sum(
        1 for f in all_findings
        if _finding_fingerprint(f) == fingerprint
        and f.get("scanner")
    )
    unique_scanners = len({
        f.get("scanner") for f in all_findings
        if _finding_fingerprint(f) == fingerprint and f.get("scanner")
    })
    return round(min(unique_scanners * 0.10, 0.30), 3)


# ── Prioritization ─────────────────────────────────────────────────────────────

_PRIORITY_LABELS = ["P1_CRITICAL", "P2_HIGH", "P3_MEDIUM", "P4_LOW", "P5_INFO"]


def _priority_label(confidence: float, severity: str) -> str:
    sev_w = _SEV_WEIGHT.get(severity.upper(), 0.2)
    score = confidence * sev_w
    if score >= 0.75:
        return "P1_CRITICAL"
    elif score >= 0.55:
        return "P2_HIGH"
    elif score >= 0.35:
        return "P3_MEDIUM"
    elif score >= 0.15:
        return "P4_LOW"
    return "P5_INFO"


# ── Main API ───────────────────────────────────────────────────────────────────

class ConfidenceEngine:
    """
    Full confidence pipeline:
    1. Score each finding
    2. Detect & remove false positives
    3. Apply consensus bonus for multi-scanner agreement
    4. Prioritize findings
    5. Deduplicate
    """

    def __init__(
        self,
        fp_threshold: float = 0.70,    # discard findings below this confidence
        dedup: bool = True,
    ) -> None:
        self.fp_threshold = fp_threshold
        self.dedup        = dedup

    def process(self, findings: List[dict]) -> dict:
        """
        Process a flat list of findings from one or more scanners.
        Returns enriched + filtered + prioritized list.
        """
        if not findings:
            return {"findings": [], "discarded_fps": [], "stats": {}}

        enriched   : List[dict] = []
        discarded  : List[dict] = []
        seen_fps   : set        = set()  # for dedup

        for raw in findings:
            finding = dict(raw)  # shallow copy
            fp      = _finding_fingerprint(finding)

            # Dedup
            if self.dedup and fp in seen_fps:
                continue
            seen_fps.add(fp)

            # Score
            conf, factors = _score_finding(finding)

            # Consensus bonus
            consensus = _consensus_score(fp, findings)
            conf      = min(1.0, conf + consensus)
            factors.consensus_bonus = consensus

            # FP filter
            is_fp, reason = _is_likely_fp(finding)
            if is_fp or conf < self.fp_threshold:
                finding["_discarded_reason"] = reason or f"low_confidence({conf:.2f})"
                discarded.append(finding)
                continue

            # Enrich
            finding["confidence"]       = conf
            finding["confidence_label"] = self._label(conf)
            finding["priority"]         = _priority_label(conf, finding.get("severity", "MEDIUM"))
            finding["fingerprint"]      = fp
            finding["_factors"]         = {
                "rule_confidence":  factors.rule_confidence,
                "context_quality":  factors.context_quality,
                "fp_risk":          factors.fp_risk,
                "consensus_bonus":  factors.consensus_bonus,
            }
            enriched.append(finding)

        # Sort: priority asc (P1 first), then confidence desc
        enriched.sort(key=lambda f: (f.get("priority", "P5"), -f.get("confidence", 0)))

        stats = self._stats(enriched, discarded)
        return {
            "findings":      enriched,
            "discarded_fps": discarded,
            "stats":         stats,
        }

    @staticmethod
    def _label(conf: float) -> str:
        if conf >= 0.90:
            return "VERY_HIGH"
        elif conf >= 0.75:
            return "HIGH"
        elif conf >= 0.55:
            return "MEDIUM"
        elif conf >= 0.35:
            return "LOW"
        return "VERY_LOW"

    @staticmethod
    def _stats(enriched: List[dict], discarded: List[dict]) -> dict:
        counts: dict = {}
        for f in enriched:
            p = f.get("priority", "P5")
            counts[p] = counts.get(p, 0) + 1
        avg_conf = (
            sum(f.get("confidence", 0) for f in enriched) / len(enriched)
            if enriched else 0.0
        )
        return {
            "total_input":     len(enriched) + len(discarded),
            "after_filter":    len(enriched),
            "discarded_fps":   len(discarded),
            "avg_confidence":  round(avg_conf, 3),
            "by_priority":     counts,
        }

    def explain(self, finding: dict) -> str:
        """Human-readable explanation of the confidence decision."""
        conf, factors = _score_finding(finding)
        is_fp, fp_reason = _is_likely_fp(finding)
        lines = [
            f"Confidence: {conf:.2f}  ({self._label(conf)})",
            f"  rule_confidence : {factors.rule_confidence:.2f}",
            f"  context_quality : {factors.context_quality:.2f}",
            f"  fp_risk         : {factors.fp_risk:.2f}" + (f"  ← {fp_reason}" if is_fp else ""),
            f"  consensus_bonus : {factors.consensus_bonus:.2f}",
            f"Priority: {_priority_label(conf, finding.get('severity','MEDIUM'))}",
        ]
        return "\n".join(lines)


# Module-level singleton
ENGINE = ConfidenceEngine()
