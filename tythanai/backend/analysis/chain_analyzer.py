"""
backend/analysis/chain_analyzer.py

Enhanced attack chain analysis — builds comprehensive chain detection beyond the
existing react_agent.py _RuleBasedFallback.  Combines CWE-relationship patterns
with rule-ID keyword patterns, deduplicates overlapping chains, builds ordered
exploit paths, and calculates a CVSS-like combined risk score.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from backend.core.confidence import Finding


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ChainNode:
    finding_fingerprint: str
    rule_id: str
    severity: str
    file: str
    line: int
    cwe_id: str


@dataclass
class ExploitPath:
    path_id: str
    nodes: List[ChainNode]        # ordered: entry point → impact
    total_risk: float             # 0.0–1.0
    exploitability: str           # "trivial" | "easy" | "moderate" | "difficult"
    impact: str                   # "data_breach" | "rce" | "priv_esc" | "dos" | "info_disclosure"
    narrative: str


@dataclass
class ChainResult:
    chain_id: str
    finding_fingerprints: List[str]
    severity: str
    chain_type: str               # "injection_chain" | "auth_chain" | "secret_chain" | "multi_vuln"
    combined_risk_score: float    # 0.0–10.0
    narrative: str
    exploit_paths: List[ExploitPath]
    confidence: float


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEV_ORDER: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def _max_sev(severities: List[str]) -> str:
    """Return the highest severity from a list."""
    return max(severities, key=lambda s: _SEV_ORDER.get(s.upper(), 0), default="LOW")


# ---------------------------------------------------------------------------
# ChainAnalyzer
# ---------------------------------------------------------------------------


class ChainAnalyzer:
    """
    Comprehensive attack chain detection and risk calculation.

    Combines two complementary detection strategies:
    1. CWE-relationship patterns — identifies dangerous CWE co-occurrences
    2. Rule-ID keyword patterns — identifies dangerous rule-ID keyword combos

    Then deduplicates overlapping chains, builds ordered exploit paths, and
    computes a CVSS-like combined risk score for each chain.
    """

    _SEV_WEIGHTS: Dict[str, float] = {
        "CRITICAL": 10.0,
        "HIGH": 7.5,
        "MEDIUM": 5.0,
        "LOW": 2.5,
        "INFO": 0.5,
    }

    # ------------------------------------------------------------------
    # CWE chain rules
    # (set_a, set_b, chain_type, severity_escalation, narrative)
    # A chain fires when ≥1 finding matches set_a AND ≥1 matches set_b.
    # ------------------------------------------------------------------
    _CWE_CHAIN_RULES: List[Tuple[Set[str], Set[str], str, str, str]] = [
        (
            {"CWE-89"},
            {"CWE-306", "CWE-862"},
            "injection_chain",
            "CRITICAL",
            "SQL Injection combined with missing authentication creates fully unauthenticated data breach path",
        ),
        (
            {"CWE-78", "CWE-94"},
            {"CWE-20"},
            "injection_chain",
            "CRITICAL",
            "Command/code injection with absent input validation enables trivial remote code execution",
        ),
        (
            {"CWE-798"},
            {"CWE-306", "CWE-862"},
            "auth_chain",
            "CRITICAL",
            "Hard-coded credentials plus weak authentication enables full system compromise",
        ),
        (
            {"CWE-287"},
            {"CWE-862"},
            "auth_chain",
            "HIGH",
            "Authentication bypass combined with missing authorization enables horizontal privilege escalation",
        ),
        (
            {"CWE-89"},
            {"CWE-200"},
            "multi_vuln",
            "CRITICAL",
            "SQL injection enables extraction of sensitive data including PII",
        ),
        (
            {"CWE-22"},
            {"CWE-200", "CWE-312"},
            "multi_vuln",
            "HIGH",
            "Path traversal enables access to files containing sensitive unencrypted data",
        ),
        (
            {"CWE-327", "CWE-326"},
            {"CWE-312", "CWE-313"},
            "multi_vuln",
            "HIGH",
            "Broken cryptography combined with cleartext storage/transmission enables data recovery",
        ),
        (
            {"CWE-502"},
            {"CWE-78", "CWE-94"},
            "injection_chain",
            "CRITICAL",
            "Unsafe deserialization leading to code execution enables full RCE via malicious payload",
        ),
        (
            {"CWE-918"},
            {"CWE-200", "CWE-306"},
            "multi_vuln",
            "HIGH",
            "SSRF enables access to internal services and sensitive metadata endpoints",
        ),
    ]

    # ------------------------------------------------------------------
    # Rule-ID keyword chain rules
    # (keywords_a, keywords_b, chain_type, severity_escalation, narrative)
    # Matching is performed on the uppercase rule_id of each finding.
    # ------------------------------------------------------------------
    _KEYWORD_CHAIN_RULES: List[Tuple[Set[str], Set[str], str, str, str]] = [
        (
            {"SQLI", "SQL", "SQL-INJECTION"},
            {"NO-AUTH", "AUTH-BYPASS", "NOAUTH"},
            "injection_chain",
            "CRITICAL",
            "SQL injection with missing authentication: full unauthenticated database access",
        ),
        (
            {"EXEC", "EVAL", "CMD"},
            {"NO-VALID", "UNVALIDATED", "UNSAFE-INPUT"},
            "injection_chain",
            "CRITICAL",
            "Code execution without input validation: trivial RCE",
        ),
        (
            {"SECRET", "API-KEY", "HARDCODED-CRED"},
            {"NO-AUTH", "AUTH"},
            "auth_chain",
            "CRITICAL",
            "Exposed credentials combined with weak auth: full compromise",
        ),
        (
            {"PATH-TRAV", "PATH_TRAV", "LFI"},
            {"WRITE", "UPLOAD", "FILE-WRITE"},
            "multi_vuln",
            "CRITICAL",
            "Path traversal + file write: arbitrary file overwrite including webshell upload",
        ),
        (
            {"XSS", "CROSS-SITE"},
            {"NO-CSP", "CORS-WILDCARD", "MISSING-HEADER"},
            "multi_vuln",
            "HIGH",
            "XSS without security headers: persistent cross-site attacks",
        ),
        (
            {"SSRF"},
            {"INTERNAL", "PRIV-ESC", "CLOUD-METADATA"},
            "multi_vuln",
            "HIGH",
            "SSRF reaching internal resources: lateral movement to internal services",
        ),
        (
            {"DESER", "PICKLE", "UNSAFE-YAML"},
            {"EXEC", "RCE", "EVAL"},
            "injection_chain",
            "CRITICAL",
            "Deserialization + execution: RCE via crafted payload",
        ),
    ]

    # ------------------------------------------------------------------
    # Impact classification helpers
    # ------------------------------------------------------------------
    _IMPACT_MAP: List[Tuple[List[str], str]] = [
        (["CWE-78", "CWE-94", "CWE-502"], "rce"),
        (["CWE-89", "CWE-200", "CWE-312", "CWE-313"], "data_breach"),
        (["CWE-306", "CWE-862", "CWE-287", "CWE-798"], "priv_esc"),
        (["CWE-400", "CWE-770", "CWE-835"], "dos"),
        (["CWE-22", "CWE-918", "CWE-79"], "info_disclosure"),
    ]

    _RCE_KEYWORDS = {"EXEC", "EVAL", "CMD", "RCE", "DESER", "PICKLE"}
    _AUTH_KEYWORDS = {"AUTH", "IDOR", "PRIV", "BYPASS"}
    _BREACH_KEYWORDS = {"SQLI", "SQL", "LFI", "TRAV", "SSRF", "SECRET", "CRED"}
    _DOS_KEYWORDS = {"DOS", "FLOOD", "BOMB", "LOOP"}

    # ------------------------------------------------------------------
    # Entry-point detection: findings that represent access-control weaknesses
    # or input surface come first in an exploit path.
    # ------------------------------------------------------------------
    _ENTRY_CWES = {"CWE-306", "CWE-862", "CWE-287", "CWE-20"}
    _ENTRY_KEYWORDS = {"AUTH", "INPUT", "VALID", "ENTRY", "NO-AUTH", "PARAM"}

    # ---------------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------------

    def analyze(self, findings: List[Finding]) -> List[ChainResult]:
        """Main entry point — detect all attack chains in *findings*."""
        if len(findings) < 2:
            return []

        cwe_chains = self._detect_cwe_chains(findings)
        kw_chains = self._detect_keyword_chains(findings)
        all_chains = cwe_chains + kw_chains

        deduped = self._deduplicate_chains(all_chains)

        # Enrich each chain with exploit paths
        enriched: List[ChainResult] = []
        for chain in deduped:
            chain_findings = [
                f for f in findings if f.fingerprint() in chain.finding_fingerprints
            ]
            chain.exploit_paths = self.build_exploit_paths(chain, chain_findings)
            enriched.append(chain)

        return enriched

    # ---------------------------------------------------------------------------
    # CWE-based chain detection
    # ---------------------------------------------------------------------------

    def _detect_cwe_chains(self, findings: List[Finding]) -> List[ChainResult]:
        """Detect chains using CWE co-occurrence rules."""
        results: List[ChainResult] = []

        for set_a, set_b, chain_type, severity, narrative in self._CWE_CHAIN_RULES:
            # Gather findings that match each side
            side_a = [f for f in findings if f.cwe_id in set_a]
            side_b = [f for f in findings if f.cwe_id in set_b]

            if not side_a or not side_b:
                continue

            # Avoid self-match: the same finding matching both sides is fine only
            # if it is genuinely in both (rare — mostly different findings).
            chain_fps = list({f.fingerprint() for f in side_a + side_b})
            chain_findings = [f for f in findings if f.fingerprint() in chain_fps]

            risk = self.calculate_chain_risk(chain_findings)
            avg_conf = sum(f.confidence for f in chain_findings) / len(chain_findings)

            results.append(
                ChainResult(
                    chain_id=uuid.uuid4().hex[:8],
                    finding_fingerprints=chain_fps,
                    severity=severity,
                    chain_type=chain_type,
                    combined_risk_score=risk,
                    narrative=narrative,
                    exploit_paths=[],
                    confidence=round(avg_conf, 4),
                )
            )

        return results

    # ---------------------------------------------------------------------------
    # Keyword-based chain detection
    # ---------------------------------------------------------------------------

    def _detect_keyword_chains(self, findings: List[Finding]) -> List[ChainResult]:
        """Detect chains using rule-ID keyword co-occurrence rules."""
        results: List[ChainResult] = []

        for kw_a, kw_b, chain_type, severity, narrative in self._KEYWORD_CHAIN_RULES:
            side_a = [
                f for f in findings
                if any(kw in f.rule_id.upper() for kw in kw_a)
            ]
            side_b = [
                f for f in findings
                if any(kw in f.rule_id.upper() for kw in kw_b)
            ]

            if not side_a or not side_b:
                continue

            chain_fps = list({f.fingerprint() for f in side_a + side_b})
            chain_findings = [f for f in findings if f.fingerprint() in chain_fps]

            risk = self.calculate_chain_risk(chain_findings)
            avg_conf = sum(f.confidence for f in chain_findings) / len(chain_findings)

            results.append(
                ChainResult(
                    chain_id=uuid.uuid4().hex[:8],
                    finding_fingerprints=chain_fps,
                    severity=severity,
                    chain_type=chain_type,
                    combined_risk_score=risk,
                    narrative=narrative,
                    exploit_paths=[],
                    confidence=round(avg_conf, 4),
                )
            )

        return results

    # ---------------------------------------------------------------------------
    # Deduplication
    # ---------------------------------------------------------------------------

    def _deduplicate_chains(self, chains: List[ChainResult]) -> List[ChainResult]:
        """
        Remove chains that cover an identical set of findings.

        When two chains share the same fingerprint set, keep the one with the
        higher severity (then higher combined_risk_score as tiebreaker).
        """
        # Key: frozenset of fingerprints → best chain so far
        best: Dict[frozenset, ChainResult] = {}

        for chain in chains:
            key = frozenset(chain.finding_fingerprints)
            if key not in best:
                best[key] = chain
            else:
                existing = best[key]
                # Prefer higher severity
                if _SEV_ORDER.get(chain.severity, 0) > _SEV_ORDER.get(existing.severity, 0):
                    best[key] = chain
                elif (
                    _SEV_ORDER.get(chain.severity, 0) == _SEV_ORDER.get(existing.severity, 0)
                    and chain.combined_risk_score > existing.combined_risk_score
                ):
                    best[key] = chain

        return list(best.values())

    # ---------------------------------------------------------------------------
    # Exploit path construction
    # ---------------------------------------------------------------------------

    def build_exploit_paths(
        self, chain: ChainResult, findings: List[Finding]
    ) -> List[ExploitPath]:
        """
        Build ordered exploit paths for a chain.

        Ordering strategy:
        1. Entry points (authentication/validation weaknesses, CWE-306/862/20)
        2. Exploitation vulnerabilities (injections, execution)
        3. Impact findings (data exposure, asset access)

        Exploitability is determined by the combined severity and confidence of
        the chain members.
        """
        if not findings:
            return []

        # Build ChainNodes
        nodes: List[ChainNode] = [
            ChainNode(
                finding_fingerprint=f.fingerprint(),
                rule_id=f.rule_id,
                severity=f.severity,
                file=f.file,
                line=f.line,
                cwe_id=f.cwe_id,
            )
            for f in findings
        ]

        # Sort: entry points first, then by severity desc, then by line number
        def _node_priority(cn: ChainNode) -> Tuple[int, int, int]:
            is_entry = int(
                cn.cwe_id in self._ENTRY_CWES
                or any(kw in cn.rule_id.upper() for kw in self._ENTRY_KEYWORDS)
            )
            sev_rank = _SEV_ORDER.get(cn.severity.upper(), 0)
            return (-is_entry, -sev_rank, cn.line)  # negative = higher priority first

        nodes.sort(key=_node_priority)

        # Risk and exploitability
        total_risk = chain.combined_risk_score / 10.0  # normalise to 0.0–1.0
        total_risk = max(0.0, min(1.0, total_risk))

        avg_conf = sum(f.confidence for f in findings) / len(findings)
        max_sev = _max_sev([f.severity for f in findings])

        if max_sev == "CRITICAL" and avg_conf >= 0.85:
            exploitability = "trivial"
        elif max_sev in ("CRITICAL", "HIGH") and avg_conf >= 0.70:
            exploitability = "easy"
        elif avg_conf >= 0.60:
            exploitability = "moderate"
        else:
            exploitability = "difficult"

        # Determine impact category
        impact = self._classify_impact(findings)

        path = ExploitPath(
            path_id=uuid.uuid4().hex[:8],
            nodes=nodes,
            total_risk=round(total_risk, 4),
            exploitability=exploitability,
            impact=impact,
            narrative=chain.narrative,
        )
        return [path]

    def _classify_impact(self, findings: List[Finding]) -> str:
        """Classify the primary impact type of a group of findings."""
        cwe_ids = {f.cwe_id for f in findings}
        rule_ids_upper = " ".join(f.rule_id.upper() for f in findings)

        for cwe_list, impact in self._IMPACT_MAP:
            if any(c in cwe_ids for c in cwe_list):
                return impact

        if any(kw in rule_ids_upper for kw in self._RCE_KEYWORDS):
            return "rce"
        if any(kw in rule_ids_upper for kw in self._AUTH_KEYWORDS):
            return "priv_esc"
        if any(kw in rule_ids_upper for kw in self._BREACH_KEYWORDS):
            return "data_breach"
        if any(kw in rule_ids_upper for kw in self._DOS_KEYWORDS):
            return "dos"
        return "info_disclosure"

    # ---------------------------------------------------------------------------
    # Risk score calculation
    # ---------------------------------------------------------------------------

    def calculate_chain_risk(self, chain_findings: List[Finding]) -> float:
        """
        Calculate combined risk score (0.0–10.0) for a group of findings.

        Algorithm:
        - base_score = max severity weight across chain members
        - multiplier = 1 + 0.2 * (len(chain) - 1)   (each extra finding adds 20 %)
        - confidence_factor = average confidence of chain members
        - final = min(10.0, base_score * multiplier * confidence_factor)
        """
        if not chain_findings:
            return 0.0

        base_score = max(
            self._SEV_WEIGHTS.get(f.severity.upper(), 5.0) for f in chain_findings
        )
        multiplier = 1.0 + 0.2 * (len(chain_findings) - 1)
        confidence_factor = sum(f.confidence for f in chain_findings) / len(chain_findings)

        raw = base_score * multiplier * confidence_factor
        return round(min(10.0, raw), 4)

    # ---------------------------------------------------------------------------
    # Critical-path filter
    # ---------------------------------------------------------------------------

    def get_critical_paths(self, findings: List[Finding]) -> List[ExploitPath]:
        """Return all exploit paths that belong to CRITICAL-severity chains."""
        chains = self.analyze(findings)
        paths: List[ExploitPath] = []
        for chain in chains:
            if chain.severity == "CRITICAL":
                paths.extend(chain.exploit_paths)
        return paths

    # ---------------------------------------------------------------------------
    # Markdown summary
    # ---------------------------------------------------------------------------

    def to_markdown_summary(self, chains: List[ChainResult]) -> str:
        """Generate a Markdown summary of all detected chains."""
        if not chains:
            return "## Attack Chain Analysis\n\nNo attack chains detected.\n"

        lines: List[str] = [
            "## Attack Chain Analysis",
            "",
            f"**Total chains detected:** {len(chains)}",
            "",
        ]

        # Sort by severity then risk score
        sorted_chains = sorted(
            chains,
            key=lambda c: (_SEV_ORDER.get(c.severity, 0), c.combined_risk_score),
            reverse=True,
        )

        for i, chain in enumerate(sorted_chains, start=1):
            lines.append(f"### Chain {i}: {chain.chain_type.replace('_', ' ').title()}")
            lines.append(f"- **ID:** `{chain.chain_id}`")
            lines.append(f"- **Severity:** {chain.severity}")
            lines.append(f"- **Risk Score:** {chain.combined_risk_score:.1f}/10.0")
            lines.append(f"- **Confidence:** {chain.confidence:.0%}")
            lines.append(f"- **Findings:** {len(chain.finding_fingerprints)}")
            lines.append(f"- **Narrative:** {chain.narrative}")

            if chain.exploit_paths:
                ep = chain.exploit_paths[0]
                lines.append(
                    f"- **Exploitability:** {ep.exploitability.title()} | "
                    f"**Impact:** {ep.impact.replace('_', ' ').title()}"
                )

            lines.append("")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------


def analyze_attack_chains(findings: List[Finding]) -> List[ChainResult]:
    """Analyze findings for attack chains."""
    return ChainAnalyzer().analyze(findings)
