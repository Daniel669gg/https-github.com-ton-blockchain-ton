"""
backend/agents/multi_agent_orchestrator.py

TythanAI Multi-Agent Orchestrator — eight specialized security analysis agents
working as a coordinated system. Pure algorithmic intelligence; no LLM calls.
"""
from __future__ import annotations

import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from backend.core.confidence import Finding

# ─────────────────────────────────────────────────────────────────────────────
# Severity helpers
# ─────────────────────────────────────────────────────────────────────────────

_SEV_ORDER: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

_SEV_WEIGHTS: Dict[str, float] = {
    "CRITICAL": 10.0,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 0.5,
}


def _max_sev(severities: List[str]) -> str:
    return max(severities, key=lambda s: _SEV_ORDER.get(s.upper(), 0), default="LOW")


# ─────────────────────────────────────────────────────────────────────────────
# Shared data models
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class AnalysisPlan:
    plan_id: str
    priority_order: List[str]   # ordered list of finding fingerprints
    focus_areas: List[str]      # e.g. ["authentication", "injection", "secrets"]
    scan_depth: str             # "quick" | "standard" | "deep"
    estimated_chains: int       # predicted number of attack chains
    notes: str


@dataclass
class ResearchResult:
    finding_fingerprint: str
    cwe_details: Dict[str, str]  # {"name": ..., "description": ..., "impact": ...}
    related_cwes: List[str]
    exploit_likelihood: float    # 0.0–1.0
    remediation_complexity: str  # "low" | "medium" | "high"
    similar_past_cases: List[str]


@dataclass
class AnalysisResult:
    finding_fingerprint: str
    adjusted_severity: str       # may differ from original
    adjusted_confidence: float
    impact_assessment: str
    attack_vectors: List[str]
    requires_chain_analysis: bool
    reasoning: str


@dataclass
class VerificationResult:
    finding_fingerprint: str
    verdict: str                 # "confirmed" | "false_positive" | "needs_review"
    evidence_found: List[str]
    confidence_adjustment: float  # -0.3 to +0.3
    reasoning: str


@dataclass
class CritiqueResult:
    finding_fingerprint: str
    issues_found: List[str]
    is_sound: bool               # True if no major issues
    suggested_revisions: List[Dict[str, Any]]


@dataclass
class GeneratedRule:
    rule_id: str
    name: str
    description: str
    pattern_hint: str
    cwe_id: str
    severity: str
    confidence: float
    based_on_fingerprints: List[str]


class OrchestratorReport(BaseModel):
    session_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:8])
    original_findings: List[Finding] = Field(default_factory=list)
    confirmed_findings: List[Finding] = Field(default_factory=list)
    removed_findings: List[Finding] = Field(default_factory=list)
    attack_chains: List[Dict[str, Any]] = Field(default_factory=list)
    generated_rules: List[Dict[str, Any]] = Field(default_factory=list)
    report_markdown: str = ""
    plan_notes: str = ""
    total_iterations: int = 0
    precision_estimate: float = 0.0

    model_config = {"arbitrary_types_allowed": True}


# ─────────────────────────────────────────────────────────────────────────────
# Agent 1: PlannerAgent
# ─────────────────────────────────────────────────────────────────────────────


class PlannerAgent:
    """Builds an analysis plan from the findings list.

    Logic:
    - Sort findings by severity (CRITICAL first)
    - Identify focus_areas from CWE IDs and rule_ids
    - Determine scan_depth: >50 findings → deep, >20 → standard, else quick
    - Estimate chains: count findings that participate in known dangerous combos
    """

    _FOCUS_AREA_KEYWORDS: Dict[str, List[str]] = {
        "injection": ["SQLI", "SQL", "EXEC", "EVAL", "CWE-89", "CWE-78", "CWE-94"],
        "authentication": ["AUTH", "IDOR", "NO-AUTH", "CWE-306", "CWE-862"],
        "secrets": ["SECRET", "KEY", "TOKEN", "CRED", "CWE-798"],
        "path_traversal": ["PATH", "TRAV", "LFI", "CWE-22"],
        "cryptography": ["CRYPTO", "MD5", "SHA1", "ECB", "CWE-327", "CWE-326"],
        "ssrf": ["SSRF", "CWE-918"],
        "xss": ["XSS", "CWE-79"],
        "deserialization": ["DESER", "PICKLE", "CWE-502"],
        "supply_chain": ["SUPPLY", "DEP", "DEPEND"],
    }

    # Keyword pairs that are known to form dangerous chains
    _CHAIN_COMBOS: List[Tuple[str, str]] = [
        ("SQLI", "NO-AUTH"),
        ("SQLI", "AUTH-BYPASS"),
        ("EXEC", "NO-VALID"),
        ("EVAL", "NO-VALID"),
        ("PATH-TRAV", "WRITE"),
        ("SSRF", "INTERNAL"),
        ("XSS", "NO-CSP"),
        ("SECRET", "NO-AUTH"),
        ("DESER", "EXEC"),
    ]

    def plan(self, findings: List[Finding]) -> AnalysisPlan:
        if not findings:
            return AnalysisPlan(
                plan_id=uuid.uuid4().hex[:8],
                priority_order=[],
                focus_areas=[],
                scan_depth="quick",
                estimated_chains=0,
                notes="No findings to analyze.",
            )

        # Sort by severity descending, then confidence descending
        sorted_findings = sorted(
            findings,
            key=lambda f: (_SEV_ORDER.get(f.severity.upper(), 0), f.confidence),
            reverse=True,
        )
        priority_order = [f.fingerprint() for f in sorted_findings]

        # Identify focus areas
        all_tokens = " ".join(
            f.rule_id.upper() + " " + f.cwe_id.upper() for f in findings
        )
        focus_areas: List[str] = []
        for area, keywords in self._FOCUS_AREA_KEYWORDS.items():
            if any(kw in all_tokens for kw in keywords):
                focus_areas.append(area)

        # Determine scan depth
        n = len(findings)
        if n > 50:
            scan_depth = "deep"
        elif n > 20:
            scan_depth = "standard"
        else:
            scan_depth = "quick"

        # Estimate chains
        rule_ids_upper = {f.rule_id.upper() for f in findings}
        chain_count = 0
        for kw_a, kw_b in self._CHAIN_COMBOS:
            has_a = any(kw_a in rid for rid in rule_ids_upper)
            has_b = any(kw_b in rid for rid in rule_ids_upper)
            if has_a and has_b:
                chain_count += 1

        notes = (
            f"Analyzed {n} findings across {len({f.file for f in findings})} file(s). "
            f"Focus: {', '.join(focus_areas) if focus_areas else 'general'}. "
            f"Depth: {scan_depth}."
        )

        return AnalysisPlan(
            plan_id=uuid.uuid4().hex[:8],
            priority_order=priority_order,
            focus_areas=focus_areas,
            scan_depth=scan_depth,
            estimated_chains=chain_count,
            notes=notes,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Agent 2: ResearcherAgent
# ─────────────────────────────────────────────────────────────────────────────


class ResearcherAgent:
    """Researches found vulnerabilities — enriches with CWE details and exploit likelihood."""

    _CWE_DETAILS: Dict[str, Dict[str, Any]] = {
        "CWE-89": {
            "name": "SQL Injection",
            "description": "Unsanitized input in SQL query",
            "impact": "Data breach, DB takeover",
            "exploit_likelihood": 0.9,
            "related": ["CWE-20", "CWE-943"],
            "remediation_complexity": "medium",
        },
        "CWE-79": {
            "name": "Cross-site Scripting",
            "description": "Unescaped user input in HTML",
            "impact": "Account hijacking, malware delivery",
            "exploit_likelihood": 0.85,
            "related": ["CWE-20", "CWE-116"],
            "remediation_complexity": "medium",
        },
        "CWE-78": {
            "name": "OS Command Injection",
            "description": "User input in OS command",
            "impact": "Remote code execution",
            "exploit_likelihood": 0.9,
            "related": ["CWE-20", "CWE-88"],
            "remediation_complexity": "medium",
        },
        "CWE-22": {
            "name": "Path Traversal",
            "description": "Unsanitized path component",
            "impact": "Unauthorized file access",
            "exploit_likelihood": 0.75,
            "related": ["CWE-20", "CWE-23"],
            "remediation_complexity": "low",
        },
        "CWE-20": {
            "name": "Improper Input Validation",
            "description": "Missing or incorrect input validation",
            "impact": "Various attacks enabled",
            "exploit_likelihood": 0.6,
            "related": ["CWE-89", "CWE-78", "CWE-79"],
            "remediation_complexity": "low",
        },
        "CWE-306": {
            "name": "Missing Authentication",
            "description": "No authentication for critical function",
            "impact": "Unauthorized access",
            "exploit_likelihood": 0.95,
            "related": ["CWE-862", "CWE-863"],
            "remediation_complexity": "medium",
        },
        "CWE-862": {
            "name": "Missing Authorization",
            "description": "Incomplete authorization checks",
            "impact": "Privilege escalation",
            "exploit_likelihood": 0.85,
            "related": ["CWE-306", "CWE-863"],
            "remediation_complexity": "medium",
        },
        "CWE-798": {
            "name": "Hard-coded Credentials",
            "description": "Credentials embedded in source",
            "impact": "System compromise",
            "exploit_likelihood": 0.95,
            "related": ["CWE-259", "CWE-321"],
            "remediation_complexity": "low",
        },
        "CWE-327": {
            "name": "Broken Crypto Algorithm",
            "description": "Weak or broken cryptographic algorithm",
            "impact": "Data exposure",
            "exploit_likelihood": 0.7,
            "related": ["CWE-326", "CWE-295"],
            "remediation_complexity": "medium",
        },
        "CWE-502": {
            "name": "Deserialization of Untrusted Data",
            "description": "Unsafe deserialization",
            "impact": "RCE",
            "exploit_likelihood": 0.85,
            "related": ["CWE-94", "CWE-78"],
            "remediation_complexity": "high",
        },
        "CWE-918": {
            "name": "SSRF",
            "description": "Server-side request forgery",
            "impact": "Internal service access",
            "exploit_likelihood": 0.8,
            "related": ["CWE-200", "CWE-306"],
            "remediation_complexity": "medium",
        },
        "CWE-200": {
            "name": "Information Exposure",
            "description": "Sensitive data exposed",
            "impact": "Information disclosure",
            "exploit_likelihood": 0.6,
            "related": ["CWE-312", "CWE-313"],
            "remediation_complexity": "low",
        },
        "CWE-352": {
            "name": "CSRF",
            "description": "Cross-site request forgery",
            "impact": "Unauthorized actions",
            "exploit_likelihood": 0.7,
            "related": ["CWE-79", "CWE-346"],
            "remediation_complexity": "low",
        },
        "CWE-190": {
            "name": "Integer Overflow",
            "description": "Arithmetic overflow",
            "impact": "Buffer overflow, RCE",
            "exploit_likelihood": 0.65,
            "related": ["CWE-125", "CWE-787"],
            "remediation_complexity": "high",
        },
        "CWE-416": {
            "name": "Use After Free",
            "description": "Memory used after free",
            "impact": "Memory corruption, RCE",
            "exploit_likelihood": 0.7,
            "related": ["CWE-415", "CWE-825"],
            "remediation_complexity": "high",
        },
        "CWE-94": {
            "name": "Code Injection",
            "description": "Unsanitized input executed as code",
            "impact": "Remote code execution",
            "exploit_likelihood": 0.9,
            "related": ["CWE-20", "CWE-78"],
            "remediation_complexity": "medium",
        },
        "CWE-287": {
            "name": "Improper Authentication",
            "description": "Authentication check can be bypassed",
            "impact": "Unauthorized access",
            "exploit_likelihood": 0.85,
            "related": ["CWE-306", "CWE-862"],
            "remediation_complexity": "medium",
        },
        "CWE-326": {
            "name": "Inadequate Encryption Strength",
            "description": "Encryption key too short or algorithm too weak",
            "impact": "Data decryption by attacker",
            "exploit_likelihood": 0.65,
            "related": ["CWE-327"],
            "remediation_complexity": "medium",
        },
        "CWE-312": {
            "name": "Cleartext Storage of Sensitive Information",
            "description": "Sensitive data stored in plaintext",
            "impact": "Credential/PII exposure",
            "exploit_likelihood": 0.7,
            "related": ["CWE-313", "CWE-200"],
            "remediation_complexity": "low",
        },
    }

    _UNKNOWN_CWE_DEFAULTS: Dict[str, Any] = {
        "name": "Unknown Vulnerability",
        "description": "No CWE mapping available — manual review required",
        "impact": "Unknown — assess manually",
        "exploit_likelihood": 0.5,
        "related": [],
        "remediation_complexity": "medium",
    }

    def research(self, finding: Finding, past_similar: List[str] = []) -> ResearchResult:
        cwe_data = self._CWE_DETAILS.get(finding.cwe_id, self._UNKNOWN_CWE_DEFAULTS)

        cwe_details: Dict[str, str] = {
            "name": cwe_data["name"],
            "description": cwe_data["description"],
            "impact": cwe_data["impact"],
        }

        # Adjust exploit likelihood based on finding confidence
        base_likelihood: float = cwe_data["exploit_likelihood"]
        adjusted_likelihood = base_likelihood * finding.confidence
        # If test file, reduce likelihood
        if finding.is_test_file:
            adjusted_likelihood *= 0.3
        adjusted_likelihood = round(min(1.0, max(0.0, adjusted_likelihood)), 4)

        related_cwes: List[str] = list(cwe_data.get("related", []))
        remediation_complexity: str = cwe_data.get("remediation_complexity", "medium")

        # Derive similar past cases from cwe_id and description keywords
        similar: List[str] = list(past_similar)
        if not similar and finding.cwe_id in self._CWE_DETAILS:
            similar = [
                f"Historic {finding.cwe_id} case in similar {finding.file.split('.')[-1]} codebase"
            ]

        return ResearchResult(
            finding_fingerprint=finding.fingerprint(),
            cwe_details=cwe_details,
            related_cwes=related_cwes,
            exploit_likelihood=adjusted_likelihood,
            remediation_complexity=remediation_complexity,
            similar_past_cases=similar,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Agent 3: SecurityAnalystAgent
# ─────────────────────────────────────────────────────────────────────────────


class SecurityAnalystAgent:
    """Evaluates vulnerability severity and attack vectors.

    Logic:
    - Check if finding severity matches CWE typical severity
    - Identify attack vectors from description and rule_id
    - Determine if finding participates in known attack chain combinations
    - Potentially adjust confidence based on context quality
    """

    # CWE IDs whose typical severity is CRITICAL
    _CRITICAL_CWES = {"CWE-89", "CWE-78", "CWE-94", "CWE-502", "CWE-798", "CWE-306"}
    # CWE IDs whose typical severity is HIGH
    _HIGH_CWES = {"CWE-79", "CWE-22", "CWE-862", "CWE-918", "CWE-287", "CWE-190", "CWE-416"}
    # CWE IDs that belong in attack chains
    _CHAIN_CWES = {
        "CWE-89", "CWE-78", "CWE-94", "CWE-502",  # injection
        "CWE-306", "CWE-862", "CWE-287", "CWE-798",  # auth
        "CWE-918", "CWE-22",  # SSRF / traversal
    }

    _ATTACK_VECTOR_MAP: List[Tuple[List[str], str]] = [
        (["SQLI", "SQL", "CWE-89"], "SQL query manipulation via unsanitized input"),
        (["XSS", "CWE-79"], "Reflected/stored script injection via user-controlled output"),
        (["EXEC", "EVAL", "CWE-94", "CWE-78"], "Arbitrary code/command execution via injected payload"),
        (["PATH", "TRAV", "LFI", "CWE-22"], "Directory traversal via path component manipulation"),
        (["SSRF", "CWE-918"], "Server-side HTTP request forgery to internal services"),
        (["AUTH", "IDOR", "CWE-306", "CWE-862"], "Authentication/authorization bypass"),
        (["SECRET", "CRED", "KEY", "CWE-798"], "Hard-coded credential extraction from source"),
        (["CRYPTO", "CWE-327", "CWE-326"], "Cryptographic weakness enabling offline brute-force"),
        (["DESER", "PICKLE", "CWE-502"], "Deserialization of attacker-controlled object graph"),
        (["CSRF", "CWE-352"], "Cross-site request forgery via crafted link"),
    ]

    def analyze(self, finding: Finding, research: ResearchResult) -> AnalysisResult:
        fp = finding.fingerprint()
        rule_upper = finding.rule_id.upper()
        cwe = finding.cwe_id

        # Determine adjusted severity
        adjusted_severity = finding.severity
        if cwe in self._CRITICAL_CWES and _SEV_ORDER.get(finding.severity, 0) < 4:
            adjusted_severity = "CRITICAL"
        elif cwe in self._HIGH_CWES and _SEV_ORDER.get(finding.severity, 0) < 3:
            adjusted_severity = "HIGH"

        # Adjust confidence: penalise if context is thin
        adjusted_confidence = finding.confidence
        if not finding.context_lines:
            adjusted_confidence = max(0.0, adjusted_confidence - 0.05)
        if len(finding.context_lines) >= 3:
            adjusted_confidence = min(1.0, adjusted_confidence + 0.05)
        if finding.is_test_file:
            adjusted_confidence = max(0.0, adjusted_confidence - 0.15)
        adjusted_confidence = round(adjusted_confidence, 4)

        # Identify attack vectors
        attack_vectors: List[str] = []
        for keywords, vector_desc in self._ATTACK_VECTOR_MAP:
            if any(kw in rule_upper or kw == cwe for kw in keywords):
                attack_vectors.append(vector_desc)
        if not attack_vectors:
            attack_vectors = ["Unclassified vulnerability — manual vector assessment required"]

        # Determine if chain analysis is warranted
        requires_chain = (
            cwe in self._CHAIN_CWES
            or any(kw in rule_upper for kw in ["AUTH", "EXEC", "SQLI", "SSRF", "DESER"])
        )

        # Build impact assessment
        impact_parts = [research.cwe_details.get("impact", "Unknown impact")]
        if research.exploit_likelihood >= 0.8:
            impact_parts.append("High exploit likelihood — immediate remediation advised.")
        elif research.exploit_likelihood >= 0.6:
            impact_parts.append("Moderate exploit likelihood — schedule remediation.")
        else:
            impact_parts.append("Lower exploit likelihood — monitor and plan remediation.")
        impact_assessment = " ".join(impact_parts)

        # Build reasoning
        sev_changed = adjusted_severity != finding.severity
        reasoning_parts = [
            f"Rule {finding.rule_id} maps to {cwe or 'no CWE'}.",
        ]
        if sev_changed:
            reasoning_parts.append(
                f"Severity escalated from {finding.severity} to {adjusted_severity} "
                f"based on CWE classification."
            )
        else:
            reasoning_parts.append(f"Severity {finding.severity} is consistent with CWE guidance.")
        if requires_chain:
            reasoning_parts.append("Finding should be correlated with others for chain detection.")
        reasoning = " ".join(reasoning_parts)

        return AnalysisResult(
            finding_fingerprint=fp,
            adjusted_severity=adjusted_severity,
            adjusted_confidence=adjusted_confidence,
            impact_assessment=impact_assessment,
            attack_vectors=attack_vectors,
            requires_chain_analysis=requires_chain,
            reasoning=reasoning,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Agent 4: VerifierAgent
# ─────────────────────────────────────────────────────────────────────────────


class VerifierAgent:
    """Confirms or rejects findings based on evidence.

    Logic:
    - Suppressed findings → false_positive
    - Test-file findings → needs_review (unless CRITICAL)
    - Low confidence (< 0.5) → check context_lines for evidence
    - Sanitization patterns in context_lines → false_positive
    - Explicit vulnerability pattern + no sanitization → confirmed
    """

    _SANITIZATION_PATTERNS: List[str] = [
        "parameterized", "prepared", "placeholder", "escape", "sanitize",
        "validate", "whitelist", "allowlist", r"\.format\(", "f-string",
        "htmlspecialchars", "htmlentities", "quote_plus", "urlencode",
    ]

    _FP_SIGNALS: List[str] = [
        "test", "mock", "fixture", "example", "sample", "demo", "fake",
        "stub", "dummy", "placeholder",
    ]

    _VULN_PATTERNS: List[str] = [
        "execute(", "cursor.execute", "os.system", "subprocess", "eval(",
        "exec(", "pickle.loads", "yaml.load", "open(", "__import__",
        "request.GET", "request.POST", "request.args", "user_input",
        "password =", "secret =", "api_key =", "token =",
    ]

    def verify(self, finding: Finding) -> VerificationResult:
        fp = finding.fingerprint()

        # Rule 1: Suppressed → always false positive
        if finding.is_suppressed:
            return VerificationResult(
                finding_fingerprint=fp,
                verdict="false_positive",
                evidence_found=["Finding has suppression marker (nosec/noqa/audit-ignore)"],
                confidence_adjustment=-0.3,
                reasoning="Suppression annotation explicitly marks this as a known non-issue.",
            )

        # Rule 2: Test file → needs_review (unless CRITICAL with no suppression)
        if finding.is_test_file:
            if finding.severity == "CRITICAL":
                return VerificationResult(
                    finding_fingerprint=fp,
                    verdict="needs_review",
                    evidence_found=["CRITICAL finding in test file — warrants manual review"],
                    confidence_adjustment=-0.1,
                    reasoning=(
                        "Test file context reduces exploitability but CRITICAL severity "
                        "warrants manual confirmation."
                    ),
                )
            return VerificationResult(
                finding_fingerprint=fp,
                verdict="needs_review",
                evidence_found=["Finding located in test file — likely non-production code"],
                confidence_adjustment=-0.2,
                reasoning="Test files often contain intentional vulnerable patterns for testing.",
            )

        ctx_text = " ".join(finding.context_lines).lower()

        # Rule 3: Sanitization patterns → false positive
        sanitization_found: List[str] = []
        for pat in self._SANITIZATION_PATTERNS:
            if re.search(pat, ctx_text, re.IGNORECASE):
                sanitization_found.append(pat.replace(r"\.", "."))
        if sanitization_found:
            return VerificationResult(
                finding_fingerprint=fp,
                verdict="false_positive",
                evidence_found=[f"Sanitization pattern detected: {', '.join(sanitization_found)}"],
                confidence_adjustment=-0.3,
                reasoning=(
                    f"Context lines contain sanitization/escaping patterns "
                    f"({', '.join(sanitization_found)}), indicating the vulnerability "
                    f"is mitigated in practice."
                ),
            )

        # Rule 4: FP signals (test/mock/demo context without test file flag)
        fp_signals_found = [sig for sig in self._FP_SIGNALS if sig in ctx_text]
        if fp_signals_found and finding.confidence < 0.75:
            return VerificationResult(
                finding_fingerprint=fp,
                verdict="false_positive",
                evidence_found=[
                    f"FP signal words found in context: {', '.join(fp_signals_found)}"
                ],
                confidence_adjustment=-0.2,
                reasoning=(
                    f"Context contains demo/test vocabulary ({', '.join(fp_signals_found)}) "
                    f"with low confidence — likely non-production code."
                ),
            )

        # Rule 5: Explicit vulnerability patterns → confirmed
        vuln_patterns_found = [p for p in self._VULN_PATTERNS if p.lower() in ctx_text]
        if vuln_patterns_found:
            adj = +0.1 if finding.confidence < 0.9 else 0.0
            return VerificationResult(
                finding_fingerprint=fp,
                verdict="confirmed",
                evidence_found=[
                    f"Vulnerability pattern in context: {', '.join(vuln_patterns_found)}"
                ],
                confidence_adjustment=adj,
                reasoning=(
                    f"Context lines show explicit vulnerability patterns: "
                    f"{', '.join(vuln_patterns_found)}. No sanitization detected."
                ),
            )

        # Rule 6: Low confidence, no evidence either way → needs_review
        if finding.confidence < 0.5:
            return VerificationResult(
                finding_fingerprint=fp,
                verdict="needs_review",
                evidence_found=[],
                confidence_adjustment=0.0,
                reasoning=(
                    "Low confidence with insufficient context evidence. "
                    "Manual inspection of source code required."
                ),
            )

        # Default: confidence is reasonable, no sanitization found → confirmed
        adj = +0.05 if finding.confidence < 0.85 else 0.0
        return VerificationResult(
            finding_fingerprint=fp,
            verdict="confirmed",
            evidence_found=[f"Rule {finding.rule_id} matched with confidence {finding.confidence:.2f}"],
            confidence_adjustment=adj,
            reasoning=(
                f"No sanitization evidence found. Rule match confidence {finding.confidence:.2f} "
                f"is sufficient for confirmation."
            ),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Agent 5: CriticAgent
# ─────────────────────────────────────────────────────────────────────────────


class CriticAgent:
    """Finds errors in analysis conclusions.

    Reviews AnalysisResult and VerificationResult for logical consistency.
    Checks:
    - Severity escalation makes sense given evidence
    - Confirmed finding has actual evidence (not just rule match)
    - FP determination has clear reasoning
    - No circular reasoning
    """

    def critique(
        self,
        finding: Finding,
        analysis: AnalysisResult,
        verification: VerificationResult,
    ) -> CritiqueResult:
        fp = finding.fingerprint()
        issues: List[str] = []
        revisions: List[Dict[str, Any]] = []

        # Check 1: Severity escalation needs supporting evidence
        original_sev_rank = _SEV_ORDER.get(finding.severity.upper(), 0)
        adjusted_sev_rank = _SEV_ORDER.get(analysis.adjusted_severity.upper(), 0)
        if adjusted_sev_rank > original_sev_rank:
            # Escalation — check that evidence exists
            has_evidence = (
                bool(verification.evidence_found)
                or bool(finding.context_lines)
                or finding.confidence >= 0.8
            )
            if not has_evidence:
                issues.append(
                    f"Severity escalated from {finding.severity} to "
                    f"{analysis.adjusted_severity} without supporting evidence."
                )
                revisions.append({
                    "field": "adjusted_severity",
                    "recommended_value": finding.severity,
                    "reason": "Insufficient evidence for severity escalation",
                })

        # Check 2: Confirmed finding should have actual evidence
        if verification.verdict == "confirmed" and not verification.evidence_found:
            issues.append(
                "Finding marked 'confirmed' but evidence_found list is empty."
            )
            revisions.append({
                "field": "verdict",
                "recommended_value": "needs_review",
                "reason": "No concrete evidence was cited for confirmation",
            })

        # Check 3: FP without reasoning is suspect
        if verification.verdict == "false_positive" and not verification.reasoning:
            issues.append("False positive verdict issued without any reasoning.")
            revisions.append({
                "field": "verdict",
                "recommended_value": "needs_review",
                "reason": "FP determination lacks reasoning",
            })

        # Check 4: Confidence adjustment out of bounds
        if not (-0.3 <= verification.confidence_adjustment <= 0.3):
            issues.append(
                f"Confidence adjustment {verification.confidence_adjustment:.2f} is out of "
                f"allowed range [-0.3, +0.3]."
            )
            clamped = max(-0.3, min(0.3, verification.confidence_adjustment))
            revisions.append({
                "field": "confidence_adjustment",
                "recommended_value": clamped,
                "reason": "Clamped to valid range",
            })

        # Check 5: If suppressed finding is confirmed — contradiction
        if finding.is_suppressed and verification.verdict == "confirmed":
            issues.append(
                "Suppressed finding was marked 'confirmed' — suppression should take precedence."
            )
            revisions.append({
                "field": "verdict",
                "recommended_value": "false_positive",
                "reason": "Suppressed findings must be false_positive",
            })

        # Check 6: Chain analysis required but no attack vectors identified
        if analysis.requires_chain_analysis and not analysis.attack_vectors:
            issues.append(
                "Chain analysis flagged as required but no attack vectors were identified."
            )

        is_sound = len(issues) == 0
        return CritiqueResult(
            finding_fingerprint=fp,
            issues_found=issues,
            is_sound=is_sound,
            suggested_revisions=revisions,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Agent 6: RuleGeneratorAgent
# ─────────────────────────────────────────────────────────────────────────────


class RuleGeneratorAgent:
    """Creates new rule proposals from confirmed findings.

    Groups confirmed findings by (cwe_id, rule_id prefix).
    For each group with >= 2 findings, proposes a new evolved rule.
    Extracts pattern_hint from common description keywords.
    """

    _COMMON_STOP_WORDS = {
        "the", "a", "an", "in", "is", "are", "was", "were", "for", "of",
        "to", "and", "or", "at", "by", "with", "as", "that", "this",
        "from", "on", "it", "its", "be", "has", "have", "but",
    }

    def generate_proposals(self, confirmed_findings: List[Finding]) -> List[GeneratedRule]:
        if not confirmed_findings:
            return []

        # Group by (cwe_id, rule_id prefix)
        groups: Dict[Tuple[str, str], List[Finding]] = defaultdict(list)
        for f in confirmed_findings:
            cwe = f.cwe_id or "UNKNOWN"
            # Take first dash-separated segment of rule_id as prefix
            prefix = f.rule_id.split("-")[0].upper()
            groups[(cwe, prefix)].append(f)

        proposals: List[GeneratedRule] = []
        for (cwe_id, prefix), group_findings in groups.items():
            if len(group_findings) < 2:
                continue

            # Extract common description keywords as pattern hint
            all_words: List[str] = []
            for f in group_findings:
                words = re.findall(r"[a-zA-Z]{3,}", f.description.lower())
                all_words.extend(words)

            word_counts: Dict[str, int] = defaultdict(int)
            for w in all_words:
                if w not in self._COMMON_STOP_WORDS:
                    word_counts[w] += 1

            # Top 3 most frequent non-stop-words
            common_words = sorted(word_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            pattern_hint = " ".join(w for w, _ in common_words) if common_words else prefix.lower()

            # Determine severity from group
            severities = [f.severity for f in group_findings]
            rule_severity = _max_sev(severities)

            # Average confidence
            avg_confidence = round(
                sum(f.confidence for f in group_findings) / len(group_findings), 4
            )

            rule_id = f"GEN-{prefix}-{cwe_id.replace('-', '')}"
            proposals.append(
                GeneratedRule(
                    rule_id=rule_id,
                    name=f"Evolved rule for {cwe_id} ({prefix} pattern)",
                    description=(
                        f"Auto-generated rule based on {len(group_findings)} confirmed findings "
                        f"matching pattern '{pattern_hint}' under {cwe_id}."
                    ),
                    pattern_hint=pattern_hint,
                    cwe_id=cwe_id,
                    severity=rule_severity,
                    confidence=avg_confidence,
                    based_on_fingerprints=[f.fingerprint() for f in group_findings],
                )
            )

        return proposals


# ─────────────────────────────────────────────────────────────────────────────
# Agent 7: ReportWriterAgent
# ─────────────────────────────────────────────────────────────────────────────


class ReportWriterAgent:
    """Generates human-readable security reports in Markdown."""

    def write_report(
        self,
        original_count: int,
        confirmed: List[Finding],
        removed: List[Finding],
        chains: List[Dict[str, Any]],
        session_id: str,
    ) -> str:
        lines: List[str] = []

        # ── Header ──────────────────────────────────────────────────────────────
        lines.append("# TythanAI Security Analysis Report")
        lines.append(f"\n**Session ID:** `{session_id}`  ")
        lines.append(f"**Total Input Findings:** {original_count}  ")
        lines.append(f"**Confirmed Findings:** {len(confirmed)}  ")
        lines.append(f"**Removed (FP/Suppressed):** {len(removed)}  ")
        lines.append(f"**Attack Chains Detected:** {len(chains)}  ")
        precision = round(len(confirmed) / original_count, 4) if original_count else 0.0
        lines.append(f"**Precision Estimate:** {precision:.1%}  ")

        # ── Executive Summary ────────────────────────────────────────────────────
        lines.append("\n## Executive Summary\n")
        critical_count = sum(1 for f in confirmed if f.severity == "CRITICAL")
        high_count = sum(1 for f in confirmed if f.severity == "HIGH")
        medium_count = sum(1 for f in confirmed if f.severity == "MEDIUM")
        low_count = sum(1 for f in confirmed if f.severity in ("LOW", "INFO"))

        if critical_count or high_count:
            lines.append(
                f"Analysis identified **{critical_count} critical** and **{high_count} high** "
                f"severity findings requiring immediate attention."
            )
        elif medium_count:
            lines.append(
                f"Analysis identified **{medium_count} medium** severity findings "
                f"that should be scheduled for remediation."
            )
        else:
            lines.append("No high-severity findings confirmed. Low-risk posture detected.")

        if chains:
            lines.append(
                f"\n**{len(chains)} attack chain(s)** were detected, indicating "
                f"compounded risk from vulnerability combinations."
            )

        # ── Critical Findings Table ──────────────────────────────────────────────
        critical_high = [f for f in confirmed if f.severity in ("CRITICAL", "HIGH")]
        if critical_high:
            lines.append("\n## Critical & High Severity Findings\n")
            lines.append("| # | Rule ID | File | Line | Severity | Confidence | CWE |")
            lines.append("|---|---------|------|------|----------|------------|-----|")
            for i, f in enumerate(
                sorted(critical_high, key=lambda x: _SEV_ORDER.get(x.severity, 0), reverse=True),
                start=1,
            ):
                lines.append(
                    f"| {i} | `{f.rule_id}` | `{f.file}` | {f.line} | "
                    f"**{f.severity}** | {f.confidence:.0%} | {f.cwe_id or 'N/A'} |"
                )

        # ── Attack Chains ────────────────────────────────────────────────────────
        if chains:
            lines.append("\n## Attack Chains\n")
            for i, chain in enumerate(chains, start=1):
                chain_id = chain.get("chain_id", f"chain-{i}")
                severity = chain.get("severity", "UNKNOWN")
                narrative = chain.get("narrative", "No narrative available.")
                risk = chain.get("combined_risk_score", chain.get("risk_score", 0.0))
                n_findings = len(chain.get("finding_fingerprints", []))
                lines.append(f"### Chain {i}: `{chain_id}` [{severity}]")
                lines.append(f"- **Risk Score:** {risk:.1f}/10.0")
                lines.append(f"- **Findings in chain:** {n_findings}")
                lines.append(f"- **Narrative:** {narrative}")
                lines.append("")

        # ── Per-finding Details ──────────────────────────────────────────────────
        lines.append("\n## Confirmed Finding Details\n")
        if not confirmed:
            lines.append("_No confirmed findings._\n")
        else:
            for f in sorted(
                confirmed,
                key=lambda x: (_SEV_ORDER.get(x.severity, 0), x.confidence),
                reverse=True,
            ):
                lines.append(f"### `{f.rule_id}` — {f.severity}")
                lines.append(f"- **File:** `{f.file}:{f.line}`")
                lines.append(f"- **CWE:** {f.cwe_id or 'N/A'}")
                lines.append(f"- **Confidence:** {f.confidence:.0%}")
                if f.description:
                    lines.append(f"- **Description:** {f.description}")
                if f.recommendation:
                    lines.append(f"- **Recommendation:** {f.recommendation}")
                lines.append("")

        # ── Remediation Priority List ────────────────────────────────────────────
        lines.append("\n## Remediation Priority\n")
        if not confirmed:
            lines.append("_No remediation required._\n")
        else:
            priorities = sorted(
                confirmed,
                key=lambda x: (_SEV_ORDER.get(x.severity, 0), x.confidence),
                reverse=True,
            )
            for rank, f in enumerate(priorities, start=1):
                lines.append(
                    f"{rank}. **[{f.severity}]** `{f.rule_id}` in `{f.file}:{f.line}`"
                    + (f" — {f.recommendation}" if f.recommendation else "")
                )

        # ── Appendix: Removed FPs ────────────────────────────────────────────────
        if removed:
            lines.append("\n## Appendix: Removed Findings (False Positives / Suppressed)\n")
            lines.append("| Rule ID | File | Line | Reason |")
            lines.append("|---------|------|------|--------|")
            for f in removed:
                reason = "suppressed" if f.is_suppressed else ("test file" if f.is_test_file else "FP")
                lines.append(f"| `{f.rule_id}` | `{f.file}` | {f.line} | {reason} |")

        lines.append("\n---\n_Report generated by TythanAI Multi-Agent Orchestrator._\n")
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Chain detection (internal, used by orchestrator)
# ─────────────────────────────────────────────────────────────────────────────

_CHAIN_COMBINATIONS: List[Tuple[set, set, str, str]] = [
    (
        {"SQLI", "SQL"},
        {"NO-AUTH", "AUTH-BYPASS"},
        "CRITICAL",
        "SQL Injection + Missing Auth: Full unauthenticated data breach",
    ),
    (
        {"EXEC", "EVAL"},
        {"NO-VALID", "NO-INPUT"},
        "CRITICAL",
        "Code Execution + No Input Validation: Remote Code Execution",
    ),
    (
        {"PATH", "TRAV", "LFI"},
        {"WRITE", "UPLOAD"},
        "CRITICAL",
        "Path Traversal + File Write: Arbitrary file overwrite",
    ),
    (
        {"SSRF"},
        {"INTERNAL", "PRIV"},
        "HIGH",
        "SSRF + Internal Access: Lateral movement to internal services",
    ),
    (
        {"XSS"},
        {"NO-CSP", "CORS"},
        "HIGH",
        "XSS + Missing Security Headers: Persistent cross-site attacks",
    ),
    (
        {"SECRET", "KEY", "TOKEN", "CRED"},
        {"NO-AUTH", "AUTH"},
        "CRITICAL",
        "Exposed Credentials + Auth weakness: Full system compromise",
    ),
    (
        {"DESER", "PICKLE"},
        {"EXEC", "CMD"},
        "CRITICAL",
        "Deserialization + Code Execution: RCE via malicious payload",
    ),
    (
        {"SQLI", "SQL"},
        {"SECRET", "CRED"},
        "CRITICAL",
        "SQL Injection + Exposed Credentials: Database + system compromise",
    ),
]


def _detect_chains(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Detect attack chains from a list of confirmed findings.

    Uses keyword matching against rule_ids, mirroring the _RuleBasedFallback
    but with richer output dicts.
    """
    results: List[Dict[str, Any]] = []
    rule_ids_upper = [f.rule_id.upper() for f in findings]

    for set_a, set_b, severity, narrative in _CHAIN_COMBINATIONS:
        # Find findings that match side A and side B
        side_a = [
            f for f in findings if any(kw in f.rule_id.upper() for kw in set_a)
        ]
        side_b = [
            f for f in findings if any(kw in f.rule_id.upper() for kw in set_b)
        ]
        if not side_a or not side_b:
            continue

        # Avoid duplicating the same finding on both sides unnecessarily
        chain_fps = list({f.fingerprint() for f in side_a + side_b})
        chain_findings = [f for f in findings if f.fingerprint() in chain_fps]

        avg_conf = sum(f.confidence for f in chain_findings) / len(chain_findings)
        # CVSS-like risk
        base = max(_SEV_WEIGHTS.get(f.severity.upper(), 5.0) for f in chain_findings)
        multiplier = 1.0 + 0.2 * (len(chain_findings) - 1)
        risk = round(min(10.0, base * multiplier * avg_conf), 4)

        results.append({
            "chain_id": uuid.uuid4().hex[:8],
            "finding_fingerprints": chain_fps,
            "severity": severity,
            "narrative": narrative,
            "combined_risk_score": risk,
            "confidence": round(avg_conf, 4),
        })

    # Deduplicate: same fingerprint set → keep highest severity
    deduped: Dict[frozenset, Dict[str, Any]] = {}
    for chain in results:
        key = frozenset(chain["finding_fingerprints"])
        existing = deduped.get(key)
        if existing is None:
            deduped[key] = chain
        else:
            if _SEV_ORDER.get(chain["severity"], 0) > _SEV_ORDER.get(existing["severity"], 0):
                deduped[key] = chain

    return list(deduped.values())


# ─────────────────────────────────────────────────────────────────────────────
# Agent 8: MultiAgentOrchestrator
# ─────────────────────────────────────────────────────────────────────────────


class MultiAgentOrchestrator:
    """Coordinates all 8 agents for comprehensive security analysis.

    Pipeline:
    1. PlannerAgent.plan(findings) → AnalysisPlan
    2. For each finding (in priority order):
       a. ResearcherAgent.research(finding) → ResearchResult
       b. SecurityAnalystAgent.analyze(finding, research) → AnalysisResult
       c. VerifierAgent.verify(finding) → VerificationResult
       d. CriticAgent.critique(finding, analysis, verification) → CritiqueResult
       e. Apply critique revisions if needed
    3. RuleGeneratorAgent.generate_proposals(confirmed) → List[GeneratedRule]
    4. Build attack chains using _detect_chains
    5. ReportWriterAgent.write_report(confirmed, removed, chains) → str
    6. Return OrchestratorReport
    """

    def __init__(self) -> None:
        self._planner = PlannerAgent()
        self._researcher = ResearcherAgent()
        self._analyst = SecurityAnalystAgent()
        self._verifier = VerifierAgent()
        self._critic = CriticAgent()
        self._rule_gen = RuleGeneratorAgent()
        self._reporter = ReportWriterAgent()

    # ── Main entry point ─────────────────────────────────────────────────────

    def run(self, findings: List[Finding]) -> OrchestratorReport:
        """Run full multi-agent analysis. Returns OrchestratorReport."""
        report = OrchestratorReport(original_findings=list(findings))

        if not findings:
            report.report_markdown = self._reporter.write_report(0, [], [], [], report.session_id)
            return report

        # Step 1: Plan
        plan = self._planner.plan(findings)
        report.plan_notes = plan.notes

        # Build lookup for fast access by fingerprint
        fp_to_finding: Dict[str, Finding] = {f.fingerprint(): f for f in findings}

        confirmed: List[Finding] = []
        removed: List[Finding] = []
        total_iterations = 0

        # Step 2: Per-finding analysis pipeline
        for fp in plan.priority_order:
            finding = fp_to_finding.get(fp)
            if finding is None:
                continue

            total_iterations += 1

            # 2a. Research
            research = self._researcher.research(finding)

            # 2b. Analyze
            analysis = self._analyst.analyze(finding, research)

            # 2c. Verify
            verification = self._verifier.verify(finding)

            # 2d. Critique
            critique = self._critic.critique(finding, analysis, verification)

            # 2e. Apply revisions from critique
            if not critique.is_sound:
                for revision in critique.suggested_revisions:
                    field_name = revision.get("field", "")
                    new_val = revision.get("recommended_value")
                    if field_name == "verdict" and new_val:
                        verification = VerificationResult(
                            finding_fingerprint=verification.finding_fingerprint,
                            verdict=str(new_val),
                            evidence_found=verification.evidence_found,
                            confidence_adjustment=verification.confidence_adjustment,
                            reasoning=f"{verification.reasoning} [Revised by CriticAgent]",
                        )
                    elif field_name == "adjusted_severity" and new_val:
                        analysis = AnalysisResult(
                            finding_fingerprint=analysis.finding_fingerprint,
                            adjusted_severity=str(new_val),
                            adjusted_confidence=analysis.adjusted_confidence,
                            impact_assessment=analysis.impact_assessment,
                            attack_vectors=analysis.attack_vectors,
                            requires_chain_analysis=analysis.requires_chain_analysis,
                            reasoning=f"{analysis.reasoning} [Revised by CriticAgent]",
                        )

            # Apply confidence adjustment to finding for final output
            adj_conf = round(
                min(1.0, max(0.0, finding.confidence + verification.confidence_adjustment)),
                4,
            )
            updated_finding = finding.model_copy(
                update={
                    "confidence": adj_conf,
                    "severity": analysis.adjusted_severity,
                }
            )

            # Route to confirmed or removed
            if verification.verdict == "false_positive":
                removed.append(updated_finding)
            elif verification.verdict in ("confirmed", "needs_review"):
                confirmed.append(updated_finding)
            else:
                # Fallback — keep it
                confirmed.append(updated_finding)

        # Step 3: Rule generation
        only_confirmed = [f for f in confirmed if not f.is_suppressed]
        generated_rules = self._rule_gen.generate_proposals(only_confirmed)
        report.generated_rules = [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "description": r.description,
                "pattern_hint": r.pattern_hint,
                "cwe_id": r.cwe_id,
                "severity": r.severity,
                "confidence": r.confidence,
                "based_on_fingerprints": r.based_on_fingerprints,
            }
            for r in generated_rules
        ]

        # Step 4: Attack chains
        chains = _detect_chains(confirmed)
        report.attack_chains = chains

        # Step 5: Report
        report.confirmed_findings = confirmed
        report.removed_findings = removed
        report.total_iterations = total_iterations
        report.precision_estimate = (
            round(len(confirmed) / len(findings), 4) if findings else 0.0
        )
        report.report_markdown = self._reporter.write_report(
            original_count=len(findings),
            confirmed=confirmed,
            removed=removed,
            chains=chains,
            session_id=report.session_id,
        )

        return report

    # ── Quick mode ───────────────────────────────────────────────────────────

    def run_quick(self, findings: List[Finding]) -> OrchestratorReport:
        """Quick mode: skip critic and rule generation, faster."""
        report = OrchestratorReport(original_findings=list(findings))

        if not findings:
            report.report_markdown = self._reporter.write_report(0, [], [], [], report.session_id)
            return report

        plan = self._planner.plan(findings)
        report.plan_notes = plan.notes

        fp_to_finding: Dict[str, Finding] = {f.fingerprint(): f for f in findings}
        confirmed: List[Finding] = []
        removed: List[Finding] = []
        total_iterations = 0

        for fp in plan.priority_order:
            finding = fp_to_finding.get(fp)
            if finding is None:
                continue

            total_iterations += 1
            research = self._researcher.research(finding)
            analysis = self._analyst.analyze(finding, research)
            verification = self._verifier.verify(finding)

            adj_conf = round(
                min(1.0, max(0.0, finding.confidence + verification.confidence_adjustment)),
                4,
            )
            updated_finding = finding.model_copy(
                update={
                    "confidence": adj_conf,
                    "severity": analysis.adjusted_severity,
                }
            )

            if verification.verdict == "false_positive":
                removed.append(updated_finding)
            else:
                confirmed.append(updated_finding)

        chains = _detect_chains(confirmed)

        report.confirmed_findings = confirmed
        report.removed_findings = removed
        report.attack_chains = chains
        report.total_iterations = total_iterations
        report.precision_estimate = (
            round(len(confirmed) / len(findings), 4) if findings else 0.0
        )
        report.report_markdown = self._reporter.write_report(
            original_count=len(findings),
            confirmed=confirmed,
            removed=removed,
            chains=chains,
            session_id=report.session_id,
        )

        return report
