"""
backend/core/explainability.py

TythanAI Explainability Engine — explains why each finding was detected,
what the confidence score means, and why groups of findings form attack chains.
Pure algorithmic; no LLM calls.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from backend.core.confidence import Finding

# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class Evidence:
    evidence_type: str   # "code_pattern" | "rule_match" | "context" | "cwe_reference"
    content: str
    weight: float        # 0.0–1.0, contribution to the finding


@dataclass
class ConfidenceExplanation:
    base_confidence: float
    adjustments: List[Dict[str, float]]  # [{"reason": ..., "delta": ...}]
    final_confidence: float
    explanation: str


@dataclass
class Explanation:
    finding_fingerprint: str
    rule_id: str
    why_detected: str              # primary reason for detection
    triggered_rules: List[str]     # all rules that matched
    reasoning_chain: List[str]     # step-by-step reasoning
    evidence: List[Evidence]
    confidence_explanation: ConfidenceExplanation
    false_positive_risk: str       # "low" | "medium" | "high"
    recommended_verification: str


@dataclass
class ChainExplanation:
    chain_id: str
    why_critical: str
    component_explanations: List[str]
    combined_risk: str
    exploitation_narrative: str


# ─────────────────────────────────────────────────────────────────────────────
# CWE knowledge base (inline)
# ─────────────────────────────────────────────────────────────────────────────

_CWE_INFO: Dict[str, Dict[str, str]] = {
    "CWE-89": {
        "name": "SQL Injection",
        "short": "unsanitized user input concatenated into a SQL query",
        "verification": (
            "Run the query with a single-quote payload (e.g., ' OR '1'='1). "
            "Check for unsanitized string concatenation in the query construction. "
            "Verify whether parameterized queries / prepared statements are used."
        ),
    },
    "CWE-79": {
        "name": "Cross-site Scripting (XSS)",
        "short": "user-controlled data rendered in HTML without escaping",
        "verification": (
            "Inject <script>alert(1)</script> via all user-facing input fields. "
            "Review output encoding functions in the template layer. "
            "Check for Content-Security-Policy headers."
        ),
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "short": "user input passed to an OS command shell",
        "verification": (
            "Trace input to os.system/subprocess call. "
            "Verify no shell=True with user-controlled arguments. "
            "Test with '; id #' payload to confirm execution."
        ),
    },
    "CWE-22": {
        "name": "Path Traversal",
        "short": "user-controlled path component not sanitized",
        "verification": (
            "Test with '../../../etc/passwd' payload. "
            "Verify path is canonicalized and confined to allowed base directory. "
            "Check for os.path.realpath / Path.resolve usage."
        ),
    },
    "CWE-20": {
        "name": "Improper Input Validation",
        "short": "input reaches sensitive operation without validation",
        "verification": (
            "Review all paths from user input to the sensitive operation. "
            "Check for whitelisting/allowlisting of allowed values. "
            "Test boundary conditions and unexpected types."
        ),
    },
    "CWE-306": {
        "name": "Missing Authentication for Critical Function",
        "short": "critical endpoint accessible without authentication",
        "verification": (
            "Call the endpoint without any authentication headers/cookies. "
            "Check decorator/middleware chain for auth enforcement. "
            "Verify session validation occurs before sensitive operations."
        ),
    },
    "CWE-862": {
        "name": "Missing Authorization",
        "short": "authenticated user can access another user's resource",
        "verification": (
            "Log in as user A and access user B's resource URL. "
            "Check if resource ownership is validated server-side. "
            "Review authorization middleware for completeness."
        ),
    },
    "CWE-798": {
        "name": "Hard-coded Credentials",
        "short": "credentials embedded directly in source code",
        "verification": (
            "Search codebase for hardcoded password/key/token strings. "
            "Verify credentials are loaded from environment variables or secrets manager. "
            "Rotate any exposed credentials immediately."
        ),
    },
    "CWE-327": {
        "name": "Use of Broken or Risky Cryptographic Algorithm",
        "short": "weak algorithm (MD5/SHA1/DES/ECB) used for security-sensitive data",
        "verification": (
            "Identify the algorithm in use and check against NIST recommendations. "
            "Verify output is not used for password storage or integrity checks. "
            "Replace with SHA-256+/AES-GCM/bcrypt as appropriate."
        ),
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "short": "attacker-controlled data deserialized without integrity validation",
        "verification": (
            "Test with a crafted pickle/YAML/Java serialized object. "
            "Verify deserialization occurs only on signed/trusted data. "
            "Check for use of safe_load vs load in PyYAML."
        ),
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "short": "user-controlled URL fetched by the server without allowlist",
        "verification": (
            "Provide an internal IP (169.254.169.254, 10.0.0.1) as the URL parameter. "
            "Check for URL allowlisting or scheme restriction. "
            "Test access to cloud metadata endpoints."
        ),
    },
    "CWE-200": {
        "name": "Exposure of Sensitive Information",
        "short": "sensitive data (PII, credentials, stack traces) leaked to unauthorized parties",
        "verification": (
            "Review all error responses for stack traces or sensitive data. "
            "Check API responses for over-exposure of internal fields. "
            "Verify logging does not capture credentials."
        ),
    },
    "CWE-94": {
        "name": "Code Injection",
        "short": "user-supplied code executed by the interpreter",
        "verification": (
            "Test eval()/exec() call sites with __import__('os').system('id') payload. "
            "Trace all inputs that reach dynamic code execution. "
            "Verify no user-controlled strings are passed to eval/exec."
        ),
    },
}

_CWE_INFO_DEFAULT: Dict[str, str] = {
    "name": "Unclassified Vulnerability",
    "short": "scanner-identified security pattern",
    "verification": (
        "Manually inspect the flagged code section. "
        "Trace data flow from user input to the vulnerable operation. "
        "Consult the CWE database for the specific rule class."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# Sanitization patterns (used for FP risk assessment)
# ─────────────────────────────────────────────────────────────────────────────

_SANITIZATION_PATTERNS: List[str] = [
    "parameterized", "prepared", "placeholder", "escape", "sanitize",
    "validate", "whitelist", "allowlist", r"htmlspecialchars",
    "htmlentities", "quote_plus", "urlencode", "safe_load",
]

# Code patterns that corroborate a finding
_VULN_CODE_PATTERNS: List[str] = [
    r"execute\s*\(",
    r"cursor\.execute",
    r"os\.system",
    r"subprocess\.(call|run|Popen)",
    r"eval\s*\(",
    r"exec\s*\(",
    r"pickle\.loads",
    r"yaml\.load\s*\(",
    r"__import__\s*\(",
    r"password\s*=\s*['\"]",
    r"secret\s*=\s*['\"]",
    r"api_key\s*=\s*['\"]",
    r"token\s*=\s*['\"]",
    r"open\s*\(.*['\"]w['\"]",
]


# ─────────────────────────────────────────────────────────────────────────────
# ExplainabilityEngine
# ─────────────────────────────────────────────────────────────────────────────


class ExplainabilityEngine:
    """Explains why each finding was detected and what its confidence score means."""

    # Confidence adjusters applied when the given context signals are present
    _CONFIDENCE_ADJUSTERS: Dict[str, float] = {
        "test_file": -0.2,
        "suppression_marker": -0.5,
        "sanitization_found": -0.3,
        "corroborating_finding": +0.15,
        "critical_chain_member": +0.1,
        "multiple_sources": +0.1,
        "high_severity_cwe": +0.05,
        "low_confidence_rule": -0.1,
    }

    # ── Public API ───────────────────────────────────────────────────────────

    def explain_finding(
        self,
        finding: Finding,
        context: Dict[str, Any] = {},
    ) -> Explanation:
        """Generate a full explanation for a finding.

        context keys:
        - "is_in_chain": bool
        - "corroborating_findings": List[Finding]
        - "sanitization_detected": bool
        - "past_similar_count": int
        """
        fp = finding.fingerprint()

        # 1. Why detected
        why_detected = self._build_why_detected(finding)

        # 2. Triggered rules
        triggered_rules = self._build_triggered_rules(finding)

        # 3. Reasoning chain
        reasoning_chain = self.build_reasoning_chain(finding, context)

        # 4. Evidence
        evidence = self.extract_evidence(finding)

        # 5. Confidence explanation
        confidence_explanation = self.explain_confidence(finding, context)

        # 6. FP risk
        false_positive_risk = self.assess_fp_risk(finding)

        # 7. Verification steps
        recommended_verification = self.generate_verification_steps(finding)

        return Explanation(
            finding_fingerprint=fp,
            rule_id=finding.rule_id,
            why_detected=why_detected,
            triggered_rules=triggered_rules,
            reasoning_chain=reasoning_chain,
            evidence=evidence,
            confidence_explanation=confidence_explanation,
            false_positive_risk=false_positive_risk,
            recommended_verification=recommended_verification,
        )

    def explain_confidence(
        self,
        finding: Finding,
        context: Dict[str, Any] = {},
    ) -> ConfidenceExplanation:
        """Explain what the confidence score means and what contributed to it."""
        base = finding.confidence
        adjustments: List[Dict[str, float]] = []

        # Apply known adjusters based on finding properties
        if finding.is_test_file:
            delta = self._CONFIDENCE_ADJUSTERS["test_file"]
            adjustments.append({"reason": "Finding is in a test file", "delta": delta})

        if finding.is_suppressed:
            delta = self._CONFIDENCE_ADJUSTERS["suppression_marker"]
            adjustments.append({"reason": "Suppression marker present", "delta": delta})

        # Check context lines for sanitization
        ctx_text = " ".join(finding.context_lines).lower()
        has_sanitization = context.get("sanitization_detected", False) or any(
            re.search(p, ctx_text, re.IGNORECASE) for p in _SANITIZATION_PATTERNS
        )
        if has_sanitization:
            delta = self._CONFIDENCE_ADJUSTERS["sanitization_found"]
            adjustments.append({"reason": "Sanitization pattern detected in context", "delta": delta})

        # Corroborating findings
        corroborating: List[Finding] = context.get("corroborating_findings", [])
        if corroborating:
            delta = self._CONFIDENCE_ADJUSTERS["corroborating_finding"]
            adjustments.append({
                "reason": f"{len(corroborating)} corroborating finding(s) in same file",
                "delta": delta,
            })

        # Chain membership
        if context.get("is_in_chain", False):
            delta = self._CONFIDENCE_ADJUSTERS["critical_chain_member"]
            adjustments.append({"reason": "Finding is part of an attack chain", "delta": delta})

        # Multiple sources
        if len(finding.sources) > 1:
            delta = self._CONFIDENCE_ADJUSTERS["multiple_sources"]
            adjustments.append({
                "reason": f"Multiple scanner sources ({len(finding.sources)})",
                "delta": delta,
            })

        # High-severity CWE
        high_sev_cwes = {"CWE-89", "CWE-78", "CWE-94", "CWE-502", "CWE-798", "CWE-306"}
        if finding.cwe_id in high_sev_cwes:
            delta = self._CONFIDENCE_ADJUSTERS["high_severity_cwe"]
            adjustments.append({
                "reason": f"{finding.cwe_id} is a high-severity CWE class",
                "delta": delta,
            })

        # Compute final (base + sum of deltas, clamped)
        total_delta = sum(a["delta"] for a in adjustments)
        final = round(min(1.0, max(0.0, base + total_delta)), 4)

        # Human-readable explanation of what the final score means
        if final >= 0.9:
            meaning = "High certainty — this finding is very likely a true positive."
        elif final >= 0.7:
            meaning = (
                "Moderate certainty — review is recommended to confirm exploitability."
            )
        else:
            meaning = (
                "Uncertain — manual verification required before treating as confirmed."
            )

        adj_summary = ""
        if adjustments:
            parts = []
            for a in adjustments:
                sign = "+" if a["delta"] >= 0 else ""
                parts.append(f"{a['reason']} ({sign}{a['delta']:.2f})")
            adj_summary = " Adjustments: " + "; ".join(parts) + "."

        explanation = (
            f"Base confidence: {base:.2f}. Final confidence: {final:.2f}. "
            f"{meaning}{adj_summary}"
        )

        return ConfidenceExplanation(
            base_confidence=base,
            adjustments=adjustments,
            final_confidence=final,
            explanation=explanation,
        )

    def explain_chain(
        self,
        chain: Dict[str, Any],
        findings: List[Finding],
    ) -> ChainExplanation:
        """Explain why a group of findings forms a critical attack chain."""
        chain_id = chain.get("chain_id", "unknown")
        severity = chain.get("severity", "UNKNOWN")
        narrative = chain.get("narrative", "No narrative provided.")
        risk_score = chain.get("combined_risk_score", chain.get("risk_score", 0.0))
        fps = set(chain.get("finding_fingerprints", []))

        chain_findings = [f for f in findings if f.fingerprint() in fps]

        # Why critical
        if severity == "CRITICAL":
            why_critical = (
                f"This chain is rated CRITICAL because the combination of vulnerabilities "
                f"creates a direct exploitation path requiring minimal attacker skill. "
                f"Risk score: {risk_score:.1f}/10.0."
            )
        elif severity == "HIGH":
            why_critical = (
                f"This chain is rated HIGH because the vulnerability combination "
                f"significantly amplifies individual finding risk. "
                f"Risk score: {risk_score:.1f}/10.0."
            )
        else:
            why_critical = (
                f"Chain severity: {severity}. "
                f"Combined vulnerabilities create a compounded risk path. "
                f"Risk score: {risk_score:.1f}/10.0."
            )

        # Component explanations
        component_explanations: List[str] = []
        for f in chain_findings:
            cwe_data = _CWE_INFO.get(f.cwe_id, _CWE_INFO_DEFAULT)
            component_explanations.append(
                f"`{f.rule_id}` ({f.cwe_id or 'N/A'}) in `{f.file}:{f.line}`: "
                f"{cwe_data['short']}."
            )

        # Combined risk description
        combined_risk = (
            f"Combined risk score {risk_score:.1f}/10.0. "
            f"Each additional finding in the chain adds multiplicative risk; "
            f"{len(chain_findings)} findings compound to create this score."
        )

        # Exploitation narrative
        exploitation_narrative = narrative

        return ChainExplanation(
            chain_id=chain_id,
            why_critical=why_critical,
            component_explanations=component_explanations,
            combined_risk=combined_risk,
            exploitation_narrative=exploitation_narrative,
        )

    def extract_evidence(self, finding: Finding) -> List[Evidence]:
        """Extract evidence items from finding context and properties."""
        evidence: List[Evidence] = []

        # Evidence from rule_id match
        evidence.append(
            Evidence(
                evidence_type="rule_match",
                content=f"Scanner rule `{finding.rule_id}` triggered at {finding.file}:{finding.line}",
                weight=0.6,
            )
        )

        # Evidence from CWE reference
        if finding.cwe_id:
            cwe_data = _CWE_INFO.get(finding.cwe_id, _CWE_INFO_DEFAULT)
            evidence.append(
                Evidence(
                    evidence_type="cwe_reference",
                    content=(
                        f"{finding.cwe_id} ({cwe_data['name']}): {cwe_data['short']}"
                    ),
                    weight=0.5,
                )
            )

        # Evidence from context lines (code patterns)
        ctx_text = " ".join(finding.context_lines)
        for pattern in _VULN_CODE_PATTERNS:
            match = re.search(pattern, ctx_text, re.IGNORECASE)
            if match:
                snippet = match.group(0)[:120]
                evidence.append(
                    Evidence(
                        evidence_type="code_pattern",
                        content=f"Vulnerable pattern detected: `{snippet}`",
                        weight=0.8,
                    )
                )
                break  # one code pattern is enough

        # Evidence from file location + description (context)
        context_desc = f"Located in `{finding.file}` at line {finding.line}."
        if finding.description:
            context_desc += f" Description: {finding.description}"
        evidence.append(
            Evidence(
                evidence_type="context",
                content=context_desc,
                weight=0.3,
            )
        )

        # Raw context lines as evidence
        if finding.context_lines:
            snippet = " | ".join(finding.context_lines[:3])
            evidence.append(
                Evidence(
                    evidence_type="code_pattern",
                    content=f"Surrounding code: {snippet[:200]}",
                    weight=0.4,
                )
            )

        return evidence

    def build_reasoning_chain(
        self,
        finding: Finding,
        context: Dict[str, Any] = {},
    ) -> List[str]:
        """Build step-by-step reasoning chain explaining the detection.

        Steps follow the pattern:
        1. Scanner identified pattern matching rule {rule_id}
        2. Pattern corresponds to {cwe_id}: {cwe_name}
        3. Found in {file}:{line} — {context description}
        4. Confidence set to {confidence} because {reason}
        5. Severity is {severity} based on {CWE/rule} classification
        """
        cwe_data = _CWE_INFO.get(finding.cwe_id, _CWE_INFO_DEFAULT)
        steps: List[str] = []

        # Step 1: Rule identification
        steps.append(
            f"Scanner identified a pattern matching rule `{finding.rule_id}` "
            f"in `{finding.file}` at line {finding.line}."
        )

        # Step 2: CWE mapping
        if finding.cwe_id:
            steps.append(
                f"Pattern corresponds to {finding.cwe_id} ({cwe_data['name']}): "
                f"{cwe_data['short']}."
            )
        else:
            steps.append(
                "No CWE mapping is available for this rule; "
                "the pattern matches a known insecure coding practice."
            )

        # Step 3: File + context description
        ctx_summary = "No surrounding context captured."
        if finding.context_lines:
            n = len(finding.context_lines)
            ctx_summary = (
                f"{n} surrounding line(s) captured. "
                f"Sample: `{finding.context_lines[0][:80].strip()}`."
            )
        steps.append(
            f"Found in `{finding.file}:{finding.line}` — {ctx_summary}"
        )

        # Step 4: Confidence reasoning
        conf_reason: str
        if finding.is_test_file:
            conf_reason = "finding is in a test file (lower exploitability expected)"
        elif finding.is_suppressed:
            conf_reason = "finding has a suppression annotation"
        elif finding.confidence >= 0.9:
            conf_reason = "high-precision rule with strong pattern match"
        elif finding.confidence >= 0.7:
            conf_reason = "moderate-precision rule — review context for confirmation"
        else:
            conf_reason = "low-precision rule — high manual verification required"
        steps.append(
            f"Confidence set to {finding.confidence:.2f} because {conf_reason}."
        )

        # Step 5: Severity classification
        sev_basis = finding.cwe_id if finding.cwe_id else "rule classification"
        steps.append(
            f"Severity is {finding.severity} based on {sev_basis} classification."
        )

        # Step 6 (optional): Chain membership
        if context.get("is_in_chain", False):
            steps.append(
                "This finding is a member of a detected attack chain, "
                "which increases its effective risk beyond the standalone severity."
            )

        # Step 7 (optional): Corroborating findings
        corroborating: List[Finding] = context.get("corroborating_findings", [])
        if corroborating:
            steps.append(
                f"{len(corroborating)} corroborating finding(s) exist in the same file "
                f"({', '.join(f.rule_id for f in corroborating[:3])}), "
                f"providing supporting evidence."
            )

        return steps

    def assess_fp_risk(self, finding: Finding) -> str:
        """Assess false positive risk: 'low' | 'medium' | 'high'."""
        # High: test file or sanitization in context
        if finding.is_test_file:
            return "high"

        ctx_text = " ".join(finding.context_lines).lower()
        has_sanitization = any(
            re.search(pat, ctx_text, re.IGNORECASE) for pat in _SANITIZATION_PATTERNS
        )
        if has_sanitization:
            return "high"

        # Also high if suppressed
        if finding.is_suppressed:
            return "high"

        # Low: high confidence and not a test file
        if finding.confidence >= 0.85:
            return "low"

        # Medium: confidence in 0.7–0.85 range
        if finding.confidence >= 0.7:
            return "medium"

        # Below 0.7 → high FP risk
        return "high"

    def generate_verification_steps(self, finding: Finding) -> str:
        """Generate recommended verification steps for this finding."""
        cwe_data = _CWE_INFO.get(finding.cwe_id, _CWE_INFO_DEFAULT)
        base_steps = cwe_data["verification"]

        # Append test-file caveat if applicable
        if finding.is_test_file:
            base_steps += (
                " Note: this finding is in a test file — verify whether the "
                "vulnerable pattern is intentional test data or production code."
            )

        return base_steps

    def batch_explain(
        self,
        findings: List[Finding],
        chains: List[Dict[str, Any]] = [],
    ) -> Dict[str, Explanation]:
        """Explain all findings. Returns dict keyed by fingerprint."""
        # Build a map of fingerprint → list of other findings in same file
        # for corroborating finding context
        file_to_findings: Dict[str, List[Finding]] = {}
        for f in findings:
            file_to_findings.setdefault(f.file, []).append(f)

        # Build chain membership set
        chained_fps: set = set()
        for chain in chains:
            for fp in chain.get("finding_fingerprints", []):
                chained_fps.add(fp)

        result: Dict[str, Explanation] = {}
        for f in findings:
            fp = f.fingerprint()
            corroborating = [
                other for other in file_to_findings.get(f.file, [])
                if other.fingerprint() != fp
            ]
            ctx: Dict[str, Any] = {
                "is_in_chain": fp in chained_fps,
                "corroborating_findings": corroborating,
            }
            result[fp] = self.explain_finding(f, context=ctx)

        return result

    # ── Private helpers ──────────────────────────────────────────────────────

    def _build_why_detected(self, finding: Finding) -> str:
        """Build the primary detection reason string."""
        cwe_data = _CWE_INFO.get(finding.cwe_id, _CWE_INFO_DEFAULT)
        if finding.cwe_id:
            return (
                f"Rule `{finding.rule_id}` detected {cwe_data['short']} "
                f"({finding.cwe_id}: {cwe_data['name']}) in `{finding.file}`."
            )
        return (
            f"Rule `{finding.rule_id}` matched a security-sensitive pattern "
            f"in `{finding.file}` at line {finding.line}."
        )

    def _build_triggered_rules(self, finding: Finding) -> List[str]:
        """Collect all rules that contributed to this finding."""
        rules = [finding.rule_id]
        # If the rule_id contains sub-rules (dash-separated), list each part
        parts = finding.rule_id.split("-")
        if len(parts) > 1:
            for part in parts:
                sub = part.strip()
                if sub and sub != finding.rule_id and len(sub) > 2:
                    rules.append(sub)
        # Add CWE as a "rule" reference
        if finding.cwe_id and finding.cwe_id not in rules:
            rules.append(finding.cwe_id)
        return rules
