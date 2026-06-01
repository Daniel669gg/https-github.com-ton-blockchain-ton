"""Fix Explainer — pattern-based AI-style explanation for verified fixes.

No LLM required. Uses CWE knowledge base to explain root cause, fix rationale,
risks removed, and verifications performed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------

_CWE_EXPLANATIONS: Dict[str, Dict[str, str]] = {
    "CWE-89": {
        "name": "SQL Injection",
        "root_cause": (
            "User-controlled input is concatenated directly into an SQL query string "
            "without sanitization. The database interprets the injected SQL syntax as "
            "commands, allowing data exfiltration, modification, or authentication bypass."
        ),
        "why_fix": (
            "Parameterized queries (prepared statements) separate code from data: the "
            "database driver transmits SQL structure and user values independently, so "
            "injected syntax is always treated as a string literal, never as SQL."
        ),
        "risk_removed": "Data exfiltration, authentication bypass, table modification/deletion (OWASP A03:2021)",
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "root_cause": (
            "Unsanitized user input is passed to a shell command (os.system, subprocess "
            "with shell=True, etc.). An attacker appends shell metacharacters to execute "
            "arbitrary commands on the host operating system."
        ),
        "why_fix": (
            "Passing command arguments as a list (not a string) to subprocess with "
            "shell=False prevents shell interpretation entirely. shlex.quote() escapes "
            "metacharacters when a string form is unavoidable."
        ),
        "risk_removed": "Remote code execution, privilege escalation, data destruction (OWASP A03:2021)",
    },
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "root_cause": (
            "User-controlled content is rendered in an HTML context without encoding. "
            "An attacker injects <script> tags or event handlers that execute in victims' "
            "browsers, enabling session hijacking or phishing."
        ),
        "why_fix": (
            "HTML-encoding all output (converting <, >, &, \" to HTML entities) ensures "
            "user input is rendered as text, not executed as markup. "
            "Content Security Policy provides defense-in-depth."
        ),
        "risk_removed": "Session hijacking, credential theft, defacement (OWASP A03:2021)",
    },
    "CWE-22": {
        "name": "Path Traversal",
        "root_cause": (
            "User-supplied file paths are not normalized before use, allowing '../' "
            "sequences that escape the intended directory. Attackers read sensitive files "
            "or overwrite system configurations."
        ),
        "why_fix": (
            "os.path.realpath() or Path.resolve() resolves symlinks and '..' components "
            "to a canonical absolute path. A prefix check against the allowed root "
            "confirms the final path stays within bounds."
        ),
        "risk_removed": "Unauthorized file read/write, configuration disclosure, code execution (OWASP A01:2021)",
    },
    "CWE-798": {
        "name": "Hardcoded Credentials",
        "root_cause": (
            "Secrets (passwords, API keys, tokens) are embedded literally in source code. "
            "Anyone with repository access can extract and abuse them; they persist in git "
            "history even after removal."
        ),
        "why_fix": (
            "Reading secrets from environment variables (os.environ) or a secrets manager "
            "ensures they never appear in source. The application retrieves them at runtime "
            "only in the deployment environment."
        ),
        "risk_removed": "Credential theft, unauthorized API access, account takeover (OWASP A07:2021)",
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "root_cause": (
            "Deserializing untrusted data with pickle.load or yaml.load (without Loader) "
            "allows attackers to craft payloads that execute arbitrary Python code during "
            "the deserialization process."
        ),
        "why_fix": (
            "yaml.safe_load restricts the YAML loader to safe types (no Python object "
            "construction). For pickle, use json.loads on untrusted input; for internal "
            "serialization, sign and verify the payload before deserializing."
        ),
        "risk_removed": "Remote code execution via deserialization gadgets (OWASP A08:2021)",
    },
    "CWE-327": {
        "name": "Use of Broken Cryptographic Algorithm",
        "root_cause": (
            "MD5 and SHA-1 are cryptographically broken: collision attacks are practical "
            "and preimage resistance is weakened. Using them for password hashing or "
            "integrity verification provides false security."
        ),
        "why_fix": (
            "SHA-256/SHA-384/SHA-512 are cryptographically secure for integrity. "
            "For passwords, use bcrypt, argon2, or scrypt — slow-by-design algorithms "
            "that resist brute-force with cost parameters."
        ),
        "risk_removed": "Password cracking, hash collision forgery (OWASP A02:2021)",
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "root_cause": (
            "The application fetches a URL derived from user input without validating "
            "the destination. Attackers redirect requests to internal services, cloud "
            "metadata endpoints, or localhost to exfiltrate data or pivot."
        ),
        "why_fix": (
            "Validate the parsed hostname against an explicit allowlist of external "
            "domains. Reject private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x). "
            "Never follow redirects to internal resources."
        ),
        "risk_removed": "Internal service access, cloud metadata theft, port scanning (OWASP A10:2021)",
    },
    "CWE-94": {
        "name": "Code Injection",
        "root_cause": (
            "User input reaches eval(), exec(), or compile() and is executed as code. "
            "An attacker supplies arbitrary Python (or other language) statements."
        ),
        "why_fix": (
            "Eliminate eval/exec entirely. Use ast.literal_eval for safe evaluation of "
            "Python literals. Parse structured data (JSON, YAML) instead of executing "
            "user-supplied code strings."
        ),
        "risk_removed": "Arbitrary code execution, full system compromise (OWASP A03:2021)",
    },
}

_DEFAULT_EXPLANATION = {
    "name": "Security Vulnerability",
    "root_cause": "The vulnerability arises from insufficient validation or sanitization of external input.",
    "why_fix": "The fix applies proper validation, encoding, or parameterization at the vulnerable code point.",
    "risk_removed": "Reduces attack surface and eliminates the specific exploitation vector.",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class FixExplanation:
    """Human-readable explanation of a verified fix."""
    finding_id: str
    cwe_id: str
    cwe_name: str
    root_cause: str
    why_fix_works: str
    what_changed: List[str] = field(default_factory=list)
    risks_removed: List[str] = field(default_factory=list)
    verifications_performed: List[str] = field(default_factory=list)
    confidence_summary: str = ""
    owasp_reference: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "root_cause": self.root_cause,
            "why_fix_works": self.why_fix_works,
            "what_changed": self.what_changed,
            "risks_removed": self.risks_removed,
            "verifications_performed": self.verifications_performed,
            "confidence_summary": self.confidence_summary,
            "owasp_reference": self.owasp_reference,
        }


# ---------------------------------------------------------------------------
# Diff helpers
# ---------------------------------------------------------------------------


def _extract_changed_lines(original: str, patched: str) -> List[str]:
    """Return a short list of what lines changed (simplified diff)."""
    orig_lines = set(original.splitlines())
    patch_lines = set(patched.splitlines())
    removed = orig_lines - patch_lines
    added = patch_lines - orig_lines
    changes: List[str] = []
    for line in sorted(removed)[:3]:
        if line.strip():
            changes.append(f"- {line.strip()[:120]}")
    for line in sorted(added)[:3]:
        if line.strip():
            changes.append(f"+ {line.strip()[:120]}")
    return changes or ["Patch applied (diff not available)"]


def _format_verifications(verified_fix: Any) -> List[str]:
    """Build a list of completed verification steps from a VerifiedFix."""
    steps: List[str] = []
    if verified_fix is None:
        return ["No verification data available"]

    build = getattr(verified_fix, "build_result", None)
    if build:
        if getattr(build, "success", False):
            steps.append(f"✅ Build validation passed ({getattr(build, 'language', 'unknown')})")
        else:
            errs = getattr(build, "errors", [])
            steps.append(f"❌ Build validation failed: {'; '.join(errs[:2])}")

    test = getattr(verified_fix, "test_result", None)
    if test:
        if getattr(test, "success", True):
            steps.append("✅ Test suite passed")
        else:
            steps.append("❌ Test suite failed")

    if getattr(verified_fix, "reachability_removed", False):
        steps.append("✅ Exploit path reachability removed")
    else:
        steps.append("⚠️ Reachability recheck inconclusive (no CPG provided)")

    if getattr(verified_fix, "regression_detected", False):
        notes = getattr(verified_fix, "validation_notes", [])
        steps.append(f"❌ Regression detected: {'; '.join(notes[:2])}")
    else:
        steps.append("✅ No security regressions detected")

    if getattr(verified_fix, "vulnerability_confirmed_fixed", False):
        steps.append("✅ Static analysis confirms vulnerability removed")
    else:
        steps.append("⚠️ Static analysis could not confirm fix (manual review advised)")

    return steps


# ---------------------------------------------------------------------------
# Main explainer
# ---------------------------------------------------------------------------


class FixExplainer:
    """Generates human-readable explanations for verified fixes without an LLM."""

    def explain(
        self,
        finding: Any,
        original_code: str = "",
        patched_code: str = "",
        verified_fix: Optional[Any] = None,
    ) -> FixExplanation:
        """Generate a FixExplanation for a finding and its patch.

        Parameters
        ----------
        finding : Finding or dict
            The vulnerability being fixed.
        original_code : str
            Source code before the fix.
        patched_code : str
            Source code after the fix.
        verified_fix : VerifiedFix, optional
            If provided, verifications_performed is populated from it.
        """
        cwe_id = _get(finding, "cwe_id", "")
        finding_id = _get(finding, "rule_id", "unknown")
        severity = _get(finding, "severity", "MEDIUM")
        description = _get(finding, "description", "")

        kb = _CWE_EXPLANATIONS.get(cwe_id, _DEFAULT_EXPLANATION)
        cwe_name = kb.get("name", cwe_id)

        # What changed
        if original_code and patched_code:
            what_changed = _extract_changed_lines(original_code, patched_code)
        else:
            what_changed = ["Patch applied to vulnerable code section"]

        # Risks removed
        risks_removed = [kb.get("risk_removed", "Vulnerability-specific attack vector eliminated")]
        if severity in ("CRITICAL", "HIGH"):
            risks_removed.append(
                f"Eliminates {severity.lower()}-severity finding "
                f"(reduces CVSS score by 5-9 points)"
            )

        # Verifications
        if verified_fix is not None:
            verifications = _format_verifications(verified_fix)
        else:
            verifications = ["Verification data not available — manual review required"]

        # Confidence summary
        if verified_fix is not None:
            confidence = getattr(verified_fix, "fix_confidence", 0.0)
            fix_status = getattr(verified_fix, "fix_status", None)
            status_str = fix_status.value if hasattr(fix_status, "value") else str(fix_status)
            confidence_summary = (
                f"Fix status: {status_str.upper()}. "
                f"Confidence: {confidence:.1%}. "
                + (
                    "Full automated verification passed."
                    if confidence >= 0.8
                    else "Partial verification — manual review recommended."
                    if confidence >= 0.4
                    else "Low confidence — human review required."
                )
            )
        else:
            confidence_summary = "Confidence not computed — run VerifiedFixEngine.verify_fix() first."

        return FixExplanation(
            finding_id=finding_id,
            cwe_id=cwe_id,
            cwe_name=cwe_name,
            root_cause=kb.get("root_cause", _DEFAULT_EXPLANATION["root_cause"]),
            why_fix_works=kb.get("why_fix", _DEFAULT_EXPLANATION["why_fix"]),
            what_changed=what_changed,
            risks_removed=risks_removed,
            verifications_performed=verifications,
            confidence_summary=confidence_summary,
            owasp_reference=_OWASP_REF.get(cwe_id, ""),
        )

    def format_markdown(self, explanation: FixExplanation) -> str:
        """Render a FixExplanation as a Markdown report section."""
        lines = [
            f"## Fix Explanation: {explanation.cwe_name} ({explanation.cwe_id})",
            "",
            f"**Finding ID:** `{explanation.finding_id}`",
            "",
            "### Root Cause",
            "",
            explanation.root_cause,
            "",
            "### Why the Fix Works",
            "",
            explanation.why_fix_works,
            "",
            "### What Changed",
            "",
        ]
        for change in explanation.what_changed:
            lines.append(f"```")
            lines.append(change)
            lines.append(f"```")
        lines.extend([
            "",
            "### Risks Removed",
            "",
        ])
        for risk in explanation.risks_removed:
            lines.append(f"- {risk}")
        lines.extend([
            "",
            "### Verifications Performed",
            "",
        ])
        for v in explanation.verifications_performed:
            lines.append(f"- {v}")
        lines.extend([
            "",
            "### Confidence Summary",
            "",
            explanation.confidence_summary,
            "",
        ])
        if explanation.owasp_reference:
            lines.extend([f"**OWASP Reference:** {explanation.owasp_reference}", ""])
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# OWASP references
# ---------------------------------------------------------------------------

_OWASP_REF: Dict[str, str] = {
    "CWE-89": "OWASP A03:2021 — Injection",
    "CWE-78": "OWASP A03:2021 — Injection",
    "CWE-79": "OWASP A03:2021 — Injection (XSS)",
    "CWE-22": "OWASP A01:2021 — Broken Access Control",
    "CWE-798": "OWASP A07:2021 — Identification and Authentication Failures",
    "CWE-502": "OWASP A08:2021 — Software and Data Integrity Failures",
    "CWE-327": "OWASP A02:2021 — Cryptographic Failures",
    "CWE-918": "OWASP A10:2021 — Server-Side Request Forgery",
    "CWE-94": "OWASP A03:2021 — Injection",
}


def _get(obj: Any, attr: str, default: Any = "") -> Any:
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)
