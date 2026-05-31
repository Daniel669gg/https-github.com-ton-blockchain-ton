"""TythanAI — Bug Bounty Report Quality Scorer
Analyzes bug bounty report quality across 10 dimensions and predicts
triage outcome. Helps researchers write compelling, accepted reports.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

# ─────────────────────────────────────────────────────────────────────────────
# Scoring dimension metadata
# ─────────────────────────────────────────────────────────────────────────────

_SCORING_DIMENSIONS = [
    {
        "name": "reproducibility",
        "weight": 0.20,
        "description": "Steps to reproduce are clear and numbered",
    },
    {
        "name": "impact_clarity",
        "weight": 0.18,
        "description": "Business/security impact is clearly stated",
    },
    {
        "name": "poc_quality",
        "weight": 0.15,
        "description": "PoC code or commands are present and executable",
    },
    {
        "name": "severity_justification",
        "weight": 0.12,
        "description": "CVSS score or equivalent severity reasoning is provided",
    },
    {
        "name": "scope_compliance",
        "weight": 0.10,
        "description": "Target is in scope for the program",
    },
    {
        "name": "technical_depth",
        "weight": 0.10,
        "description": "Root cause is explained at a technical level",
    },
    {
        "name": "remediation_quality",
        "weight": 0.07,
        "description": "A concrete fix or mitigation is suggested",
    },
    {
        "name": "communication_clarity",
        "weight": 0.05,
        "description": "Grammar, structure, and professionalism are adequate",
    },
    {
        "name": "cve_reference",
        "weight": 0.02,
        "description": "CVE/CWE is referenced where applicable",
    },
    {
        "name": "attachments",
        "weight": 0.01,
        "description": "Screenshots, logs, or supporting files are attached",
    },
]

assert abs(sum(d["weight"] for d in _SCORING_DIMENSIONS) - 1.0) < 1e-9, "Weights must sum to 1.0"

# ─────────────────────────────────────────────────────────────────────────────
# Pydantic models
# ─────────────────────────────────────────────────────────────────────────────


class ReportDimension(BaseModel):
    name: str
    score: float = Field(ge=0, le=10)
    weight: float
    feedback: str
    passed: bool


class BugBountyScoreReport(BaseModel):
    overall_score: float = Field(ge=0, le=100)
    predicted_outcome: str   # "LIKELY_ACCEPTED" | "NEEDS_IMPROVEMENT" | "LIKELY_REJECTED"
    severity_suggested: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    dimensions: List[ReportDimension]
    strengths: List[str]
    weaknesses: List[str]
    recommendations: List[str]
    estimated_response_time: str  # "24h" | "3-7 days" | "2-4 weeks"

    def to_markdown(self) -> str:
        """Render the score report as a Markdown string."""
        lines: List[str] = [
            "# Bug Bounty Report Quality Analysis",
            "",
            f"**Overall Score:** {self.overall_score:.1f} / 100",
            f"**Predicted Outcome:** {self.predicted_outcome}",
            f"**Suggested Severity:** {self.severity_suggested}",
            f"**Estimated Response Time:** {self.estimated_response_time}",
            "",
            "## Dimension Scores",
            "",
            "| Dimension | Score | Weight | Status |",
            "|-----------|-------|--------|--------|",
        ]
        for dim in self.dimensions:
            status = "PASS" if dim.passed else "FAIL"
            lines.append(f"| {dim.name} | {dim.score:.1f}/10 | {dim.weight:.0%} | {status} |")

        if self.strengths:
            lines += ["", "## Strengths", ""]
            for s in self.strengths:
                lines.append(f"- {s}")

        if self.weaknesses:
            lines += ["", "## Weaknesses", ""]
            for w in self.weaknesses:
                lines.append(f"- {w}")

        if self.recommendations:
            lines += ["", "## Recommendations", ""]
            for i, r in enumerate(self.recommendations, 1):
                lines.append(f"{i}. {r}")

        lines += ["", "## Dimension Feedback", ""]
        for dim in self.dimensions:
            lines.append(f"**{dim.name}** ({dim.score:.1f}/10): {dim.feedback}")

        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Regex/keyword patterns used by dimension scorers
# ─────────────────────────────────────────────────────────────────────────────

_RE_NUMBERED_STEPS = re.compile(
    r"(?:step\s*\d+[:\.]|^\s*\d+[\.\)]\s+\S|first[,\s]|navigate\s+to|go\s+to|visit\s+|open\s+the)",
    re.IGNORECASE | re.MULTILINE,
)
_RE_IMPACT = re.compile(
    r"(?:impact\s*:|allows?\s+(?:an?\s+)?attacker|results?\s+in|can\s+lead\s+to|enables?\s+|"
    r"attacker\s+(?:can|could|is\s+able)|leads?\s+to\s+|consequences?\s*:)",
    re.IGNORECASE,
)
_RE_CODE_BLOCK = re.compile(r"```[\s\S]*?```|`[^`]+`", re.MULTILINE)
_RE_CURL = re.compile(r"\bcurl\s+-", re.IGNORECASE)
_RE_PYTHON_SCRIPT = re.compile(r"(?:import\s+\w+|def\s+\w+\s*\(|requests\.(?:get|post))", re.IGNORECASE)
_RE_HTTP_REQUEST = re.compile(r"(?:GET|POST|PUT|DELETE|PATCH)\s+/[^\s]*\s+HTTP/", re.IGNORECASE)
_RE_CVSS = re.compile(r"(?:CVSS[:\s]*(?:\d+\.?\d*)|(?:critical|high|medium|low)\s+because)", re.IGNORECASE)
_RE_IN_SCOPE = re.compile(r"(?:in[\s-]scope|in\s+scope|target:\s*\S+|url\s*:\s*https?://)", re.IGNORECASE)
_RE_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_RE_CWE_CVE = re.compile(r"(?:CVE-\d{4}-\d+|CWE-\d+)", re.IGNORECASE)
_RE_ROOT_CAUSE = re.compile(
    r"(?:root\s+cause|CWE-\d+|HTTP\s+\d{3}|stack\s+trace|traceback|Exception|NullPointer"
    r"|race\s+condition|unsanitized|unvalidated|missing\s+(?:auth|validation|check))",
    re.IGNORECASE,
)
_RE_REMEDIATION = re.compile(
    r"(?:fix\s*:|recommend|patch|mitigat|sanitiz|parameteriz|escape|encode|validat|whitelist|allowlist"
    r"|use\s+prepared\s+statement|content.security.policy|x-frame-options)",
    re.IGNORECASE,
)
_RE_ATTACHMENTS = re.compile(
    r"(?:\[screenshot|\!\[|attached|\.png|\.jpg|\.jpeg|\.gif|\.mp4|\.har|\.log\b|attachment)",
    re.IGNORECASE,
)


def _count_matches(pattern: re.Pattern, text: str) -> int:
    return len(pattern.findall(text))


def _text_word_count(text: str) -> int:
    return len(text.split())


# ─────────────────────────────────────────────────────────────────────────────
# Individual dimension scorers (returns score 0-10, feedback, passed)
# ─────────────────────────────────────────────────────────────────────────────

def _score_reproducibility(text: str) -> tuple[float, str, bool]:
    matches = _count_matches(_RE_NUMBERED_STEPS, text)
    word_count = _text_word_count(text)
    if matches >= 4 or (matches >= 2 and word_count >= 150):
        return 9.0, "Clear numbered steps to reproduce are present.", True
    if matches >= 2:
        return 7.0, "Some reproduction steps found; add more numbered steps for clarity.", True
    if matches == 1:
        return 4.0, "Only one reproduction step indicator found. Add a complete numbered step sequence.", False
    return 1.0, "No clear steps to reproduce detected. Triagers cannot reproduce without numbered steps.", False


def _score_impact_clarity(text: str) -> tuple[float, str, bool]:
    matches = _count_matches(_RE_IMPACT, text)
    if matches >= 3:
        return 9.5, "Impact is well-articulated with multiple supporting statements.", True
    if matches == 2:
        return 7.5, "Good impact description. Consider quantifying the business risk.", True
    if matches == 1:
        return 5.0, "Impact mentioned but could be more detailed. Explain who is affected and how.", False
    return 1.0, "Impact is not described. Triagers need to understand the real-world consequences.", False


def _score_poc_quality(text: str) -> tuple[float, str, bool]:
    has_code_block = bool(_RE_CODE_BLOCK.search(text))
    has_curl = bool(_RE_CURL.search(text))
    has_script = bool(_RE_PYTHON_SCRIPT.search(text))
    has_http = bool(_RE_HTTP_REQUEST.search(text))

    signals = sum([has_code_block, has_curl, has_script, has_http])
    if signals >= 3:
        return 10.0, "Excellent PoC with executable code or full HTTP request.", True
    if signals == 2:
        return 8.0, "Good PoC present. Adding a self-contained script would strengthen this.", True
    if signals == 1:
        return 5.5, "Partial PoC detected. Include a complete, executable example.", True
    return 0.5, "No PoC code, curl command, or HTTP request found. PoC is critical for triage.", False


def _score_severity_justification(text: str) -> tuple[float, str, bool]:
    has_cvss = bool(_RE_CVSS.search(text))
    has_cwe = bool(_RE_CWE_CVE.search(text))
    word_count = _text_word_count(text)

    if has_cvss and has_cwe:
        return 10.0, "CVSS score and CWE reference both present — excellent severity justification.", True
    if has_cvss:
        return 8.0, "CVSS score provided. Adding a CWE reference would complete the justification.", True
    if has_cwe:
        return 6.0, "CWE reference found. Include a CVSS base score for stronger severity justification.", True
    if word_count > 300:
        return 4.0, "Lengthy report but no explicit CVSS/CWE found. State CVSS score and reasoning.", False
    return 2.0, "No severity justification found. Include CVSS vector and score.", False


def _score_scope_compliance(text: str, program_name: str = "") -> tuple[float, str, bool]:
    has_url = bool(_RE_URL.search(text))
    has_scope_mention = bool(_RE_IN_SCOPE.search(text))

    if has_scope_mention:
        return 9.0, "Target appears to be declared in scope.", True
    if has_url:
        return 7.0, "URL target found. Explicitly confirm it falls within the program scope.", True
    return 5.0, "Scope compliance could not be verified from the report text. State the target URL and confirm it is in scope.", False


def _score_technical_depth(text: str) -> tuple[float, str, bool]:
    matches = _count_matches(_RE_ROOT_CAUSE, text)
    if matches >= 3:
        return 9.0, "Strong technical depth — root cause, CWE, and technical details present.", True
    if matches == 2:
        return 7.0, "Good technical depth. Adding more root-cause analysis would improve the report.", True
    if matches == 1:
        return 4.5, "Limited technical depth. Explain the root cause: which code path, which parameter, why it fails.", False
    return 2.0, "Minimal technical content. Triagers need to understand the vulnerability mechanism.", False


def _score_remediation_quality(text: str) -> tuple[float, str, bool]:
    matches = _count_matches(_RE_REMEDIATION, text)
    if matches >= 3:
        return 9.0, "Concrete remediation guidance with multiple specific recommendations.", True
    if matches == 2:
        return 7.0, "Good remediation suggestion. Consider adding code-level examples.", True
    if matches == 1:
        return 5.0, "Some remediation hint present. Provide a specific fix with example code.", True
    return 1.0, "No remediation suggestion. Even a brief recommendation helps the triage team.", False


def _score_communication_clarity(text: str) -> tuple[float, str, bool]:
    word_count = _text_word_count(text)
    all_caps_words = len(re.findall(r"\b[A-Z]{4,}\b", text))
    exclamations = text.count("!")
    has_headers = bool(re.search(r"^#+\s+\w|^[A-Z][^a-z]{0,30}:\s*$", text, re.MULTILINE))

    score = 8.0
    feedback_parts: List[str] = []

    if word_count < 50:
        score -= 5.0
        feedback_parts.append("Report is too short to be meaningful.")
    elif word_count < 100:
        score -= 2.0
        feedback_parts.append("Report is brief; add more detail.")

    if all_caps_words > 5:
        score -= 1.5
        feedback_parts.append("Excessive ALL CAPS usage reduces professionalism.")

    if exclamations > 5:
        score -= 1.0
        feedback_parts.append("Reduce the number of exclamation marks.")

    if has_headers:
        score += 1.5

    score = max(0.0, min(10.0, score))
    passed = score >= 5.0
    feedback = " ".join(feedback_parts) if feedback_parts else "Report communicates clearly and professionally."
    return round(score, 1), feedback, passed


def _score_cve_reference(text: str) -> tuple[float, str, bool]:
    if bool(_RE_CWE_CVE.search(text)):
        return 10.0, "CVE or CWE reference found.", True
    return 0.0, "No CVE/CWE reference. If applicable, reference the relevant CWE identifier.", False


def _score_attachments(text: str) -> tuple[float, str, bool]:
    if bool(_RE_ATTACHMENTS.search(text)):
        return 10.0, "Attachment or screenshot reference found.", True
    return 0.0, "No attachments referenced. Screenshots or request/response logs add credibility.", False


# Map dimension names to scorer functions
_DIMENSION_SCORERS = {
    "reproducibility":       lambda t, _p: _score_reproducibility(t),
    "impact_clarity":        lambda t, _p: _score_impact_clarity(t),
    "poc_quality":           lambda t, _p: _score_poc_quality(t),
    "severity_justification": lambda t, _p: _score_severity_justification(t),
    "scope_compliance":      lambda t, p: _score_scope_compliance(t, p),
    "technical_depth":       lambda t, _p: _score_technical_depth(t),
    "remediation_quality":   lambda t, _p: _score_remediation_quality(t),
    "communication_clarity": lambda t, _p: _score_communication_clarity(t),
    "cve_reference":         lambda t, _p: _score_cve_reference(t),
    "attachments":           lambda t, _p: _score_attachments(t),
}


def _infer_severity(text: str) -> str:
    text_lower = text.lower()
    if any(kw in text_lower for kw in ["critical", "cvss 9", "cvss 10", "rce", "remote code", "pre-auth rce"]):
        return "CRITICAL"
    if any(kw in text_lower for kw in ["high", "cvss 7", "cvss 8", "sql injection", "authentication bypass", "stored xss"]):
        return "HIGH"
    if any(kw in text_lower for kw in ["medium", "cvss 4", "cvss 5", "cvss 6", "reflected xss", "csrf"]):
        return "MEDIUM"
    return "LOW"


def _estimate_response_time(overall_score: float, predicted_outcome: str) -> str:
    if predicted_outcome == "LIKELY_REJECTED":
        return "2-4 weeks"
    if overall_score >= 75:
        return "24h"
    if overall_score >= 50:
        return "3-7 days"
    return "2-4 weeks"


# ─────────────────────────────────────────────────────────────────────────────
# Main scorer class
# ─────────────────────────────────────────────────────────────────────────────


class BugBountyScorer:
    """
    Scores bug bounty report text across 10 quality dimensions and predicts
    the likely triage outcome.
    """

    def score(self, report_text: str, program_name: str = "") -> BugBountyScoreReport:
        """Score a report and return a BugBountyScoreReport."""
        dimensions: List[ReportDimension] = []
        weighted_sum = 0.0

        for dim_meta in _SCORING_DIMENSIONS:
            name = dim_meta["name"]
            weight = dim_meta["weight"]
            scorer = _DIMENSION_SCORERS[name]

            raw_score, feedback, passed = scorer(report_text, program_name)
            raw_score = max(0.0, min(10.0, raw_score))

            dimensions.append(ReportDimension(
                name=name,
                score=round(raw_score, 2),
                weight=weight,
                feedback=feedback,
                passed=passed,
            ))
            weighted_sum += raw_score * weight

        overall_score = round(weighted_sum * 10, 2)  # scale 0-100

        # Predict outcome
        if overall_score >= 70:
            predicted_outcome = "LIKELY_ACCEPTED"
        elif overall_score >= 40:
            predicted_outcome = "NEEDS_IMPROVEMENT"
        else:
            predicted_outcome = "LIKELY_REJECTED"

        severity_suggested = _infer_severity(report_text)
        estimated_response_time = _estimate_response_time(overall_score, predicted_outcome)

        # Derive strengths, weaknesses, and recommendations
        strengths: List[str] = []
        weaknesses: List[str] = []
        recommendations: List[str] = []

        for dim in dimensions:
            if dim.passed and dim.score >= 7.0:
                strengths.append(f"{dim.name.replace('_', ' ').title()}: {dim.feedback}")
            elif not dim.passed:
                weaknesses.append(f"{dim.name.replace('_', ' ').title()}: {dim.feedback}")
                recommendations.append(f"Improve {dim.name.replace('_', ' ')}: {dim.feedback}")

        return BugBountyScoreReport(
            overall_score=overall_score,
            predicted_outcome=predicted_outcome,
            severity_suggested=severity_suggested,
            dimensions=dimensions,
            strengths=strengths,
            weaknesses=weaknesses,
            recommendations=recommendations,
            estimated_response_time=estimated_response_time,
        )

    def suggest_improvements(self, report: BugBountyScoreReport) -> str:
        """Return a Markdown improvement guide for a scored report."""
        lines = [
            "# Improvement Guide",
            "",
            f"Current Score: **{report.overall_score:.1f}/100** ({report.predicted_outcome})",
            "",
            "## Priority Improvements",
            "",
        ]
        failing = [d for d in report.dimensions if not d.passed]
        failing_sorted = sorted(failing, key=lambda d: d.weight, reverse=True)

        if not failing_sorted:
            lines.append("All dimensions passed — focus on polish and additional PoC depth.")
        else:
            for dim in failing_sorted:
                lines.append(
                    f"### {dim.name.replace('_', ' ').title()} (weight: {dim.weight:.0%})"
                )
                lines.append(f"- Current score: {dim.score:.1f}/10")
                lines.append(f"- Feedback: {dim.feedback}")
                lines.append("")

        lines += [
            "## Quick Wins",
            "",
            "- Add a numbered step-by-step reproduction sequence",
            "- Include a working curl command or code snippet as PoC",
            "- State the CVSS base score (use https://cvss.js.org to calculate)",
            "- Add the relevant CWE-ID (see https://cwe.mitre.org)",
            "- Include at least one screenshot or HTTP request/response log",
            "- Conclude with a concrete remediation recommendation",
        ]
        return "\n".join(lines)

    def compare_reports(self, report_a: str, report_b: str) -> Dict:
        """Compare two report texts and return which is stronger and why."""
        score_a = self.score(report_a)
        score_b = self.score(report_b)
        winner = "A" if score_a.overall_score >= score_b.overall_score else "B"

        dim_comparison = {}
        for da, db in zip(score_a.dimensions, score_b.dimensions):
            assert da.name == db.name
            diff = round(da.score - db.score, 2)
            dim_comparison[da.name] = {
                "score_a": da.score,
                "score_b": db.score,
                "delta": diff,
                "winner": "A" if diff > 0 else ("B" if diff < 0 else "tie"),
            }

        return {
            "winner": winner,
            "score_a": score_a.overall_score,
            "score_b": score_b.overall_score,
            "margin": round(abs(score_a.overall_score - score_b.overall_score), 2),
            "dimension_comparison": dim_comparison,
            "summary": (
                f"Report {winner} scores higher by "
                f"{abs(score_a.overall_score - score_b.overall_score):.1f} points "
                f"({score_a.overall_score:.1f} vs {score_b.overall_score:.1f})."
            ),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience
# ─────────────────────────────────────────────────────────────────────────────

def score_report(report_text: str) -> BugBountyScoreReport:
    """Score a bug bounty report text and return a BugBountyScoreReport."""
    return BugBountyScorer().score(report_text)
