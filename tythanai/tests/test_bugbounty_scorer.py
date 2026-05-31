"""Tests for backend/agents/bugbounty_scorer.py."""
from __future__ import annotations
import sys, pathlib
_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.agents.bugbounty_scorer import (
    BugBountyScorer, BugBountyScoreReport, score_report,
)

_GOOD_REPORT = """
## SQL Injection in /api/users endpoint

**Impact:** An attacker can dump the entire users database including PII and credentials.
This allows full account takeover, data breach, and regulatory violations.

**Steps to Reproduce:**
1. Navigate to https://example.com/api/users
2. Set the id parameter to: 1' UNION SELECT username,password FROM users--
3. Observe the response contains all user records
4. Verify by extracting: 1' AND SLEEP(5)--

**PoC:**
```bash
curl -s 'https://example.com/api/users?id=1%27+UNION+SELECT+username,password+FROM+users--'
```

**Severity:** Critical — CVSS 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
CWE-89: Improper Neutralization of Special Elements used in SQL Command.
Root cause: User input directly concatenated into SQL query without sanitization.

**Fix:** Use parameterized queries / prepared statements. Never concatenate user input.

![screenshot of response](response.png)
"""

_POOR_REPORT = "found sql injection on login page"


def test_good_report_scores_high():
    scorer = BugBountyScorer()
    report = scorer.score(_GOOD_REPORT)
    assert isinstance(report, BugBountyScoreReport)
    assert report.overall_score > 50, (
        f"Good report should score >50, got {report.overall_score:.1f}"
    )


def test_poor_report_scores_low():
    scorer = BugBountyScorer()
    report = scorer.score(_POOR_REPORT)
    assert report.overall_score < 40, (
        f"Poor report should score <40, got {report.overall_score:.1f}"
    )


def test_poc_boosts_score():
    no_poc = "SQL injection found at /api/users. Steps: 1. Go to page 2. Login fails."
    with_poc = no_poc + "\n```\ncurl 'https://example.com/api?id=1 OR 1=1'\n```"
    scorer = BugBountyScorer()
    score_without = scorer.score(no_poc).overall_score
    score_with = scorer.score(with_poc).overall_score
    assert score_with >= score_without, (
        f"PoC should boost score: without={score_without:.1f} with={score_with:.1f}"
    )


def test_predicted_outcome_high_score():
    scorer = BugBountyScorer()
    report = scorer.score(_GOOD_REPORT)
    # High score should predict acceptance
    assert report.predicted_outcome in ("LIKELY_ACCEPTED", "NEEDS_IMPROVEMENT"), (
        f"Unexpected outcome: {report.predicted_outcome}"
    )


def test_to_markdown():
    scorer = BugBountyScorer()
    report = scorer.score(_GOOD_REPORT)
    md = report.to_markdown()
    assert isinstance(md, str)
    assert len(md) > 100
    assert "##" in md or "#" in md


def test_dimensions_count():
    scorer = BugBountyScorer()
    report = scorer.score(_GOOD_REPORT)
    assert len(report.dimensions) == 10, (
        f"Expected 10 dimensions, got {len(report.dimensions)}"
    )


def test_module_level_function():
    report = score_report(_GOOD_REPORT)
    assert isinstance(report, BugBountyScoreReport)
    assert 0.0 <= report.overall_score <= 100.0
    assert isinstance(report.recommendations, list)
    assert isinstance(report.strengths, list)
    assert isinstance(report.weaknesses, list)
