"""
Ghost Security Platform — PR Inline Comment Integration

Posts security findings as inline code-review comments directly on GitHub
Pull Requests and GitLab Merge Requests.  This is a key developer-workflow
feature analogous to what Snyk and CodeQL provide: every finding lands on
the exact line it was found so the developer can fix-in-context without
switching to a separate dashboard.

Supported platforms:
  - GitHub  – POST /repos/{owner}/{repo}/pulls/{pr}/comments  (review API)
  - GitLab  – POST /projects/{id}/merge_requests/{iid}/discussions

Key behaviours:
  • Only comments on lines that are part of the PR diff (changed lines).
    Off-diff findings are collected into the PR-level summary instead.
  • Groups findings by (file, line) — at most one comment per line —
    to avoid spamming a PR with dozens of individual bot comments.
  • Formats comments as polished Markdown: severity emoji, description,
    fix suggestion, CWE / OWASP reference links.
  • Summary comment enumerates ALL findings (incl. off-diff) in a
    collapsible table so nothing is lost.

Usage:
    from integrations.pr_commenter import PRCommenter

    commenter = PRCommenter(platform="github", token="ghp_...")
    stats = commenter.post_findings(
        findings,
        owner="acme", repo="backend",
        pr_number=42,
        commit_sha="abc123",
    )
    # stats → {"posted": 5, "skipped_off_diff": 3, "errors": 0, ...}

    commenter.post_summary_comment(findings, "acme", "backend", 42)
"""
from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ── Severity metadata ─────────────────────────────────────────────────────────

_SEV_EMOJI: Dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "⚪",
}

_SEV_ORDER: List[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# OWASP Top-10 2021 short names keyed by A-number
_OWASP_NAMES: Dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable Components",
    "A07": "Auth & Session Failures",
    "A08": "Software/Data Integrity",
    "A09": "Logging Failures",
    "A10": "SSRF",
}

# ── Diff parsing ──────────────────────────────────────────────────────────────

def _parse_unified_diff(patch_text: str) -> Set[int]:
    """
    Extract the set of *new* line numbers that appear in a unified diff patch.

    GitHub returns per-file patches in unified diff format.  The hunk header
    ``@@ -old_start,old_count +new_start,new_count @@`` tells us where in the
    new file each hunk begins.  We track only added/context lines (not removed
    ones, which have no new-file line number).
    """
    lines: Set[int] = set()
    new_line = 0
    for raw_line in patch_text.splitlines():
        hunk_match = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw_line)
        if hunk_match:
            new_line = int(hunk_match.group(1))
            continue
        if raw_line.startswith("-"):
            # Removed line: no new-file line number
            continue
        if raw_line.startswith("+"):
            lines.add(new_line)
            new_line += 1
        else:
            # Context line
            new_line += 1
    return lines


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _http_request(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[dict] = None,
    timeout: int = 20,
) -> Tuple[int, dict]:
    """
    Minimal HTTP helper using only the standard library.

    Returns (status_code, response_body_as_dict).
    Does NOT raise on 4xx/5xx — callers check the status code.
    """
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req  = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
            try:
                return status, json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                return status, {"_raw": raw.decode("utf-8", errors="replace")}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return exc.code, {"_raw": raw.decode("utf-8", errors="replace")}
    except urllib.error.URLError as exc:
        logger.error("Network error calling %s %s: %s", method, url, exc)
        return 0, {"error": str(exc)}


# ── CWE / OWASP link builders ─────────────────────────────────────────────────

def _cwe_link(cwe: str) -> str:
    """Return a Markdown link to the CWE definition, or the raw string."""
    if not cwe or cwe.upper() == "N/A":
        return "N/A"
    m = re.search(r"(\d+)", cwe)
    if m:
        num = m.group(1)
        return f"[{cwe}](https://cwe.mitre.org/data/definitions/{num}.html)"
    return cwe


def _owasp_link(owasp: str) -> str:
    """Return a Markdown link to the OWASP page, or the raw string."""
    if not owasp or owasp.upper() == "N/A":
        return "N/A"
    m = re.search(r"(A\d+)", owasp.upper())
    if m:
        code = m.group(1)
        name = _OWASP_NAMES.get(code[:3], "OWASP Top 10")
        return f"[{owasp} – {name}](https://owasp.org/Top10/)"
    return owasp


# ── Main class ────────────────────────────────────────────────────────────────

class PRCommenter:
    """
    Posts Ghost Security findings as inline PR / MR review comments.

    Parameters
    ----------
    platform : "github" | "gitlab"
        Target code hosting platform.
    token : str, optional
        Personal access token (PAT) or installation token.
        Falls back to ``GITHUB_TOKEN`` / ``GITLAB_TOKEN`` env vars.
    base_url : str, optional
        Override the API base URL.  Useful for GitHub Enterprise Server or
        self-hosted GitLab instances.  Defaults:
          GitHub  → https://api.github.com
          GitLab  → https://gitlab.com
    max_inline_comments : int
        Hard cap on inline comments per PR run (default 30).  Findings
        beyond this cap are included only in the summary comment.
    """

    _GITHUB_DEFAULT_BASE  = "https://api.github.com"
    _GITLAB_DEFAULT_BASE  = "https://gitlab.com"

    def __init__(
        self,
        platform: str = "github",
        token: Optional[str] = None,
        base_url: Optional[str] = None,
        max_inline_comments: int = 30,
    ) -> None:
        self.platform = platform.lower().strip()
        if self.platform not in ("github", "gitlab"):
            raise ValueError(f"Unsupported platform: {platform!r}. Use 'github' or 'gitlab'.")

        import os
        if token:
            self._token = token
        elif self.platform == "github":
            self._token = os.getenv("GITHUB_TOKEN", "")
        else:
            self._token = os.getenv("GITLAB_TOKEN", "")

        if base_url:
            self._base_url = base_url.rstrip("/")
        elif self.platform == "github":
            self._base_url = self._GITHUB_DEFAULT_BASE
        else:
            self._base_url = self._GITLAB_DEFAULT_BASE

        self._max_inline = max_inline_comments

    # ── Headers ───────────────────────────────────────────────────────────────

    def _github_headers(self) -> Dict[str, str]:
        return {
            "Authorization":         f"Bearer {self._token}",
            "Accept":                "application/vnd.github+json",
            "X-GitHub-Api-Version":  "2022-11-28",
            "Content-Type":          "application/json",
            "User-Agent":            "SentinelOps/3.0",
        }

    def _gitlab_headers(self) -> Dict[str, str]:
        return {
            "PRIVATE-TOKEN": self._token,
            "Content-Type":  "application/json",
            "User-Agent":    "SentinelOps/3.0",
        }

    def _headers(self) -> Dict[str, str]:
        return self._github_headers() if self.platform == "github" else self._gitlab_headers()

    # ── Public API ─────────────────────────────────────────────────────────────

    def post_findings(
        self,
        findings: List[dict],
        owner: str,
        repo: str,
        pr_number: int,
        commit_sha: str,
    ) -> dict:
        """
        Post inline review comments for findings that fall on changed diff lines.

        Findings on unchanged lines (off-diff) are noted in the return stats
        but are NOT dropped — they will appear in the summary comment posted
        by :meth:`post_summary_comment`.

        Returns a stats dict::

            {
              "posted":           int,   # inline comments successfully created
              "skipped_off_diff": int,   # findings not in the diff
              "skipped_duplicate":int,   # >1 finding on same (file, line)
              "capped":           int,   # findings dropped by max_inline cap
              "errors":           int,   # API call failures
              "platform":         str,
            }
        """
        stats: Dict[str, int] = {
            "posted": 0,
            "skipped_off_diff": 0,
            "skipped_duplicate": 0,
            "capped": 0,
            "errors": 0,
        }

        if not findings:
            logger.info("PRCommenter.post_findings: no findings to post")
            return {**stats, "platform": self.platform}

        # 1. Fetch diff lines per file
        diff_map = self._get_diff_lines(owner, repo, pr_number)

        # 2. Group findings by (file, line), keeping the highest severity per slot
        slot_map: Dict[Tuple[str, int], List[dict]] = defaultdict(list)
        for f in findings:
            file_path = f.get("file", "").lstrip("/")
            line_num  = int(f.get("line", 0) or 0)
            if not file_path or line_num < 1:
                stats["skipped_off_diff"] += 1
                continue
            changed_lines = diff_map.get(file_path, set())
            if line_num not in changed_lines:
                stats["skipped_off_diff"] += 1
                continue
            slot_map[(file_path, line_num)].append(f)

        # 3. For each slot emit one comment (merge if multiple findings)
        posted_count = 0
        for (file_path, line_num), slot_findings in slot_map.items():
            if posted_count >= self._max_inline:
                stats["capped"] += len(slot_findings)
                continue

            # Sort by severity: CRITICAL first
            slot_findings.sort(
                key=lambda x: _SEV_ORDER.index(x.get("severity", "INFO").upper())
                if x.get("severity", "INFO").upper() in _SEV_ORDER else 99
            )

            if len(slot_findings) > 1:
                stats["skipped_duplicate"] += len(slot_findings) - 1

            comment_body = self._format_comment_group(slot_findings)

            if self.platform == "github":
                ok = self._post_github_comment(
                    file=file_path,
                    line=line_num,
                    body=comment_body,
                    owner=owner,
                    repo=repo,
                    pr_number=pr_number,
                    commit_sha=commit_sha,
                )
            else:
                ok = self._post_gitlab_comment(
                    file=file_path,
                    line=line_num,
                    body=comment_body,
                    owner=owner,
                    repo=repo,
                    pr_number=pr_number,
                    commit_sha=commit_sha,
                )

            if ok:
                posted_count += 1
                stats["posted"] += 1
            else:
                stats["errors"] += 1

        logger.info(
            "PRCommenter.post_findings: posted=%d off_diff=%d errors=%d",
            stats["posted"], stats["skipped_off_diff"], stats["errors"],
        )
        return {**stats, "platform": self.platform}

    def format_comment(self, finding: dict) -> str:
        """
        Format a single finding as a Markdown review comment body.

        Exposed as a public method so callers can preview the output
        without actually posting to an API.
        """
        return self._format_single_finding(finding)

    def post_summary_comment(
        self,
        findings: List[dict],
        owner: str,
        repo: str,
        pr_number: int,
    ) -> bool:
        """
        Post (or update) a PR-level summary comment that lists ALL findings.

        This complements the inline comments: findings on unchanged lines are
        only visible here.

        Returns True on success.
        """
        body = self._build_summary_body(findings, owner, repo, pr_number)

        if self.platform == "github":
            url    = f"{self._base_url}/repos/{owner}/{repo}/issues/{pr_number}/comments"
            status, _ = _http_request("POST", url, self._headers(), {"body": body})
            ok = (200 <= status < 300)
        else:
            project_id = urllib.parse.quote(f"{owner}/{repo}", safe="")
            url = (
                f"{self._base_url}/api/v4/projects/{project_id}"
                f"/merge_requests/{pr_number}/notes"
            )
            status, _ = _http_request("POST", url, self._headers(), {"body": body})
            ok = (200 <= status < 300)

        if not ok:
            logger.warning("PRCommenter: failed to post summary comment (HTTP %d)", status)
        return ok

    # ── Diff retrieval ─────────────────────────────────────────────────────────

    def _get_diff_lines(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> Dict[str, Set[int]]:
        """
        Return a mapping of {filename → set_of_new_line_numbers} for all files
        touched by the PR / MR.

        Only *added or context* lines are included (removed lines have no
        position in the new file and cannot receive inline comments).
        """
        if self.platform == "github":
            return self._get_diff_lines_github(owner, repo, pr_number)
        return self._get_diff_lines_gitlab(owner, repo, pr_number)

    def _get_diff_lines_github(
        self, owner: str, repo: str, pr_number: int
    ) -> Dict[str, Set[int]]:
        """Fetch per-file patches from the GitHub PR files endpoint."""
        url = f"{self._base_url}/repos/{owner}/{repo}/pulls/{pr_number}/files"
        # GitHub paginates at 30 per page; handle up to 10 pages (300 files)
        diff_map: Dict[str, Set[int]] = {}
        page = 1
        while True:
            paged_url = f"{url}?per_page=100&page={page}"
            status, data = _http_request("GET", paged_url, self._github_headers())
            if status != 200 or not isinstance(data, list):
                logger.warning(
                    "PRCommenter: GitHub PR files returned HTTP %d (page %d)", status, page
                )
                break
            if not data:
                break
            for file_entry in data:
                filename = file_entry.get("filename", "")
                patch    = file_entry.get("patch", "")
                if filename and patch:
                    diff_map[filename] = _parse_unified_diff(patch)
            if len(data) < 100:
                break
            page += 1
            if page > 10:
                break
        logger.debug("PRCommenter: diff_map covers %d file(s)", len(diff_map))
        return diff_map

    def _get_diff_lines_gitlab(
        self, owner: str, repo: str, pr_number: int
    ) -> Dict[str, Set[int]]:
        """Fetch diffs from the GitLab MR changes endpoint."""
        project_id = urllib.parse.quote(f"{owner}/{repo}", safe="")
        url = (
            f"{self._base_url}/api/v4/projects/{project_id}"
            f"/merge_requests/{pr_number}/changes"
        )
        status, data = _http_request("GET", url, self._gitlab_headers())
        diff_map: Dict[str, Set[int]] = {}
        if status != 200 or not isinstance(data, dict):
            logger.warning("PRCommenter: GitLab MR changes returned HTTP %d", status)
            return diff_map
        for change in data.get("changes", []):
            new_path = change.get("new_path", "")
            diff     = change.get("diff", "")
            if new_path and diff:
                diff_map[new_path] = _parse_unified_diff(diff)
        logger.debug("PRCommenter: GitLab diff_map covers %d file(s)", len(diff_map))
        return diff_map

    # ── Comment posting ────────────────────────────────────────────────────────

    def _post_github_comment(
        self,
        file: str,
        line: int,
        body: str,
        owner: str,
        repo: str,
        pr_number: int,
        commit_sha: str,
    ) -> bool:
        """
        POST a single inline pull-request review comment via the GitHub REST API.

        Uses the ``/repos/{owner}/{repo}/pulls/{pr}/comments`` endpoint with
        ``line`` (new file line number) and ``side: RIGHT`` so the comment
        appears on the new version of the file.
        """
        url     = f"{self._base_url}/repos/{owner}/{repo}/pulls/{pr_number}/comments"
        payload = {
            "body":      body,
            "commit_id": commit_sha,
            "path":      file,
            "line":      line,
            "side":      "RIGHT",
        }
        status, resp = _http_request("POST", url, self._github_headers(), payload)
        if 200 <= status < 300:
            logger.debug("PRCommenter: posted GitHub comment on %s:%d", file, line)
            return True
        logger.warning(
            "PRCommenter: GitHub comment failed %s:%d → HTTP %d: %s",
            file, line, status, str(resp)[:200],
        )
        return False

    def _post_gitlab_comment(
        self,
        file: str,
        line: int,
        body: str,
        owner: str,
        repo: str,
        pr_number: int,
        commit_sha: str,
    ) -> bool:
        """
        POST an inline discussion note via the GitLab Merge Request Discussions API.

        ``POST /projects/{id}/merge_requests/{iid}/discussions``
        with ``position.new_line`` set to the target line.
        """
        project_id = urllib.parse.quote(f"{owner}/{repo}", safe="")
        url        = (
            f"{self._base_url}/api/v4/projects/{project_id}"
            f"/merge_requests/{pr_number}/discussions"
        )
        payload: Dict[str, Any] = {
            "body": body,
            "position": {
                "position_type": "text",
                "new_path":      file,
                "new_line":      line,
                "base_sha":      commit_sha,   # GitLab requires base/head/start SHA triplet;
                "head_sha":      commit_sha,   # callers should pass head SHA; base fallback OK
                "start_sha":     commit_sha,
            },
        }
        status, resp = _http_request("POST", url, self._gitlab_headers(), payload)
        if 200 <= status < 300:
            logger.debug("PRCommenter: posted GitLab discussion on %s:%d", file, line)
            return True
        logger.warning(
            "PRCommenter: GitLab discussion failed %s:%d → HTTP %d: %s",
            file, line, status, str(resp)[:200],
        )
        return False

    # ── Markdown formatters ────────────────────────────────────────────────────

    def _format_single_finding(self, finding: dict) -> str:
        """
        Render one finding as a self-contained Markdown comment block.

        Sections:
          1. Header line with severity emoji, severity label, rule id
          2. Finding description
          3. Fix suggestion (if present)
          4. Reference links: CWE, OWASP
          5. Confidence / priority metadata
        """
        sev     = (finding.get("severity") or "MEDIUM").upper()
        emoji   = _SEV_EMOJI.get(sev, "⚪")
        rule_id = finding.get("rule_id") or finding.get("id") or "N/A"
        desc    = (
            finding.get("message")
            or finding.get("description")
            or "Security finding detected."
        )
        fix     = finding.get("recommendation") or finding.get("fix") or ""
        cwe_raw = finding.get("cwe", "N/A")
        owasp_raw = finding.get("owasp", "N/A")
        confidence = finding.get("confidence", "N/A")

        lines = [
            f"{emoji} **[{sev}]** `{rule_id}` — Security Finding",
            "",
            desc,
        ]

        if fix:
            lines += ["", f"> **Suggested Fix:** {fix}"]

        lines += [
            "",
            f"**References:** "
            f"CWE: {_cwe_link(str(cwe_raw))} &nbsp;|&nbsp; "
            f"OWASP: {_owasp_link(str(owasp_raw))}",
        ]

        if confidence and str(confidence) != "N/A":
            lines.append(f"**Confidence:** {confidence}")

        lines += [
            "",
            "<sub>Posted by [SentinelOps](https://github.com/ghost-security/platform) "
            "— Security Gate</sub>",
        ]
        return "\n".join(lines)

    def _format_comment_group(self, findings: List[dict]) -> str:
        """
        Render one or more findings that share the same (file, line) slot.

        If there is only one finding the result is identical to
        :meth:`_format_single_finding`.  For multiple findings on the same
        line they are rendered as distinct sections separated by a divider.
        """
        if len(findings) == 1:
            return self._format_single_finding(findings[0])

        parts: List[str] = [
            f"**SentinelOps: {len(findings)} findings on this line**",
            "",
        ]
        for i, f in enumerate(findings, 1):
            parts.append(f"---")
            parts.append(f"**Finding {i} of {len(findings)}**")
            parts.append("")
            parts.append(self._format_single_finding(f))
            parts.append("")

        return "\n".join(parts)

    # ── Summary comment body ───────────────────────────────────────────────────

    def _build_summary_body(
        self,
        findings: List[dict],
        owner: str,
        repo: str,
        pr_number: int,
    ) -> str:
        """
        Build a full PR-level Markdown summary comment.

        Includes:
          • Severity counts table
          • Link to inline comments note
          • Collapsible <details> table of all findings
        """
        counts: Dict[str, int] = defaultdict(int)
        for f in findings:
            sev = (f.get("severity") or "INFO").upper()
            counts[sev] += 1

        total = sum(counts.values())
        gate_icon = (
            "🔴" if counts.get("CRITICAL", 0) > 0
            else "🟠" if counts.get("HIGH", 0) > 0
            else "🟡" if counts.get("MEDIUM", 0) > 0
            else "✅"
        )

        repo_display = f"{owner}/{repo}"

        header_lines = [
            f"## {gate_icon} SentinelOps Security Scan — PR #{pr_number}",
            "",
            f"Scanned **{repo_display}** · **{total}** finding(s) detected.",
            "",
            "| Severity | Count |",
            "|:---------|------:|",
        ]
        for sev in _SEV_ORDER:
            c = counts.get(sev, 0)
            emoji = _SEV_EMOJI.get(sev, "⚪")
            header_lines.append(f"| {emoji} {sev} | {c} |")

        header_lines += [""]

        if total == 0:
            header_lines.append("✅ **No security issues found. Deployment gate: PASS.**")
            header_lines += [
                "",
                "<sub>_[SentinelOps](https://github.com/ghost-security/platform) "
                "— automated AppSec scanning_</sub>",
            ]
            return "\n".join(header_lines)

        # Collapsible table of all findings
        header_lines += [
            "<details>",
            "<summary><b>View all findings</b></summary>",
            "",
            "| # | Severity | Rule | File | Line | Description |",
            "|--:|:---------|:-----|:-----|-----:|:------------|",
        ]

        sorted_findings = sorted(
            findings,
            key=lambda x: _SEV_ORDER.index(x.get("severity", "INFO").upper())
            if x.get("severity", "INFO").upper() in _SEV_ORDER else 99,
        )

        for i, f in enumerate(sorted_findings, 1):
            sev     = (f.get("severity") or "INFO").upper()
            emoji   = _SEV_EMOJI.get(sev, "⚪")
            rule_id = f.get("rule_id") or f.get("id") or "N/A"
            fpath   = f.get("file", "N/A")
            lineno  = f.get("line", "N/A")
            desc    = (
                f.get("message") or f.get("description") or "Security finding"
            )
            # Truncate long descriptions for table readability
            desc_short = (desc[:100] + "…") if len(desc) > 100 else desc
            # Escape pipes in description to avoid breaking the table
            desc_short = desc_short.replace("|", "&#124;")
            header_lines.append(
                f"| {i} | {emoji} {sev} | `{rule_id}` | `{fpath}` | {lineno} | {desc_short} |"
            )

        header_lines += [
            "",
            "</details>",
            "",
        ]

        # Note about inline comments
        on_diff = sum(
            1 for f in findings
            if f.get("file") and int(f.get("line") or 0) > 0
        )
        header_lines += [
            f"> **ℹ️ Note:** {on_diff} finding(s) may have inline comments "
            "on the changed lines in this PR's **Files changed** tab.",
            "",
            "<sub>_[SentinelOps](https://github.com/ghost-security/platform) "
            "— automated AppSec scanning_</sub>",
        ]

        return "\n".join(header_lines)
