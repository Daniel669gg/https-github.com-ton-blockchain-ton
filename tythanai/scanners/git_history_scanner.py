"""
TythanAI — Git History Scanner v1.0

Scans git commit history for accidentally committed secrets.
Inspired by TruffleHog but with zero external dependencies — only
the standard library and a local git installation are required.

How it works:
    1. Retrieve up to `max_commits` commit hashes via `git log`.
    2. For each commit, fetch the diff of added lines via `git show`.
    3. Apply regex patterns for known secret formats to each added line.
    4. Redact matches and emit findings with commit metadata.

Usage:
    from scanners.git_history_scanner import GitHistoryScanner
    scanner = GitHistoryScanner("/path/to/repo", max_commits=500)
    report  = scanner.scan()
    for finding in report["findings"]:
        print(finding["message"])
"""
from __future__ import annotations

import re
import subprocess
import sys
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------

# Each entry: (secret_type_label, compiled_pattern, is_context_dependent)
# Context-dependent patterns require an assignment-style context (key=, secret=, etc.)
_SECRET_PATTERNS: List[Tuple[str, re.Pattern, bool]] = [
    (
        "AWS_ACCESS_KEY",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        False,
    ),
    (
        "GITHUB_TOKEN",
        re.compile(r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"),
        False,
    ),
    (
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
        False,
    ),
    (
        "STRIPE_KEY",
        re.compile(r"\b(sk_live_[0-9a-zA-Z]{24}|rk_live_[0-9a-zA-Z]{24})\b"),
        False,
    ),
    (
        "SLACK_WEBHOOK",
        re.compile(
            r"https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[A-Za-z0-9]{24}"
        ),
        False,
    ),
    (
        "JWT",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
        False,
    ),
    (
        "GOOGLE_API_KEY",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        False,
    ),
    (
        # Generic high-entropy secret — only flagged when found in an
        # assignment context such as: key=, password=, secret=, token=
        "HIGH_ENTROPY_SECRET",
        re.compile(r"[A-Za-z0-9+/]{40,}"),
        True,   # context-dependent
    ),
]

# Assignment-context pattern used to gate high-entropy matches
_CONTEXT_PATTERN = re.compile(
    r"(?:key|password|passwd|secret|token|api[_\-]?key|auth|credential|cred)"
    r"\s*[=:]\s*[\"']?",
    re.I,
)

# Directories to skip when examining filenames in diff output
_SKIP_PATH_PREFIXES = ("vendor/", "node_modules/", ".git/")

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _redact(value: str) -> str:
    """
    Redact a secret value, exposing only the first 4 and last 4 characters.
    For values shorter than 12 characters the whole string is replaced with ***.
    """
    if len(value) <= 12:
        return "***"
    return value[:4] + "***" + value[-4:]


def _is_skipped_path(filename: str) -> bool:
    """Return True if the filename is inside a vendored or generated directory."""
    for prefix in _SKIP_PATH_PREFIXES:
        if filename.startswith(prefix) or f"/{prefix}" in filename:
            return True
    return False


def _run_git(args: List[str], cwd: str, max_output_bytes: int = 0) -> Optional[str]:
    """
    Run a git subcommand and return stdout as a string.
    Returns None on any error.  If max_output_bytes > 0 and the output exceeds
    that limit the tail is silently truncated (safe for large diffs).
    """
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        raw = result.stdout
        if max_output_bytes and len(raw) > max_output_bytes:
            raw = raw[:max_output_bytes]
        return raw.decode("utf-8", errors="replace")
    except FileNotFoundError:
        # git binary not found
        raise
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class GitHistoryScanner:
    """
    Scans git commit history for accidentally committed secrets.

    Args:
        repo_path:      Path to the git repository root (default: current dir).
        max_commits:    Maximum number of commits to inspect (default: 200).
        max_diff_bytes: Maximum bytes to read from a single commit diff to
                        avoid memory issues on large initial commits (default: 500 000).
    """

    def __init__(
        self,
        repo_path: str = ".",
        max_commits: int = 200,
        max_diff_bytes: int = 500_000,
    ) -> None:
        self.repo_path     = repo_path
        self.max_commits   = max_commits
        self.max_diff_bytes = max_diff_bytes

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self) -> Dict:
        """
        Run the full git history scan.

        Returns:
            {
                "commits_scanned": int,
                "findings":        List[Dict],
                "total_findings":  int,
                "scanner":         "git_history",
            }

        If git is not installed or the path is not a repository the returned
        dict will contain an "error" key and an empty findings list.
        """
        try:
            commits = self._get_commits()
        except FileNotFoundError:
            return {
                "error":           "git not found",
                "findings":        [],
                "commits_scanned": 0,
                "total_findings":  0,
                "scanner":         "git_history",
            }
        except Exception as exc:
            return {
                "error":           f"git error: {exc}",
                "findings":        [],
                "commits_scanned": 0,
                "total_findings":  0,
                "scanner":         "git_history",
            }

        findings: List[Dict] = []
        seen: Set[Tuple[str, str]] = set()   # (pattern_label, commit_hash) dedup set

        for commit_hash in commits:
            commit_info = self._get_commit_info(commit_hash)
            diff        = self._get_diff(commit_hash)
            if not diff:
                continue
            for finding in self._scan_diff(diff, commit_hash, commit_info):
                dedup_key = (finding["secret_type"], commit_hash)
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append(finding)

        return {
            "commits_scanned": len(commits),
            "findings":        findings,
            "total_findings":  len(findings),
            "scanner":         "git_history",
        }

    # ── Git interaction ───────────────────────────────────────────────────────

    def _get_commits(self) -> List[str]:
        """
        Return up to max_commits commit hashes from the full git history
        (all branches, including remotes).

        Raises FileNotFoundError if git is not installed.
        """
        output = _run_git(
            ["log", "--all", "--format=%H", f"--max-count={self.max_commits}"],
            cwd=self.repo_path,
        )
        if output is None:
            return []
        return [line.strip() for line in output.splitlines() if line.strip()]

    def _get_diff(self, commit_hash: str) -> str:
        """
        Return only the added lines (+) from the diff of a single commit.
        Lines starting with +++ (file header) are excluded.
        The output is limited to max_diff_bytes to protect against huge diffs.
        """
        raw = _run_git(
            ["show", "--unified=0", commit_hash, "--"],
            cwd=self.repo_path,
            max_output_bytes=self.max_diff_bytes,
        )
        if not raw:
            return ""
        # Keep only lines that start with + and are not the +++ file header
        added_lines = [
            line for line in raw.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]
        return "\n".join(added_lines)

    def _get_commit_info(self, commit_hash: str) -> Dict:
        """
        Return author name, email, date and subject for a commit.

        Returns an empty dict if the commit metadata cannot be retrieved.
        """
        output = _run_git(
            ["log", "-1", "--format=%an|%ae|%ai|%s", commit_hash],
            cwd=self.repo_path,
        )
        if not output:
            return {"author": "unknown", "email": "", "date": "", "subject": ""}
        parts = output.strip().split("|", 3)
        return {
            "author":  parts[0] if len(parts) > 0 else "unknown",
            "email":   parts[1] if len(parts) > 1 else "",
            "date":    parts[2] if len(parts) > 2 else "",
            "subject": parts[3] if len(parts) > 3 else "",
        }

    # ── Diff scanning ─────────────────────────────────────────────────────────

    def _scan_diff(
        self, diff: str, commit_hash: str, commit_info: Dict
    ) -> List[Dict]:
        """
        Scan the added lines of a diff for secret patterns.

        Returns a list of findings (may contain duplicates by pattern/commit;
        deduplication is done by the caller).
        """
        findings: List[Dict] = []
        current_file = ""

        for line in diff.splitlines():
            # Track current file from diff header lines like: diff --git a/foo b/foo
            if line.startswith("diff --git "):
                m = re.search(r" b/(.+)$", line)
                if m:
                    current_file = m.group(1)
                continue

            if _is_skipped_path(current_file):
                continue

            # line starts with + (guaranteed by _get_diff, but double-check)
            content = line[1:] if line.startswith("+") else line

            for secret_type, pattern, context_dependent in _SECRET_PATTERNS:
                if context_dependent:
                    # Only match if the line has an assignment-style context
                    if not _CONTEXT_PATTERN.search(content):
                        continue

                for match in pattern.finditer(content):
                    matched_value = match.group(0)
                    findings.append(
                        self._make_finding(
                            secret_type=secret_type,
                            matched_value=matched_value,
                            commit_hash=commit_hash,
                            commit_info=commit_info,
                            filename=current_file,
                            line_content=content,
                        )
                    )

        return findings

    # ── Finding builder ───────────────────────────────────────────────────────

    def _make_finding(
        self,
        secret_type: str,
        matched_value: str,
        commit_hash: str,
        commit_info: Dict,
        filename: str,
        line_content: str,
    ) -> Dict:
        """Construct a Ghost-format finding dict for an exposed secret."""
        author   = commit_info.get("author", "unknown")
        email    = commit_info.get("email", "")
        date     = commit_info.get("date", "")
        subject  = commit_info.get("subject", "")
        redacted = _redact(matched_value)

        # Human-readable secret type label
        type_label = secret_type.replace("_", " ").title()

        return {
            "type":        "GIT_SECRET",
            "id":          f"GIT-SECRET-{secret_type}",
            "severity":    "CRITICAL",
            "cwe":         "CWE-798",
            "file":        f"{commit_hash[:8]}:{filename}",
            "line":        0,
            "message":     (
                f"Secret found in git history: commit {commit_hash[:8]} by {author}"
            ),
            "description": (
                f"A {type_label} was detected in the added lines of commit "
                f"{commit_hash[:8]} ({subject!r}). Secrets committed to version "
                "control history remain accessible even after deletion from HEAD "
                "because the git object database retains them indefinitely."
            ),
            "evidence":    redacted,
            "recommendation": (
                "Rotate the exposed credential immediately. "
                "Use git-filter-repo to purge the secret from history, then "
                "force-push to all remotes and invalidate any forks or clones."
            ),
            "source":         "git_history_scanner",
            "scanner":        "git_history",
            "confidence":     90,
            "commit_hash":    commit_hash,
            "commit_date":    date,
            "commit_author":  author,
            "commit_email":   email,
            "commit_subject": subject,
            "secret_type":    secret_type,
            "filename":       filename,
        }
