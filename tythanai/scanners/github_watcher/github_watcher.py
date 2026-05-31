"""
TythanAI Platform — GitHub Watcher
Real GitHub API integration for monitoring commits and detecting security issues.
No placeholders. Real API calls with real analysis.
"""
import json
import time
import hashlib
import re
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from datetime import datetime, timezone
import urllib.request
import urllib.error
import urllib.parse

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from config.config import GITHUB_TOKEN, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW


class GitHubWatcher:
    """
    Real GitHub API watcher.
    Monitors repositories for security-relevant commits, exposed secrets,
    and dangerous code changes.
    """

    BASE_URL = "https://api.github.com"

    # Patterns that indicate security-relevant changes
    SECURITY_PATTERNS = [
        (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', SEVERITY_CRITICAL, "Hardcoded password"),
        (r'AKIA[0-9A-Z]{16}', SEVERITY_CRITICAL, "AWS Access Key"),
        (r'(?i)(secret|api_key|token)\s*=\s*["\'][^"\']{8,}["\']', SEVERITY_CRITICAL, "Hardcoded secret"),
        (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', SEVERITY_CRITICAL, "Private key"),
        (r'ghp_[A-Za-z0-9]{36}', SEVERITY_CRITICAL, "GitHub PAT"),
        (r'(?i)eval\s*\(.*\$', SEVERITY_HIGH, "Dynamic eval"),
        (r'(?i)exec\s*\(.*\$', SEVERITY_HIGH, "Dynamic exec"),
        (r'(?i)shell\s*=\s*True', SEVERITY_HIGH, "Shell injection risk"),
        (r'(?i)DROP\s+TABLE', SEVERITY_HIGH, "SQL DROP TABLE"),
        (r'(?i)DELETE\s+FROM.*WHERE\s+1=1', SEVERITY_CRITICAL, "SQL DELETE all rows"),
        (r'(?i)chmod\s+777', SEVERITY_HIGH, "Insecure permissions"),
        (r'(?i)disable.*ssl.*verify', SEVERITY_HIGH, "SSL verification disabled"),
        (r'(?i)verify\s*=\s*False', SEVERITY_HIGH, "SSL verification disabled"),
        (r'(?i)DEBUG\s*=\s*True', SEVERITY_MEDIUM, "Debug mode enabled"),
        (r'(?i)allow_all_origins\s*=\s*True', SEVERITY_MEDIUM, "CORS allow all origins"),
    ]

    def __init__(self):
        self.token = GITHUB_TOKEN
        self._seen_commits: Dict[str, set] = {}  # repo -> set of seen SHAs

    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Tuple[Optional[Dict], Optional[str]]:
        """Make authenticated GitHub API request."""
        url = f"{self.BASE_URL}/{endpoint.lstrip('/')}"
        if params:
            url += "?" + urllib.parse.urlencode(params)

        req = urllib.request.Request(url)
        req.add_header("Accept", "application/vnd.github.v3+json")
        req.add_header("User-Agent", "Ghost-Security-Platform/1.0")
        if self.token:
            req.add_header("Authorization", f"token {self.token}")

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                return data, None
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8', errors='replace')[:500]
            return None, f"HTTP {e.code}: {error_body}"
        except Exception as e:
            return None, str(e)

    def get_repo_info(self, owner: str, repo: str) -> Dict:
        """Get repository information."""
        data, error = self._make_request(f"repos/{owner}/{repo}")
        if error:
            return {"error": error}
        return {
            "name": data.get("full_name"),
            "description": data.get("description"),
            "stars": data.get("stargazers_count"),
            "forks": data.get("forks_count"),
            "language": data.get("language"),
            "open_issues": data.get("open_issues_count"),
            "private": data.get("private"),
            "default_branch": data.get("default_branch"),
            "created_at": data.get("created_at"),
            "updated_at": data.get("updated_at"),
            "topics": data.get("topics", []),
            "license": data.get("license", {}).get("name") if data.get("license") else None
        }

    def get_commits(self, owner: str, repo: str, branch: str = "main",
                    since: Optional[str] = None, per_page: int = 10) -> List[Dict]:
        """Get recent commits from repository."""
        params = {"sha": branch, "per_page": per_page}
        if since:
            params["since"] = since

        data, error = self._make_request(f"repos/{owner}/{repo}/commits", params)
        if error or not isinstance(data, list):
            return []

        commits = []
        for commit in data:
            commits.append({
                "sha": commit.get("sha", "")[:12],
                "full_sha": commit.get("sha", ""),
                "message": commit.get("commit", {}).get("message", ""),
                "author": commit.get("commit", {}).get("author", {}).get("name", ""),
                "email": commit.get("commit", {}).get("author", {}).get("email", ""),
                "date": commit.get("commit", {}).get("author", {}).get("date", ""),
                "url": commit.get("html_url", "")
            })
        return commits

    def get_commit_diff(self, owner: str, repo: str, sha: str) -> Optional[str]:
        """Get the diff for a specific commit."""
        req_url = f"{self.BASE_URL}/repos/{owner}/{repo}/commits/{sha}"
        req = urllib.request.Request(req_url)
        req.add_header("Accept", "application/vnd.github.v3.diff")
        req.add_header("User-Agent", "Ghost-Security-Platform/1.0")
        if self.token:
            req.add_header("Authorization", f"token {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read().decode('utf-8', errors='replace')[:50000]
        except Exception:
            return None

    def analyze_commit(self, owner: str, repo: str, sha: str) -> Dict:
        """Analyze a commit for security issues."""
        diff = self.get_commit_diff(owner, repo, sha)
        if not diff:
            return {"sha": sha, "findings": [], "error": "Could not fetch diff"}

        findings = []
        lines = diff.split('\n')
        current_file = ""

        for i, line in enumerate(lines, 1):
            # Track current file
            if line.startswith('+++ b/'):
                current_file = line[6:].strip()
                continue
            # Only analyze added lines
            if not line.startswith('+') or line.startswith('+++'):
                continue

            added_line = line[1:]  # Remove the '+' prefix
            for pattern, severity, desc in self.SECURITY_PATTERNS:
                if re.search(pattern, added_line):
                    findings.append({
                        "type": "Security Issue in Commit",
                        "severity": severity,
                        "file": current_file,
                        "line": i,
                        "description": f"{desc} detected in commit {sha[:8]}",
                        "evidence": added_line.strip()[:200],
                        "recommendation": "Review and remove this security issue before merging",
                        "sha": sha,
                        "source": "github_watcher"
                    })

        return {
            "sha": sha[:12],
            "findings": findings,
            "finding_count": len(findings),
            "analyzed_lines": len([l for l in lines if l.startswith('+') and not l.startswith('+++')])
        }

    def watch_repository(self, owner: str, repo: str, branch: str = "main",
                         max_commits: int = 5) -> Dict:
        """
        Watch a repository for new security issues.
        Analyzes recent commits and returns all findings.
        """
        repo_key = f"{owner}/{repo}"

        # Get repo info
        repo_info = self.get_repo_info(owner, repo)
        if "error" in repo_info:
            return {"error": repo_info["error"], "repo": repo_key}

        # Get recent commits
        commits = self.get_commits(owner, repo, branch, per_page=max_commits)
        if not commits:
            return {"error": "No commits found or API error", "repo": repo_key}

        # Find new commits
        seen = self._seen_commits.get(repo_key, set())
        new_commits = [c for c in commits if c["full_sha"] not in seen]

        all_findings = []
        analyzed_commits = []

        for commit in new_commits[:max_commits]:
            analysis = self.analyze_commit(owner, repo, commit["full_sha"])
            analyzed_commits.append({
                **commit,
                "findings": analysis.get("findings", []),
                "finding_count": analysis.get("finding_count", 0)
            })
            all_findings.extend(analysis.get("findings", []))
            # Mark as seen
            seen.add(commit["full_sha"])

        self._seen_commits[repo_key] = seen

        return {
            "repo": repo_key,
            "repo_info": repo_info,
            "branch": branch,
            "total_commits_checked": len(new_commits),
            "commits": analyzed_commits,
            "total_findings": len(all_findings),
            "findings": all_findings,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def search_exposed_secrets(self, owner: str, repo: str) -> Dict:
        """Search repository for exposed secrets using GitHub code search."""
        # Use GitHub search API to find potential secrets
        secret_queries = [
            f"repo:{owner}/{repo} password=",
            f"repo:{owner}/{repo} api_key=",
            f"repo:{owner}/{repo} secret=",
        ]

        findings = []
        for query in secret_queries:
            params = {"q": query, "per_page": 5}
            data, error = self._make_request("search/code", params)
            if error or not data:
                continue

            for item in data.get("items", []):
                findings.append({
                    "type": "Potential Exposed Secret",
                    "severity": SEVERITY_HIGH,
                    "file": item.get("path", ""),
                    "description": f"Search match for '{query.split()[-1]}' in {item.get('path', '')}",
                    "evidence": item.get("name", ""),
                    "url": item.get("html_url", ""),
                    "recommendation": "Review file for hardcoded credentials",
                    "source": "github_search"
                })
            time.sleep(0.5)  # Rate limiting

        return {
            "repo": f"{owner}/{repo}",
            "findings": findings,
            "total_findings": len(findings)
        }

    def get_security_advisories(self, owner: str, repo: str) -> List[Dict]:
        """Get known security advisories for the repository."""
        data, error = self._make_request(f"repos/{owner}/{repo}/vulnerability-alerts")
        if error:
            # Try dependabot alerts
            data, error = self._make_request(f"repos/{owner}/{repo}/dependabot/alerts")
            if error or not isinstance(data, list):
                return []

        advisories = []
        if isinstance(data, list):
            for alert in data[:20]:
                advisory = alert.get("security_advisory", alert.get("security_vulnerability", {}))
                advisories.append({
                    "type": "Known Vulnerability",
                    "severity": self._map_advisory_severity(
                        advisory.get("severity", alert.get("severity", "medium"))
                    ),
                    "description": advisory.get("summary", advisory.get("description", "")),
                    "package": alert.get("dependency", {}).get("package", {}).get("name", ""),
                    "cve": advisory.get("cve_id", ""),
                    "source": "github_advisories"
                })
        return advisories

    def _map_advisory_severity(self, severity: str) -> str:
        """Map GitHub advisory severity to our levels."""
        mapping = {
            "critical": SEVERITY_CRITICAL,
            "high": SEVERITY_HIGH,
            "medium": SEVERITY_MEDIUM,
            "low": SEVERITY_LOW,
            "moderate": SEVERITY_MEDIUM
        }
        return mapping.get(severity.lower(), SEVERITY_MEDIUM)
