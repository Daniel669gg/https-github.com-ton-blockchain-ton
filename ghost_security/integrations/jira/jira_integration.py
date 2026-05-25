"""
Ghost Security — Jira REST API v3 Integration

Creates Jira issues from security findings using the Jira Cloud REST API v3.
Authentication: Basic auth (base64 email:api_token).

Usage:
    from integrations.jira.jira_integration import JiraIntegration, JiraConfig

    # Auto-load from env vars
    jira = JiraIntegration.from_env()

    # Explicit config
    cfg = JiraConfig(
        base_url="https://company.atlassian.net",
        email="user@company.com",
        api_token="your-api-token",
        project_key="SEC",
    )
    jira = JiraIntegration(cfg)
    result = jira.create_issue(finding)
    print(result["key"])   # e.g. "SEC-123"
"""
from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional


_SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class JiraConfig:
    """Configuration for the Jira integration."""

    base_url: str = ""          # e.g. "https://company.atlassian.net"
    email: str = ""
    api_token: str = ""         # Jira API token (not password)
    project_key: str = ""       # e.g. "SEC"
    issue_type: str = "Bug"
    labels: List[str] = field(default_factory=lambda: ["ghost-security", "security"])
    priority_map: Dict[str, str] = field(default_factory=lambda: {
        "CRITICAL": "Highest",
        "HIGH":     "High",
        "MEDIUM":   "Medium",
        "LOW":      "Low",
        "INFO":     "Lowest",
    })

    @classmethod
    def from_env(cls) -> "JiraConfig":
        """Load config from environment variables."""
        return cls(
            base_url=os.getenv("JIRA_BASE_URL", ""),
            email=os.getenv("JIRA_EMAIL", ""),
            api_token=os.getenv("JIRA_API_TOKEN", ""),
            project_key=os.getenv("JIRA_PROJECT_KEY", ""),
        )


class JiraIntegration:
    """Real Jira REST API v3 integration for Ghost Security findings."""

    def __init__(self, config: Optional[JiraConfig] = None) -> None:
        if config is None:
            config = JiraConfig.from_env()
        self.config = config
        self._auth_header = self._make_auth_header()

    # ── Public API ─────────────────────────────────────────────────────────────

    def is_configured(self) -> bool:
        """Return True if all required configuration fields are present."""
        cfg = self.config
        return bool(cfg.base_url and cfg.email and cfg.api_token and cfg.project_key)

    def test_connection(self) -> dict:
        """
        GET /rest/api/3/myself — verify credentials.

        Returns:
            {"ok": True,  "user": "...", "account_id": "..."}
            {"ok": False, "error": "..."}
        """
        if not self.is_configured():
            return {"ok": False, "error": "Jira not configured — set JIRA_BASE_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY"}
        url = f"{self.config.base_url.rstrip('/')}/rest/api/3/myself"
        try:
            data = self._get(url)
            return {
                "ok": True,
                "user": data.get("displayName", ""),
                "account_id": data.get("accountId", ""),
            }
        except urllib.error.HTTPError as exc:
            msg = f"HTTP {exc.code}"
            if exc.code in (401, 403):
                msg = f"Authentication failed (HTTP {exc.code}) — check JIRA_EMAIL and JIRA_API_TOKEN"
            return {"ok": False, "error": msg}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}

    def create_issue(self, finding: dict) -> dict:
        """
        POST /rest/api/3/issue — create a Jira issue from a security finding.

        Returns:
            {"key": "SEC-123", "id": "...", "url": "..."}
        """
        if not self.is_configured():
            raise RuntimeError("Jira not configured — call is_configured() first")

        url = f"{self.config.base_url.rstrip('/')}/rest/api/3/issue"
        payload = self._build_issue_payload(finding)
        result = self._post(url, payload)
        key = result.get("key", "")
        return {
            "key":  key,
            "id":   result.get("id", ""),
            "url":  f"{self.config.base_url.rstrip('/')}/browse/{key}",
        }

    def create_issues_batch(
        self,
        findings: List[dict],
        max_issues: int = 50,
        min_severity: str = "MEDIUM",
    ) -> List[dict]:
        """
        Create Jira issues for findings at or above *min_severity*.

        - Deduplicates by (rule_id, file) to avoid spam.
        - Rate-limits to 2 requests/second.
        - Returns list of created issue dicts from create_issue().
        """
        if not self.is_configured():
            raise RuntimeError("Jira not configured")

        min_idx = _SEV_ORDER.index(min_severity) if min_severity in _SEV_ORDER else 2
        filtered = [
            f for f in findings
            if _SEV_ORDER.index(f.get("severity", "MEDIUM")) >= min_idx
        ]

        # Deduplicate by (rule_id, file)
        seen: set = set()
        deduped: List[dict] = []
        for f in filtered:
            key = (f.get("rule_id", ""), f.get("file", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        # Sort by severity descending and cap at max_issues
        deduped.sort(
            key=lambda f: _SEV_ORDER.index(f.get("severity", "MEDIUM")),
            reverse=True,
        )
        deduped = deduped[:max_issues]

        created: List[dict] = []
        for i, finding in enumerate(deduped):
            if i > 0:
                time.sleep(0.5)  # 2 req/sec rate limit
            try:
                result = self.create_issue(finding)
                created.append(result)
            except Exception as exc:  # noqa: BLE001
                created.append({"error": str(exc), "finding": finding.get("rule_id", "")})

        return created

    def get_existing_issues(self, rule_id: Optional[str] = None) -> List[dict]:
        """
        GET /rest/api/3/search?jql=... — return simplified list of existing Ghost issues.

        Returns:
            [{"key": "SEC-123", "summary": "...", "status": "Open"}, ...]
        """
        if not self.is_configured():
            raise RuntimeError("Jira not configured")

        jql_parts = [f"project={self.config.project_key}", 'labels="ghost-security"']
        if rule_id:
            # escape double quotes for JQL
            escaped = rule_id.replace('"', '\\"')
            jql_parts.append(f'summary ~ "{escaped}"')
        jql = " AND ".join(jql_parts)

        params = urllib.parse.urlencode({"jql": jql, "maxResults": 200, "fields": "summary,status"})
        url = f"{self.config.base_url.rstrip('/')}/rest/api/3/search?{params}"
        data = self._get(url)

        issues = []
        for issue in data.get("issues", []):
            fields = issue.get("fields", {})
            status_obj = fields.get("status", {})
            issues.append({
                "key":     issue.get("key", ""),
                "summary": fields.get("summary", ""),
                "status":  status_obj.get("name", ""),
            })
        return issues

    @classmethod
    def from_env(cls) -> "JiraIntegration":
        """Create a JiraIntegration instance with config loaded from environment variables."""
        return cls(JiraConfig.from_env())

    # ── ADF builder ────────────────────────────────────────────────────────────

    def _finding_to_adf(self, finding: dict) -> dict:
        """
        Convert a Ghost finding dict to Atlassian Document Format (ADF).

        https://developer.atlassian.com/cloud/jira/platform/apis/document/structure/
        """
        severity  = finding.get("severity", "MEDIUM")
        rule_id   = finding.get("rule_id",   finding.get("id", "UNKNOWN"))
        file_path = finding.get("file",      "unknown")
        line      = finding.get("line",      "")
        cwe       = finding.get("cwe",       "")
        message   = finding.get("message",   finding.get("description", ""))
        evidence  = finding.get("evidence",  finding.get("code",
                    finding.get("snippet", "")))
        recommendation = finding.get("recommendation",
                         finding.get("fix", "Review and remediate the identified vulnerability."))

        def _text(t: str, bold: bool = False) -> dict:
            node: dict = {"type": "text", "text": t}
            if bold:
                node["marks"] = [{"type": "strong"}]
            return node

        def _paragraph(*children) -> dict:
            return {"type": "paragraph", "content": list(children)}

        def _heading(level: int, text: str) -> dict:
            return {
                "type":    "heading",
                "attrs":   {"level": level},
                "content": [_text(text, bold=True)],
            }

        def _table_row(cells: list, is_header: bool = False) -> dict:
            cell_type = "tableHeader" if is_header else "tableCell"
            return {
                "type":    "tableRow",
                "content": [
                    {
                        "type":    cell_type,
                        "content": [_paragraph(_text(str(c)))],
                    }
                    for c in cells
                ],
            }

        # Finding details table
        table: dict = {
            "type":  "table",
            "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
            "content": [
                _table_row(["Field", "Value"], is_header=True),
                _table_row(["Severity",  severity]),
                _table_row(["Rule ID",   rule_id]),
                _table_row(["File",      file_path]),
                _table_row(["Line",      str(line) if line else "—"]),
                _table_row(["CWE",       cwe if cwe else "—"]),
            ],
        }

        content_nodes: list = [
            _heading(2, "Finding Details"),
            table,
        ]

        if evidence:
            content_nodes += [
                _heading(2, "Evidence"),
                {
                    "type":  "codeBlock",
                    "attrs": {"language": ""},
                    "content": [_text(str(evidence))],
                },
            ]

        content_nodes += [
            _heading(2, "Recommendation"),
            _paragraph(_text(str(recommendation))),
            _heading(2, "Description"),
            _paragraph(_text(str(message))),
        ]

        return {
            "type":    "doc",
            "version": 1,
            "content": content_nodes,
        }

    # ── Issue payload builder ───────────────────────────────────────────────────

    def _build_issue_title(self, finding: dict) -> str:
        """Build issue title in format: [GHOST] {severity} — {rule_id}: {short_message}"""
        severity = finding.get("severity", "MEDIUM")
        rule_id  = finding.get("rule_id", finding.get("id", "UNKNOWN"))
        message  = finding.get("message", finding.get("description", "Security finding"))
        short_msg = message[:80].rstrip()
        return f"[GHOST] {severity} — {rule_id}: {short_msg}"

    def _build_issue_payload(self, finding: dict) -> dict:
        """Build the full Jira issue creation payload."""
        cfg      = self.config
        severity = finding.get("severity", "MEDIUM")
        priority = cfg.priority_map.get(severity, "Medium")

        return {
            "fields": {
                "project":     {"key": cfg.project_key},
                "issuetype":   {"name": cfg.issue_type},
                "summary":     self._build_issue_title(finding),
                "description": self._finding_to_adf(finding),
                "labels":      cfg.labels,
                "priority":    {"name": priority},
            }
        }

    # ── HTTP helpers ────────────────────────────────────────────────────────────

    def _make_auth_header(self) -> str:
        """Return Basic auth header value (base64 email:api_token)."""
        if not self.config.email or not self.config.api_token:
            return ""
        raw = f"{self.config.email}:{self.config.api_token}"
        return "Basic " + base64.b64encode(raw.encode()).decode()

    def _headers(self) -> dict:
        h = {
            "Content-Type":  "application/json",
            "Accept":        "application/json",
        }
        if self._auth_header:
            h["Authorization"] = self._auth_header
        return h

    def _get(self, url: str) -> dict:
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())

    def _post(self, url: str, payload: dict) -> dict:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(url, data=data, headers=self._headers(), method="POST")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
