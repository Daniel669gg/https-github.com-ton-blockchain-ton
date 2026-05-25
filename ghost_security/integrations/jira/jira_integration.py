"""
Ghost Security — Jira REST API v3 Integration
Creates Jira issues from security findings.
Authentication: Basic auth (base64 email:api_token).
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
    base_url: str = ""
    email: str = ""
    api_token: str = ""
    project_key: str = ""
    issue_type: str = "Bug"
    labels: List[str] = field(default_factory=lambda: ["ghost-security", "security"])
    priority_map: Dict[str, str] = field(default_factory=lambda: {
        "CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium",
        "LOW": "Low", "INFO": "Lowest",
    })

    @classmethod
    def from_env(cls) -> "JiraConfig":
        return cls(
            base_url=os.getenv("JIRA_BASE_URL", ""),
            email=os.getenv("JIRA_EMAIL", ""),
            api_token=os.getenv("JIRA_API_TOKEN", ""),
            project_key=os.getenv("JIRA_PROJECT_KEY", ""),
        )


class JiraIntegration:
    def __init__(self, config: Optional[JiraConfig] = None) -> None:
        if config is None:
            config = JiraConfig.from_env()
        self.config = config
        self._auth_header = self._make_auth_header()

    def is_configured(self) -> bool:
        cfg = self.config
        return bool(cfg.base_url and cfg.email and cfg.api_token and cfg.project_key)

    def test_connection(self) -> dict:
        if not self.is_configured():
            return {"ok": False, "error": "Jira not configured"}
        url = f"{self.config.base_url.rstrip('/')}/rest/api/3/myself"
        try:
            data = self._get(url)
            return {"ok": True, "user": data.get("displayName", ""), "account_id": data.get("accountId", "")}
        except urllib.error.HTTPError as exc:
            msg = f"HTTP {exc.code}"
            if exc.code in (401, 403):
                msg = f"Authentication failed (HTTP {exc.code})"
            return {"ok": False, "error": msg}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def create_issue(self, finding: dict) -> dict:
        if not self.is_configured():
            raise RuntimeError("Jira not configured")
        url = f"{self.config.base_url.rstrip('/')}/rest/api/3/issue"
        payload = self._build_issue_payload(finding)
        result = self._post(url, payload)
        key = result.get("key", "")
        return {"key": key, "id": result.get("id", ""), "url": f"{self.config.base_url.rstrip('/')}/browse/{key}"}

    def create_issues_batch(self, findings: List[dict], max_issues: int = 50, min_severity: str = "MEDIUM") -> List[dict]:
        if not self.is_configured():
            raise RuntimeError("Jira not configured")
        min_idx = _SEV_ORDER.index(min_severity) if min_severity in _SEV_ORDER else 2
        filtered = [f for f in findings if _SEV_ORDER.index(f.get("severity", "MEDIUM")) >= min_idx]
        seen: set = set()
        deduped: List[dict] = []
        for f in filtered:
            key = (f.get("rule_id", ""), f.get("file", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(f)
        deduped.sort(key=lambda f: _SEV_ORDER.index(f.get("severity", "MEDIUM")), reverse=True)
        deduped = deduped[:max_issues]
        created: List[dict] = []
        for i, finding in enumerate(deduped):
            if i > 0:
                time.sleep(0.5)
            try:
                result = self.create_issue(finding)
                created.append(result)
            except Exception as exc:
                created.append({"error": str(exc), "finding": finding.get("rule_id", "")})
        return created

    @classmethod
    def from_env(cls) -> "JiraIntegration":
        return cls(JiraConfig.from_env())

    def _finding_to_adf(self, finding: dict) -> dict:
        severity  = finding.get("severity", "MEDIUM")
        rule_id   = finding.get("rule_id", finding.get("id", "UNKNOWN"))
        file_path = finding.get("file", "unknown")
        line      = finding.get("line", "")
        cwe       = finding.get("cwe", "")
        message   = finding.get("message", finding.get("description", ""))
        evidence  = finding.get("evidence", finding.get("code", finding.get("snippet", "")))
        recommendation = finding.get("recommendation", finding.get("fix", "Review and remediate."))

        def _text(t, bold=False):
            node = {"type": "text", "text": t}
            if bold:
                node["marks"] = [{"type": "strong"}]
            return node

        def _paragraph(*children):
            return {"type": "paragraph", "content": list(children)}

        def _heading(level, text):
            return {"type": "heading", "attrs": {"level": level}, "content": [_text(text, bold=True)]}

        def _table_row(cells, is_header=False):
            cell_type = "tableHeader" if is_header else "tableCell"
            return {"type": "tableRow", "content": [{"type": cell_type, "content": [_paragraph(_text(str(c)))]} for c in cells]}

        table = {"type": "table", "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
                 "content": [_table_row(["Field", "Value"], is_header=True),
                              _table_row(["Severity", severity]), _table_row(["Rule ID", rule_id]),
                              _table_row(["File", file_path]), _table_row(["Line", str(line) if line else "—"]),
                              _table_row(["CWE", cwe if cwe else "—"])]}

        content_nodes = [_heading(2, "Finding Details"), table]
        if evidence:
            content_nodes += [_heading(2, "Evidence"),
                               {"type": "codeBlock", "attrs": {"language": ""}, "content": [_text(str(evidence))]}]
        content_nodes += [_heading(2, "Recommendation"), _paragraph(_text(str(recommendation))),
                          _heading(2, "Description"), _paragraph(_text(str(message)))]
        return {"type": "doc", "version": 1, "content": content_nodes}

    def _build_issue_title(self, finding: dict) -> str:
        severity = finding.get("severity", "MEDIUM")
        rule_id  = finding.get("rule_id", finding.get("id", "UNKNOWN"))
        message  = finding.get("message", finding.get("description", "Security finding"))
        return f"[GHOST] {severity} — {rule_id}: {message[:80].rstrip()}"

    def _build_issue_payload(self, finding: dict) -> dict:
        cfg      = self.config
        severity = finding.get("severity", "MEDIUM")
        priority = cfg.priority_map.get(severity, "Medium")
        return {"fields": {"project": {"key": cfg.project_key}, "issuetype": {"name": cfg.issue_type},
                            "summary": self._build_issue_title(finding),
                            "description": self._finding_to_adf(finding),
                            "labels": cfg.labels, "priority": {"name": priority}}}

    def _make_auth_header(self) -> str:
        if not self.config.email or not self.config.api_token:
            return ""
        raw = f"{self.config.email}:{self.config.api_token}"
        return "Basic " + base64.b64encode(raw.encode()).decode()

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
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
