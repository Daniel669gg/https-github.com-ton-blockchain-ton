"""
Ghost Security Platform — Slack Webhook + Bot API Integration
Sends security finding alerts and scan summaries to Slack.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional

_SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_SEV_EMOJI = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "🔶", "LOW": "🔵", "INFO": "ℹ️"}
_SEV_COLOR = {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "#ffcc00", "LOW": "good", "INFO": "#cccccc"}


@dataclass
class SlackConfig:
    webhook_url: str = ""
    bot_token: str = ""
    channel: str = "#security"
    min_severity: str = "HIGH"
    mention_on_critical: str = "@channel"

    @classmethod
    def from_env(cls) -> "SlackConfig":
        return cls(
            webhook_url=os.getenv("SLACK_WEBHOOK_URL", ""),
            bot_token=os.getenv("SLACK_BOT_TOKEN", ""),
            channel=os.getenv("SLACK_CHANNEL", "#security"),
            min_severity=os.getenv("SLACK_MIN_SEVERITY", "HIGH"),
            mention_on_critical=os.getenv("SLACK_MENTION_CRITICAL", "@channel"),
        )


class SlackNotifier:
    def __init__(self, config: Optional[SlackConfig] = None) -> None:
        if config is None:
            config = SlackConfig.from_env()
        self.config = config

    def is_configured(self) -> bool:
        return bool(self.config.webhook_url or (self.config.bot_token and self.config.channel))

    def send_finding(self, finding: dict) -> bool:
        severity = finding.get("severity", "MEDIUM")
        if not self._above_min_severity(severity):
            return False
        blocks = self._finding_blocks(finding)
        payload = {"blocks": blocks, "text": self._finding_fallback_text(finding)}
        if not self.config.webhook_url and self.config.bot_token:
            payload["channel"] = self.config.channel
        return self._deliver(payload)

    def send_scan_summary(self, findings: List[dict], scan_path: str, duration: float) -> bool:
        counts: dict = {}
        for f in findings:
            s = f.get("severity", "MEDIUM")
            counts[s] = counts.get(s, 0) + 1
        total = len(findings)
        crits = counts.get("CRITICAL", 0)
        highs = counts.get("HIGH", 0)
        color = "danger" if crits else ("warning" if highs else "good")
        parts = [f"{_SEV_EMOJI.get(sev, '')} {sev}: {n}" for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if (n := counts.get(sev, 0))]
        counts_text = "  |  ".join(parts) if parts else "No findings"
        top = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")][:3]
        top_lines = [f"{_SEV_EMOJI.get(f.get('severity',''), '')} *{f.get('rule_id', f.get('id', 'unknown'))}* — {(f.get('message') or f.get('description', ''))[:60]}  `{f.get('file', '')}:{f.get('line', '')}`" for f in top]
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"👻 Ghost Security Scan Complete — {scan_path}", "emoji": True}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Total findings:* {total}"},
                {"type": "mrkdwn", "text": f"*Duration:* {duration:.2f}s"},
                {"type": "mrkdwn", "text": f"*Path:* `{scan_path}`"},
                {"type": "mrkdwn", "text": f"*Severity breakdown:*\n{counts_text}"},
            ]},
        ]
        if top_lines:
            blocks += [{"type": "divider"}, {"type": "section", "text": {"type": "mrkdwn", "text": "*Top critical/high findings:*\n" + "\n".join(top_lines)}}]
        payload: dict = {"text": f"Ghost scan complete: {total} findings in {scan_path}", "attachments": [{"color": color, "blocks": blocks}]}
        if not self.config.webhook_url and self.config.bot_token:
            payload["channel"] = self.config.channel
        return self._deliver(payload)

    def test(self) -> bool:
        payload: dict = {"text": "👻 Ghost Security — test message.", "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "👻 *Ghost Security* — test message. Integration working correctly."}}]}
        if not self.config.webhook_url and self.config.bot_token:
            payload["channel"] = self.config.channel
        return self._deliver(payload)

    def send_alert(self, title: str, message: str, severity: str = "HIGH") -> bool:
        emoji = _SEV_EMOJI.get(severity, "⚠️")
        blocks = [{"type": "header", "text": {"type": "plain_text", "text": f"{emoji} {title}", "emoji": True}},
                  {"type": "section", "text": {"type": "mrkdwn", "text": message}}]
        payload: dict = {"text": f"{emoji} {title}: {message}", "blocks": blocks}
        if not self.config.webhook_url and self.config.bot_token:
            payload["channel"] = self.config.channel
        return self._deliver(payload)

    def _finding_blocks(self, finding: dict) -> list:
        severity = finding.get("severity", "MEDIUM")
        rule_id  = finding.get("rule_id", finding.get("id", "UNKNOWN"))
        message  = (finding.get("message") or finding.get("description", ""))[:120]
        file_    = finding.get("file", "unknown")
        line     = finding.get("line", "")
        cwe      = finding.get("cwe", "")
        emoji    = _SEV_EMOJI.get(severity, "⚠️")
        loc      = f"{file_}:{line}" if line else file_
        mention  = f"{self.config.mention_on_critical} " if severity == "CRITICAL" and self.config.mention_on_critical else ""
        fields = [{"type": "mrkdwn", "text": f"*Severity:* {severity}"}, {"type": "mrkdwn", "text": f"*Rule:* `{rule_id}`"}, {"type": "mrkdwn", "text": f"*Location:* `{loc}`"}]
        if cwe:
            fields.append({"type": "mrkdwn", "text": f"*CWE:* {cwe}"})
        blocks = [{"type": "header", "text": {"type": "plain_text", "text": f"{mention}{emoji} [{severity}] {rule_id}", "emoji": True}},
                  {"type": "section", "text": {"type": "mrkdwn", "text": message}, "fields": fields}]
        evidence = finding.get("evidence", finding.get("code", finding.get("snippet", "")))
        if evidence:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Evidence:*\n```{str(evidence)[:500]}```"}})
        blocks.append({"type": "divider"})
        return blocks

    def _finding_fallback_text(self, finding: dict) -> str:
        severity = finding.get("severity", "MEDIUM")
        rule_id  = finding.get("rule_id", finding.get("id", "UNKNOWN"))
        message  = (finding.get("message") or finding.get("description", ""))[:80]
        return f"{_SEV_EMOJI.get(severity, '⚠️')} [{severity}] {rule_id}: {message}"

    def _above_min_severity(self, severity: str) -> bool:
        min_sev = self.config.min_severity
        try:
            return _SEV_ORDER.index(severity) >= _SEV_ORDER.index(min_sev)
        except ValueError:
            return True

    def _deliver(self, payload: dict) -> bool:
        if not self.is_configured():
            return False
        if self.config.webhook_url:
            return self._post_webhook(self.config.webhook_url, payload)
        return self._post_bot_api(payload)

    def _post_webhook(self, url: str, payload: dict) -> bool:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode()
                return body.strip() == "ok" or resp.status == 200
        except Exception:
            return False

    def _post_bot_api(self, payload: dict) -> bool:
        url  = "https://slack.com/api/chat.postMessage"
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.config.bot_token}"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode())
                return bool(result.get("ok"))
        except Exception:
            return False
