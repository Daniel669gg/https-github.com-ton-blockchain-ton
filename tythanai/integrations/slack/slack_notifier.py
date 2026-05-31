"""
TythanAI Platform — Slack Webhook + Bot API Integration

Sends security finding alerts and scan summaries to Slack using
Incoming Webhooks or the chat.postMessage Bot API.

Usage:
    from integrations.slack.slack_notifier import SlackNotifier, SlackConfig

    # Auto-load from environment variables
    notifier = SlackNotifier()

    # Explicit config
    cfg = SlackConfig(
        webhook_url="https://hooks.slack.com/services/...",
        channel="#security",
        min_severity="HIGH",
    )
    notifier = SlackNotifier(cfg)
    notifier.send_finding(finding)
    notifier.send_scan_summary(findings, scan_path=".", duration=3.14)
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import List, Optional


# ── Severity metadata ──────────────────────────────────────────────────────────

_SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

_SEV_EMOJI = {
    "CRITICAL": "🚨",
    "HIGH":     "⚠️",
    "MEDIUM":   "🔶",
    "LOW":      "🔵",
    "INFO":     "ℹ️",
}

_SEV_COLOR = {
    "CRITICAL": "danger",
    "HIGH":     "warning",
    "MEDIUM":   "#ffcc00",
    "LOW":      "good",
    "INFO":     "#cccccc",
}


@dataclass
class SlackConfig:
    """Configuration for the Slack integration."""

    webhook_url: str = ""             # Incoming Webhook URL
    bot_token: str = ""               # Bot OAuth token for chat.postMessage
    channel: str = "#security"
    min_severity: str = "HIGH"
    mention_on_critical: str = "@channel"  # mention string for CRITICAL findings

    @classmethod
    def from_env(cls) -> "SlackConfig":
        """Load config from environment variables."""
        return cls(
            webhook_url=os.getenv("SLACK_WEBHOOK_URL", ""),
            bot_token=os.getenv("SLACK_BOT_TOKEN", ""),
            channel=os.getenv("SLACK_CHANNEL", "#security"),
            min_severity=os.getenv("SLACK_MIN_SEVERITY", "HIGH"),
            mention_on_critical=os.getenv("SLACK_MENTION_CRITICAL", "@channel"),
        )


class SlackNotifier:
    """
    Slack notification integration for TythanAI findings.

    Supports two delivery modes:
    - Incoming Webhook (webhook_url): simplest, no bot setup needed.
    - Bot API (bot_token + channel): allows posting to specific channels.

    Webhook takes priority when both are configured.
    """

    def __init__(self, config: Optional[SlackConfig] = None) -> None:
        if config is None:
            config = SlackConfig.from_env()
        self.config = config

    # ── Public API ─────────────────────────────────────────────────────────────

    def is_configured(self) -> bool:
        """Return True if at least one delivery method is configured."""
        return bool(self.config.webhook_url or (self.config.bot_token and self.config.channel))

    def send_finding(self, finding: dict) -> bool:
        """
        Send a rich Block Kit message for a single finding.

        Returns True on successful delivery, False otherwise.
        Skips findings below min_severity.
        """
        severity = finding.get("severity", "MEDIUM")
        if not self._above_min_severity(severity):
            return False

        blocks = self._finding_blocks(finding)
        payload = {"blocks": blocks}

        # For webhook delivery add optional text fallback
        payload["text"] = self._finding_fallback_text(finding)

        # Add channel when using bot token
        if not self.config.webhook_url and self.config.bot_token:
            payload["channel"] = self.config.channel

        return self._deliver(payload)

    def send_scan_summary(
        self,
        findings: List[dict],
        scan_path: str,
        duration: float,
    ) -> bool:
        """
        Send a scan completion summary with counts by severity.

        Includes colour-coded attachment and top 3 critical/high findings.
        """
        counts: dict = {}
        for f in findings:
            s = f.get("severity", "MEDIUM")
            counts[s] = counts.get(s, 0) + 1

        total = len(findings)
        crits = counts.get("CRITICAL", 0)
        highs = counts.get("HIGH", 0)

        # Attachment colour reflects highest severity present
        if crits:
            color = "danger"
        elif highs:
            color = "warning"
        else:
            color = "good"

        # Summary text
        parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            n = counts.get(sev, 0)
            if n:
                parts.append(f"{_SEV_EMOJI.get(sev, '')} {sev}: {n}")
        counts_text = "  |  ".join(parts) if parts else "No findings"

        # Top findings (CRITICAL + HIGH)
        top = [
            f for f in findings
            if f.get("severity") in ("CRITICAL", "HIGH")
        ][:3]

        top_lines = []
        for f in top:
            sev   = f.get("severity", "")
            emoji = _SEV_EMOJI.get(sev, "")
            rid   = f.get("rule_id", f.get("id", "unknown"))
            msg   = (f.get("message") or f.get("description", ""))[:60]
            loc   = f"{f.get('file', '')}:{f.get('line', '')}"
            top_lines.append(f"{emoji} *{rid}* — {msg}  `{loc}`")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type":  "plain_text",
                    "text":  f"👻 TythanAI Scan Complete — {scan_path}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Total findings:* {total}"},
                    {"type": "mrkdwn", "text": f"*Duration:* {duration:.2f}s"},
                    {"type": "mrkdwn", "text": f"*Path:* `{scan_path}`"},
                    {"type": "mrkdwn", "text": f"*Severity breakdown:*\n{counts_text}"},
                ],
            },
        ]

        if top_lines:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Top critical/high findings:*\n" + "\n".join(top_lines),
                },
            })

        payload: dict = {
            "text": f"Ghost scan complete: {total} findings in {scan_path}",
            "attachments": [
                {
                    "color":  color,
                    "blocks": blocks,
                }
            ],
        }

        if not self.config.webhook_url and self.config.bot_token:
            payload["channel"] = self.config.channel

        return self._deliver(payload)

    def send_alert(
        self,
        title: str,
        message: str,
        severity: str = "HIGH",
    ) -> bool:
        """Send a generic alert message."""
        emoji = _SEV_EMOJI.get(severity, "⚠️")
        color = _SEV_COLOR.get(severity, "warning")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type":  "plain_text",
                    "text":  f"{emoji} {title}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": message},
            },
        ]

        payload: dict = {
            "text":  f"{emoji} {title}: {message}",
            "color": color,
            "blocks": blocks,
        }

        if not self.config.webhook_url and self.config.bot_token:
            payload["channel"] = self.config.channel

        return self._deliver(payload)

    def test(self) -> bool:
        """Send a test message and return True if delivery was confirmed."""
        payload: dict = {
            "text": "👻 TythanAI — test message. Integration working correctly.",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "👻 *TythanAI* — test message. Integration working correctly.",
                    },
                }
            ],
        }

        if not self.config.webhook_url and self.config.bot_token:
            payload["channel"] = self.config.channel

        return self._deliver(payload)

    # ── Block Kit builders ──────────────────────────────────────────────────────

    def _finding_blocks(self, finding: dict) -> list:
        """Build Slack Block Kit blocks for a single finding."""
        severity = finding.get("severity", "MEDIUM")
        rule_id  = finding.get("rule_id", finding.get("id", "UNKNOWN"))
        message  = (finding.get("message") or finding.get("description", ""))[:120]
        file_    = finding.get("file", "unknown")
        line     = finding.get("line", "")
        cwe      = finding.get("cwe", "")

        emoji = _SEV_EMOJI.get(severity, "⚠️")
        loc   = f"{file_}:{line}" if line else file_

        mention = ""
        if severity == "CRITICAL" and self.config.mention_on_critical:
            mention = f"{self.config.mention_on_critical} "

        header_text = f"{mention}{emoji} [{severity}] {rule_id}"

        fields = [
            {"type": "mrkdwn", "text": f"*Severity:* {severity}"},
            {"type": "mrkdwn", "text": f"*Rule:* `{rule_id}`"},
            {"type": "mrkdwn", "text": f"*Location:* `{loc}`"},
        ]
        if cwe:
            fields.append({"type": "mrkdwn", "text": f"*CWE:* {cwe}"})

        blocks = [
            {
                "type": "header",
                "text": {
                    "type":  "plain_text",
                    "text":  header_text,
                    "emoji": True,
                },
            },
            {
                "type":   "section",
                "text":   {"type": "mrkdwn", "text": message},
                "fields": fields,
            },
        ]

        # Evidence / code snippet
        evidence = finding.get("evidence", finding.get("code", finding.get("snippet", "")))
        if evidence:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Evidence:*\n```{str(evidence)[:500]}```",
                },
            })

        blocks.append({"type": "divider"})
        return blocks

    def _finding_fallback_text(self, finding: dict) -> str:
        """Plain-text fallback for notifications."""
        severity = finding.get("severity", "MEDIUM")
        rule_id  = finding.get("rule_id", finding.get("id", "UNKNOWN"))
        message  = (finding.get("message") or finding.get("description", ""))[:80]
        emoji    = _SEV_EMOJI.get(severity, "⚠️")
        return f"{emoji} [{severity}] {rule_id}: {message}"

    # ── Severity filter ─────────────────────────────────────────────────────────

    def _above_min_severity(self, severity: str) -> bool:
        """Return True if *severity* is at or above config.min_severity."""
        min_sev = self.config.min_severity
        try:
            return _SEV_ORDER.index(severity) >= _SEV_ORDER.index(min_sev)
        except ValueError:
            return True

    # ── HTTP delivery ───────────────────────────────────────────────────────────

    def _deliver(self, payload: dict) -> bool:
        """
        Deliver payload to Slack.

        Prefers Incoming Webhook (webhook_url).
        Falls back to chat.postMessage (bot_token + channel).
        Returns True on success (HTTP 2xx / Slack "ok").
        """
        if not self.is_configured():
            return False

        if self.config.webhook_url:
            return self._post_webhook(self.config.webhook_url, payload)

        # Bot token path
        return self._post_bot_api(payload)

    def _post_webhook(self, url: str, payload: dict) -> bool:
        """POST to an Incoming Webhook URL."""
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode()
                # Slack webhooks return "ok" on success
                return body.strip() == "ok" or resp.status == 200
        except urllib.error.HTTPError:
            return False
        except Exception:  # noqa: BLE001
            return False

    def _post_bot_api(self, payload: dict) -> bool:
        """POST to chat.postMessage using Bot OAuth token."""
        url  = "https://slack.com/api/chat.postMessage"
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {self.config.bot_token}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode())
                return bool(result.get("ok"))
        except urllib.error.HTTPError:
            return False
        except Exception:  # noqa: BLE001
            return False
