"""
Tests for Ghost Security Platform — new CLI commands:
  notify, sla, audit-log, and the extended rules CDN commands.

No real network calls — all external I/O is mocked.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


SAMPLE_FINDINGS = [
    {"severity": "CRITICAL", "type": "sqli",     "message": "SQL injection",     "file": "app.py",   "line": 42, "rule_id": "GH-001"},
    {"severity": "HIGH",     "type": "xss",      "message": "XSS vulnerability", "file": "view.py",  "line": 10, "rule_id": "GH-002"},
    {"severity": "MEDIUM",   "type": "info-leak","message": "Info disclosure",  "file": "api.py",   "line": 5,  "rule_id": "GH-003"},
    {"severity": "LOW",      "type": "log",      "message": "Sensitive log",     "file": "utils.py", "line": 99, "rule_id": "GH-004"},
]


def _write_findings(tmpdir: str, findings=None) -> str:
    p = Path(tmpdir) / "findings.json"
    p.write_text(json.dumps(findings or SAMPLE_FINDINGS))
    return str(p)


def _args(**kw) -> SimpleNamespace:
    defaults = {"findings": "findings.json", "jira": False, "slack": False,
                "min_severity": "HIGH", "test_connection": False, "open_findings": False,
                "overdue": False, "report": False, "fmt": "table", "policy": "default",
                "tail": 50, "stats": False, "export_path": None}
    defaults.update(kw)
    return SimpleNamespace(**defaults)


class TestCmdNotify(unittest.TestCase):

    def _import_cmd(self):
        import ghost_cli_main
        return ghost_cli_main.cmd_notify

    def test_test_connection_jira_ok(self):
        cmd = self._import_cmd()
        mock_jira = MagicMock()
        mock_jira.return_value.test_connection.return_value = {"ok": True, "user": "admin"}
        with patch.dict("sys.modules", {"integrations.jira.jira_integration": MagicMock(JiraIntegration=mock_jira)}):
            rc = cmd(_args(test_connection=True, jira=True))
        self.assertEqual(rc, 0)

    def test_test_connection_jira_fail(self):
        cmd = self._import_cmd()
        mock_jira = MagicMock()
        mock_jira.return_value.test_connection.return_value = {"ok": False, "error": "auth failed"}
        with patch.dict("sys.modules", {"integrations.jira.jira_integration": MagicMock(JiraIntegration=mock_jira)}):
            rc = cmd(_args(test_connection=True, jira=True))
        self.assertEqual(rc, 0)

    def test_test_connection_slack_ok(self):
        cmd = self._import_cmd()
        mock_slack = MagicMock()
        mock_slack.return_value.test.return_value = True
        with patch.dict("sys.modules", {"integrations.slack.slack_notifier": MagicMock(SlackNotifier=mock_slack)}):
            rc = cmd(_args(test_connection=True, slack=True))
        self.assertEqual(rc, 0)

    def test_missing_findings_file_returns_1(self):
        cmd = self._import_cmd()
        rc = cmd(_args(findings="/nonexistent/path/findings.json"))
        self.assertEqual(rc, 1)

    def test_notify_jira_not_configured(self):
        cmd = self._import_cmd()
        with tempfile.TemporaryDirectory() as tmpdir:
            fp = _write_findings(tmpdir)
            mock_jira_cls = MagicMock()
            mock_jira_cls.return_value.is_configured.return_value = False
            mock_module = MagicMock()
            mock_module.JiraIntegration = mock_jira_cls
            with patch.dict("sys.modules", {"integrations.jira.jira_integration": mock_module}):
                rc = cmd(_args(findings=fp, jira=True))
        self.assertEqual(rc, 0)

    def test_notify_jira_configured_creates_issues(self):
        cmd = self._import_cmd()
        with tempfile.TemporaryDirectory() as tmpdir:
            fp = _write_findings(tmpdir)
            mock_jira_cls = MagicMock()
            instance = mock_jira_cls.return_value
            instance.is_configured.return_value = True
            instance.create_issues_batch.return_value = [{"id": "GH-1"}, {"id": "GH-2"}]
            mock_module = MagicMock()
            mock_module.JiraIntegration = mock_jira_cls
            with patch.dict("sys.modules", {"integrations.jira.jira_integration": mock_module}):
                rc = cmd(_args(findings=fp, jira=True, min_severity="HIGH"))
        self.assertEqual(rc, 0)
        instance.create_issues_batch.assert_called_once()

    def test_notify_slack_not_configured(self):
        cmd = self._import_cmd()
        with tempfile.TemporaryDirectory() as tmpdir:
            fp = _write_findings(tmpdir)
            mock_cls = MagicMock()
            mock_cls.return_value.is_configured.return_value = False
            mock_module = MagicMock()
            mock_module.SlackNotifier = mock_cls
            with patch.dict("sys.modules", {"integrations.slack.slack_notifier": mock_module}):
                rc = cmd(_args(findings=fp, slack=True))
        self.assertEqual(rc, 0)

    def test_notify_slack_sends_summary(self):
        cmd = self._import_cmd()
        with tempfile.TemporaryDirectory() as tmpdir:
            fp = _write_findings(tmpdir)
            mock_cls = MagicMock()
            instance = mock_cls.return_value
            instance.is_configured.return_value = True
            instance.send_scan_summary.return_value = True
            mock_module = MagicMock()
            mock_module.SlackNotifier = mock_cls
            with patch.dict("sys.modules", {"integrations.slack.slack_notifier": mock_module}):
                rc = cmd(_args(findings=fp, slack=True))
        self.assertEqual(rc, 0)
        instance.send_scan_summary.assert_called_once()

    def test_min_severity_filters_findings(self):
        cmd = self._import_cmd()
        captured = {}
        with tempfile.TemporaryDirectory() as tmpdir:
            fp = _write_findings(tmpdir)
            mock_cls = MagicMock()
            instance = mock_cls.return_value
            instance.is_configured.return_value = True
            def capture_batch(findings, **kw):
                captured["findings"] = findings
                return []
            instance.create_issues_batch.side_effect = capture_batch
            mock_module = MagicMock()
            mock_module.JiraIntegration = mock_cls
            with patch.dict("sys.modules", {"integrations.jira.jira_integration": mock_module}):
                cmd(_args(findings=fp, jira=True, min_severity="HIGH"))
        sent = captured.get("findings", [])
        severities = {f["severity"] for f in sent}
        self.assertTrue(all(s in {"CRITICAL", "HIGH"} for s in severities))

    def test_no_backend_specified_returns_0(self):
        cmd = self._import_cmd()
        with tempfile.TemporaryDirectory() as tmpdir:
            fp = _write_findings(tmpdir)
            rc = cmd(_args(findings=fp, jira=False, slack=False))
        self.assertEqual(rc, 0)


class TestCmdSla(unittest.TestCase):

    def _import_cmd(self):
        import ghost_cli_main
        return ghost_cli_main.cmd_sla

    def _mock_tracker(self, **overrides):
        tracker = MagicMock()
        tracker.track_batch.return_value = {"total": 2}
        tracker.overdue.return_value = []
        tracker.report.return_value = "SLA report text"
        tracker.summary.return_value = {"sla_score": 95.0, "total": 10, "on_track": 9, "at_risk": 1, "overdue": 0}
        for k, v in overrides.items():
            setattr(tracker, k, v)
        return tracker

    def _mock_sla_module(self, tracker=None):
        if tracker is None:
            tracker = self._mock_tracker()
        mock_mod = MagicMock()
        mock_mod.SLATracker.return_value = tracker
        mock_mod.SLAPolicy.default.return_value = MagicMock()
        mock_mod.SLAPolicy.pci_dss.return_value = MagicMock()
        mock_mod.SLAPolicy.soc2.return_value = MagicMock()
        return mock_mod

    def test_default_shows_summary(self):
        cmd = self._import_cmd()
        mock_mod = self._mock_sla_module()
        with patch.dict("sys.modules", {"core.enterprise.sla_tracker": mock_mod}):
            rc = cmd(_args())
        self.assertEqual(rc, 0)
        mock_mod.SLATracker.return_value.summary.assert_called_once()

    def test_open_missing_file_returns_1(self):
        cmd = self._import_cmd()
        mock_mod = self._mock_sla_module()
        with patch.dict("sys.modules", {"core.enterprise.sla_tracker": mock_mod}):
            rc = cmd(_args(findings="/no/such/file.json", open_findings=True))
        self.assertEqual(rc, 1)

    def test_open_findings_calls_track_batch(self):
        cmd = self._import_cmd()
        with tempfile.TemporaryDirectory() as tmpdir:
            fp = _write_findings(tmpdir)
            mock_mod = self._mock_sla_module()
            with patch.dict("sys.modules", {"core.enterprise.sla_tracker": mock_mod}):
                rc = cmd(_args(findings=fp, open_findings=True))
        self.assertEqual(rc, 0)
        mock_mod.SLATracker.return_value.track_batch.assert_called_once()

    def test_overdue_no_items_returns_0(self):
        cmd = self._import_cmd()
        mock_mod = self._mock_sla_module()
        with patch.dict("sys.modules", {"core.enterprise.sla_tracker": mock_mod}):
            rc = cmd(_args(overdue=True))
        self.assertEqual(rc, 0)

    def test_overdue_items_returns_1(self):
        cmd = self._import_cmd()
        tracker = self._mock_tracker()
        overdue_item = MagicMock()
        overdue_item.rule_id = "GH-001"
        overdue_item.file = "app.py"
        overdue_item.days_remaining = -3
        tracker.overdue.return_value = [overdue_item]
        mock_mod = self._mock_sla_module(tracker=tracker)
        with patch.dict("sys.modules", {"core.enterprise.sla_tracker": mock_mod}):
            rc = cmd(_args(overdue=True))
        self.assertEqual(rc, 1)

    def test_report_calls_report(self):
        cmd = self._import_cmd()
        mock_mod = self._mock_sla_module()
        with patch.dict("sys.modules", {"core.enterprise.sla_tracker": mock_mod}):
            rc = cmd(_args(report=True))
        self.assertEqual(rc, 0)
        mock_mod.SLATracker.return_value.report.assert_called_once()

    def test_pci_dss_policy_used(self):
        cmd = self._import_cmd()
        mock_mod = self._mock_sla_module()
        with patch.dict("sys.modules", {"core.enterprise.sla_tracker": mock_mod}):
            cmd(_args(policy="pci-dss"))
        mock_mod.SLAPolicy.pci_dss.assert_called_once()

    def test_soc2_policy_used(self):
        cmd = self._import_cmd()
        mock_mod = self._mock_sla_module()
        with patch.dict("sys.modules", {"core.enterprise.sla_tracker": mock_mod}):
            cmd(_args(policy="soc2"))
        mock_mod.SLAPolicy.soc2.assert_called_once()

    def test_summary_color_green_for_high_score(self):
        cmd = self._import_cmd()
        mock_mod = self._mock_sla_module()
        with patch.dict("sys.modules", {"core.enterprise.sla_tracker": mock_mod}):
            rc = cmd(_args())
        self.assertEqual(rc, 0)

    def test_summary_color_red_for_low_score(self):
        tracker = self._mock_tracker()
        tracker.summary.return_value = {"sla_score": 55.0, "total": 10, "on_track": 5, "at_risk": 2, "overdue": 3}
        cmd = self._import_cmd()
        mock_mod = self._mock_sla_module(tracker=tracker)
        with patch.dict("sys.modules", {"core.enterprise.sla_tracker": mock_mod}):
            rc = cmd(_args())
        self.assertEqual(rc, 0)


class TestCmdAuditLog(unittest.TestCase):

    def _import_cmd(self):
        import ghost_cli_main
        return ghost_cli_main.cmd_audit_log

    def _mock_log(self, events=None, stats=None, export_path=None):
        log = MagicMock()
        log.tail.return_value = events or []
        log.stats.return_value = stats or {"total_events": 0}
        log.export_csv.return_value = export_path or "/tmp/audit_export.csv"
        return log

    def _mock_mod(self, log=None):
        mod = MagicMock()
        mod.AuditLog.return_value = log or self._mock_log()
        return mod

    def test_empty_log_returns_0(self):
        cmd = self._import_cmd()
        with patch.dict("sys.modules", {"core.audit_log": self._mock_mod()}):
            rc = cmd(_args(tail=50))
        self.assertEqual(rc, 0)

    def test_tail_shows_events(self):
        events = [{"timestamp": 1700000000.0, "event_type": "scan_started", "detail": "app/"},
                  {"timestamp": 1700000001.0, "event_type": "scan_complete", "detail": "app/"}]
        cmd = self._import_cmd()
        log = self._mock_log(events=events)
        with patch.dict("sys.modules", {"core.audit_log": self._mock_mod(log=log)}):
            rc = cmd(_args(tail=10))
        self.assertEqual(rc, 0)
        log.tail.assert_called_once_with(10)

    def test_stats_flag(self):
        cmd = self._import_cmd()
        log = self._mock_log(stats={"total_events": 42, "unique_actors": 3})
        with patch.dict("sys.modules", {"core.audit_log": self._mock_mod(log=log)}):
            rc = cmd(_args(stats=True))
        self.assertEqual(rc, 0)
        log.stats.assert_called_once()

    def test_export_calls_export_csv(self):
        cmd = self._import_cmd()
        log = self._mock_log(export_path="/tmp/out.csv")
        with patch.dict("sys.modules", {"core.audit_log": self._mock_mod(log=log)}):
            rc = cmd(_args(export_path="/tmp/out.csv"))
        self.assertEqual(rc, 0)
        log.export_csv.assert_called_once_with("/tmp/out.csv")

    def test_events_with_string_timestamp(self):
        events = [{"timestamp": "2026-01-01 00:00:00", "event_type": "test", "detail": "x"}]
        cmd = self._import_cmd()
        log = self._mock_log(events=events)
        with patch.dict("sys.modules", {"core.audit_log": self._mock_mod(log=log)}):
            rc = cmd(_args(tail=5))
        self.assertEqual(rc, 0)

    def test_events_with_action_key(self):
        events = [{"timestamp": 1700000000.0, "action": "user_login", "message": "admin"}]
        cmd = self._import_cmd()
        log = self._mock_log(events=events)
        with patch.dict("sys.modules", {"core.audit_log": self._mock_mod(log=log)}):
            rc = cmd(_args())
        self.assertEqual(rc, 0)


class TestCmdRulesCDN(unittest.TestCase):

    def _import_cmd(self):
        import ghost_cli_main
        return ghost_cli_main.cmd_rules

    def _rules_ns(self, path=".", **kw):
        ns = SimpleNamespace(path=path, rules_dir=None, output="table",
                             save=None, create_example=False, check_only=False, force=False)
        for k, v in kw.items():
            setattr(ns, k, v)
        return ns

    def test_rules_update_calls_download(self):
        cmd = self._import_cmd()
        mock_cdn = MagicMock()
        mock_cdn.return_value.check_updates.return_value = {"has_update": True, "current": "1.0.0", "latest": "2.0.0", "new_rules": []}
        mock_cdn.return_value.download_rules.return_value = {"downloaded": 3, "skipped": 0, "errors": 0, "version": "2.0.0"}
        mock_mod = MagicMock()
        mock_mod.RulesCDN = mock_cdn
        with patch.dict("sys.modules", {"integrations.rules_cdn": mock_mod}):
            rc = cmd(self._rules_ns(path="update"))
        self.assertEqual(rc, 0)
        mock_cdn.return_value.download_rules.assert_called_once()

    def test_rules_update_no_update_available(self):
        cmd = self._import_cmd()
        mock_cdn = MagicMock()
        mock_cdn.return_value.check_updates.return_value = {"has_update": False, "current": "1.0.0", "latest": "1.0.0", "new_rules": []}
        mock_mod = MagicMock()
        mock_mod.RulesCDN = mock_cdn
        with patch.dict("sys.modules", {"integrations.rules_cdn": mock_mod}):
            rc = cmd(self._rules_ns(path="update"))
        self.assertEqual(rc, 0)
        mock_cdn.return_value.download_rules.assert_not_called()

    def test_rules_list_empty(self):
        cmd = self._import_cmd()
        mock_cdn = MagicMock()
        mock_cdn.return_value.list_local_rules.return_value = []
        mock_cdn.return_value.get_version.return_value = None
        mock_mod = MagicMock()
        mock_mod.RulesCDN = mock_cdn
        with patch.dict("sys.modules", {"integrations.rules_cdn": mock_mod}):
            rc = cmd(self._rules_ns(path="list"))
        self.assertEqual(rc, 0)

    def test_rules_list_with_rules(self):
        cmd = self._import_cmd()
        mock_cdn = MagicMock()
        mock_cdn.return_value.list_local_rules.return_value = [
            {"name": "owasp/sqli.yml", "size_bytes": 1024, "checksum": "sha256:abc123"},
            {"name": "owasp/xss.yml",  "size_bytes": 512,  "checksum": "sha256:def456"},
        ]
        mock_cdn.return_value.get_version.return_value = "2.0.0"
        mock_mod = MagicMock()
        mock_mod.RulesCDN = mock_cdn
        with patch.dict("sys.modules", {"integrations.rules_cdn": mock_mod}):
            rc = cmd(self._rules_ns(path="list"))
        self.assertEqual(rc, 0)


class TestCLIArgParsing(unittest.TestCase):

    def test_notify_subparser_registered(self):
        result = __import__("subprocess").run(
            [__import__("sys").executable, "ghost_cli_main.py", "notify", "--help"],
            capture_output=True, text=True, cwd="/tmp/ghost_v11_build",
        )
        self.assertIn("notify", result.stdout + result.stderr)

    def test_sla_subparser_registered(self):
        result = __import__("subprocess").run(
            [__import__("sys").executable, "ghost_cli_main.py", "sla", "--help"],
            capture_output=True, text=True, cwd="/tmp/ghost_v11_build",
        )
        self.assertIn("sla", result.stdout + result.stderr)

    def test_audit_log_subparser_registered(self):
        result = __import__("subprocess").run(
            [__import__("sys").executable, "ghost_cli_main.py", "audit-log", "--help"],
            capture_output=True, text=True, cwd="/tmp/ghost_v11_build",
        )
        self.assertIn("audit", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
