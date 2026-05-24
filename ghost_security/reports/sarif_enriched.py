"""
Ghost Security Platform — SARIF 2.1.0 Enriched Exporter
Full SARIF output with:
  • CWE / OWASP / CVE enrichment in rule metadata
  • GitHub Code Scanning compatible format
  • PR annotations (locations with regions)
  • Findings normalisation across all scanners
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


_TOOL_VERSION = "2.2.0"
_SCHEMA       = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


# ── Severity normalisation ─────────────────────────────────────────────────────
_SEV_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "INFO":     "none",
}

_SEV_TO_RANK = {
    "CRITICAL": 9.5,
    "HIGH":     7.5,
    "MEDIUM":   5.0,
    "LOW":      2.5,
    "INFO":     0.5,
}


class SARIFExporter:
    """
    Convert Ghost Security findings to SARIF 2.1.0.

    Usage:
        exporter = SARIFExporter()
        sarif    = exporter.export(report_dict)
        Path("results.sarif").write_text(json.dumps(sarif, indent=2))
    """

    def __init__(self, repo_root: str = ".") -> None:
        self.repo_root = str(Path(repo_root).resolve())

    # ── Public API ─────────────────────────────────────────────────────────────

    def export(self, report: dict) -> dict:
        """
        Accept a Ghost report dict (with a 'findings' list) and return
        a complete SARIF 2.1.0 document as a Python dict.
        """
        findings = self._collect_findings(report)
        rules    = self._build_rules(findings)
        results  = [self._finding_to_result(f) for f in findings]

        return {
            "$schema": _SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": self._tool_descriptor(rules),
                    "results":           results,
                    "columnKind":        "utf16CodeUnits",
                    "originalUriBaseIds": {"SRCROOT": {"uri": f"file:///{self.repo_root}/"}},
                    "properties": {
                        "ghost_version":  _TOOL_VERSION,
                        "exported_at":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "total_findings": len(findings),
                        "severity_counts": self._sev_counts(findings),
                        "target":         report.get("target", ""),
                    },
                }
            ],
        }

    def export_file(self, report: dict, output_path: str) -> str:
        """Export to a .sarif file. Returns the path."""
        sarif = self.export(report)
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(sarif, indent=2))
        return str(p)

    def normalize_finding(self, raw: dict) -> dict:
        """
        Normalize a raw finding from any scanner into a canonical form.
        Adds missing fields, normalises severity, generates rule_id.
        """
        f = dict(raw)

        # Severity
        sev = (f.get("severity") or "MEDIUM").upper()
        if sev not in _SEV_TO_LEVEL:
            sev = "MEDIUM"
        f["severity"] = sev

        # Rule ID — derive from type/id/rule_id
        if not f.get("rule_id"):
            base = f.get("id") or f.get("type") or "FINDING"
            f["rule_id"] = base.upper().replace(" ", "_")[:32]

        # File & line
        f.setdefault("file",    "unknown")
        f.setdefault("line",    1)
        f.setdefault("column",  1)

        # Message
        if not f.get("message"):
            f["message"] = f.get("description") or f.get("type") or "Security finding"

        return f

    # ── SARIF building blocks ──────────────────────────────────────────────────

    def _tool_descriptor(self, rules: List[dict]) -> dict:
        return {
            "driver": {
                "name":            "GhostSecurity",
                "version":         _TOOL_VERSION,
                "semanticVersion": _TOOL_VERSION,
                "informationUri":  "https://github.com/ghost-security/platform",
                "organization":    "Ghost Security",
                "rules":           rules,
            }
        }

    def _build_rules(self, findings: List[dict]) -> List[dict]:
        """Deduplicated rule list with CWE / OWASP / help text."""
        seen: Dict[str, dict] = {}
        for f in findings:
            rid = f.get("rule_id") or "UNKNOWN"
            if rid in seen:
                continue
            rule: dict = {
                "id":   rid,
                "name": self._rule_name(f),
                "shortDescription": {"text": f.get("message") or rid},
                "fullDescription":  {"text": f.get("description") or f.get("message") or rid},
                "defaultConfiguration": {
                    "level": _SEV_TO_LEVEL.get(f.get("severity", "MEDIUM"), "warning"),
                    "rank":  _SEV_TO_RANK.get(f.get("severity", "MEDIUM"), 5.0),
                },
                "properties": {
                    "tags":      self._rule_tags(f),
                    "precision": "medium",
                    "security-severity": str(_SEV_TO_RANK.get(f.get("severity", "MEDIUM"), 5.0)),
                },
            }

            # Help / reference URIs
            uris = []
            cwe = f.get("cwe")
            if cwe:
                cwe_num = cwe.replace("CWE-", "")
                uris.append({"text": cwe, "uri": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"})
            owasp = f.get("owasp")
            if owasp:
                uris.append({"text": owasp, "uri": f"https://owasp.org/Top10/{owasp.replace(':', '_').replace(' ', '-')}/"})

            if uris:
                rule["helpUri"] = uris[0]["uri"]
                rule["help"]    = {
                    "text": " | ".join(u["text"] for u in uris),
                    "markdown": "\n".join(f"- [{u['text']}]({u['uri']})" for u in uris),
                }

            seen[rid] = rule
        return list(seen.values())

    def _finding_to_result(self, f: dict) -> dict:
        sev   = f.get("severity", "MEDIUM").upper()
        rid   = f.get("rule_id") or "UNKNOWN"
        fpath = f.get("file") or "unknown"

        # Make path relative to repo root
        try:
            rel = str(Path(fpath).relative_to(self.repo_root))
        except ValueError:
            rel = fpath

        result: dict = {
            "ruleId":  rid,
            "level":   _SEV_TO_LEVEL.get(sev, "warning"),
            "message": {"text": f.get("message") or f.get("description") or rid},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri":       rel.replace("\\", "/"),
                            "uriBaseId": "SRCROOT",
                        },
                        "region": {
                            "startLine":   max(1, int(f.get("line",   1))),
                            "startColumn": max(1, int(f.get("column", 1))),
                        },
                    }
                }
            ],
            "fingerprints": {
                "identityHash/v1": self._fingerprint(f),
            },
            "properties": {
                "severity":  sev,
                "scanner":   f.get("scanner") or "",
                "confidence":str(f.get("confidence") or ""),
                "cwe":       f.get("cwe") or "",
                "owasp":     f.get("owasp") or "",
                "priority":  f.get("priority") or "",
            },
        }

        # Code snippet (optional)
        snippet = f.get("context") or f.get("code_snippet") or f.get("evidence")
        if snippet:
            result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                "text": str(snippet)[:500]
            }

        # Related locations (e.g. taint source)
        if f.get("source_location"):
            src = f["source_location"]
            result["relatedLocations"] = [
                {
                    "id":      1,
                    "message": {"text": "Taint source"},
                    "physicalLocation": {
                        "artifactLocation": {"uri": src.get("file", "unknown")},
                        "region":           {"startLine": src.get("line", 1)},
                    },
                }
            ]

        # Fix suggestion
        if f.get("fix") or f.get("remediation"):
            result["fixes"] = [
                {
                    "description": {"text": f.get("fix") or f.get("remediation") or ""},
                }
            ]

        return result

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _collect_findings(report: dict) -> List[dict]:
        """Flatten findings from various report structures."""
        findings = []
        # Top-level findings list
        for f in report.get("findings", []):
            findings.append(f)
        # Nested scanner results
        for scanner_result in report.get("scanner_results", {}).values():
            for f in scanner_result.get("findings", []):
                findings.append(f)
        return findings

    @staticmethod
    def _fingerprint(f: dict) -> str:
        key = "|".join([
            str(f.get("rule_id") or ""),
            str(f.get("file")    or ""),
            str(f.get("line")    or ""),
        ])
        return hashlib.sha1(key.encode()).hexdigest()[:20]

    @staticmethod
    def _rule_name(f: dict) -> str:
        name = (f.get("type") or f.get("rule_id") or "finding")
        return "".join(w.capitalize() for w in name.replace("-", "_").split("_"))

    @staticmethod
    def _rule_tags(f: dict) -> List[str]:
        tags = ["security"]
        cwe   = f.get("cwe")
        owasp = f.get("owasp")
        sev   = f.get("severity")
        if cwe:   tags.append(cwe)
        if owasp: tags.append(owasp)
        if sev:   tags.append(sev)
        cat = f.get("category") or f.get("cwe_category")
        if cat:   tags.append(cat.lower())
        return tags

    @staticmethod
    def _sev_counts(findings: List[dict]) -> dict:
        counts: dict = {}
        for f in findings:
            s = f.get("severity", "MEDIUM")
            counts[s] = counts.get(s, 0) + 1
        return counts


# ── GitHub Actions workflow helper ─────────────────────────────────────────────

def generate_github_actions_workflow(scan_type: str = "all") -> str:
    """Return a GitHub Actions YAML that runs Ghost Security on push/PR."""
    return f"""name: Ghost Security Scan

on:
  push:
    branches: [ main, master, develop ]
  pull_request:
    branches: [ main, master ]

permissions:
  contents: read
  security-events: write
  pull-requests: write

jobs:
  ghost-security:
    name: Ghost Security Analysis
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install Ghost Security Platform
        run: |
          pip install -r requirements.txt
          pip install semgrep bandit

      - name: Run Ghost Security scan
        id: ghost_scan
        env:
          OPENAI_API_KEY: ${{{{ secrets.OPENAI_API_KEY }}}}
        run: |
          python3 ghost_cli.py scan . --mode {scan_type} -o /tmp/ghost_report.json
          python3 ghost_cli.py sarif /tmp/ghost_report.json > /tmp/ghost.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: /tmp/ghost.sarif
          category: ghost-security

      - name: Post PR comment
        if: github.event_name == 'pull_request' && always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            let summary = 'Ghost Security scan complete.';
            try {{
              const report = JSON.parse(fs.readFileSync('/tmp/ghost_report.json', 'utf8'));
              const counts = report.severity_counts || {{}};
              summary = [
                '## 🔒 Ghost Security Scan Results',
                '',
                `| Severity | Count |`,
                `|----------|-------|`,
                `| 🔴 CRITICAL | ${{counts.CRITICAL || 0}} |`,
                `| 🟠 HIGH     | ${{counts.HIGH     || 0}} |`,
                `| 🟡 MEDIUM   | ${{counts.MEDIUM   || 0}} |`,
                `| 🟢 LOW      | ${{counts.LOW      || 0}} |`,
                '',
                `Risk Score: **${{report.risk_score || 'N/A'}}** (${{report.risk_level || 'N/A'}})`,
                '',
                '_See Security tab for detailed findings →_',
              ].join('\\n');
            }} catch(e) {{}}
            github.rest.issues.createComment({{
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: summary,
            }});

      - name: Fail on CRITICAL findings
        run: |
          python3 -c "
          import json, sys
          r = json.load(open('/tmp/ghost_report.json'))
          crits = r.get('severity_counts', {{}}).get('CRITICAL', 0)
          if crits > 0:
              print(f'FAIL: {{crits}} CRITICAL finding(s) found')
              sys.exit(1)
          print('OK: No CRITICAL findings')
          "
"""
