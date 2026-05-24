"""
Ghost Security — SARIF Exporter (v2.1.0)
Exports findings in Static Analysis Results Interchange Format
for GitHub Code Scanning, VS Code, and other SARIF consumers.
Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
"""
import json
import time
from typing import Dict, List


class SARIFExporter:
    TOOL_NAME    = "Ghost Security Platform"
    TOOL_VERSION = "2.2.0"
    TOOL_URI     = "https://github.com/ghost-security/platform"

    SEV_MAP = {"CRITICAL": "error", "HIGH": "error",
               "MEDIUM": "warning", "LOW": "note", "INFO": "none"}
    RANK_MAP = {"CRITICAL": 100.0, "HIGH": 75.0,
                "MEDIUM": 50.0, "LOW": 25.0, "INFO": 5.0}

    def export(self, report: Dict) -> Dict:
        findings  = report.get("findings", [])
        rules     = self._build_rules(findings)
        results   = [self._finding_to_result(f) for f in findings]

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name":            self.TOOL_NAME,
                        "version":         self.TOOL_VERSION,
                        "informationUri":  self.TOOL_URI,
                        "rules":           rules,
                    }
                },
                "results":       results,
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": report.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%SZ")),
                }],
                "properties": {
                    "target":      report.get("target", ""),
                    "risk_score":  report.get("risk_score", 0),
                    "risk_level":  report.get("risk_level", ""),
                },
            }],
        }

    def export_to_file(self, report: Dict, path: str) -> None:
        sarif = self.export(report)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _build_rules(self, findings: List[Dict]) -> List[Dict]:
        seen, rules = set(), []
        for f in findings:
            rid = f.get("id", f.get("type", "UNKNOWN"))
            if rid in seen:
                continue
            seen.add(rid)
            cwe = f.get("cwe", "")
            tags = ["security"]
            if cwe:
                tags.append(cwe)

            rule: Dict = {
                "id":   rid,
                "name": rid.replace("_", " ").title(),
                "shortDescription": {"text": f.get("description", rid)[:150]},
                "fullDescription":  {"text": f.get("description", rid)},
                "help": {"text": f.get("recommendation", ""), "markdown": f.get("recommendation", "")},
                "defaultConfiguration": {
                    "level": self.SEV_MAP.get(f.get("severity", "INFO"), "note"),
                    "rank":  self.RANK_MAP.get(f.get("severity", "INFO"), 5.0),
                },
                "properties": {"tags": tags, "precision": "medium"},
            }
            if cwe:
                rule["relationships"] = [{
                    "target": {
                        "id": cwe,
                        "toolComponent": {"name": "CWE", "guid": "1489b0c4-7d58-4fe0-9886-1ef19dfe135e"},
                    },
                    "kinds": ["superset"],
                }]
            rules.append(rule)
        return rules

    def _finding_to_result(self, f: Dict) -> Dict:
        rid  = f.get("id", f.get("type", "UNKNOWN"))
        file = f.get("file", "")
        line = max(int(f.get("line", 1)), 1)
        sev  = f.get("severity", "INFO")

        result: Dict = {
            "ruleId":  rid,
            "level":   self.SEV_MAP.get(sev, "note"),
            "rank":    self.RANK_MAP.get(sev, 5.0),
            "message": {"text": f.get("description", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file.replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": line, "startColumn": 1},
                }
            }],
        }

        # Add fix / remediation if available
        rec = f.get("recommendation") or f.get("code_fix")
        if rec and rec != "N/A":
            result["fixes"] = [{"description": {"text": rec}}]

        # Additional properties
        props: Dict = {"severity": sev, "source": f.get("source", "ghost")}
        if f.get("confidence") is not None:
            props["confidence"] = f["confidence"]
        if f.get("cvss_score"):
            props["cvss_score"] = f["cvss_score"]
        if f.get("cvss_vector"):
            props["cvss_vector"] = f["cvss_vector"]
        if f.get("false_positive_risk"):
            props["false_positive_risk"] = f["false_positive_risk"]
        result["properties"] = props

        # Evidence as related location snippet
        evidence = f.get("evidence", "")
        if evidence:
            result["relatedLocations"] = [{
                "id": 1,
                "message": {"text": "Evidence: " + evidence[:200]},
                "physicalLocation": {
                    "artifactLocation": {"uri": file.replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": line},
                },
            }]
        return result
