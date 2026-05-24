"""
Ghost Security Platform — Bug Bounty Report Generator
Генерирует professional responsible disclosure отчёты
в форматах Immunefi / HackenProof / TON Foundation.

Только для легитимного bug bounty: находим уязвимость через
статический анализ → формируем отчёт → отправляем через
официальный канал → получаем вознаграждение.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


# ── Severity → bounty tier mapping (Immunefi стандарт) ───────────────────────
_BOUNTY_TIERS = {
    "CRITICAL": {
        "range": "$50,000 – $250,000+",
        "label": "Critical",
        "immunefi_level": "Critical",
        "typical_examples": [
            "Direct theft of user funds",
            "Permanent freezing of funds",
            "Protocol insolvency",
            "Unauthorized minting",
        ],
    },
    "HIGH": {
        "range": "$10,000 – $50,000",
        "label": "High",
        "immunefi_level": "High",
        "typical_examples": [
            "Theft of unclaimed yield",
            "Temporary freezing of funds",
            "Significant financial loss < 100%",
        ],
    },
    "MEDIUM": {
        "range": "$1,000 – $10,000",
        "label": "Medium",
        "immunefi_level": "Medium",
        "typical_examples": [
            "Smart contract unable to operate normally",
            "DoS with recoverable state",
        ],
    },
    "LOW": {
        "range": "$100 – $1,000",
        "label": "Low",
        "immunefi_level": "Low",
        "typical_examples": [
            "Smart contract fails to function correctly",
            "Gas griefing",
        ],
    },
}

_BOUNTY_PLATFORMS = {
    "immunefi":    "https://immunefi.com/bounty/",
    "hackenproof": "https://hackenproof.com/programs/",
    "ton_security": "https://github.com/ton-blockchain/security-policy",
    "cantina":     "https://cantina.xyz/",
}

# ── Категория → описание атаки ────────────────────────────────────────────────
_CATEGORY_ATTACK_DESC = {
    "Fund Flow":    "An attacker can manipulate fund transfer modes to drain contract balance",
    "Access Control": "An unauthorized caller gains access to privileged contract functions",
    "Replay Protection": "A previously signed transaction can be replayed to execute operations multiple times",
    "Gas Control":  "An attacker can force the contract to spend gas, eventually depleting its balance",
    "Jetton Safety": "The contract incorrectly handles TEP-74 Jetton standard, enabling token theft or fake deposits",
    "NFT Safety":   "The contract incorrectly handles TEP-62 NFT standard",
    "Upgrade Safety": "Contract code or data can be replaced by an unauthorized party",
    "Randomness":   "The random number generation is predictable by validators or sophisticated attackers",
    "State Management": "Contract state can be corrupted through reentrancy-like callback patterns",
    "Integer Arithmetic": "Integer overflow or underflow leads to incorrect balance or logic calculations",
    "Dataflow":     "User-controlled data flows into sensitive operations without proper validation",
    "Cross-Contract": "Interactions with external contracts are not properly authenticated or validated",
    "Cell Handling": "Malformed cell data causes TVM exceptions or unexpected contract behaviour",
    "Input Validation": "Unvalidated user input leads to TVM exceptions or logic errors",
}


@dataclass
class BugBountyReport:
    """Structured bug bounty responsible disclosure report."""
    title:           str
    severity:        str
    category:        str
    target_contract: str
    description:     str
    impact:          str
    root_cause:      str
    recommendation:  str
    cwe:             str = ""
    affected_lines:  List[str] = field(default_factory=list)
    references:      List[str] = field(default_factory=list)
    researcher_notes: str = ""
    finding_id:      str = ""

    def immunefi_markdown(self) -> str:
        """Immunefi-compatible Markdown report."""
        tier      = _BOUNTY_TIERS.get(self.severity, _BOUNTY_TIERS["MEDIUM"])
        date_str  = time.strftime("%Y-%m-%d")
        cwe_link  = (
            f"[{self.cwe}](https://cwe.mitre.org/data/definitions/{self.cwe.replace('CWE-','')}.html)"
            if self.cwe else "N/A"
        )

        lines = [
            f"# {self.title}",
            "",
            f"**Severity:** {self.severity} ({tier['label']})",
            f"**Category:** {self.category}",
            f"**CWE:** {cwe_link}",
            f"**Date:** {date_str}",
            f"**Estimated Bounty Range:** {tier['range']}",
            "",
            "---",
            "",
            "## Summary",
            "",
            self.description,
            "",
            "## Vulnerability Details",
            "",
            "### Root Cause",
            "",
            self.root_cause,
            "",
        ]

        if self.affected_lines:
            lines += [
                "### Affected Code",
                "",
                "```func",
            ]
            lines += self.affected_lines
            lines += ["```", ""]

        lines += [
            "### Attack Scenario",
            "",
            _CATEGORY_ATTACK_DESC.get(self.category, self.impact),
            "",
            "## Impact",
            "",
            self.impact,
            "",
            "## Proof of Concept",
            "",
            "> **Note:** Full PoC available upon request after triage. "
            "The vulnerability has been verified through static analysis.",
            "",
            "## Recommendation",
            "",
            self.recommendation,
            "",
        ]

        if self.references:
            lines += ["## References", ""]
            for ref in self.references:
                lines.append(f"- {ref}")
            lines.append("")

        if self.researcher_notes:
            lines += ["## Researcher Notes", "", self.researcher_notes, ""]

        lines += [
            "---",
            "",
            "*Report generated by Ghost Security Platform — defensive static analysis tool*",
            f"*Finding ID: {self.finding_id}*",
        ]

        return "\n".join(lines)

    def hackenproof_json(self) -> dict:
        """HackenProof structured JSON submission format."""
        return {
            "title":       self.title,
            "severity":    self.severity.lower(),
            "description": self.description,
            "impact":      self.impact,
            "steps_to_reproduce": [
                "1. Deploy the target contract with default configuration",
                "2. Identify the vulnerable function in source code",
                f"3. {_CATEGORY_ATTACK_DESC.get(self.category, 'Execute the attack vector')}",
                "4. Observe the unintended behaviour described in Impact",
            ],
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "affected_contract": self.target_contract,
            "references": self.references,
        }


class BugBountyReportGenerator:
    """
    Конвертирует TON scanner findings в professional responsible disclosure отчёты.
    Поддерживает: Immunefi Markdown, HackenProof JSON, plain text summary.
    """

    def __init__(self, contract_name: str = "TON Smart Contract") -> None:
        self.contract_name = contract_name

    # ── Публичный API ──────────────────────────────────────────────────────────

    def from_findings(
        self,
        findings: List[dict],
        min_severity: str = "MEDIUM",
    ) -> List[BugBountyReport]:
        """Генерирует отчёты из списка findings. Фильтрует по severity."""
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        min_idx = order.index(min_severity) if min_severity in order else 2

        # Дедупликация по category+file
        seen: set = set()
        unique: List[dict] = []
        for f in findings:
            key = (f.get("category", ""), f.get("file", ""), f.get("rule_id", ""))
            sev = f.get("severity", "INFO")
            if sev not in order:
                continue
            if order.index(sev) <= min_idx and key not in seen:
                seen.add(key)
                unique.append(f)

        reports = []
        for f in sorted(unique, key=lambda x: order.index(x.get("severity","INFO"))):
            report = self._finding_to_report(f)
            if report:
                reports.append(report)
        return reports

    def generate_all(
        self,
        findings: List[dict],
        output_dir: str,
        min_severity: str = "MEDIUM",
        formats: List[str] = None,
    ) -> Dict[str, str]:
        """
        Генерирует все отчёты в output_dir.
        Returns: {filename: content}
        """
        if formats is None:
            formats = ["markdown", "json", "summary"]

        Path(output_dir).mkdir(parents=True, exist_ok=True)
        reports = self.from_findings(findings, min_severity)
        outputs: Dict[str, str] = {}

        for i, report in enumerate(reports, start=1):
            slug = f"{report.severity}_{report.category.replace(' ','_')}_{i:02d}"

            if "markdown" in formats:
                md_path = str(Path(output_dir) / f"{slug}.md")
                content = report.immunefi_markdown()
                Path(md_path).write_text(content, encoding="utf-8")
                outputs[md_path] = content

            if "json" in formats:
                js_path = str(Path(output_dir) / f"{slug}.json")
                content = json.dumps(report.hackenproof_json(), indent=2)
                Path(js_path).write_text(content, encoding="utf-8")
                outputs[js_path] = content

        if "summary" in formats:
            summary = self.executive_summary(findings, reports)
            s_path  = str(Path(output_dir) / "EXECUTIVE_SUMMARY.md")
            Path(s_path).write_text(summary, encoding="utf-8")
            outputs[s_path] = summary

        return outputs

    def executive_summary(
        self,
        findings: List[dict],
        reports: Optional[List[BugBountyReport]] = None,
    ) -> str:
        """Краткое резюме для первичной отправки в bug bounty программу."""
        if reports is None:
            reports = self.from_findings(findings)

        counts: Dict[str, int] = {}
        for f in findings:
            s = f.get("severity", "INFO")
            counts[s] = counts.get(s, 0) + 1

        total_bounty_low  = sum(
            int(t["range"].split("–")[0].replace("$","").replace(",","").strip())
            for r in reports
            if (t := _BOUNTY_TIERS.get(r.severity))
        )
        total_bounty_high = sum(
            int(t["range"].split("–")[1].replace("+","").replace("$","").replace(",","").strip().split()[0])
            for r in reports
            if (t := _BOUNTY_TIERS.get(r.severity))
        )

        lines = [
            f"# Security Audit Summary — {self.contract_name}",
            f"**Date:** {time.strftime('%Y-%m-%d')}",
            f"**Audited by:** Ghost Security Platform (static analysis)",
            "",
            "## Finding Overview",
            "",
            "| Severity | Count | Bounty Range per Finding |",
            "|----------|-------|--------------------------|",
        ]
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
            if counts.get(sev,0) > 0:
                tier = _BOUNTY_TIERS[sev]
                lines.append(f"| {sev} | {counts[sev]} | {tier['range']} |")

        lines += [
            "",
            f"**Total unique reportable findings:** {len(reports)}",
            f"**Estimated bounty range:** ${total_bounty_low:,} – ${total_bounty_high:,}",
            "",
            "## Critical & High Findings",
            "",
        ]

        for r in reports:
            if r.severity in ("CRITICAL", "HIGH"):
                tier = _BOUNTY_TIERS.get(r.severity, {})
                lines += [
                    f"### {r.title}",
                    f"- **Severity:** {r.severity} | **Category:** {r.category}",
                    f"- **CWE:** {r.cwe}",
                    f"- **Bounty range:** {tier.get('range','N/A')}",
                    f"- **Summary:** {r.description[:200]}",
                    f"- **Fix:** {r.recommendation[:150]}",
                    "",
                ]

        lines += [
            "## Submission Checklist",
            "",
            "- [ ] Verify finding on actual deployed contract (check if code matches)",
            "- [ ] Write minimal PoC in local TON sandbox (toncli / blueprint)",
            "- [ ] Document exact steps to reproduce",
            "- [ ] Submit through official program channel (Immunefi / HackenProof)",
            "- [ ] Include this report + PoC code",
            "- [ ] Await triage response (typically 1–7 days)",
            "",
            "## Responsible Disclosure Reminder",
            "",
            "> Do not share findings publicly before the project has confirmed the fix.",
            "> Follow the program's coordinated disclosure policy.",
            "> Most programs have 90-day disclosure deadline.",
            "",
            "---",
            "*Generated by Ghost Security Platform — static analysis only, no funds were accessed*",
        ]
        return "\n".join(lines)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _finding_to_report(self, f: dict) -> Optional[BugBountyReport]:
        sev      = f.get("severity", "MEDIUM")
        category = f.get("category", "Security")
        rule_id  = f.get("rule_id") or f.get("id", "")
        desc     = f.get("description") or f.get("message") or ""
        rec      = f.get("recommendation", "Review and fix the identified pattern")
        cwe      = f.get("cwe", "")
        evidence = f.get("evidence", "")
        fname    = Path(f.get("file","contract.fc")).name
        lineno   = f.get("line", 0)
        impact   = (
            f.get("known_impact") or
            _CATEGORY_ATTACK_DESC.get(category) or
            f.get("description") or
            "This vulnerability may impact contract security and user funds."
        )

        title = self._make_title(sev, category, desc)

        root_cause = (
            f"In `{fname}` (line {lineno}), the following pattern was detected:\n\n"
            f"```\n{evidence}\n```\n\n"
            f"{desc}"
        ) if evidence else desc

        refs = []
        if cwe:
            refs.append(f"[{cwe}](https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-','')}.html)")
        refs.append("https://docs.ton.org/develop/smart-contracts/security")
        refs.append("https://github.com/ton-blockchain/TEPs")

        return BugBountyReport(
            title           = title,
            severity        = sev,
            category        = category,
            target_contract = self.contract_name,
            description     = desc,
            impact          = impact,
            root_cause      = root_cause,
            recommendation  = rec,
            cwe             = cwe,
            affected_lines  = [evidence] if evidence else [],
            references      = refs,
            finding_id      = f"{rule_id}_{fname}_{lineno}",
        )

    @staticmethod
    def _make_title(sev: str, category: str, desc: str) -> str:
        short = desc[:60].rstrip(".,; ")
        return f"[{sev}] {category}: {short}"
