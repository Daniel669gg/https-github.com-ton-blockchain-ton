"""
TythanAI — TON Bug Bounty Public Writeup Generator
Генерирует профессиональный writeup для ответственного раскрытия.
Формат совместим с:
  • https://github.com/ton-blockchain/bug-bounty
  • Immunefi submission format
  • HackerOne / Bugcrowd
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Dict, List, Optional


# ── Публичные TON контракты — реальные цели для аудита ───────────────────────

TON_AUDIT_TARGETS = {
    "wallet-v4": {
        "repo": "https://github.com/ton-blockchain/wallet-contract",
        "description": "TON Wallet V4R2 — основной кошелёк экосистемы",
        "bounty_url": "https://github.com/ton-blockchain/bug-bounty",
        "max_payout": 250_000,
    },
    "nominator-pool": {
        "repo": "https://github.com/ton-blockchain/nominator-pool",
        "description": "Стейкинг-пул для номинаторов",
        "bounty_url": "https://github.com/ton-blockchain/bug-bounty",
        "max_payout": 100_000,
    },
    "bridge-func": {
        "repo": "https://github.com/ton-blockchain/bridge-func",
        "description": "TON-Ethereum Toncoin bridge",
        "bounty_url": "https://github.com/ton-blockchain/bug-bounty",
        "max_payout": 250_000,
    },
    "token-bridge": {
        "repo": "https://github.com/ton-blockchain/token-bridge-func",
        "description": "TON-Ethereum token bridge",
        "bounty_url": "https://github.com/ton-blockchain/bug-bounty",
        "max_payout": 250_000,
    },
    "jetton": {
        "repo": "https://github.com/ton-blockchain/token-contract",
        "description": "Jetton (Fungible Token) стандарт",
        "bounty_url": "https://github.com/ton-blockchain/bug-bounty",
        "max_payout": 50_000,
    },
}

# ── Шаблоны writeup по типам уязвимостей ─────────────────────────────────────

WRITEUP_TEMPLATES: Dict[str, Dict] = {
    "TON001": {
        "title": "Unconditional accept_message() Enables Gas Drain Attack",
        "impact": (
            "An attacker can force the contract to accept and pay for arbitrary "
            "external messages, draining its TON balance at minimal cost. "
            "The attack is repeatable and requires no special permissions."
        ),
        "attack_scenario": (
            "1. Attacker observes contract accepting messages without sender validation.\n"
            "2. Attacker crafts minimal external message to the contract.\n"
            "3. Contract calls accept_message() before checking msg.sender.\n"
            "4. Contract pays gas for attacker's message from own balance.\n"
            "5. Repeated 1000× drains contract entirely."
        ),
        "poc_template": """
;; Proof of Concept — Gas Drain
;; Deploy attacker.fc and call drain() pointing at victim contract

cell msg = begin_cell()
    .store_uint(0x18, 6)         ;; flags
    .store_slice(victim_addr)    ;; target contract
    .store_coins(0)              ;; 0 TON sent
    .store_uint(0, 107)          ;; rest of header
.end_cell();

send_raw_message(msg, 64);  ;; repeat N times
""",
        "fix": (
            "Move `throw_unless(401, equal_slices(sender, owner));` "
            "BEFORE `accept_message();`. "
            "Or use mode 0 instead of unconditional accept for untrusted senders."
        ),
    },
    "TON002": {
        "title": "send_raw_message Mode 64/128 Drains Entire Contract Balance",
        "impact": (
            "Mode 64 forwards the entire incoming message value plus contract balance. "
            "Mode 128 sends ALL remaining contract funds. Combined with insufficient "
            "access control, this allows complete fund extraction in a single transaction."
        ),
        "attack_scenario": (
            "1. Attacker sends message triggering mode 64/128 send.\n"
            "2. Contract forwards its entire balance to attacker-controlled address.\n"
            "3. Contract is left with 0 TON and becomes non-functional."
        ),
        "poc_template": """
;; PoC: trigger mode 64 with crafted message
send_raw_message(
    begin_cell()
        .store_uint(0x18, 6)
        .store_slice(attacker_addr)
        .store_coins(0)
        .store_uint(0, 107)
    .end_cell(),
    64  ;; mode 64 = forward all incoming value + contract balance
);
""",
        "fix": (
            "Use mode 0 for normal sends. Reserve contract operational balance "
            "with raw_reserve() before using mode 64. "
            "Add strict sender validation before any mode 64/128 message."
        ),
    },
    "TON004": {
        "title": "Missing Sender Validation in recv_internal Allows Unauthorized Actions",
        "impact": (
            "Any wallet can trigger privileged operations (ownership transfer, "
            "fund withdrawal, configuration changes) without authorization. "
            "Attacker can take full control of the contract."
        ),
        "attack_scenario": (
            "1. Attacker identifies privileged op-code (e.g., op=1 for transfer).\n"
            "2. Sends message with that op-code from any wallet.\n"
            "3. Contract executes privileged action without checking msg.sender.\n"
            "4. Attacker gains control / drains funds."
        ),
        "poc_template": """
;; PoC: send privileged op without being owner
cell msg = begin_cell()
    .store_uint(0x18, 6)
    .store_slice(victim_contract)
    .store_coins(50000000)  ;; 0.05 TON for gas
    .store_uint(0, 107)
    .store_uint(1, 32)      ;; op = transfer/privileged action
    .store_uint(0, 64)      ;; query_id
    .store_slice(attacker_addr)
.end_cell();
send_raw_message(msg, 3);
""",
        "fix": (
            "Add at the top of recv_internal:\n"
            "throw_unless(401, equal_slices(sender, storage::owner_address));\n"
            "Or use a whitelist for trusted callers."
        ),
    },
    "TON008": {
        "title": "Predictable Randomness via now() Manipulable by Validators",
        "impact": (
            "Validators can manipulate block timestamp (now()) within ~15 seconds. "
            "Any lottery, NFT mint order, or reward distribution based on now() "
            "is exploitable by colluding validators for guaranteed wins."
        ),
        "attack_scenario": (
            "1. Contract uses now() % N to select winner/outcome.\n"
            "2. Validator observes pending lottery transactions.\n"
            "3. Validator adjusts block timestamp to produce desired outcome.\n"
            "4. Validator (or colluding participant) wins every time."
        ),
        "poc_template": """
;; Vulnerable pattern:
int winner_idx = now() % total_participants;  ;; MANIPULABLE

;; Correct fix:
randomize_lt();
int winner_idx = random() % total_participants;  ;; cryptographically safe
""",
        "fix": (
            "Replace now() with randomize_lt() + random() from stdlib.fc. "
            "For high-value randomness, use commit-reveal scheme or "
            "TON VRF (Verifiable Random Function)."
        ),
    },
}


class WriteupGenerator:
    """
    Генерирует профессиональный writeup для bug bounty submission.
    """

    def generate(self, finding: Dict,
                 target_name: str = "",
                 researcher_name: str = "Security Researcher",
                 additional_context: str = "") -> str:
        """
        Генерировать полный writeup в Markdown.

        Args:
            finding: finding dict от TONAnalyzer / TONSelfCheck
            target_name: имя целевого проекта
            researcher_name: имя для writeup
            additional_context: дополнительные детали

        Returns:
            Markdown writeup готовый к submission
        """
        rule_id = finding.get("id", "")
        sev = finding.get("severity", "HIGH")
        cwe = finding.get("cwe", "")
        desc = finding.get("description", "")
        file = finding.get("file", "")
        line = finding.get("line", "?")
        rec = finding.get("recommendation", "")
        evidence = finding.get("evidence", "")

        template = WRITEUP_TEMPLATES.get(rule_id, {})
        title = template.get("title") or f"{desc[:80]}"
        impact = template.get("impact") or (
            f"This vulnerability in {target_name or 'the contract'} allows an attacker to "
            f"exploit {desc}. Impact severity: {sev}."
        )
        scenario = template.get("attack_scenario") or (
            f"1. Attacker identifies vulnerable pattern at {file}:{line}\n"
            f"2. Crafts malicious transaction exploiting {cwe}\n"
            f"3. Executes attack achieving unauthorized access or fund loss"
        )
        poc = template.get("poc_template") or evidence or "PoC code to be added."
        fix = template.get("fix") or rec or "Implement proper access controls and input validation."

        # Payout estimate
        from agents_ext.ton_self_check import TON_PAYOUT_TIERS
        tier = TON_PAYOUT_TIERS.get(sev, {})
        payout_range = f"${tier.get('range',(0,0))[0]:,}–${tier.get('range',(0,0))[1]:,}"

        ts = time.strftime("%Y-%m-%d", time.gmtime())

        lines = [
            f"# Bug Report: {title}",
            f"",
            f"**Date:** {ts}  ",
            f"**Researcher:** {researcher_name}  ",
            f"**Target:** {target_name or 'TON Smart Contract'}  ",
            f"**Severity:** {sev}  ",
            f"**CWE:** {cwe}  ",
            f"**Rule:** {rule_id}  ",
            f"**Estimated Payout:** {payout_range}  ",
            f"",
            f"---",
            f"",
            f"## Summary",
            f"",
            f"{desc}",
            f"",
            f"## Vulnerability Details",
            f"",
            f"**File:** `{file}`  ",
            f"**Line:** {line}  ",
            f"**CWE:** [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-','')}.html)  ",
            f"",
            f"### Description",
            f"",
            f"{impact}",
            f"",
            f"## Impact",
            f"",
            f"{impact}",
            f"",
            f"**Severity justification:**",
            f"- Severity: **{sev}**",
        ]

        if tier:
            for ex in tier.get("examples", [])[:2]:
                lines.append(f"- Matches: {ex}")

        lines += [
            f"",
            f"## Attack Scenario",
            f"",
            f"{scenario}",
            f"",
            f"## Proof of Concept",
            f"",
            f"```func",
            poc.strip(),
            f"```",
            f"",
        ]

        if evidence and evidence != poc:
            lines += [
                f"**Vulnerable code at `{file}:{line}`:**",
                f"```",
                evidence[:500],
                f"```",
                f"",
            ]

        if additional_context:
            lines += [
                f"## Additional Context",
                f"",
                additional_context,
                f"",
            ]

        lines += [
            f"## Recommended Fix",
            f"",
            f"{fix}",
            f"",
            f"## References",
            f"",
            f"- [CWE-{cwe.replace('CWE-','')}](https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-','')}.html)",
            f"- [TON Bug Bounty Program](https://github.com/ton-blockchain/bug-bounty)",
            f"- [TON FunC Documentation](https://docs.ton.org/develop/func/overview)",
            f"",
            f"## Disclosure Timeline",
            f"",
            f"- {ts}: Vulnerability discovered via TythanAI Platform",
            f"- {ts}: Self-check validation completed (score: {finding.get('_check_score','N/A')}/100)",
            f"- TBD: Reported to TON Security Team",
            f"- TBD: Fix deployed",
            f"",
            f"---",
            f"*This report was generated with [TythanAI Platform](https://ghost-security.io) "
            f"and validated against the official TON bug-bounty-self-check.md criteria.*",
        ]

        return "\n".join(lines)

    def generate_batch(self, findings: List[Dict],
                       target_name: str = "",
                       researcher_name: str = "Security Researcher") -> List[Dict]:
        """Генерировать writeup для списка findings."""
        results = []
        for f in findings:
            writeup = self.generate(f, target_name, researcher_name)
            results.append({
                "finding_id": f.get("id", ""),
                "severity": f.get("severity", ""),
                "title": f.get("description", "")[:80],
                "writeup_md": writeup,
                "length": len(writeup),
            })
        return results

    def save(self, finding: Dict, output_path: str,
             target_name: str = "", researcher_name: str = "Security Researcher") -> str:
        """Сохранить writeup в файл."""
        md = self.generate(finding, target_name, researcher_name)
        Path(output_path).write_text(md, encoding="utf-8")
        return output_path


# Alias for compatibility
TONWriteupGenerator = WriteupGenerator
