"""
TythanAI Platform — TON Contract Graph & Upgradeability Analyzer
Builds contract interaction graph and detects:
  • upgradeability risks (set_code, replace_code)
  • admin/ownership patterns
  • cross-contract call chains
  • replay-risk surfaces
  • privilege escalation paths
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ── Patterns ───────────────────────────────────────────────────────────────────
_UPGRADE_PATTERNS = [
    (re.compile(r"\bset_code\s*\("),        "CRITICAL", "Direct set_code call — contract can be fully replaced"),
    (re.compile(r"\bset_c5\s*\("),          "CRITICAL", "set_c5 (code cell) — upgradeability vector"),
    (re.compile(r"\baccept_message\s*\(.*?set_code", re.DOTALL), "CRITICAL", "Upgrade inside accept_message"),
    (re.compile(r"migrate\s*\("),           "HIGH",     "Migration function — verify access control"),
    (re.compile(r"upgrade\s*\("),           "HIGH",     "Upgrade function — verify access control"),
]

_OWNERSHIP_PATTERNS = [
    (re.compile(r"\bowner\b.*?="),          "INFO",  "owner field assignment"),
    (re.compile(r"\badmin\b.*?="),          "INFO",  "admin field assignment"),
    (re.compile(r"throw_unless\s*\(\s*\d+\s*,\s*equal_slices"), "MEDIUM", "Access control via equal_slices"),
    (re.compile(r"op::transfer_ownership"), "HIGH",  "Ownership transfer operation"),
]

_REPLAY_PATTERNS = [
    (re.compile(r"\bquery_id\b"),           "LOW",   "query_id field present"),
    (re.compile(r"\bget_seqno\b|\bseqno\b"),"MEDIUM","seqno check — verify replay protection"),
    (re.compile(r"valid_until"),            "LOW",   "valid_until — replay window"),
    (re.compile(r"cell_hash.*seqno", re.DOTALL), "HIGH", "seqno stored in cell — verify increment"),
]

_CROSS_CONTRACT = [
    (re.compile(r"\bsend_raw_message\s*\("), "INFO", "send_raw_message — outgoing message"),
    (re.compile(r"\bsend_message\s*\("),     "INFO", "send_message — outgoing message"),
    (re.compile(r"in_msg_body.*?op\s*=="),   "INFO", "Op-code dispatch — message routing"),
]

_PRIVILEGE_ESCALATION = [
    (re.compile(r"op::admin|op::sudo|op::root", re.IGNORECASE), "HIGH",     "Privileged op-code"),
    (re.compile(r"force_chain|force_workchain"),                  "MEDIUM",  "Chain-force — verify sender"),
    (re.compile(r"load_data\(\).*?owner", re.DOTALL),            "MEDIUM",  "Owner loaded from persistent storage"),
]


@dataclass
class ContractNode:
    name:     str
    path:     str
    size_bytes: int = 0
    sends_to: List[str]       = field(default_factory=list)   # other contracts addressed
    findings: List[dict]      = field(default_factory=list)
    has_upgrade:  bool        = False
    has_ownership: bool       = False
    replay_risk:  str         = "UNKNOWN"  # LOW/MEDIUM/HIGH

    def to_dict(self) -> dict:
        return {
            "name":         self.name,
            "path":         self.path,
            "size_bytes":   self.size_bytes,
            "sends_to":     self.sends_to,
            "has_upgrade":  self.has_upgrade,
            "has_ownership":self.has_ownership,
            "replay_risk":  self.replay_risk,
            "findings_count": len(self.findings),
        }


class TONContractGraph:
    """
    Analyse a directory of TON smart contracts (.fc/.func/.tact):
    1. Build a contract interaction graph
    2. Detect upgradeability patterns
    3. Detect ownership/admin patterns
    4. Detect replay-risk surfaces
    5. Identify privilege escalation paths
    """

    _EXTENSIONS = {".fc", ".func", ".tact"}

    def analyze(self, path: str) -> dict:
        root = Path(path)
        if root.is_file():
            files = [root]
        else:
            files = [
                f for f in root.rglob("*")
                if f.suffix in self._EXTENSIONS
            ]

        nodes: Dict[str, ContractNode] = {}
        all_findings: List[dict] = []

        for fpath in files:
            try:
                code = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            node = ContractNode(
                name=fpath.stem,
                path=str(fpath),
                size_bytes=len(code.encode()),
            )

            # Run all detectors
            node.findings += self._detect(code, fpath.stem, str(fpath), _UPGRADE_PATTERNS, "upgradeability")
            node.findings += self._detect(code, fpath.stem, str(fpath), _OWNERSHIP_PATTERNS, "ownership")
            node.findings += self._detect(code, fpath.stem, str(fpath), _REPLAY_PATTERNS, "replay")
            node.findings += self._detect(code, fpath.stem, str(fpath), _CROSS_CONTRACT, "cross_contract")
            node.findings += self._detect(code, fpath.stem, str(fpath), _PRIVILEGE_ESCALATION, "privilege")

            # Flags
            node.has_upgrade  = any(f["category"] == "upgradeability" and f["severity"] in ("CRITICAL","HIGH") for f in node.findings)
            node.has_ownership = any(f["category"] == "ownership" for f in node.findings)

            # Replay risk assessment
            replay_findings = [f for f in node.findings if f["category"] == "replay"]
            seqno_present = any("seqno" in f["message"].lower() for f in replay_findings)
            query_id_present = any("query_id" in f["message"].lower() for f in replay_findings)
            if seqno_present and query_id_present:
                node.replay_risk = "LOW"
            elif seqno_present or query_id_present:
                node.replay_risk = "MEDIUM"
            elif replay_findings:
                node.replay_risk = "HIGH"
            else:
                node.replay_risk = "UNKNOWN"

            # Detect send targets (addresses hardcoded or from storage)
            node.sends_to = self._detect_send_targets(code)

            nodes[node.name] = node
            all_findings.extend(node.findings)

        # Build edge list for graph visualization
        edges = []
        for name, node in nodes.items():
            for target in node.sends_to:
                if target in nodes:
                    edges.append({"from": name, "to": target, "type": "message"})

        # Risk ranking
        risk_ranking = sorted(
            nodes.values(),
            key=lambda n: (
                -sum(1 for f in n.findings if f["severity"] == "CRITICAL"),
                -sum(1 for f in n.findings if f["severity"] == "HIGH"),
                -len(n.findings),
            )
        )

        return {
            "contracts_analyzed": len(nodes),
            "total_findings":     len(all_findings),
            "nodes":              [n.to_dict() for n in nodes.values()],
            "edges":              edges,
            "findings":           all_findings,
            "risk_ranking":       [{"name": n.name, "findings": len(n.findings)} for n in risk_ranking],
            "severity_counts":    self._sev_counts(all_findings),
            "upgrade_risk_contracts": [n.name for n in nodes.values() if n.has_upgrade],
            "high_replay_risk":   [n.name for n in nodes.values() if n.replay_risk in ("HIGH", "MEDIUM")],
            "graph_summary": {
                "nodes": len(nodes),
                "edges": len(edges),
                "isolated": [n.name for n in nodes.values() if not n.sends_to],
            },
        }

    # ── Internal ───────────────────────────────────────────────────────────────

    def _detect(
        self,
        code: str,
        contract: str,
        filepath: str,
        patterns: list,
        category: str,
    ) -> List[dict]:
        findings = []
        for pattern, severity, message in patterns:
            for m in pattern.finditer(code):
                lineno = code[:m.start()].count("\n") + 1
                snippet = code[max(0, m.start()-30):m.end()+60].strip()[:120]
                findings.append({
                    "rule_id":   f"TON-{category.upper()[:3]}-{len(findings)+1:03d}",
                    "severity":  severity,
                    "message":   message,
                    "category":  category,
                    "contract":  contract,
                    "file":      filepath,
                    "line":      lineno,
                    "evidence":  snippet,
                    "scanner":   "ton_contract_graph",
                })
        return findings

    @staticmethod
    def _detect_send_targets(code: str) -> List[str]:
        """Extract contract names referenced in send_raw_message / send_message calls."""
        targets = []
        # Look for variable names that look like contract references
        for m in re.finditer(r"(?:send_raw_message|send_message)\s*\(\s*(\w+)", code):
            var = m.group(1)
            # Exclude generic vars
            if var not in ("msg", "message", "body", "cell", "slice", "builder"):
                targets.append(var)
        return list(dict.fromkeys(targets))

    @staticmethod
    def _sev_counts(findings: List[dict]) -> dict:
        counts: dict = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1
        return counts
