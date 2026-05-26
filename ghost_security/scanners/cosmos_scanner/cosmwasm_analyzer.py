"""
Ghost Security Platform — CosmWasm / Cosmos Security Scanner
Static analysis for CosmWasm smart contracts written in Rust.

Detects: unauthorized execute handlers, missing admin check in migration,
reentrancy via submessages, unbounded query/iteration, missing input
validation, unsafe math, IBC channel ordering assumptions, and missing
reply handler error cases.
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

_COSMOS_RULES: List[Dict] = [
    # ── GHOST-COS-001  Unauthorized execute message handler ───────────────
    {
        "rule_id": "GHOST-COS-001",
        "name": "Unauthorized execute message handler",
        "severity": "CRITICAL",
        "cwe": "CWE-284",
        "owasp": "A01:2021",
        "pattern": (
            r"ExecuteMsg::\w+\s*\{"
            r"(?![\s\S]{0,300}info\.sender\s*==)"
        ),
        "confidence": 0.75,
        "description": (
            "ExecuteMsg handler branch does not appear to verify info.sender "
            "against an admin or owner address. Any external caller can invoke "
            "this message and alter contract state."
        ),
        "fix": (
            "Add sender authorization at the top of sensitive execute branches: "
            "if info.sender != config.admin { "
            "return Err(ContractError::Unauthorized {}); }"
        ),
        "scanner": "cosmos_scanner",
        "multi": True,
    },

    # ── GHOST-COS-002  Missing admin check in migration ───────────────────
    {
        "rule_id": "GHOST-COS-002",
        "name": "Missing admin check in migrate entry point",
        "severity": "CRITICAL",
        "cwe": "CWE-284",
        "owasp": "A01:2021",
        "pattern": (
            r"pub\s+fn\s+migrate\s*\([^)]*\)\s*->\s*Result\s*<[^>]+>"
            r"(?![\s\S]{0,400}info\.sender)"
        ),
        "confidence": 0.80,
        "description": (
            "migrate() entry point does not verify that info.sender is the "
            "contract admin. Anyone who can trigger migration could upgrade "
            "to a malicious contract version."
        ),
        "fix": (
            "Verify admin at migration start: "
            "let config = CONFIG.load(deps.storage)?; "
            "if info.sender != config.admin { return Err(ContractError::Unauthorized {}); }"
        ),
        "scanner": "cosmos_scanner",
        "multi": True,
    },

    # ── GHOST-COS-003  Reentrancy via submessages ─────────────────────────
    {
        "rule_id": "GHOST-COS-003",
        "name": "Potential reentrancy via submessage with reply",
        "severity": "HIGH",
        "cwe": "CWE-841",
        "owasp": "A01:2021",
        "pattern": (
            r"SubMsg::(?:reply_on_success|reply_on_error|reply_always)\s*\("
            r"|\.add_submessage\s*\("
        ),
        "confidence": 0.72,
        "description": (
            "Submessage with reply callback detected. If the reply handler "
            "reads or writes state that the parent execution has already "
            "written, a cross-function reentrancy path exists via the "
            "CosmWasm submessage reply mechanism."
        ),
        "fix": (
            "Ensure all state writes are finalized before dispatching "
            "submessages. In reply handlers, re-load state fresh from storage "
            "rather than relying on cached values from the parent call."
        ),
        "scanner": "cosmos_scanner",
        "multi": False,
    },

    # ── GHOST-COS-004  Unbounded query/iteration ──────────────────────────
    {
        "rule_id": "GHOST-COS-004",
        "name": "Unbounded storage iteration (DoS risk)",
        "severity": "HIGH",
        "cwe": "CWE-400",
        "owasp": "A05:2021",
        "pattern": (
            r"\.range\s*\((?:deps\.storage|storage)[^)]*\)\s*\n?"
            r"(?:.*\n){0,3}.*\.collect\s*::<Vec"
            r"|items\s*\(\s*(?:deps\.storage|storage)\s*,\s*None\s*,\s*None"
        ),
        "confidence": 0.75,
        "description": (
            "Storage iterator is collected without a limit. If the map grows "
            "unboundedly, this query/execute will eventually hit the gas limit, "
            "causing a DoS for all users. Pagination is required."
        ),
        "fix": (
            "Add pagination: items.range(storage, start, end, order)"
            ".take(limit.unwrap_or(DEFAULT_LIMIT) as usize).collect(). "
            "Enforce a maximum limit constant (e.g., 30) to bound gas usage."
        ),
        "scanner": "cosmos_scanner",
        "multi": True,
    },

    # ── GHOST-COS-005  Missing input validation ───────────────────────────
    {
        "rule_id": "GHOST-COS-005",
        "name": "Missing input validation on message fields",
        "severity": "MEDIUM",
        "cwe": "CWE-20",
        "owasp": "A03:2021",
        "pattern": (
            r"msg\.\w+\s*(?:\.to_string\(\)|\.clone\(\)|\.as_str\(\))"
            r"(?![\s\S]{0,200}(?:is_empty|len\s*\(\)|validate|check))"
        ),
        "confidence": 0.65,
        "description": (
            "Message field is used directly without validation of length, "
            "format, or allowed values. Oversized inputs can inflate storage "
            "costs; malformed inputs may cause unexpected behavior."
        ),
        "fix": (
            "Validate all message fields before use: "
            "if msg.name.is_empty() || msg.name.len() > MAX_NAME_LEN { "
            "return Err(ContractError::InvalidInput {}); }"
        ),
        "scanner": "cosmos_scanner",
        "multi": True,
    },

    # ── GHOST-COS-006  Unsafe math without checked ops ────────────────────
    {
        "rule_id": "GHOST-COS-006",
        "name": "Unsafe arithmetic without checked operations",
        "severity": "HIGH",
        "cwe": "CWE-190",
        "owasp": "A02:2021",
        "pattern": (
            r"(?:u64|u128|Uint128|Uint256)\s*=\s*\w+\s*[+\-\*]\s*\w+"
            r"|\w+\s*\+=\s*\w+"
            r"|\w+\s*-=\s*\w+"
        ),
        "confidence": 0.65,
        "description": (
            "Arithmetic on numeric types without checked_add/checked_sub/checked_mul "
            "or CosmWasm's Uint128 safe methods. Integer overflow or underflow "
            "will panic in debug mode or wrap in release, corrupting balances."
        ),
        "fix": (
            "Use Uint128::checked_add(amount).ok_or(ContractError::Overflow {})? "
            "or cosmwasm_std Uint128 which uses checked math internally. "
            "Never use raw arithmetic on financial amounts."
        ),
        "scanner": "cosmos_scanner",
        "multi": False,
    },

    # ── GHOST-COS-007  IBC channel ordering assumptions ──────────────────
    {
        "rule_id": "GHOST-COS-007",
        "name": "IBC channel ordering assumption",
        "severity": "MEDIUM",
        "cwe": "CWE-20",
        "owasp": "A05:2021",
        "pattern": (
            r"IbcOrder::Ordered"
            r"|channel\.order\s*==\s*IbcOrder"
            r"|ibc_channel_open"
        ),
        "confidence": 0.70,
        "description": (
            "IBC channel open handler enforces a specific ordering "
            "(Ordered/Unordered) or hardcodes channel order. Changes in "
            "counterparty channel configuration can break packet delivery "
            "or cause packet replay if assumptions are violated."
        ),
        "fix": (
            "Validate channel order explicitly in ibc_channel_open and return "
            "IbcChannelOpenResponse with confirmed channel order. Document "
            "why the order is required and test both orderings if applicable."
        ),
        "scanner": "cosmos_scanner",
        "multi": False,
    },

    # ── GHOST-COS-008  Reply handler missing error cases ──────────────────
    {
        "rule_id": "GHOST-COS-008",
        "name": "Reply handler missing error case handling",
        "severity": "HIGH",
        "cwe": "CWE-754",
        "owasp": "A05:2021",
        "pattern": (
            r"pub\s+fn\s+reply\s*\([^)]*\)\s*->\s*Result\s*<[^>]+>"
            r"(?![\s\S]{0,600}SubMsgResult::Err)"
        ),
        "confidence": 0.75,
        "description": (
            "Reply handler does not appear to handle the SubMsgResult::Err "
            "case. If a submessage fails and the handler only handles success, "
            "the reply entry point will panic or return an unintended error, "
            "potentially leaving the contract in an inconsistent state."
        ),
        "fix": (
            "Handle both reply outcomes: match msg.result { "
            "SubMsgResult::Ok(res) => { /* handle success */ }, "
            "SubMsgResult::Err(err) => { /* rollback or log */ } }"
        ),
        "scanner": "cosmos_scanner",
        "multi": True,
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_rust_comments(source: str) -> Tuple[str, List[str]]:
    original_lines = source.splitlines()
    no_block = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group().count("\n"), source, flags=re.DOTALL)
    cleaned = "\n".join(re.sub(r"//.*$", "", line) for line in no_block.splitlines())
    return cleaned, original_lines


def _make_finding(rule: Dict, file_path: str, lineno: int, evidence: str) -> Dict:
    return {
        "rule_id": rule["rule_id"],
        "name": rule["name"],
        "severity": rule["severity"],
        "file": str(file_path),
        "line": lineno,
        "column": 0,
        "description": rule["description"],
        "cwe": rule["cwe"],
        "owasp": rule.get("owasp", ""),
        "fix": rule["fix"],
        "confidence": rule["confidence"],
        "scanner": rule["scanner"],
        "evidence": evidence[:160],
    }


# ---------------------------------------------------------------------------
# CosmosScanner
# ---------------------------------------------------------------------------

class CosmosScanner:
    """
    Static security analyzer for CosmWasm smart contracts (.rs files).

    Usage::

        scanner = CosmosScanner()
        findings = scanner.scan_file("/path/to/contract.rs")
        result   = scanner.scan_directory("/path/to/contracts/")
    """

    def __init__(self) -> None:
        self._compiled: List[Dict] = []
        for rule in _COSMOS_RULES:
            flags = re.MULTILINE | re.DOTALL if rule.get("multi") else re.MULTILINE
            try:
                pat = re.compile(rule["pattern"], flags)
            except re.error:
                pat = re.compile(re.escape(rule["pattern"]), flags)
            self._compiled.append({**rule, "_compiled": pat})

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_file(self, path: str) -> List[Dict]:
        """Scan a single Rust file and return findings."""
        p = Path(path)
        if p.suffix.lower() != ".rs":
            return []
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        cleaned, original_lines = _strip_rust_comments(raw)
        findings: List[Dict] = []
        seen: set = set()

        for rule in self._compiled:
            if rule.get("multi"):
                for m in rule["_compiled"].finditer(cleaned):
                    lineno = cleaned[: m.start()].count("\n") + 1
                    key = (rule["rule_id"], lineno)
                    if key in seen:
                        continue
                    seen.add(key)
                    evidence = (original_lines[lineno - 1] if lineno <= len(original_lines) else "").strip()
                    findings.append(_make_finding(rule, p, lineno, evidence))
            else:
                for lineno, line in enumerate(cleaned.splitlines(), 1):
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if rule["_compiled"].search(stripped):
                        key = (rule["rule_id"], lineno)
                        if key in seen:
                            continue
                        seen.add(key)
                        orig = (original_lines[lineno - 1] if lineno <= len(original_lines) else "").strip()
                        findings.append(_make_finding(rule, p, lineno, orig))

        return findings

    def scan_directory(self, path: str) -> Dict:
        """Recursively scan a directory for CosmWasm contract Rust files.

        Returns::

            {
                "findings": [...],
                "files_scanned": N,
                "total_findings": N,
                "severity_counts": {...},
            }
        """
        root = Path(path)
        all_findings: List[Dict] = []
        files_scanned = 0
        severity_counts: Dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        }

        for file in root.rglob("*.rs"):
            if ".git" in file.parts or "target" in file.parts:
                continue
            file_findings = self.scan_file(str(file))
            all_findings.extend(file_findings)
            files_scanned += 1
            for f in file_findings:
                sev = f.get("severity", "INFO")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "findings": all_findings,
            "files_scanned": files_scanned,
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
        }
