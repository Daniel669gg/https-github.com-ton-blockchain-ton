"""
TythanAI Platform — Polkadot / ink! Security Scanner
Static analysis for ink! smart contracts (.rs files with ink! attributes).

Detects: missing constructor access control, unchecked arithmetic,
missing caller() validation, storage key collision risk, missing payable
annotation, unsafe unwrap(), and cross-contract call error handling gaps.
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

_INK_RULES: List[Dict] = [
    # ── GHOST-INK-001  Missing constructor access control ─────────────────
    {
        "rule_id": "GHOST-INK-001",
        "name": "Missing access control in ink! constructor",
        "severity": "HIGH",
        "cwe": "CWE-284",
        "owasp": "A01:2021",
        "pattern": (
            r"#\[ink\(constructor\)\]"
            r"(?![\s\S]{0,400}Self::env\(\)\.caller\(\))"
        ),
        "confidence": 0.78,
        "description": (
            "ink! constructor does not record or validate the caller. "
            "Without storing the deployer as owner, subsequent messages "
            "have no privileged authority to check against, leaving the "
            "contract open to unauthorized administration."
        ),
        "fix": (
            "Store the deployer at construction time: "
            "let caller = Self::env().caller(); "
            "Self { owner: caller, ... } "
            "Then verify in sensitive messages: "
            "assert_eq!(self.env().caller(), self.owner, 'Unauthorized');"
        ),
        "scanner": "polkadot_scanner",
        "multi": True,
    },

    # ── GHOST-INK-002  Unchecked arithmetic ───────────────────────────────
    {
        "rule_id": "GHOST-INK-002",
        "name": "Unchecked arithmetic in ink! contract",
        "severity": "HIGH",
        "cwe": "CWE-190",
        "owasp": "A02:2021",
        "pattern": (
            r"\bself\.\w+\s*[+\-\*]=\s*\w+"
            r"|\b(?:u64|u128|Balance)\s+\w+\s*=\s*\w+\s*[+\-\*]\s*\w+"
        ),
        "confidence": 0.68,
        "description": (
            "Arithmetic operation in ink! contract does not use checked_add, "
            "checked_sub, or checked_mul. ink! contracts compiled with "
            "overflow-checks = false (production builds) will silently wrap, "
            "enabling balance manipulation."
        ),
        "fix": (
            "Use checked arithmetic: "
            "self.balance = self.balance.checked_add(amount)"
            ".ok_or(Error::Overflow)?; "
            "Ensure Cargo.toml has overflow-checks = true in release profile."
        ),
        "scanner": "polkadot_scanner",
        "multi": False,
    },

    # ── GHOST-INK-003  Missing caller() validation ────────────────────────
    {
        "rule_id": "GHOST-INK-003",
        "name": "Missing caller() validation in ink! message",
        "severity": "CRITICAL",
        "cwe": "CWE-284",
        "owasp": "A01:2021",
        "pattern": (
            r"#\[ink\(message\)\]"
            r"(?![\s\S]{0,500}(?:self\.env\(\)\.caller\(\)|ensure_owner|only_owner|caller\s*==|assert_eq!))"
        ),
        "confidence": 0.70,
        "description": (
            "ink! message handler does not appear to validate the caller. "
            "State-changing messages that skip caller verification can be "
            "invoked by any account, bypassing access control."
        ),
        "fix": (
            "Validate caller at the start of sensitive messages: "
            "let caller = self.env().caller(); "
            "if caller != self.owner { return Err(Error::Unauthorized); }"
        ),
        "scanner": "polkadot_scanner",
        "multi": True,
    },

    # ── GHOST-INK-004  Storage key collision risk ─────────────────────────
    {
        "rule_id": "GHOST-INK-004",
        "name": "Storage key collision risk",
        "severity": "MEDIUM",
        "cwe": "CWE-119",
        "owasp": "A02:2021",
        "pattern": (
            r"#\[ink\(storage\)\]"
            r"[\s\S]{0,1000}"
            r"Lazy\s*<"
            r"|StorageVec\s*<"
            r"|Mapping\s*<"
        ),
        "confidence": 0.65,
        "description": (
            "ink! storage struct uses Lazy, StorageVec, or Mapping types. "
            "Adding, removing, or reordering these fields in contract upgrades "
            "changes storage layout and can cause key collisions with existing "
            "on-chain data, corrupting state."
        ),
        "fix": (
            "Use explicit storage keys: #[ink(storage_key = 0x...)] to "
            "pin each field to a stable key. Document storage layout and "
            "treat it as a public ABI — never reorder or remove fields."
        ),
        "scanner": "polkadot_scanner",
        "multi": True,
    },

    # ── GHOST-INK-005  Missing payable on transfer handler ────────────────
    {
        "rule_id": "GHOST-INK-005",
        "name": "Missing payable annotation on transfer/deposit handler",
        "severity": "MEDIUM",
        "cwe": "CWE-754",
        "owasp": "A05:2021",
        "pattern": (
            r"#\[ink\(message\)\]\s*\n"
            r"(?:.*\n){0,3}"
            r"(?:pub\s+fn\s+(?:deposit|receive|pay|fund|transfer_in))"
        ),
        "confidence": 0.72,
        "description": (
            "A function named deposit/receive/pay/fund does not have the "
            "#[ink(message, payable)] annotation. Without payable, the "
            "function will reject any transferred value, breaking fund "
            "receipt functionality."
        ),
        "fix": (
            "Add the payable flag: #[ink(message, payable)] "
            "pub fn deposit(&mut self) -> Result<(), Error> { "
            "let received = self.env().transferred_value(); ... }"
        ),
        "scanner": "polkadot_scanner",
        "multi": True,
    },

    # ── GHOST-INK-006  Unsafe unwrap() in ink! code ───────────────────────
    {
        "rule_id": "GHOST-INK-006",
        "name": "Unsafe unwrap() call in ink! contract",
        "severity": "HIGH",
        "cwe": "CWE-754",
        "owasp": "A05:2021",
        "pattern": r"\.unwrap\s*\(\s*\)",
        "confidence": 0.75,
        "description": (
            "unwrap() panics on None or Err, causing the entire transaction "
            "to revert with an uninformative error. In ink! contracts, panics "
            "are expensive and provide no structured error information to callers."
        ),
        "fix": (
            "Replace unwrap() with explicit error handling: "
            ".ok_or(Error::NotFound)? or .unwrap_or_default(). "
            "Define an Error enum and propagate errors via ? operator."
        ),
        "scanner": "polkadot_scanner",
        "multi": False,
    },

    # ── GHOST-INK-007  Cross-contract call without error handling ─────────
    {
        "rule_id": "GHOST-INK-007",
        "name": "Cross-contract call without error handling",
        "severity": "HIGH",
        "cwe": "CWE-252",
        "owasp": "A05:2021",
        "pattern": (
            r"build_call\s*::<\s*\w+\s*>"
            r"|\.call_v1\s*\("
            r"|CallBuilder::\w+"
            r"(?![\s\S]{0,300}(?:\?\s*;|\.map_err|match\s))"
        ),
        "confidence": 0.72,
        "description": (
            "Cross-contract call via ink! CallBuilder does not appear to "
            "propagate or handle errors. If the callee reverts, the caller "
            "may continue with stale state unless the error is checked."
        ),
        "fix": (
            "Use the ? operator or match on the result: "
            "let result = build_call::<E>().call(callee).invoke(); "
            "result.map_err(|_| Error::CallFailed)?"
        ),
        "scanner": "polkadot_scanner",
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


def _is_ink_file(content: str) -> bool:
    """Heuristic: check whether the file uses ink! macros."""
    return bool(re.search(r"#\[ink\s*(?:::\s*contract|\(contract\))\]|ink::contract", content))


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
# PolkadotScanner
# ---------------------------------------------------------------------------

class PolkadotScanner:
    """
    Static security analyzer for Polkadot / ink! smart contracts (.rs files).

    Usage::

        scanner = PolkadotScanner()
        findings = scanner.scan_file("/path/to/lib.rs")
        result   = scanner.scan_directory("/path/to/contract/")
    """

    def __init__(self) -> None:
        self._compiled: List[Dict] = []
        for rule in _INK_RULES:
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
        """Scan a single Rust file for ink! vulnerabilities."""
        p = Path(path)
        if p.suffix.lower() != ".rs":
            return []
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        # Only scan files that actually use ink!
        if not _is_ink_file(raw):
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
        """Recursively scan a directory for ink! contract Rust files.

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
            if file_findings or _is_ink_file(
                file.read_text(encoding="utf-8", errors="replace")
            ):
                files_scanned += 1
            all_findings.extend(file_findings)
            for f in file_findings:
                sev = f.get("severity", "INFO")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "findings": all_findings,
            "files_scanned": files_scanned,
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
        }
