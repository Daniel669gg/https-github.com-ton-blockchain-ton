"""
TythanAI Platform — Solana / Anchor Security Scanner
Static analysis for Solana programs written in Rust with the Anchor framework.

Detects: missing signer checks, missing owner checks, PDA seed manipulation,
arithmetic overflow/underflow, unchecked CPI return values, account discriminator
bypass, missing account constraints, unsafe deserialization, integer truncation,
missing rent exemption, and reinitialization attacks.
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

_SOLANA_RULES: List[Dict] = [
    # ── GHOST-SOL-001  Missing signer check ───────────────────────────────
    {
        "rule_id": "GHOST-SOL-001",
        "name": "Missing signer check on account",
        "severity": "CRITICAL",
        "cwe": "CWE-284",
        "owasp": "A01:2021",
        "pattern": (
            r"pub\s+\w+\s*:\s*AccountInfo\s*<\s*'info\s*>"
            r"(?![\s\S]{0,200}is_signer)"
        ),
        "confidence": 0.78,
        "description": (
            "An AccountInfo account is used without verifying account.is_signer. "
            "Without this check, any account can be passed as a signer, "
            "allowing unauthorized instruction execution."
        ),
        "fix": (
            "In Anchor, use Signer<'info> type instead of AccountInfo for "
            "accounts that must be signers. In native programs, explicitly check: "
            "if !account.is_signer { return Err(ProgramError::MissingRequiredSignature); }"
        ),
        "scanner": "solana_scanner",
        "multi": True,
    },

    # ── GHOST-SOL-002  Missing owner check ────────────────────────────────
    {
        "rule_id": "GHOST-SOL-002",
        "name": "Missing account owner check",
        "severity": "HIGH",
        "cwe": "CWE-284",
        "owasp": "A01:2021",
        "pattern": (
            r"AccountInfo\s*<\s*'info\s*>(?![\s\S]{0,300}owner\s*==)"
        ),
        "confidence": 0.72,
        "description": (
            "Account is accepted without verifying its owner program. "
            "An attacker can supply an account owned by a different program "
            "that happens to have matching data layout, causing incorrect "
            "state reads or writes."
        ),
        "fix": (
            "Check account.owner == &expected_program_id before use. "
            "In Anchor, use Account<'info, T> which automatically checks owner. "
            "Or add #[account(owner = expected_program_id)] constraint."
        ),
        "scanner": "solana_scanner",
        "multi": True,
    },

    # ── GHOST-SOL-003  PDA seed manipulation ──────────────────────────────
    {
        "rule_id": "GHOST-SOL-003",
        "name": "PDA seed manipulation vulnerability",
        "severity": "HIGH",
        "cwe": "CWE-20",
        "owasp": "A03:2021",
        "pattern": (
            r"find_program_address\s*\(&\[(?:[^]]*\buser_provided\b[^]]*"
            r"|[^]]*ctx\.accounts\.\w+\.key\(\)[^]]*"
            r"|[^]]*&args\.\w+[^]]*)\]"
        ),
        "confidence": 0.70,
        "description": (
            "PDA seeds include user-controlled input without canonical bump "
            "verification. An attacker may derive a PDA for a different account "
            "by manipulating seed components, bypassing access controls."
        ),
        "fix": (
            "Always use and verify the canonical bump seed returned by "
            "find_program_address. In Anchor, use seeds and bump constraints: "
            "#[account(seeds = [b'prefix', user.key().as_ref()], bump)]"
        ),
        "scanner": "solana_scanner",
        "multi": True,
    },

    # ── GHOST-SOL-004  Arithmetic overflow/underflow ──────────────────────
    {
        "rule_id": "GHOST-SOL-004",
        "name": "Arithmetic overflow/underflow without checked operations",
        "severity": "HIGH",
        "cwe": "CWE-190",
        "owasp": "A02:2021",
        "pattern": (
            r"(?:u64|u128|i64|i128|u32|i32|u8)\s+\w+\s*=\s*\w+\s*[+\-\*]\s*\w+"
            r"|\w+\s*\+=\s*\w+(?!.*checked_add)"
            r"|\w+\s*-=\s*\w+(?!.*checked_sub)"
            r"|\w+\s*\*=\s*\w+(?!.*checked_mul)"
        ),
        "confidence": 0.68,
        "description": (
            "Arithmetic operation on integer type without using checked_add, "
            "checked_sub, or checked_mul. In release builds Rust integer "
            "overflow/underflow wraps silently (in debug it panics), which "
            "can corrupt account balances."
        ),
        "fix": (
            "Use checked arithmetic: amount.checked_add(fee).ok_or(ErrorCode::Overflow)? "
            "Or use saturating_add/sub for non-critical counters. "
            "Enable overflow-checks = true in Cargo.toml [profile.release]."
        ),
        "scanner": "solana_scanner",
        "multi": False,
    },

    # ── GHOST-SOL-005  CPI without return value check ─────────────────────
    {
        "rule_id": "GHOST-SOL-005",
        "name": "Cross-program invocation without return value check",
        "severity": "HIGH",
        "cwe": "CWE-252",
        "owasp": "A05:2021",
        "pattern": (
            r"invoke\s*\("
            r"|invoke_signed\s*\("
        ),
        "confidence": 0.75,
        "description": (
            "Cross-program invocation (CPI) result is not propagated or "
            "checked with ?. If the inner program returns an error and it "
            "is ignored, the outer program continues with inconsistent state."
        ),
        "fix": (
            "Always propagate CPI errors: invoke(&ix, &accounts)?; "
            "In Anchor CPI calls raise errors automatically, but "
            "native invoke() must use ? operator or explicit match."
        ),
        "scanner": "solana_scanner",
        "multi": False,
    },

    # ── GHOST-SOL-006  Account discriminator bypass ───────────────────────
    {
        "rule_id": "GHOST-SOL-006",
        "name": "Account discriminator bypass risk",
        "severity": "CRITICAL",
        "cwe": "CWE-20",
        "owasp": "A03:2021",
        "pattern": (
            r"try_from_slice\s*\((?:&accounts\[\d+\]\.data\.borrow\(\)|&\w+\.data)"
            r"(?![\s\S]{0,100}discriminator)"
        ),
        "confidence": 0.80,
        "description": (
            "Account data is deserialized without first verifying the "
            "8-byte Anchor discriminator. An attacker can pass an account "
            "of a different type that happens to share deserialization "
            "compatibility, leading to type confusion."
        ),
        "fix": (
            "In Anchor, use Account<'info, T> which checks the discriminator "
            "automatically. In native programs, read and verify the first 8 "
            "bytes match hash('account:TypeName')[..8] before deserializing."
        ),
        "scanner": "solana_scanner",
        "multi": True,
    },

    # ── GHOST-SOL-007  Missing account constraint validation ──────────────
    {
        "rule_id": "GHOST-SOL-007",
        "name": "Missing account constraint validation",
        "severity": "MEDIUM",
        "cwe": "CWE-20",
        "owasp": "A03:2021",
        "pattern": (
            r"#\[account\(\s*\)\]"
            r"|#\[account\(\s*mut\s*\)\]"
        ),
        "confidence": 0.82,
        "description": (
            "Anchor #[account] attribute has no constraints (no seeds, owner, "
            "has_one, or constraint fields). The account is accepted without "
            "verification, allowing attackers to substitute arbitrary accounts."
        ),
        "fix": (
            "Add appropriate constraints: #[account(mut, has_one = authority, "
            "seeds = [b'vault'], bump)]. At minimum verify ownership and "
            "relevant relationships between accounts."
        ),
        "scanner": "solana_scanner",
        "multi": False,
    },

    # ── GHOST-SOL-008  Unsafe deserialization ─────────────────────────────
    {
        "rule_id": "GHOST-SOL-008",
        "name": "Unsafe account deserialization",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "owasp": "A08:2021",
        "pattern": (
            r"unsafe\s*\{[^}]*from_raw_parts\b"
            r"|borsh::BorshDeserialize::deserialize\s*\(&mut[^)]*\)(?!.*\?)"
            r"|\.try_borrow_data\s*\(\).*unwrap\s*\(\)"
        ),
        "confidence": 0.75,
        "description": (
            "Deserialization of account data uses unsafe operations or "
            "ignores errors. Malformed account data can cause panics, "
            "undefined behavior, or incorrect state interpretation."
        ),
        "fix": (
            "Use safe Borsh deserialization with proper error handling: "
            "MyState::try_from_slice(&data).map_err(|_| ErrorCode::InvalidData)?. "
            "Avoid unsafe memory operations for account data access."
        ),
        "scanner": "solana_scanner",
        "multi": True,
    },

    # ── GHOST-SOL-009  Integer truncation ─────────────────────────────────
    {
        "rule_id": "GHOST-SOL-009",
        "name": "Integer truncation (u128 to u64)",
        "severity": "HIGH",
        "cwe": "CWE-197",
        "owasp": "A02:2021",
        "pattern": (
            r"as\s+u64(?=\s*[;,\)])"
            r"|as\s+u32(?=\s*[;,\)])"
            r"|as\s+u8(?=\s*[;,\)])"
        ),
        "confidence": 0.68,
        "description": (
            "Explicit integer cast (as u64/u32/u8) truncates the upper bits "
            "without error on overflow. If the value exceeds the target type's "
            "max, the result silently wraps, potentially corrupting balances."
        ),
        "fix": (
            "Use u64::try_from(large_value).map_err(|_| ErrorCode::Overflow)? "
            "instead of bare 'as u64' casts. "
            "This raises an error instead of silently truncating."
        ),
        "scanner": "solana_scanner",
        "multi": False,
    },

    # ── GHOST-SOL-010  Missing rent exemption check ───────────────────────
    {
        "rule_id": "GHOST-SOL-010",
        "name": "Missing rent exemption check",
        "severity": "MEDIUM",
        "cwe": "CWE-754",
        "owasp": "A05:2021",
        "pattern": (
            r"create_account\s*\("
            r"|system_instruction::create_account"
        ),
        "confidence": 0.70,
        "description": (
            "Account creation detected without an explicit rent exemption "
            "check. Non-rent-exempt accounts can be garbage-collected by "
            "validators, causing loss of state or funds held in the account."
        ),
        "fix": (
            "Ensure lamports >= rent.minimum_balance(space) when creating "
            "accounts. In Anchor, init with payer and space automatically "
            "handles rent exemption."
        ),
        "scanner": "solana_scanner",
        "multi": False,
    },

    # ── GHOST-SOL-011  Reinitialization attack ────────────────────────────
    {
        "rule_id": "GHOST-SOL-011",
        "name": "Reinitialization attack",
        "severity": "CRITICAL",
        "cwe": "CWE-665",
        "owasp": "A01:2021",
        "pattern": (
            r"pub\s+fn\s+initialize\s*\([^)]*\)(?![\s\S]{0,400}is_initialized)"
        ),
        "confidence": 0.75,
        "description": (
            "Initialize function does not appear to check whether the account "
            "has already been initialized. An attacker can call initialize() "
            "again to reset account state and take control."
        ),
        "fix": (
            "In Anchor, use the init constraint which enforces that the account "
            "is new: #[account(init, payer = user, space = 8 + MyState::LEN)]. "
            "In native programs: if account.is_initialized { return Err(...); }"
        ),
        "scanner": "solana_scanner",
        "multi": True,
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_rust_comments(source: str) -> Tuple[str, List[str]]:
    """Remove // and /* */ comments from Rust source."""
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
# SolanaScanner
# ---------------------------------------------------------------------------

class SolanaScanner:
    """
    Static security analyzer for Solana / Anchor programs (.rs files).

    Usage::

        scanner = SolanaScanner()
        findings = scanner.scan_file("/path/to/lib.rs")
        result   = scanner.scan_directory("/path/to/program/")
    """

    def __init__(self) -> None:
        self._compiled: List[Dict] = []
        for rule in _SOLANA_RULES:
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
        """Recursively scan a directory for Solana program Rust files.

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
