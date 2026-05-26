"""
Ghost Security Platform — Move Language Security Scanner
Static analysis for Move smart contracts targeting Sui and Aptos (.move files).

Detects: missing capability checks, unchecked arithmetic, missing object
ownership validation, public entry functions without access control, coin/balance
manipulation without guards, missing abort conditions, shared object reentrancy
risk, and dynamic field access without validation.
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

_MOVE_RULES: List[Dict] = [
    # ── GHOST-MOV-001  Missing capability check ───────────────────────────
    {
        "rule_id": "GHOST-MOV-001",
        "name": "Missing capability check (AdminCap/OwnerCap)",
        "severity": "CRITICAL",
        "cwe": "CWE-284",
        "owasp": "A01:2021",
        "pattern": (
            r"public\s+(?:entry\s+)?fun\s+(?:admin|set_|update_|upgrade|mint|burn|"
            r"transfer_ownership|pause|unpause|withdraw|drain)\w*\s*\([^)]*\)"
            r"(?![\s\S]{0,600}(?:AdminCap|OwnerCap|GovernanceCap|TreasuryCap|Cap\b))"
        ),
        "confidence": 0.75,
        "description": (
            "Administrative function does not appear to require an AdminCap, "
            "OwnerCap, or similar capability object in its parameters. "
            "In Move, authorization is enforced by requiring callers to pass "
            "a capability they uniquely own; missing this allows anyone to call."
        ),
        "fix": (
            "Add a capability parameter: "
            "public fun admin_action(_: &AdminCap, ...) { ... } "
            "Only the holder of AdminCap (the deployer or designated admin) "
            "can obtain and pass the capability object."
        ),
        "scanner": "move_scanner",
        "multi": True,
    },

    # ── GHOST-MOV-002  Unchecked arithmetic ───────────────────────────────
    {
        "rule_id": "GHOST-MOV-002",
        "name": "Unchecked arithmetic operation",
        "severity": "HIGH",
        "cwe": "CWE-190",
        "owasp": "A02:2021",
        "pattern": (
            r"\blet\s+\w+\s*=\s*\w+\s*[+\-\*]\s*\w+\s*;"
            r"|\w+\s*=\s*\w+\s*[+\-\*]\s*\w+\s*;"
        ),
        "confidence": 0.65,
        "description": (
            "Arithmetic operation without abort condition or overflow check. "
            "Move aborts on integer overflow by default in Sui/Aptos, but "
            "custom overflow handling or saturation logic may suppress these "
            "aborts, silently corrupting balances."
        ),
        "fix": (
            "Ensure overflow aborts propagate correctly. "
            "If saturation is desired, use explicit checks: "
            "assert!(a <= MAX_U64 - b, EOverflow); let result = a + b; "
            "Use move-stdlib's math module for safe operations."
        ),
        "scanner": "move_scanner",
        "multi": False,
    },

    # ── GHOST-MOV-003  Missing object ownership validation ────────────────
    {
        "rule_id": "GHOST-MOV-003",
        "name": "Missing object ownership validation",
        "severity": "CRITICAL",
        "cwe": "CWE-284",
        "owasp": "A01:2021",
        "pattern": (
            r"transfer::transfer\s*\([^,]+,\s*tx_context::sender\s*\("
            r"|public\s+fun\s+\w+\s*\([^)]*&\s*mut\s+\w+[^)]*\)"
            r"(?![\s\S]{0,400}(?:assert!\s*\(\s*object::owner|tx_context::sender))"
        ),
        "confidence": 0.70,
        "description": (
            "Function accepts a mutable reference to an owned object without "
            "first verifying that the caller (tx_context::sender) is the "
            "legitimate owner. An attacker could mutate objects they do not own."
        ),
        "fix": (
            "Verify ownership before mutation: "
            "assert!(object::owner(obj) == tx_context::sender(ctx), ENotOwner); "
            "Or use Sui's ownership model by accepting object by value (not &mut) "
            "which the runtime enforces is caller-owned."
        ),
        "scanner": "move_scanner",
        "multi": True,
    },

    # ── GHOST-MOV-004  Public entry without access control ────────────────
    {
        "rule_id": "GHOST-MOV-004",
        "name": "Public entry function without access control",
        "severity": "HIGH",
        "cwe": "CWE-284",
        "owasp": "A01:2021",
        "pattern": (
            r"public\s+entry\s+fun\s+\w+\s*\([^)]*\)"
            r"(?![\s\S]{0,500}(?:AdminCap|OwnerCap|TreasuryCap|assert!\s*\("
            r"|abort\s+E(?:Not|Unauthorized|Only)))"
        ),
        "confidence": 0.68,
        "description": (
            "public entry function is callable by any transaction without "
            "apparent access control. Entry functions are transaction "
            "entrypoints; state-changing ones need explicit authorization."
        ),
        "fix": (
            "Add capability parameter for admin functions: "
            "public entry fun restricted(_cap: &AdminCap, ...) {} "
            "Or add an assertion: assert!(tx_context::sender(ctx) == admin, EUnauthorized);"
        ),
        "scanner": "move_scanner",
        "multi": True,
    },

    # ── GHOST-MOV-005  Coin/balance manipulation without checks ───────────
    {
        "rule_id": "GHOST-MOV-005",
        "name": "Coin/balance manipulation without validation",
        "severity": "CRITICAL",
        "cwe": "CWE-841",
        "owasp": "A01:2021",
        "pattern": (
            r"coin::split\s*\("
            r"|balance::split\s*\("
            r"|coin::into_balance\s*\("
            r"|coin::from_balance\s*\("
            r"|balance::join\s*\("
        ),
        "confidence": 0.72,
        "description": (
            "Coin or Balance split/join operation detected. These operations "
            "directly manipulate token amounts. If called without validating "
            "the caller, amounts, and token type, an attacker can drain "
            "protocol-held balances."
        ),
        "fix": (
            "Before any coin/balance operation, verify: "
            "1) Caller is authorized (capability check), "
            "2) Amount is within expected range (assert!(amount > 0 && amount <= max)), "
            "3) Coin type matches expected type (phantom type parameter)."
        ),
        "scanner": "move_scanner",
        "multi": False,
    },

    # ── GHOST-MOV-006  Missing abort conditions ───────────────────────────
    {
        "rule_id": "GHOST-MOV-006",
        "name": "Missing abort conditions on critical path",
        "severity": "MEDIUM",
        "cwe": "CWE-754",
        "owasp": "A05:2021",
        "pattern": (
            r"public\s+(?:entry\s+)?fun\s+\w+\s*\([^)]*\)\s*\{"
            r"(?![\s\S]{0,800}(?:assert!\s*\(|abort\s+))"
        ),
        "confidence": 0.60,
        "description": (
            "Public function body does not appear to contain any assert! or "
            "abort statements. Functions that can fail (invalid inputs, "
            "unauthorized callers, arithmetic constraints) should explicitly "
            "abort with meaningful error codes."
        ),
        "fix": (
            "Add assertions for all preconditions: "
            "assert!(amount > 0, EInvalidAmount); "
            "assert!(tx_context::sender(ctx) == self.owner, EUnauthorized); "
            "Define error constants at module level: const EInvalidAmount: u64 = 1;"
        ),
        "scanner": "move_scanner",
        "multi": True,
    },

    # ── GHOST-MOV-007  Shared object reentrancy risk ───────────────────────
    {
        "rule_id": "GHOST-MOV-007",
        "name": "Shared object reentrancy risk",
        "severity": "HIGH",
        "cwe": "CWE-841",
        "owasp": "A01:2021",
        "pattern": (
            r"transfer::share_object\s*\("
            r"|object::new_uid_from_hash"
            r"|\bshared\b.*\bUID\b"
        ),
        "confidence": 0.68,
        "description": (
            "Shared object detected. In Sui, shared objects can be accessed "
            "by multiple transactions concurrently. If a function both reads "
            "and writes a shared object without atomic locking semantics, "
            "concurrent transactions can observe inconsistent intermediate state."
        ),
        "fix": (
            "Design shared object APIs to be atomic — a single transaction "
            "reads, modifies, and writes in one step with no intermediate "
            "exposed state. Avoid patterns where multiple transactions must "
            "cooperate to complete a single logical operation."
        ),
        "scanner": "move_scanner",
        "multi": False,
    },

    # ── GHOST-MOV-008  Dynamic field access without validation ────────────
    {
        "rule_id": "GHOST-MOV-008",
        "name": "Dynamic field access without existence validation",
        "severity": "MEDIUM",
        "cwe": "CWE-476",
        "owasp": "A05:2021",
        "pattern": (
            r"dynamic_field::borrow\s*<"
            r"|dynamic_field::borrow_mut\s*<"
            r"|dynamic_object_field::borrow\s*<"
            r"|dynamic_object_field::borrow_mut\s*<"
        ),
        "confidence": 0.75,
        "description": (
            "Dynamic field borrow without a prior exists() check. "
            "If the field does not exist, borrow() aborts the transaction "
            "with a generic error. An attacker can craft inputs that trigger "
            "this abort as a DoS, or legitimate callers may hit unexpected failures."
        ),
        "fix": (
            "Check existence before borrowing: "
            "assert!(dynamic_field::exists_(&obj.id, key), EFieldNotFound); "
            "let field = dynamic_field::borrow(&obj.id, key); "
            "Or use dynamic_field::exists_ in an if-else for optional logic."
        ),
        "scanner": "move_scanner",
        "multi": False,
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_move_comments(source: str) -> Tuple[str, List[str]]:
    """Remove Move // and /* */ comments."""
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
# MoveScanner
# ---------------------------------------------------------------------------

class MoveScanner:
    """
    Static security analyzer for Move language smart contracts (.move files).

    Supports both Sui Move and Aptos Move dialects.

    Usage::

        scanner = MoveScanner()
        findings = scanner.scan_file("/path/to/module.move")
        result   = scanner.scan_directory("/path/to/sources/")
    """

    def __init__(self) -> None:
        self._compiled: List[Dict] = []
        for rule in _MOVE_RULES:
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
        """Scan a single .move file and return findings."""
        p = Path(path)
        if p.suffix.lower() != ".move":
            return []
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        cleaned, original_lines = _strip_move_comments(raw)
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
        """Recursively scan a directory for Move source files.

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

        for file in root.rglob("*.move"):
            if ".git" in file.parts or "build" in file.parts:
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
