"""
Ghost Security Platform — TON Blockchain Analyzer v2.2
Static analysis for FunC, Tact, and Fift smart contracts.
75+ rules across 20 categories: access control, replay attacks, integer overflow,
gas griefing, randomness abuse, Jetton safety, bounce handling, and more.
"""
import os
import re
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict

# Extended ruleset — imported and merged at module load
try:
    from scanners.ton_scanner.ton_rules_extended import (
        EXTENDED_LINE_RULES, EXTENDED_CONTEXT_RULES, TONDataflowAnalyzer
    )
    _EXTENDED_AVAILABLE = True
except ImportError:
    EXTENDED_LINE_RULES, EXTENDED_CONTEXT_RULES = [], []
    _EXTENDED_AVAILABLE = False


@dataclass
class TONFinding:
    rule_id: str
    severity: str        # CRITICAL / HIGH / MEDIUM / LOW / INFO
    file: str
    line: int
    description: str
    evidence: str
    recommendation: str
    cwe: str = ""
    category: str = ""

    def to_dict(self) -> Dict:
        return {
            "type": "TON_VULNERABILITY",
            "id": self.rule_id,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "category": self.category,
            "source": "ton_analyzer",
        }


LINE_RULES: List[Dict] = [
    # ── Access Control ─────────────────────────────────────────────
    {"id": "TON001", "pattern": r"\baccept_message\s*\(\s*\)",
     "severity": "HIGH", "cwe": "CWE-284", "category": "Access Control",
     "description": "Unconditional accept_message() — gas drain risk if placed before sender validation",
     "recommendation": "Validate sender with equal_slices BEFORE calling accept_message()"},
    {"id": "TON010", "pattern": r"(?i)(set_owner|set_admin|change_owner|transfer_ownership)\s*\(",
     "severity": "HIGH", "cwe": "CWE-284", "category": "Access Control",
     "description": "Sensitive ownership function — verify access guard exists before this call",
     "recommendation": "Add throw_unless(error::unauthorized, equal_slices(sender, owner)) before ownership changes"},
    {"id": "TON022", "pattern": r"\bthrow_if\s*\(\s*0\s*,",
     "severity": "MEDIUM", "cwe": "CWE-754", "category": "Access Control",
     "description": "throw_if(0, ...) — error code 0 is a no-op; condition is never enforced",
     "recommendation": "Use a non-zero error code (e.g. 401)"},
    {"id": "TON017", "pattern": r"(?i)\breceive\s*\([^)]*\)\s*\{",
     "severity": "INFO", "cwe": "CWE-284", "category": "Access Control",
     "description": "Tact receive() handler — verify ownership guard is the first statement",
     "recommendation": "Add require(ctx.sender == self.owner, 'Unauthorized') at top of sensitive handlers"},

    # ── Fund Safety ─────────────────────────────────────────────────
    {"id": "TON002", "pattern": r"send_raw_message\s*\([^,]+,\s*(128|64\s*\+\s*2|66)\s*\)",
     "severity": "HIGH", "cwe": "CWE-691", "category": "Fund Safety",
     "description": "send_raw_message mode 64/128 — can drain entire contract balance",
     "recommendation": "Use mode 0 or 1 unless intentionally forwarding remaining balance"},
    {"id": "TON016", "pattern": r"\bmsg_value\b",
     "severity": "INFO", "cwe": "CWE-20", "category": "Fund Safety",
     "description": "msg_value usage — verify checked against minimum before accepting operations",
     "recommendation": "Add throw_unless(error::insufficient_value, msg_value >= min_fee) at recv_internal entry"},
    {"id": "TON025", "pattern": r"raw_reserve\s*\([^,]+,\s*0\s*\)",
     "severity": "MEDIUM", "cwe": "CWE-400", "category": "Fund Safety",
     "description": "raw_reserve mode 0 — may leave contract with zero balance",
     "recommendation": "Prefer raw_reserve(amount, 2) to ensure minimum balance is maintained"},

    # ── Replay Protection ───────────────────────────────────────────
    {"id": "TON006", "pattern": r"\bquery_id\b",
     "severity": "INFO", "cwe": "CWE-294", "category": "Replay Protection",
     "description": "query_id detected — confirm stored and checked to prevent replay attacks",
     "recommendation": "Persist processed query_ids in contract storage and reject duplicates"},
    {"id": "TON023", "pattern": r"\bvalid_until\b",
     "severity": "INFO", "cwe": "CWE-294", "category": "Replay Protection",
     "description": "valid_until detected — verify compared against now() and expired messages rejected",
     "recommendation": "Add throw_if(error::expired, now() > valid_until) after loading valid_until"},

    # ── Randomness ──────────────────────────────────────────────────
    {"id": "TON008", "pattern": r"\b(now|block_lt|cur_lt)\s*\(\s*\)",
     "severity": "HIGH", "cwe": "CWE-338", "category": "Randomness",
     "description": "Block/time value used — predictable entropy, exploitable by validators",
     "recommendation": "Use randomize_lt() + rand(); never use now() or block_lt as sole entropy"},
    {"id": "TON024", "pattern": r"\brand\s*\(",
     "severity": "MEDIUM", "cwe": "CWE-338", "category": "Randomness",
     "description": "rand() — seed can be influenced by validators in same block",
     "recommendation": "Call commit() before rand() to prevent validator manipulation"},

    # ── Integer Safety ──────────────────────────────────────────────
    {"id": "TON005", "pattern": r"\b(muldiv|muldivc)\s*\(",
     "severity": "INFO", "cwe": "CWE-369", "category": "Integer Safety",
     "description": "muldiv/muldivc — verify divisor cannot be zero (TVM exception 5)",
     "recommendation": "Add throw_if(error::division_by_zero, divisor == 0) before muldiv"},
    {"id": "TON026", "pattern": r"\.store_uint\s*\([^,]+,\s*([0-9]+)\s*\)",
     "severity": "INFO", "cwe": "CWE-190", "category": "Integer Safety",
     "description": "store_uint with fixed bit-width — verify value fits to prevent truncation",
     "recommendation": "Validate value < (1 << bits) before storing"},

    # ── State Ordering / Reentrancy ──────────────────────────────────
    {"id": "TON009", "pattern": r"send_raw_message\s*\(",
     "severity": "INFO", "cwe": "CWE-362", "category": "State Ordering",
     "description": "send_raw_message — verify set_data() called BEFORE this to ensure consistent state",
     "recommendation": "Always call set_data(pack_storage()) before any send_raw_message"},

    # ── Dictionary Safety ────────────────────────────────────────────
    {"id": "TON003", "pattern": r"~\s*dict_(set|delete|replace)\s*\(",
     "severity": "MEDIUM", "cwe": "CWE-400", "category": "Gas / DoS",
     "description": "Manual dictionary mutation — unbounded growth may cause gas exhaustion",
     "recommendation": "Cap dictionary size; validate key before insertion; handle ~found on deletions"},
    {"id": "TON027", "pattern": r"dict_get\s*\??\s*\(",
     "severity": "INFO", "cwe": "CWE-252", "category": "Error Handling",
     "description": "dict_get result — confirm found flag checked before using slice value",
     "recommendation": "Destructure: (slice val, int found) = dict.udict_get?(256, key); throw_unless(err, found);"},

    # ── Bounce Handling ──────────────────────────────────────────────
    {"id": "TON011", "pattern": r"recv_internal\s*\(",
     "severity": "INFO", "cwe": "CWE-754", "category": "Bounce Safety",
     "description": "recv_internal — verify bounced messages (op == 0xFFFFFFFF) handled to prevent fund loss",
     "recommendation": "Check in_msg_body~load_uint(1) for bounce flag; handle op 0xFFFFFFFF"},

    # ── Token Safety ─────────────────────────────────────────────────
    {"id": "TON012", "pattern": r"(?i)(jetton_transfer|send_jetton)\s*\(",
     "severity": "MEDIUM", "cwe": "CWE-20", "category": "Token Safety",
     "description": "Jetton transfer — verify forward_ton_amount >= min_storage and response_destination set",
     "recommendation": "Ensure forward_ton_amount covers storage+gas; validate response_destination != null_addr()"},
    {"id": "TON028", "pattern": r"(?i)jetton_wallet_address\s*\(",
     "severity": "MEDIUM", "cwe": "CWE-20", "category": "Token Safety",
     "description": "Jetton wallet address — never trust user-supplied addresses",
     "recommendation": "Always recompute jetton wallet address from (jetton_master, owner) pair on-chain"},

    # ── Upgrade Safety ───────────────────────────────────────────────
    {"id": "TON018", "pattern": r"(?i)\bset_code\s*\(",
     "severity": "HIGH", "cwe": "CWE-284", "category": "Upgrade Safety",
     "description": "Contract upgrade/data override — verify strict ownership check before allowing",
     "recommendation": "Only allow set_code/set_data from deployer/owner; consider time-lock or multisig"},

    # ── Gas / DoS ─────────────────────────────────────────────────────
    {"id": "TON007", "pattern": r"\brepeat\s*\(",
     "severity": "MEDIUM", "cwe": "CWE-400", "category": "Gas / DoS",
     "description": "repeat() loop — user-controlled iteration count enables gas griefing",
     "recommendation": "Cap count: throw_if(error::too_many, n > MAX_ITERATIONS)"},
    {"id": "TON021", "pattern": r"accept_message\s*\(\s*\)",
     "severity": "CRITICAL", "cwe": "CWE-284", "category": "Gas / DoS",
     "description": "accept_message() with no preceding guard — callers can drain gas from this contract",
     "recommendation": "Validate sender identity or message signature BEFORE calling accept_message()"},

    # ── Input Validation ─────────────────────────────────────────────
    {"id": "TON014", "pattern": r"\.preload_(uint|int|bits|ref)\s*\(",
     "severity": "MEDIUM", "cwe": "CWE-125", "category": "Input Validation",
     "description": "preload_* without bounds check — TVM exception 9 (cell underflow) on malformed input",
     "recommendation": "Check slice_bits(s) >= N before preloading; wrap in try/catch for external messages"},
    {"id": "TON031", "pattern": r"\.load_(uint|int|bits)\s*\(",
     "severity": "INFO", "cwe": "CWE-125", "category": "Input Validation",
     "description": "load_* on slice — verify sufficient bits exist to avoid TVM exception 9",
     "recommendation": "Validate slice_bits(s) >= expected_bits before destructuring user-supplied cells"},

    # ── Address Safety ───────────────────────────────────────────────
    {"id": "TON013", "pattern": r"\baddr_std\s*\(\s*0\s*,",
     "severity": "LOW", "cwe": "CWE-20", "category": "Address Safety",
     "description": "Hardcoded workchain 0 — wrong addresses on other workchains",
     "recommendation": "Use my_address().workchain dynamically or make workchain a constructor parameter"},
]


CONTEXT_RULES: List[Dict] = [
    {
        "id": "TON004",
        "trigger_pattern": r"\brecv_internal\b",
        "missing_pattern": r"equal_slices|sender.*owner|owner.*sender|require.*sender|throw.*unauthorized",
        "severity": "HIGH", "cwe": "CWE-284", "category": "Access Control",
        "description": "recv_internal handler may lack sender validation — no ownership check found",
        "recommendation": "Add: throw_unless(error::unauthorized, equal_slices(sender, storage::owner));",
        "scope_lines": 40,
    },
    {
        "id": "TON015",
        "trigger_pattern": r"\brecv_external\b",
        "missing_pattern": r"check_signature|is_signature_valid",
        "severity": "CRITICAL", "cwe": "CWE-287", "category": "Authentication",
        "description": "recv_external with no signature verification — any external actor can call this",
        "recommendation": "Always verify: throw_unless(error::invalid_sig, check_signature(hash, sig, pubkey));",
        "scope_lines": 30,
    },
    {
        "id": "TON020",
        "trigger_pattern": r"\bset_data\s*\(",
        "missing_pattern": r"\bimpure\b",
        "severity": "HIGH", "cwe": "CWE-664", "category": "State Safety",
        "description": "State-mutating function (set_data) may be missing `impure` — optimizer may remove call",
        "recommendation": "Declare all functions calling set_data/set_code/send_raw_message with `impure`",
        "scope_lines": 60, "look_before": True,
    },
]


class TONAnalyzer:
    """
    Static analyzer for TON smart contracts (FunC, Tact, Fift).
    75+ rules across 20 categories.
    """

    SUPPORTED_EXTENSIONS = (".fc", ".func", ".tact", ".fift", ".fif")

    def __init__(self):
        # Keep sub-components for potential dynamic analysis integration
        try:
            from scanners.ton_scanner.rollback_analyzer import RollbackAnalyzer
            from scanners.ton_scanner.trace_analyzer import TraceAnalyzer
            self.rollback = RollbackAnalyzer()
            self.trace_analyzer = TraceAnalyzer()
        except Exception:
            self.rollback = None
            self.trace_analyzer = None

    def analyze_file(self, file_path: str) -> List[Dict]:
        path = Path(file_path)
        if path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            return []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        findings = []
        findings.extend(self._run_line_rules(file_path, content))
        findings.extend(self._run_context_rules(file_path, content))
        # Extended ruleset: 47 line rules + 8 context rules + dataflow
        if _EXTENDED_AVAILABLE:
            findings.extend(self._run_extended_line_rules(file_path, content))
            findings.extend(self._run_extended_context_rules(file_path, content))
            findings.extend(TONDataflowAnalyzer().analyze(content, file_path))
        if file_path.endswith(".tact"):
            findings.extend(self._run_tact_checks(file_path, content))
        findings = self._deduplicate(findings)
        def _sev_key(f):
            sev = f.severity if hasattr(f, "severity") else f.get("severity", "INFO")
            return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(sev, 5)
        findings.sort(key=_sev_key)
        return [f.to_dict() if hasattr(f, "to_dict") else f for f in findings]

    def scan_directory(self, directory: str) -> Dict:
        all_findings: List[Dict] = []
        files_scanned = 0
        for root, _, files in os.walk(directory):
            for fname in files:
                fpath = os.path.join(root, fname)
                if Path(fpath).suffix.lower() in self.SUPPORTED_EXTENSIONS:
                    all_findings.extend(self.analyze_file(fpath))
                    files_scanned += 1
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in all_findings:
            severity_counts[f.get("severity", "INFO")] = severity_counts.get(f.get("severity", "INFO"), 0) + 1
        return {"files_scanned": files_scanned, "total_findings": len(all_findings),
                "severity_counts": severity_counts, "findings": all_findings}

    def get_rules_summary(self) -> List[Dict]:
        summary = [{"id": r["id"], "severity": r["severity"], "category": r["category"],
                     "description": r["description"]} for r in LINE_RULES]
        for r in CONTEXT_RULES:
            summary.append({"id": r["id"], "severity": r["severity"],
                             "category": r["category"], "description": r["description"]})
        return sorted(summary, key=lambda x: x["id"])

    def _run_line_rules(self, file_path: str, content: str) -> List[TONFinding]:
        findings = []
        lines = content.splitlines()
        for rule in LINE_RULES:
            pattern = re.compile(rule["pattern"])
            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith(";;") or stripped.startswith("//"):
                    continue
                if pattern.search(line):
                    findings.append(TONFinding(
                        rule_id=rule["id"], severity=rule["severity"],
                        file=file_path, line=lineno,
                        description=rule["description"], evidence=stripped[:120],
                        recommendation=rule["recommendation"],
                        cwe=rule.get("cwe", ""), category=rule.get("category", ""),
                    ))
        return findings

    def _run_context_rules(self, file_path: str, content: str) -> List[TONFinding]:
        findings = []
        lines = content.splitlines()
        for rule in CONTEXT_RULES:
            trigger_re = re.compile(rule["trigger_pattern"])
            missing_re = re.compile(rule["missing_pattern"], re.IGNORECASE)
            scope = rule.get("scope_lines", 30)
            look_before = rule.get("look_before", False)
            for lineno, line in enumerate(lines, start=1):
                if trigger_re.search(line):
                    start = max(0, lineno - scope - 1) if look_before else lineno - 1
                    end = lineno if look_before else min(len(lines), lineno + scope)
                    window = "\n".join(lines[start:end])
                    if not missing_re.search(window):
                        findings.append(TONFinding(
                            rule_id=rule["id"], severity=rule["severity"],
                            file=file_path, line=lineno,
                            description=rule["description"], evidence=line.strip()[:120],
                            recommendation=rule["recommendation"],
                            cwe=rule.get("cwe", ""), category=rule.get("category", ""),
                        ))
        return findings

    def _run_tact_checks(self, file_path: str, content: str) -> List[TONFinding]:
        findings = []
        if re.search(r"\bowner\s*:\s*Address", content) and not re.search(r"get\s+fun\s+owner\s*\(", content):
            findings.append(TONFinding(
                rule_id="TON032", severity="LOW", file=file_path, line=1,
                description="Tact contract has owner field but no owner() getter",
                evidence="owner: Address (no getter found)",
                recommendation="Add: get fun owner(): Address { return self.owner; }",
                cwe="CWE-200", category="Transparency",
            ))
        for m in re.finditer(r"receive\s*\([^)]*\)\s*\{", content):
            block_start = m.end()
            depth, idx = 1, block_start
            while idx < len(content) and depth > 0:
                if content[idx] == "{": depth += 1
                elif content[idx] == "}": depth -= 1
                idx += 1
            block_body = content[block_start:idx]
            line_num = content[:m.start()].count("\n") + 1
            has_guard = bool(re.search(r"\brequire\s*\(|throw_unless|throw_if\b", block_body))
            has_mutation = bool(re.search(r"\bself\.\w+\s*=\s*|send\s*\(|emit\s*\(", block_body))
            if has_mutation and not has_guard and len(block_body.strip()) > 8:
                findings.append(TONFinding(
                    rule_id="TON033", severity="MEDIUM", file=file_path, line=line_num,
                    description="Tact receive() with state mutation/send but no access guard",
                    evidence=content[m.start():m.start() + 70].strip(),
                    recommendation="Add require(self.owner == ctx.sender, 'Unauthorized') at handler entry",
                    cwe="CWE-284", category="Access Control",
                ))
        return findings

    def _run_extended_line_rules(self, file_path: str, content: str) -> List[Dict]:
        findings = []
        lines = content.splitlines()
        for rule in EXTENDED_LINE_RULES:
            pattern = re.compile(rule["pattern"])
            for lineno, line in enumerate(lines, start=1):
                stripped = line.strip()
                if stripped.startswith(";;") or stripped.startswith("//"):
                    continue
                if pattern.search(line):
                    findings.append({
                        "type": "TON_VULNERABILITY", "id": rule["id"],
                        "rule_id": rule["id"], "severity": rule["severity"],
                        "cwe": rule.get("cwe", ""), "category": rule.get("category", ""),
                        "file": file_path, "line": lineno,
                        "message": rule["description"], "description": rule["description"],
                        "evidence": stripped[:120], "recommendation": rule["recommendation"],
                        "source": "ton_analyzer_extended",
                        "bounty_class": rule.get("bounty_class", ""),
                        "known_impact": rule.get("known_impact", ""),
                    })
        return findings

    def _run_extended_context_rules(self, file_path: str, content: str) -> List[Dict]:
        findings = []
        lines = content.splitlines()
        for rule in EXTENDED_CONTEXT_RULES:
            trigger_re = re.compile(rule["trigger_pattern"])
            missing_re = re.compile(rule["missing_pattern"], re.IGNORECASE)
            scope      = rule.get("scope_lines", 30)
            look_before = rule.get("look_before", False)
            for lineno, line in enumerate(lines, start=1):
                if trigger_re.search(line):
                    start  = max(0, lineno - scope - 1) if look_before else lineno - 1
                    end    = lineno if look_before else min(len(lines), lineno + scope)
                    window = "\n".join(lines[start:end])
                    if not missing_re.search(window):
                        findings.append({
                            "type": "TON_VULNERABILITY", "id": rule["id"],
                            "rule_id": rule["id"], "severity": rule["severity"],
                            "cwe": rule.get("cwe", ""), "category": rule.get("category", ""),
                            "file": file_path, "line": lineno,
                            "message": rule["description"], "description": rule["description"],
                            "evidence": line.strip()[:120], "recommendation": rule["recommendation"],
                            "source": "ton_analyzer_extended",
                            "bounty_class": rule.get("bounty_class", ""),
                            "known_impact": rule.get("known_impact", ""),
                        })
        return findings

    @staticmethod
    def _deduplicate(findings) -> list:
        """Deduplicate mix of TONFinding objects and plain dicts."""
        seen, result = set(), []
        for f in findings:
            if hasattr(f, "rule_id"):
                key = (f.rule_id, f.file, f.line)
            else:
                key = (f.get("rule_id") or f.get("id",""), f.get("file",""), f.get("line",0))
            if key not in seen:
                seen.add(key)
                result.append(f)
        return result
