"""Ghost Security Platform — Rust Security Analyzer (Phase 15)"""

from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path
from typing import List, Optional

from .base import LangFinding, LangAnalysisResult


class RustAnalyzer:
    """Security analyzer for Rust codebases.

    Runs cargo-audit for known CVEs when available, then applies
    native pattern-based rules covering unsafe code, integer casts,
    panic paths, and concurrency issues.
    """

    RULES = [
        # (rule_id, title, pattern, severity, category, recommendation)
        ("RS001", "Unsafe block with raw pointer dereference",
         r"unsafe\s*\{[^}]*\*(?:mut\s+)?\*?[a-zA-Z_]\w*",
         "HIGH", "memory_safety",
         "Ensure pointer validity and lifetime before dereferencing. Prefer safe abstractions."),
        ("RS002", "from_raw_parts / transmute usage",
         r"\bfrom_raw_parts\s*\(|\btransmute\s*::<",
         "CRITICAL", "memory_safety",
         "from_raw_parts and transmute bypass all safety checks. Validate inputs rigorously."),
        ("RS003", "unwrap() on potentially-None/Err value",
         r"(?:\.unwrap\(\)|\.expect\(['\"])",
         "MEDIUM", "panic",
         "Replace unwrap/expect with proper error propagation using ? or match."),
        ("RS004", "Narrowing integer cast (u64→u32 or i64→u32)",
         r"\bas\s+u(?:8|16|32)\b|\bas\s+i(?:8|16|32)\b",
         "HIGH", "sign_confusion",
         "Use checked_as or saturating_as to detect overflow. Document all intentional truncations."),
        ("RS005", "Signed-to-unsigned cast without sign check",
         r"\bas\s+u(?:64|128)\b",
         "HIGH", "sign_confusion",
         "Negative signed values cast to u64 produce large positives (e.g., -1 → UINT64_MAX). "
         "Add a guard: if val < 0 { return Err(...) }"),
        ("RS006", "Process::Command with user-controlled argument",
         r"Command::new\s*\(|\.arg\s*\(",
         "CRITICAL", "cmd_injection",
         "Never build shell commands from user input without strict allowlisting."),
        ("RS007", "Mutex/RwLock double-lock (potential deadlock)",
         r"\.lock\(\)\.unwrap\(\);\s*\n[^\n]*\.lock\(\)",
         "MEDIUM", "deadlock",
         "Acquire locks in consistent order to prevent deadlocks."),
        ("RS008", "Deserialize without validation (serde + untrusted input)",
         r"serde_json::from_str\s*\(|bincode::deserialize\s*\(",
         "MEDIUM", "deserialization",
         "Apply strict schema validation after deserialization of untrusted data."),
        ("RS009", "std::mem::forget — potential resource leak",
         r"\bstd::mem::forget\s*\(|\bmem::forget\s*\(",
         "MEDIUM", "resource_leak",
         "Use ManuallyDrop or restructure ownership to avoid leaking resources."),
        ("RS010", "Array index without bounds check in unsafe block",
         r"unsafe\s*\{[^}]*\[\s*\w+\s*\]",
         "HIGH", "memory_safety",
         "Use get() with bounds check instead of direct indexing in unsafe blocks."),
        ("RS011", "Global mutable static (data race risk)",
         r"static\s+mut\s+\w+\s*:",
         "HIGH", "race_condition",
         "Replace static mut with a Mutex<T> or atomic types to prevent data races."),
        ("RS012", "Panic in library code (unwrap in pub fn)",
         r"pub\s+fn\s+\w+[^{]*\{[^}]*\.unwrap\(\)",
         "LOW", "panic",
         "Library functions should return Result, not panic on invalid input."),
    ]

    def __init__(self, cargo_audit_path: str = "cargo-audit"):
        self.cargo_audit_path = cargo_audit_path

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, path: str) -> LangAnalysisResult:
        t0 = time.time()
        findings: List[LangFinding] = []
        tool_available = False

        # Try cargo-audit first
        audit_findings, tool_available = self.run_cargo_audit(path)
        findings.extend(audit_findings)

        # Always run native analysis
        native_findings = self.run_native(path)
        findings.extend(native_findings)

        summary = self._summarize(findings)
        return LangAnalysisResult(
            language="rust",
            files_analyzed=len(self._collect_files(path)),
            findings=findings,
            tool_available=tool_available,
            scan_time=time.time() - t0,
            summary=summary,
        )

    def run_cargo_audit(self, path: str) -> tuple[List[LangFinding], bool]:
        """Run cargo-audit for known CVEs in dependencies."""
        try:
            result = subprocess.run(
                [self.cargo_audit_path, "audit", "--json"],
                cwd=path if Path(path).is_dir() else str(Path(path).parent),
                capture_output=True, text=True, timeout=60,
            )
            tool_available = True
            if not result.stdout.strip():
                return [], True
            data = json.loads(result.stdout)
            findings = []
            for vuln in data.get("vulnerabilities", {}).get("list", []):
                advisory = vuln.get("advisory", {})
                findings.append(LangFinding(
                    filepath=str(Path(path) / "Cargo.lock"),
                    line=0,
                    column=0,
                    rule_id=advisory.get("id", "CARGO-ADV"),
                    title=advisory.get("title", "Known vulnerability in dependency"),
                    description=advisory.get("description", ""),
                    severity="HIGH",
                    category="known_cve",
                    code_snippet=vuln.get("package", {}).get("name", ""),
                    recommendation=advisory.get("url", "Update to patched version"),
                    tool="cargo_audit",
                    confidence=1.0,
                ))
            return findings, True
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            return [], False

    def run_native(self, path: str) -> List[LangFinding]:
        findings: List[LangFinding] = []
        for filepath in self._collect_files(path):
            try:
                source = Path(filepath).read_text(errors="replace")
            except OSError:
                continue
            findings.extend(self.check_unsafe_blocks(source, filepath))
            findings.extend(self.check_integer_overflow(source, filepath))
            findings.extend(self.check_unwrap_panic(source, filepath))
            findings.extend(self.check_memory_safety(source, filepath))
            findings.extend(self.check_race_conditions(source, filepath))
            findings.extend(self.check_serialization(source, filepath))
        return findings

    # ------------------------------------------------------------------
    # Specific checks
    # ------------------------------------------------------------------

    def check_unsafe_blocks(self, source: str, filepath: str) -> List[LangFinding]:
        return self._apply_rules(source, filepath, ["RS001", "RS002", "RS009", "RS010"])

    def check_integer_overflow(self, source: str, filepath: str) -> List[LangFinding]:
        return self._apply_rules(source, filepath, ["RS004", "RS005"])

    def check_unwrap_panic(self, source: str, filepath: str) -> List[LangFinding]:
        return self._apply_rules(source, filepath, ["RS003", "RS012"])

    def check_memory_safety(self, source: str, filepath: str) -> List[LangFinding]:
        return self._apply_rules(source, filepath, ["RS001", "RS002", "RS010"])

    def check_race_conditions(self, source: str, filepath: str) -> List[LangFinding]:
        return self._apply_rules(source, filepath, ["RS007", "RS011"])

    def check_serialization(self, source: str, filepath: str) -> List[LangFinding]:
        return self._apply_rules(source, filepath, ["RS008"])

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_rules(
        self, source: str, filepath: str, rule_ids: List[str]
    ) -> List[LangFinding]:
        findings: List[LangFinding] = []
        lines = source.splitlines()
        rules = {r[0]: r for r in self.RULES}
        for rid in rule_ids:
            if rid not in rules:
                continue
            rule_id, title, pattern, severity, category, recommendation = rules[rid]
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    findings.append(LangFinding(
                        filepath=filepath,
                        line=i,
                        column=0,
                        rule_id=rule_id,
                        title=title,
                        description=f"Pattern matched at line {i}: {line.strip()[:100]}",
                        severity=severity,
                        category=category,
                        code_snippet=line.strip()[:120],
                        recommendation=recommendation,
                        tool="native",
                        confidence=0.75,
                    ))
        return findings

    def _collect_files(self, path: str) -> List[str]:
        p = Path(path)
        if p.is_file() and p.suffix == ".rs":
            return [str(p)]
        return [str(f) for f in p.rglob("*.rs") if f.is_file()]

    def _summarize(self, findings: List[LangFinding]) -> dict:
        s: dict = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            s[f.severity] = s.get(f.severity, 0) + 1
        return s
