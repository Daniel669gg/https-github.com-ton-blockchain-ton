"""
TythanAI Platform — Finding Message Normalizer
Гарантирует, что у каждого finding есть человекочитаемое message.
Источники (в порядке приоритета):
  1. Уже заполненное message / description
  2. CWE-based шаблон
  3. OWASP-based шаблон  
  4. rule_id / type шаблон
  5. Generic fallback
"""
from __future__ import annotations
from typing import Optional

# ── CWE → human message ───────────────────────────────────────────────────────
_CWE_MESSAGES: dict[str, str] = {
    "CWE-79":  "Cross-Site Scripting (XSS): unsanitised user input reflected in HTML output",
    "CWE-89":  "SQL Injection: user input concatenated directly into SQL query",
    "CWE-78":  "OS Command Injection: unsanitised input passed to shell command",
    "CWE-94":  "Code Injection: dynamic code execution with user-controlled input (eval/exec)",
    "CWE-22":  "Path Traversal: user input used in file path without sanitisation",
    "CWE-502": "Unsafe Deserialization: untrusted data deserialised without validation",
    "CWE-918": "Server-Side Request Forgery (SSRF): server makes requests to attacker-controlled URL",
    "CWE-601": "Open Redirect: user-controlled URL used in redirect without validation",
    "CWE-352": "Cross-Site Request Forgery (CSRF): state-changing request lacks CSRF protection",
    "CWE-862": "Missing Authorization: endpoint accessible without proper permission check",
    "CWE-863": "Incorrect Authorization: authorization check can be bypassed",
    "CWE-306": "Missing Authentication: sensitive functionality accessible without authentication",
    "CWE-798": "Hard-coded Credential: secret, key or password embedded directly in source code",
    "CWE-259": "Hard-coded Password: password stored in plain text in source code",
    "CWE-321": "Hard-coded Cryptographic Key: secret key embedded in code",
    "CWE-312": "Cleartext Storage of Sensitive Information: credential or secret stored unencrypted",
    "CWE-327": "Broken Cryptographic Algorithm: use of weak or broken hash/cipher (MD5, SHA1, DES)",
    "CWE-330": "Insufficient Randomness: use of non-cryptographic random for security purpose",
    "CWE-611": "XML External Entity (XXE): XML parser processes external entity references",
    "CWE-400": "Uncontrolled Resource Consumption: resource usage not bounded (DoS risk)",
    "CWE-732": "Incorrect Permission: file or resource created with overly permissive access",
    "CWE-703": "Improper Error Handling: exception exposes sensitive information",
    "CWE-190": "Integer Overflow: arithmetic operation wraps, causing logic error",
    "CWE-125": "Out-of-Bounds Read: buffer read past allocated boundary",
    "CWE-787": "Out-of-Bounds Write: buffer write past allocated boundary (memory corruption)",
    "CWE-416": "Use-After-Free: memory accessed after being freed",
    "CWE-476": "NULL Pointer Dereference: pointer used without null-check",
    "CWE-377": "Insecure Temporary File: temp file created in shared directory without exclusivity",
    "CWE-307": "Improper Restriction of Excessive Authentication Attempts: no rate limiting on login",
    "CWE-95":  "Improper Neutralization of Directives in eval() (eval Injection)",
    "CWE-20":  "Improper Input Validation: input not validated before use",
}

# ── OWASP → human message ────────────────────────────────────────────────────
_OWASP_MESSAGES: dict[str, str] = {
    "A01:2021": "Broken Access Control: access control policy not enforced",
    "A02:2021": "Cryptographic Failure: sensitive data exposed due to weak or missing encryption",
    "A03:2021": "Injection: untrusted data sent to interpreter as part of a command or query",
    "A04:2021": "Insecure Design: missing or ineffective security control at design level",
    "A05:2021": "Security Misconfiguration: insecure default, unnecessary feature or open cloud storage",
    "A06:2021": "Vulnerable and Outdated Component: using component with known vulnerability",
    "A07:2021": "Authentication Failure: authentication or session management weakness",
    "A08:2021": "Software and Data Integrity Failure: code or data without integrity verification",
    "A09:2021": "Security Logging Failure: insufficient logging and monitoring",
    "A10:2021": "Server-Side Request Forgery: server fetches user-supplied URL without validation",
}

# ── Rule-type prefix → message ────────────────────────────────────────────────
_TYPE_MESSAGES: dict[str, str] = {
    "sql_injection":      "SQL Injection: user input used in raw database query",
    "xss":                "Cross-Site Scripting: user input echoed to HTML without escaping",
    "ssrf":               "SSRF: server-side request to attacker-controlled destination",
    "command_injection":  "Command Injection: user input executed as shell command",
    "shell_injection":    "Shell Injection: subprocess call with shell=True and user input",
    "path_traversal":     "Path Traversal: file path constructed from user input",
    "hardcoded_secret":   "Hard-coded Secret: credential or API key found in source code",
    "hardcoded_password": "Hard-coded Password: password literal found in source code",
    "hardcoded_key":      "Hard-coded Key: cryptographic key embedded in source code",
    "secret_exposure":    "Secret Exposure: sensitive credential found in plaintext",
    "weak_hash":          "Weak Hash Algorithm: MD5 or SHA-1 used for security purpose",
    "insecure_random":    "Insecure Randomness: non-cryptographic random used for security token",
    "eval_injection":     "Eval Injection: eval() called with user-controlled input",
    "deserialization":    "Unsafe Deserialization: untrusted data deserialised",
    "xxe":                "XXE Injection: XML parser may process external entity references",
    "csrf":               "CSRF: state-changing request lacks CSRF token validation",
    "open_redirect":      "Open Redirect: redirect URL controlled by user input",
    "debug_mode":         "Debug Mode Enabled: application running with debug=True in production",
    "missing_auth":       "Missing Authentication: endpoint has no authentication check",
    "broken_access":      "Broken Access Control: authorization check missing or bypassable",
    "integer_overflow":   "Integer Overflow: unchecked arithmetic may wrap around",
    "null_deref":         "Null Pointer Dereference: pointer used without null-check",
    "use_after_free":     "Use-After-Free: memory accessed after deallocation",
    "format_string":      "Format String Vulnerability: user input passed as format string",
    "owasp_finding":      "Security Finding: potential vulnerability detected by OWASP scanner",
    "secret_scanner":     "Secret Detected: sensitive value found in source code",
    "dep_vulnerability":  "Vulnerable Dependency: component with known CVE in use",
    "ton_":               "TON Smart Contract Security Issue detected",
    "taint":              "Taint Flow: user-controlled data reaches sensitive sink without sanitisation",
}


def _normalise_type(t: str) -> str:
    return (t or "").lower().replace("-", "_").replace(" ", "_")


def build_message(finding: dict) -> str:
    """
    Собирает человекочитаемое сообщение для finding.
    Возвращает наилучший вариант из доступных источников.
    """
    # 1. Уже есть непустой message
    existing = (finding.get("message") or "").strip()
    if existing and len(existing) > 5:
        return existing

    # 2. Уже есть description
    desc = (finding.get("description") or "").strip()
    if desc and len(desc) > 5:
        return desc

    # 3. CWE-based
    cwe = (finding.get("cwe") or "").strip()
    if cwe in _CWE_MESSAGES:
        return _CWE_MESSAGES[cwe]

    # 4. OWASP-based
    owasp = (finding.get("owasp") or finding.get("owasp_category") or "").strip()
    for key, msg in _OWASP_MESSAGES.items():
        if key in owasp:
            return msg

    # 5. Type/rule-id keyword match
    ftype = _normalise_type(
        finding.get("type") or finding.get("rule_id") or finding.get("id") or ""
    )
    for keyword, msg in _TYPE_MESSAGES.items():
        if keyword in ftype:
            return msg

    # 6. Generic fallback с деталями
    sev  = finding.get("severity", "UNKNOWN")
    file = finding.get("file") or ""
    line = finding.get("line") or ""
    loc  = f" at {file}:{line}" if file else ""
    return f"{sev} security finding{loc}"


def normalise_finding(finding: dict) -> dict:
    """In-place нормализация finding. Возвращает тот же dict."""
    f = dict(finding)
    f["message"] = build_message(f)

    # Нормализация severity
    sev = (f.get("severity") or "MEDIUM").upper()
    if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        sev = "MEDIUM"
    f["severity"] = sev

    # rule_id если пусто
    if not f.get("rule_id"):
        f["rule_id"] = (
            f.get("id") or
            (f.get("type") or "FINDING").upper().replace(" ", "_")[:32]
        )

    return f


def normalise_all(findings: list[dict]) -> list[dict]:
    """Нормализует весь список findings."""
    return [normalise_finding(f) for f in findings]
