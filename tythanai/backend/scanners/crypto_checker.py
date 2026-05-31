"""
backend/scanners/crypto_checker.py — Cryptographic Misuse Checker

Detects cryptographic weaknesses in Python files via AST analysis and in
non-Python files via regex scanning.

Key detection rules:
- Weak hash (MD5/SHA1) for password vs. general checksum context
- Insecure random in security-sensitive variable assignments
- Hardcoded AES/cipher keys and IVs
- ECB mode usage
- Weak algorithms: DES, RC4, Blowfish, 3DES
- Deprecated TLS versions
- SSL verification disabled
"""
from __future__ import annotations

import ast
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.crypto")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Variable names that indicate password/credential context
_PASSWORD_NAMES: Set[str] = {"password", "passwd", "pwd", "secret", "credential", "passphrase"}

# Variable names that indicate security-sensitive random usage
_SECURE_RANDOM_NAMES: Set[str] = {"token", "otp", "key", "secret", "nonce", "salt", "csrf", "session_id"}

# Variable names that indicate cryptographic key material
_KEY_NAMES: Set[str] = {"key", "iv", "nonce", "secret", "aes_key", "cipher_key", "enc_key", "encryption_key"}

# Byte lengths that could be AES keys (16=128-bit, 24=192-bit, 32=256-bit)
_KEY_BYTE_LENGTHS: Set[int] = {16, 24, 32}

# Checksum/integrity context indicators (reduce severity to INFO)
_CHECKSUM_NAMES: Set[str] = {
    "checksum", "hash", "digest", "fingerprint", "etag", "integrity",
    "file_hash", "content_hash", "data_hash", "chunk_hash", "md5sum",
    "sha1sum", "file_digest", "content_digest", "file_content",
}

_CHECKSUM_CONTEXT_KEYWORDS = {
    "checksum", "integrity", "fingerprint", "etag", "file", "content",
    "data", "chunk", "block", "cache", "dedup", "deduplicate",
}

_SKIP_DIRS: Set[str] = {
    ".git", "__pycache__", ".venv", "venv", "node_modules",
    ".mypy_cache", ".pytest_cache", "dist", "build",
}

# ─────────────────────────────────────────────────────────────────────────────
# NIST SP 800-131A recommendations
# ─────────────────────────────────────────────────────────────────────────────

_RECS: Dict[str, str] = {
    "weak_hash_password": (
        "Replace MD5/SHA-1 with a password hashing function: bcrypt, argon2, or scrypt "
        "(NIST SP 800-131A Rev. 2 §9). MD5 and SHA-1 are disallowed for credential hashing."
    ),
    "weak_hash_general": (
        "Consider replacing MD5/SHA-1 with SHA-256 or SHA-3 for general hashing "
        "(NIST SP 800-131A Rev. 2). MD5/SHA-1 are acceptable only for non-security checksums."
    ),
    "insecure_random": (
        "Replace random.random()/random.randint()/random.choice() with secrets.token_bytes() "
        "or secrets.token_hex() for security-sensitive values (NIST SP 800-90A)."
    ),
    "hardcoded_key": (
        "Never hardcode cryptographic keys/IVs in source code (NIST SP 800-57 Part 1). "
        "Use a key management system (AWS KMS, HashiCorp Vault, Azure Key Vault)."
    ),
    "ecb_mode": (
        "Replace AES-ECB with AES-GCM or AES-CBC with HMAC (authenticated encryption). "
        "ECB mode leaks patterns and provides no semantic security (NIST SP 800-38A)."
    ),
    "weak_algorithm": (
        "Replace DES/3DES/RC4/Blowfish with AES-256-GCM. "
        "These algorithms are deprecated per NIST SP 800-131A Rev. 2."
    ),
    "deprecated_tls": (
        "Use ssl.TLSVersion.TLSv1_2 or TLSv1_3 minimum. "
        "TLS 1.0 and 1.1 are deprecated per NIST SP 800-52 Rev. 2."
    ),
    "no_ssl_verify": (
        "Never disable SSL certificate verification (verify=False). "
        "Use the 'certifi' package for CA bundle and always validate certificates "
        "(NIST SP 800-52 Rev. 2)."
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# AST helpers
# ─────────────────────────────────────────────────────────────────────────────

def _node_line(node: ast.AST) -> int:
    return getattr(node, "lineno", 0)


def _attr_chain(node: ast.expr) -> List[str]:
    parts: List[str] = []
    cur: ast.expr = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    parts.reverse()
    return parts


def _call_parts(node: ast.Call) -> Tuple[str, ...]:
    return tuple(_attr_chain(node.func))


def _get_string_args(node: ast.Call) -> List[str]:
    """Extract constant string arguments from a call node."""
    result: List[str] = []
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            result.append(arg.value)
    for kw in node.keywords:
        if kw.value and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            result.append(kw.value.value)
    return result


def _get_bytes_length(node: ast.expr) -> Optional[int]:
    """Return byte length if node is a bytes literal, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
        return len(node.value)
    return None


def _var_name_contains(name: str, name_set: Set[str]) -> bool:
    """Check if a variable name (lowercased) contains any of the given tokens."""
    name_lower = name.lower()
    return any(token in name_lower for token in name_set)


def _context(lines: List[str], lineno: int, radius: int = 2) -> List[str]:
    start = max(0, lineno - radius - 1)
    end = min(len(lines), lineno + radius)
    return lines[start:end]


def _is_checksum_context(arg_name: str, context_lines: List[str]) -> bool:
    """
    Return True if usage looks like a file integrity/checksum context
    rather than password hashing.
    """
    # Check the variable name itself
    if _var_name_contains(arg_name, _CHECKSUM_NAMES):
        return True
    # Check surrounding code lines
    ctx_text = " ".join(context_lines).lower()
    return any(kw in ctx_text for kw in _CHECKSUM_CONTEXT_KEYWORDS)


def _extract_first_arg_name(node: ast.Call) -> str:
    """Extract the name/attribute of the first argument to a call if it's a Name node."""
    if not node.args:
        return ""
    arg = node.args[0]
    if isinstance(arg, ast.Name):
        return arg.id
    if isinstance(arg, ast.Attribute):
        return arg.attr
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# AST visitor
# ─────────────────────────────────────────────────────────────────────────────

class _CryptoVisitor(ast.NodeVisitor):
    """
    AST visitor that detects cryptographic misuse patterns.
    """

    def __init__(self, source_lines: List[str], filepath: str) -> None:
        self._lines = source_lines
        self._filepath = filepath
        self.findings: List[Finding] = []
        self._imports: Set[str] = set()           # module names imported
        self._import_froms: Dict[str, str] = {}   # name → module

    # ── Import tracking ────────────────────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._imports.add(alias.name)
            self._check_weak_algorithm_import(alias.name, _node_line(node))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            self._import_froms[alias.asname or alias.name] = module
        self._check_weak_algorithm_import(module, _node_line(node))
        self.generic_visit(node)

    def _check_weak_algorithm_import(self, name: str, lineno: int) -> None:
        name_lower = name.lower()
        weak_algos = {
            "des": "DES", "rc4": "RC4", "blowfish": "Blowfish",
            "tripledes": "3DES", "3des": "3DES", "arcfour": "RC4 (arcfour)",
        }
        for key, display in weak_algos.items():
            if key in name_lower:
                ctx = _context(self._lines, lineno)
                self.findings.append(Finding(
                    rule_id="CRYPTO-WEAK-ALGORITHM",
                    file=self._filepath,
                    line=lineno,
                    severity="HIGH",
                    confidence=0.90,
                    cwe_id="CWE-327",
                    description=f"Import of weak cryptographic algorithm: {display}. This algorithm is deprecated per NIST SP 800-131A.",
                    recommendation=_RECS["weak_algorithm"],
                    sources=[self._filepath],
                    context_lines=ctx,
                ))
                break

    # ── Assignment tracking for key material ──────────────────────────────────

    def visit_Assign(self, node: ast.Assign) -> None:
        # Check for hardcoded key/IV bytes assigned to security-sensitive var names
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if _var_name_contains(var_name, _KEY_NAMES):
                    blen = _get_bytes_length(node.value)
                    if blen in _KEY_BYTE_LENGTHS:
                        ctx = _context(self._lines, _node_line(node))
                        self.findings.append(Finding(
                            rule_id="CRYPTO-HARDCODED-KEY",
                            file=self._filepath,
                            line=_node_line(node),
                            severity="HIGH",
                            confidence=0.92,
                            cwe_id="CWE-321",
                            description=(
                                f"Hardcoded {blen*8}-bit key/IV material in variable '{var_name}'. "
                                f"Keys embedded in source are trivially extractable."
                            ),
                            recommendation=_RECS["hardcoded_key"],
                            sources=[self._filepath],
                            context_lines=ctx,
                        ))
                    # Also check for string-based keys
                    elif isinstance(node.value, ast.Constant) and isinstance(node.value.value, (str, bytes)):
                        val = node.value.value
                        byte_len = len(val.encode() if isinstance(val, str) else val)
                        if byte_len in _KEY_BYTE_LENGTHS:
                            ctx = _context(self._lines, _node_line(node))
                            self.findings.append(Finding(
                                rule_id="CRYPTO-HARDCODED-KEY",
                                file=self._filepath,
                                line=_node_line(node),
                                severity="HIGH",
                                confidence=0.88,
                                cwe_id="CWE-321",
                                description=(
                                    f"Hardcoded {byte_len*8}-bit key material in variable '{var_name}'. "
                                    f"Keys embedded in source are trivially extractable."
                                ),
                                recommendation=_RECS["hardcoded_key"],
                                sources=[self._filepath],
                                context_lines=ctx,
                            ))

            # Check for insecure random assigned to security-sensitive var
            if isinstance(target, ast.Name):
                var_name = target.id
                if _var_name_contains(var_name, _SECURE_RANDOM_NAMES):
                    if isinstance(node.value, ast.Call):
                        parts = _call_parts(node.value)
                        if (
                            len(parts) >= 2
                            and parts[0] == "random"
                            and parts[1] in {"random", "randint", "choice", "uniform", "randrange", "getrandbits"}
                        ):
                            ctx = _context(self._lines, _node_line(node))
                            self.findings.append(Finding(
                                rule_id="CRYPTO-INSECURE-RANDOM",
                                file=self._filepath,
                                line=_node_line(node),
                                severity="HIGH",
                                confidence=0.90,
                                cwe_id="CWE-338",
                                description=(
                                    f"Insecure PRNG (random.{parts[1]}) used for security-sensitive "
                                    f"variable '{var_name}'. The random module is not cryptographically secure."
                                ),
                                recommendation=_RECS["insecure_random"],
                                sources=[self._filepath],
                                context_lines=ctx,
                            ))

        self.generic_visit(node)

    # ── Call-level checks ──────────────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:
        parts = _call_parts(node)

        # ── hashlib.md5() / hashlib.sha1() ─────────────────────────────────
        if len(parts) >= 2 and parts[0] == "hashlib" and parts[1] in ("md5", "sha1"):
            self._check_weak_hash(node, parts[1])

        # ── hashlib.new("md5",...) ────────────────────────────────────────
        elif len(parts) >= 2 and parts[0] == "hashlib" and parts[1] == "new":
            str_args = _get_string_args(node)
            if str_args and str_args[0].lower() in ("md5", "sha1", "sha-1"):
                # Treat hashlib.new("md5") the same as hashlib.md5()
                self._check_weak_hash(node, str_args[0].lower())

        # ── AES.new(..., AES.MODE_ECB) ─────────────────────────────────────
        elif (
            (len(parts) >= 2 and parts[0] == "AES" and parts[1] == "new")
            or (len(parts) >= 1 and parts[-1] == "new")
        ):
            self._check_ecb_mode(node)

        # ── Cipher(..., modes.ECB()) ───────────────────────────────────────
        elif len(parts) >= 1 and parts[-1] == "Cipher":
            self._check_ecb_mode(node)

        # ── ssl.PROTOCOL_TLSv1 / ssl.PROTOCOL_TLSv1_1 ────────────────────
        elif len(parts) >= 2 and parts[0] == "ssl":
            pass  # handled via attribute access below

        # ── requests.get/post/put/etc. with verify=False ──────────────────
        if len(parts) >= 2 and parts[0] in ("requests", "session", "Session"):
            self._check_ssl_verify(node)
        elif len(parts) >= 1 and parts[-1] in ("get", "post", "put", "patch", "delete", "request"):
            self._check_ssl_verify(node)

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Detect ssl.PROTOCOL_TLSv1 and ssl.PROTOCOL_TLSv1_1 usage."""
        if (
            isinstance(node.value, ast.Name)
            and node.value.id == "ssl"
            and node.attr in ("PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1", "PROTOCOL_SSLv2", "PROTOCOL_SSLv3")
        ):
            lineno = _node_line(node)
            ctx = _context(self._lines, lineno)
            self.findings.append(Finding(
                rule_id="CRYPTO-DEPRECATED-TLS",
                file=self._filepath,
                line=lineno,
                severity="HIGH",
                confidence=0.95,
                cwe_id="CWE-326",
                description=f"Deprecated TLS/SSL version: ssl.{node.attr}. This version has known vulnerabilities.",
                recommendation=_RECS["deprecated_tls"],
                sources=[self._filepath],
                context_lines=ctx,
            ))
        self.generic_visit(node)

    # ── Weak hash helper ───────────────────────────────────────────────────────

    def _check_weak_hash(self, node: ast.Call, algo: str) -> None:
        """
        Determine context for a weak hash call:
        - If argument name contains password/secret/pwd → HIGH (CWE-328)
        - If argument name or surrounding context suggests checksum → INFO
        - Otherwise → INFO (general use)
        """
        lineno = _node_line(node)
        ctx = _context(self._lines, lineno)
        arg_name = _extract_first_arg_name(node)
        algo_display = algo.upper().replace("-", "")

        # Check if the argument name indicates password context
        is_password_ctx = _var_name_contains(arg_name, _PASSWORD_NAMES)

        # Check if surrounding context indicates checksum use
        is_checksum_ctx = not is_password_ctx and _is_checksum_context(arg_name, ctx)

        if is_password_ctx:
            self.findings.append(Finding(
                rule_id="CRYPTO-WEAK-HASH-PASSWORD",
                file=self._filepath,
                line=lineno,
                severity="HIGH",
                confidence=0.93,
                cwe_id="CWE-328",
                description=(
                    f"Weak hash function {algo_display} used with password/secret data "
                    f"(argument: '{arg_name}'). MD5 and SHA-1 are cryptographically broken "
                    f"for credential hashing."
                ),
                recommendation=_RECS["weak_hash_password"],
                sources=[self._filepath],
                context_lines=ctx,
            ))
        elif is_checksum_ctx:
            # Checksum context — INFO only, not a security issue
            self.findings.append(Finding(
                rule_id="CRYPTO-WEAK-HASH-CHECKSUM",
                file=self._filepath,
                line=lineno,
                severity="INFO",
                confidence=0.60,
                cwe_id="CWE-328",
                description=(
                    f"Weak hash function {algo_display} used in apparent checksum/integrity context "
                    f"(argument: '{arg_name}'). Acceptable for non-security checksums but consider SHA-256."
                ),
                recommendation=_RECS["weak_hash_general"],
                sources=[self._filepath],
                context_lines=ctx,
            ))
        else:
            # Unknown/general context — INFO
            self.findings.append(Finding(
                rule_id="CRYPTO-WEAK-HASH-GENERAL",
                file=self._filepath,
                line=lineno,
                severity="INFO",
                confidence=0.70,
                cwe_id="CWE-328",
                description=(
                    f"Weak hash function {algo_display} used. While acceptable for non-security "
                    f"checksums, prefer SHA-256 or SHA-3 for new code."
                ),
                recommendation=_RECS["weak_hash_general"],
                sources=[self._filepath],
                context_lines=ctx,
            ))

    def _check_ecb_mode(self, node: ast.Call) -> None:
        """Check for ECB mode in AES or generic Cipher calls."""
        lineno = _node_line(node)

        # Check for MODE_ECB in positional args
        for arg in node.args:
            if isinstance(arg, ast.Attribute) and arg.attr in ("MODE_ECB",):
                ctx = _context(self._lines, lineno)
                self.findings.append(Finding(
                    rule_id="CRYPTO-ECB-MODE",
                    file=self._filepath,
                    line=lineno,
                    severity="HIGH",
                    confidence=0.95,
                    cwe_id="CWE-327",
                    description="AES-ECB mode used. ECB mode leaks data patterns and is not semantically secure.",
                    recommendation=_RECS["ecb_mode"],
                    sources=[self._filepath],
                    context_lines=ctx,
                ))
                return
            # modes.ECB() pattern
            if isinstance(arg, ast.Call):
                parts = _call_parts(arg)
                if len(parts) >= 2 and parts[-1] == "ECB":
                    ctx = _context(self._lines, lineno)
                    self.findings.append(Finding(
                        rule_id="CRYPTO-ECB-MODE",
                        file=self._filepath,
                        line=lineno,
                        severity="HIGH",
                        confidence=0.95,
                        cwe_id="CWE-327",
                        description="ECB cipher mode detected. ECB mode leaks data patterns.",
                        recommendation=_RECS["ecb_mode"],
                        sources=[self._filepath],
                        context_lines=ctx,
                    ))
                    return
        # Check keyword arguments
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Attribute):
                if kw.value.attr == "MODE_ECB":
                    ctx = _context(self._lines, lineno)
                    self.findings.append(Finding(
                        rule_id="CRYPTO-ECB-MODE",
                        file=self._filepath,
                        line=lineno,
                        severity="HIGH",
                        confidence=0.95,
                        cwe_id="CWE-327",
                        description="AES-ECB mode used via keyword argument.",
                        recommendation=_RECS["ecb_mode"],
                        sources=[self._filepath],
                        context_lines=ctx,
                    ))
                    return

    def _check_ssl_verify(self, node: ast.Call) -> None:
        """Check for verify=False in HTTP requests."""
        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant):
                if kw.value.value is False:
                    lineno = _node_line(node)
                    ctx = _context(self._lines, lineno)
                    self.findings.append(Finding(
                        rule_id="CRYPTO-NO-SSL-VERIFY",
                        file=self._filepath,
                        line=lineno,
                        severity="MEDIUM",
                        confidence=0.95,
                        cwe_id="CWE-295",
                        description="SSL certificate verification disabled (verify=False). Vulnerable to MITM attacks.",
                        recommendation=_RECS["no_ssl_verify"],
                        sources=[self._filepath],
                        context_lines=ctx,
                    ))


# ─────────────────────────────────────────────────────────────────────────────
# Regex patterns for non-Python files
# ─────────────────────────────────────────────────────────────────────────────

_NON_PY_PATTERNS: List[Tuple[str, re.Pattern[str], str, str, str, float]] = [
    (
        "CRYPTO-ECB-MODE",
        re.compile(r"""(?i)(AES[._\-]ECB|MODE_ECB|ECB\s*mode|cipher\s*=\s*['"']?ecb)"""),
        "HIGH", "CWE-327",
        "ECB cipher mode detected in non-Python source.",
        0.85,
    ),
    (
        "CRYPTO-WEAK-ALGORITHM",
        re.compile(r"""(?i)\b(DES3?|TripleDES|RC4|Blowfish|ARC4|arcfour)\b"""),
        "HIGH", "CWE-327",
        "Weak or deprecated cryptographic algorithm detected.",
        0.82,
    ),
    (
        "CRYPTO-NO-SSL-VERIFY",
        re.compile(r"""(?i)verify\s*[=:]\s*false"""),
        "MEDIUM", "CWE-295",
        "SSL verification disabled in configuration.",
        0.80,
    ),
    (
        "CRYPTO-HARDCODED-KEY",
        re.compile(r"""(?i)(aes[_\-]?key|cipher[_\-]?key|encryption[_\-]?key)\s*[=:]\s*['""][a-zA-Z0-9+/=]{16,}"""),
        "HIGH", "CWE-321",
        "Hardcoded cryptographic key detected.",
        0.80,
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Public scanner class
# ─────────────────────────────────────────────────────────────────────────────

class CryptoChecker:
    """
    Cryptographic misuse checker.

    Uses Python AST for .py files and regex for non-Python files.

    Methods:
        scan_file(path)       → List[Finding]
        scan_directory(path)  → List[Finding]
    """

    def scan_file(self, path: str) -> List[Finding]:
        """Scan a single file for cryptographic misuse."""
        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", path, exc)
            return []

        if path.endswith(".py"):
            return self._scan_python(path, content)
        else:
            return self._scan_non_python(path, content)

    def scan_directory(self, path: str) -> List[Finding]:
        """Scan all eligible files in a directory tree."""
        findings: List[Finding] = []
        target_exts = {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go",
            ".rb", ".php", ".cs", ".cpp", ".c", ".yaml", ".yml",
        }
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for fname in files:
                ext = Path(fname).suffix.lower()
                if ext in target_exts:
                    findings.extend(self.scan_file(os.path.join(root, fname)))
        return findings

    # ── Internal scanning methods ─────────────────────────────────────────────

    def _scan_python(self, filepath: str, content: str) -> List[Finding]:
        """Scan Python source via AST."""
        try:
            tree = ast.parse(content)
        except SyntaxError as exc:
            logger.debug("Syntax error in %s: %s", filepath, exc)
            return []

        lines = content.splitlines()
        visitor = _CryptoVisitor(lines, filepath)
        visitor.visit(tree)
        return visitor.findings

    def _scan_non_python(self, filepath: str, content: str) -> List[Finding]:
        """Scan non-Python files using regex patterns."""
        findings: List[Finding] = []
        lines = content.splitlines()

        for i, line in enumerate(lines, start=1):
            # Skip comment lines
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "/*")):
                continue

            ctx = _context(lines, i)
            for rule_id, pattern, severity, cwe_id, description, confidence in _NON_PY_PATTERNS:
                if pattern.search(line):
                    findings.append(Finding(
                        rule_id=rule_id,
                        file=filepath,
                        line=i,
                        severity=severity,
                        confidence=confidence,
                        cwe_id=cwe_id,
                        description=description,
                        recommendation=_RECS.get(rule_id.lower().replace("crypto-", "").replace("-", "_"), ""),
                        sources=[filepath],
                        context_lines=ctx,
                    ))

        return findings
