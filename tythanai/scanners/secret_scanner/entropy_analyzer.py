"""
TythanAI Platform — Entropy-based Secret Scanner
Shannon entropy analysis for catching secrets that pattern-matching misses:
random API keys, tokens without standard prefixes, and high-entropy assignments.

Combines entropy scoring with context heuristics (variable names, assignment
contexts, encoding type) to minimize false positives from legitimate
high-entropy code (hashes, test vectors, minified JS, etc.).
"""
from __future__ import annotations

import base64
import math
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Skip-lists
# ---------------------------------------------------------------------------

SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar",
    ".gz", ".bin", ".exe", ".dll", ".so", ".pyc", ".lock", ".woff",
    ".woff2", ".ttf", ".eot", ".map", ".svg",
})

SKIP_DIRS = frozenset({
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".next", "vendor",
})

# ---------------------------------------------------------------------------
# Entropy thresholds by encoding class
# ---------------------------------------------------------------------------

# (min_entropy, min_length)
THRESHOLDS: Dict[str, Tuple[float, int]] = {
    "hex":         (3.5, 16),
    "base64":      (4.5, 20),
    "alphanumeric":(3.8, 20),
    "url":         (3.6, 24),
    "generic":     (4.0, 20),
}

# Variable/context names that strongly indicate secrets
SECRET_VAR_NAMES = frozenset({
    "key", "secret", "token", "password", "passwd", "pwd", "api_key",
    "apikey", "auth", "credential", "credentials", "access_key",
    "access_token", "refresh_token", "private_key", "secret_key",
    "client_secret", "signing_key", "encryption_key", "auth_token",
    "bearer", "authorization", "private", "seed", "mnemonic",
    "passphrase", "service_account", "webhook_secret",
})

# File extensions where high-entropy strings are EXPECTED (lower threshold boost)
LIKELY_CODE_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".java", ".go", ".rb", ".rs", ".c", ".cpp",
    ".cs", ".swift", ".kt", ".php", ".scala", ".clj",
})

# Patterns that almost certainly indicate benign high-entropy strings
FALSE_POSITIVE_PATTERNS: List[re.Pattern] = [
    re.compile(r'^[0-9a-f]{32,64}$', re.IGNORECASE),         # plain hash digest
    re.compile(r'^[0-9a-fA-F]{64}$'),                         # SHA-256 hex
    re.compile(r'(?:test|mock|fake|example|placeholder|dummy|sample|xxx)', re.IGNORECASE),
    re.compile(r'^[A-Z_]{5,}$'),                               # all-caps constant
    re.compile(r'\.(min|bundle|chunk)\.(js|css)$', re.IGNORECASE),  # minified files
    re.compile(r'[^a-zA-Z0-9+/=\-_]'),                        # non-secret chars
]

# Regex to identify assignment contexts: var_name = "value" or var_name: "value"
ASSIGNMENT_RE = re.compile(
    r"""
    (?:
        (?P<varname>[a-zA-Z_][\w.]*?)           # variable/key name
        \s*[:=]\s*                               # assignment or dict colon
        ["\'](?P<value>[A-Za-z0-9+/=_\-]{10,})["\']  # quoted string value
    )
    """,
    re.VERBOSE,
)

# Standalone high-entropy string (not necessarily assigned)
STANDALONE_RE = re.compile(r'["\']([A-Za-z0-9+/=_\-]{20,})["\']')


# ---------------------------------------------------------------------------
# Encoding detection helpers
# ---------------------------------------------------------------------------

def _detect_encoding(value: str) -> str:
    """Classify a string's likely encoding."""
    if re.fullmatch(r'[0-9a-fA-F]+', value):
        return "hex"
    if re.fullmatch(r'[A-Za-z0-9+/=]+', value) and len(value) % 4 == 0:
        try:
            base64.b64decode(value, validate=True)
            return "base64"
        except Exception:
            pass
    if re.fullmatch(r'[A-Za-z0-9_\-]+', value):
        return "alphanumeric"
    if re.fullmatch(r'[A-Za-z0-9%_.~\-]+', value):
        return "url"
    return "generic"


def _mask(s: str) -> str:
    """Partially mask a sensitive string for display."""
    if len(s) <= 8:
        return "****"
    return s[:4] + "*" * min(len(s) - 8, 24) + s[-4:]


# ---------------------------------------------------------------------------
# EntropyAnalyzer
# ---------------------------------------------------------------------------

class EntropyAnalyzer:
    """
    Shannon entropy-based scanner for hardcoded secrets.

    Combines entropy scoring with variable-name heuristics to surface
    high-entropy strings that are likely secrets, while filtering out
    legitimate high-entropy content (code hashes, test vectors, etc.).

    Usage::

        analyzer = EntropyAnalyzer()
        findings = analyzer.scan_file("/path/to/config.py")
        findings = analyzer.scan_string(text, context="config.env")
    """

    def scan_file(self, path: str) -> List[Dict]:
        """
        Scan a single file for high-entropy secrets.

        Skips binary files, minified JS/CSS, and known-safe extensions.
        Returns a list of finding dicts compatible with the Ghost platform schema.
        """
        p = Path(path)
        if p.suffix.lower() in SKIP_EXTENSIONS:
            return []
        if any(part in SKIP_DIRS for part in p.parts):
            return []

        # Guard against minified files: if a single line > 2000 chars → skip
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        if self._is_minified(raw):
            return []

        context = str(p)
        findings = self.scan_string(raw, context=context)
        return self._filter_false_positives(findings)

    def scan_string(self, text: str, context: str = "") -> List[Dict]:
        """
        Scan an arbitrary string for high-entropy secret patterns.

        ``context`` is used only for metadata in findings (e.g. filename).
        Returns raw findings before false-positive filtering.
        """
        findings: List[Dict] = []
        lines = text.splitlines()
        seen: set = set()

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip comment-only lines
            if stripped.startswith(("#", "//", "/*", "*", "<!--", ";")):
                continue

            # Priority path: assignment context
            for m in ASSIGNMENT_RE.finditer(line):
                varname = (m.group("varname") or "").lower().rstrip("._")
                value   = m.group("value") or ""
                if len(value) < 10:
                    continue
                entropy = self.shannon_entropy(value)
                if self.is_likely_secret(value, var_name=varname, context=context):
                    key = (lineno, value[:16])
                    if key in seen:
                        continue
                    seen.add(key)
                    encoding = _detect_encoding(value)
                    is_named = varname in SECRET_VAR_NAMES or any(
                        s in varname for s in SECRET_VAR_NAMES
                    )
                    findings.append(self._build_finding(
                        file=context,
                        line=lineno,
                        varname=varname,
                        value=value,
                        entropy=entropy,
                        encoding=encoding,
                        confidence=90 if is_named else 65,
                        context_type="assignment",
                    ))

            # Secondary path: any quoted string with high entropy (no assignment)
            for m in STANDALONE_RE.finditer(line):
                value = m.group(1)
                if len(value) < 20:
                    continue
                # Only flag standalone strings with very high entropy
                entropy = self.shannon_entropy(value)
                encoding = _detect_encoding(value)
                threshold, _ = THRESHOLDS.get(encoding, THRESHOLDS["generic"])
                if entropy >= threshold + 0.5:  # stricter threshold for no-context
                    key = (lineno, value[:16])
                    if key in seen:
                        continue
                    # Skip if already caught by assignment path
                    already = any(
                        f["line"] == lineno and value[:16] in f.get("evidence", "")
                        for f in findings
                    )
                    if already:
                        continue
                    seen.add(key)
                    findings.append(self._build_finding(
                        file=context,
                        line=lineno,
                        varname="",
                        value=value,
                        entropy=entropy,
                        encoding=encoding,
                        confidence=45,
                        context_type="standalone",
                    ))

        return findings

    @staticmethod
    def shannon_entropy(data: str) -> float:
        """
        Calculate the Shannon entropy of a string in bits per character.

        A truly random 64-char alphanumeric string scores ~5.95 bits.
        English prose typically scores 3.0–4.0 bits.
        Returns 0.0 for empty strings.
        """
        if not data:
            return 0.0
        length = len(data)
        freq = {}
        for ch in data:
            freq[ch] = freq.get(ch, 0) + 1
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    def is_likely_secret(
        self,
        value: str,
        var_name: str = "",
        context: str = "",
    ) -> bool:
        """
        Determine whether a string value is likely a hardcoded secret.

        Considers:
        - Shannon entropy vs. encoding-specific threshold
        - Variable name heuristics
        - Known benign patterns (test vectors, plain hashes, constant names)
        """
        if not value or len(value) < 8:
            return False

        entropy  = self.shannon_entropy(value)
        encoding = _detect_encoding(value)
        threshold, min_len = THRESHOLDS.get(encoding, THRESHOLDS["generic"])

        if len(value) < min_len:
            return False

        # Check against known-benign patterns
        for pat in FALSE_POSITIVE_PATTERNS[:3]:  # skip filename pattern
            if pat.search(value):
                # Benign pattern match — override only if var name is a known secret name
                var_lower = var_name.lower()
                if not (var_lower in SECRET_VAR_NAMES or any(s in var_lower for s in SECRET_VAR_NAMES)):
                    return False

        # Boost threshold for contexts without a suspicious variable name
        var_lower = var_name.lower()
        name_match = (
            var_lower in SECRET_VAR_NAMES
            or any(s in var_lower for s in SECRET_VAR_NAMES)
        )

        effective_threshold = threshold if name_match else threshold + 0.6

        if entropy < effective_threshold:
            return False

        # If it's a source-code file without a secret variable name,
        # require a higher bar (high-entropy strings are common in code)
        ctx_ext = Path(context).suffix.lower() if context else ""
        if ctx_ext in LIKELY_CODE_EXTENSIONS and not name_match:
            if entropy < threshold + 1.0:
                return False

        return True

    def _filter_false_positives(self, findings: List[Dict]) -> List[Dict]:
        """
        Post-process findings to remove known false-positive classes:

        - Strings that are all-caps constants (e.g. DEFAULT_REGION)
        - Values that look like UUIDs (already well-structured)
        - Very short values that slipped through
        - Duplicate findings at the same line/value
        - Findings from minified or binary-like contexts
        """
        uuid_re  = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            re.IGNORECASE,
        )
        allcaps_re = re.compile(r'^[A-Z0-9_]{6,}$')
        # Common benign high-entropy patterns
        hash_re  = re.compile(r'^[0-9a-f]{32,}$', re.IGNORECASE)
        version_re = re.compile(r'^\d+\.\d+\.\d+')

        seen_keys: set = set()
        result: List[Dict] = []

        for f in findings:
            raw_value = f.get("_raw_value", "")
            if not raw_value:
                # Fall back to evidence
                raw_value = f.get("evidence", "").replace("*", "")

            # Deduplicate by (line, first-12-chars of value)
            dedup_key = (f.get("line", 0), raw_value[:12])
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            # Skip UUID-shaped values
            if uuid_re.match(raw_value):
                continue

            # Skip all-caps constants
            if allcaps_re.match(raw_value):
                continue

            # Skip plain hashes without secret variable name
            if hash_re.match(raw_value) and f.get("confidence", 100) < 70:
                continue

            # Skip version strings
            if version_re.match(raw_value):
                continue

            # Remove internal field before returning
            clean = {k: v for k, v in f.items() if not k.startswith("_")}
            result.append(clean)

        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_finding(
        self,
        file: str,
        line: int,
        varname: str,
        value: str,
        entropy: float,
        encoding: str,
        confidence: int,
        context_type: str,
    ) -> Dict:
        severity = self._severity_for_entropy(entropy, varname)
        desc_varname = f" in variable '{varname}'" if varname else ""
        return {
            "type":           "HIGH_ENTROPY_SECRET",
            "id":             "ENT-SECRET",
            "severity":       severity,
            "cwe":            "CWE-798",
            "file":           file,
            "line":           line,
            "description":    (
                f"High-entropy {encoding} string (entropy={entropy:.2f})"
                f"{desc_varname} — likely hardcoded secret"
            ),
            "evidence":       _mask(value),
            "_raw_value":     value,        # stripped by _filter_false_positives
            "entropy":        round(entropy, 3),
            "encoding":       encoding,
            "var_name":       varname,
            "context_type":   context_type,
            "recommendation": (
                "Remove hardcoded secret from source code. "
                "Rotate the credential immediately. "
                "Store in environment variables or a secrets manager "
                "(HashiCorp Vault, AWS Secrets Manager, etc.)."
            ),
            "category":       "High Entropy Secret",
            "source":         "entropy_analyzer",
            "confidence":     confidence,
        }

    @staticmethod
    def _severity_for_entropy(entropy: float, varname: str) -> str:
        """Map entropy + variable name to a severity level."""
        var_lower = varname.lower()
        is_critical_name = any(
            s in var_lower
            for s in ("private_key", "secret_key", "signing_key", "mnemonic",
                      "seed", "passphrase", "password", "passwd", "pwd")
        )
        is_high_name = any(
            s in var_lower
            for s in ("token", "api_key", "apikey", "auth", "credential",
                      "access_key", "access_token", "client_secret")
        )

        if is_critical_name:
            return "CRITICAL"
        if entropy >= 5.5 or is_high_name:
            return "HIGH"
        if entropy >= 4.5:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _is_minified(text: str) -> bool:
        """
        Heuristic: if ANY single line exceeds 2000 characters and the file
        contains mostly alphanumeric runs, treat it as minified/binary.
        """
        for line in text.splitlines():
            if len(line) > 2000:
                return True
        # Binary content check: high proportion of non-printable bytes
        sample = text[:4096]
        non_printable = sum(1 for c in sample if ord(c) > 127 or (ord(c) < 32 and c not in "\t\n\r"))
        if len(sample) > 0 and non_printable / len(sample) > 0.1:
            return True
        return False
