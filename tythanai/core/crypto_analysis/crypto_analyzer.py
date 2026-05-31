"""TythanAI Platform — Cryptographic Vulnerability Analyzer (Phase 15)

Detects: weak randomness, timing attacks, weak algorithms,
key management errors, nonce reuse, padding oracle patterns.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class CryptoFinding:
    filepath: str
    line: int
    vuln_type: str       # "weak_rng", "timing_attack", "weak_algo", "key_exposure", "nonce_reuse"
    severity: str
    description: str
    cve_ref: Optional[str]
    recommendation: str
    code_snippet: str
    confidence: float = 0.75


@dataclass
class CryptoReport:
    files_analyzed: int
    findings: List[CryptoFinding]
    risk_score: float    # 0–10
    language: str
    scan_time: float
    summary: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "files_analyzed": self.files_analyzed,
            "language": self.language,
            "risk_score": round(self.risk_score, 2),
            "scan_time": round(self.scan_time, 3),
            "summary": self.summary,
            "findings": [
                {
                    "filepath": f.filepath,
                    "line": f.line,
                    "vuln_type": f.vuln_type,
                    "severity": f.severity,
                    "description": f.description,
                    "cve_ref": f.cve_ref,
                    "recommendation": f.recommendation,
                    "code_snippet": f.code_snippet,
                    "confidence": f.confidence,
                }
                for f in self.findings
            ],
        }


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

# (rule_id, vuln_type, severity, cve_ref, languages, pattern, description, recommendation)
CRYPTO_RULES = [
    # ── Weak randomness ────────────────────────────────────────────────
    ("CR001", "weak_rng", "HIGH", None,
     ["python"], r"\brandom\.(?:random|randint|choice|seed|shuffle)\s*\(",
     "Python math/random PRNG is not cryptographically secure.",
     "Use secrets.token_bytes() or os.urandom() for security-sensitive values."),

    ("CR002", "weak_rng", "HIGH", None,
     ["go"], r"\bmath/rand\b|\brand\.(?:Intn|Int63|Float64|Seed)\s*\(",
     "math/rand is not cryptographically secure.",
     "Use crypto/rand.Read() for security-sensitive random values."),

    ("CR003", "weak_rng", "HIGH", None,
     ["cpp"], r"\bsrand\s*\(\s*time\s*\(|\brand\s*\(\s*\)",
     "C rand() seeded with time is predictable.",
     "Use /dev/urandom, RAND_bytes (OpenSSL), or std::random_device for security."),

    ("CR004", "weak_rng", "CRITICAL", None,
     ["solidity"], r"\bblock\.(?:timestamp|number|difficulty|prevrandao|coinbase)\b.*(?:seed|random|nonce|entropy)",
     "Block values are miner-manipulable and not suitable as entropy sources.",
     "Use a commit-reveal scheme or Chainlink VRF for on-chain randomness."),

    ("CR005", "weak_rng", "HIGH", None,
     ["rust"], r"\bRng::(?:gen|next|fill)|rand::thread_rng\(\)\.gen",
     "rand::thread_rng is not cryptographically secure in security contexts.",
     "Use rand::rngs::OsRng or the getrandom crate for cryptographic randomness."),

    # ── Timing attacks ─────────────────────────────────────────────────
    ("CR010", "timing_attack", "HIGH", None,
     ["python"], r"if\s+\w+\s*==\s*\w+\s*:.*#.*(?:password|token|secret|hmac|sig)",
     "String equality check is not constant-time — vulnerable to timing oracle.",
     "Use hmac.compare_digest() for constant-time comparison of secrets."),

    ("CR011", "timing_attack", "HIGH", None,
     ["python"], r"if\s+(?:password|token|secret|hmac|signature|key)\s*==",
     "Direct == comparison of cryptographic values leaks timing information.",
     "Use hmac.compare_digest() or secrets.compare_digest() for constant-time comparison."),

    ("CR012", "timing_attack", "HIGH", None,
     ["cpp"], r"\bmemcmp\s*\([^)]*(?:password|hmac|token|sig|secret|key)[^)]*\)",
     "memcmp short-circuits on first mismatch, enabling timing oracle attacks.",
     "Use a constant-time comparison function (e.g., CRYPTO_memcmp from OpenSSL)."),

    ("CR013", "timing_attack", "HIGH", None,
     ["go"], r'bytes\.Equal\s*\([^)]*(?:password|token|hmac|sig)\w*[^)]*\)',
     "bytes.Equal is not guaranteed to be constant-time.",
     "Use subtle.ConstantTimeCompare() for comparing cryptographic values."),

    # ── Weak algorithms ────────────────────────────────────────────────
    ("CR020", "weak_algo", "HIGH", "CVE-2004-2761",
     ["python", "go", "cpp", "rust", "solidity"],
     r'\b(?:MD5|md5|SHA1|sha1|sha_1|SHA-1)\b',
     "MD5/SHA-1 are cryptographically broken for security uses.",
     "Use SHA-256, SHA-3, or BLAKE2 for security-sensitive hashing."),

    ("CR021", "weak_algo", "CRITICAL", "CVE-2016-2183",
     ["python", "go", "cpp"],
     r'\b(?:DES|3DES|TripleDES|RC4|RC2|Blowfish)\b',
     "DES/3DES/RC4 are broken symmetric ciphers.",
     "Use AES-256-GCM or ChaCha20-Poly1305."),

    ("CR022", "weak_algo", "HIGH", None,
     ["python"], r'AES\.new\s*\([^)]+,\s*AES\.MODE_ECB',
     "AES-ECB mode does not provide semantic security (patterns leak).",
     "Use AES-GCM or AES-CBC with a random IV."),

    ("CR023", "weak_algo", "HIGH", None,
     ["python", "go", "cpp"],
     r'RSA\w*\s*\(\s*(?:key_size\s*=\s*)?(?:512|768|1024)\b',
     "RSA key size < 2048 bits is insufficient for security.",
     "Use RSA-2048 minimum; prefer RSA-4096 or ECDSA P-256."),

    # ── Key management ─────────────────────────────────────────────────
    ("CR030", "key_exposure", "CRITICAL", None,
     ["python", "go", "cpp", "rust", "solidity"],
     r'(?:private_key|priv_key|secret_key|sk|PRIVATE_KEY)\s*=\s*["\'](?:[A-Fa-f0-9]{32,}|[A-Za-z0-9+/=]{32,})["\']',
     "Hardcoded private key detected in source code.",
     "Store keys in environment variables, KMS, or HSM. Never commit keys to source."),

    ("CR031", "key_exposure", "HIGH", None,
     ["python", "go", "cpp", "rust"],
     r'(?:password|passwd|secret|api_key|apikey)\s*=\s*["\'][^"\']{8,}["\']',
     "Hardcoded credential/secret detected.",
     "Use environment variables or a secrets management service."),

    ("CR032", "key_exposure", "HIGH", None,
     ["python"], r'key\s*=\s*os\.environ\.get\s*\([^)]+\)\s*or\s*["\'][^"\']+["\']',
     "Fallback hardcoded key if env var not set.",
     "Raise an exception if the required environment variable is missing — never fall back to a hardcoded value."),

    ("CR033", "key_exposure", "MEDIUM", None,
     ["python", "go", "cpp", "rust"],
     r'(?:seed|salt)\s*=\s*(?:b?["\'][^"\']{0,8}["\']|\d{1,6})\b',
     "Short or hardcoded seed/salt detected.",
     "Use a cryptographically random salt of at least 16 bytes."),

    # ── Nonce reuse ────────────────────────────────────────────────────
    ("CR040", "nonce_reuse", "CRITICAL", None,
     ["python"], r'AES\.(?:GCM|CCM).*nonce\s*=\s*(?:b?\x27\x27\x27|b?"\x22\x22|b?0{24,}|b?\x27.{0,8}\x27)',
     "Static or zero nonce with AES-GCM — nonce reuse breaks authentication.",
     "Generate a fresh random 12-byte nonce for every AES-GCM encryption."),

    ("CR041", "nonce_reuse", "HIGH", None,
     ["python", "go", "cpp"],
     r'nonce\s*=\s*(?:0|None|b"\\x00+"|bytes\s*\(\s*\d+\s*\))\b',
     "Zero or null nonce detected — likely nonce reuse.",
     "Use os.urandom(12) or equivalent for each encryption operation."),

    # ── Padding oracle ─────────────────────────────────────────────────
    ("CR050", "padding_oracle", "HIGH", None,
     ["python"], r'unpad\s*\(|PKCS7\s*\(|padding\.PKCS7\s*\(',
     "CBC+PKCS7 padding without authenticated encryption is vulnerable to padding oracle.",
     "Use AES-GCM (AEAD) instead of CBC+PKCS7. If CBC is required, add HMAC-SHA256 before decryption."),

    ("CR051", "padding_oracle", "HIGH", None,
     ["cpp", "go"],
     r'(?:EVP_DecryptFinal|AES_cbc_encrypt|CBCDecrypt)\s*\(',
     "CBC decryption without prior MAC verification — potential padding oracle.",
     "Verify HMAC before decrypting. Use AEAD ciphers to avoid this class of attack."),

    # ── Side channels ──────────────────────────────────────────────────
    ("CR060", "side_channel", "MEDIUM", None,
     ["python", "go", "cpp", "rust"],
     r'(?:pow|math\.pow)\s*\([^)]+\)\s*%\s*\w+',
     "Modular exponentiation without constant-time implementation leaks via timing.",
     "Use a constant-time modular exponentiation library for RSA/DH private operations."),

    ("CR061", "side_channel", "MEDIUM", None,
     ["cpp"], r'(?:BN_mod_exp|RSA_private_decrypt)\s*\(',
     "Ensure BN_mod_exp is called with BN_FLG_CONSTTIME flag to prevent timing leakage.",
     "Pass BN_FLG_CONSTTIME to BN_mod_exp. Use BN_mod_exp_mont_consttime."),
]

EXT_TO_LANG = {
    ".py": "python", ".sol": "solidity", ".vy": "solidity",
    ".rs": "rust", ".go": "go",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".c": "cpp", ".h": "cpp", ".hpp": "cpp",
}


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class CryptoAnalyzer:

    def __init__(self):
        self._rules = CRYPTO_RULES

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, path: str) -> CryptoReport:
        t0 = time.time()
        p = Path(path)
        files = self._collect_files(p)
        all_findings: List[CryptoFinding] = []

        for filepath in files:
            lang = EXT_TO_LANG.get(Path(filepath).suffix.lower(), "unknown")
            try:
                source = Path(filepath).read_text(errors="replace")
            except OSError:
                continue
            for check in (
                self.check_weak_randomness,
                self.check_timing_attacks,
                self.check_weak_algorithms,
                self.check_key_management,
                self.check_padding_oracle,
                self.check_nonce_reuse,
                self.check_side_channels,
            ):
                all_findings.extend(check(source, filepath, lang))

        risk_score = self._compute_risk(all_findings)
        summary = self._summarize(all_findings)
        dominant_lang = self._dominant_lang(files)

        return CryptoReport(
            files_analyzed=len(files),
            findings=all_findings,
            risk_score=risk_score,
            language=dominant_lang,
            scan_time=time.time() - t0,
            summary=summary,
        )

    # ------------------------------------------------------------------
    # Specific checks (each delegates to _apply_rules)
    # ------------------------------------------------------------------

    def check_weak_randomness(self, source: str, filepath: str, lang: str) -> List[CryptoFinding]:
        return self._apply_rules(source, filepath, lang, "weak_rng")

    def check_timing_attacks(self, source: str, filepath: str, lang: str) -> List[CryptoFinding]:
        return self._apply_rules(source, filepath, lang, "timing_attack")

    def check_weak_algorithms(self, source: str, filepath: str, lang: str) -> List[CryptoFinding]:
        return self._apply_rules(source, filepath, lang, "weak_algo")

    def check_key_management(self, source: str, filepath: str, lang: str) -> List[CryptoFinding]:
        return self._apply_rules(source, filepath, lang, "key_exposure")

    def check_padding_oracle(self, source: str, filepath: str, lang: str) -> List[CryptoFinding]:
        return self._apply_rules(source, filepath, lang, "padding_oracle")

    def check_nonce_reuse(self, source: str, filepath: str, lang: str) -> List[CryptoFinding]:
        return self._apply_rules(source, filepath, lang, "nonce_reuse")

    def check_side_channels(self, source: str, filepath: str, lang: str) -> List[CryptoFinding]:
        return self._apply_rules(source, filepath, lang, "side_channel")

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report(self, report: CryptoReport) -> str:
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        lines = [
            "=" * 70,
            "  CRYPTOGRAPHIC VULNERABILITY REPORT — TythanAI Phase 15",
            "=" * 70,
            f"Language:        {report.language}",
            f"Files analyzed:  {report.files_analyzed}",
            f"Risk score:      {report.risk_score:.1f}/10",
            f"Scan time:       {report.scan_time:.2f}s",
            "",
            "Summary:",
        ]
        for sev in sev_order:
            count = report.summary.get(sev, 0)
            if count:
                lines.append(f"  {sev:<12} {count}")
        lines.append("")

        by_type: Dict[str, List[CryptoFinding]] = {}
        for f in report.findings:
            by_type.setdefault(f.vuln_type, []).append(f)

        type_labels = {
            "weak_rng": "Weak Randomness",
            "timing_attack": "Timing Attack",
            "weak_algo": "Weak Algorithm",
            "key_exposure": "Key / Secret Exposure",
            "nonce_reuse": "Nonce Reuse",
            "padding_oracle": "Padding Oracle",
            "side_channel": "Side Channel",
        }

        for vtype, label in type_labels.items():
            if vtype not in by_type:
                continue
            lines.append(f"\n[{label}] — {len(by_type[vtype])} finding(s)")
            lines.append("-" * 60)
            for f in by_type[vtype]:
                lines.append(f"  [{f.severity}] {f.description}")
                lines.append(f"  File: {f.filepath}:{f.line}")
                if f.cve_ref:
                    lines.append(f"  CVE:  {f.cve_ref}")
                lines.append(f"  Fix:  {f.recommendation}")
                lines.append(f"  Code: {f.code_snippet[:80]}")
                lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_rules(
        self, source: str, filepath: str, lang: str, vuln_type: str
    ) -> List[CryptoFinding]:
        findings: List[CryptoFinding] = []
        lines = source.splitlines()
        for rule in self._rules:
            rid, vtype, severity, cve_ref, languages, pattern, description, recommendation = rule
            if vtype != vuln_type:
                continue
            if languages and lang not in languages:
                continue
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(CryptoFinding(
                        filepath=filepath,
                        line=i,
                        vuln_type=vtype,
                        severity=severity,
                        description=description,
                        cve_ref=cve_ref,
                        recommendation=recommendation,
                        code_snippet=line.strip()[:100],
                        confidence=0.80,
                    ))
        return findings

    def _collect_files(self, p: Path) -> List[str]:
        if p.is_file():
            return [str(p)]
        exts = set(EXT_TO_LANG.keys())
        return [str(f) for f in p.rglob("*") if f.is_file() and f.suffix.lower() in exts]

    def _dominant_lang(self, files: List[str]) -> str:
        counts: Dict[str, int] = {}
        for f in files:
            lang = EXT_TO_LANG.get(Path(f).suffix.lower(), "unknown")
            counts[lang] = counts.get(lang, 0) + 1
        return max(counts, key=counts.get) if counts else "unknown"

    def _compute_risk(self, findings: List[CryptoFinding]) -> float:
        weights = {"CRITICAL": 3.0, "HIGH": 1.5, "MEDIUM": 0.5, "LOW": 0.1}
        raw = sum(weights.get(f.severity, 0) * f.confidence for f in findings)
        return min(raw, 10.0)

    def _summarize(self, findings: List[CryptoFinding]) -> Dict[str, int]:
        s: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            s[f.severity] = s.get(f.severity, 0) + 1
        return s
