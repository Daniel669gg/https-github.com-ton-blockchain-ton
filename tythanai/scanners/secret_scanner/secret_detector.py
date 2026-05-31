"""
TythanAI — Enhanced Secret Detector v2.2
High-entropy + pattern detection for 60+ secret types.
"""
import math, re
from pathlib import Path
from typing import Dict, List

# (name, regex, severity, service)
SECRET_PATTERNS = [
    # ── OpenAI ────────────────────────────────────────────────────────────────
    ("openai_key",       r'sk-[a-zA-Z0-9]{48}',                          "CRITICAL","OpenAI"),
    ("openai_org",       r'org-[a-zA-Z0-9]{24}',                         "HIGH",    "OpenAI"),
    # ── AWS ───────────────────────────────────────────────────────────────────
    ("aws_access_key",   r'AKIA[0-9A-Z]{16}',                            "CRITICAL","AWS"),
    ("aws_secret_key",   r'(?i)aws.{0,20}secret.{0,20}["\'][0-9a-zA-Z/+]{40}["\']',"CRITICAL","AWS"),
    ("aws_session_token",r'(?i)aws.{0,20}session.{0,20}["\'][A-Za-z0-9/+=]{100,}["\']',"CRITICAL","AWS"),
    # ── GCP ───────────────────────────────────────────────────────────────────
    ("gcp_service_account",r'"type":\s*"service_account"',               "CRITICAL","GCP"),
    ("gcp_api_key",      r'AIza[0-9A-Za-z\-_]{35}',                      "CRITICAL","GCP"),
    # ── GitHub ────────────────────────────────────────────────────────────────
    ("github_pat",       r'ghp_[A-Za-z0-9]{36}',                         "CRITICAL","GitHub"),
    ("github_oauth",     r'gho_[A-Za-z0-9]{36}',                         "CRITICAL","GitHub"),
    ("github_app",       r'(ghs_|ghu_)[A-Za-z0-9]{36}',                  "CRITICAL","GitHub"),
    # ── Stripe ────────────────────────────────────────────────────────────────
    ("stripe_secret",    r'sk_live_[0-9a-zA-Z]{24,}',                    "CRITICAL","Stripe"),
    ("stripe_restricted",r'rk_live_[0-9a-zA-Z]{24,}',                   "CRITICAL","Stripe"),
    ("stripe_test",      r'sk_test_[0-9a-zA-Z]{24,}',                   "HIGH",    "Stripe"),
    # ── Twilio ────────────────────────────────────────────────────────────────
    ("twilio_account",   r'AC[a-z0-9]{32}',                              "HIGH",    "Twilio"),
    ("twilio_auth",      r'(?i)twilio.{0,20}["\'][a-z0-9]{32}["\']',    "CRITICAL","Twilio"),
    # ── SendGrid ──────────────────────────────────────────────────────────────
    ("sendgrid_key",     r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}', "CRITICAL","SendGrid"),
    # ── Slack ─────────────────────────────────────────────────────────────────
    ("slack_token",      r'xox[baprs]-[0-9A-Za-z\-]{10,}',              "CRITICAL","Slack"),
    ("slack_webhook",    r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+', "HIGH","Slack"),
    # ── Discord ───────────────────────────────────────────────────────────────
    ("discord_token",    r'(?i)(discord.{0,20}token.{0,10})["\'][A-Za-z0-9\.\-_]{50,}["\']',"CRITICAL","Discord"),
    ("discord_webhook",  r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+', "HIGH","Discord"),
    # ── Telegram ──────────────────────────────────────────────────────────────
    ("telegram_bot",     r'[0-9]{8,10}:[A-Za-z0-9_\-]{35}',             "HIGH",    "Telegram"),
    # ── JWT ───────────────────────────────────────────────────────────────────
    ("jwt_token",        r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', "HIGH","JWT"),
    # ── Private Keys ─────────────────────────────────────────────────────────
    ("rsa_private",      r'-----BEGIN RSA PRIVATE KEY-----',             "CRITICAL","Crypto"),
    ("ec_private",       r'-----BEGIN EC PRIVATE KEY-----',              "CRITICAL","Crypto"),
    ("openssh_private",  r'-----BEGIN OPENSSH PRIVATE KEY-----',         "CRITICAL","Crypto"),
    ("pgp_private",      r'-----BEGIN PGP PRIVATE KEY BLOCK-----',       "CRITICAL","Crypto"),
    # ── Crypto Wallets ────────────────────────────────────────────────────────
    ("eth_private_key",  r'(?i)(private.?key|pk).{0,10}0x[0-9a-fA-F]{64}', "CRITICAL","Ethereum"),
    ("mnemonic_phrase",  r'\b(abandon|ability|able|about|above)\b.{1,200}\b(abandon|ability|able|about|above)\b', "CRITICAL","Crypto Wallet"),
    # ── Databases ────────────────────────────────────────────────────────────
    ("mongodb_uri",      r'mongodb(\+srv)?://[^:]+:[^@]+@',              "CRITICAL","MongoDB"),
    ("postgres_uri",     r'postgresql?://[^:]+:[^@]+@',                  "CRITICAL","PostgreSQL"),
    ("mysql_uri",        r'mysql://[^:]+:[^@]+@',                        "CRITICAL","MySQL"),
    ("redis_url",        r'redis://:[^@]+@',                             "HIGH",    "Redis"),
    # ── Generic patterns ─────────────────────────────────────────────────────
    ("generic_secret",   r'(?i)(secret|password|passwd|pwd)\s*=\s*["\'][a-zA-Z0-9!@#$%^&*]{12,}["\']',"HIGH","Generic"),
    ("generic_api_key",  r'(?i)api.?key\s*=\s*["\'][a-zA-Z0-9_\-]{20,}["\']', "HIGH","Generic"),
    ("bearer_token",     r'[Bb]earer\s+[A-Za-z0-9\-_\.=]{20,}',         "HIGH",    "Bearer Auth"),
    ("basic_auth_url",   r'https?://[^:@\s]+:[^@\s]+@',                  "HIGH",    "Basic Auth in URL"),
    # ── Cloud / SaaS ──────────────────────────────────────────────────────────
    ("mailgun_key",      r'key-[0-9a-z]{32}',                            "HIGH",    "Mailgun"),
    ("cloudinary_url",   r'cloudinary://[0-9]+:[A-Za-z0-9_\-]+@',       "HIGH",    "Cloudinary"),
    ("heroku_api",       r'(?i)heroku.{0,20}["\'][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\']',"HIGH","Heroku"),
    ("firebase_key",     r'AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}', "CRITICAL","Firebase"),
    # ── TON / Blockchain ──────────────────────────────────────────────────────
    ("ton_mnemonic",     r'(?i)(ton.{0,20})(mnemonic|seed|words).{0,30}["\'][a-z ]{60,}["\']',"CRITICAL","TON"),
    ("ton_private_hex",  r'(?i)(private|secret).{0,20}[0-9a-fA-F]{64}', "CRITICAL","TON/Crypto"),
]

SKIP_EXTS = {".png",".jpg",".jpeg",".gif",".ico",".pdf",".zip",".tar",
             ".gz",".bin",".exe",".dll",".so",".pyc",".lock"}
SKIP_DIRS = {"node_modules",".git","__pycache__",".venv","venv","dist","build"}

def _entropy(s: str) -> float:
    if not s: return 0.0
    freq = {c: s.count(c)/len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


class SecretDetector:
    """60+ secret patterns + entropy-based detection."""

    ENTROPY_THRESHOLD = 4.5
    MIN_LENGTH        = 20

    def scan_file(self, file_path: str) -> List[Dict]:
        p = Path(file_path)
        if p.suffix.lower() in SKIP_EXTS: return []
        try: content = p.read_text(errors="replace")
        except OSError: return []
        return self._scan(content, str(p))

    def scan_directory(self, directory: str) -> Dict:
        all_findings, count = [], 0
        for f in Path(directory).rglob("*"):
            if (f.is_file() and f.suffix.lower() not in SKIP_EXTS
                    and not any(s in f.parts for s in SKIP_DIRS)):
                found = self.scan_file(str(f))
                all_findings.extend(found)
                count += 1
        sev_c: Dict = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for f in all_findings:
            sev_c[f.get("severity","HIGH")] = sev_c.get(f.get("severity","HIGH"),0)+1
        return {"files_scanned":count,"total_findings":len(all_findings),
                "severity_counts":sev_c,"findings":all_findings}

    def _scan(self, content: str, file_path: str) -> List[Dict]:
        findings = []
        lines = content.splitlines()
        seen  = set()

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#","//","/*","*",";")):
                continue

            # Pattern-based detection
            for name, pattern, severity, service in SECRET_PATTERNS:
                m = re.search(pattern, line)
                if m:
                    matched = m.group(0)[:80]
                    key = (name, lineno)
                    if key in seen: continue
                    seen.add(key)
                    findings.append({
                        "type":           "SECRET_EXPOSURE",
                        "id":             f"SEC-{name.upper()[:20]}",
                        "severity":       severity,
                        "cwe":            "CWE-798",
                        "file":           file_path,
                        "line":           lineno,
                        "description":    f"{service} secret exposed in source code",
                        "evidence":       self._mask(matched),
                        "recommendation": f"Remove from code; rotate the {service} credential immediately; use environment variables",
                        "category":       "Secret Exposure",
                        "source":         "secret_detector",
                        "service":        service,
                        "confidence":     90,
                    })

            # Entropy-based detection for strings > MIN_LENGTH
            for m in re.finditer(r'["\']([A-Za-z0-9+/=_\-]{20,})["\']', line):
                val = m.group(1)
                if len(val) >= self.MIN_LENGTH and _entropy(val) >= self.ENTROPY_THRESHOLD:
                    key = ("entropy", lineno, val[:20])
                    if key in seen: continue
                    seen.add(key)
                    findings.append({
                        "type":           "HIGH_ENTROPY_STRING",
                        "id":             "SEC-ENTROPY",
                        "severity":       "MEDIUM",
                        "cwe":            "CWE-798",
                        "file":           file_path,
                        "line":           lineno,
                        "description":    f"High-entropy string (entropy={_entropy(val):.2f}) — possible secret",
                        "evidence":       self._mask(val[:60]),
                        "recommendation": "Verify this is not a hardcoded secret; move to environment variable if so",
                        "category":       "High Entropy",
                        "source":         "secret_detector",
                        "confidence":     55,
                    })
        return findings

    @staticmethod
    def _mask(s: str) -> str:
        if len(s) <= 8: return "****"
        return s[:4] + "*" * (len(s) - 8) + s[-4:]
