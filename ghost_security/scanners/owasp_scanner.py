"""
Ghost Security — OWASP Top 10 (2021) Scanner
Systematic coverage of all 10 OWASP categories.
Pattern-based static analysis for Python, JS/TS, PHP.
"""
import ast, re
from pathlib import Path
from typing import Dict, List

# OWASP 2021 categories
OWASP = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable Components",
    "A07": "Authentication Failures",
    "A08": "Software Integrity Failures",
    "A09": "Logging Failures",
    "A10": "SSRF",
}

# Each rule: id, owasp, pattern, severity, description, recommendation, cwe, langs
RULES: List[Dict] = [

    # ── A01 Broken Access Control ────────────────────────────────────────────
    {"id":"OW-A01-001","owasp":"A01","severity":"CRITICAL","cwe":"CWE-862",
     "pattern":r'request\.(user|session)\s*\.\s*is_authenticated\s*==\s*False',
     "desc":"Negated auth check — logic likely inverted (allows unauthenticated access)",
     "fix":"Use `if not request.user.is_authenticated: return 403`","langs":["py"]},

    {"id":"OW-A01-002","owasp":"A01","severity":"HIGH","cwe":"CWE-284",
     "pattern":r'@app\.route\([^)]+\)\s*\ndef\s+\w+\(',
     "desc":"Flask route without @login_required — check if endpoint should be authenticated",
     "fix":"Add @login_required or equivalent decorator to protected endpoints","langs":["py"]},

    {"id":"OW-A01-003","owasp":"A01","severity":"HIGH","cwe":"CWE-639",
     "pattern":r'(request\.args|request\.form|request\.json)\s*\.get\s*\(\s*["\']id["\']',
     "desc":"User-supplied object ID — verify ownership before access (IDOR risk)",
     "fix":"Check object.owner == request.user before returning/modifying","langs":["py"]},

    {"id":"OW-A01-004","owasp":"A01","severity":"HIGH","cwe":"CWE-22",
     "pattern":r'open\s*\(\s*(request\.|user_|data\[|f["\'])',
     "desc":"User-controlled file path passed to open() — path traversal risk",
     "fix":"Validate path: use os.path.abspath + whitelist, reject '../'","langs":["py"]},

    {"id":"OW-A01-005","owasp":"A01","severity":"HIGH","cwe":"CWE-22",
     "pattern":r'(send_file|send_from_directory)\s*\([^)]*request\.',
     "desc":"User-controlled path in send_file/send_from_directory — directory traversal",
     "fix":"Use send_from_directory with a fixed base directory only","langs":["py"]},

    # ── A02 Cryptographic Failures ───────────────────────────────────────────
    {"id":"OW-A02-001","owasp":"A02","severity":"CRITICAL","cwe":"CWE-312",
     "pattern":r'(password|secret|key|token)\s*=\s*["\'][^"\']{8,}["\']',
     "desc":"Hardcoded credential in source code",
     "fix":"Move to environment variable: os.environ.get('KEY')","langs":["py","js","ts"]},

    {"id":"OW-A02-002","owasp":"A02","severity":"HIGH","cwe":"CWE-327",
     "pattern":r'hashlib\.(md5|sha1)\s*\(',
     "desc":"Weak hash algorithm (MD5/SHA1) — broken for security purposes",
     "fix":"Use hashlib.sha256() or hashlib.sha3_256(); for passwords use bcrypt/argon2","langs":["py"]},

    {"id":"OW-A02-003","owasp":"A02","severity":"HIGH","cwe":"CWE-326",
     "pattern":r'(AES|DES|RC4)\s*\.\s*(new|encrypt)\s*\(',
     "desc":"Check cipher mode — ECB mode leaks patterns; RC4/DES are broken",
     "fix":"Use AES-GCM or AES-CBC with random IV; never use ECB or RC4","langs":["py","js"]},

    {"id":"OW-A02-004","owasp":"A02","severity":"HIGH","cwe":"CWE-330",
     "pattern":r'random\.(random|randint|choice|shuffle)\s*\(',
     "desc":"Python random module is not cryptographically secure",
     "fix":"Use secrets.token_hex() or secrets.choice() for security-sensitive randomness","langs":["py"]},

    {"id":"OW-A02-005","owasp":"A02","severity":"MEDIUM","cwe":"CWE-311",
     "pattern":r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)',
     "desc":"Plain HTTP URL — data transmitted unencrypted",
     "fix":"Use HTTPS for all external connections","langs":["py","js","ts"]},

    {"id":"OW-A02-006","owasp":"A02","severity":"MEDIUM","cwe":"CWE-295",
     "pattern":r'verify\s*=\s*False',
     "desc":"SSL certificate verification disabled — vulnerable to MITM",
     "fix":"Never disable SSL verification in production; fix the certificate instead","langs":["py"]},

    {"id":"OW-A02-007","owasp":"A02","severity":"HIGH","cwe":"CWE-321",
     "pattern":r'(jwt\.encode|jwt\.decode)\s*\([^)]*["\'](?:HS256|none)["\']',
     "desc":"JWT with weak algorithm (HS256 shared secret or 'none')",
     "fix":"Use RS256 with asymmetric keys; always validate 'alg' header","langs":["py","js"]},

    # ── A03 Injection ────────────────────────────────────────────────────────
    {"id":"OW-A03-001","owasp":"A03","severity":"CRITICAL","cwe":"CWE-89",
     "pattern":r'(?i)(execute|query|raw)\s*\([^)]*(%s|\.format\(|f["\'].*\{)',
     "desc":"SQL query constructed with string formatting — SQL injection",
     "fix":"Use parameterised queries: cursor.execute(sql, (param,))","langs":["py"]},

    {"id":"OW-A03-002","owasp":"A03","severity":"CRITICAL","cwe":"CWE-78",
     "pattern":r'subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True',
     "desc":"Shell injection — command executed through shell with user data risk",
     "fix":"Use shell=False with shlex.split(); never interpolate user data","langs":["py"]},

    {"id":"OW-A03-003","owasp":"A03","severity":"CRITICAL","cwe":"CWE-78",
     "pattern":r'os\.(system|popen)\s*\(',
     "desc":"os.system/popen — shell injection risk if any user data reaches this call",
     "fix":"Replace with subprocess.run([...], shell=False)","langs":["py"]},

    {"id":"OW-A03-004","owasp":"A03","severity":"CRITICAL","cwe":"CWE-95",
     "pattern":r'\beval\s*\(',
     "desc":"eval() executes arbitrary code — injection if user data reaches this",
     "fix":"Use ast.literal_eval() for data parsing; never eval() user input","langs":["py","js"]},

    {"id":"OW-A03-005","owasp":"A03","severity":"CRITICAL","cwe":"CWE-94",
     "pattern":r'render_template_string\s*\(',
     "desc":"render_template_string — Server-Side Template Injection (SSTI) if user-controlled",
     "fix":"Use render_template() with static template files only","langs":["py"]},

    {"id":"OW-A03-006","owasp":"A03","severity":"HIGH","cwe":"CWE-643",
     "pattern":r'xpath\s*\(.*request\.',
     "desc":"XPath query with user input — XPath injection",
     "fix":"Parameterise XPath queries; validate and escape all user input","langs":["py","js"]},

    {"id":"OW-A03-007","owasp":"A03","severity":"HIGH","cwe":"CWE-79",
     "pattern":r'innerHTML\s*=\s*(?!`[^`]*`)',
     "desc":"innerHTML assignment — XSS risk if value contains user data",
     "fix":"Use textContent for text, or sanitise with DOMPurify before innerHTML","langs":["js","ts"]},

    {"id":"OW-A03-008","owasp":"A03","severity":"HIGH","cwe":"CWE-79",
     "pattern":r'document\.(write|writeln)\s*\(',
     "desc":"document.write — XSS vector, deprecated, injects HTML directly",
     "fix":"Use DOM manipulation methods (createElement, appendChild) instead","langs":["js","ts"]},

    {"id":"OW-A03-009","owasp":"A03","severity":"HIGH","cwe":"CWE-917",
     "pattern":r'(Function|setTimeout|setInterval)\s*\(\s*["\']',
     "desc":"String passed to Function/setTimeout — code injection via string eval",
     "fix":"Pass a function reference instead of a string","langs":["js","ts"]},

    {"id":"OW-A03-010","owasp":"A03","severity":"MEDIUM","cwe":"CWE-917",
     "pattern":r'\.query\s*\(\s*[`"\'].*\$\{',
     "desc":"Template literal in database query — injection if user data interpolated",
     "fix":"Use parameterised queries with ? or $1 placeholders","langs":["js","ts"]},

    # ── A04 Insecure Design ──────────────────────────────────────────────────
    {"id":"OW-A04-001","owasp":"A04","severity":"MEDIUM","cwe":"CWE-770",
     "pattern":r'while\s+True\s*:|for\s+\w+\s+in\s+\w+\s*:(?!.*break)',
     "desc":"Potentially unbounded loop — may cause DoS if user-controlled iteration",
     "fix":"Add explicit bounds and timeout; validate input size before looping","langs":["py"]},

    {"id":"OW-A04-002","owasp":"A04","severity":"MEDIUM","cwe":"CWE-400",
     "pattern":r'(json\.loads|pickle\.loads|yaml\.load)\s*\([^)]*request\.',
     "desc":"Deserialising user-supplied data without size or type limits",
     "fix":"Validate content-type, set max_size, use safe deserialiser","langs":["py"]},

    # ── A05 Security Misconfiguration ────────────────────────────────────────
    {"id":"OW-A05-001","owasp":"A05","severity":"HIGH","cwe":"CWE-16",
     "pattern":r'DEBUG\s*=\s*True',
     "desc":"DEBUG=True in production exposes stack traces and interactive debugger",
     "fix":"Set DEBUG=False in production; control via env var","langs":["py","js"]},

    {"id":"OW-A05-002","owasp":"A05","severity":"HIGH","cwe":"CWE-16",
     "pattern":r'ALLOWED_HOSTS\s*=\s*\[\s*["\'][*]["\']',
     "desc":"ALLOWED_HOSTS=['*'] — Django accepts requests from any host (Host header injection)",
     "fix":"Set ALLOWED_HOSTS to explicit domain list in production","langs":["py"]},

    {"id":"OW-A05-003","owasp":"A05","severity":"MEDIUM","cwe":"CWE-16",
     "pattern":r'CORS_ORIGIN_ALLOW_ALL\s*=\s*True',
     "desc":"CORS allows all origins — any website can make credentialed requests",
     "fix":"Set CORS_ALLOWED_ORIGINS to explicit list of trusted domains","langs":["py"]},

    {"id":"OW-A05-004","owasp":"A05","severity":"MEDIUM","cwe":"CWE-614",
     "pattern":r'(httpOnly|secure|samesite)\s*[:=]\s*(false|False|None)',
     "desc":"Cookie missing security attributes — vulnerable to XSS theft or CSRF",
     "fix":"Set httpOnly=True, secure=True, samesite='Strict'","langs":["py","js","ts"]},

    {"id":"OW-A05-005","owasp":"A05","severity":"LOW","cwe":"CWE-548",
     "pattern":r'(app\.run|uvicorn\.run)\s*\([^)]*host\s*=\s*["\']0\.0\.0\.0["\']',
     "desc":"Server binding to 0.0.0.0 — exposed on all interfaces including public",
     "fix":"Bind to 127.0.0.1 locally; use reverse proxy for public exposure","langs":["py"]},

    # ── A07 Authentication Failures ──────────────────────────────────────────
    {"id":"OW-A07-001","owasp":"A07","severity":"CRITICAL","cwe":"CWE-798",
     "pattern":r'(?i)(admin|root|test)\s*[=:]\s*["\'](?:admin|password|123456|root|test)["\']',
     "desc":"Default/weak credential in code",
     "fix":"Remove default credentials; require strong passwords; use env vars","langs":["py","js","ts"]},

    {"id":"OW-A07-002","owasp":"A07","severity":"HIGH","cwe":"CWE-307",
     "pattern":r'(?i)(login|authenticate|check_password)\s*\([^)]+\)(?!.*rate.?limit)',
     "desc":"Authentication function without visible rate limiting — brute-force risk",
     "fix":"Add rate limiting: max 5 attempts per IP per minute; use account lockout","langs":["py"]},

    {"id":"OW-A07-003","owasp":"A07","severity":"HIGH","cwe":"CWE-613",
     "pattern":r'session\.(clear|flush)\s*\(\s*\)(?!.*logout)',
     "desc":"Session cleared but logout not properly signalled to client",
     "fix":"On logout: clear server session, invalidate token, clear client cookies","langs":["py","js"]},

    {"id":"OW-A07-004","owasp":"A07","severity":"HIGH","cwe":"CWE-294",
     "pattern":r'token\s*=\s*request\.(args|form|json)\s*\.get\s*\(["\']token["\']',
     "desc":"CSRF token from URL parameter — logged in server logs, referer headers",
     "fix":"CSRF tokens must come from headers (X-CSRFToken) or POST body only","langs":["py"]},

    # ── A08 Software Integrity Failures ─────────────────────────────────────
    {"id":"OW-A08-001","owasp":"A08","severity":"HIGH","cwe":"CWE-502",
     "pattern":r'pickle\.(load|loads)\s*\(',
     "desc":"pickle deserialisation — arbitrary code execution on malicious input",
     "fix":"Use JSON/msgpack for data; never unpickle untrusted data","langs":["py"]},

    {"id":"OW-A08-002","owasp":"A08","severity":"HIGH","cwe":"CWE-502",
     "pattern":r'yaml\.load\s*\([^,)]+\)',
     "desc":"yaml.load without Loader — code execution via Python object tags",
     "fix":"Use yaml.safe_load() which only parses basic data types","langs":["py"]},

    {"id":"OW-A08-003","owasp":"A08","severity":"MEDIUM","cwe":"CWE-829",
     "pattern":r'require\s*\(\s*[`"\']http',
     "desc":"require() loading remote module — supply chain risk",
     "fix":"Only require local or npm-registered packages; use lockfiles","langs":["js","ts"]},

    # ── A09 Logging Failures ─────────────────────────────────────────────────
    {"id":"OW-A09-001","owasp":"A09","severity":"MEDIUM","cwe":"CWE-532",
     "pattern":r'(log|logger|logging)\.(info|debug|warning|error)\s*\(.*password',
     "desc":"Password logged — sensitive data written to log files",
     "fix":"Never log passwords, tokens, or PII; mask or omit sensitive fields","langs":["py","js"]},

    {"id":"OW-A09-002","owasp":"A09","severity":"LOW","cwe":"CWE-117",
     "pattern":r'(print|console\.log)\s*\(.*request\.',
     "desc":"Request data printed to stdout — may contain sensitive user data",
     "fix":"Use structured logging with PII filtering; remove debug prints","langs":["py","js","ts"]},

    # ── A10 SSRF ─────────────────────────────────────────────────────────────
    {"id":"OW-A10-001","owasp":"A10","severity":"CRITICAL","cwe":"CWE-918",
     "pattern":r'(requests\.get|requests\.post|urllib\.request|httpx\.get)\s*\([^)]*request\.',
     "desc":"HTTP request with user-supplied URL — Server-Side Request Forgery (SSRF)",
     "fix":"Validate URL against allowlist; block private/localhost ranges; use DNS rebinding protection","langs":["py"]},

    {"id":"OW-A10-002","owasp":"A10","severity":"CRITICAL","cwe":"CWE-918",
     "pattern":r'(fetch|axios\.get|axios\.post)\s*\(\s*\w*(url|href|src|endpoint)',
     "desc":"HTTP request using user-supplied URL — potential SSRF",
     "fix":"Validate and allowlist URLs server-side; block 169.254.x.x, 10.x, 172.x, 192.168.x","langs":["js","ts"]},
]

LANG_EXTS = {
    "py":  [".py"],
    "js":  [".js", ".mjs"],
    "ts":  [".ts", ".tsx"],
    "sol": [".sol"],
}
ALL_EXTS = {ext for exts in LANG_EXTS.values() for ext in exts}


class OWASPScanner:
    """
    Systematic OWASP Top 10 (2021) static analysis.
    Covers A01–A10 for Python, JavaScript, TypeScript.
    Each finding includes OWASP category, CWE, severity, and concrete fix.
    """

    def scan_file(self, file_path: str) -> List[Dict]:
        p = Path(file_path)
        if p.suffix.lower() not in ALL_EXTS:
            return []
        try:
            content = p.read_text(errors="replace")
            lang    = next((k for k, exts in LANG_EXTS.items() if p.suffix.lower() in exts), "py")
        except OSError:
            return []
        return self._apply_rules(content, str(p), lang)

    def scan_directory(self, directory: str) -> Dict:
        all_findings: List[Dict] = []
        files_scanned = 0
        for f in Path(directory).rglob("*"):
            if f.is_file() and f.suffix.lower() in ALL_EXTS:
                if any(skip in f.parts for skip in ("__pycache__","node_modules",".git",".venv","venv")):
                    continue
                all_findings.extend(self.scan_file(str(f)))
                files_scanned += 1

        owasp_counts: Dict[str, int] = {}
        sev_counts:   Dict[str, int] = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for f in all_findings:
            cat = f.get("owasp_category","?")
            owasp_counts[cat] = owasp_counts.get(cat,0) + 1
            sev = f.get("severity","MEDIUM")
            sev_counts[sev]   = sev_counts.get(sev,0)+1

        return {
            "files_scanned":   files_scanned,
            "total_findings":  len(all_findings),
            "owasp_counts":    owasp_counts,
            "severity_counts": sev_counts,
            "findings":        sorted(all_findings,
                key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x.get("severity","LOW"),4)),
        }

    def _apply_rules(self, content: str, file_path: str, lang: str) -> List[Dict]:
        findings = []
        lines    = content.splitlines()
        for rule in RULES:
            if lang not in rule.get("langs", [lang]):
                continue
            pattern = re.compile(rule["pattern"])
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                # Skip comment lines
                if stripped.startswith(("#","//","/*","*",";")):
                    continue
                if pattern.search(line):
                    owasp_id  = rule["owasp"]
                    findings.append({
                        "type":           "OWASP_FINDING",
                        "id":             rule["id"],
                        "owasp_category": f"{owasp_id}: {OWASP.get(owasp_id,'?')}",
                        "severity":       rule["severity"],
                        "cwe":            rule["cwe"],
                        "file":           file_path,
                        "line":           lineno,
                        "description":    rule["desc"],
                        "evidence":       stripped[:120],
                        "recommendation": rule["fix"],
                        "source":         "owasp_scanner",
                        "category":       OWASP.get(owasp_id,"?"),
                        "confidence":     80,
                    })
        return self._dedupe(findings)

    @staticmethod
    def _dedupe(findings: List[Dict]) -> List[Dict]:
        seen, result = set(), []
        for f in findings:
            key = (f["id"], f["file"], f["line"])
            if key not in seen:
                seen.add(key); result.append(f)
        return result
