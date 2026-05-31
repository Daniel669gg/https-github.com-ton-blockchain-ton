"""
TythanAI — JavaScript / TypeScript Security Analyzer
Static analysis for JS/TS: prototype pollution, XSS, SSRF,
insecure dependencies patterns, JWT issues, React security.
"""
import re
from pathlib import Path
from typing import Dict, List

JS_RULES: List[Dict] = [
    # ── Prototype Pollution ───────────────────────────────────────────────────
    {"id":"JS001","severity":"CRITICAL","cwe":"CWE-1321",
     "pattern":r'(merge|extend|assign|deepCopy|defaults)\s*\([^)]*req\.',
     "desc":"Prototype pollution via user-controlled object merge",
     "fix":"Use Object.create(null) for merge targets; validate keys against '__proto__', 'constructor', 'prototype'",
     "category":"Prototype Pollution"},
    {"id":"JS002","severity":"HIGH","cwe":"CWE-1321",
     "pattern":r'\[.*req\.(body|query|params).*\]\s*=',
     "desc":"User-controlled property name used as object key — prototype pollution",
     "fix":"Whitelist allowed keys; reject '__proto__' and 'constructor'",
     "category":"Prototype Pollution"},

    # ── XSS ──────────────────────────────────────────────────────────────────
    {"id":"JS003","severity":"CRITICAL","cwe":"CWE-79",
     "pattern":r'innerHTML\s*[+]?=\s*(?!`[^`$]*`)',
     "desc":"innerHTML assignment — XSS if value contains user data",
     "fix":"Use textContent for text; DOMPurify.sanitize() if HTML required",
     "category":"XSS"},
    {"id":"JS004","severity":"CRITICAL","cwe":"CWE-79",
     "pattern":r'(document\.write|document\.writeln)\s*\(',
     "desc":"document.write — injects HTML directly, XSS vector",
     "fix":"Use DOM API methods (createElement, appendChild) instead",
     "category":"XSS"},
    {"id":"JS005","severity":"HIGH","cwe":"CWE-79",
     "pattern":r'dangerouslySetInnerHTML\s*=\s*\{\s*\{',
     "desc":"React dangerouslySetInnerHTML — XSS if value is user-controlled",
     "fix":"Sanitise with DOMPurify before passing to dangerouslySetInnerHTML",
     "category":"XSS"},
    {"id":"JS006","severity":"HIGH","cwe":"CWE-79",
     "pattern":r'(location\.href|location\.replace|window\.open)\s*=\s*[^"\'`][^;]*req\.',
     "desc":"Open redirect — user-controlled URL in navigation",
     "fix":"Validate URL against an allowlist; reject absolute URLs from user input",
     "category":"Open Redirect"},

    # ── Injection ─────────────────────────────────────────────────────────────
    {"id":"JS007","severity":"CRITICAL","cwe":"CWE-89",
     "pattern":r'(find|findOne|aggregate)\s*\(\s*\{[^}]*\$',
     "desc":"NoSQL injection — MongoDB operator in user-controlled query",
     "fix":"Validate input type (string, not object); use mongoose schema validation",
     "category":"NoSQL Injection"},
    {"id":"JS008","severity":"CRITICAL","cwe":"CWE-78",
     "pattern":r'(exec|execSync|spawn|spawnSync)\s*\(',
     "desc":"Shell command execution — injection if any user data flows here",
     "fix":"Use execFile with argument array; never interpolate user data into shell strings",
     "category":"Command Injection"},
    {"id":"JS009","severity":"HIGH","cwe":"CWE-917",
     "pattern":r'new Function\s*\(',
     "desc":"new Function() — code injection if any argument is user-controlled",
     "fix":"Avoid new Function(); use specific logic functions instead",
     "category":"Code Injection"},
    {"id":"JS010","severity":"CRITICAL","cwe":"CWE-95",
     "pattern":r'\beval\s*\(',
     "desc":"eval() — code execution risk if user data reaches this call",
     "fix":"Never eval() user input; refactor to explicit logic",
     "category":"Code Injection"},

    # ── Path Traversal ────────────────────────────────────────────────────────
    {"id":"JS011","severity":"HIGH","cwe":"CWE-22",
     "pattern":r'(readFile|readFileSync|createReadStream)\s*\([^)]*req\.',
     "desc":"User-controlled path in file read — directory traversal",
     "fix":"Use path.resolve() + check it starts with allowed base dir; reject '../'",
     "category":"Path Traversal"},
    {"id":"JS012","severity":"HIGH","cwe":"CWE-22",
     "pattern":r'(writeFile|writeFileSync|createWriteStream)\s*\([^)]*req\.',
     "desc":"User-controlled path in file write — arbitrary file write",
     "fix":"Whitelist output directories; use path.basename() to strip traversal",
     "category":"Path Traversal"},

    # ── SSRF ─────────────────────────────────────────────────────────────────
    {"id":"JS013","severity":"CRITICAL","cwe":"CWE-918",
     "pattern":r'(fetch|axios|got|superagent)\s*\(\s*req\.(body|query|params)',
     "desc":"HTTP request with user-supplied URL — SSRF",
     "fix":"Validate URL against allowlist; block internal IP ranges (169.254.x, 10.x, 192.168.x)",
     "category":"SSRF"},

    # ── Authentication / JWT ──────────────────────────────────────────────────
    {"id":"JS014","severity":"CRITICAL","cwe":"CWE-347",
     "pattern":r'jwt\.verify\s*\([^,]+,\s*(?!process\.env)',
     "desc":"JWT secret hardcoded or not from env — key exposure risk",
     "fix":"Load JWT secret from process.env.JWT_SECRET only; rotate regularly",
     "category":"Authentication"},
    {"id":"JS015","severity":"HIGH","cwe":"CWE-345",
     "pattern":r'algorithms\s*:\s*\[\s*["\']none["\']',
     "desc":"JWT 'none' algorithm accepted — signature verification bypass",
     "fix":"Explicitly whitelist only RS256 or HS256; never allow 'none'",
     "category":"Authentication"},
    {"id":"JS016","severity":"HIGH","cwe":"CWE-307",
     "pattern":r'(password|passphrase)\s*===?\s*req\.(body|query)',
     "desc":"Direct password comparison — timing attack + missing hash check",
     "fix":"Use bcrypt.compare() or crypto.timingSafeEqual(); never compare plaintext",
     "category":"Authentication"},

    # ── Insecure Randomness ───────────────────────────────────────────────────
    {"id":"JS017","severity":"HIGH","cwe":"CWE-338",
     "pattern":r'Math\.random\s*\(',
     "desc":"Math.random() is not cryptographically secure",
     "fix":"Use crypto.randomBytes() or crypto.randomUUID() for security-sensitive values",
     "category":"Randomness"},

    # ── Dependency / Supply Chain ─────────────────────────────────────────────
    {"id":"JS018","severity":"MEDIUM","cwe":"CWE-829",
     "pattern":r'require\s*\(\s*["`\']\.',
     "desc":"Relative require path — verify module not shadowed in node_modules",
     "fix":"Use absolute imports or path aliases; keep node_modules clean",
     "category":"Supply Chain"},

    # ── Secrets ───────────────────────────────────────────────────────────────
    {"id":"JS019","severity":"CRITICAL","cwe":"CWE-798",
     "pattern":r'(?i)(apikey|api_key|secret|password|token)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
     "desc":"Hardcoded secret / API key in JavaScript source",
     "fix":"Use process.env.SECRET_NAME; never hardcode credentials",
     "category":"Hardcoded Secret"},

    # ── Express.js Specific ───────────────────────────────────────────────────
    {"id":"JS020","severity":"HIGH","cwe":"CWE-352",
     "pattern":r'app\.(get|post|put|delete|patch)\s*\([^)]+\)(?!.*csrf)',
     "desc":"Express route without visible CSRF protection",
     "fix":"Use csurf middleware or SameSite=Strict cookies for state-changing endpoints",
     "category":"CSRF"},
    {"id":"JS021","severity":"MEDIUM","cwe":"CWE-16",
     "pattern":r'app\.disable\s*\(["\']x-powered-by["\']',
     "desc":"Good: x-powered-by disabled. Ensure other security headers are set.",
     "fix":"Also add: helmet() middleware for CSP, HSTS, X-Frame-Options",
     "category":"Security Headers"},
    {"id":"JS022","severity":"HIGH","cwe":"CWE-16",
     "pattern":r'cors\s*\(\s*\{[^}]*origin\s*:\s*["\'][*]["\']',
     "desc":"CORS wildcard origin — any domain can make credentialed requests",
     "fix":"Set origin to specific allowed domains array",
     "category":"Security Misconfiguration"},

    # ── React Specific ────────────────────────────────────────────────────────
    {"id":"JS023","severity":"HIGH","cwe":"CWE-79",
     "pattern":r'href\s*=\s*\{[^}]*props\.',
     "desc":"User-supplied href — javascript: URL injection (XSS)",
     "fix":"Validate href starts with https:// or /; block javascript: protocol",
     "category":"XSS"},

    # ── Type confusion ────────────────────────────────────────────────────────
    {"id":"JS024","severity":"MEDIUM","cwe":"CWE-843",
     "pattern":r'==\s*(true|false|null|0|1|undefined)(?!=)',
     "desc":"Loose equality (==) — type coercion may bypass security checks",
     "fix":"Use strict equality (===) for all security-relevant comparisons",
     "category":"Type Confusion"},
]

SUPPORTED_EXTS = (".js", ".mjs", ".jsx", ".ts", ".tsx")


class JSAnalyzer:
    """
    JavaScript / TypeScript static security analyzer.
    24 rules covering: XSS, injection, SSRF, prototype pollution,
    JWT issues, CSRF, path traversal, and more.
    """

    def analyze_file(self, file_path: str) -> List[Dict]:
        p = Path(file_path)
        if p.suffix.lower() not in SUPPORTED_EXTS:
            return []
        try:
            content = p.read_text(errors="replace")
        except OSError:
            return []
        return self._scan(content, str(p))

    def scan_directory(self, directory: str) -> Dict:
        all_findings: List[Dict] = []
        files_scanned = 0
        for f in Path(directory).rglob("*"):
            if (f.is_file() and f.suffix.lower() in SUPPORTED_EXTS
                    and not any(s in f.parts for s in ("node_modules",".git",".next","dist","build"))):
                all_findings.extend(self.analyze_file(str(f)))
                files_scanned += 1

        sev_c: Dict[str,int] = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for f in all_findings:
            sev_c[f.get("severity","MEDIUM")] = sev_c.get(f.get("severity","MEDIUM"),0)+1

        return {"files_scanned":files_scanned,"total_findings":len(all_findings),
                "severity_counts":sev_c,"findings":all_findings}

    def _scan(self, content: str, file_path: str) -> List[Dict]:
        findings = []
        lines = content.splitlines()
        for rule in JS_RULES:
            pat = re.compile(rule["pattern"])
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith(("//","/*","*")):
                    continue
                if pat.search(line):
                    findings.append({
                        "type":           "JS_VULNERABILITY",
                        "id":             rule["id"],
                        "severity":       rule["severity"],
                        "cwe":            rule["cwe"],
                        "file":           file_path,
                        "line":           lineno,
                        "description":    rule["desc"],
                        "evidence":       stripped[:120],
                        "recommendation": rule["fix"],
                        "category":       rule["category"],
                        "source":         "js_analyzer",
                        "confidence":     75,
                    })
        return self._dedupe(findings)

    @staticmethod
    def _dedupe(findings):
        seen, result = set(), []
        for f in findings:
            k = (f["id"], f["file"], f["line"])
            if k not in seen: seen.add(k); result.append(f)
        return result
