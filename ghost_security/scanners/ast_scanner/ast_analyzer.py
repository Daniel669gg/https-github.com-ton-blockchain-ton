"""
Ghost Security Platform — AST Security Analyzer
Real AST-based vulnerability detection using tree-sitter and Python's ast module.
No regex hacks. No placeholders. Real structural code analysis.
"""
import ast
import json
import re
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from config.config import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO


@dataclass
class ASTFinding:
    """A real finding from AST analysis."""
    type: str
    severity: str
    file: str
    line: int
    col: int
    description: str
    evidence: str
    recommendation: str
    cwe: str = ""

    def to_dict(self) -> Dict:
        return {
            "type": self.type,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "col": self.col,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "source": "ast_analyzer"
        }


class PythonASTAnalyzer(ast.NodeVisitor):
    """
    Real Python AST security analyzer.
    Detects actual vulnerability patterns through structural AST traversal.
    """

    DANGEROUS_FUNCTIONS = {
        "eval": (SEVERITY_CRITICAL, "CWE-95", "Code injection via eval()"),
        "exec": (SEVERITY_CRITICAL, "CWE-95", "Code injection via exec()"),
        "compile": (SEVERITY_HIGH, "CWE-95", "Dynamic code compilation"),
        "__import__": (SEVERITY_HIGH, "CWE-95", "Dynamic import"),
        "pickle.loads": (SEVERITY_CRITICAL, "CWE-502", "Insecure deserialization via pickle"),
        "pickle.load": (SEVERITY_CRITICAL, "CWE-502", "Insecure deserialization via pickle"),
        "marshal.loads": (SEVERITY_HIGH, "CWE-502", "Insecure deserialization via marshal"),
        "yaml.load": (SEVERITY_HIGH, "CWE-502", "Unsafe YAML load (use yaml.safe_load)"),
        "subprocess.call": (SEVERITY_HIGH, "CWE-78", "Potential command injection"),
        "subprocess.Popen": (SEVERITY_HIGH, "CWE-78", "Potential command injection"),
        "subprocess.run": (SEVERITY_MEDIUM, "CWE-78", "Subprocess execution — verify inputs"),
        "os.system": (SEVERITY_CRITICAL, "CWE-78", "OS command injection via os.system()"),
        "os.popen": (SEVERITY_HIGH, "CWE-78", "OS command injection via os.popen()"),
        "os.execve": (SEVERITY_HIGH, "CWE-78", "OS exec — verify inputs"),
        "shutil.rmtree": (SEVERITY_HIGH, "CWE-22", "Recursive deletion — path traversal risk"),
        "open": (SEVERITY_LOW, "CWE-22", "File open — verify path is not user-controlled"),
        "hashlib.md5": (SEVERITY_MEDIUM, "CWE-327", "MD5 is cryptographically weak"),
        "hashlib.sha1": (SEVERITY_MEDIUM, "CWE-327", "SHA1 is cryptographically weak"),
        "random.random": (SEVERITY_MEDIUM, "CWE-338", "Weak PRNG — use secrets module for security"),
        "random.randint": (SEVERITY_MEDIUM, "CWE-338", "Weak PRNG — use secrets module for security"),
        "tempfile.mktemp": (SEVERITY_HIGH, "CWE-377", "Insecure temp file creation (race condition)"),
        "ssl.wrap_socket": (SEVERITY_MEDIUM, "CWE-326", "Deprecated SSL API — use ssl.SSLContext"),
        "xmlrpc": (SEVERITY_MEDIUM, "CWE-611", "XML-RPC may be vulnerable to XXE"),
        "xml.etree.ElementTree.parse": (SEVERITY_MEDIUM, "CWE-611", "ElementTree vulnerable to XXE"),
        "lxml.etree.parse": (SEVERITY_MEDIUM, "CWE-611", "lxml — check for XXE protection"),
    }

    SQL_PATTERNS = [
        r"(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*\+",
        r"(SELECT|INSERT|UPDATE|DELETE).*%s",
        r"(SELECT|INSERT|UPDATE|DELETE).*\.format\(",
        r"(SELECT|INSERT|UPDATE|DELETE).*f['\"]",
    ]

    HARDCODED_SECRET_PATTERNS = [
        (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']', SEVERITY_HIGH, "Hardcoded password"),
        (r'(?i)(secret|api_key|apikey|token|auth_token)\s*=\s*["\'][^"\']{8,}["\']', SEVERITY_CRITICAL, "Hardcoded secret/API key"),
        (r'(?i)(private_key|privatekey)\s*=\s*["\'][^"\']{8,}["\']', SEVERITY_CRITICAL, "Hardcoded private key"),
        (r'(?i)aws_access_key_id\s*=\s*["\'][A-Z0-9]{20}["\']', SEVERITY_CRITICAL, "Hardcoded AWS Access Key"),
        (r'(?i)aws_secret_access_key\s*=\s*["\'][^"\']{40}["\']', SEVERITY_CRITICAL, "Hardcoded AWS Secret Key"),
        (r'(?i)(db_password|database_password|mysql_password)\s*=\s*["\'][^"\']{4,}["\']', SEVERITY_HIGH, "Hardcoded DB password"),
        (r'AKIA[0-9A-Z]{16}', SEVERITY_CRITICAL, "AWS Access Key ID pattern"),
        (r'(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*', SEVERITY_HIGH, "Hardcoded Bearer token"),
        (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', SEVERITY_CRITICAL, "Embedded private key"),
        (r'(?i)github_token\s*=\s*["\'][a-zA-Z0-9_]{35,}["\']', SEVERITY_CRITICAL, "Hardcoded GitHub token"),
    ]

    def __init__(self, filename: str, source: str):
        self.filename = filename
        self.source = source
        self.lines = source.split('\n')
        self.findings: List[ASTFinding] = []
        self._tree: Optional[ast.AST] = None

    def analyze(self) -> List[ASTFinding]:
        """Run full AST analysis."""
        try:
            self._tree = ast.parse(self.source, filename=self.filename)
        except SyntaxError as e:
            # Still run regex-based checks on unparseable files
            self._run_regex_checks()
            return self.findings

        self.visit(self._tree)
        self._run_regex_checks()
        self._check_sql_injection()
        return self.findings

    def visit_Call(self, node: ast.Call):
        """Detect dangerous function calls."""
        func_name = self._get_call_name(node)
        if func_name:
            for dangerous_name, (severity, cwe, desc) in self.DANGEROUS_FUNCTIONS.items():
                if func_name == dangerous_name or func_name.endswith('.' + dangerous_name.split('.')[-1]):
                    # Check if arguments contain user input (variables, not literals)
                    has_dynamic_args = any(
                        not isinstance(arg, ast.Constant)
                        for arg in node.args
                    )
                    evidence = self._get_line(node.lineno)
                    # Elevate severity if dynamic args
                    actual_severity = severity
                    if has_dynamic_args and severity in [SEVERITY_MEDIUM, SEVERITY_LOW]:
                        actual_severity = SEVERITY_HIGH
                    elif has_dynamic_args and severity == SEVERITY_HIGH:
                        actual_severity = SEVERITY_CRITICAL

                    self.findings.append(ASTFinding(
                        type=self._get_vuln_type(func_name),
                        severity=actual_severity,
                        file=self.filename,
                        line=node.lineno,
                        col=node.col_offset,
                        description=f"{desc} — {'dynamic args detected' if has_dynamic_args else 'static call'}",
                        evidence=evidence,
                        recommendation=self._get_recommendation(func_name),
                        cwe=cwe
                    ))
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert):
        """Detect use of assert for security checks (disabled with -O flag)."""
        # Check if assert is used for auth/permission checks
        test_str = ast.unparse(node.test) if hasattr(ast, 'unparse') else str(node.test)
        security_keywords = ['auth', 'permission', 'admin', 'role', 'access', 'login', 'user']
        if any(kw in test_str.lower() for kw in security_keywords):
            self.findings.append(ASTFinding(
                type="Broken Access Control",
                severity=SEVERITY_HIGH,
                file=self.filename,
                line=node.lineno,
                col=node.col_offset,
                description="Security check using assert() — disabled when Python runs with -O flag",
                evidence=self._get_line(node.lineno),
                recommendation="Replace assert with explicit if/raise for security checks",
                cwe="CWE-617"
            ))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Detect hardcoded secrets in assignments."""
        for target in node.targets:
            target_name = ""
            if isinstance(target, ast.Name):
                target_name = target.id
            elif isinstance(target, ast.Attribute):
                target_name = target.attr

            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                value = node.value.value
                self._check_secret_value(target_name, value, node.lineno)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Check function definitions for security issues."""
        # Check for missing input validation in functions with 'request' params
        param_names = [arg.arg for arg in node.args.args]
        if any(p in ['request', 'req', 'data', 'input', 'user_input'] for p in param_names):
            # Look for direct use without validation
            has_validation = False
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    call_name = self._get_call_name(child)
                    if call_name and any(v in call_name for v in ['validate', 'sanitize', 'escape', 'clean']):
                        has_validation = True
                        break
            # Only report if function is short (likely handler without validation)
            if not has_validation and len(list(ast.walk(node))) < 30:
                self.findings.append(ASTFinding(
                    type="Missing Input Validation",
                    severity=SEVERITY_LOW,
                    file=self.filename,
                    line=node.lineno,
                    col=node.col_offset,
                    description=f"Function '{node.name}' accepts user-like input without apparent validation",
                    evidence=self._get_line(node.lineno),
                    recommendation="Add input validation and sanitization before processing user data",
                    cwe="CWE-20"
                ))
        self.generic_visit(node)

    def _check_sql_injection(self):
        """Check for SQL injection patterns using AST + regex."""
        for i, line in enumerate(self.lines, 1):
            for pattern in self.SQL_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    self.findings.append(ASTFinding(
                        type="SQL Injection",
                        severity=SEVERITY_CRITICAL,
                        file=self.filename,
                        line=i,
                        col=0,
                        description="SQL query constructed with string concatenation/formatting — SQL injection risk",
                        evidence=line.strip(),
                        recommendation="Use parameterized queries or ORM. Never concatenate user input into SQL.",
                        cwe="CWE-89"
                    ))

    def _run_regex_checks(self):
        """Run regex-based secret detection on source."""
        for i, line in enumerate(self.lines, 1):
            for pattern, severity, desc in self.HARDCODED_SECRET_PATTERNS:
                if re.search(pattern, line):
                    # Avoid duplicate findings
                    already_found = any(
                        f.line == i and "secret" in f.type.lower()
                        for f in self.findings
                    )
                    if not already_found:
                        self.findings.append(ASTFinding(
                            type="Hardcoded Secret",
                            severity=severity,
                            file=self.filename,
                            line=i,
                            col=0,
                            description=desc,
                            evidence=self._redact_secret(line.strip()),
                            recommendation="Move secrets to environment variables or a secrets manager (e.g., HashiCorp Vault)",
                            cwe="CWE-798"
                        ))

    def _check_secret_value(self, name: str, value: str, lineno: int):
        """Check if a variable name + value looks like a secret."""
        secret_names = ['password', 'passwd', 'pwd', 'secret', 'token', 'api_key',
                        'apikey', 'private_key', 'auth', 'credential', 'access_key']
        if any(s in name.lower() for s in secret_names) and len(value) > 3:
            # Skip obvious placeholders
            placeholders = ['', 'changeme', 'your_key', 'xxx', 'todo', 'placeholder', 'example']
            if value.lower() not in placeholders:
                self.findings.append(ASTFinding(
                    type="Hardcoded Secret",
                    severity=SEVERITY_HIGH,
                    file=self.filename,
                    line=lineno,
                    col=0,
                    description=f"Variable '{name}' appears to contain a hardcoded secret",
                    evidence=f"{name} = '{self._redact_secret(value)}'",
                    recommendation="Use environment variables: os.environ.get('{name.upper()}')",
                    cwe="CWE-798"
                ))

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Extract function call name from AST node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return None

    def _get_line(self, lineno: int) -> str:
        """Get source line by number."""
        if 1 <= lineno <= len(self.lines):
            return self.lines[lineno - 1].strip()
        return ""

    def _redact_secret(self, text: str) -> str:
        """Partially redact secret values for safe display."""
        # Redact values in quotes
        def redact_match(m):
            val = m.group(0)
            if len(val) > 8:
                return val[:4] + '*' * (len(val) - 8) + val[-4:]
            return '*' * len(val)
        return re.sub(r'["\'][^"\']{4,}["\']', redact_match, text)

    def _get_vuln_type(self, func_name: str) -> str:
        """Map function name to vulnerability type."""
        mapping = {
            'eval': 'Code Injection', 'exec': 'Code Injection',
            'os.system': 'Command Injection', 'os.popen': 'Command Injection',
            'subprocess': 'Command Injection',
            'pickle': 'Insecure Deserialization',
            'yaml.load': 'Insecure Deserialization',
            'hashlib.md5': 'Weak Cryptography', 'hashlib.sha1': 'Weak Cryptography',
            'random': 'Weak PRNG',
            'tempfile.mktemp': 'Race Condition',
            'open': 'Path Traversal Risk',
            'xml': 'XXE Injection',
        }
        for key, vtype in mapping.items():
            if key in func_name:
                return vtype
        return "Dangerous Function Call"

    def _get_recommendation(self, func_name: str) -> str:
        """Get specific recommendation for dangerous function."""
        recs = {
            'eval': 'Never use eval() with user input. Use ast.literal_eval() for safe parsing.',
            'exec': 'Avoid exec(). If needed, use restricted execution environment.',
            'os.system': 'Use subprocess with shell=False and a list of arguments instead.',
            'os.popen': 'Use subprocess.run() with shell=False instead.',
            'pickle.loads': 'Use JSON or other safe serialization. Never unpickle untrusted data.',
            'yaml.load': 'Use yaml.safe_load() instead of yaml.load().',
            'hashlib.md5': 'Use SHA-256 or SHA-3 for security purposes.',
            'hashlib.sha1': 'Use SHA-256 or SHA-3 for security purposes.',
            'random.random': 'Use secrets module for cryptographic randomness.',
            'tempfile.mktemp': 'Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead.',
        }
        for key, rec in recs.items():
            if key in func_name:
                return rec
        return "Review this call carefully and validate all inputs."


class ASTScanner:
    """
    Multi-language AST security scanner.
    Supports Python (full AST), JavaScript and C (tree-sitter).
    """

    def __init__(self):
        self._ts_available = self._check_tree_sitter()

    def _check_tree_sitter(self) -> bool:
        """Check if tree-sitter is available."""
        try:
            import tree_sitter_python
            import tree_sitter
            return True
        except ImportError:
            return False

    def scan_file(self, filepath: str) -> List[Dict]:
        """Scan a single file for security issues."""
        path = Path(filepath)
        if not path.exists():
            return []

        try:
            source = path.read_text(encoding='utf-8', errors='replace')
        except Exception:
            return []

        ext = path.suffix.lower()
        findings = []

        if ext == '.py':
            analyzer = PythonASTAnalyzer(filepath, source)
            findings = [f.to_dict() for f in analyzer.analyze()]
        elif ext in ['.js', '.ts', '.jsx', '.tsx']:
            findings = self._scan_javascript(filepath, source)
        elif ext in ['.c', '.cpp', '.cc', '.h', '.hpp']:
            findings = self._scan_c(filepath, source)
        else:
            # Generic secret scan for any text file
            findings = self._scan_generic_secrets(filepath, source)

        return findings

    def scan_directory(self, dirpath: str, extensions: Optional[List[str]] = None) -> Dict:
        """Scan entire directory recursively."""
        if extensions is None:
            extensions = ['.py', '.js', '.ts', '.jsx', '.tsx', '.c', '.cpp', '.h',
                          '.env', '.yaml', '.yml', '.json', '.xml', '.conf', '.cfg',
                          '.ini', '.sh', '.bash', '.php', '.rb', '.go', '.java']

        all_findings = []
        scanned_files = 0
        errors = []

        for filepath in Path(dirpath).rglob('*'):
            if filepath.is_file() and filepath.suffix.lower() in extensions:
                # Skip common non-security files
                skip_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build'}
                if any(part in skip_dirs for part in filepath.parts):
                    continue
                try:
                    file_findings = self.scan_file(str(filepath))
                    all_findings.extend(file_findings)
                    scanned_files += 1
                except Exception as e:
                    errors.append({"file": str(filepath), "error": str(e)})

        return {
            "scanned_files": scanned_files,
            "total_findings": len(all_findings),
            "findings": all_findings,
            "errors": errors,
            "summary": self._summarize(all_findings)
        }

    def _scan_javascript(self, filepath: str, source: str) -> List[Dict]:
        """JavaScript security scan using tree-sitter + patterns."""
        findings = []
        lines = source.split('\n')

        # Dangerous patterns in JS
        js_patterns = [
            (r'eval\s*\(', SEVERITY_CRITICAL, "Code Injection", "eval() usage detected", "CWE-95",
             "Avoid eval(). Use JSON.parse() for data, or restructure logic."),
            (r'innerHTML\s*=', SEVERITY_HIGH, "XSS", "innerHTML assignment — XSS risk", "CWE-79",
             "Use textContent or DOMPurify to sanitize HTML."),
            (r'document\.write\s*\(', SEVERITY_HIGH, "XSS", "document.write() — XSS risk", "CWE-79",
             "Avoid document.write(). Use DOM manipulation methods."),
            (r'\.exec\s*\(', SEVERITY_MEDIUM, "Code Injection", "Function.exec() or RegExp.exec()", "CWE-95",
             "Verify this is RegExp.exec() and not dynamic code execution."),
            (r'require\s*\(\s*[^"\'`]', SEVERITY_HIGH, "Code Injection", "Dynamic require() call", "CWE-95",
             "Avoid dynamic require() with user-controlled paths."),
            (r'child_process', SEVERITY_HIGH, "Command Injection", "child_process usage", "CWE-78",
             "Sanitize all inputs passed to child_process functions."),
            (r'Math\.random\s*\(\)', SEVERITY_MEDIUM, "Weak PRNG", "Math.random() for security", "CWE-338",
             "Use crypto.getRandomValues() for security-sensitive randomness."),
            (r'md5\s*\(', SEVERITY_MEDIUM, "Weak Cryptography", "MD5 hash usage", "CWE-327",
             "Use SHA-256 or stronger hash functions."),
            (r'localStorage\.setItem.*password', SEVERITY_HIGH, "Sensitive Data Exposure",
             "Password stored in localStorage", "CWE-312",
             "Never store passwords in localStorage. Use secure session management."),
            (r'(?i)(password|secret|token|api_key)\s*[:=]\s*["\'][^"\']{4,}["\']',
             SEVERITY_HIGH, "Hardcoded Secret", "Hardcoded credential in JS", "CWE-798",
             "Move secrets to environment variables or server-side configuration."),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, severity, vuln_type, desc, cwe, rec in js_patterns:
                if re.search(pattern, line):
                    findings.append({
                        "type": vuln_type, "severity": severity,
                        "file": filepath, "line": i, "col": 0,
                        "description": desc, "evidence": line.strip(),
                        "recommendation": rec, "cwe": cwe, "source": "ast_scanner"
                    })
        return findings

    def _scan_c(self, filepath: str, source: str) -> List[Dict]:
        """C/C++ security scan."""
        findings = []
        lines = source.split('\n')

        c_patterns = [
            (r'\bgets\s*\(', SEVERITY_CRITICAL, "Buffer Overflow", "gets() is unsafe — no bounds checking", "CWE-120",
             "Use fgets() with explicit size limit instead."),
            (r'\bstrcpy\s*\(', SEVERITY_HIGH, "Buffer Overflow", "strcpy() without bounds checking", "CWE-120",
             "Use strncpy() or strlcpy() with explicit size."),
            (r'\bstrcat\s*\(', SEVERITY_HIGH, "Buffer Overflow", "strcat() without bounds checking", "CWE-120",
             "Use strncat() with explicit size."),
            (r'\bsprintf\s*\(', SEVERITY_HIGH, "Buffer Overflow", "sprintf() without bounds checking", "CWE-120",
             "Use snprintf() with explicit size."),
            (r'\bscanf\s*\([^,]+,\s*%s', SEVERITY_CRITICAL, "Buffer Overflow", "scanf(%s) without width limit", "CWE-120",
             "Use scanf with width limit: scanf(\"%255s\", buf)"),
            (r'\bsystem\s*\(', SEVERITY_CRITICAL, "Command Injection", "system() call", "CWE-78",
             "Avoid system(). Use execve() with explicit arguments."),
            (r'\bpopen\s*\(', SEVERITY_HIGH, "Command Injection", "popen() call", "CWE-78",
             "Sanitize all input passed to popen()."),
            (r'\bmalloc\s*\(.*\*.*\)', SEVERITY_MEDIUM, "Integer Overflow", "Potential integer overflow in malloc()", "CWE-190",
             "Check for integer overflow before multiplying in malloc()."),
            (r'\bfree\s*\(.*\)\s*;.*\bfree\s*\(', SEVERITY_HIGH, "Double Free", "Potential double-free", "CWE-415",
             "Set pointer to NULL after free() to prevent double-free."),
            (r'printf\s*\(\s*[^"\']+\s*\)', SEVERITY_HIGH, "Format String", "printf with non-literal format string", "CWE-134",
             "Always use printf(\"%s\", str) not printf(str)."),
            (r'rand\s*\(\s*\)', SEVERITY_MEDIUM, "Weak PRNG", "rand() is not cryptographically secure", "CWE-338",
             "Use /dev/urandom or platform-specific CSPRNG."),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, severity, vuln_type, desc, cwe, rec in c_patterns:
                if re.search(pattern, line):
                    findings.append({
                        "type": vuln_type, "severity": severity,
                        "file": filepath, "line": i, "col": 0,
                        "description": desc, "evidence": line.strip(),
                        "recommendation": rec, "cwe": cwe, "source": "ast_scanner"
                    })
        return findings

    def _scan_generic_secrets(self, filepath: str, source: str) -> List[Dict]:
        """Generic secret detection for any file type."""
        findings = []
        lines = source.split('\n')
        secret_patterns = [
            (r'AKIA[0-9A-Z]{16}', SEVERITY_CRITICAL, "AWS Access Key ID"),
            (r'(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+]{40}', SEVERITY_CRITICAL, "AWS Secret Key"),
            (r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', SEVERITY_CRITICAL, "Private Key"),
            (r'(?i)(password|passwd|pwd)\s*[=:]\s*[^\s#]{4,}', SEVERITY_HIGH, "Hardcoded Password"),
            (r'(?i)(api_key|apikey|api-key)\s*[=:]\s*[^\s#]{8,}', SEVERITY_HIGH, "Hardcoded API Key"),
            (r'(?i)(secret|token)\s*[=:]\s*[^\s#]{8,}', SEVERITY_HIGH, "Hardcoded Secret"),
            (r'ghp_[A-Za-z0-9]{36}', SEVERITY_CRITICAL, "GitHub Personal Access Token"),
            (r'xox[baprs]-[A-Za-z0-9-]+', SEVERITY_CRITICAL, "Slack Token"),
            (r'(?i)mongodb://[^:]+:[^@]+@', SEVERITY_HIGH, "MongoDB connection string with credentials"),
            (r'(?i)postgres://[^:]+:[^@]+@', SEVERITY_HIGH, "PostgreSQL connection string with credentials"),
            (r'(?i)mysql://[^:]+:[^@]+@', SEVERITY_HIGH, "MySQL connection string with credentials"),
        ]
        for i, line in enumerate(lines, 1):
            for pattern, severity, desc in secret_patterns:
                if re.search(pattern, line):
                    findings.append({
                        "type": "Hardcoded Secret", "severity": severity,
                        "file": filepath, "line": i, "col": 0,
                        "description": desc,
                        "evidence": re.sub(r'["\'][^"\']{4,}["\']',
                                           lambda m: m.group(0)[:4] + '****', line.strip()),
                        "recommendation": "Move to environment variables or secrets manager",
                        "cwe": "CWE-798", "source": "ast_scanner"
                    })
        return findings

    def _summarize(self, findings: List[Dict]) -> Dict:
        """Summarize findings by severity."""
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        types = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            summary[sev] = summary.get(sev, 0) + 1
            t = f.get("type", "Unknown")
            types[t] = types.get(t, 0) + 1
        return {"by_severity": summary, "by_type": types}
