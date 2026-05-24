"""
Ghost Security — Auto-Remediation / Patch Generator
Generates concrete code patches for common vulnerability patterns.
Works offline (pattern-based) + optionally via LLM for complex cases.
"""
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── Offline patch templates ────────────────────────────────────────────────
# Each entry: (detection_pattern, unsafe_example, safe_replacement, explanation)
PATCHES: Dict[str, Dict] = {
    "shell_injection": {
        "detect":  r'subprocess\.(run|call|Popen).*shell\s*=\s*True',
        "before":  'subprocess.run(cmd, shell=True)',
        "after":   'subprocess.run(shlex.split(cmd), shell=False)',
        "imports": "import shlex",
        "explanation": "shell=True passes the command through the system shell, enabling injection. Use shell=False with a pre-split argument list.",
    },
    "eval_user_input": {
        "detect":  r'\beval\s*\(',
        "before":  'result = eval(user_input)',
        "after":   'result = ast.literal_eval(user_input)  # safe for data only',
        "imports": "import ast",
        "explanation": "eval() executes arbitrary code. ast.literal_eval() safely parses Python literals (str/int/list/dict) only.",
    },
    "sql_injection": {
        "detect":  r'(?i)(execute|query)\s*\(.*%\s*[(\w]',
        "before":  'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)',
        "after":   'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        "imports": "",
        "explanation": "String formatting in SQL queries enables injection. Use parameterised queries — pass values as a tuple, not as formatted strings.",
    },
    "pickle_unsafe": {
        "detect":  r'pickle\.(load|loads)\s*\(',
        "before":  'data = pickle.loads(user_data)',
        "after":   'data = json.loads(user_data)  # use JSON for untrusted data',
        "imports": "import json",
        "explanation": "pickle can execute arbitrary code during deserialisation. Use JSON or MessagePack for untrusted data.",
    },
    "yaml_unsafe_load": {
        "detect":  r'yaml\.load\s*\([^,)]+\)',
        "before":  'config = yaml.load(stream)',
        "after":   'config = yaml.safe_load(stream)',
        "imports": "",
        "explanation": "yaml.load() with untrusted input can execute arbitrary Python. Always use yaml.safe_load().",
    },
    "weak_hash_md5": {
        "detect":  r'hashlib\.md5\s*\(',
        "before":  'digest = hashlib.md5(password.encode()).hexdigest()',
        "after":   'digest = hashlib.sha256(password.encode() + salt).hexdigest()',
        "imports": "import os\nsalt = os.urandom(32)",
        "explanation": "MD5 is cryptographically broken and trivially reversible. Use SHA-256+ with a random salt, or bcrypt/argon2 for passwords.",
    },
    "weak_hash_sha1": {
        "detect":  r'hashlib\.sha1\s*\(',
        "before":  'digest = hashlib.sha1(data).hexdigest()',
        "after":   'digest = hashlib.sha256(data).hexdigest()',
        "imports": "",
        "explanation": "SHA-1 is deprecated for security use. Use SHA-256 or SHA-3.",
    },
    "hardcoded_secret": {
        "detect":  r'(?i)(password|secret|api_key)\s*=\s*["\'][^"\']{8,}["\']',
        "before":  'API_KEY = "sk-abcdef1234567890"',
        "after":   'API_KEY = os.environ.get("API_KEY")  # load from environment',
        "imports": "import os",
        "explanation": "Hardcoded secrets are exposed in version control. Load secrets from environment variables or a secrets manager.",
    },
    "open_redirect": {
        "detect":  r'redirect\s*\(\s*(request\.|user_|data\[)',
        "before":  'return redirect(request.args.get("next"))',
        "after":   '''safe_url = request.args.get("next", "/")
if not safe_url.startswith("/"):
    safe_url = "/"
return redirect(safe_url)''',
        "imports": "",
        "explanation": "Unvalidated redirect destinations allow phishing. Validate the URL is relative or matches your domain.",
    },
    "debug_mode_on": {
        "detect":  r'(?i)debug\s*=\s*True',
        "before":  'app.run(debug=True)',
        "after":   'app.run(debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true")',
        "imports": "import os",
        "explanation": "Debug mode in production exposes an interactive debugger. Control it via environment variable only.",
    },
    # TON-specific patches
    "ton_accept_unguarded": {
        "detect":  r'\baccept_message\s*\(\s*\)',
        "before":  "accept_message();",
        "after":   "throw_unless(error::unauthorized, equal_slices(sender, storage::owner));\naccept_message();",
        "imports": "",
        "explanation": "accept_message() without sender validation allows any external actor to drain gas from the contract.",
    },
    "ton_recv_external_no_sig": {
        "detect":  r'\brecv_external\b',
        "before":  "() recv_external(slice in_msg) impure {\n    accept_message();\n}",
        "after":   "() recv_external(slice in_msg) impure {\n    slice ds = get_data().begin_parse();\n    int stored_seqno = ds~load_uint(32);\n    int public_key   = ds~load_uint(256);\n    int msg_seqno    = in_msg~load_uint(32);\n    throw_unless(35, msg_seqno == stored_seqno);\n    var signature = in_msg~load_bits(512);\n    var msg_hash  = slice_hash(in_msg);\n    throw_unless(35, check_signature(msg_hash, signature, public_key));\n    accept_message();\n}",
        "imports": "",
        "explanation": "recv_external without signature check allows replay attacks. Validate seqno and Ed25519 signature.",
    },
}


class PatchGenerator:
    """
    Generates concrete remediation patches for security findings.
    Pattern-based (offline) for common vulnerabilities.
    Optionally uses LLM for complex/context-dependent cases.
    """

    def __init__(self):
        self._llm = None
        try:
            from config.config import OPENAI_API_KEY, OPENAI_BASE_URL, LLM_FAST_MODEL
            if OPENAI_API_KEY:
                from openai import OpenAI
                self._llm   = OpenAI(api_key=OPENAI_API_KEY, base_url=OPENAI_BASE_URL)
                self._model = LLM_FAST_MODEL
        except Exception:
            pass

    def patch_finding(self, finding: Dict) -> Dict:
        """Generate a patch for a single finding. Returns enriched finding dict."""
        patch = self._offline_patch(finding)
        if not patch and self._llm:
            patch = self._llm_patch(finding)
        if patch:
            finding["code_fix"]       = patch["after"]
            finding["patch_before"]   = patch["before"]
            finding["patch_imports"]  = patch.get("imports","")
            finding["patch_source"]   = patch.get("source","pattern")
            finding["patch_explanation"] = patch["explanation"]
        return finding

    def patch_all(self, findings: List[Dict]) -> Tuple[List[Dict], int]:
        """Patch all findings. Returns (patched_list, patch_count)."""
        count = 0
        for f in findings:
            if "code_fix" not in f or not f.get("code_fix") or f.get("code_fix") == "N/A":
                before = len(f.get("code_fix","") or "")
                self.patch_finding(f)
                if len(f.get("code_fix","") or "") > before:
                    count += 1
        return findings, count

    def generate_diff(self, finding: Dict) -> str:
        """Generate a human-readable unified diff for the finding."""
        before = finding.get("patch_before","# original code")
        after  = finding.get("code_fix","# fixed code")
        if not after or after == "N/A":
            return ""
        lines  = []
        for line in before.splitlines():
            lines.append(f"- {line}")
        for line in after.splitlines():
            lines.append(f"+ {line}")
        return "\n".join(lines)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _offline_patch(self, finding: Dict) -> Optional[Dict]:
        import re as _re
        cwe      = finding.get("cwe","")
        evidence = finding.get("evidence","")
        rule_id  = finding.get("id","")
        source   = finding.get("source","")

        for patch_id, patch in PATCHES.items():
            if _re.search(patch["detect"], evidence or "", _re.IGNORECASE):
                return {**patch, "source":"pattern", "patch_id": patch_id}
            # Also match by CWE or rule keywords
            cwe_match = {"CWE-78":"shell_injection","CWE-89":"sql_injection",
                         "CWE-95":"eval_user_input","CWE-502":"pickle_unsafe",
                         "CWE-798":"hardcoded_secret"}.get(cwe)
            if cwe_match and cwe_match == patch_id:
                return {**patch, "source":"cwe_match", "patch_id": patch_id}
            if "ton" in source.lower() and "TON001" in rule_id and "accept_message" in patch_id:
                return {**patch, "source":"rule_match", "patch_id": patch_id}
        return None

    def _llm_patch(self, finding: Dict) -> Optional[Dict]:
        try:
            import json as _json
            prompt = (
                "You are a security engineer. Generate a concrete code patch for this finding.\n"
                f"Finding: {_json.dumps(finding, indent=2)[:1500]}\n\n"
                "Return JSON only:\n"
                '{"before":"original code","after":"fixed code","imports":"any new imports","explanation":"why"}'
            )
            resp = self._llm.chat.completions.create(
                model=self._model, max_tokens=400, temperature=0.1,
                messages=[{"role":"user","content":prompt}],
            )
            text = resp.choices[0].message.content.strip()
            text = text.replace("```json","").replace("```","").strip()
            data = _json.loads(text)
            return {**data, "source":"llm"}
        except Exception:
            return None
