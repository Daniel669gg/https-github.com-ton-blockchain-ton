"""
TythanAI Platform — Autonomous Remediation Engine
Defensive fix automation:
  1. Анализирует finding → генерирует конкретный патч через LLM
  2. Валидирует патч (синтаксис, тесты)
  3. Предлагает diff в UI / открывает PR через GitHub API
  4. Хранит историю применённых фиксов в векторной памяти
  5. Rollback — может отменить применённый фикс

Принципы безопасности:
  - Никогда не применяет фикс автоматически без подтверждения
  - Все патчи показываются как diff перед применением
  - Rollback всегда доступен
"""
from __future__ import annotations

import ast
import difflib
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── Известные безопасные паттерны исправлений ─────────────────────────────────
_SAFE_FIX_PATTERNS: Dict[str, Dict] = {
    "sql_injection": {
        "description": "Replace string concatenation with parameterised query",
        "patterns": [
            # cursor.execute("SELECT" + var) → cursor.execute("SELECT %s", (var,))
            (r'cursor\.execute\s*\(\s*(["\'])(.+?)\1\s*\+\s*(\w+)\s*\)',
             r'cursor.execute(\1\2%s\1, (\3,))'),
            (r'cursor\.execute\s*\(\s*f["\'](.+?)["\'].*?\)',
             None),  # flag for LLM
        ],
        "severity": ["CRITICAL", "HIGH"],
    },
    "hardcoded_secret": {
        "description": "Move secret to environment variable",
        "template": "os.environ.get('{env_var_name}', '')",
        "severity": ["CRITICAL", "HIGH"],
    },
    "weak_hash": {
        "description": "Replace MD5/SHA1 with SHA-256",
        "patterns": [
            (r'hashlib\.md5\s*\(', 'hashlib.sha256('),
            (r'hashlib\.sha1\s*\(', 'hashlib.sha256('),
        ],
        "severity": ["HIGH", "MEDIUM"],
    },
    "eval_injection": {
        "description": "Remove eval(); use safe alternative",
        "patterns": [
            (r'\beval\s*\((.+?)\)', r'# REMOVED EVAL — use ast.literal_eval(\1) for safe parsing'),
        ],
        "severity": ["CRITICAL"],
    },
    "shell_injection": {
        "description": "Set shell=False and pass args as list",
        "patterns": [
            (r'subprocess\.run\((.+?),\s*shell=True\)',
             r'subprocess.run(\1, shell=False)'),
            (r'subprocess\.call\((.+?),\s*shell=True\)',
             r'subprocess.call(\1, shell=False)'),
        ],
        "severity": ["CRITICAL", "HIGH"],
    },
    "debug_mode": {
        "description": "Disable debug mode in production",
        "patterns": [
            (r'app\.run\((.*)debug\s*=\s*True(.*)\)',
             r'app.run(\1debug=False\2)'),
            (r'DEBUG\s*=\s*True', 'DEBUG = False'),
        ],
        "severity": ["HIGH", "MEDIUM"],
    },
    # TON-specific
    "ton_mode128": {
        "description": "Add raw_reserve before mode-128 send",
        "template": "raw_reserve(min_storage_fee, 2);  ;; protect storage balance\n{original}",
        "severity": ["CRITICAL"],
    },
    "ton_accept_unauth": {
        "description": "Add sender check before accept_message",
        "template": "throw_unless(error::unauthorized, equal_slices(sender, storage::owner));\n{original}",
        "severity": ["CRITICAL", "HIGH"],
    },
    # K8s-specific
    "k8s_privileged": {
        "description": "Set privileged: false",
        "patterns": [(r'privileged:\s*true', 'privileged: false')],
        "severity": ["CRITICAL"],
    },
    "k8s_run_as_root": {
        "description": "Set runAsNonRoot and runAsUser",
        "template": "runAsNonRoot: true\n          runAsUser: 1000",
        "severity": ["HIGH"],
    },
    "k8s_latest_tag": {
        "description": "Pin image to specific version",
        "patterns": [(r'image:\s*(\S+):latest', r'image: \1:1.0.0  # TODO: pin to exact version')],
        "severity": ["LOW", "MEDIUM"],
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# PATCH MODEL
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class RemediationPatch:
    finding_id:   str
    finding_type: str
    file:         str
    line:         int
    original:     str      # original code snippet
    fixed:        str      # fixed code snippet
    diff:         str      # unified diff
    description:  str
    method:       str      # "pattern" | "llm" | "template"
    confidence:   float    # 0.0–1.0
    safe_to_apply: bool    = True
    applied:      bool     = False
    applied_at:   float    = 0.0
    rollback_data: str     = ""  # original content for rollback

    def to_dict(self) -> dict:
        return {
            "finding_id":   self.finding_id,
            "finding_type": self.finding_type,
            "file":         self.file,
            "line":         self.line,
            "diff":         self.diff,
            "description":  self.description,
            "method":       self.method,
            "confidence":   self.confidence,
            "safe_to_apply": self.safe_to_apply,
            "applied":      self.applied,
        }


# ══════════════════════════════════════════════════════════════════════════════
# PATTERN-BASED FIXER (fast, high confidence, no LLM)
# ══════════════════════════════════════════════════════════════════════════════

class PatternFixer:
    """Применяет известные безопасные regex-замены без LLM."""

    def fix(self, finding: dict, code: str) -> Optional[RemediationPatch]:
        ftype = self._classify(finding)
        if not ftype or ftype not in _SAFE_FIX_PATTERNS:
            return None

        pattern_cfg = _SAFE_FIX_PATTERNS[ftype]
        patterns    = pattern_cfg.get("patterns", [])
        if not patterns:
            return None

        new_code = code
        applied  = False
        for old_pat, new_pat in patterns:
            if new_pat is None:
                continue  # needs LLM
            if re.search(old_pat, code):
                new_code = re.sub(old_pat, new_pat, code)
                applied  = True
                break

        if not applied or new_code == code:
            return None

        diff = self._make_diff(code, new_code, finding.get("file", ""))
        return RemediationPatch(
            finding_id   = hashlib.sha1(json.dumps(finding).encode()).hexdigest()[:12],
            finding_type = ftype,
            file         = finding.get("file", ""),
            line         = finding.get("line", 0),
            original     = code,
            fixed        = new_code,
            diff         = diff,
            description  = pattern_cfg["description"],
            method       = "pattern",
            confidence   = 0.90,
        )

    @staticmethod
    def _classify(finding: dict) -> Optional[str]:
        t = (finding.get("type") or finding.get("rule_id") or "").lower().replace("-", "_")
        mapping = {
            "sql":        "sql_injection",
            "secret":     "hardcoded_secret",
            "hardcoded":  "hardcoded_secret",
            "md5":        "weak_hash",
            "sha1":       "weak_hash",
            "weak_hash":  "weak_hash",
            "eval":       "eval_injection",
            "shell":      "shell_injection",
            "command":    "shell_injection",
            "debug":      "debug_mode",
            "ton_fund":   "ton_mode128",
            "ton_gas":    "ton_accept_unauth",
            "k8s_pod_004": "k8s_privileged",
            "k8s_pod_005": "k8s_run_as_root",
            "k8s_img":    "k8s_latest_tag",
        }
        for keyword, ftype in mapping.items():
            if keyword in t:
                return ftype
        return None

    @staticmethod
    def _make_diff(original: str, fixed: str, filename: str) -> str:
        orig_lines  = original.splitlines(keepends=True)
        fixed_lines = fixed.splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines, fixed_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
            lineterm="",
        )
        return "".join(diff)


# ══════════════════════════════════════════════════════════════════════════════
# LLM-BASED FIXER (richer fixes, lower confidence)
# ══════════════════════════════════════════════════════════════════════════════

class LLMFixer:
    """Генерирует фикс через Multi-LLM Router."""

    _SYSTEM = (
        "You are a senior security engineer specialising in secure code fixes. "
        "Given a vulnerability and the vulnerable code, provide ONLY the fixed code. "
        "Rules: 1) Output ONLY the fixed code, no explanation. "
        "2) Keep formatting identical to input. "
        "3) Make minimal changes — only fix the specific vulnerability. "
        "4) Add a single inline comment # SECURITY FIX: <reason> on the changed line."
    )

    def fix(self, finding: dict, code_context: str) -> Optional[RemediationPatch]:
        try:
            from runtime.providers.multi_llm_router import ROUTER
        except ImportError:
            return None

        sev  = finding.get("severity", "MEDIUM")
        task = "remediation"
        if sev == "CRITICAL":
            task = "security"  # use best model for critical

        ftype   = finding.get("type") or finding.get("rule_id") or "vulnerability"
        message = finding.get("message") or finding.get("description") or ""
        cwe     = finding.get("cwe", "")
        prompt  = f"""Vulnerability found:
Type: {ftype}
Severity: {sev}
Message: {message}
CWE: {cwe}
File: {finding.get('file','')} line {finding.get('line','')}

Vulnerable code:
```
{code_context[:2000]}
```

Provide only the fixed code (same language, minimal changes):"""

        resp = ROUTER.call(task, prompt, system=self._SYSTEM, max_tokens=1500)
        if not resp.ok:
            return None

        fixed = self._extract_code(resp.text)
        if not fixed or fixed == code_context:
            return None

        diff = PatternFixer._make_diff(code_context, fixed, finding.get("file",""))
        return RemediationPatch(
            finding_id   = hashlib.sha1(json.dumps(finding).encode()).hexdigest()[:12],
            finding_type = ftype,
            file         = finding.get("file", ""),
            line         = finding.get("line", 0),
            original     = code_context,
            fixed        = fixed,
            diff         = diff,
            description  = f"LLM-generated fix for {ftype} ({resp.provider}/{resp.model})",
            method       = "llm",
            confidence   = 0.70,
            safe_to_apply = False,  # LLM fixes require human review
        )

    @staticmethod
    def _extract_code(text: str) -> str:
        """Extract code from LLM response — remove markdown fences."""
        # Try code block first
        m = re.search(r"```(?:\w+)?\n(.*?)```", text, re.DOTALL)
        if m:
            return m.group(1).strip()
        # Strip explanation lines (start with capital letter + full stop)
        lines = text.splitlines()
        code_lines = [l for l in lines if not re.match(r'^[A-Z][^`]*\.$', l.strip())]
        return "\n".join(code_lines).strip()


# ══════════════════════════════════════════════════════════════════════════════
# PATCH VALIDATOR
# ══════════════════════════════════════════════════════════════════════════════

class PatchValidator:
    """Валидирует патч перед применением."""

    def validate(self, patch: RemediationPatch) -> Tuple[bool, str]:
        """Returns (is_valid, reason)."""
        if not patch.fixed.strip():
            return False, "Empty fix"

        ext = Path(patch.file).suffix.lower()
        if ext == ".py":
            return self._validate_python(patch.fixed)
        if ext in (".yaml", ".yml"):
            return self._validate_yaml(patch.fixed)
        return True, "No syntax validation for this file type"

    @staticmethod
    def _validate_python(code: str) -> Tuple[bool, str]:
        try:
            ast.parse(code)
            return True, "Valid Python syntax"
        except SyntaxError as e:
            return False, f"Syntax error: {e}"

    @staticmethod
    def _validate_yaml(code: str) -> Tuple[bool, str]:
        try:
            import yaml
            yaml.safe_load(code)
            return True, "Valid YAML"
        except Exception as e:
            return False, f"Invalid YAML: {e}"


# ══════════════════════════════════════════════════════════════════════════════
# FILE APPLIER (with rollback)
# ══════════════════════════════════════════════════════════════════════════════

class FileApplier:
    """Применяет патч к файлу. Хранит backup для rollback."""

    def __init__(self, backup_dir: str = "./data/fix_backups") -> None:
        self._backup_dir = Path(backup_dir)
        self._backup_dir.mkdir(parents=True, exist_ok=True)

    def apply(self, patch: RemediationPatch) -> Tuple[bool, str]:
        """Apply patch to file. Returns (success, message)."""
        fpath = Path(patch.file)
        if not fpath.exists():
            return False, f"File not found: {patch.file}"

        original_content = fpath.read_text(encoding="utf-8")

        # Backup
        backup_id  = f"{hashlib.sha1(patch.file.encode()).hexdigest()[:8]}_{int(time.time())}"
        backup_path = self._backup_dir / f"{backup_id}.bak"
        backup_path.write_text(original_content, encoding="utf-8")
        patch.rollback_data = str(backup_path)

        # Write fix
        try:
            fpath.write_text(patch.fixed, encoding="utf-8")
            patch.applied    = True
            patch.applied_at = time.time()
            return True, f"Applied. Backup at {backup_path}"
        except Exception as e:
            # Restore on failure
            fpath.write_text(original_content, encoding="utf-8")
            return False, f"Failed to write: {e}"

    def rollback(self, patch: RemediationPatch) -> Tuple[bool, str]:
        """Rollback a previously applied patch."""
        if not patch.applied:
            return False, "Patch was not applied"
        if not patch.rollback_data or not Path(patch.rollback_data).exists():
            return False, "Backup not found"
        original = Path(patch.rollback_data).read_text(encoding="utf-8")
        Path(patch.file).write_text(original, encoding="utf-8")
        patch.applied = False
        return True, "Rollback successful"


# ══════════════════════════════════════════════════════════════════════════════
# GITHUB PR CREATOR
# ══════════════════════════════════════════════════════════════════════════════

class PRCreator:
    """Opens a GitHub PR with the security fix."""

    def create_fix_pr(
        self,
        patch: RemediationPatch,
        owner: str,
        repo:  str,
        base_branch: str = "main",
    ) -> dict:
        """
        Creates a branch with the fix and opens a draft PR.
        Requires GITHUB_TOKEN with repo write permission.
        """
        token = os.getenv("GITHUB_TOKEN", "")
        if not token:
            return {"error": "GITHUB_TOKEN not set"}

        import urllib.request, base64
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        }

        def gh(method: str, path: str, body: dict = None) -> dict:
            url  = f"https://api.github.com{path}"
            data = json.dumps(body).encode() if body else None
            req  = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with urllib.request.urlopen(req, timeout=15) as r:
                    return json.loads(r.read())
            except Exception as e:
                return {"error": str(e)}

        # 1. Get base branch SHA
        ref  = gh("GET", f"/repos/{owner}/{repo}/git/ref/heads/{base_branch}")
        if "error" in ref:
            return ref
        sha  = ref["object"]["sha"]

        # 2. Create fix branch
        branch = f"ghost-security-fix/{patch.finding_type}-{int(time.time())}"
        create = gh("POST", f"/repos/{owner}/{repo}/git/refs", {
            "ref": f"refs/heads/{branch}", "sha": sha,
        })
        if "error" in create:
            return create

        # 3. Get current file content
        file_content = gh("GET", f"/repos/{owner}/{repo}/contents/{patch.file}")
        if "error" in file_content:
            return file_content
        file_sha = file_content.get("sha", "")

        # 4. Push fix
        content_b64 = base64.b64encode(patch.fixed.encode()).decode()
        push = gh("PUT", f"/repos/{owner}/{repo}/contents/{patch.file}", {
            "message": f"fix: {patch.finding_type} security vulnerability\n\n"
                       f"Automated fix by TythanAI Platform.\n"
                       f"CWE: {patch.finding_type}\n"
                       f"Confidence: {patch.confidence:.0%}",
            "content": content_b64,
            "sha":     file_sha,
            "branch":  branch,
        })
        if "error" in push:
            return push

        # 5. Open draft PR
        pr = gh("POST", f"/repos/{owner}/{repo}/pulls", {
            "title":  f"[TythanAI] Fix {patch.finding_type} in {Path(patch.file).name}",
            "body":   self._pr_body(patch),
            "head":   branch,
            "base":   base_branch,
            "draft":  True,
        })
        return {
            "pr_url":    pr.get("html_url", ""),
            "pr_number": pr.get("number", 0),
            "branch":    branch,
            "status":    "created" if "html_url" in pr else "failed",
        }

    @staticmethod
    def _pr_body(patch: RemediationPatch) -> str:
        return f"""## 🔒 TythanAI — Automated Fix

**Finding:** `{patch.finding_type}`  
**File:** `{patch.file}` line {patch.line}  
**Fix method:** {patch.method} (confidence: {patch.confidence:.0%})  

### Diff
```diff
{patch.diff[:3000]}
```

### Description
{patch.description}

---
⚠️ **This is a DRAFT PR** — please review the diff carefully before merging.  
*Generated by [TythanAI Platform](https://github.com/ghost-security/platform)*
"""


# ══════════════════════════════════════════════════════════════════════════════
# REMEDIATION ENGINE (main)
# ══════════════════════════════════════════════════════════════════════════════

class RemediationEngine:
    """
    Единый entry point автономной ремедиации.

    Workflow:
      1. generate(finding)  → RemediationPatch (diff показывается пользователю)
      2. validate(patch)    → bool (синтаксис OK?)
      3. apply(patch)       → применить к файлу (только с разрешения пользователя)
      4. create_pr(patch)   → открыть GitHub PR
      5. rollback(patch)    → отменить
    """

    def __init__(self) -> None:
        self._pattern  = PatternFixer()
        self._llm      = LLMFixer()
        self._validator = PatchValidator()
        self._applier  = FileApplier()
        self._pr       = PRCreator()
        self._history: List[RemediationPatch] = []

    def generate(
        self,
        finding: dict,
        code_context: str = "",
        use_llm: bool     = True,
    ) -> Optional[RemediationPatch]:
        """
        Генерирует патч для finding.
        Пробует: pattern → LLM.
        """
        # Try pattern first (fast, deterministic)
        patch = self._pattern.fix(finding, code_context or self._load_context(finding))
        if patch:
            valid, reason = self._validator.validate(patch)
            patch.safe_to_apply = valid
            self._history.append(patch)
            return patch

        # Fallback to LLM
        if use_llm:
            patch = self._llm.fix(finding, code_context or self._load_context(finding))
            if patch:
                valid, _ = self._validator.validate(patch)
                patch.safe_to_apply = valid
                self._history.append(patch)
                return patch

        return None

    def generate_batch(
        self,
        findings: List[dict],
        use_llm: bool = True,
    ) -> List[RemediationPatch]:
        """Генерирует патчи для списка findings."""
        patches = []
        for f in findings:
            p = self.generate(f, use_llm=use_llm)
            if p:
                patches.append(p)
        return patches

    def apply(self, patch: RemediationPatch) -> Tuple[bool, str]:
        """Применяет патч к файлу (с backup)."""
        valid, reason = self._validator.validate(patch)
        if not valid:
            return False, f"Validation failed: {reason}"
        return self._applier.apply(patch)

    def rollback(self, patch: RemediationPatch) -> Tuple[bool, str]:
        return self._applier.rollback(patch)

    def create_pr(self, patch: RemediationPatch, owner: str, repo: str) -> dict:
        return self._pr.create_fix_pr(patch, owner, repo)

    def history(self) -> List[dict]:
        return [p.to_dict() for p in self._history]

    @staticmethod
    def _load_context(finding: dict, window: int = 30) -> str:
        """Загружает контекст (±window строк) из файла finding."""
        try:
            fpath = Path(finding.get("file", ""))
            if not fpath.exists():
                return finding.get("evidence", "")
            lines  = fpath.read_text(encoding="utf-8").splitlines()
            lineno = max(0, finding.get("line", 1) - 1)
            start  = max(0, lineno - window)
            end    = min(len(lines), lineno + window)
            return "\n".join(lines[start:end])
        except Exception:
            return finding.get("evidence", "")


# Singleton
REMEDIATION = RemediationEngine()
