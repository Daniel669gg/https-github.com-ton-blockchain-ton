"""
TythanAI Platform — Semgrep Integration
Расширяет Ghost на Java, Go, Ruby, PHP, C#, Kotlin через Semgrep.
Нормализует вывод Semgrep в Ghost finding формат с CWE/OWASP enrichment.
Graceful fallback если Semgrep не установлен.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

# Semgrep ruleset по языку — официальные и community правила
_RULESETS: Dict[str, List[str]] = {
    "java":       ["p/java", "p/owasp-top-ten"],
    "go":         ["p/golang", "p/owasp-top-ten"],
    "ruby":       ["p/ruby", "p/owasp-top-ten"],
    "php":        ["p/php"],
    "kotlin":     ["p/kotlin"],
    "csharp":     ["p/csharp"],
    "scala":      ["p/scala"],
    "python":     ["p/python"],
    "javascript": ["p/javascript", "p/typescript", "p/nodejsscan"],
    "typescript": ["p/typescript", "p/javascript"],
    "rust":       ["p/rust"],
    "c":          ["p/c"],
    "cpp":        ["p/cpp"],
}

_EXT_TO_LANG: Dict[str, str] = {
    ".java":  "java",
    ".go":    "go",
    ".rb":    "ruby",
    ".php":   "php",
    ".kt":    "kotlin",
    ".kts":   "kotlin",
    ".cs":    "csharp",
    ".scala": "scala",
    ".py":    "python",
    ".js":    "javascript",
    ".ts":    "typescript",
    ".jsx":   "javascript",
    ".tsx":   "typescript",
    ".rs":    "rust",
    ".c":     "c",
    ".cpp":   "cpp",
    ".cc":    "cpp",
}

# Semgrep severity → Ghost severity
_SEV_MAP = {
    "ERROR":   "HIGH",
    "WARNING": "MEDIUM",
    "INFO":    "LOW",
}

# Semgrep CWE tag patterns
import re as _re
_CWE_RE = _re.compile(r"CWE-(\d+)", _re.IGNORECASE)


def _semgrep_available() -> bool:
    try:
        r = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _detect_languages(path: str) -> List[str]:
    """Определяет языки в директории по расширениям файлов."""
    root  = Path(path)
    langs: Dict[str, int] = {}
    skip  = {".git", "__pycache__", "node_modules", ".venv", "venv"}
    for f in root.rglob("*"):
        if not f.is_file():
            continue
        if any(p in f.parts for p in skip):
            continue
        lang = _EXT_TO_LANG.get(f.suffix.lower())
        if lang:
            langs[lang] = langs.get(lang, 0) + 1
    # Sort by file count
    return sorted(langs.keys(), key=lambda l: -langs[l])


def _normalize_finding(raw: dict, source_path: str) -> dict:
    """Конвертирует Semgrep finding в Ghost finding формат."""
    extra   = raw.get("extra", {})
    meta    = extra.get("metadata", {})
    message = extra.get("message", raw.get("check_id", "Semgrep finding"))
    sev     = _SEV_MAP.get(extra.get("severity", "WARNING"), "MEDIUM")

    # Extract CWE from metadata tags
    cwe = ""
    for tag in meta.get("cwe", meta.get("cwe2022-top25", [])):
        m = _CWE_RE.search(str(tag))
        if m:
            cwe = f"CWE-{m.group(1)}"
            break

    # OWASP mapping from metadata
    owasp = ""
    for key in ("owasp", "owasp-top-ten"):
        val = meta.get(key, "")
        if val:
            owasp = str(val[0] if isinstance(val, list) else val)[:20]
            break

    start = raw.get("start", {})
    return {
        "rule_id":     raw.get("check_id", "SEMGREP"),
        "type":        raw.get("check_id", "SEMGREP").split(".")[-1],
        "severity":    sev,
        "cwe":         cwe,
        "owasp":       owasp,
        "file":        raw.get("path", source_path),
        "line":        start.get("line", 1),
        "column":      start.get("col", 1),
        "message":     message,
        "description": message,
        "evidence":    extra.get("lines", "").strip()[:200],
        "recommendation": meta.get("fix", meta.get("references", ["See rule documentation"])[0]
                                   if meta.get("references") else ""),
        "source":      "semgrep",
        "scanner":     "semgrep",
        "confidence":  0.75,
        "category":    meta.get("category", "security"),
        "references":  meta.get("references", [])[:3],
    }


class SemgrepScanner:
    """
    Запускает Semgrep с автоматически выбранными рулсетами.
    Нормализует вывод в Ghost формат.
    """

    def __init__(self) -> None:
        self._available = _semgrep_available()

    def is_available(self) -> bool:
        return self._available

    def scan_directory(
        self,
        path: str,
        languages: Optional[List[str]] = None,
        rulesets:  Optional[List[str]] = None,
        timeout:   int = 120,
        max_findings: int = 500,
    ) -> dict:
        """
        Сканирует директорию всеми применимыми рулсетами.
        Возвращает Ghost-формат results dict.
        """
        if not self._available:
            return {
                "findings": [],
                "error": "Semgrep not installed. Run: pip install semgrep",
                "languages": [],
                "scanner": "semgrep",
            }

        root = Path(path)
        if not root.exists():
            return {"findings": [], "error": f"Path not found: {path}", "scanner": "semgrep"}

        # Detect languages and pick rulesets
        detected = languages or _detect_languages(path)
        active_rulesets: List[str] = rulesets or []
        if not active_rulesets:
            for lang in detected[:4]:  # limit to top 4 languages
                active_rulesets.extend(_RULESETS.get(lang, []))
            # Deduplicate keeping order
            seen: set = set()
            active_rulesets = [r for r in active_rulesets if not (r in seen or seen.add(r))]

        if not active_rulesets:
            return {"findings": [], "languages": detected, "scanner": "semgrep",
                    "note": "No applicable rulesets for detected languages"}

        all_findings: List[dict] = []
        errors: List[str] = []

        for ruleset in active_rulesets[:6]:  # cap at 6 rulesets to avoid timeout
            findings, err = self._run_semgrep(path, ruleset, timeout // len(active_rulesets[:6]))
            all_findings.extend(findings)
            if err:
                errors.append(err)

        # Deduplicate by (rule_id, file, line)
        seen_keys: set = set()
        unique: List[dict] = []
        for f in all_findings:
            key = (f.get("rule_id",""), f.get("file",""), f.get("line",0))
            if key not in seen_keys:
                seen_keys.add(key)
                unique.append(f)

        unique = unique[:max_findings]

        counts: dict = {}
        for f in unique:
            s = f.get("severity","MEDIUM")
            counts[s] = counts.get(s,0) + 1

        return {
            "findings":        unique,
            "total":           len(unique),
            "severity_counts": counts,
            "languages":       detected,
            "rulesets_used":   active_rulesets,
            "errors":          errors,
            "scanner":         "semgrep",
        }

    def scan_file(self, filepath: str, timeout: int = 30) -> List[dict]:
        """Сканирует один файл."""
        if not self._available:
            return []
        ext  = Path(filepath).suffix.lower()
        lang = _EXT_TO_LANG.get(ext)
        if not lang:
            return []
        rulesets = _RULESETS.get(lang, [])[:2]
        findings = []
        for rs in rulesets:
            f, _ = self._run_semgrep(filepath, rs, timeout)
            findings.extend(f)
        return findings

    def _run_semgrep(self, path: str, ruleset: str, timeout: int) -> tuple:
        """Run semgrep with a single ruleset. Returns (findings, error_or_None)."""
        cmd = [
            "semgrep",
            "--config", ruleset,
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--timeout", str(max(10, timeout)),
            str(path),
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 5,
            )
            if result.returncode not in (0, 1):
                # Exit code 1 = findings found (normal), other = error
                stderr = result.stderr[:200] if result.stderr else ""
                return [], f"semgrep error ({result.returncode}): {stderr}"

            data     = json.loads(result.stdout) if result.stdout.strip() else {}
            raw_list = data.get("results", [])
            return [_normalize_finding(r, str(path)) for r in raw_list], None

        except subprocess.TimeoutExpired:
            return [], f"semgrep timeout ({timeout}s) for {ruleset}"
        except json.JSONDecodeError as e:
            return [], f"semgrep JSON parse error: {e}"
        except Exception as e:
            return [], str(e)

    def version(self) -> str:
        if not self._available:
            return "not installed"
        try:
            r = subprocess.run(["semgrep", "--version"], capture_output=True, text=True, timeout=5)
            return r.stdout.strip()
        except Exception:
            return "unknown"

    def status(self) -> dict:
        return {
            "available": self._available,
            "version":   self.version(),
            "supported_languages": sorted(_EXT_TO_LANG.values()),
            "rulesets": list(set(rs for rss in _RULESETS.values() for rs in rss)),
        }
