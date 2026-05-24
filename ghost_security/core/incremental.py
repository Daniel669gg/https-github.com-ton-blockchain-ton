"""
Ghost Security Platform — Incremental Scanner
Сканирует только файлы изменённые с последнего коммита / между двумя refs.
Результаты кешируются по SHA контента — повторный скан того же файла = мгновенно.

Принцип:
  1. git diff --name-only <base> <head>  → список изменённых файлов
  2. Для каждого файла: SHA-256 контента → проверить кеш
  3. Кеш miss → сканировать → сохранить в кеш
  4. Смерджить с предыдущими результатами (незатронутые файлы берём из истории)

Результат: 2-секундный скан вместо 2-минутного для CI/CD.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# ── Кеш ──────────────────────────────────────────────────────────────────────

class ScanCache:
    """
    Файловый кеш результатов сканирования.
    Ключ: SHA-256(file_content) — инвалидируется при изменении файла.
    """

    def __init__(self, cache_dir: str = "./data/scan_cache") -> None:
        self._dir = Path(cache_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._hits  = 0
        self._misses = 0

    def _key(self, content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()[:24]

    def _path(self, key: str) -> Path:
        return self._dir / f"{key}.json"

    def get(self, filepath: str) -> Optional[List[dict]]:
        """Возвращает кешированные findings если файл не изменился."""
        try:
            content = Path(filepath).read_bytes()
        except OSError:
            return None
        key   = self._key(content)
        cache = self._path(key)
        if cache.exists():
            try:
                data = json.loads(cache.read_text())
                if data.get("filepath") == filepath:
                    self._hits += 1
                    return data["findings"]
            except Exception:
                pass
        self._misses += 1
        return None

    def set(self, filepath: str, findings: List[dict]) -> None:
        """Сохраняет findings в кеш."""
        try:
            content = Path(filepath).read_bytes()
            key     = self._key(content)
            self._path(key).write_text(json.dumps({
                "filepath": filepath,
                "cached_at": time.time(),
                "findings": findings,
            }))
        except Exception:
            pass

    def invalidate(self, filepath: str) -> None:
        """Удаляет кеш для файла (например, после применения фикса)."""
        try:
            content = Path(filepath).read_bytes()
            key     = self._key(content)
            p       = self._path(key)
            if p.exists():
                p.unlink()
        except Exception:
            pass

    def clear(self) -> int:
        """Полная очистка кеша. Возвращает количество удалённых записей."""
        count = 0
        for p in self._dir.glob("*.json"):
            p.unlink()
            count += 1
        return count

    def stats(self) -> dict:
        entries = len(list(self._dir.glob("*.json")))
        total_bytes = sum(p.stat().st_size for p in self._dir.glob("*.json"))
        return {
            "entries":     entries,
            "size_kb":     round(total_bytes / 1024, 1),
            "hits":        self._hits,
            "misses":      self._misses,
            "hit_rate":    round(self._hits / max(self._hits + self._misses, 1), 3),
        }


# ── Git helpers ───────────────────────────────────────────────────────────────

def _git_available(repo: str) -> bool:
    try:
        r = subprocess.run(
            ["git", "-C", repo, "rev-parse", "--git-dir"],
            capture_output=True, timeout=5,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _git_changed_files(
    repo:  str,
    base:  str = "HEAD~1",
    head:  str = "HEAD",
    include_untracked: bool = True,
) -> List[str]:
    """
    Возвращает список изменённых файлов относительно base..head.
    include_untracked=True добавляет неотслеживаемые файлы (новые).
    """
    files: Set[str] = set()
    root = Path(repo).resolve()

    # Tracked changes
    try:
        r = subprocess.run(
            ["git", "-C", repo, "diff", "--name-only", base, head, "--diff-filter=ACMR"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if line.strip():
                    files.add(str(root / line.strip()))
    except Exception:
        pass

    # Unstaged changes (working tree)
    try:
        r = subprocess.run(
            ["git", "-C", repo, "diff", "--name-only", "--diff-filter=ACMR"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if line.strip():
                    files.add(str(root / line.strip()))
    except Exception:
        pass

    # Staged changes
    try:
        r = subprocess.run(
            ["git", "-C", repo, "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if line.strip():
                    files.add(str(root / line.strip()))
    except Exception:
        pass

    # Untracked files
    if include_untracked:
        try:
            r = subprocess.run(
                ["git", "-C", repo, "ls-files", "--others", "--exclude-standard"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    if line.strip():
                        files.add(str(root / line.strip()))
        except Exception:
            pass

    return [f for f in files if Path(f).exists() and Path(f).is_file()]


def _git_current_commit(repo: str) -> str:
    try:
        r = subprocess.run(
            ["git", "-C", repo, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip() if r.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


# ── Scanner dispatch ───────────────────────────────────────────────────────────

_SCANNABLE_EXTS = {
    ".py": ["owasp", "secrets", "ast"],
    ".js": ["js"], ".ts": ["js"], ".jsx": ["js"], ".tsx": ["js"],
    ".sol": ["solidity"],
    ".fc": ["ton"], ".func": ["ton"], ".tact": ["ton"],
    ".yaml": ["k8s"], ".yml": ["k8s"],
}

def _scan_single_file(filepath: str) -> List[dict]:
    """Сканирует один файл всеми подходящими сканерами."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))

    ext      = Path(filepath).suffix.lower()
    scanners = _SCANNABLE_EXTS.get(ext, [])
    findings: List[dict] = []

    for scanner in scanners:
        try:
            if scanner == "owasp":
                from scanners.owasp_scanner import OWASPScanner
                findings += OWASPScanner().scan_file(filepath)
            elif scanner == "secrets":
                from scanners.secret_scanner.secret_detector import SecretDetector
                findings += SecretDetector().scan_file(filepath)
            elif scanner == "js":
                from scanners.js_scanner import JSScanner
                findings += JSScanner().scan_file(filepath)
            elif scanner == "solidity":
                from scanners.solidity_scanner.solidity_analyzer import SolidityAnalyzer
                findings += SolidityAnalyzer().scan_file(filepath)
            elif scanner == "ton":
                from scanners.ton_scanner.ton_analyzer import TONAnalyzer
                findings += TONAnalyzer().analyze_file(filepath)
            elif scanner == "k8s":
                from scanners.k8s_scanner.k8s_scanner import ManifestScanner
                founds = ManifestScanner().scan_file(filepath) if hasattr(ManifestScanner(), 'scan_file') else []
                findings += [f.to_dict() if hasattr(f,'to_dict') else f for f in founds]
        except Exception as e:
            findings.append({
                "type": "SCAN_ERROR", "severity": "INFO",
                "file": filepath, "message": f"Scanner error: {e}",
            })

    # Normalise
    try:
        from core.knowledge.message_normalizer import normalise_all
        findings = normalise_all(findings)
    except Exception:
        pass

    return findings


# ── Incremental Scanner ────────────────────────────────────────────────────────

@dataclass
class IncrementalResult:
    changed_files:   List[str]
    scanned_files:   List[str]
    cached_files:    List[str]
    new_findings:    List[dict]      # findings in changed files
    all_findings:    List[dict]      # new + historical (from DB)
    duration_s:      float
    commit:          str
    base:            str
    cache_stats:     dict = field(default_factory=dict)

    def summary(self) -> dict:
        counts: dict = {}
        for f in self.new_findings:
            s = f.get("severity", "MEDIUM")
            counts[s] = counts.get(s, 0) + 1
        return {
            "changed_files":  len(self.changed_files),
            "scanned_files":  len(self.scanned_files),
            "cached_files":   len(self.cached_files),
            "new_findings":   len(self.new_findings),
            "duration_s":     round(self.duration_s, 3),
            "commit":         self.commit,
            "severity_counts": counts,
            "speedup":        f"{len(self.cached_files)}/{len(self.changed_files)} files from cache",
        }


class IncrementalScanner:
    """
    Инкрементальный сканер.
    Типичное использование в CI/CD:
        scanner = IncrementalScanner("/repo")
        result  = scanner.scan(base="origin/main", head="HEAD")
    """

    def __init__(self, repo: str = ".", cache_dir: str = "./data/scan_cache") -> None:
        self.repo  = str(Path(repo).resolve())
        self.cache = ScanCache(cache_dir)
        self._git  = _git_available(self.repo)

    def scan(
        self,
        base: str = "HEAD~1",
        head: str = "HEAD",
        include_untracked: bool = True,
        merge_historical: bool  = True,
    ) -> IncrementalResult:
        """
        Сканирует только изменённые файлы.
        merge_historical=True добавляет findings из БД для незатронутых файлов.
        """
        t0 = time.time()

        if self._git:
            changed = _git_changed_files(self.repo, base, head, include_untracked)
            commit  = _git_current_commit(self.repo)
        else:
            # Fallback: scan all files (no git)
            changed = self._all_scannable_files()
            commit  = "no-git"

        scanned: List[str] = []
        cached:  List[str] = []
        findings: List[dict] = []

        for filepath in changed:
            # Check cache first
            cached_result = self.cache.get(filepath)
            if cached_result is not None:
                cached.append(filepath)
                findings.extend(cached_result)
                continue

            # Cache miss — scan the file
            scanned.append(filepath)
            file_findings = _scan_single_file(filepath)
            self.cache.set(filepath, file_findings)
            findings.extend(file_findings)

        # Merge with historical findings from DB
        all_findings = findings[:]
        if merge_historical:
            all_findings = self._merge_historical(findings, changed)

        duration = time.time() - t0
        return IncrementalResult(
            changed_files = changed,
            scanned_files = scanned,
            cached_files  = cached,
            new_findings  = findings,
            all_findings  = all_findings,
            duration_s    = duration,
            commit        = commit,
            base          = base,
            cache_stats   = self.cache.stats(),
        )

    def scan_file(self, filepath: str) -> List[dict]:
        """Сканирует один файл с кешированием."""
        cached = self.cache.get(filepath)
        if cached is not None:
            return cached
        result = _scan_single_file(filepath)
        self.cache.set(filepath, result)
        return result

    def invalidate(self, filepath: str) -> None:
        """Инвалидирует кеш файла (после применения фикса)."""
        self.cache.invalidate(filepath)

    def cache_stats(self) -> dict:
        return self.cache.stats()

    def _all_scannable_files(self) -> List[str]:
        """Fallback: все сканируемые файлы в репозитории."""
        files = []
        skip  = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"}
        for p in Path(self.repo).rglob("*"):
            if p.is_file() and p.suffix.lower() in _SCANNABLE_EXTS:
                if not any(s in p.parts for s in skip):
                    files.append(str(p))
        return files

    def _merge_historical(
        self, new_findings: List[dict], changed_files: List[str]
    ) -> List[dict]:
        """Добавляет findings для незатронутых файлов из SQLite истории."""
        try:
            from core.persistence.db import get_db
            db      = get_db()
            scans   = db.list_scans(limit=1)
            if not scans:
                return new_findings
            last_scan = scans[0]
            historical = db.get_findings(last_scan["id"])
            changed_set = set(changed_files)
            # Keep historical findings for files NOT in this diff
            old_kept = [
                f for f in historical
                if f.get("file") not in changed_set
            ]
            return new_findings + old_kept
        except Exception:
            return new_findings
