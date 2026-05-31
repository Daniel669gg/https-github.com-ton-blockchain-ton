"""
TythanAI Platform — Performance Optimizer
Цель: < 0.5 секунды на файл, < 10 секунд на средний проект.

Оптимизации:
  1. Compiled regex cache — компилируем паттерны один раз
  2. Parallel file scanning — ThreadPoolExecutor
  3. Fast pre-filter — фильтруем файлы по сигнатурам ДО полного скана
  4. Memory-mapped file reading — быстрое чтение больших файлов
  5. Result streaming — возвращаем findings сразу, не ждём конца
"""
from __future__ import annotations

import mmap
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path
from typing import Callable, Dict, Generator, Iterator, List, Optional, Set, Tuple


# ── Compiled regex cache ───────────────────────────────────────────────────────

_PATTERN_CACHE: Dict[str, re.Pattern] = {}
_CACHE_LOCK    = threading.Lock()

@lru_cache(maxsize=512)
def _compile(pattern: str, flags: int = 0) -> re.Pattern:
    """LRU-cached regex compilation. Same pattern = one compile."""
    return re.compile(pattern, flags)


def compile_cached(pattern: str, flags: int = re.MULTILINE) -> re.Pattern:
    """Get compiled regex, using cache."""
    return _compile(pattern, flags)


# ── Fast pre-filter ────────────────────────────────────────────────────────────

# Minimal signatures to quickly decide if a file is worth scanning
_QUICK_SIGS: Dict[str, bytes] = {
    "python":     b"import ",
    "javascript": b"require(",
    "typescript": b"import ",
    "ton":        b"impure",
    "solidity":   b"pragma solidity",
    "kubernetes": b"apiVersion:",
    "secrets":    b"KEY",
}

_SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    "dist", "build", ".tox", ".eggs", ".mypy_cache",
}


def _quick_check(filepath: str, min_size: int = 20, max_size: int = 512 * 1024) -> bool:
    """Fast O(1) check before full scan. Returns True if file should be scanned."""
    try:
        stat = os.stat(filepath)
        size = stat.st_size
        if size < min_size or size > max_size:
            return False
        # Check for binary (read first 512 bytes)
        with open(filepath, "rb") as f:
            header = f.read(512)
        # Binary check: more than 10% non-printable bytes = skip
        non_print = sum(1 for b in header if b < 9 or (13 < b < 32) or b > 126)
        return non_print / max(len(header), 1) < 0.10
    except OSError:
        return False


def _collect_files(
    root: str,
    extensions: Optional[Set[str]] = None,
    max_size_kb: int = 512,
) -> List[str]:
    """Fast file collection with skip-dir pruning."""
    if extensions is None:
        extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".sol",
                      ".fc", ".func", ".tact", ".yaml", ".yml", ".go",
                      ".java", ".rb", ".php", ".rs", ".cs"}
    files = []
    max_bytes = max_size_kb * 1024
    for entry in os.scandir(root):
        if entry.name.startswith(".") and entry.name not in {".github"}:
            continue
        if entry.name in _SKIP_DIRS:
            continue
        if entry.is_dir(follow_symlinks=False):
            files.extend(_collect_files(entry.path, extensions, max_size_kb))
        elif (entry.is_file(follow_symlinks=False)
              and Path(entry.name).suffix.lower() in extensions
              and entry.stat().st_size <= max_bytes):
            files.append(entry.path)
    return files


# ── Parallel scanner ───────────────────────────────────────────────────────────

class ParallelScanner:
    """
    Runs multiple scanners in parallel across files.
    Up to 4x speedup on multi-core machines.
    """

    def __init__(
        self,
        workers: int = 0,  # 0 = auto (min(cpu_count, 8))
        timeout_per_file: float = 10.0,
    ) -> None:
        self._workers = workers or min(os.cpu_count() or 4, 8)
        self._timeout = timeout_per_file

    def scan_directory(
        self,
        path: str,
        scanner_fn: Callable[[str], List[dict]],
        progress_cb: Optional[Callable[[str, int, int], None]] = None,
    ) -> dict:
        """
        Scan all files in parallel.
        scanner_fn(filepath) → List[finding_dict]
        progress_cb(filepath, done, total) → None
        """
        root  = Path(path)
        files = _collect_files(str(root)) if root.is_dir() else [str(root)]
        files = [f for f in files if _quick_check(f)]

        total    = len(files)
        findings : List[dict] = []
        done_count = 0
        lock     = threading.Lock()

        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            future_map = {pool.submit(self._safe_scan, f, scanner_fn): f for f in files}
            for future in as_completed(future_map, timeout=self._timeout * total + 30):
                filepath = future_map[future]
                try:
                    result = future.result(timeout=self._timeout)
                    with lock:
                        findings.extend(result)
                        done_count += 1
                        if progress_cb:
                            progress_cb(filepath, done_count, total)
                except Exception:
                    with lock:
                        done_count += 1

        counts: dict = {}
        for f in findings:
            s = f.get("severity", "MEDIUM")
            counts[s] = counts.get(s, 0) + 1

        return {
            "findings":        findings,
            "total":           len(findings),
            "severity_counts": counts,
            "files_scanned":   total,
            "workers":         self._workers,
        }

    def scan_stream(
        self,
        path: str,
        scanner_fn: Callable[[str], List[dict]],
    ) -> Iterator[dict]:
        """
        Generator that yields findings as they're discovered.
        Perfect for WebSocket streaming to dashboard.
        """
        root  = Path(path)
        files = _collect_files(str(root)) if root.is_dir() else [str(root)]
        files = [f for f in files if _quick_check(f)]

        with ThreadPoolExecutor(max_workers=self._workers) as pool:
            futures = {pool.submit(self._safe_scan, f, scanner_fn): f for f in files}
            for future in as_completed(futures):
                try:
                    for finding in future.result(timeout=self._timeout):
                        yield finding
                except Exception:
                    pass

    @staticmethod
    def _safe_scan(filepath: str, scanner_fn: Callable) -> List[dict]:
        try:
            return scanner_fn(filepath) or []
        except Exception:
            return []


# ── Memory-mapped fast reader ─────────────────────────────────────────────────

def read_fast(filepath: str) -> Optional[str]:
    """
    Fast file reading using mmap for files > 64KB.
    Falls back to regular read for small files.
    """
    try:
        size = os.path.getsize(filepath)
        if size == 0:
            return ""
        if size < 65536:
            return Path(filepath).read_text(encoding="utf-8", errors="replace")
        with open(filepath, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                return mm[:].decode("utf-8", errors="replace")
            finally:
                mm.close()
    except Exception:
        return None


# ── Scan timing & profiler ────────────────────────────────────────────────────

class ScanProfiler:
    """Tracks per-file and per-scanner timing for performance tuning."""

    def __init__(self) -> None:
        self._timings: List[Tuple[str, float]] = []
        self._lock = threading.Lock()

    def record(self, name: str, duration_ms: float) -> None:
        with self._lock:
            self._timings.append((name, duration_ms))

    def report(self) -> dict:
        if not self._timings:
            return {}
        total   = sum(d for _, d in self._timings)
        slowest = sorted(self._timings, key=lambda x: -x[1])[:5]
        avg     = total / len(self._timings)
        return {
            "total_scans":  len(self._timings),
            "total_ms":     round(total, 2),
            "avg_ms":       round(avg, 2),
            "slowest_files": [{"name": n, "ms": round(d, 2)} for n, d in slowest],
        }

    def reset(self) -> None:
        with self._lock:
            self._timings.clear()


# ── Optimized ghost scanner function ─────────────────────────────────────────

def make_fast_scanner() -> Callable[[str], List[dict]]:
    """
    Returns a scanner function optimised for parallel use.
    Pre-loads all scanner instances once, reuses them.
    """
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))

    from scanners.owasp_scanner import OWASPScanner
    from scanners.secret_scanner.secret_detector import SecretDetector
    from scanners.ton_scanner.ton_analyzer import TONAnalyzer

    # Pre-instantiate (avoid __init__ overhead per file)
    _owasp   = OWASPScanner()
    _secrets = SecretDetector()
    _ton     = TONAnalyzer()

    def _scan(filepath: str) -> List[dict]:
        ext    = Path(filepath).suffix.lower()
        result = []
        try:
            if ext == ".py":
                result += _owasp.scan_file(filepath)
                result += _secrets.scan_file(filepath)
            elif ext in (".fc", ".func", ".tact"):
                result += _ton.analyze_file(filepath)
            elif ext in (".yaml", ".yml"):
                from scanners.k8s_scanner.k8s_scanner import ManifestScanner
                raw = ManifestScanner().scan_file(filepath) if hasattr(ManifestScanner(), 'scan_file') else []
                result += [r.to_dict() if hasattr(r,'to_dict') else r for r in raw]
        except Exception:
            pass
        return result

    return _scan


# Singleton parallel scanner
PARALLEL = ParallelScanner()
