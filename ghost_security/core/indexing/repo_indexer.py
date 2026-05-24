"""
Ghost Security Platform — Repository Indexer
Semantic indexing, fingerprinting, dependency inventory, risk heatmaps,
and project metadata analysis.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ── Risk signals ───────────────────────────────────────────────────────────────
_HIGH_RISK_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".sol", ".fc", ".func", ".tact"}
_SECRET_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|password|passwd|aws[_-]?secret)\s*[=:]\s*["\'][^"\']{8,}["\']'),
    re.compile(r'(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),
]
_INJECTION_PATTERNS = [
    re.compile(r'\beval\s*\('),
    re.compile(r'\bexec\s*\('),
    re.compile(r'shell\s*=\s*True'),
    re.compile(r'cursor\.execute\s*\(.*?%\s*'),
]
_FRAMEWORK_SIGNATURES = {
    "django":    ["django", "from django"],
    "flask":     ["from flask", "import flask"],
    "fastapi":   ["from fastapi", "import fastapi"],
    "express":   ["require('express')", 'require("express")'],
    "react":     ["import React", "from 'react'"],
    "hardhat":   ["require('hardhat')", "import 'hardhat'"],
    "foundry":   ["forge-std", "Test.sol"],
}
_LANG_MAP = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
    ".jsx": "JavaScript/React", ".tsx": "TypeScript/React",
    ".sol": "Solidity", ".fc": "FunC", ".func": "FunC", ".tact": "Tact",
    ".go": "Go", ".rs": "Rust", ".java": "Java",
    ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".cpp": "C++",
    ".sh": "Shell", ".yaml": "YAML", ".yml": "YAML", ".json": "JSON",
}
_MANIFEST_FILES = {
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
    "package.json", "yarn.lock", "pnpm-lock.yaml",
    "Cargo.toml", "go.mod", "Gemfile",
    "composer.json", "pom.xml",
}


@dataclass
class FileRisk:
    path:       str
    language:   str
    lines:      int
    risk_score: float       = 0.0
    signals:    List[str]   = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path":       self.path,
            "language":   self.language,
            "lines":      self.lines,
            "risk_score": self.risk_score,
            "signals":    self.signals,
        }


class RepoIndexer:
    """
    Perform a comprehensive security-oriented analysis of a repository:
      - Language composition
      - Dependency inventory
      - Risk heatmap (per-file risk scores)
      - Framework detection
      - Repo fingerprint (reproducible hash)
      - Structural metadata
    """

    def __init__(self, max_file_size_kb: int = 256) -> None:
        self._max_bytes = max_file_size_kb * 1024

    def index(self, path: str) -> dict:
        root = Path(path)
        if not root.exists():
            return {"error": f"Path not found: {path}"}

        files = self._collect_files(root)

        lang_counts: Dict[str, int]     = defaultdict(int)
        lang_lines:  Dict[str, int]     = defaultdict(int)
        file_risks:  List[FileRisk]     = []
        manifests:   List[str]          = []
        frameworks:  List[str]          = []
        total_lines  = 0
        total_bytes  = 0
        hasher       = hashlib.sha256()

        for fpath in files:
            stat    = fpath.stat()
            ext     = fpath.suffix.lower()
            lang    = _LANG_MAP.get(ext, "Other")
            relpath = str(fpath.relative_to(root))

            # Hash for fingerprint
            hasher.update(relpath.encode())
            hasher.update(str(stat.st_size).encode())

            total_bytes += stat.st_size
            lang_counts[lang] += 1

            # Manifest detection
            if fpath.name in _MANIFEST_FILES:
                manifests.append(relpath)

            # Skip large or binary files
            if stat.st_size > self._max_bytes or ext not in _HIGH_RISK_EXTENSIONS:
                if ext in _LANG_MAP:
                    # Count lines cheaply
                    try:
                        lc = fpath.read_bytes().count(b"\n")
                        lang_lines[lang] += lc
                        total_lines      += lc
                    except Exception:
                        pass
                continue

            # Read and analyse
            try:
                code = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            lines = code.count("\n") + 1
            total_lines      += lines
            lang_lines[lang] += lines

            # Framework detection
            for fw, sigs in _FRAMEWORK_SIGNATURES.items():
                if fw not in frameworks and any(s in code for s in sigs):
                    frameworks.append(fw)

            # Risk scoring
            fr = self._score_file(relpath, lang, lines, code)
            if fr.risk_score > 0:
                file_risks.append(fr)

        # Heatmap: top 30 risky files
        heatmap = sorted(file_risks, key=lambda f: -f.risk_score)[:30]

        # Dependency inventory
        deps = self._inventory_deps(root, manifests)

        # Overall risk score
        overall_risk = self._overall_risk(file_risks)

        return {
            "path":             str(root),
            "fingerprint":      hasher.hexdigest()[:16],
            "total_files":      len(files),
            "total_lines":      total_lines,
            "total_bytes":      total_bytes,
            "languages":        dict(sorted(lang_counts.items(), key=lambda x: -x[1])),
            "language_lines":   dict(sorted(lang_lines.items(),  key=lambda x: -x[1])),
            "frameworks":       frameworks,
            "manifests":        manifests,
            "dependencies":     deps,
            "risk_heatmap":     [f.to_dict() for f in heatmap],
            "overall_risk_score": overall_risk,
            "risk_level":       self._risk_label(overall_risk),
            "stats": {
                "risky_files":    len([f for f in file_risks if f.risk_score >= 2.0]),
                "secret_signals": sum(1 for f in file_risks if any("secret" in s for s in f.signals)),
                "injection_signals": sum(1 for f in file_risks if any("injection" in s for s in f.signals)),
            },
        }

    # ── Scoring ────────────────────────────────────────────────────────────────

    def _score_file(self, relpath: str, lang: str, lines: int, code: str) -> FileRisk:
        fr = FileRisk(path=relpath, language=lang, lines=lines)

        for pat in _SECRET_PATTERNS:
            if pat.search(code):
                fr.risk_score += 3.0
                fr.signals.append("secret_pattern")
                break

        for pat in _INJECTION_PATTERNS:
            if pat.search(code):
                fr.risk_score += 2.0
                fr.signals.append("injection_pattern")
                break

        # Large files = higher attack surface
        if lines > 500:
            fr.risk_score += 0.5
            fr.signals.append("large_file")

        # Test files are low risk
        if "test" in relpath.lower() or relpath.endswith(("_test.py", "spec.js")):
            fr.risk_score *= 0.3

        fr.risk_score = round(fr.risk_score, 2)
        return fr

    @staticmethod
    def _overall_risk(file_risks: List[FileRisk]) -> float:
        if not file_risks:
            return 0.0
        top5 = sorted(file_risks, key=lambda f: -f.risk_score)[:5]
        return round(sum(f.risk_score for f in top5) / len(top5), 2)

    @staticmethod
    def _risk_label(score: float) -> str:
        if score >= 4.0: return "CRITICAL"
        if score >= 2.5: return "HIGH"
        if score >= 1.5: return "MEDIUM"
        if score > 0:    return "LOW"
        return "CLEAN"

    # ── Dependency inventory ───────────────────────────────────────────────────

    def _inventory_deps(self, root: Path, manifests: List[str]) -> List[dict]:
        deps: List[dict] = []
        for relpath in manifests:
            fpath = root / relpath
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            if fpath.name == "requirements.txt":
                deps += self._parse_requirements(text, relpath)
            elif fpath.name == "package.json":
                deps += self._parse_package_json(text, relpath)
        return deps

    @staticmethod
    def _parse_requirements(text: str, source: str) -> List[dict]:
        deps = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"([A-Za-z0-9_\-\.]+)\s*([><=!~]{1,2}\s*[\d\.\*]+)?", line)
            if m:
                deps.append({
                    "name":       m.group(1),
                    "constraint": (m.group(2) or "").strip(),
                    "ecosystem":  "PyPI",
                    "source":     source,
                })
        return deps

    @staticmethod
    def _parse_package_json(text: str, source: str) -> List[dict]:
        deps = []
        try:
            data = json.loads(text)
            for section in ("dependencies", "devDependencies"):
                for name, ver in data.get(section, {}).items():
                    deps.append({
                        "name":       name,
                        "constraint": ver,
                        "ecosystem":  "npm",
                        "dev":        section == "devDependencies",
                        "source":     source,
                    })
        except Exception:
            pass
        return deps

    # ── File collection ────────────────────────────────────────────────────────

    @staticmethod
    def _collect_files(root: Path) -> List[Path]:
        skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv",
                     "dist", "build", ".tox", ".eggs"}
        files = []
        for f in root.rglob("*"):
            if f.is_file() and not any(p in f.parts for p in skip_dirs):
                files.append(f)
        return files
