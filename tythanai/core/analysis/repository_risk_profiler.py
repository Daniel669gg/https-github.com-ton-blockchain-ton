"""
TythanAI — Repository Risk Profiler
Semantic fingerprinting, risk heatmap, and dependency graph for repos.
"""
import os, re, json, hashlib
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple

RISK_PATTERNS = {
    "hardcoded_secret": (r'(?i)(password|secret|api_key|token|private_key)\s*=\s*["\'][^"\']{8,}["\']', "CRITICAL"),
    "sql_format":       (r'(?i)(execute|query)\s*\(.*%\s*[(\w]', "HIGH"),
    "shell_injection":  (r'subprocess\.(run|call|Popen).*shell\s*=\s*True', "CRITICAL"),
    "eval_usage":       (r'\beval\s*\(', "CRITICAL"),
    "pickle_load":      (r'pickle\.(load|loads)\s*\(', "HIGH"),
    "yaml_unsafe":      (r'yaml\.load\s*\([^,)]+\)', "HIGH"),
    "weak_hash":        (r'hashlib\.(md5|sha1)\s*\(', "MEDIUM"),
    "debug_mode":       (r'(?i)debug\s*=\s*True', "MEDIUM"),
    "http_url":         (r'http://(?!localhost|127\.0\.0\.1)', "LOW"),
    "todo_security":    (r'(?i)#\s*(todo|fixme|hack|xxx).*security', "LOW"),
}

FILE_RISK = {".env": "CRITICAL", ".pem": "CRITICAL", ".key": "CRITICAL",
             ".pfx": "HIGH", "id_rsa": "CRITICAL", "credentials": "HIGH"}

LANG_EXT = {
    ".py":"Python",".js":"JavaScript",".ts":"TypeScript",
    ".sol":"Solidity",".fc":"FunC",".tact":"Tact",
    ".rs":"Rust",".go":"Go",".java":"Java",".rb":"Ruby",
}

class RepositoryRiskProfiler:
    """
    Produces a full risk profile of a repository:
    - Language/file composition
    - Risk heatmap (file → risk score)
    - Hotspot files (most risky)
    - Dependency surface (imports/requires)
    - Code fingerprint (sha256 of structure)
    - Overall risk tier
    """

    def profile(self, directory: str) -> Dict:
        root = Path(directory)
        if not root.exists():
            return {"error": f"Directory not found: {directory}"}

        langs: Dict[str,int]      = defaultdict(int)
        file_risks: List[Dict]    = []
        dep_surface: Set[str]     = set()
        total_lines               = 0
        total_files               = 0
        risk_accumulator          = 0
        fingerprint_parts: List[str] = []

        for f in root.rglob("*"):
            if not f.is_file():             continue
            if any(p in f.parts for p in (".git","__pycache__","node_modules",".venv","venv")):
                continue

            total_files += 1
            ext    = f.suffix.lower()
            lang   = LANG_EXT.get(ext)
            if lang: langs[lang] += 1

            file_score = 0
            file_hits:  List[Dict] = []

            # Sensitive file name check
            for fname, sev in FILE_RISK.items():
                if fname in f.name.lower():
                    sev_score = {"CRITICAL":100,"HIGH":60,"MEDIUM":30,"LOW":10}.get(sev,10)
                    file_score += sev_score
                    file_hits.append({"rule":"sensitive_filename","severity":sev,"match":f.name})

            # Content analysis for code files
            if ext in LANG_EXT:
                try:
                    content = f.read_text(errors="replace")
                    lines   = content.splitlines()
                    total_lines += len(lines)
                    fingerprint_parts.append(f"{f.name}:{len(lines)}")

                    for rule_id, (pattern, sev) in RISK_PATTERNS.items():
                        matches = re.findall(pattern, content)
                        if matches:
                            sev_score = {"CRITICAL":100,"HIGH":60,"MEDIUM":30,"LOW":10}.get(sev,10)
                            file_score += sev_score * len(matches)
                            file_hits.append({"rule":rule_id,"severity":sev,
                                              "count":len(matches)})

                    # Extract dependency surface
                    dep_surface.update(self._extract_deps(content, ext))
                except Exception:
                    pass

            if file_hits:
                risk_accumulator += file_score
                file_risks.append({
                    "file":  str(f.relative_to(root)),
                    "score": file_score,
                    "hits":  file_hits,
                    "risk_level": "CRITICAL" if file_score>=100 else
                                  "HIGH"     if file_score>=60  else
                                  "MEDIUM"   if file_score>=30  else "LOW",
                })

        file_risks.sort(key=lambda x: x["score"], reverse=True)
        hotspots = file_risks[:10]

        norm_risk = min(100, round(risk_accumulator / max(total_files,1)))
        risk_tier = ("CRITICAL" if norm_risk>=75 else "HIGH" if norm_risk>=50
                     else "MEDIUM" if norm_risk>=25 else "LOW")

        fingerprint = hashlib.sha256("|".join(sorted(fingerprint_parts)).encode()).hexdigest()[:16]

        return {
            "directory":        directory,
            "fingerprint":      fingerprint,
            "total_files":      total_files,
            "total_lines":      total_lines,
            "languages":        dict(langs),
            "risk_score":       norm_risk,
            "risk_tier":        risk_tier,
            "hotspot_files":    hotspots,
            "all_risky_files":  file_risks,
            "dependency_surface": sorted(dep_surface)[:50],
            "heatmap_summary":  self._heatmap(file_risks),
        }

    @staticmethod
    def _extract_deps(content: str, ext: str) -> Set[str]:
        deps: Set[str] = set()
        if ext == ".py":
            for m in re.finditer(r'^(?:import|from)\s+([\w\.]+)', content, re.MULTILINE):
                deps.add(m.group(1).split(".")[0])
        elif ext in (".js",".ts"):
            for m in re.finditer(r'require\(["\']([^"\'@][^"\']+)["\']', content):
                deps.add(m.group(1).split("/")[0])
            for m in re.finditer(r'from ["\']([^"\'@][^"\']+)["\']', content):
                deps.add(m.group(1).split("/")[0])
        return deps

    @staticmethod
    def _heatmap(file_risks: List[Dict]) -> Dict:
        counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for f in file_risks:
            counts[f["risk_level"]] = counts.get(f["risk_level"],0) + 1
        return counts
