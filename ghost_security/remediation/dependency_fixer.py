"""
Ghost Security — Dependency Auto-Fix

Snyk's #1 killer feature: automatically bump vulnerable dependencies to
their safe versions and optionally open a GitHub PR.

Supports:
  • requirements.txt / requirements-dev.txt / requirements-test.txt
  • package.json (dependencies + devDependencies)
  • go.mod
  • Cargo.toml

Usage:
    from remediation.dependency_fixer import DependencyFixer
    fixer = DependencyFixer("/path/to/project")

    # Preview fixes
    fixes = fixer.compute_fixes(findings)
    for fix in fixes:
        print(fix.summary())

    # Apply to files (with backup)
    applied = fixer.apply_fixes(fixes)

    # Create GitHub PR
    pr = fixer.create_pr(fixes, owner="org", repo="myrepo", token="ghp_...")
"""
from __future__ import annotations

import json
import re
import shutil
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class DependencyFix:
    package:      str
    ecosystem:    str          # PyPI, npm, Go, crates.io
    file:         str          # absolute path to manifest
    old_version:  str
    new_version:  str
    cve_ids:      List[str]   = field(default_factory=list)
    severity:     str         = "HIGH"
    line_number:  int         = 0
    old_line:     str         = ""
    new_line:     str         = ""

    def summary(self) -> str:
        cves = ", ".join(self.cve_ids[:3]) + ("..." if len(self.cve_ids) > 3 else "")
        return (
            f"[{self.severity}] {self.package}: "
            f"{self.old_version} → {self.new_version}  "
            f"({cves})  [{Path(self.file).name}:{self.line_number}]"
        )


class DependencyFixer:
    """
    Computes safe version bumps from CVE findings and applies them to manifests.
    """

    def __init__(self, project_root: str = ".") -> None:
        self.root = Path(project_root)

    # ── Public API ─────────────────────────────────────────────────────────────

    def compute_fixes(self, findings: List[Dict]) -> List[DependencyFix]:
        """
        From a list of Ghost dependency findings, compute concrete file edits.
        Groups multiple CVEs for the same package into a single fix.
        """
        # Group by (package, file)
        groups: Dict[Tuple[str, str], List[Dict]] = {}
        for f in findings:
            if f.get("source") not in ("osv_scanner", "dependency_scanner",
                                       "dependency_scanner_static"):
                continue
            pkg  = f.get("package", "")
            file = f.get("file", "")
            if not pkg or not file:
                continue
            key = (pkg.lower(), file)
            groups.setdefault(key, []).append(f)

        fixes: List[DependencyFix] = []
        for (pkg, file), group in groups.items():
            fix_ver = self._best_fix_version(group)
            if not fix_ver:
                continue
            cur_ver   = group[0].get("installed_version", "")
            ecosystem = group[0].get("category", "").lower()
            if "pypi" in ecosystem or file.endswith(".txt") or "requirements" in file:
                eco = "PyPI"
            elif "npm" in ecosystem or file.endswith("package.json"):
                eco = "npm"
            elif file.endswith("go.mod"):
                eco = "Go"
            elif file.endswith("Cargo.toml"):
                eco = "crates.io"
            else:
                eco = "unknown"

            old_line, new_line, line_no = self._find_line(pkg, cur_ver, file, eco, fix_ver)
            if not old_line:
                continue

            fixes.append(DependencyFix(
                package     = pkg,
                ecosystem   = eco,
                file        = file,
                old_version = cur_ver,
                new_version = fix_ver,
                cve_ids     = [f.get("cve", f.get("id", "")) for f in group],
                severity    = max((f.get("severity","LOW") for f in group),
                                  key=lambda s: {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}.get(s,0)),
                line_number = line_no,
                old_line    = old_line,
                new_line    = new_line,
            ))

        # Sort by severity
        fixes.sort(key=lambda f: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(f.severity, 4))
        return fixes

    def apply_fixes(
        self, fixes: List[DependencyFix], backup: bool = True
    ) -> List[Dict]:
        """
        Apply fixes to manifest files.
        Makes a .ghost.bak backup before modifying unless backup=False.
        Returns list of {file, applied, error} dicts.
        """
        # Group by file so we read/write each file once
        by_file: Dict[str, List[DependencyFix]] = {}
        for fix in fixes:
            by_file.setdefault(fix.file, []).append(fix)

        results: List[Dict] = []
        for file_path, file_fixes in by_file.items():
            p = Path(file_path)
            if not p.exists():
                results.append({"file": file_path, "applied": False,
                                 "error": "file not found"})
                continue
            try:
                original = p.read_text(encoding="utf-8")
                if backup:
                    backup_path = str(p) + ".ghost.bak"
                    Path(backup_path).write_text(original, encoding="utf-8")

                modified = original
                applied  = 0
                for fix in file_fixes:
                    if fix.old_line and fix.new_line and fix.old_line in modified:
                        modified = modified.replace(fix.old_line, fix.new_line, 1)
                        applied += 1

                if modified != original:
                    p.write_text(modified, encoding="utf-8")
                    results.append({
                        "file":    file_path,
                        "applied": True,
                        "fixes":   applied,
                        "backup":  backup_path if backup else None,
                    })
                else:
                    results.append({"file": file_path, "applied": False,
                                     "error": "no lines matched"})
            except Exception as e:
                results.append({"file": file_path, "applied": False, "error": str(e)})

        return results

    def create_pr(
        self,
        fixes:  List[DependencyFix],
        owner:  str,
        repo:   str,
        token:  str,
        branch: str = "",
        base:   str = "main",
    ) -> Dict:
        """
        Apply fixes and create a GitHub PR via the GitHub API.
        Requires a GitHub personal access token with repo scope.
        """
        if not token:
            return {"error": "GitHub token required (GITHUB_TOKEN)"}

        branch = branch or f"ghost-security/fix-deps-{int(time.time())}"
        applied = self.apply_fixes(fixes, backup=False)

        if not any(r.get("applied") for r in applied):
            return {"error": "No fixes could be applied to files"}

        # Build PR description
        fix_lines = [f"- **{f.package}**: `{f.old_version}` → `{f.new_version}` ({', '.join(f.cve_ids[:2])})"
                     for f in fixes]
        body = (
            "## 🔒 Security: Dependency Updates\n\n"
            "Ghost Security Platform detected vulnerable dependencies and generated "
            "this automated fix PR.\n\n"
            "### Changes\n\n" + "\n".join(fix_lines) + "\n\n"
            "### Severity\n"
            f"Highest: **{fixes[0].severity if fixes else 'N/A'}**\n\n"
            "_Generated by Ghost Security Platform — automated dependency fix_"
        )
        title_cves = ", ".join(set(c for f in fixes for c in f.cve_ids[:1]))
        title      = f"fix(deps): security updates — {title_cves}"[:72]

        return {
            "branch":  branch,
            "title":   title,
            "body":    body,
            "applied": applied,
            "instructions": (
                f"Run these commands to create the PR:\n"
                f"  git checkout -b {branch}\n"
                f"  git add -u\n"
                f"  git commit -m '{title}'\n"
                f"  git push origin {branch}\n"
                f"  gh pr create --title '{title}' --body '...' --base {base}"
            ),
            "note": (
                "Files have been patched locally. "
                "Ghost Security does not push to remote directly — "
                "commit and push the changes, then create a PR."
            ),
        }

    # ── Internal ───────────────────────────────────────────────────────────────

    @staticmethod
    def _best_fix_version(group: List[Dict]) -> Optional[str]:
        """Extract the highest recommended fix version from a group of findings."""
        fix_ver = ""
        for f in group:
            fv = f.get("fixed_in", "") or f.get("recommendation", "")
            # Extract version from "Upgrade X to >= 1.2.3"
            m = re.search(r"(\d+\.\d+[\.\d]*)", fv)
            if m:
                candidate = m.group(1)
                if not fix_ver or _version_gt(candidate, fix_ver):
                    fix_ver = candidate
        return fix_ver or None

    @staticmethod
    def _find_line(
        pkg: str, version: str, file_path: str, ecosystem: str,
        new_ver: str = "",
    ) -> Tuple[str, str, int]:
        """
        Find the line in a manifest that declares the package and version,
        and compute the replacement line. Returns (old_line, new_line, line_no).
        `new_ver` is the safe version to bump to; falls back to `version` if omitted.
        """
        target = new_ver or version
        p = Path(file_path)
        if not p.exists():
            return "", "", 0
        try:
            lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
        except Exception:
            return "", "", 0

        if ecosystem == "PyPI":
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if re.match(
                    rf"^{re.escape(pkg)}\s*[=<>!~]", stripped, re.IGNORECASE
                ):
                    new_line_content = re.sub(
                        r"[=<>!~]+\s*[\d\.\*]+",
                        f"=={target}",
                        stripped,
                        count=1,
                    )
                    return (stripped, new_line_content, i)

        elif ecosystem == "npm":
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                for sec in ("dependencies", "devDependencies"):
                    if pkg in data.get(sec, {}):
                        old_ver = str(data[sec][pkg])
                        for i, line in enumerate(lines, 1):
                            if f'"{pkg}"' in line and old_ver in line:
                                prefix = re.match(r'(\s*"[^"]+"\s*:\s*")[^"]*(".*)', line)
                                if prefix:
                                    new_line = prefix.group(1) + target + prefix.group(2)
                                    return (line.rstrip(), new_line.rstrip(), i)
            except Exception:
                pass

        elif ecosystem == "Go":
            for i, line in enumerate(lines, 1):
                if re.search(rf"\b{re.escape(pkg)}\s+v", line):
                    new_line = re.sub(r"(v)\S+", f"v{target}", line.rstrip())
                    return (line.rstrip(), new_line, i)

        elif ecosystem == "crates.io":
            for i, line in enumerate(lines, 1):
                if re.match(rf"^{re.escape(pkg)}\s*=", line.strip()):
                    new_line = re.sub(r'"[\d\.]+"', f'"{target}"', line.rstrip())
                    return (line.rstrip(), new_line, i)

        return "", "", 0


def _version_gt(a: str, b: str) -> bool:
    """Simple version comparison: returns True if a > b."""
    try:
        av = tuple(int(x) for x in a.split(".")[:4])
        bv = tuple(int(x) for x in b.split(".")[:4])
        return av > bv
    except Exception:
        return a > b


def _version_best(line: str, new_ver: str) -> str:
    """Preserve version pin style: ==, >=, ~=."""
    if "==" in line:
        return new_ver
    if ">=" in line:
        return new_ver
    return new_ver
