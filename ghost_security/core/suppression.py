"""
Ghost Security — Finding Suppression (.ghostignore)

Equivalent to Snyk's .snyk policy file. Allows developers to:
  • Suppress false positives with justification
  • Ignore known CVEs that don't apply to their context
  • Set expiry dates on suppressions (auto-expire)
  • Suppress by rule ID, CVE, file pattern, or severity

.ghostignore format (YAML):
-----------------------------
version: 1
suppressions:
  - id: CVE-2021-44228            # CVE or rule ID to suppress
    reason: "Not reachable — log4j not used in request path"
    expires: 2025-12-31           # optional, ISO date
    files:                        # optional file patterns
      - "tests/*"
      - "*.test.py"

  - id: HARDCODED_SECRET
    reason: "Test fixture, not production"
    files: ["tests/fixtures/*"]

  - id: CPP-070                   # Ghost rule ID
    reason: "rand() used only for non-crypto shuffle"
    expires: 2026-06-01

  - severity: LOW                 # suppress entire severity level
    reason: "Only HIGH+ in CI"

Usage:
    from core.suppression import SuppressionManager
    mgr      = SuppressionManager("/path/to/project")
    filtered = mgr.apply(findings)   # removes suppressed, adds suppression_reason to suppressed
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import yaml as _yaml
    _YAML_OK = True
except ImportError:
    _YAML_OK = False

_IGNORE_FILENAMES = (".ghostignore", ".ghost", "ghost.yml", "ghost.yaml")


@dataclass
class Suppression:
    raw_id:   Optional[str]       = None   # CVE-xxxx or rule ID
    severity: Optional[str]       = None   # suppress entire severity
    reason:   str                 = ""
    expires:  Optional[date]      = None
    files:    List[str]           = field(default_factory=list)

    def is_expired(self) -> bool:
        if self.expires is None:
            return False
        return date.today() > self.expires

    def matches_finding(self, finding: Dict) -> bool:
        if self.is_expired():
            return False

        # Severity-level suppression
        if self.severity:
            if finding.get("severity", "").upper() != self.severity.upper():
                return False
            return self._file_matches(finding.get("file", ""))

        # ID matching (CVE, rule ID, type)
        if self.raw_id:
            finding_ids = {
                str(finding.get("id",   "") or "").upper(),
                str(finding.get("cve",  "") or "").upper(),
                str(finding.get("type", "") or "").upper(),
                str(finding.get("rule_id", "") or "").upper(),
            }
            if self.raw_id.upper() not in finding_ids:
                return False
            return self._file_matches(finding.get("file", ""))

        return False

    def _file_matches(self, file_path: str) -> bool:
        if not self.files:
            return True
        name = Path(file_path).name
        for pattern in self.files:
            if fnmatch.fnmatch(file_path, pattern) or fnmatch.fnmatch(name, pattern):
                return True
        return False


def _parse_date(val) -> Optional[date]:
    if val is None:
        return None
    try:
        if isinstance(val, date):
            return val
        parts = str(val).split("-")
        return date(int(parts[0]), int(parts[1]), int(parts[2]))
    except Exception:
        return None


def _load_yaml_suppressions(path: Path) -> List[Suppression]:
    if not _YAML_OK:
        return _load_simple(path)
    try:
        data = _yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    result: List[Suppression] = []
    for entry in data.get("suppressions", []):
        if not isinstance(entry, dict):
            continue
        result.append(Suppression(
            raw_id   = str(entry["id"]) if "id" in entry else None,
            severity = str(entry.get("severity", "") or "").upper() or None,
            reason   = str(entry.get("reason", "suppressed")),
            expires  = _parse_date(entry.get("expires")),
            files    = [str(f) for f in entry.get("files", [])],
        ))
    return result


def _load_simple(path: Path) -> List[Suppression]:
    """
    Minimal parser when PyYAML not available.
    Supports lines like:
        CVE-2021-44228 # reason text
        HARDCODED_SECRET tests/* # reason
    """
    result: List[Suppression] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("#", 1)
        tokens = parts[0].strip().split()
        if not tokens:
            continue
        raw_id = tokens[0]
        files  = tokens[1:] if len(tokens) > 1 else []
        reason = parts[1].strip() if len(parts) > 1 else "suppressed"
        result.append(Suppression(raw_id=raw_id, reason=reason, files=files))
    return result


class SuppressionManager:
    """
    Loads .ghostignore from a project root and filters findings.
    """

    def __init__(self, project_root: str = ".") -> None:
        self.root          = Path(project_root)
        self._suppressions = self._load()

    # ── Public API ─────────────────────────────────────────────────────────────

    def apply(
        self, findings: List[Dict]
    ) -> Tuple[List[Dict], List[Dict]]:
        """
        Split findings into (active, suppressed).
        Suppressed findings get a 'suppressed_reason' field added.
        """
        active: List[Dict]     = []
        suppressed: List[Dict] = []

        for f in findings:
            match = self._find_match(f)
            if match:
                f = dict(f)
                f["suppressed"]        = True
                f["suppression_reason"] = match.reason
                f["suppression_expires"] = str(match.expires) if match.expires else None
                suppressed.append(f)
            else:
                active.append(f)

        return active, suppressed

    def filter(self, findings: List[Dict]) -> List[Dict]:
        """Return only non-suppressed findings."""
        active, _ = self.apply(findings)
        return active

    @property
    def suppressions(self) -> List[Suppression]:
        return self._suppressions

    @property
    def suppression_count(self) -> int:
        return len(self._suppressions)

    def add_suppression(
        self,
        rule_id: str,
        reason: str,
        files: Optional[List[str]] = None,
        expires: Optional[str] = None,
    ) -> None:
        """
        Add a suppression and write it back to .ghostignore.
        Creates the file if it doesn't exist.
        """
        sup = Suppression(
            raw_id  = rule_id,
            reason  = reason,
            files   = files or [],
            expires = _parse_date(expires),
        )
        self._suppressions.append(sup)
        self._save()

    def status(self) -> Dict:
        expired = [s for s in self._suppressions if s.is_expired()]
        return {
            "total_suppressions":   len(self._suppressions),
            "active_suppressions":  len(self._suppressions) - len(expired),
            "expired_suppressions": len(expired),
            "file":                 str(self._ignore_path() or "(none)"),
        }

    # ── Internal ───────────────────────────────────────────────────────────────

    def _load(self) -> List[Suppression]:
        p = self._ignore_path()
        if p is None:
            return []
        if p.suffix in (".yml", ".yaml") or p.name in ("ghost.yml", "ghost.yaml"):
            return _load_yaml_suppressions(p)
        if _YAML_OK:
            return _load_yaml_suppressions(p)
        return _load_simple(p)

    def _ignore_path(self) -> Optional[Path]:
        for name in _IGNORE_FILENAMES:
            p = self.root / name
            if p.exists():
                return p
        return None

    def _find_match(self, finding: Dict) -> Optional[Suppression]:
        for sup in self._suppressions:
            if sup.matches_finding(finding):
                return sup
        return None

    def _save(self) -> None:
        p = self._ignore_path() or (self.root / ".ghostignore")
        lines = ["version: 1\nsuppressions:\n"]
        for sup in self._suppressions:
            lines.append(f"  - id: {sup.raw_id or sup.severity}\n")
            lines.append(f"    reason: \"{sup.reason}\"\n")
            if sup.expires:
                lines.append(f"    expires: {sup.expires}\n")
            if sup.files:
                lines.append("    files:\n")
                for f in sup.files:
                    lines.append(f"      - \"{f}\"\n")
        p.write_text("".join(lines), encoding="utf-8")

    @staticmethod
    def create_example(project_root: str = ".") -> str:
        """Write an example .ghostignore to project root."""
        example = """version: 1

# Ghost Security — Finding Suppression File
# Docs: https://ghost-security.dev/docs/ghostignore

suppressions:
  # Suppress a specific CVE that doesn't apply to your context
  - id: CVE-2024-35195
    reason: "requests library used only for internal mTLS endpoints, redirect headers stripped"
    expires: 2026-01-01

  # Suppress a Ghost rule in test files
  - id: HARDCODED_SECRET
    reason: "Test fixtures only, not production credentials"
    files:
      - "tests/*"
      - "*.test.py"
      - "conftest.py"

  # Suppress a C/C++ rule globally
  - id: CPP-070
    reason: "rand() used only for non-cryptographic shuffle in UI animations"

  # Suppress all LOW severity findings in CI
  # - severity: LOW
  #   reason: "Only HIGH+ enforced in CI pipeline"
"""
        path = Path(project_root) / ".ghostignore"
        path.write_text(example, encoding="utf-8")
        return str(path)
