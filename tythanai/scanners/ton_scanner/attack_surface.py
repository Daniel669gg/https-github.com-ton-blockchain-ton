"""
TythanAI Platform — TON Attack Surface Mapper
Produces a complete attack surface summary for a TON smart contract project.

Detects:
  • Entry points: recv_internal, recv_external, get methods
  • Upgradeability (set_code / set_c5)
  • Total op-codes dispatched
  • Unguarded ops (op handlers without throw_unless)
  • Admin operations
  • External message sends (send_raw_message)
  • Composite risk score (0-100)
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ── Patterns ────────────────────────────────────────────────────────────────────

_RECV_INTERNAL_RE  = re.compile(r"\brecv_internal\s*\(")
_RECV_EXTERNAL_RE  = re.compile(r"\brecv_external\s*\(")
# FunC get methods: `int get_balance() method_id { ... }`
_GET_METHOD_RE     = re.compile(
    r"^\s*[\w\s\*]+\b(\w+)\s*\([^)]*\)\s+method_id\b", re.MULTILINE
)
# Tact get function: `get fun something(`
_TACT_GET_RE       = re.compile(r"\bget\s+fun\s+(\w+)\s*\(")

_OP_DISPATCH_RE    = re.compile(r"\bop\s*==\s*(0x[0-9a-fA-F]+|\d+)")
_GUARD_RE          = re.compile(r"\b(throw_unless|throw_if)\s*\(")
_ACCEPT_RE         = re.compile(r"\baccept_message\s*\(\s*\)")
_SET_CODE_RE       = re.compile(r"\b(set_code|set_c5)\s*\(")
_SEND_MSG_RE       = re.compile(r"\bsend_raw_message\s*\(")
_COINS_RE          = re.compile(r"\bmsg_value\b|\bload_coins\s*\(")
_COMMENT_RE        = re.compile(r";;.*$")

# Admin op patterns
_ADMIN_OP_RE       = re.compile(
    r"op\s*==\s*(?:op::)?(?:admin|upgrade|set_code|set_owner|change_owner|transfer_ownership)",
    re.IGNORECASE,
)

_SUPPORTED_EXTENSIONS = {".fc", ".func", ".tact", ".fif", ".fift"}


# ── Data classes ────────────────────────────────────────────────────────────────

@dataclass
class EntryPoint:
    """Represents a callable entry point of a TON smart contract."""
    type:             str    # "recv_internal" | "recv_external" | "get_method"
    name:             str
    line:             int
    accepts_coins:    bool   # True if msg_value / load_coins used nearby
    has_op_dispatch:  bool   # True if op == 0x... dispatch found in body
    guarded:          bool   # True if throw_unless/throw_if found in body

    def to_dict(self) -> Dict:
        return {
            "type":            self.type,
            "name":            self.name,
            "line":            self.line,
            "accepts_coins":   self.accepts_coins,
            "has_op_dispatch": self.has_op_dispatch,
            "guarded":         self.guarded,
        }


@dataclass
class AttackSurface:
    """Complete attack surface summary for a single contract file."""
    file_path:      str
    entry_points:   List[EntryPoint] = field(default_factory=list)
    upgradeable:    bool = False
    total_ops:      int  = 0     # distinct op-codes handled
    unguarded_ops:  int  = 0     # ops without throw_unless guard nearby
    has_admin_ops:  bool = False
    external_calls: int  = 0     # number of send_raw_message
    risk_score:     int  = 0     # 0-100
    risk_level:     str  = "LOW" # LOW / MEDIUM / HIGH / CRITICAL

    def to_dict(self) -> Dict:
        return {
            "file_path":      self.file_path,
            "entry_points":   [ep.to_dict() for ep in self.entry_points],
            "upgradeable":    self.upgradeable,
            "total_ops":      self.total_ops,
            "unguarded_ops":  self.unguarded_ops,
            "has_admin_ops":  self.has_admin_ops,
            "external_calls": self.external_calls,
            "risk_score":     self.risk_score,
            "risk_level":     self.risk_level,
        }


# ── Mapper ──────────────────────────────────────────────────────────────────────

class AttackSurfaceMapper:
    """
    Maps the attack surface of one or more TON smart contract files.

    Public API
    ----------
    map_file(file_path)       → AttackSurface
    map_directory(directory)  → Dict
    to_findings(surface)      → List[Dict]
    """

    def map_file(self, file_path: str) -> AttackSurface:
        """Analyse a single contract file and return its AttackSurface."""
        path = Path(file_path)
        surface = AttackSurface(file_path=file_path)

        if not path.exists():
            return surface

        try:
            code = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return surface

        lines = code.splitlines()

        # Entry points
        surface.entry_points = self._find_entry_points(code, lines)

        # Upgradeability
        surface.upgradeable = bool(_SET_CODE_RE.search(code))

        # Op-codes
        ops_all = _OP_DISPATCH_RE.findall(code)
        surface.total_ops = len(set(ops_all))

        # Unguarded ops — count op dispatches not preceded by guard in 10 lines
        surface.unguarded_ops = self._count_unguarded_ops(lines)

        # Admin ops
        surface.has_admin_ops = bool(_ADMIN_OP_RE.search(code))

        # External calls
        surface.external_calls = len(_SEND_MSG_RE.findall(code))

        # Risk score
        surface.risk_score = self._compute_risk_score(surface)
        surface.risk_level = self._risk_level(surface.risk_score)

        return surface

    def map_directory(self, directory: str) -> Dict:
        """
        Analyse all TON contract files in a directory tree.
        Returns a summary dict with per-file surfaces, aggregate score, and
        the highest-risk file path.
        """
        surfaces: List[AttackSurface] = []
        root = Path(directory)

        for fpath in root.rglob("*"):
            if fpath.suffix.lower() in _SUPPORTED_EXTENSIONS:
                surfaces.append(self.map_file(str(fpath)))

        if not surfaces:
            return {
                "surfaces":          [],
                "total_risk_score":  0,
                "highest_risk_file": "",
            }

        total_score    = sum(s.risk_score for s in surfaces)
        highest        = max(surfaces, key=lambda s: s.risk_score)

        return {
            "surfaces":          [s.to_dict() for s in surfaces],
            "total_risk_score":  total_score,
            "highest_risk_file": highest.file_path,
        }

    def _compute_risk_score(self, surface: AttackSurface) -> int:
        """
        Compute a 0-100 risk score from surface characteristics.

        Scoring rationale:
          +30  if upgradeable (set_code present)
          +20  per recv_external entry point (no auth by default)
          +10  per recv_internal entry point
          +5   per get_method (information disclosure surface)
          +15  if has admin operations
          +10  if unguarded_ops > 0 (each unguarded op +2, capped at 20)
          +5   per external call (each send_raw_message, capped at 20)
          –10  for each guarded entry point (reward)
        """
        score = 0

        if surface.upgradeable:
            score += 30

        if surface.has_admin_ops:
            score += 15

        for ep in surface.entry_points:
            if ep.type == "recv_external":
                score += 20
            elif ep.type == "recv_internal":
                score += 10
            elif ep.type == "get_method":
                score += 5
            # Reward guarded entry points
            if ep.guarded:
                score -= 10

        # Unguarded ops penalty (capped)
        score += min(surface.unguarded_ops * 2, 20)

        # External calls (capped)
        score += min(surface.external_calls * 5, 20)

        return max(0, min(score, 100))

    def to_findings(self, surface: AttackSurface) -> List[Dict]:
        """
        Convert high-risk surface elements to finding dicts suitable for SARIF
        output or the TythanAI finding pipeline.
        """
        findings: List[Dict] = []

        # Upgradeable contract
        if surface.upgradeable:
            findings.append({
                "type":           "TON_ATTACK_SURFACE",
                "id":             "AS-001",
                "rule_id":        "AS-001",
                "severity":       "HIGH",
                "line":           1,
                "file":           surface.file_path,
                "description":    "Contract is upgradeable (set_code/set_c5 detected) — "
                                  "verify strict ownership guard protects upgrade path",
                "evidence":       "set_code() or set_c5() present",
                "recommendation": "Ensure set_code is only callable by deployer/owner with "
                                  "throw_unless; consider time-lock or multisig",
                "category":       "Upgrade Safety",
                "source":         "attack_surface_mapper",
            })

        # recv_external without guard
        for ep in surface.entry_points:
            if ep.type == "recv_external" and not ep.guarded:
                findings.append({
                    "type":           "TON_ATTACK_SURFACE",
                    "id":             "AS-002",
                    "rule_id":        "AS-002",
                    "severity":       "CRITICAL",
                    "line":           ep.line,
                    "file":           surface.file_path,
                    "description":    "recv_external entry point without guard — "
                                      "any external actor can invoke this handler",
                    "evidence":       f"recv_external at line {ep.line}",
                    "recommendation": "Add throw_unless(error::invalid_sig, "
                                      "check_signature(hash, sig, pubkey)) as first statement",
                    "category":       "Authentication",
                    "source":         "attack_surface_mapper",
                })

        # Unguarded recv_internal
        for ep in surface.entry_points:
            if ep.type == "recv_internal" and not ep.guarded and ep.has_op_dispatch:
                findings.append({
                    "type":           "TON_ATTACK_SURFACE",
                    "id":             "AS-003",
                    "rule_id":        "AS-003",
                    "severity":       "HIGH",
                    "line":           ep.line,
                    "file":           surface.file_path,
                    "description":    "recv_internal dispatches op-codes without a "
                                      "throw_unless sender-validation guard",
                    "evidence":       f"recv_internal (op dispatch) at line {ep.line}",
                    "recommendation": "Add throw_unless(error::unauthorized, "
                                      "equal_slices(sender, owner)) before op dispatch",
                    "category":       "Access Control",
                    "source":         "attack_surface_mapper",
                })

        # Admin ops detected
        if surface.has_admin_ops:
            findings.append({
                "type":           "TON_ATTACK_SURFACE",
                "id":             "AS-004",
                "rule_id":        "AS-004",
                "severity":       "HIGH",
                "line":           1,
                "file":           surface.file_path,
                "description":    "Admin/privileged op-codes present — verify these are "
                                  "protected by strict ownership checks",
                "evidence":       "admin/upgrade op-code handler detected",
                "recommendation": "Restrict all admin ops to a single deployer/owner address; "
                                  "add throw_unless guard at the very start of handler",
                "category":       "Access Control",
                "source":         "attack_surface_mapper",
            })

        # High unguarded op count
        if surface.unguarded_ops >= 3:
            findings.append({
                "type":           "TON_ATTACK_SURFACE",
                "id":             "AS-005",
                "rule_id":        "AS-005",
                "severity":       "MEDIUM",
                "line":           1,
                "file":           surface.file_path,
                "description":    f"{surface.unguarded_ops} op-code handlers lack a "
                                  "throw_unless guard — state mutation possible by any caller",
                "evidence":       f"{surface.unguarded_ops} unguarded ops",
                "recommendation": "Add per-op access control checks before any state mutation",
                "category":       "Access Control",
                "source":         "attack_surface_mapper",
            })

        return findings

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _find_entry_points(self, code: str, lines: List[str]) -> List[EntryPoint]:
        entry_points: List[EntryPoint] = []

        # --- recv_internal ---
        for m in _RECV_INTERNAL_RE.finditer(code):
            ep = self._build_entry_point(
                code=code,
                lines=lines,
                match_start=m.start(),
                ep_type="recv_internal",
                name="recv_internal",
            )
            entry_points.append(ep)

        # --- recv_external ---
        for m in _RECV_EXTERNAL_RE.finditer(code):
            ep = self._build_entry_point(
                code=code,
                lines=lines,
                match_start=m.start(),
                ep_type="recv_external",
                name="recv_external",
            )
            entry_points.append(ep)

        # --- FunC get methods ---
        for m in _GET_METHOD_RE.finditer(code):
            lineno = code[:m.start()].count("\n") + 1
            name   = m.group(1)
            ep = self._build_entry_point(
                code=code,
                lines=lines,
                match_start=m.start(),
                ep_type="get_method",
                name=name,
            )
            entry_points.append(ep)

        # --- Tact get fun ---
        for m in _TACT_GET_RE.finditer(code):
            ep = self._build_entry_point(
                code=code,
                lines=lines,
                match_start=m.start(),
                ep_type="get_method",
                name=m.group(1),
            )
            entry_points.append(ep)

        return entry_points

    def _build_entry_point(
        self,
        code: str,
        lines: List[str],
        match_start: int,
        ep_type: str,
        name: str,
    ) -> EntryPoint:
        """Extract an EntryPoint by analysing the function body."""
        lineno = code[:match_start].count("\n") + 1

        # Find the opening brace
        brace_pos = code.find("{", match_start)
        if brace_pos == -1:
            # No body — minimal entry point
            return EntryPoint(
                type=ep_type, name=name, line=lineno,
                accepts_coins=False, has_op_dispatch=False, guarded=False,
            )

        # Walk to matching closing brace
        depth, idx = 1, brace_pos + 1
        while idx < len(code) and depth > 0:
            if code[idx] == "{":
                depth += 1
            elif code[idx] == "}":
                depth -= 1
            idx += 1
        body = code[brace_pos + 1: idx - 1]

        accepts_coins   = bool(_COINS_RE.search(body))
        has_op_dispatch = bool(_OP_DISPATCH_RE.search(body))
        guarded         = bool(_GUARD_RE.search(body))

        return EntryPoint(
            type=ep_type,
            name=name,
            line=lineno,
            accepts_coins=accepts_coins,
            has_op_dispatch=has_op_dispatch,
            guarded=guarded,
        )

    def _count_unguarded_ops(self, lines: List[str]) -> int:
        """
        Count op-dispatch lines (op == 0x...) that have no throw_unless/throw_if
        within the preceding 20 lines.
        """
        guard_lines: set = set()
        for i, raw in enumerate(lines, start=1):
            stripped = _COMMENT_RE.sub("", raw)
            if _GUARD_RE.search(stripped):
                guard_lines.add(i)

        LOOKBACK = 20
        count = 0
        for i, raw in enumerate(lines, start=1):
            stripped = _COMMENT_RE.sub("", raw)
            if _OP_DISPATCH_RE.search(stripped):
                window_start = max(1, i - LOOKBACK)
                if not any(g in guard_lines for g in range(window_start, i)):
                    count += 1
        return count

    @staticmethod
    def _risk_level(score: int) -> str:
        if score >= 70:
            return "CRITICAL"
        if score >= 45:
            return "HIGH"
        if score >= 20:
            return "MEDIUM"
        return "LOW"
