"""
TythanAI — Per-Rule Confidence Tuner
==========================================
Allows users to tune false-positive rates by adjusting per-rule confidence
weights without modifying scanner source code.

Configuration is loaded from YAML files (first match wins):
  1. ~/.ghost/rule_tuning.yaml
  2. .ghost/rule_tuning.yaml  (project-local)
  3. ghost_rule_tuning.yaml   (cwd)

YAML format::

    rules:
      JAVA-001:
        confidence_delta: -20
        note: "Too many FPs in unit test directories"
      JAVA-003:
        enabled: false
        note: "Jackson configured globally with safe defaults"
      TON-MF001:
        confidence_delta: +15
        note: "Always real when fired in our codebase"

Usage::

    from core.analysis.rule_tuner import RuleTuner

    tuner = RuleTuner()
    tuner.load()
    enriched_findings = tuner.apply(raw_findings)
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class RuleTuning:
    """Configuration for one rule's confidence adjustment."""

    rule_id: str
    """Rule identifier, e.g. ``JAVA-001`` or ``TON-MF001``."""

    confidence_delta: int = 0
    """Signed integer in [-50, +50] added to the finding's base confidence."""

    enabled: bool = True
    """When *False* every finding for this rule is suppressed."""

    note: str = ""
    """Human-readable reason for the tuning decision."""

    def __post_init__(self) -> None:
        # Clamp delta to the permitted range
        self.confidence_delta = max(-50, min(50, int(self.confidence_delta)))


# ---------------------------------------------------------------------------
# Default search paths (in priority order)
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_PATHS: List[str] = [
    str(Path.home() / ".ghost" / "rule_tuning.yaml"),
    ".ghost/rule_tuning.yaml",
    "ghost_rule_tuning.yaml",
]

# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class RuleTuner:
    """
    Load per-rule confidence tuning from YAML and apply it to a list of
    TythanAI findings dicts.
    """

    def __init__(self, config_paths: Optional[List[str]] = None) -> None:
        """
        Parameters
        ----------
        config_paths:
            Explicit list of paths to search for YAML config.  When *None*
            the default search order is used.
        """
        self._search_paths: List[str] = (
            config_paths if config_paths is not None else list(_DEFAULT_CONFIG_PATHS)
        )
        self._tunings: Dict[str, RuleTuning] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self) -> int:
        """
        Load tuning configuration from the first YAML file found among the
        configured search paths.

        Returns
        -------
        int
            Number of rule tunings loaded (0 when no config file is found).
        """
        try:
            import yaml  # type: ignore[import]
        except ImportError:
            # PyYAML not available — graceful no-op
            return 0

        for path_str in self._search_paths:
            path = Path(path_str)
            if not path.exists():
                continue
            try:
                with path.open("r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh) or {}
            except Exception:
                continue
            self._load_from_data(data)
            return len(self._tunings)

        return 0

    def apply(self, findings: List[Dict]) -> List[Dict]:
        """
        Apply loaded tuning rules to a list of finding dicts.

        Each finding dict is copied (not mutated in-place) and may receive
        the following modifications:

        * ``confidence`` — clamped to ``[0, 100]`` after the delta is applied.
        * ``suppressed`` — set to ``True`` when the matching rule is disabled.
        * ``tuning_note`` — populated with the reason when a tuning was applied.

        Parameters
        ----------
        findings:
            Raw findings as returned by any TythanAI scanner.

        Returns
        -------
        List[Dict]
            Updated copies of the findings list.
        """
        result: List[Dict] = []
        for finding in findings:
            rule_id = self._extract_rule_id(finding)
            tuning = self._tunings.get(rule_id) if rule_id else None

            if tuning is None:
                result.append(dict(finding))
                continue

            updated = dict(finding)

            if not tuning.enabled:
                updated["suppressed"] = True
                if tuning.note:
                    updated["tuning_note"] = tuning.note
            else:
                if tuning.confidence_delta != 0:
                    base = int(updated.get("confidence", 70))
                    updated["confidence"] = max(0, min(100, base + tuning.confidence_delta))
                    if tuning.note:
                        updated["tuning_note"] = tuning.note

            result.append(updated)

        return result

    def get_tuning(self, rule_id: str) -> Optional[RuleTuning]:
        """Return the :class:`RuleTuning` for *rule_id*, or ``None``."""
        return self._tunings.get(rule_id)

    def create_example_config(self, output_path: str) -> str:
        """
        Write an annotated example YAML configuration to *output_path*.

        Returns
        -------
        str
            The resolved absolute path that was written.
        """
        content = _EXAMPLE_CONFIG
        dest = Path(output_path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        return str(dest.resolve())

    # ------------------------------------------------------------------
    # Class methods
    # ------------------------------------------------------------------

    @classmethod
    def from_dict(cls, data: dict) -> "RuleTuner":
        """
        Build a :class:`RuleTuner` directly from a Python dict without
        touching the file system.  Useful in tests.

        Parameters
        ----------
        data:
            Dict in the same shape as the YAML file, e.g.::

                {"rules": {"JAVA-001": {"confidence_delta": -20}}}

        Returns
        -------
        RuleTuner
        """
        tuner = cls(config_paths=[])
        tuner._load_from_data(data)
        return tuner

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_from_data(self, data: dict) -> None:
        """Populate ``self._tunings`` from a parsed YAML dict."""
        rules_section = data.get("rules", {}) or {}
        for rule_id, rule_data in rules_section.items():
            rule_id = str(rule_id)
            if isinstance(rule_data, dict):
                self._tunings[rule_id] = RuleTuning(
                    rule_id=rule_id,
                    confidence_delta=int(rule_data.get("confidence_delta", 0)),
                    enabled=bool(rule_data.get("enabled", True)),
                    note=str(rule_data.get("note", "")),
                )
            else:
                # Minimal form: just a boolean (enabled/disabled)
                self._tunings[rule_id] = RuleTuning(
                    rule_id=rule_id,
                    enabled=bool(rule_data),
                )

    @staticmethod
    def _extract_rule_id(finding: Dict) -> Optional[str]:
        """
        Extract a normalised rule ID from a finding dict.

        Checks ``id``, ``rule_id``, and ``rule`` keys in that order.
        """
        for key in ("id", "rule_id", "rule"):
            val = finding.get(key)
            if val and isinstance(val, str):
                return val.strip()
        return None


# ---------------------------------------------------------------------------
# Example configuration template
# ---------------------------------------------------------------------------

_EXAMPLE_CONFIG = """\
# TythanAI — Rule Tuning Configuration
# ===========================================
# This file lets you adjust per-rule confidence weights and enable/disable
# individual rules without modifying scanner source code.
#
# Place this file at one of:
#   ~/.ghost/rule_tuning.yaml          (user-global)
#   .ghost/rule_tuning.yaml            (project-local, recommended)
#   ghost_rule_tuning.yaml             (cwd fallback)
#
# Fields per rule:
#   confidence_delta  Signed integer, range -50 to +50.
#                     Added to the scanner's base confidence score.
#                     Negative values reduce confidence (more likely FP).
#                     Positive values increase confidence (more likely TP).
#   enabled           Boolean. Set to false to suppress all findings for
#                     this rule entirely (adds suppressed: true to findings).
#   note              Free-text reason for the tuning decision.
#                     Shown in the finding's tuning_note field.

rules:
  # ── Java scanner rules ────────────────────────────────────────────────────

  JAVA-001:
    confidence_delta: -20
    note: "Fires frequently on test utilities that build SQL for fixtures"

  JAVA-003:
    enabled: false
    note: >
      ObjectInputStream usage is intentional — we use a validating subclass
      globally via a custom ClassLoader allowlist.

  JAVA-006:
    confidence_delta: -15
    note: "Many matches are example config constants, not production secrets"

  # ── TON blockchain scanner rules ──────────────────────────────────────────

  TON-MF001:
    confidence_delta: +15
    note: "Upgrade path without ownership check is always a real finding here"

  TON-MF003:
    confidence_delta: +10
    note: "Unguarded state writes confirmed exploitable in our contract design"

  # ── Taint tracker rules ───────────────────────────────────────────────────

  TAINT-SQL:
    confidence_delta: -10
    note: >
      Django ORM wraps all raw calls; residual matches are in migration helpers
      that are never exposed to user input.
"""
