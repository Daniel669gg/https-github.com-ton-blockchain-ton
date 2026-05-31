"""Security rules registry for TythanAI SAST scanner."""
from typing import Dict, List

from backend.scanners.rules.python_rules import PYTHON_RULES
from backend.scanners.rules.javascript_rules import JS_RULES

ALL_RULES: List[Dict] = PYTHON_RULES + JS_RULES


def get_rules_by_language(language: str) -> List[Dict]:
    return [r for r in ALL_RULES if r.get("language") == language]


def get_rules_by_severity(severity: str) -> List[Dict]:
    return [r for r in ALL_RULES if r.get("severity") == severity]


def get_rules_by_category(category: str) -> List[Dict]:
    return [r for r in ALL_RULES if r.get("category") == category]
