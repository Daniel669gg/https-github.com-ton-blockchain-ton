"""Package Reputation Engine — offline heuristic-based package trust scoring."""

from __future__ import annotations

import re
import string
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Constants — embedded static knowledge
# ---------------------------------------------------------------------------

# Popular packages that are common typosquat targets (lowercase)
_POPULAR_PACKAGES: Dict[str, Set[str]] = {
    "requests":    {"request", "requestss", "requets", "reqquests", "rquests"},
    "numpy":       {"nunpy", "nump", "numphy", "nnumpy", "nmupy"},
    "pandas":      {"panda", "pandass", "panads", "pandaas"},
    "flask":       {"falsk", "flaask", "flaskk", "flak"},
    "django":      {"djnago", "djangoo", "djago", "diango"},
    "boto3":       {"botto3", "bot03", "botto", "boto"},
    "pillow":      {"pillo", "pilow", "pillllow", "pill0w"},
    "pyyaml":      {"pyyam1", "pyyamil", "pyyam", "pyaml"},
    "cryptography": {"cryptographyy", "criptography", "cryptograpy"},
    "paramiko":    {"paramikoo", "paramikio", "parmiko"},
    "setuptools":  {"setuptoolss", "setutools", "setupool"},
    "six":         {"sixx", "si6", "siix"},
    "urllib3":     {"urllb3", "urllib", "urllib33"},
    "certifi":     {"certiffi", "certfy", "cerrtifi"},
    "pip":         {"pipp", "piip", "pi-p"},
    "wheel":       {"wheell", "whheel"},
    "pytest":      {"py-test", "pytets", "pyteest"},
    "lodash":      {"loadash", "loodash", "lodaash", "lodsh"},
    "express":     {"expresss", "expres", "expresss"},
    "react":       {"reakt", "reect", "recat"},
    "axios":       {"axois", "axios-", "axio"},
    "moment":      {"moement", "momnet"},
    "webpack":     {"webpackk", "webpak"},
    "babel":       {"baabel", "babeel"},
    "eslint":      {"eslnit", "esllint"},
    "typescript":  {"typescritp", "typscript"},
    "colors":      {"c0lors", "coloors", "coulors"},
    "ua-parser-js": {"ua-pars3r-js", "ua_parser_js"},
}

# Known malicious package names (historically flagged)
_KNOWN_MALICIOUS: Set[str] = {
    "ctx",                 # 2022 malicious PyPI package
    "noblox.js-proxied",   # npm malicious
    "twilio-npm",          # npm typosquat
    "discord-selfbot-v14", # malicious
    "xreact",              # React typosquat
    "react-native-fast-image-viewer",
    "colourama",           # PyPI typosquat for colorama
    "crypt0",              # crypto typosquat
    "loguru-colorama",
    "jeIlyfish",           # jellyfish typosquat (capital I)
    "python-sqlite",       # sqlite typosquat
    "httplib3",            # urllib3 typosquat
    "python3-dateutil",    # dateutil typosquat
    "cachetools-",
    "pycrypto2",           # pycrypto typosquat
    "beautifulsoup",       # bs4 typosquat
    "bs4-",
    "py-requests",
    "urllib",              # urllib2/urllib3 confusion
    "setup-tools",         # setuptools typosquat
    "pip-install",
    "pip3",
    "python-mysql",
    "django-utils-six",
    "sqlalchemy-",
    "aiohttp-",
    "colorama-",
    "pytest-utils",
}

# Suspicious name patterns (regex)
_SUSPICIOUS_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\d{4,}"),        "contains long numeric sequence"),
    (re.compile(r"-[a-z]{1,2}$"),  "ends with short suffix (typosquat indicator)"),
    (re.compile(r"^[a-z]-[a-z]"),  "starts with single-letter prefix"),
    (re.compile(r"[_-]{2,}"),      "multiple consecutive separators"),
    (re.compile(r"[0-9][oOlI]"),   "digit-to-letter substitution"),
    (re.compile(r"[oOlI][0-9]"),   "letter-to-digit substitution"),
    (re.compile(r"(.)\1{3,}"),     "repeated character sequence"),
]

# Internal/private package name patterns (dependency confusion risk)
_INTERNAL_PATTERNS: List[re.Pattern] = [
    re.compile(r"^(internal|private|corp|company|myapp|myorg|local)-"),
    re.compile(r"-(internal|private|corp|dev|test|staging)$"),
    re.compile(r"^[a-z]{2,4}\.[a-z]"),  # namespace like co.acme.lib
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ReputationFlags:
    is_typosquat: bool = False
    is_known_malicious: bool = False
    has_suspicious_name: bool = False
    has_dependency_confusion_risk: bool = False
    has_digit_substitution: bool = False
    is_short_name: bool = False    # single-char or two-char names
    reasons: List[str] = field(default_factory=list)


@dataclass
class PackageReputation:
    package_name: str
    ecosystem: str
    reputation_score: float         # 0.0-100.0 (100 = fully trusted)
    risk_level: str                  # CRITICAL/HIGH/MEDIUM/LOW/SAFE
    flags: ReputationFlags = field(default_factory=ReputationFlags)
    typosquat_target: Optional[str] = None
    similar_packages: List[str] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "ecosystem": self.ecosystem,
            "reputation_score": self.reputation_score,
            "risk_level": self.risk_level,
            "is_typosquat": self.flags.is_typosquat,
            "is_known_malicious": self.flags.is_known_malicious,
            "has_suspicious_name": self.flags.has_suspicious_name,
            "has_dependency_confusion_risk": self.flags.has_dependency_confusion_risk,
            "typosquat_target": self.typosquat_target,
            "similar_packages": self.similar_packages,
            "explanation": self.explanation,
            "flag_reasons": self.flags.reasons,
        }


# ---------------------------------------------------------------------------
# Edit distance helpers
# ---------------------------------------------------------------------------


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    rows = len(a) + 1
    cols = len(b) + 1
    dist = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        dist[i][0] = i
    for j in range(cols):
        dist[0][j] = j

    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dist[i][j] = min(
                dist[i - 1][j] + 1,
                dist[i][j - 1] + 1,
                dist[i - 1][j - 1] + cost,
            )
    return dist[rows - 1][cols - 1]


def _normalised_distance(a: str, b: str) -> float:
    """Return edit distance normalised to [0, 1] (0 = identical)."""
    if a == b:
        return 0.0
    maxlen = max(len(a), len(b))
    if maxlen == 0:
        return 0.0
    return _levenshtein(a, b) / maxlen


def _find_typosquat_target(name: str) -> Optional[Tuple[str, float]]:
    """Check if *name* is likely a typosquat of any known popular package.

    Returns (target_name, similarity) or None.
    """
    name_lower = name.lower().replace("-", "").replace("_", "")
    best_target: Optional[str] = None
    best_dist = 1.0

    # First check explicit sets
    for popular, squats in _POPULAR_PACKAGES.items():
        if name_lower == popular.replace("-", "").replace("_", ""):
            return None  # It IS the popular package
        if name.lower() in squats or name_lower in {s.replace("-", "").replace("_", "") for s in squats}:
            return popular, 0.95  # Explicit match

    # Then check edit distance against all popular packages
    for popular in _POPULAR_PACKAGES:
        pop_norm = popular.replace("-", "").replace("_", "")
        if name_lower == pop_norm:
            return None  # exact match = it's the real package
        dist = _normalised_distance(name_lower, pop_norm)
        if dist < best_dist:
            best_dist = dist
            best_target = popular

    if best_dist <= 0.2 and best_target:
        return best_target, 1.0 - best_dist

    return None


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------


class PackageReputationEngine:
    """Offline package reputation scoring using naming heuristics and static intelligence."""

    def score(
        self,
        package_name: str,
        ecosystem: str = "pypi",
    ) -> PackageReputation:
        """Compute reputation score for a single package.

        Returns a PackageReputation with a score in [0, 100] (100 = fully trusted).
        """
        name_lower = package_name.lower()
        flags = ReputationFlags()
        deductions: List[Tuple[float, str]] = []
        similar: List[str] = []

        # ── 1. Known malicious ─────────────────────────────────────────────
        for mal in _KNOWN_MALICIOUS:
            if name_lower == mal or name_lower.startswith(mal.rstrip("-")):
                flags.is_known_malicious = True
                flags.reasons.append(f"'{package_name}' appears in known-malicious package list")
                deductions.append((80.0, "known malicious"))
                break

        # ── 2. Typosquat detection ────────────────────────────────────────
        typo_result = _find_typosquat_target(name_lower)
        if typo_result:
            target, similarity = typo_result
            flags.is_typosquat = True
            flags.reasons.append(
                f"Likely typosquat of '{target}' (similarity={similarity:.0%})"
            )
            deductions.append((60.0 * similarity, f"typosquat of {target}"))
            similar.append(target)
            for s in _POPULAR_PACKAGES.get(target, set()):
                similar.append(s)
        else:
            # Check if package IS a popular package (high trust)
            for popular in _POPULAR_PACKAGES:
                if name_lower == popular or name_lower == popular.replace("-", "_"):
                    # This is a well-known package
                    break
            else:
                # Not in popular list — check partial matches
                for popular in _POPULAR_PACKAGES:
                    pop_norm = popular.replace("-", "").replace("_", "")
                    name_norm = name_lower.replace("-", "").replace("_", "")
                    if _normalised_distance(name_norm, pop_norm) < 0.35:
                        similar.append(popular)

        # ── 3. Suspicious name patterns ───────────────────────────────────
        for pattern, reason in _SUSPICIOUS_PATTERNS:
            if pattern.search(name_lower):
                flags.has_suspicious_name = True
                flags.reasons.append(f"Suspicious pattern: {reason}")
                deductions.append((15.0, reason))
                break  # one deduction per category

        # ── 4. Digit/letter substitution ──────────────────────────────────
        digit_subs = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"}
        for digit, letter in digit_subs.items():
            if digit in name_lower:
                # Check if replacing with letter creates a known package name
                candidate = name_lower.replace(digit, letter)
                if any(
                    candidate == pop.replace("-", "").replace("_", "")
                    for pop in _POPULAR_PACKAGES
                ):
                    flags.has_digit_substitution = True
                    flags.reasons.append(
                        f"Digit '{digit}' substituted for letter '{letter}' matches known package"
                    )
                    deductions.append((50.0, "digit substitution attack"))
                    break

        # ── 5. Dependency confusion / internal package patterns ───────────
        for pat in _INTERNAL_PATTERNS:
            if pat.search(name_lower):
                flags.has_dependency_confusion_risk = True
                flags.reasons.append(
                    f"Name matches internal/private package pattern — possible dependency confusion"
                )
                deductions.append((30.0, "dependency confusion risk"))
                break

        # ── 6. Very short names (often squatted) ──────────────────────────
        if len(package_name) <= 2 and ecosystem == "pypi":
            flags.is_short_name = True
            flags.reasons.append(f"Very short package name (len={len(package_name)})")
            deductions.append((10.0, "very short name"))

        # ── Compute score ──────────────────────────────────────────────────
        total_deduction = sum(d for d, _ in deductions)
        # Deductions stack but can't push below 0
        reputation_score = max(0.0, 100.0 - total_deduction)

        # Risk level
        if reputation_score <= 20.0:
            risk_level = "CRITICAL"
        elif reputation_score <= 40.0:
            risk_level = "HIGH"
        elif reputation_score <= 65.0:
            risk_level = "MEDIUM"
        elif reputation_score <= 85.0:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"

        # Explanation
        if deductions:
            explanation_parts = [reason for _, reason in deductions]
            explanation = f"Reputation reduced by: {'; '.join(explanation_parts)}. Score: {reputation_score:.1f}/100."
        else:
            explanation = f"No reputation concerns detected. Score: {reputation_score:.1f}/100."

        return PackageReputation(
            package_name=package_name,
            ecosystem=ecosystem,
            reputation_score=round(reputation_score, 2),
            risk_level=risk_level,
            flags=flags,
            typosquat_target=typo_result[0] if typo_result else None,
            similar_packages=sorted(set(similar))[:10],
            explanation=explanation,
        )

    def score_batch(
        self,
        packages: List[str],
        ecosystem: str = "pypi",
    ) -> List[PackageReputation]:
        """Score a list of package names, sorted by ascending reputation score."""
        results = [self.score(pkg, ecosystem) for pkg in packages]
        results.sort(key=lambda r: r.reputation_score)
        return results

    def find_suspicious(
        self,
        packages: List[str],
        ecosystem: str = "pypi",
        threshold: float = 65.0,
    ) -> List[PackageReputation]:
        """Return only packages whose reputation score is at or below *threshold*."""
        return [
            r for r in self.score_batch(packages, ecosystem)
            if r.reputation_score <= threshold
        ]

    def levenshtein_distance(self, a: str, b: str) -> int:
        """Expose Levenshtein distance for testing."""
        return _levenshtein(a, b)
