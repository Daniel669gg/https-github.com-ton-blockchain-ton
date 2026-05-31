"""
backend/scanners/git_secrets.py — Git History Secret Scanner

Scans full git commit history (via gitpython) for leaked secrets using
contextual regex patterns with comprehensive false-positive filters.

Falls back to scanning the working tree when gitpython is unavailable.
"""
from __future__ import annotations

import logging
import os
import re
import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.core.confidence import Finding

logger = logging.getLogger("tythanai.git_secrets")

# ─────────────────────────────────────────────────────────────────────────────
# Try to import gitpython; degrade gracefully if absent
# ─────────────────────────────────────────────────────────────────────────────

try:
    import git as _gitlib  # type: ignore
    _GIT_AVAILABLE = True
except ImportError:
    _GIT_AVAILABLE = False
    logger.info("gitpython not installed; falling back to working-tree scan only")

# ─────────────────────────────────────────────────────────────────────────────
# BIP-39 word list (representative subset for TON mnemonic detection)
# ─────────────────────────────────────────────────────────────────────────────

_BIP39_COMMON: Set[str] = {
    "abandon", "ability", "able", "about", "above", "absent", "absorb",
    "abstract", "absurd", "abuse", "access", "accident", "account", "accuse",
    "achieve", "acid", "acoustic", "acquire", "across", "action", "actor",
    "actual", "adapt", "add", "addict", "address", "adjust", "admit",
    "adult", "advance", "advice", "afford", "afraid", "again", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm",
    "album", "alert", "alien", "alley", "allow", "almost", "alone",
    "alpha", "already", "also", "alter", "always", "amateur", "amazing",
    "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle",
    "angry", "animal", "ankle", "announce", "annual", "another", "answer",
    "antenna", "antique", "anxiety", "apart", "apple", "approve", "april",
    "arch", "arctic", "area", "arena", "argue", "arm", "armed",
    "armor", "army", "around", "arrange", "arrest", "arrive", "arrow",
    "arrow", "ask", "assume", "attract", "auction", "audit", "august",
    "author", "auto", "autumn", "average", "avocado", "avoid", "awake",
    "aware", "baby", "bacon", "badge", "bag", "balance", "bamboo",
    "banana", "banner", "bar", "barely", "bargain", "barrel", "base",
    "basic", "basket", "battle", "beach", "bean", "beauty", "become",
    "beef", "before", "begin", "behave", "behind", "believe", "below",
    "belt", "bench", "benefit", "beyond", "bird", "birth", "bitter",
    "black", "blade", "blame", "blanket", "blast", "bleak", "bless",
    "blind", "blood", "blossom", "blur", "boat", "body", "bomb",
    "bone", "book", "boost", "border", "boring", "borrow", "boss",
    "bottom", "bounce", "brain", "brand", "brave", "breeze", "brick",
    "bridge", "brief", "bright", "bring", "brisk", "broken", "bronze",
    "brother", "brown", "brush", "bubble", "budget", "build", "bulb",
    "bulk", "bullet", "bundle", "burden", "burst", "business", "busy",
    "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "call",
    "calm", "camera", "camp", "canoe", "capital", "captain", "card",
    "cargo", "carpet", "carry", "cart", "case", "cash", "castle",
    "casual", "catalog", "catch", "cause", "ceiling", "celery", "cement",
    "census", "century", "cereal", "certain", "chair", "chaos", "chapter",
    "charge", "chase", "cheap", "check", "cheese", "chef", "cherry",
    "chest", "chicken", "chief", "child", "chimney", "choice", "choose",
    "chronic", "circle", "citizen", "city", "civil", "claim", "clap",
    "clarify", "clean", "clerk", "clever", "click", "client", "cliff",
    "climb", "clinic", "clip", "close", "cloth", "cloud", "clown",
    "cluster", "coach", "code", "coffee", "coil", "collect", "color",
    "column", "combine", "come", "comfort", "comic", "common", "company",
    "concert", "conduct", "confirm", "congress", "connect", "consider",
    "control", "convince", "cook", "cool", "copper", "copy", "coral",
    "core", "corn", "correct", "cost", "cotton", "couch", "country",
    "couple", "course", "cousin", "cover", "coyote", "crack", "cradle",
    "craft", "cram", "crane", "crash", "crazy", "cream", "credit",
    "creek", "crew", "cricket", "crime", "crisp", "critic", "cross",
    "crown", "crucial", "cruel", "cruise", "crumble", "crunch", "crush",
    "cube", "culture", "cup", "cupboard", "curious", "current", "curtain",
    "curve", "cushion", "custom", "cute", "cycle", "damage", "danger",
    "daring", "dash", "daughter", "dawn", "deal", "debate", "debris",
    "decade", "december", "decide", "decline", "decorate", "decrease",
    "deer", "defense", "define", "delay", "deliver", "denial", "depart",
    "depend", "deposit", "depth", "deputy", "derive", "describe", "desert",
    "design", "desk", "despair", "destroy", "detail", "detect", "develop",
    "devote", "diagram", "dial", "diamond", "dice", "diesel", "diet",
    "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur",
    "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss",
    "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor",
    "document", "domain", "donate", "donkey", "donor", "door", "dose",
    "double", "dove", "draft", "dragon", "drama", "drastic", "draw",
    "dream", "dress", "drift", "drill", "drink", "drip", "drive",
    "drop", "drum", "dry", "duck", "dumb", "dune", "during",
    "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle",
    "early", "earn", "easily", "east", "easy", "echo", "ecology",
    "edge", "effort", "either", "elbow", "elder", "electric", "elegant",
    "element", "elephant", "elite", "else", "embark", "embody", "emerge",
    "emotion", "employ", "empty", "enable", "enact", "endless", "endorse",
    "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy",
    "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire",
    "entry", "envelope", "episode", "equal", "equip", "erase", "erode",
    "erosion", "error", "erupt", "escape", "essay", "essence", "estate",
    "eternal", "ethics", "evidence", "evil", "evolve", "exact", "example",
    "excess", "exchange", "excite", "exclude", "exhaust", "exhibit", "exile",
    "exist", "exit", "exotic", "expand", "expire", "explain", "expose",
    "express", "extend", "extra", "fabric", "face", "faculty", "faint",
    "faith", "fall", "false", "fame", "family", "famous", "fancy",
    "fantasy", "finger", "finish", "fire", "firm", "first", "fiscal",
    "fish", "flame", "flash", "flat", "flavor", "flee", "flight",
    "flip", "float", "flock", "floor", "flower", "fluid", "flush",
    "foam", "focus", "fold", "follow", "force", "forest", "forge",
    "fortune", "fossil", "foster", "found", "frame", "frequent", "fresh",
    "friend", "fringe", "frog", "front", "frost", "fruit", "fuel",
    "funny", "furnace", "fury", "future", "gadget", "galaxy", "gallery",
    "game", "gap", "garbage", "garden", "garlic", "garment", "gate",
    "gather", "gauge", "giant", "gift", "giggle", "ginger", "giraffe",
    "give", "glad", "glance", "glide", "glimpse", "globe", "gloom",
    "glove", "glow", "glue", "goat", "goddess", "gold", "good",
    "goose", "gorilla", "gospel", "gossip", "government", "grab", "grace",
    "grain", "grant", "grape", "grass", "gravity", "great", "green",
    "grid", "grief", "grit", "grocery", "ground", "group", "grow",
    "grunt", "guard", "guide", "guilt", "guitar", "habit", "hair",
    "half", "hammer", "hamster", "hand", "happy", "harsh", "harvest",
    "have", "hawk", "hazard", "head", "heart", "heavy", "hedgehog",
    "height", "hello", "helmet", "help", "hero", "hidden", "high",
    "hint", "hollow", "honey", "honor", "hope", "horse", "human",
    "humid", "hunger", "hybrid", "immune", "impact", "impose", "improve",
    "impulse", "inbox", "inch", "include", "income", "increase", "index",
    "indicate", "indoor", "inform", "inhale", "inject", "inner", "innocent",
    "input", "inquiry", "insane", "insect", "inspire", "install", "intact",
    "interest", "involve", "iron", "island", "isolate", "issue", "item",
    "ivory", "jacket", "jaguar", "jewel", "job", "join", "joke",
    "journey", "judge", "juice", "jump", "jungle", "junior", "junk",
    "keep", "ketchup", "kidney", "kind", "kingdom", "kiss", "kitchen",
    "knee", "knife", "knock", "knowledge", "lava", "lawyer", "layer",
    "lazy", "leader", "learn", "leave", "legend", "lemon", "leopard",
    "lesson", "letter", "level", "library", "life", "lift", "light",
    "like", "limit", "link", "lion", "liquid", "list", "little",
    "lizard", "loan", "lobster", "lock", "logic", "lonely", "long",
    "loop", "loud", "love", "loyal", "lucky", "luggage", "lumber",
    "lunar", "lunch", "luxury", "magic", "magnet", "manage", "mandate",
    "manual", "maple", "marble", "march", "margin", "master", "match",
    "matrix", "meadow", "measure", "media", "melody", "member", "mental",
    "mention", "mercy", "mesh", "message", "metal", "method", "middle",
    "midnight", "milk", "million", "mimic", "mind", "minimum", "minor",
    "miracle", "miss", "mixture", "mobile", "model", "modify", "moment",
    "month", "moral", "morning", "mountain", "mouse", "move", "much",
    "muffin", "muscle", "museum", "music", "myself", "mystery", "naive",
    "nature", "near", "neck", "need", "negative", "neglect", "neither",
    "nephew", "nerve", "network", "news", "night", "noble", "noise",
    "normal", "north", "notable", "nothing", "notice", "novel", "nuclear",
    "nurse", "object", "obtain", "ocean", "offer", "office", "once",
    "opera", "option", "orange", "order", "organ", "orient", "original",
    "orphan", "other", "output", "outside", "over", "owner", "panic",
    "paper", "parade", "parent", "park", "patrol", "pause", "payment",
    "peace", "peanut", "peasant", "pelican", "penalty", "penguin", "pepper",
    "permit", "person", "phrase", "picnic", "pilot", "pink", "pioneer",
    "pizza", "planet", "plastic", "plate", "please", "pledge", "plunge",
    "poem", "poet", "point", "polar", "poll", "pond", "popular",
    "position", "possible", "potato", "poverty", "powder", "power", "practice",
    "praise", "predict", "prepare", "present", "pretty", "price", "pride",
    "primary", "print", "prison", "private", "prize", "problem", "process",
    "produce", "profit", "promise", "promote", "proof", "property", "protect",
    "proud", "provide", "public", "pulse", "purpose", "push", "puzzle",
    "quality", "quantum", "quarter", "queen", "question", "quick", "quit",
    "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio",
    "rail", "rain", "rather", "raven", "razor", "ready", "real",
    "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record",
    "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret",
    "regular", "reject", "relate", "relax", "remain", "remind", "remove",
    "render", "renew", "rent", "reopen", "repair", "repeat", "replace",
    "report", "require", "rescue", "resource", "response", "result", "retire",
    "retreat", "reunion", "reveal", "review", "reward", "rhythm", "ribbon",
    "rice", "rich", "rifle", "right", "ring", "riot", "ripple",
    "risk", "ritual", "rival", "river", "road", "robot", "robust",
    "rocket", "romance", "roof", "rookie", "room", "rose", "rough",
    "royal", "rubber", "rude", "rugby", "ruin", "rule", "runway",
    "safe", "sail", "salad", "salmon", "salon", "salt", "salute",
    "same", "sample", "sand", "satisfy", "sauce", "sausage", "save",
    "scale", "scan", "scary", "scene", "science", "scissors", "scorpion",
    "scout", "search", "season", "seat", "second", "secret", "section",
    "select", "senior", "sense", "sentence", "series", "service", "session",
    "settle", "seven", "shadow", "shaft", "share", "shed", "shell",
    "shield", "shift", "shine", "ship", "shiver", "shock", "shoot",
    "short", "shoulder", "shrug", "shuffle", "sibling", "sight", "signal",
    "simple", "since", "skill", "skin", "skirt", "skull", "slender",
    "slice", "slide", "slim", "slogan", "slot", "slow", "slush",
    "small", "smart", "smile", "smoke", "smooth", "snack", "snake",
    "snap", "soldier", "solid", "solution", "solve", "someone", "song",
    "space", "spare", "spark", "spawn", "speak", "special", "speed",
    "spell", "spend", "sphere", "spider", "spike", "spirit", "split",
    "spot", "spray", "spread", "spring", "square", "squirrel", "stable",
    "stadium", "staff", "stage", "stair", "stand", "start", "state",
    "stay", "steel", "stem", "step", "stereo", "stick", "still",
    "stock", "stomach", "stone", "stop", "storm", "story", "stove",
    "strategy", "street", "strike", "strong", "struggle", "student", "stuff",
    "stumble", "sugar", "suit", "summer", "super", "supply", "supreme",
    "surprise", "sustain", "swarm", "swift", "symbol", "tackle", "talent",
    "tank", "tape", "target", "taste", "taxi", "teach", "team",
    "token", "tomato", "tomorrow", "tone", "topic", "total", "tourist",
    "toward", "tower", "town", "trade", "traffic", "tragic", "train",
    "transfer", "travel", "treat", "tree", "trend", "trial", "trick",
    "trigger", "trouble", "truly", "trust", "truth", "tube", "tunnel",
    "turkey", "twin", "type", "typical", "ugly", "umbrella", "unable",
    "uncle", "under", "undo", "unfair", "unfold", "unhappy", "uniform",
    "unique", "unlock", "until", "unusual", "update", "upgrade", "upon",
    "upper", "upset", "urban", "useful", "useless", "usual", "utility",
    "vacuum", "valid", "valley", "valve", "various", "vast", "vault",
    "vendor", "venture", "venue", "verify", "version", "very", "veto",
    "viable", "vibrant", "vicious", "victory", "video", "view", "village",
    "vintage", "violin", "viral", "virtual", "virus", "visit", "visual",
    "vital", "vocal", "voice", "void", "volcano", "volume", "vote",
    "voyage", "wage", "wallet", "warfare", "warm", "warrior", "waste",
    "water", "wave", "weapon", "week", "welcome", "well", "west",
    "wheat", "wheel", "where", "whip", "whisper", "wide", "width",
    "window", "wing", "winner", "winter", "wire", "wisdom", "wish",
    "witness", "wolf", "wonder", "wood", "wool", "word", "world",
    "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write",
    "wrong", "yard", "year", "yellow", "young", "youth", "zebra",
    "zero", "zone", "zoo",
}

# ─────────────────────────────────────────────────────────────────────────────
# False-positive placeholder patterns
# ─────────────────────────────────────────────────────────────────────────────

_PLACEHOLDER_KEYWORDS = (
    "your_key_here", "your_api_key", "xxx", "example", "test", "dummy",
    "fake", "placeholder", "changeme", "sample", "not_real", "not-real",
    "replace_me", "replaceme", "insert_here",
)

_PLACEHOLDER_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"<[^>]+>"),           # <REPLACE_ME>
    re.compile(r"\$\{[^}]+\}"),       # ${MY_SECRET}
    re.compile(r"\$[A-Z_]{3,}"),      # $MY_SECRET
]

_QUOTED_VALUE_RE = re.compile(r"""['"]([^'"]{4,})['"]""")


def _is_placeholder(text: str) -> bool:
    """Return True if the matched text looks like a placeholder, not a real secret.

    Checks the VALUE portion (between quotes when present) for placeholder
    keywords at the START of the value — this avoids false-positives from
    real keys that merely contain a keyword substring (e.g. AKIAIOSFODNN7EXAMPLE).
    """
    val_match = _QUOTED_VALUE_RE.search(text)
    value_low = (val_match.group(1) if val_match else text).lower()

    for kw in _PLACEHOLDER_KEYWORDS:
        if value_low.startswith(kw):
            return True

    for pat in _PLACEHOLDER_PATTERNS:
        if pat.search(text):
            return True
    return False

_TEMPLATE_FILE_PATTERNS: List[str] = [
    "*example*", "*sample*", "*template*",
    "*.example", "*.sample", "*.template",
]

_TEST_FILE_GLOBS: List[str] = [
    "test_*", "*_test.py", "conftest.py",
]

# ─────────────────────────────────────────────────────────────────────────────
# Detection rules
# ─────────────────────────────────────────────────────────────────────────────

class _Rule:
    def __init__(
        self,
        rule_id: str,
        pattern: re.Pattern[str],
        severity: str,
        cwe_id: str,
        description: str,
        recommendation: str,
        confidence: float = 0.9,
    ) -> None:
        self.rule_id = rule_id
        self.pattern = pattern
        self.severity = severity
        self.cwe_id = cwe_id
        self.description = description
        self.recommendation = recommendation
        self.confidence = confidence


_RULES: List[_Rule] = [
    _Rule(
        rule_id="SECRET-API-KEY",
        pattern=re.compile(
            r"""(?i)(api[_\-]?key|apikey)[\s]*[=:][\s]*['"][a-zA-Z0-9_\-]{20,}['"]"""
        ),
        severity="HIGH",
        cwe_id="CWE-798",
        description="Hardcoded API key detected in source.",
        recommendation="Remove the key, rotate it immediately, and use environment variables or a secrets manager.",
        confidence=0.9,
    ),
    _Rule(
        rule_id="SECRET-JWT-TOKEN",
        pattern=re.compile(
            r"""eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"""
        ),
        severity="HIGH",
        cwe_id="CWE-798",
        description="JWT token hardcoded in source code.",
        recommendation="Never commit live JWT tokens; rotate the token and use environment-based injection.",
        confidence=0.95,
    ),
    _Rule(
        rule_id="SECRET-PRIVATE-KEY",
        pattern=re.compile(
            r"""-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----"""
        ),
        severity="CRITICAL",
        cwe_id="CWE-321",
        description="Private key material embedded in source.",
        recommendation="Remove key immediately, rotate it, and store keys in a hardware security module or secrets vault.",
        confidence=0.99,
    ),
    _Rule(
        rule_id="SECRET-AWS-ACCESS-KEY",
        pattern=re.compile(r"""AKIA[0-9A-Z]{16}"""),
        severity="CRITICAL",
        cwe_id="CWE-798",
        description="AWS Access Key ID detected.",
        recommendation="Revoke the key in IAM immediately and use IAM roles or environment injection instead.",
        confidence=0.97,
    ),
    _Rule(
        rule_id="SECRET-AWS-SECRET",
        pattern=re.compile(
            r"""(?i)aws.{0,20}secret.{0,20}[0-9a-zA-Z/+]{40}"""
        ),
        severity="CRITICAL",
        cwe_id="CWE-798",
        description="AWS Secret Access Key detected.",
        recommendation="Revoke the key in IAM immediately and use IAM roles or environment injection instead.",
        confidence=0.88,
    ),
    _Rule(
        rule_id="SECRET-ETH-PRIVATE-KEY",
        pattern=re.compile(
            r"""(?:private[_\-]?key|wallet|key)\s*[=:]\s*['"]?(?:0x)?[0-9a-fA-F]{64}['"]?""",
            re.IGNORECASE,
        ),
        severity="CRITICAL",
        cwe_id="CWE-321",
        description="Ethereum/blockchain private key detected near sensitive variable name.",
        recommendation="Remove immediately; rotate the wallet key and use environment-based key injection.",
        confidence=0.85,
    ),
    _Rule(
        rule_id="SECRET-GENERIC-PASSWORD",
        pattern=re.compile(
            r"""(?i)(password|secret|pwd|passwd)\s*[=:]\s*['"][^'"]{8,}['"]"""
        ),
        severity="HIGH",
        cwe_id="CWE-798",
        description="Hardcoded password or secret string detected.",
        recommendation="Remove hardcoded credential; store in environment variables or a secrets manager.",
        confidence=0.80,
    ),
    _Rule(
        rule_id="SECRET-TON-MNEMONIC",
        pattern=re.compile(
            # 24 lowercase words separated by spaces (BIP-39 mnemonic)
            r"""\b([a-z]{3,10}(?:\s+[a-z]{3,10}){23})\b"""
        ),
        severity="CRITICAL",
        cwe_id="CWE-321",
        description="Possible 24-word BIP-39/TON wallet mnemonic phrase detected.",
        recommendation="Remove immediately; the mnemonic controls the wallet. Rotate funds to a new wallet.",
        confidence=0.75,
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# Helper utilities
# ─────────────────────────────────────────────────────────────────────────────



def _is_template_file(filepath: str) -> bool:
    """Return True for example/sample/template files that should be ignored."""
    basename = os.path.basename(filepath).lower()
    for glob in _TEMPLATE_FILE_PATTERNS:
        if fnmatch.fnmatch(basename, glob):
            return True
    return False


def _is_test_file(filepath: str) -> bool:
    """Return True if the file is a test file."""
    basename = os.path.basename(filepath).lower()
    for glob in _TEST_FILE_GLOBS:
        if fnmatch.fnmatch(basename, glob):
            return True
    # check path components
    parts = Path(filepath).parts
    return any(p.lower() in {"tests", "test", "spec"} for p in parts)


def _downgrade_severity(severity: str) -> str:
    _order = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "INFO", "INFO": "INFO"}
    return _order.get(severity, severity)


def _is_ton_mnemonic(candidate: str) -> bool:
    """Validate that a 24-word sequence contains mostly BIP-39 words."""
    words = candidate.lower().split()
    if len(words) != 24:
        return False
    bip39_count = sum(1 for w in words if w in _BIP39_COMMON)
    # At least 18/24 words must be in BIP-39 to avoid random text
    return bip39_count >= 18


def _scan_line_for_rules(
    line: str,
    filepath: str,
    lineno: int,
    context_lines: List[str],
    extra_sources: Optional[List[str]] = None,
) -> List[Finding]:
    """Apply all rules to a single line, return findings."""
    findings: List[Finding] = []

    # Skip pure comment lines
    stripped = line.strip()
    if stripped.startswith("#") or stripped.startswith("//"):
        return findings

    is_test = _is_test_file(filepath)

    for rule in _RULES:
        for match in rule.pattern.finditer(line):
            matched_text = match.group(0)

            # False-positive: placeholder values
            if _is_placeholder(matched_text):
                logger.debug("Skipping placeholder match in %s:%d", filepath, lineno)
                continue

            # Extra validation for TON mnemonic: check BIP-39 word ratio
            if rule.rule_id == "SECRET-TON-MNEMONIC":
                if not _is_ton_mnemonic(matched_text):
                    continue

            severity = rule.severity
            is_test_file = is_test
            confidence = rule.confidence

            if is_test:
                severity = _downgrade_severity(severity)
                confidence = max(0.4, confidence - 0.2)

            sources = extra_sources or [filepath]

            findings.append(Finding(
                rule_id=rule.rule_id,
                file=filepath,
                line=lineno,
                severity=severity,
                confidence=confidence,
                cwe_id=rule.cwe_id,
                description=rule.description,
                recommendation=rule.recommendation,
                sources=sources,
                context_lines=context_lines,
                is_test_file=is_test_file,
            ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Working-tree scanner (fallback when git is unavailable)
# ─────────────────────────────────────────────────────────────────────────────

_SKIP_DIRS: Set[str] = {
    ".git", "__pycache__", ".venv", "venv", "node_modules",
    ".mypy_cache", ".pytest_cache", "dist", "build",
}

_TEXT_EXTENSIONS: Set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
    ".php", ".cs", ".cpp", ".c", ".h", ".sh", ".bash", ".zsh",
    ".env", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
    ".conf", ".properties", ".xml", ".tf", ".tfvars", ".hcl",
    ".dockerfile", "", ".md", ".txt",
}


def _scan_file_content(filepath: str, content: str, sources: Optional[List[str]] = None) -> List[Finding]:
    """Scan a single file's text content for secrets."""
    if _is_template_file(filepath):
        return []

    findings: List[Finding] = []
    lines = content.splitlines()
    ctx_radius = 2

    for i, line in enumerate(lines, start=1):
        ctx_start = max(0, i - ctx_radius - 1)
        ctx_end = min(len(lines), i + ctx_radius)
        ctx = lines[ctx_start:ctx_end]
        findings.extend(_scan_line_for_rules(line, filepath, i, ctx, sources))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Git history scanner
# ─────────────────────────────────────────────────────────────────────────────

def _truncate(s: str, max_len: int = 80) -> str:
    return s[:max_len] + "…" if len(s) > max_len else s


def _scan_repo_history(repo_path: str) -> List[Finding]:
    """Scan every blob in git commit history for secrets."""
    if not _GIT_AVAILABLE:
        logger.warning("gitpython unavailable; skipping history scan")
        return []

    try:
        repo = _gitlib.Repo(repo_path, search_parent_directories=True)
    except Exception as exc:
        logger.warning("Could not open git repo at %s: %s", repo_path, exc)
        return []

    findings: List[Finding] = []
    seen_blobs: Set[str] = set()  # avoid scanning the same blob twice

    for commit in repo.iter_commits("--all"):
        try:
            author = str(commit.author)
            date = commit.authored_datetime.isoformat()
            msg = _truncate(commit.message.strip())
            commit_hash = commit.hexsha[:12]

            for blob in commit.tree.traverse():
                if blob.type != "blob":  # type: ignore[attr-defined]
                    continue

                # Skip already-scanned identical blobs
                blob_key = blob.hexsha  # type: ignore[attr-defined]
                if blob_key in seen_blobs:
                    continue
                seen_blobs.add(blob_key)

                filepath: str = blob.path  # type: ignore[attr-defined]

                # Only scan text-like files
                ext = Path(filepath).suffix.lower()
                if ext not in _TEXT_EXTENSIONS and ext:
                    continue

                if _is_template_file(filepath):
                    continue

                try:
                    content = blob.data_stream.read().decode("utf-8", errors="replace")  # type: ignore[attr-defined]
                except Exception:
                    continue

                sources = [
                    f"commit:{commit_hash}",
                    f"author:{author}",
                    f"date:{date}",
                    f"message:{msg}",
                ]
                file_findings = _scan_file_content(filepath, content, sources)
                findings.extend(file_findings)

        except Exception as exc:
            logger.debug("Error processing commit %s: %s", getattr(commit, "hexsha", "?"), exc)

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Public scanner class
# ─────────────────────────────────────────────────────────────────────────────

class GitSecretsScanner:
    """
    Scans git history and/or working tree files for leaked secrets.

    Methods:
        scan_file(path)       → scan a single file in the working tree
        scan_directory(path)  → scan all eligible files in a directory tree
        scan_history(path)    → scan full git commit history (requires gitpython)
        scan(path)            → history scan with working-tree fallback
    """

    def scan_file(self, path: str) -> List[Finding]:
        """Scan a single file for secrets."""
        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", path, exc)
            return []
        return _scan_file_content(path, content)

    def scan_directory(self, path: str) -> List[Finding]:
        """Scan all text files in a directory tree for secrets."""
        findings: List[Finding] = []
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for fname in files:
                ext = Path(fname).suffix.lower()
                if ext not in _TEXT_EXTENSIONS and ext:
                    continue
                full_path = os.path.join(root, fname)
                findings.extend(self.scan_file(full_path))
        return findings

    def scan_history(self, repo_path: str) -> List[Finding]:
        """Scan full git commit history for secrets (requires gitpython)."""
        if not _GIT_AVAILABLE:
            logger.warning(
                "gitpython not installed. Install with: pip install gitpython. "
                "Falling back to working-tree scan."
            )
            return self.scan_directory(repo_path)
        return _scan_repo_history(repo_path)

    def scan(self, path: str) -> Dict[str, Any]:
        """
        Primary entry point. Attempts full history scan; falls back to
        working-tree scan if git is unavailable or path is not a repo.

        Returns a dict with keys: findings, git_available, mode.
        """
        if _GIT_AVAILABLE:
            try:
                import git as _g
                _g.Repo(path, search_parent_directories=True)
                findings = _scan_repo_history(path)
                mode = "history"
            except Exception:
                findings = self.scan_directory(path)
                mode = "working_tree"
        else:
            findings = self.scan_directory(path)
            mode = "working_tree"

        logger.info("GitSecretsScanner: %d findings in %s mode", len(findings), mode)
        return {
            "findings": findings,
            "git_available": _GIT_AVAILABLE,
            "mode": mode,
            "total": len(findings),
        }
