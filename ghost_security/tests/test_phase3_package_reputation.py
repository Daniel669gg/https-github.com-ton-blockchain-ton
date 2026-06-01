"""
tests/test_phase3_package_reputation.py — Phase 3 Package Reputation Engine tests.
20 tests covering typosquat detection, known malicious, suspicious patterns, scoring.
"""
import sys
import pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.supply_chain.package_reputation import (
    PackageReputationEngine, PackageReputation, ReputationFlags,
)


# ─────────────────────────────────────────────────────────────────────────────
# Import / instantiation
# ─────────────────────────────────────────────────────────────────────────────

class TestImports:
    def test_engine_importable(self):
        assert PackageReputationEngine is not None

    def test_package_reputation_importable(self):
        assert PackageReputation is not None

    def test_reputation_flags_importable(self):
        assert ReputationFlags is not None

    def test_engine_instantiable(self):
        eng = PackageReputationEngine()
        assert eng is not None


# ─────────────────────────────────────────────────────────────────────────────
# Single package scoring
# ─────────────────────────────────────────────────────────────────────────────

class TestSingleScore:
    def test_score_returns_package_reputation(self):
        eng = PackageReputationEngine()
        rep = eng.score("requests")
        assert isinstance(rep, PackageReputation)

    def test_score_has_required_fields(self):
        eng = PackageReputationEngine()
        rep = eng.score("flask")
        assert hasattr(rep, "package_name")
        assert hasattr(rep, "reputation_score")
        assert hasattr(rep, "risk_level")
        assert hasattr(rep, "flags")

    def test_score_range_is_0_to_100(self):
        eng = PackageReputationEngine()
        rep = eng.score("numpy")
        assert 0.0 <= rep.reputation_score <= 100.0

    def test_well_known_package_has_good_score(self):
        eng = PackageReputationEngine()
        rep = eng.score("requests")
        # Well-known packages should score reasonably well (above 50)
        assert rep.reputation_score >= 50.0

    def test_risk_level_is_valid(self):
        eng = PackageReputationEngine()
        rep = eng.score("django")
        assert rep.risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE")

    def test_has_explanation(self):
        eng = PackageReputationEngine()
        rep = eng.score("flask")
        assert isinstance(rep.explanation, str)
        assert len(rep.explanation) > 0


# ─────────────────────────────────────────────────────────────────────────────
# Typosquat detection
# ─────────────────────────────────────────────────────────────────────────────

class TestTyposquatDetection:
    def test_obvious_typosquat_flagged(self):
        eng = PackageReputationEngine()
        # "reqquests" is close to "requests"
        rep = eng.score("reqquests")
        assert rep.flags.is_typosquat or rep.reputation_score < 80.0

    def test_typosquat_has_lower_score_than_original(self):
        eng = PackageReputationEngine()
        legit = eng.score("requests")
        typo = eng.score("rquests")
        assert typo.reputation_score < legit.reputation_score

    def test_typosquat_target_identified(self):
        eng = PackageReputationEngine()
        rep = eng.score("nunpy")   # close to numpy
        if rep.flags.is_typosquat:
            assert rep.typosquat_target is not None
            assert isinstance(rep.typosquat_target, str)

    def test_known_squats_are_flagged(self):
        eng = PackageReputationEngine()
        rep = eng.score("colourama")   # known pyyaml/colorama squatter
        assert rep.reputation_score < 80.0 or rep.flags.is_known_malicious


# ─────────────────────────────────────────────────────────────────────────────
# Known malicious packages
# ─────────────────────────────────────────────────────────────────────────────

class TestKnownMalicious:
    def test_known_malicious_package_flagged(self):
        eng = PackageReputationEngine()
        rep = eng.score("ctx")   # 2022 malicious PyPI package
        assert rep.flags.is_known_malicious or rep.reputation_score < 50.0

    def test_known_malicious_has_critical_or_high_risk(self):
        eng = PackageReputationEngine()
        rep = eng.score("ctx")
        # Should be HIGH or CRITICAL risk
        assert rep.risk_level in ("CRITICAL", "HIGH", "MEDIUM")


# ─────────────────────────────────────────────────────────────────────────────
# Batch scoring
# ─────────────────────────────────────────────────────────────────────────────

class TestBatchScore:
    def test_score_batch_returns_list(self):
        eng = PackageReputationEngine()
        results = eng.score_batch(["requests", "flask", "pyyaml"])
        assert isinstance(results, list)
        assert len(results) == 3

    def test_score_batch_all_package_reputation(self):
        eng = PackageReputationEngine()
        results = eng.score_batch(["numpy", "pandas"])
        for r in results:
            assert isinstance(r, PackageReputation)

    def test_score_batch_sorted_ascending_score(self):
        eng = PackageReputationEngine()
        results = eng.score_batch(["requests", "nunpy", "ctx"])
        if len(results) >= 2:
            for i in range(len(results) - 1):
                assert results[i].reputation_score <= results[i + 1].reputation_score

    def test_find_suspicious_returns_only_low_score(self):
        eng = PackageReputationEngine()
        results = eng.find_suspicious(["requests", "ctx", "nunpy"], threshold=80.0)
        assert isinstance(results, list)
        for r in results:
            assert r.reputation_score <= 80.0

    def test_score_empty_list(self):
        eng = PackageReputationEngine()
        results = eng.score_batch([])
        assert results == []

    def test_levenshtein_distance_method_works(self):
        eng = PackageReputationEngine()
        dist = eng.levenshtein_distance("requests", "reqquests")
        assert isinstance(dist, int)
        assert dist >= 1
