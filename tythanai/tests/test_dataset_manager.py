"""
tests/test_dataset_manager.py — 8 tests for DatasetManager
"""
from __future__ import annotations

import json
import os
import tempfile

import pytest
from backend.core.confidence import Finding
from backend.core.dataset_manager import DatasetEntry, DatasetManager, DatasetStats
from tests.conftest import InMemoryDatabase


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db():
    _db = InMemoryDatabase()
    _db.init_schema()
    return _db


@pytest.fixture()
def mgr(db):
    return DatasetManager(db=db)


def _make_finding(
    rule_id: str = "SQL-INJ",
    file: str = "src/auth.py",
    line: int = 10,
    severity: str = "HIGH",
    confidence: float = 0.92,
    cwe_id: str = "CWE-89",
    description: str = "SQL injection via concatenation",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        file=file,
        line=line,
        severity=severity,
        confidence=confidence,
        cwe_id=cwe_id,
        description=description,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_add_tp_entry(mgr):
    """verdict='true_positive' is stored correctly and returned as DatasetEntry."""
    finding = _make_finding()
    entry = mgr.add_entry(finding, verdict="true_positive", scan_id="scan-1")
    assert isinstance(entry, DatasetEntry)
    assert entry.verdict == "true_positive"
    assert entry.rule_id == "SQL-INJ"
    assert entry.entry_id != ""
    # Retrieve from DB
    loaded = mgr.get_entry(entry.entry_id)
    assert loaded is not None
    assert loaded.verdict == "true_positive"


def test_add_fp_entry(mgr):
    """verdict='false_positive' is stored and retrievable."""
    finding = _make_finding(line=20)
    entry = mgr.add_entry(finding, verdict="false_positive", scan_id="scan-2")
    assert entry.verdict == "false_positive"
    loaded = mgr.get_entry(entry.entry_id)
    assert loaded is not None
    assert loaded.verdict == "false_positive"


def test_invalid_verdict_raises(mgr):
    """Invalid verdict raises ValueError."""
    finding = _make_finding()
    with pytest.raises(ValueError, match="Invalid verdict"):
        mgr.add_entry(finding, verdict="unknown_verdict")


def test_export_jsonl(mgr, tmp_path):
    """Export to JSONL; each line is valid JSON with correct fields."""
    for i in range(3):
        finding = _make_finding(line=i + 1)
        mgr.add_entry(finding, verdict="true_positive", scan_id="scan-x")

    out_file = str(tmp_path / "output.jsonl")
    count = mgr.export_jsonl(out_file)
    assert count == 3

    lines = open(out_file).read().strip().split("\n")
    assert len(lines) == 3
    for line in lines:
        obj = json.loads(line)
        assert "entry_id" in obj
        assert "verdict" in obj
        assert obj["verdict"] == "true_positive"
        assert "rule_id" in obj


def test_export_json(mgr, tmp_path):
    """Export to JSON; parses as list with correct length."""
    for i in range(4):
        finding = _make_finding(line=i + 10)
        mgr.add_entry(finding, verdict="false_positive", scan_id="scan-y")

    out_file = str(tmp_path / "output.json")
    count = mgr.export_json(out_file)
    assert count == 4

    with open(out_file) as fh:
        data = json.load(fh)
    assert isinstance(data, list)
    assert len(data) == 4
    assert all("entry_id" in item for item in data)


def test_get_stats(mgr):
    """After 5 entries (3 TP, 2 FP), stats.tp_rate == 0.6."""
    for i in range(3):
        finding = _make_finding(line=i + 1)
        mgr.add_entry(finding, verdict="true_positive", scan_id="scan-stats")
    for i in range(2):
        finding = _make_finding(line=i + 100)
        mgr.add_entry(finding, verdict="false_positive", scan_id="scan-stats")

    stats = mgr.get_stats()
    assert isinstance(stats, DatasetStats)
    assert stats.total_entries == 5
    assert stats.true_positives == 3
    assert stats.false_positives == 2
    assert stats.needs_review == 0
    assert abs(stats.tp_rate - 0.6) < 1e-6
    assert abs(stats.fp_rate - 0.4) < 1e-6


def test_filter_confirmed(mgr):
    """filter_confirmed excludes 'needs_review' entries."""
    mgr.add_entry(_make_finding(line=1), verdict="true_positive")
    mgr.add_entry(_make_finding(line=2), verdict="false_positive")
    mgr.add_entry(_make_finding(line=3), verdict="needs_review")
    mgr.add_entry(_make_finding(line=4), verdict="needs_review")

    confirmed = mgr.filter_confirmed()
    assert len(confirmed) == 2
    verdicts = {e.verdict for e in confirmed}
    assert "needs_review" not in verdicts
    assert "true_positive" in verdicts
    assert "false_positive" in verdicts


def test_get_entries_for_training(mgr):
    """min_confidence=0.9 filters out entries with confidence < 0.9."""
    mgr.add_entry(_make_finding(line=1, confidence=0.95), verdict="true_positive")
    mgr.add_entry(_make_finding(line=2, confidence=0.85), verdict="true_positive")
    mgr.add_entry(_make_finding(line=3, confidence=0.70), verdict="false_positive")
    mgr.add_entry(_make_finding(line=4, confidence=0.92), verdict="false_positive")
    mgr.add_entry(_make_finding(line=5, confidence=0.88), verdict="needs_review")

    training = mgr.get_entries_for_training(min_confidence=0.9, exclude_needs_review=True)
    # Only entries with confidence >= 0.9 AND verdict in (TP, FP)
    assert len(training) == 2
    for e in training:
        assert e.confidence >= 0.9
        assert e.verdict in ("true_positive", "false_positive")
