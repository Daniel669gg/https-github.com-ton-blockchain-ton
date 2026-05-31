"""
tests/test_continuous_learning.py — 8 tests for ContinuousLearningCoordinator
"""
from __future__ import annotations

import pytest
from backend.core.confidence import Finding
from backend.core.continuous_learning import ContinuousLearningCoordinator, LearningEvent, LearningStats
from backend.core.dataset_manager import DatasetManager
from backend.core.rule_evolution import RuleEvolutionSystem
from backend.core.self_improvement import SelfImprovementEngine
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
def coordinator(db, tmp_path):
    """ContinuousLearningCoordinator with in-memory DB and isolated sub-systems."""
    dataset_mgr = DatasetManager(db=db)
    rule_evo = RuleEvolutionSystem(db=db, rules_output_dir=str(tmp_path / "rules"))
    self_imp = SelfImprovementEngine(db=db)
    return ContinuousLearningCoordinator(
        db=db,
        dataset_manager=dataset_mgr,
        rule_evolution=rule_evo,
        self_improvement=self_imp,
    )


def _make_finding(rule_id: str = "RULE-XYZ", line: int = 1) -> Finding:
    return Finding(
        rule_id=rule_id,
        file="src/main.py",
        line=line,
        severity="HIGH",
        confidence=0.9,
        cwe_id="CWE-89",
        description="SQL injection via user input concatenation",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_after_scan_creates_event(coordinator):
    """after_scan returns a LearningEvent."""
    findings = [_make_finding(line=i) for i in range(1, 4)]
    event = coordinator.after_scan("scan-001", findings=findings, scan_path="/repo")
    assert isinstance(event, LearningEvent)


def test_after_scan_event_type(coordinator):
    """Event returned by after_scan has event_type == 'scan_completed'."""
    findings = [_make_finding()]
    event = coordinator.after_scan("scan-002", findings=findings)
    assert event.event_type == "scan_completed"
    assert event.scan_id == "scan-002"


def test_process_feedback_empty(coordinator):
    """No FP fingerprints → returns 0 actions taken."""
    count = coordinator.process_feedback("scan-003", fp_fingerprints=[], fn_descriptions=[])
    assert count == 0


def test_process_feedback_records_fps(coordinator, db):
    """2 FP fingerprints → 2 fp_feedback records and returns 2 actions."""
    findings = [_make_finding(line=i) for i in range(1, 6)]
    coordinator.after_scan("scan-004", findings=findings)

    fp_fingerprints = [findings[0].fingerprint(), findings[1].fingerprint()]
    count = coordinator.process_feedback("scan-004", fp_fingerprints=fp_fingerprints)
    assert count == 2

    # Verify fp_feedback rows were inserted
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM fp_feedback WHERE scan_id=? AND verdict='fp'", ("scan-004",)
        ).fetchall()
    assert len(rows) == 2


def test_get_stats_initial(coordinator):
    """get_stats returns a LearningStats with all required fields."""
    stats = coordinator.get_stats()
    assert isinstance(stats, LearningStats)
    assert hasattr(stats, "total_events")
    assert hasattr(stats, "processed_events")
    assert hasattr(stats, "total_scans_learned_from")
    assert hasattr(stats, "total_rules_evolved")
    assert hasattr(stats, "total_fps_learned")
    assert hasattr(stats, "total_confirmed_tps")
    assert hasattr(stats, "current_system_precision")
    assert hasattr(stats, "current_system_recall")
    assert hasattr(stats, "last_learning_cycle")
    assert hasattr(stats, "knowledge_entries")
    # Fresh system: no events yet
    assert stats.total_events == 0


def test_get_recent_events(coordinator):
    """get_recent_events returns a list (empty or populated)."""
    events = coordinator.get_recent_events(limit=10)
    assert isinstance(events, list)

    # After a scan, should have at least one event
    coordinator.after_scan("scan-events", findings=[_make_finding()])
    events = coordinator.get_recent_events(limit=10)
    assert len(events) >= 1
    assert all(isinstance(e, LearningEvent) for e in events)


def test_trigger_learning_cycle(coordinator):
    """trigger_learning_cycle returns a dict summary with expected keys."""
    result = coordinator.trigger_learning_cycle()
    assert isinstance(result, dict)
    assert "triggered_at" in result
    assert "improvement_report" in result
    assert "rule_evolution_stats" in result
    assert "dataset_stats" in result
    assert "errors" in result
    assert isinstance(result["errors"], list)


def test_mark_event_processed(coordinator):
    """mark_event_processed flips event.processed to True."""
    findings = [_make_finding()]
    event = coordinator.after_scan("scan-mark", findings=findings)
    assert event.processed is False

    coordinator.mark_event_processed(event.event_id)

    # Reload from DB
    events = coordinator.get_recent_events(limit=50)
    matching = [e for e in events if e.event_id == event.event_id]
    assert len(matching) == 1
    assert matching[0].processed is True
