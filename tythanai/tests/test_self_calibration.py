"""Tests for backend/core/self_calibration.py."""
from __future__ import annotations
import sys, pathlib, sqlite3, tempfile, json
_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.self_calibration import SelfCalibrationEngine, CalibrationReport, calibrate


def _make_test_db(path: str, findings: list) -> str:
    """Create a test SQLite DB with findings table."""
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY,
            scan_id TEXT,
            rule_id TEXT,
            file TEXT,
            line INTEGER,
            severity TEXT,
            confidence REAL,
            cwe_id TEXT,
            description TEXT,
            created_at TEXT,
            is_fp INTEGER DEFAULT 0,
            suppressed INTEGER DEFAULT 0
        )
    """)
    conn.executemany(
        "INSERT INTO findings (scan_id, rule_id, file, line, severity, confidence, cwe_id, description, created_at, is_fp, suppressed) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        findings,
    )
    conn.commit()
    conn.close()
    return path


def test_run_with_empty_db():
    with tempfile.TemporaryDirectory() as tmp:
        db = str(pathlib.Path(tmp) / "test.db")
        cfg = str(pathlib.Path(tmp) / "calibration.json")
        engine = SelfCalibrationEngine(db_path=db, config_path=cfg)
        report = engine.run()
        assert isinstance(report, CalibrationReport)
        assert report.total_rules_analyzed >= 0


def test_high_fp_rate_raises_threshold():
    """rule with 40% FP rate → threshold raised."""
    with tempfile.TemporaryDirectory() as tmp:
        db = str(pathlib.Path(tmp) / "test.db")
        cfg = str(pathlib.Path(tmp) / "calibration.json")
        # Create 10 findings for CRYPTO-001, 4 are FP (40%)
        findings = []
        for i in range(6):
            findings.append(("scan1", "CRYPTO-001", "app.py", i, "HIGH", 0.5, "CWE-327", "weak crypto", "2026-01-01", 0, 0))
        for i in range(4):
            findings.append(("scan1", "CRYPTO-001", "app.py", i+10, "HIGH", 0.5, "CWE-327", "weak crypto", "2026-01-01", 1, 0))
        _make_test_db(db, findings)
        engine = SelfCalibrationEngine(db_path=db, config_path=cfg)
        report = engine.run()
        # Find CRYPTO-001 in report
        crypto_rule = next((r for r in report.rules if r.rule_id == "CRYPTO-001"), None)
        assert crypto_rule is not None, "CRYPTO-001 not found in calibration report"
        assert crypto_rule.fp_rate >= 0.30, f"FP rate should be >= 0.30, got {crypto_rule.fp_rate}"
        assert crypto_rule.suggested_threshold > crypto_rule.current_threshold, (
            f"High FP rule should have raised threshold: {crypto_rule}"
        )


def test_config_file_created():
    with tempfile.TemporaryDirectory() as tmp:
        db = str(pathlib.Path(tmp) / "test.db")
        cfg = str(pathlib.Path(tmp) / "calib.json")
        engine = SelfCalibrationEngine(db_path=db, config_path=cfg)
        report = engine.run()
        assert pathlib.Path(cfg).exists(), f"Config file not created at {cfg}"
        data = json.loads(pathlib.Path(cfg).read_text())
        assert isinstance(data, dict)


def test_get_threshold_returns_default_for_unknown():
    with tempfile.TemporaryDirectory() as tmp:
        cfg = str(pathlib.Path(tmp) / "calib.json")
        engine = SelfCalibrationEngine(config_path=cfg)
        t = engine.get_threshold("NONEXISTENT-RULE")
        assert 0.0 < t <= 1.0, f"Default threshold should be in (0, 1], got {t}"


def test_calibration_report_to_markdown():
    with tempfile.TemporaryDirectory() as tmp:
        db = str(pathlib.Path(tmp) / "test.db")
        cfg = str(pathlib.Path(tmp) / "calib.json")
        engine = SelfCalibrationEngine(db_path=db, config_path=cfg)
        report = engine.run()
        md = report.to_markdown()
        assert isinstance(md, str)
        assert "calibrat" in md.lower() or "rule" in md.lower() or "#" in md


def test_module_level_calibrate():
    with tempfile.TemporaryDirectory() as tmp:
        db = str(pathlib.Path(tmp) / "test.db")
        report = calibrate(db_path=db)
        assert isinstance(report, CalibrationReport)
