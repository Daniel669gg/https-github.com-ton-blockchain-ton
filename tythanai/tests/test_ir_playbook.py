"""Tests for backend/agents/ir_playbook.py."""
from __future__ import annotations
import sys, pathlib, tempfile
_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.confidence import Finding
from backend.agents.ir_playbook import IRPlaybookGenerator, IRPlaybook, generate_ir_playbook


def _critical_sqli(**kw):
    defaults = dict(rule_id="SQLI-001", file="app.py", line=10,
                    severity="CRITICAL", cwe_id="CWE-89", description="SQL injection")
    defaults.update(kw)
    return Finding(**defaults)


def test_generate_returns_playbook():
    gen = IRPlaybookGenerator()
    pb = gen.generate(_critical_sqli(), risk_score=85.0)
    assert isinstance(pb, IRPlaybook)


def test_playbook_has_steps():
    gen = IRPlaybookGenerator()
    pb = gen.generate(_critical_sqli(), risk_score=85.0)
    assert len(pb.steps) > 0, "Playbook must have at least 1 step"


def test_playbook_has_all_phases():
    gen = IRPlaybookGenerator()
    pb = gen.generate(_critical_sqli(), risk_score=90.0)
    phases = {s.phase for s in pb.steps}
    # Must have containment and eradication at minimum
    assert "containment" in phases, f"Missing containment phase. Got: {phases}"
    assert "eradication" in phases, f"Missing eradication phase. Got: {phases}"


def test_save_creates_file():
    with tempfile.TemporaryDirectory() as tmp:
        gen = IRPlaybookGenerator(output_dir=tmp)
        pb = gen.generate(_critical_sqli(), risk_score=85.0, scan_id="test-001")
        saved = gen.save(pb)
        assert saved.exists(), f"Playbook file not created at {saved}"
        content = saved.read_text()
        assert len(content) > 100, "Playbook file is too short"


def test_risk_score_above_80_creates_playbook():
    """Main requirement: risk_score > 80 → playbook is generated and saved."""
    with tempfile.TemporaryDirectory() as tmp:
        gen = IRPlaybookGenerator(output_dir=tmp)
        path = gen.generate_and_save(_critical_sqli(), risk_score=85.0, scan_id="risk-test")
        assert path is not None, "generate_and_save should return a path for risk_score>80"
        assert path.exists(), f"Playbook not found at {path}"


def test_low_risk_not_generated():
    gen = IRPlaybookGenerator()
    finding = Finding(rule_id="INFO-001", file="app.py", line=1, severity="LOW",
                      cwe_id="CWE-200", description="Info disclosure")
    pb = gen.generate(finding, risk_score=20.0)
    # Low severity + low risk_score → returns None (no playbook)
    assert pb is None, f"Expected None for low-risk finding, got {pb}"


def test_to_markdown_contains_attck():
    gen = IRPlaybookGenerator()
    pb = gen.generate(_critical_sqli(), risk_score=85.0)
    if pb:
        md = pb.to_markdown()
        assert "ATT&CK" in md or "MITRE" in md or "T1" in md, (
            "Markdown should reference ATT&CK techniques"
        )
        assert "## " in md, "Markdown should have section headers"


def test_module_level_function():
    pb = generate_ir_playbook(_critical_sqli(), risk_score=85.0)
    assert isinstance(pb, IRPlaybook)
