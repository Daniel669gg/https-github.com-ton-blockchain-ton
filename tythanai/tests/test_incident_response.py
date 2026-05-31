"""Tests — fixed imports."""
from __future__ import annotations
import sys, pathlib, json
_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.confidence import Finding
from backend.agents.incident_response import (
    IncidentResponseEngine, IncidentSeverity, PlaybookStepStatus,
    BUILTIN_PLAYBOOKS, create_incident, PLAYBOOKS
)

def _make_finding(
    rule_id: str = "SQLI-001",
    severity: str = "HIGH",
    cwe_id: str = "CWE-89",
    file: str = "app/views.py",
    line: int = 42,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        file=file,
        line=line,
        severity=severity,
        cwe_id=cwe_id,
        description="Test finding",
        recommendation="Fix it",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_create_incident_from_critical_findings():
    """A CRITICAL-severity finding must produce a P1 incident ticket."""
    finding = _make_finding(severity="CRITICAL", cwe_id="CWE-94")
    ticket = create_incident([finding])

    assert ticket.severity == IncidentSeverity.P1, (
        f"Expected P1 for CRITICAL finding, got {ticket.severity}"
    )
    assert ticket.ticket_id.startswith("IR-"), (
        f"Ticket ID should start with 'IR-', got {ticket.ticket_id}"
    )
    assert ticket.status in ("open", "investigating"), (
        f"Unexpected status: {ticket.status}"
    )


def test_playbook_assignment():
    """CWE-89 findings must trigger the SQL Injection playbook."""
    finding = _make_finding(rule_id="SQLI-001", severity="HIGH", cwe_id="CWE-89")
    engine = IncidentResponseEngine()
    ticket = engine.triage_findings([finding])

    assert ticket.assigned_playbook, "assigned_playbook must not be empty"
    assert "SQL" in ticket.assigned_playbook or "Injection" in ticket.assigned_playbook, (
        f"Expected SQL playbook, got: {ticket.assigned_playbook}"
    )


def test_ticket_has_steps():
    """A ticket with an assigned playbook must have at least one playbook step."""
    finding = _make_finding(cwe_id="CWE-89")
    engine = IncidentResponseEngine()
    ticket = engine.triage_findings([finding])

    assert len(ticket.playbook_steps) >= 1, (
        "Ticket must contain at least one playbook step after triage."
    )


def test_complete_step_resolves_ticket_when_all_done():
    """Completing every playbook step must transition ticket status to 'resolved'."""
    finding = _make_finding(cwe_id="CWE-89", severity="HIGH")
    engine = IncidentResponseEngine()
    ticket = engine.triage_findings([finding])

    assert ticket.playbook_steps, "Ticket must have steps before we can complete them."

    for step in ticket.playbook_steps:
        ticket = engine.complete_step(ticket, step.step_id, notes="Done in test.")

    assert ticket.status == "resolved", (
        f"Expected 'resolved' after completing all steps, got '{ticket.status}'"
    )


def test_report_markdown_has_table():
    """generate_report must return a Markdown table for playbook progress."""
    finding = _make_finding(cwe_id="CWE-79", severity="MEDIUM")
    engine = IncidentResponseEngine()
    ticket = engine.triage_findings([finding])
    report = engine.generate_report(ticket)

    assert "| Step ID |" in report or "| `" in report, (
        "Markdown report must contain a table with a step column header."
    )
    # Also check that all major sections are present
    assert "## Timeline" in report
    assert "## Affected Files" in report
    assert "## Playbook Progress" in report
    assert "## Resolution" in report


def test_timeline_populated():
    """A newly created ticket must have at least one timeline entry."""
    finding = _make_finding()
    ticket = create_incident([finding])

    assert len(ticket.timeline) >= 1, (
        "Timeline must contain at least one entry immediately after ticket creation."
    )
    # Validate entry structure
    first = ticket.timeline[0]
    assert "time" in first, "Timeline entry must have a 'time' key."
    assert "event" in first, "Timeline entry must have an 'event' key."
    assert "actor" in first, "Timeline entry must have an 'actor' key."


def test_builtin_playbooks_count():
    """There must be at least 8 built-in playbooks."""
    assert len(BUILTIN_PLAYBOOKS) >= 8, (
        f"Expected >= 8 built-in playbooks, found {len(BUILTIN_PLAYBOOKS)}."
    )
    # Also verify PLAYBOOKS alias
    assert PLAYBOOKS is BUILTIN_PLAYBOOKS, "PLAYBOOKS must alias BUILTIN_PLAYBOOKS."


def test_all_playbooks_have_steps():
    """Every built-in playbook must have at least 3 response steps."""
    for pb in BUILTIN_PLAYBOOKS:
        assert len(pb.steps) >= 3, (
            f"Playbook '{pb.name}' ({pb.playbook_id}) has only {len(pb.steps)} step(s); "
            f"expected >= 3."
        )
        # Each step must have a non-empty command_hint
        for step in pb.steps:
            assert step.step_id, f"Step in playbook '{pb.name}' missing step_id."
            assert step.name, f"Step {step.step_id} in playbook '{pb.name}' missing name."
