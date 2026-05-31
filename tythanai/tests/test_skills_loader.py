"""Tests for backend/agents/skills_loader.py."""
from __future__ import annotations
import sys, pathlib
_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.agents.skills_loader import SkillsLoader, SkillMeta, SkillContent


def test_registry_has_40_skills():
    loader = SkillsLoader()
    all_skills = loader.scan_all("", top_n=100)  # empty query → return all
    assert len(all_skills) >= 40, f"Expected >=40 skills, got {len(all_skills)}"


def test_scan_all_sql_injection():
    loader = SkillsLoader()
    results = loader.scan_all("sql injection", top_n=5)
    assert len(results) > 0, "scan_all should return results for 'sql injection'"
    # At least one result should be from web-application-security domain
    domains = [r.domain for r in results]
    assert any("web" in d or "application" in d for d in domains), (
        f"Expected web-application-security domain in results, got {domains}"
    )


def test_search_by_framework_attck_t1003():
    loader = SkillsLoader()
    results = loader.search_by_framework("ATT&CK", "T1003")
    assert len(results) > 0, "search_by_framework ATT&CK T1003 should return results"
    # All results should have T1003 in mitre_ids
    for r in results:
        assert "T1003" in r.mitre_ids, f"Skill {r.skill_id} missing T1003 in mitre_ids"


def test_search_by_framework_d3fend():
    loader = SkillsLoader()
    results = loader.search_by_framework("D3FEND", "D3-DA")
    assert isinstance(results, list)


def test_search_by_domain():
    loader = SkillsLoader()
    results = loader.search_by_domain("threat-hunting")
    assert len(results) >= 3, "Expected >=3 threat-hunting skills"
    for r in results:
        assert "threat" in r.domain or "hunting" in r.domain, (
            f"Unexpected domain: {r.domain}"
        )


def test_load_skill_returns_content():
    loader = SkillsLoader()
    # Find any skill name from registry
    skills = loader.scan_all("injection", top_n=3)
    assert skills, "Need at least one skill to test load_skill"
    content = loader.load_skill(skills[0].name)
    assert content is not None, f"load_skill returned None for {skills[0].name}"
    assert isinstance(content, SkillContent)
    assert len(content.workflow_steps) > 0, "SkillContent must have workflow_steps"
    assert len(content.verification_steps) > 0, "SkillContent must have verification_steps"


def test_skill_meta_has_required_fields():
    loader = SkillsLoader()
    skills = loader.scan_all("", top_n=100)
    for s in skills[:10]:
        assert s.skill_id, f"Missing skill_id: {s}"
        assert s.name, f"Missing name: {s}"
        assert s.domain, f"Missing domain: {s}"
        assert isinstance(s.mitre_ids, list), f"mitre_ids not a list: {s}"
        assert isinstance(s.d3fend_ids, list), f"d3fend_ids not a list: {s}"


def test_domains_cover_required_set():
    from backend.agents.skills_loader import _EMBEDDED_SKILLS
    domains = {s.domain for s in _EMBEDDED_SKILLS}
    required = {
        "web-application-security", "threat-hunting", "cryptography",
        "identity-access-management", "incident-response",
    }
    for req in required:
        assert req in domains, f"Missing required domain: {req}. Got: {domains}"
