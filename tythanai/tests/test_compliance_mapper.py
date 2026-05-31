"""Tests — fixed imports."""
from __future__ import annotations
import sys, pathlib, json
_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.confidence import Finding
from backend.analysis.compliance_mapper import (
    ComplianceMapper, CWE_COMPLIANCE_MAP, ATTACK_TECHNIQUES,
    NIST_CSF_CONTROLS, map_to_compliance, export_sarif
)

def _sqli_finding(**kwargs):
    defaults = dict(rule_id="SQLI-001", file="app.py", line=10, severity="CRITICAL", cwe_id="CWE-89", description="SQL injection")
    defaults.update(kwargs)
    return Finding(**defaults)

def _hardcoded_cred_finding(**kwargs):
    defaults = dict(rule_id="CRED-001", file="config.py", line=3, severity="CRITICAL", cwe_id="CWE-798", description="Hardcoded credential")
    defaults.update(kwargs)
    return Finding(**defaults)

def _xss_finding(**kwargs):
    defaults = dict(rule_id="XSS-001", file="views.py", line=5, severity="HIGH", cwe_id="CWE-79", description="XSS")
    defaults.update(kwargs)
    return Finding(**defaults)


def test_cwe89_maps_to_owasp_injection():
    """CWE-89 must map to the OWASP 'Injection' category."""
    mapper = ComplianceMapper()
    result = mapper.map_finding(_sqli_finding())

    owasp_cats = result["owasp_top10"]
    assert any("Injection" in cat for cat in owasp_cats), (
        f"Expected 'Injection' in OWASP categories for CWE-89, got: {owasp_cats}"
    )


def test_cwe89_maps_to_mitre_t1190():
    """CWE-89 must include T1190 (Exploit Public-Facing Application) in ATT&CK techniques."""
    mapper = ComplianceMapper()
    result = mapper.map_finding(_sqli_finding())

    technique_ids = [t["technique_id"] for t in result["mitre_attack"]]
    assert "T1190" in technique_ids, (
        f"Expected T1190 in MITRE ATT&CK mappings for CWE-89, got: {technique_ids}"
    )


def test_compliance_score_range():
    """Compliance score must always be within [0, 100] regardless of findings."""
    mapper = ComplianceMapper()

    # Empty findings — perfect score
    empty_report = mapper.generate_compliance_report([])
    assert 0.0 <= empty_report["compliance_score"] <= 100.0, (
        f"Empty findings score out of range: {empty_report['compliance_score']}"
    )

    # Many critical findings — low score, but still in range
    findings = [
        Finding(
            rule_id=f"CRIT-{i}",
            file=f"app/file{i}.py",
            line=i,
            severity="CRITICAL",
            cwe_id="CWE-89",
        )
        for i in range(20)
    ]
    heavy_report = mapper.generate_compliance_report(findings)
    assert 0.0 <= heavy_report["compliance_score"] <= 100.0, (
        f"Score out of range for heavy findings: {heavy_report['compliance_score']}"
    )

    # Mixed findings
    mixed = [_sqli_finding(severity="HIGH"), _xss_finding(severity="MEDIUM")]
    mixed_report = mapper.generate_compliance_report(mixed)
    assert 0.0 <= mixed_report["compliance_score"] <= 100.0, (
        f"Score out of range for mixed findings: {mixed_report['compliance_score']}"
    )


def test_sarif_schema_version():
    """SARIF export must declare version '2.1.0'."""
    mapper = ComplianceMapper()
    sarif = mapper.to_sarif_enriched([_sqli_finding()])

    assert sarif.get("version") == "2.1.0", (
        f"Expected SARIF version '2.1.0', got: {sarif.get('version')}"
    )
    # Also confirm the $schema URL is present
    assert "sarif-2.1.0" in sarif.get("$schema", ""), (
        f"$schema URL does not reference sarif-2.1.0: {sarif.get('$schema')}"
    )


def test_sarif_has_results():
    """SARIF export with 2 findings must produce a results array of length 2."""
    findings = [_sqli_finding(rule_id="SQLI-001"), _xss_finding()]
    mapper = ComplianceMapper()
    sarif = mapper.to_sarif_enriched(findings)

    runs = sarif.get("runs", [])
    assert len(runs) == 1, f"Expected 1 run in SARIF, got {len(runs)}"

    results = runs[0].get("results", [])
    assert len(results) == 2, (
        f"Expected 2 SARIF results for 2 findings, got {len(results)}"
    )


def test_nist_gap_analysis():
    """Findings with known CWEs must produce NIST CSF control gaps in the report."""
    findings = [_sqli_finding(), _hardcoded_cred_finding()]
    mapper = ComplianceMapper()
    report = mapper.generate_compliance_report(findings, standards=["NIST_CSF"])

    nist_gaps = report.get("nist_csf_gaps", [])
    assert len(nist_gaps) > 0, (
        "Expected at least one NIST CSF gap for CWE-89 and CWE-798 findings."
    )
    # CWE-89 maps to PR.DS-1 per CWE_COMPLIANCE_MAP
    assert "PR.DS-1" in nist_gaps, (
        f"Expected PR.DS-1 in NIST gaps for CWE-89, gaps: {nist_gaps}"
    )


def test_batch_mapping_aggregation():
    """Three findings with the same CWE must all appear in the aggregated OWASP entry."""
    findings = [
        _sqli_finding(rule_id="SQLI-001", line=10),
        _sqli_finding(rule_id="SQLI-002", line=20),
        _sqli_finding(rule_id="SQLI-003", line=30),
    ]
    mapper = ComplianceMapper()
    batch = mapper.map_findings_batch(findings)

    # Total count
    assert batch["total_findings"] == 3, (
        f"Expected total_findings=3, got {batch['total_findings']}"
    )

    # All 3 rule_ids should appear under the Injection OWASP category
    owasp_agg = batch["aggregated"]["owasp_top10"]
    injection_cat = next(
        (cat for cat in owasp_agg if "Injection" in cat), None
    )
    assert injection_cat is not None, "OWASP Injection category not found in aggregation."
    assert set(owasp_agg[injection_cat]) == {"SQLI-001", "SQLI-002", "SQLI-003"}, (
        f"Not all SQLI rule_ids aggregated: {owasp_agg[injection_cat]}"
    )

    # T1190 must appear in ATT&CK aggregation (CWE-89 → T1190)
    attack_agg = batch["aggregated"]["mitre_attack_techniques"]
    assert "T1190" in attack_agg, (
        f"Expected T1190 in aggregated ATT&CK techniques; keys: {list(attack_agg.keys())}"
    )


def test_to_markdown_has_owasp_section():
    """to_markdown must produce output that contains an 'OWASP' section heading."""
    findings = [_sqli_finding(), _xss_finding()]
    mapper = ComplianceMapper()
    report = mapper.generate_compliance_report(findings)
    md = mapper.to_markdown(report)

    assert "OWASP" in md, "Markdown report must contain an OWASP section."
    assert "## OWASP" in md, "Markdown report must have an '## OWASP' heading."
    # Ensure the Injection category appears in the table
    assert "Injection" in md, (
        "Markdown report must include the OWASP Injection category for CWE-89 findings."
    )
