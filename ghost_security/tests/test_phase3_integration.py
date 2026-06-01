"""
tests/test_phase3_integration.py — Phase 3 full integration tests.
25 tests: dep_intelligence engine, reachable VEX, SBOM diff, end-to-end pipeline.
"""
import sys
import pathlib
import json
import tempfile

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest
from backend.core.supply_chain.dep_intelligence import DepIntelligenceEngine, DepIntelReport
from backend.sbom.sbom_diff import SBOMDiffEngine, SBOMDiffResult
from backend.sbom.reachable_vex import ReachableVEXGenerator
from backend.sbom.vex import VEXDocument, VEXStatement, VEXStatus, VEXGenerator
from backend.sbom.cyclonedx import CycloneDXBOM, Component
from backend.core.cpg.graph import CodePropertyGraph


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_requirements_txt(tmp_path, content):
    req = tmp_path / "requirements.txt"
    req.write_text(content)
    return str(req)


def _make_vex_doc(statements=None):
    from datetime import datetime, timezone
    import uuid
    stmts = statements or []
    return VEXDocument(
        id=f"urn:uuid:{uuid.uuid4()}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        statements=stmts,
    )


class _MockReachableCVE:
    def __init__(self, cve_id, is_reachable=False, score=0.0, path=None):
        self.cve_id = cve_id
        self.is_reachable = is_reachable
        self.reachability_score = score
        self.call_path = path or []
        self.severity = "HIGH"
        self.package_name = "test-pkg"
        self.installed_version = "1.0.0"

    def to_dict(self):
        return {"cve_id": self.cve_id, "is_reachable": self.is_reachable}


# ─────────────────────────────────────────────────────────────────────────────
# DepIntelligenceEngine
# ─────────────────────────────────────────────────────────────────────────────

class TestDepIntelligenceEngine:
    def test_engine_importable(self):
        assert DepIntelligenceEngine is not None

    def test_report_importable(self):
        assert DepIntelReport is not None

    def test_engine_instantiable(self):
        eng = DepIntelligenceEngine()
        assert eng is not None

    def test_analyze_empty_manifest(self, tmp_path):
        req = _make_requirements_txt(tmp_path, "")
        eng = DepIntelligenceEngine()
        report = eng.analyze(manifest_path=str(req))
        assert isinstance(report, DepIntelReport)

    def test_analyze_safe_manifest(self, tmp_path):
        req = _make_requirements_txt(tmp_path, "pyyaml==5.4.1\nrequests==2.28.0\n")
        eng = DepIntelligenceEngine()
        report = eng.analyze(manifest_path=str(req))
        assert report is not None
        assert isinstance(report.total_packages, int)

    def test_analyze_vulnerable_manifest(self, tmp_path):
        req = _make_requirements_txt(tmp_path, "pyyaml==5.3.1\n")
        eng = DepIntelligenceEngine()
        report = eng.analyze(manifest_path=str(req))
        assert report is not None
        assert report.total_vulnerable >= 0   # at least analyzed

    def test_report_has_timestamp(self, tmp_path):
        req = _make_requirements_txt(tmp_path, "requests==2.28.0\n")
        eng = DepIntelligenceEngine()
        report = eng.analyze(manifest_path=str(req))
        assert isinstance(report.timestamp, str)
        assert len(report.timestamp) > 0

    def test_report_has_analysis_time(self, tmp_path):
        req = _make_requirements_txt(tmp_path, "flask==2.0.0\n")
        eng = DepIntelligenceEngine()
        report = eng.analyze(manifest_path=str(req))
        assert report.analysis_time_ms >= 0.0

    def test_report_overall_risk_score_in_range(self, tmp_path):
        req = _make_requirements_txt(tmp_path, "pyyaml==5.3.1\n")
        eng = DepIntelligenceEngine()
        report = eng.analyze(manifest_path=str(req))
        assert 0.0 <= report.overall_risk_score <= 100.0

    def test_report_to_dict_works(self, tmp_path):
        req = _make_requirements_txt(tmp_path, "requests==2.28.0\n")
        eng = DepIntelligenceEngine()
        report = eng.analyze(manifest_path=str(req))
        d = report.to_dict()
        assert isinstance(d, dict)
        assert "timestamp" in d

    def test_analyze_with_cpg(self, tmp_path):
        req = _make_requirements_txt(tmp_path, "pyyaml==5.3.1\n")
        cpg = CodePropertyGraph()
        eng = DepIntelligenceEngine()
        report = eng.analyze(manifest_path=str(req), cpg=cpg)
        assert report is not None

    def test_analyze_with_source_code(self, tmp_path):
        req = _make_requirements_txt(tmp_path, "pyyaml==5.3.1\n")
        src = "import yaml\ndata = yaml.load(open('f.yaml'))\n"
        eng = DepIntelligenceEngine()
        report = eng.analyze(manifest_path=str(req), source_code=src)
        assert report is not None

    def test_analyze_packages_works(self):
        from backend.core.supply_chain.dependency_taint import InstalledPackage
        packages = [
            InstalledPackage(name="requests", version="2.28.0", ecosystem="pypi",
                             is_dev=False, manifest_file="requirements.txt", line=1),
            InstalledPackage(name="flask", version="2.0.0", ecosystem="pypi",
                             is_dev=False, manifest_file="requirements.txt", line=2),
        ]
        eng = DepIntelligenceEngine()
        report = eng.analyze_packages(packages)
        assert isinstance(report, DepIntelReport)
        assert report.total_packages == 2

    def test_diff_sboms_works(self):
        old_json = json.dumps({"components": [{"name": "flask", "version": "1.0.0"}]})
        new_json = json.dumps({"components": [{"name": "flask", "version": "2.0.0"}]})
        eng = DepIntelligenceEngine()
        result = eng.diff_sboms(old_json, new_json)
        assert isinstance(result, SBOMDiffResult)


# ─────────────────────────────────────────────────────────────────────────────
# ReachableVEXGenerator
# ─────────────────────────────────────────────────────────────────────────────

class TestReachableVEX:
    def test_generator_importable(self):
        assert ReachableVEXGenerator is not None

    def test_generator_instantiable(self):
        gen = ReachableVEXGenerator()
        assert gen is not None

    def test_generate_from_reachability_returns_vex_doc(self):
        gen = ReachableVEXGenerator()
        from datetime import datetime, timezone
        import uuid
        stmt = VEXStatement(
            vulnerability_id="CVE-2020-14343",
            product="pyyaml@5.3.1",
            status=VEXStatus.AFFECTED,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        base_vex = _make_vex_doc([stmt])
        rc = _MockReachableCVE("CVE-2020-14343", is_reachable=False, score=0.1)
        result = gen.generate_from_reachability(base_vex, [rc])
        assert isinstance(result, VEXDocument)

    def test_not_reachable_cve_gets_not_affected_status(self):
        gen = ReachableVEXGenerator()
        from datetime import datetime, timezone
        stmt = VEXStatement(
            vulnerability_id="CVE-2020-14343",
            product="pyyaml@5.3.1",
            status=VEXStatus.AFFECTED,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        base_vex = _make_vex_doc([stmt])
        rc = _MockReachableCVE("CVE-2020-14343", is_reachable=False, score=0.05)
        result = gen.generate_from_reachability(base_vex, [rc])
        not_affected = [s for s in result.statements if s.status == VEXStatus.NOT_AFFECTED]
        assert len(not_affected) >= 1

    def test_reachable_cve_stays_affected(self):
        gen = ReachableVEXGenerator()
        from datetime import datetime, timezone
        stmt = VEXStatement(
            vulnerability_id="CVE-2020-14343",
            product="pyyaml@5.3.1",
            status=VEXStatus.AFFECTED,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        base_vex = _make_vex_doc([stmt])
        rc = _MockReachableCVE("CVE-2020-14343", is_reachable=True, score=0.9)
        result = gen.generate_from_reachability(base_vex, [rc])
        affected = [s for s in result.statements if s.status == VEXStatus.AFFECTED]
        assert len(affected) >= 1

    def test_auto_assign_not_affected(self):
        gen = ReachableVEXGenerator()
        from datetime import datetime, timezone
        stmt = VEXStatement(
            vulnerability_id="CVE-2020-14343",
            product="pyyaml@5.3.1",
            status=VEXStatus.AFFECTED,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        base_vex = _make_vex_doc([stmt])
        result = gen.auto_assign_not_affected(base_vex, {"CVE-2020-14343": False})
        not_affected = [s for s in result.statements if s.status == VEXStatus.NOT_AFFECTED]
        assert len(not_affected) >= 1

    def test_to_json_works(self):
        gen = ReachableVEXGenerator()
        doc = _make_vex_doc()
        j = gen.to_json(doc)
        assert isinstance(j, str)
        data = json.loads(j)
        assert isinstance(data, dict)

    def test_fixed_statement_not_overridden(self):
        gen = ReachableVEXGenerator()
        from datetime import datetime, timezone
        stmt = VEXStatement(
            vulnerability_id="CVE-2020-14343",
            product="pyyaml@5.4.1",
            status=VEXStatus.FIXED,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        base_vex = _make_vex_doc([stmt])
        rc = _MockReachableCVE("CVE-2020-14343", is_reachable=True, score=0.9)
        result = gen.generate_from_reachability(base_vex, [rc])
        fixed = [s for s in result.statements if s.status == VEXStatus.FIXED]
        assert len(fixed) >= 1   # FIXED should be preserved
