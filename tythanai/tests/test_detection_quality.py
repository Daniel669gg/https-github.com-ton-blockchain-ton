"""
TythanAI — Detection Quality Tests
=========================================
Unit tests for:
  1. ``core.analysis.rule_tuner.RuleTuner`` — per-rule confidence tuning
  2. ``tests.corpus.known_findings.CorpusValidator`` — TP/FP corpus regression

Run::

    python3 -m pytest tests/test_detection_quality.py -v
    # or via unittest:
    python3 -m unittest tests.test_detection_quality -v
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest

# ---------------------------------------------------------------------------
# Make sure the project root is on the path regardless of invocation style
# ---------------------------------------------------------------------------
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)


# ===========================================================================
# TestRuleTuner
# ===========================================================================

class TestRuleTuner(unittest.TestCase):
    """Tests for core.analysis.rule_tuner.RuleTuner."""

    def _make_tuner(self, rules_dict: dict):
        """Helper: build a RuleTuner from a dict without touching the filesystem."""
        from core.analysis.rule_tuner import RuleTuner
        return RuleTuner.from_dict({"rules": rules_dict})

    # ------------------------------------------------------------------
    # test_apply_confidence_delta
    # ------------------------------------------------------------------
    def test_apply_confidence_delta(self):
        """A rule with confidence_delta=-20 must reduce the finding's confidence."""
        tuner = self._make_tuner({
            "OWASP-SQL-001": {"confidence_delta": -20, "note": "too noisy"},
        })
        findings = [
            {"id": "OWASP-SQL-001", "confidence": 75, "severity": "HIGH"},
        ]
        result = tuner.apply(findings)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["confidence"], 55,
                         "confidence should drop from 75 to 55 (75 + -20)")

    def test_apply_confidence_delta_positive(self):
        """A rule with confidence_delta=+15 must increase the finding's confidence."""
        tuner = self._make_tuner({
            "TON-MF001": {"confidence_delta": 15, "note": "always real"},
        })
        findings = [{"id": "TON-MF001", "confidence": 70}]
        result = tuner.apply(findings)

        self.assertEqual(result[0]["confidence"], 85)

    def test_apply_confidence_delta_clamped_at_zero(self):
        """Confidence must not go below 0 after a large negative delta."""
        tuner = self._make_tuner({"RULE-X": {"confidence_delta": -50}})
        findings = [{"id": "RULE-X", "confidence": 30}]
        result = tuner.apply(findings)

        self.assertGreaterEqual(result[0]["confidence"], 0)

    def test_apply_confidence_delta_clamped_at_100(self):
        """Confidence must not exceed 100 after a large positive delta."""
        tuner = self._make_tuner({"RULE-Y": {"confidence_delta": 50}})
        findings = [{"id": "RULE-Y", "confidence": 90}]
        result = tuner.apply(findings)

        self.assertLessEqual(result[0]["confidence"], 100)

    # ------------------------------------------------------------------
    # test_disabled_rule_suppresses_finding
    # ------------------------------------------------------------------
    def test_disabled_rule_suppresses_finding(self):
        """A rule with enabled=False must set suppressed=True on matching findings."""
        tuner = self._make_tuner({
            "JAVA-003": {
                "enabled": False,
                "note": "Jackson configured globally with safe defaults",
            },
        })
        findings = [
            {"id": "JAVA-003", "confidence": 80, "severity": "MEDIUM"},
            {"id": "JAVA-001", "confidence": 70, "severity": "HIGH"},
        ]
        result = tuner.apply(findings)

        java003 = next(r for r in result if r["id"] == "JAVA-003")
        java001 = next(r for r in result if r["id"] == "JAVA-001")

        self.assertTrue(java003.get("suppressed"),
                        "JAVA-003 finding must be marked suppressed")
        self.assertFalse(java001.get("suppressed", False),
                         "JAVA-001 (no tuning) must not be suppressed")

    def test_disabled_rule_sets_tuning_note(self):
        """When a rule is disabled with a note, the note must appear in tuning_note."""
        note_text = "Jackson configured globally"
        tuner = self._make_tuner({
            "JAVA-003": {"enabled": False, "note": note_text},
        })
        result = tuner.apply([{"id": "JAVA-003", "confidence": 80}])

        self.assertEqual(result[0].get("tuning_note"), note_text)

    # ------------------------------------------------------------------
    # test_unknown_rule_passes_through
    # ------------------------------------------------------------------
    def test_unknown_rule_passes_through_unchanged(self):
        """A finding whose rule_id has no tuning entry must pass through unchanged."""
        tuner = self._make_tuner({"KNOWN-RULE": {"confidence_delta": -10}})
        original = {"id": "UNKNOWN-RULE", "confidence": 65, "severity": "HIGH"}
        result   = tuner.apply([original])

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["confidence"], 65)
        self.assertFalse(result[0].get("suppressed", False))
        self.assertNotIn("tuning_note", result[0])

    def test_unknown_rule_does_not_mutate_original(self):
        """apply() must not mutate the original finding dict."""
        tuner    = self._make_tuner({"SOME-RULE": {"confidence_delta": -15}})
        original = {"id": "SOME-RULE", "confidence": 70}
        _copy    = dict(original)
        tuner.apply([original])

        self.assertEqual(original, _copy, "Original dict must not be mutated")

    # ------------------------------------------------------------------
    # test_load_from_dict
    # ------------------------------------------------------------------
    def test_load_from_dict(self):
        """from_dict() must load rules and make get_tuning() return them."""
        from core.analysis.rule_tuner import RuleTuner, RuleTuning

        data  = {
            "rules": {
                "JAVA-001": {"confidence_delta": -20, "note": "noisy"},
                "JAVA-003": {"enabled": False, "note": "disabled"},
                "TON-MF001": {"confidence_delta": 15},
            }
        }
        tuner = RuleTuner.from_dict(data)

        java001 = tuner.get_tuning("JAVA-001")
        java003 = tuner.get_tuning("JAVA-003")
        ton_mf  = tuner.get_tuning("TON-MF001")

        self.assertIsInstance(java001, RuleTuning)
        self.assertEqual(java001.confidence_delta, -20)
        self.assertEqual(java001.note, "noisy")
        self.assertTrue(java001.enabled)

        self.assertIsInstance(java003, RuleTuning)
        self.assertFalse(java003.enabled)

        self.assertIsInstance(ton_mf, RuleTuning)
        self.assertEqual(ton_mf.confidence_delta, 15)

    def test_load_from_dict_returns_correct_count(self):
        """load() via config_paths must return the count of rules loaded."""
        from core.analysis.rule_tuner import RuleTuner

        content = "rules:\n  R1:\n    confidence_delta: -10\n  R2:\n    enabled: false\n"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            tuner = RuleTuner(config_paths=[tmp_path])
            count = tuner.load()
        finally:
            os.unlink(tmp_path)

        self.assertEqual(count, 2)

    def test_get_tuning_returns_none_for_unknown_rule(self):
        """get_tuning() must return None for a rule not in the config."""
        from core.analysis.rule_tuner import RuleTuner
        tuner = RuleTuner.from_dict({"rules": {}})
        self.assertIsNone(tuner.get_tuning("NONEXISTENT-RULE-999"))

    # ------------------------------------------------------------------
    # test_create_example_config_writes_valid_yaml
    # ------------------------------------------------------------------
    def test_create_example_config_writes_valid_yaml(self):
        """create_example_config() must write a YAML file parseable by PyYAML."""
        try:
            import yaml  # type: ignore[import]
        except ImportError:
            self.skipTest("PyYAML not installed")

        from core.analysis.rule_tuner import RuleTuner

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path    = os.path.join(tmpdir, "example_rule_tuning.yaml")
            tuner       = RuleTuner()
            written     = tuner.create_example_config(out_path)

            self.assertTrue(os.path.isfile(written),
                            f"Expected file at {written}")

            with open(written, "r", encoding="utf-8") as fh:
                parsed = yaml.safe_load(fh)

            self.assertIsInstance(parsed, dict, "YAML must parse to a dict")
            self.assertIn("rules", parsed,
                          "Parsed YAML must contain a 'rules' key")
            self.assertIsInstance(parsed["rules"], dict)
            # Must contain at least 5 rules as documented
            self.assertGreaterEqual(len(parsed["rules"]), 5,
                                    "Example config must document at least 5 rules")

    def test_create_example_config_returned_path_matches(self):
        """create_example_config() must return the resolved path it wrote."""
        from core.analysis.rule_tuner import RuleTuner

        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "sub", "rule_tuning.yaml")
            tuner    = RuleTuner()
            returned = tuner.create_example_config(out_path)

            self.assertTrue(os.path.isfile(returned))

    def test_tuning_note_on_confidence_delta(self):
        """When confidence_delta is applied with a note, tuning_note must be set."""
        tuner = self._make_tuner({
            "SEC-001": {"confidence_delta": -10, "note": "FP in fixtures"},
        })
        result = tuner.apply([{"id": "SEC-001", "confidence": 75}])
        self.assertEqual(result[0].get("tuning_note"), "FP in fixtures")

    def test_zero_delta_no_tuning_note(self):
        """A rule with confidence_delta=0 must not inject tuning_note."""
        tuner = self._make_tuner({"SEC-002": {"confidence_delta": 0}})
        result = tuner.apply([{"id": "SEC-002", "confidence": 75}])
        self.assertNotIn("tuning_note", result[0])

    def test_apply_uses_rule_id_field(self):
        """apply() should also respect 'rule_id' key, not only 'id'."""
        tuner = self._make_tuner({"ALIAS-001": {"confidence_delta": -15}})
        findings = [{"rule_id": "ALIAS-001", "confidence": 80}]
        result   = tuner.apply(findings)
        self.assertEqual(result[0]["confidence"], 65)

    def test_empty_findings_returns_empty_list(self):
        """apply() with empty list must return empty list."""
        tuner  = self._make_tuner({"R1": {"confidence_delta": -10}})
        result = tuner.apply([])
        self.assertEqual(result, [])

    def test_confidence_defaults_to_70_when_absent(self):
        """Findings without a 'confidence' key default to 70 before delta."""
        tuner = self._make_tuner({"NO-CONF": {"confidence_delta": -10}})
        result = tuner.apply([{"id": "NO-CONF"}])
        self.assertEqual(result[0]["confidence"], 60)


# ===========================================================================
# TestCorpusValidator
# ===========================================================================

class TestCorpusValidator(unittest.TestCase):
    """Tests for tests.corpus.known_findings.CorpusValidator."""

    @classmethod
    def setUpClass(cls):
        from tests.corpus.known_findings import (
            CorpusValidator,
            TRUE_POSITIVE_CORPUS,
            FALSE_POSITIVE_CORPUS,
        )
        cls.validator = CorpusValidator()
        cls.tp_corpus = TRUE_POSITIVE_CORPUS
        cls.fp_corpus = FALSE_POSITIVE_CORPUS

    # ------------------------------------------------------------------
    # test_true_positive_corpus_passes
    # ------------------------------------------------------------------
    def test_true_positive_corpus_passes(self):
        """True-positive corpus must achieve >70% pass rate."""
        results = self.validator.validate_all(self.tp_corpus)

        total  = results["total"]
        passed = results["passed"]
        rate   = passed / total if total else 0.0

        self.assertGreater(total, 0, "TP corpus must not be empty")
        self.assertGreaterEqual(
            rate, 0.70,
            f"TP pass rate {rate:.0%} below 70%. "
            f"Failures: {[d['name'] for d in results['details'] if not d['passed']]}",
        )

    # ------------------------------------------------------------------
    # test_false_positive_corpus_passes
    # ------------------------------------------------------------------
    def test_false_positive_corpus_passes(self):
        """False-positive corpus must achieve >70% pass rate (scanners must NOT fire)."""
        results = self.validator.validate_all(self.fp_corpus)

        total  = results["total"]
        passed = results["passed"]
        rate   = passed / total if total else 0.0

        self.assertGreater(total, 0, "FP corpus must not be empty")
        self.assertGreaterEqual(
            rate, 0.70,
            f"FP pass rate {rate:.0%} below 70%. "
            f"Failures: {[d['name'] for d in results['details'] if not d['passed']]}",
        )

    def test_true_positive_corpus_minimum_size(self):
        """True-positive corpus must contain at least 8 entries."""
        self.assertGreaterEqual(
            len(self.tp_corpus), 8,
            "Require at least 8 TP corpus entries for meaningful coverage",
        )

    def test_false_positive_corpus_minimum_size(self):
        """False-positive corpus must contain at least 5 entries."""
        self.assertGreaterEqual(
            len(self.fp_corpus), 5,
            "Require at least 5 FP corpus entries for meaningful coverage",
        )

    # ------------------------------------------------------------------
    # Individual entry spot-checks (fast, no scanner invocation needed)
    # ------------------------------------------------------------------
    def test_tp_entry_has_required_fields(self):
        """Every TP corpus entry must declare language, code, scanner, expected_rule."""
        required = {"language", "code", "scanner", "expected_rule"}
        for entry in self.tp_corpus:
            missing = required - entry.keys()
            self.assertFalse(
                missing,
                f"TP entry '{entry.get('name', '?')}' is missing fields: {missing}",
            )

    def test_fp_entry_has_required_fields(self):
        """Every FP corpus entry must declare language, code, scanner, expected_no_rule."""
        required = {"language", "code", "scanner", "expected_no_rule"}
        for entry in self.fp_corpus:
            missing = required - entry.keys()
            self.assertFalse(
                missing,
                f"FP entry '{entry.get('name', '?')}' is missing fields: {missing}",
            )

    def test_corpus_entries_have_non_trivial_code(self):
        """Each corpus entry must contain at least 3 lines of code."""
        all_entries = self.tp_corpus + self.fp_corpus
        for entry in all_entries:
            code_lines = [l for l in entry.get("code", "").splitlines() if l.strip()]
            self.assertGreaterEqual(
                len(code_lines), 3,
                f"Entry '{entry.get('name', '?')}' has only {len(code_lines)} non-empty lines",
            )

    # ------------------------------------------------------------------
    # validate_entry unit tests (without running a real scanner)
    # ------------------------------------------------------------------
    def test_validate_entry_unknown_scanner_returns_failed(self):
        """validate_entry() with an unknown scanner name must return passed=False."""
        result = self.validator.validate_entry({
            "name": "bad_scanner",
            "language": "python",
            "code": "x = 1",
            "scanner": "nonexistent_scanner_xyz",
            "expected_rule": "FAKE-001",
        })
        self.assertFalse(result["passed"])
        self.assertIn("Unknown scanner", result["reason"])

    def test_validate_entry_returns_findings_list(self):
        """validate_entry() must always return a 'findings' key with a list."""
        # Use a real TP entry
        entry  = self.tp_corpus[0]
        result = self.validator.validate_entry(entry)

        self.assertIn("findings", result)
        self.assertIsInstance(result["findings"], list)

    def test_validate_entry_true_positive_sql_injection(self):
        """The sql_injection_fstring TP entry must pass."""
        entry  = next(e for e in self.tp_corpus if e["name"] == "sql_injection_fstring")
        result = self.validator.validate_entry(entry)
        self.assertTrue(result["passed"], result["reason"])

    def test_validate_entry_false_positive_parameterized_query(self):
        """The parameterized_query_safe FP entry must pass (rule should NOT fire)."""
        entry  = next(e for e in self.fp_corpus if e["name"] == "parameterized_query_safe")
        result = self.validator.validate_entry(entry)
        self.assertTrue(result["passed"], result["reason"])

    def test_validate_entry_reason_is_non_empty_string(self):
        """validate_entry() must always return a non-empty 'reason' string."""
        entry  = self.tp_corpus[0]
        result = self.validator.validate_entry(entry)
        self.assertIsInstance(result["reason"], str)
        self.assertTrue(result["reason"].strip())

    # ------------------------------------------------------------------
    # test_report_format
    # ------------------------------------------------------------------
    def test_report_format(self):
        """report() must return a non-empty string containing summary statistics."""
        results = self.validator.validate_all(self.tp_corpus[:3])
        report  = self.validator.report(results)

        self.assertIsInstance(report, str)
        self.assertTrue(report.strip(), "report() must not return an empty string")
        # Must contain pass/fail counts in some form
        self.assertIn("Passed", report)
        self.assertIn("Failed", report)
        self.assertIn("Total",  report)

    def test_report_contains_entry_names(self):
        """report() must list the name of each validated entry."""
        subset  = self.tp_corpus[:2]
        results = self.validator.validate_all(subset)
        report  = self.validator.report(results)

        for entry in subset:
            self.assertIn(entry["name"], report,
                          f"Entry '{entry['name']}' should appear in report")

    def test_report_marks_failures_clearly(self):
        """report() must mark failed entries with FAIL (not just omit them)."""
        # Craft a deliberately-failing entry
        bad_entry = {
            "name": "intentional_fail_for_report_test",
            "language": "python",
            "code": "x = 1 + 1  # completely harmless",
            "scanner": "owasp",
            "expected_rule": "OW-DOES-NOT-EXIST-999",
        }
        results = self.validator.validate_all([bad_entry])
        report  = self.validator.report(results)

        self.assertIn("FAIL", report)

    # ------------------------------------------------------------------
    # Full combined corpus regression (integration)
    # ------------------------------------------------------------------
    def test_full_combined_corpus_above_70_percent(self):
        """Combined TP+FP corpus overall pass rate must exceed 70%."""
        combined = self.tp_corpus + self.fp_corpus
        results  = self.validator.validate_all(combined)

        total  = results["total"]
        passed = results["passed"]
        rate   = passed / total if total else 0.0

        failures = [d["name"] for d in results["details"] if not d["passed"]]
        self.assertGreaterEqual(
            rate, 0.70,
            f"Combined pass rate {rate:.0%} < 70%. Failing: {failures}",
        )

    def test_validate_all_keys_present(self):
        """validate_all() must return a dict with total, passed, failed, details."""
        results = self.validator.validate_all(self.tp_corpus[:1])
        for key in ("total", "passed", "failed", "details"):
            self.assertIn(key, results, f"Missing key '{key}' in validate_all result")

    def test_validate_all_counts_consistent(self):
        """passed + failed must equal total in validate_all output."""
        results = self.validator.validate_all(self.tp_corpus)
        self.assertEqual(
            results["passed"] + results["failed"],
            results["total"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
