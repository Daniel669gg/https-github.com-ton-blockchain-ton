"""
Tests — Extended TON Scanner + Bug Bounty Report Generator
Run: python3 -m unittest tests.test_ton_extended -v
"""
import os, sys, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Vulnerable contract snippets ──────────────────────────────────────────────
_DRAIN_128 = """
() recv_internal(int msg_value, cell in_msg_cell, slice in_msg_body) impure {
    slice sender = cs~load_msg_addr();
    send_raw_message(build_msg(), 128);
}
"""
_UNAUTH_SET_CODE = """
() upgrade(slice in_msg_body) impure {
    cell new_code = in_msg_body~load_ref();
    set_code(new_code);
}
"""
_NO_SIG_EXTERNAL = """
() recv_external(slice in_msg_body) impure {
    accept_message();
    int seqno = in_msg_body~load_uint(32);
}
"""
_BALANCE_UNDERFLOW = """
() transfer(int amount) impure {
    int jetton_balance = load_balance();
    jetton_balance -= amount;
    save_balance(jetton_balance);
}
"""
_FAKE_NOTIFICATION = """
() recv_internal(int v, cell c, slice s) impure {
    int op = s~load_uint(32);
    if (op == op::transfer_notification) {
        int amount = s~load_coins();
        credit_user(amount);
    }
}
"""
_PREDICTABLE_RAND = """
int pick_winner() {
    randomize_lt();
    return rand(100);
}
"""
_SAFE_CONTRACT = """
() recv_internal(int msg_value, cell in_msg_cell, slice in_msg_body) impure {
    slice sender = force_chain(0, cs~load_msg_addr());
    int op = in_msg_body~load_uint(32);
    int query_id = in_msg_body~load_uint(64);
    throw_unless(error::unauthorized, equal_slices(sender, storage::owner));
    throw_unless(error::insufficient, msg_value >= min_fee);
    raw_reserve(storage_fee, 2);
    if (op == op::transfer) {
        int amount = in_msg_body~load_coins();
        int balance = storage::balance;
        throw_unless(error::balance, balance >= amount);
        balance -= amount;
        storage::balance = balance;
        set_data(pack_storage());
        send_raw_message(build_msg(), 64);
    } else {
        throw(error::unknown_op);
    }
}
"""


class TONExtendedScannerTests(unittest.TestCase):

    def setUp(self):
        from scanners.ton_scanner.ton_analyzer import TONAnalyzer
        self.analyzer = TONAnalyzer()
        self._tmpdir  = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _scan(self, code: str, suffix: str = ".fc") -> list:
        path = os.path.join(self._tmpdir, f"test{suffix}")
        with open(path, "w") as f:
            f.write(code)
        return self.analyzer.analyze_file(path)

    def _ids(self, findings: list) -> set:
        return {f.get("rule_id") or f.get("id") for f in findings}

    # ── Fund drain ────────────────────────────────────────────────────────────

    def test_mode128_drain_detected(self):
        findings = self._scan(_DRAIN_128)
        ids = self._ids(findings)
        self.assertTrue(
            ids & {"TON-FUND-001", "TON002", "TON-DRAIN-RESERVE"},
            f"Mode-128 drain not found. Got: {ids}"
        )

    def test_mode128_severity_critical(self):
        findings = self._scan(_DRAIN_128)
        crits = [f for f in findings if f.get("severity") == "CRITICAL"]
        self.assertGreater(len(crits), 0, "No CRITICAL findings for mode-128 drain")

    # ── Unauthorised upgrade ──────────────────────────────────────────────────

    def test_unauth_set_code_detected(self):
        findings = self._scan(_UNAUTH_SET_CODE)
        ids = self._ids(findings)
        self.assertTrue(
            ids & {"TON-UPG-001", "TON018", "TON-UPG-UNAUTH"},
            f"Unauthorised set_code not found. Got: {ids}"
        )

    def test_upgrade_critical_severity(self):
        findings = self._scan(_UNAUTH_SET_CODE)
        crits = [f for f in findings
                 if f.get("severity") == "CRITICAL"
                 and "set_code" in f.get("description","").lower()]
        self.assertGreater(len(crits), 0)

    # ── External without signature ────────────────────────────────────────────

    def test_recv_external_no_sig(self):
        findings = self._scan(_NO_SIG_EXTERNAL)
        ids = self._ids(findings)
        self.assertTrue(
            ids & {"TON015", "TON-GAS-UNAUTH", "TON-REPLAY-EXT"},
            f"Missing external-sig checks not found. Got: {ids}"
        )

    # ── Jetton balance underflow ───────────────────────────────────────────────

    def test_balance_underflow_detected(self):
        findings = self._scan(_BALANCE_UNDERFLOW)
        ids = self._ids(findings)
        self.assertTrue(
            ids & {"TON-JET-004", "TON-JET-UNDERFLOW"},
            f"Balance underflow not detected. Got: {ids}"
        )

    # ── Fake jetton notification ──────────────────────────────────────────────

    def test_fake_jetton_notification(self):
        findings = self._scan(_FAKE_NOTIFICATION)
        ids = self._ids(findings)
        self.assertTrue(
            ids & {"TON-JET-FAKE", "TON028"},
            f"Fake jetton notification not detected. Got: {ids}"
        )

    # ── Predictable randomness ────────────────────────────────────────────────

    def test_predictable_rand_detected(self):
        findings = self._scan(_PREDICTABLE_RAND)
        ids = self._ids(findings)
        self.assertTrue(
            ids & {"TON-RAND-001", "TON008", "TON024"},
            f"Predictable randomness not detected. Got: {ids}"
        )

    # ── Safe contract = no critical/high ─────────────────────────────────────

    def test_safe_contract_no_critical(self):
        findings = self._scan(_SAFE_CONTRACT)
        crits = [f for f in findings if f.get("severity") == "CRITICAL"]
        highs = [f for f in findings if f.get("severity") == "HIGH"]
        self.assertEqual(len(crits), 0, f"False positive CRITICALs: {[f['id'] for f in crits]}")
        self.assertEqual(len(highs), 0, f"False positive HIGHs: {[f['id'] for f in highs]}")

    # ── Tact support ──────────────────────────────────────────────────────────

    def test_tact_unauth_receive(self):
        tact_code = """
contract Vault {
    owner: Address;
    balance: Int as coins;
    receive(msg: Withdraw) {
        self.balance -= msg.amount;
        send(SendParameters{ to: msg.to, value: msg.amount });
    }
}
"""
        findings = self._scan(tact_code, suffix=".tact")
        ids = self._ids(findings)
        self.assertTrue(
            ids & {"TON-TACT-UNAUTH", "TON033"},
            f"Tact unauthorized receive not detected. Got: {ids}"
        )

    # ── Dataflow ──────────────────────────────────────────────────────────────

    def test_op_dispatch_no_default(self):
        code = """
() recv_internal(int msg_value, cell c, slice s) impure {
    int op = s~load_uint(32);
    if (op == 0x12345678) { do_transfer(); }
    if (op == 0xabcdef01) { do_stake(); }
    if (op == 0x11111111) { do_unstake(); }
}
"""
        findings = self._scan(code)
        ids = self._ids(findings)
        self.assertIn("TON-DF-004", ids, "Missing default op dispatch not detected")

    # ── Rule count ────────────────────────────────────────────────────────────

    def test_total_rule_count(self):
        from scanners.ton_scanner.ton_rules_extended import (
            EXTENDED_LINE_RULES, EXTENDED_CONTEXT_RULES
        )
        total = 28 + len(EXTENDED_LINE_RULES) + len(EXTENDED_CONTEXT_RULES) + 4
        self.assertGreaterEqual(total, 87, f"Expected 87+ rules, got {total}")


class BountyReportTests(unittest.TestCase):

    def _sample_findings(self) -> list:
        return [
            {
                "rule_id":     "TON-FUND-001",
                "id":          "TON-FUND-001",
                "severity":    "CRITICAL",
                "category":    "Fund Flow",
                "file":        "wallet.fc",
                "line":        15,
                "message":     "send_raw_message mode=128 — forwards ENTIRE contract balance",
                "description": "send_raw_message mode=128 forwards entire contract balance including storage reserve",
                "recommendation": "Use raw_reserve(min_storage, 2) before mode-128 send",
                "evidence":    "send_raw_message(msg, 128);",
                "cwe":         "CWE-691",
                "known_impact":"Complete fund drain — contract loses all TON",
                "bounty_class":"fund_drain",
                "confidence":  0.95,
            },
            {
                "rule_id":     "TON015",
                "severity":    "CRITICAL",
                "category":    "Authentication",
                "file":        "wallet.fc",
                "line":        30,
                "message":     "recv_external without signature verification",
                "description": "recv_external with no signature check — any actor can call",
                "recommendation": "Add: throw_unless(err, check_signature(hash, sig, pubkey));",
                "cwe":         "CWE-287",
                "confidence":  0.92,
            },
            {
                "rule_id":     "TON-RAND-001",
                "severity":    "HIGH",
                "category":    "Randomness",
                "file":        "lottery.fc",
                "line":        45,
                "message":     "randomize_lt() — validator-manipulable seed",
                "description": "randomize_lt() uses block lt as seed; validators can predict outcome",
                "recommendation": "Use commit-reveal scheme for high-value randomness",
                "cwe":         "CWE-338",
                "confidence":  0.88,
            },
        ]

    def test_report_generation(self):
        from reports.bounty_report import BugBountyReportGenerator
        gen     = BugBountyReportGenerator("TestContract.fc")
        reports = gen.from_findings(self._sample_findings(), min_severity="HIGH")
        self.assertGreater(len(reports), 0)

    def test_immunefi_markdown_structure(self):
        from reports.bounty_report import BugBountyReportGenerator
        gen     = BugBountyReportGenerator("TestContract.fc")
        reports = gen.from_findings(self._sample_findings())
        md = reports[0].immunefi_markdown()
        for section in ["## Summary", "## Impact", "## Recommendation", "## References"]:
            self.assertIn(section, md, f"Missing section: {section}")

    def test_hackenproof_json_structure(self):
        from reports.bounty_report import BugBountyReportGenerator
        gen     = BugBountyReportGenerator("TestContract.fc")
        reports = gen.from_findings(self._sample_findings())
        j = reports[0].hackenproof_json()
        for key in ["title", "severity", "description", "impact", "recommendation"]:
            self.assertIn(key, j)

    def test_executive_summary_contains_bounty_range(self):
        from reports.bounty_report import BugBountyReportGenerator
        gen     = BugBountyReportGenerator("TestContract.fc")
        summary = gen.executive_summary(self._sample_findings())
        self.assertIn("Estimated bounty range", summary)
        self.assertIn("$", summary)
        self.assertIn("Responsible Disclosure", summary)

    def test_severity_filter(self):
        from reports.bounty_report import BugBountyReportGenerator
        gen      = BugBountyReportGenerator("TestContract.fc")
        findings = self._sample_findings()
        findings.append({
            "rule_id": "TON-LOW", "severity": "LOW",
            "message": "low severity finding", "category": "Gas Control",
            "file": "contract.fc", "line": 1, "confidence": 0.7,
        })
        critical_only = gen.from_findings(findings, min_severity="CRITICAL")
        self.assertTrue(all(r.severity == "CRITICAL" for r in critical_only))

    def test_report_has_message_not_empty(self):
        from reports.bounty_report import BugBountyReportGenerator
        gen     = BugBountyReportGenerator("TestContract.fc")
        reports = gen.from_findings(self._sample_findings())
        for r in reports:
            self.assertTrue(r.description.strip(), f"Empty description in {r.title}")
            self.assertTrue(r.impact.strip(),      f"Empty impact in {r.title}")
            self.assertTrue(r.recommendation.strip(), f"Empty recommendation in {r.title}")

    def test_file_output(self):
        import shutil
        from reports.bounty_report import BugBountyReportGenerator
        gen    = BugBountyReportGenerator("TestContract.fc")
        tmpdir = tempfile.mkdtemp()
        try:
            outputs = gen.generate_all(
                self._sample_findings(), tmpdir,
                min_severity="HIGH",
                formats=["markdown", "summary"],
            )
            self.assertGreater(len(outputs), 0)
            for path in outputs:
                self.assertTrue(os.path.exists(path), f"File not created: {path}")
                self.assertGreater(os.path.getsize(path), 100)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
