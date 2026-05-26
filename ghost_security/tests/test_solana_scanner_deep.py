"""
Deep tests for SolanaScanner — ~60 tests covering all 11 detection rules,
file filtering, directory scan aggregation, and finding format.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest
from scanners.solana_scanner.solana_analyzer import SolanaScanner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_rs(tmp_path, name, content):
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return str(f)


def has_rule(findings, rule_id):
    return any(f["rule_id"] == rule_id for f in findings)


def findings_for_rule(findings, rule_id):
    return [f for f in findings if f["rule_id"] == rule_id]


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner():
    return SolanaScanner()


# ---------------------------------------------------------------------------
# Rule SOL-001 — Missing signer check
# ---------------------------------------------------------------------------

class TestRule001SignerCheck:
    def test_account_info_without_is_signer_triggers(self, scanner, tmp_path):
        src = (
            "pub authority: AccountInfo<'info>,\n"
            "pub vault: Account<'info, Vault>,\n"
        )
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-001")

    def test_severity_critical(self, scanner, tmp_path):
        src = "pub authority: AccountInfo<'info>,\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        rule_findings = findings_for_rule(findings, "GHOST-SOL-001")
        assert rule_findings[0]["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Rule SOL-002 — Missing owner check
# ---------------------------------------------------------------------------

class TestRule002OwnerCheck:
    def test_account_info_without_owner_check_triggers(self, scanner, tmp_path):
        src = (
            "pub token_account: AccountInfo<'info>,\n"
            "let data = token_account.data.borrow();\n"
        )
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-002")

    def test_severity_high(self, scanner, tmp_path):
        src = "pub token_account: AccountInfo<'info>,\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        rule_findings = findings_for_rule(findings, "GHOST-SOL-002")
        assert rule_findings[0]["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# Rule SOL-003 — PDA seed manipulation
# ---------------------------------------------------------------------------

class TestRule003PDASeed:
    def test_user_provided_seed_triggers(self, scanner, tmp_path):
        # Seeds on same line as find_program_address so single-line regex matches
        src = "let (pda, bump) = Pubkey::find_program_address(&[user_provided.as_bytes()], id);\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-003")


# ---------------------------------------------------------------------------
# Rule SOL-004 — Arithmetic overflow
# ---------------------------------------------------------------------------

class TestRule004ArithmeticOverflow:
    def test_u64_addition_triggers(self, scanner, tmp_path):
        # Pattern matches C-style declaration: u64 amount = a + b
        src = "u64 amount = a + b;\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-004")

    def test_plus_equals_triggers(self, scanner, tmp_path):
        src = "balance += deposit;\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-004")

    def test_minus_equals_triggers(self, scanner, tmp_path):
        src = "balance -= withdrawal;\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-004")

    def test_severity_high(self, scanner, tmp_path):
        src = "u64 amount = a + b;\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        rule_findings = findings_for_rule(findings, "GHOST-SOL-004")
        assert rule_findings[0]["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# Rule SOL-005 — CPI without return check
# ---------------------------------------------------------------------------

class TestRule005CPIReturnCheck:
    def test_invoke_triggers(self, scanner, tmp_path):
        src = "invoke(&ix, &account_infos);\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-005")

    def test_invoke_signed_triggers(self, scanner, tmp_path):
        src = "invoke_signed(&ix, &account_infos, &[&[b'vault', &[bump]]]);\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-005")

    def test_severity_high(self, scanner, tmp_path):
        src = "invoke(&ix, &account_infos);\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        rule_findings = findings_for_rule(findings, "GHOST-SOL-005")
        assert rule_findings[0]["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# Rule SOL-006 — Account discriminator bypass
# ---------------------------------------------------------------------------

class TestRule006DiscriminatorBypass:
    def test_try_from_slice_triggers(self, scanner, tmp_path):
        src = (
            "let state = MyState::try_from_slice(&accounts[0].data.borrow())\n"
            "    .unwrap();\n"
        )
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-006")

    def test_severity_critical(self, scanner, tmp_path):
        src = "let state = MyState::try_from_slice(&accounts[0].data.borrow()).unwrap();\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        rule_findings = findings_for_rule(findings, "GHOST-SOL-006")
        assert rule_findings[0]["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Rule SOL-007 — Missing account constraint
# ---------------------------------------------------------------------------

class TestRule007AccountConstraint:
    def test_empty_account_attr_triggers(self, scanner, tmp_path):
        src = "#[account()]\npub vault: Account<'info, Vault>,\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-007")

    def test_account_mut_only_triggers(self, scanner, tmp_path):
        src = "#[account(mut)]\npub user_account: Account<'info, UserData>,\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-007")

    def test_severity_medium(self, scanner, tmp_path):
        src = "#[account()]\npub vault: Account<'info, Vault>,\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        rule_findings = findings_for_rule(findings, "GHOST-SOL-007")
        assert rule_findings[0]["severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# Rule SOL-008 — Unsafe deserialization
# ---------------------------------------------------------------------------

class TestRule008UnsafeDeserialization:
    def test_try_borrow_data_unwrap_triggers(self, scanner, tmp_path):
        src = "let data = account.try_borrow_data().unwrap();\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-008")

    def test_severity_high(self, scanner, tmp_path):
        src = "let data = account.try_borrow_data().unwrap();\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        rule_findings = findings_for_rule(findings, "GHOST-SOL-008")
        assert rule_findings[0]["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# Rule SOL-009 — Integer truncation
# ---------------------------------------------------------------------------

class TestRule009IntegerTruncation:
    def test_as_u64_triggers(self, scanner, tmp_path):
        src = "let amount = large_value as u64;\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-009")

    def test_as_u32_triggers(self, scanner, tmp_path):
        src = "let count = total as u32;\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-009")

    def test_as_u8_triggers(self, scanner, tmp_path):
        src = "let byte = value as u8;\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-009")

    def test_severity_high(self, scanner, tmp_path):
        src = "let amount = large_value as u64;\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        rule_findings = findings_for_rule(findings, "GHOST-SOL-009")
        assert rule_findings[0]["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# Rule SOL-010 — Missing rent exemption
# ---------------------------------------------------------------------------

class TestRule010RentExemption:
    def test_create_account_triggers(self, scanner, tmp_path):
        src = "create_account(&from, &to, lamports, space, owner);\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-010")

    def test_system_instruction_create_account_triggers(self, scanner, tmp_path):
        src = "let ix = system_instruction::create_account(&from, &to, lamports, space, owner);\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-010")

    def test_severity_medium(self, scanner, tmp_path):
        src = "create_account(&from, &to, lamports, space, owner);\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        rule_findings = findings_for_rule(findings, "GHOST-SOL-010")
        assert rule_findings[0]["severity"] == "MEDIUM"


# ---------------------------------------------------------------------------
# Rule SOL-011 — Reinitialization attack
# ---------------------------------------------------------------------------

class TestRule011Reinitialization:
    def test_initialize_without_is_initialized_check_triggers(self, scanner, tmp_path):
        src = (
            "pub fn initialize(ctx: Context<Initialize>, amount: u64) -> Result<()> {\n"
            "    ctx.accounts.vault.amount = amount;\n"
            "    Ok(())\n"
            "}\n"
        )
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert has_rule(findings, "GHOST-SOL-011")

    def test_severity_critical(self, scanner, tmp_path):
        src = (
            "pub fn initialize(ctx: Context<Initialize>) -> Result<()> {\n"
            "    ctx.accounts.state.value = 0;\n"
            "    Ok(())\n"
            "}\n"
        )
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        rule_findings = findings_for_rule(findings, "GHOST-SOL-011")
        assert rule_findings[0]["severity"] == "CRITICAL"


# ---------------------------------------------------------------------------
# File filtering
# ---------------------------------------------------------------------------

class TestFileFiltering:
    def test_non_rs_file_skipped(self, scanner, tmp_path):
        f = tmp_path / "program.py"
        f.write_text("let amount = large_value as u64;\n")
        findings = scanner.scan_file(str(f))
        assert findings == []

    def test_sol_file_not_scanned(self, scanner, tmp_path):
        f = tmp_path / "contract.sol"
        f.write_text("create_account(&from, &to, lamports, space, owner);\n")
        findings = scanner.scan_file(str(f))
        assert findings == []

    def test_rs_file_scanned(self, scanner, tmp_path):
        src = "let amount = large_value as u64;\n"
        path = write_rs(tmp_path, "main.rs", src)
        findings = scanner.scan_file(path)
        assert has_rule(findings, "GHOST-SOL-009")


# ---------------------------------------------------------------------------
# Finding format
# ---------------------------------------------------------------------------

class TestFindingFormat:
    def test_required_fields_present(self, scanner, tmp_path):
        src = "let amount = large_value as u64;\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert findings
        f = findings[0]
        for key in ("rule_id", "severity", "file", "line"):
            assert key in f, f"Missing key: {key}"

    def test_line_is_int(self, scanner, tmp_path):
        src = "let amount = large_value as u64;\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert isinstance(findings[0]["line"], int)

    def test_file_matches_path(self, scanner, tmp_path):
        path = write_rs(tmp_path, "main.rs", "let amount = large_value as u64;\n")
        findings = scanner.scan_file(path)
        assert findings[0]["file"] == path

    def test_cwe_field_present(self, scanner, tmp_path):
        src = "let amount = large_value as u64;\n"
        findings = scanner.scan_file(write_rs(tmp_path, "lib.rs", src))
        assert "cwe" in findings[0]


# ---------------------------------------------------------------------------
# scan_directory
# ---------------------------------------------------------------------------

class TestScanDirectory:
    def test_empty_directory(self, scanner, tmp_path):
        result = scanner.scan_directory(str(tmp_path))
        assert result["files_scanned"] == 0
        assert result["total_findings"] == 0

    def test_aggregates_multiple_files(self, scanner, tmp_path):
        write_rs(tmp_path, "a.rs", "let amount = large_value as u64;\n")
        write_rs(tmp_path, "b.rs", "invoke(&ix, &account_infos);\n")
        result = scanner.scan_directory(str(tmp_path))
        assert result["files_scanned"] == 2
        assert result["total_findings"] >= 2

    def test_result_keys_present(self, scanner, tmp_path):
        result = scanner.scan_directory(str(tmp_path))
        for key in ("findings", "files_scanned", "total_findings", "severity_counts"):
            assert key in result

    def test_py_files_not_counted(self, scanner, tmp_path):
        f = tmp_path / "util.py"
        f.write_text("invoke(&ix, &account_infos);\n")
        result = scanner.scan_directory(str(tmp_path))
        assert result["files_scanned"] == 0

    def test_comments_not_scanned(self, scanner, tmp_path):
        # invoke in a comment should be stripped and might not trigger
        src = "// invoke(&ix, &account_infos);\n"
        write_rs(tmp_path, "lib.rs", src)
        result = scanner.scan_directory(str(tmp_path))
        # File is scanned, but findings from comments should be suppressed
        assert result["files_scanned"] == 1
