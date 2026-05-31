"""
TythanAI Platform — TON Extended Ruleset v2
60+ правил, основанных на реальных уязвимостях из публичных аудитов:
  • CertiK, Trail of Bits, Quantstamp, Hexens, Ackee отчёты по TON-контрактам
  • TON Security Best Practices (официальная документация)
  • Известные баги из bug bounty программ (Immunefi, HackenProof)

Категории:
  INTEGER_ARITHMETIC  — переполнения, truncation, деление на ноль
  FUND_FLOW           — некорректные режимы send, drain-уязвимости
  ACCESS_CONTROL      — отсутствие проверок sender/signature
  REPLAY_PROTECTION   — отсутствие seqno/query_id защиты
  STATE_MANAGEMENT    — reentrancy-like, CEI нарушения
  GAS_CONTROL         — gas griefing, accept_message злоупотребления
  JETTON_SAFETY       — уязвимости стандарта TEP-74
  NFT_SAFETY          — уязвимости стандарта TEP-62
  UPGRADE_SAFETY      — небезопасные апгрейды
  RANDOMNESS          — предсказуемая энтропия
  TACT_SPECIFIC       — уязвимости специфичные для Tact
  CELL_HANDLING       — некорректная работа с cells/slices
  CROSS_CONTRACT      — небезопасное взаимодействие контрактов
"""
from __future__ import annotations

import re
from typing import List, Dict, Tuple, Optional

# ══════════════════════════════════════════════════════════════════════════════
# РАСШИРЕННЫЕ LINE_RULES (добавляются к существующим 28)
# ══════════════════════════════════════════════════════════════════════════════

EXTENDED_LINE_RULES: List[Dict] = [

    # ── INTEGER ARITHMETIC ────────────────────────────────────────────────────

    {
        "id": "TON-INT-001",
        "pattern": r"\b(\d+)\s*<<\s*(\d+)\b",
        "severity": "MEDIUM",
        "cwe": "CWE-190",
        "category": "Integer Arithmetic",
        "description": "Bit-shift may overflow 257-bit TVM integer — verify result fits target type",
        "recommendation": "Assert result <= max_value before storing; use muldiv for scaled arithmetic",
        "bounty_class": "arithmetic",
    },
    {
        "id": "TON-INT-002",
        "pattern": r"\.store_int\s*\([^,]+,\s*([0-9]+)\s*\)",
        "severity": "MEDIUM",
        "cwe": "CWE-681",
        "category": "Integer Arithmetic",
        "description": "store_int with fixed bit-width — signed value may truncate silently",
        "recommendation": "Validate -(1 << (bits-1)) <= value < (1 << (bits-1)) before store_int",
        "bounty_class": "arithmetic",
    },
    {
        "id": "TON-INT-003",
        "pattern": r"\b(\w+)\s*/\s*(\w+)\b",
        "severity": "LOW",
        "cwe": "CWE-369",
        "category": "Integer Arithmetic",
        "description": "Division operator — verify divisor cannot be zero (TVM exception 5: integer divide by zero)",
        "recommendation": "Add throw_if(error::div_by_zero, denominator == 0) before division",
        "bounty_class": "arithmetic",
    },
    {
        "id": "TON-INT-004",
        "pattern": r"\babs\s*\(\s*-",
        "severity": "LOW",
        "cwe": "CWE-190",
        "category": "Integer Arithmetic",
        "description": "abs() on negative literal — in 257-bit TVM min integer has no positive counterpart",
        "recommendation": "Use muldiv or explicit range checks instead of abs for boundary values",
        "bounty_class": "arithmetic",
    },

    # ── FUND FLOW ─────────────────────────────────────────────────────────────

    {
        "id": "TON-FUND-001",
        "pattern": r"send_raw_message\s*\([^,]+,\s*(128)\s*\)",
        "severity": "CRITICAL",
        "cwe": "CWE-691",
        "category": "Fund Flow",
        "description": "send_raw_message mode=128 — forwards ENTIRE contract balance including storage reserve",
        "recommendation": "Mode 128 drains contract below min-storage; use mode 64 only to forward inbound value, mode 0 for fixed amounts",
        "bounty_class": "fund_drain",
        "known_impact": "Complete fund drain — HIGH bug bounty payout potential",
    },
    {
        "id": "TON-FUND-002",
        "pattern": r"send_raw_message\s*\([^,]+,\s*(64\s*\+\s*2|66)\s*\)",
        "severity": "HIGH",
        "cwe": "CWE-691",
        "category": "Fund Flow",
        "description": "send_raw_message mode=66 (64+2) — forwards remaining balance AND ignores errors; silent fund loss",
        "recommendation": "Avoid mode combinations with +2 (ignore errors) when forwarding value; handle send errors explicitly",
        "bounty_class": "fund_drain",
    },
    {
        "id": "TON-FUND-003",
        "pattern": r"\bmsg_value\s*-\s*\w+",
        "severity": "MEDIUM",
        "cwe": "CWE-191",
        "category": "Fund Flow",
        "description": "msg_value subtraction — may underflow if fee > msg_value (TVM exception on negative)",
        "recommendation": "Check msg_value >= fee before subtraction: throw_unless(err, msg_value >= storage_fee + gas_fee)",
        "bounty_class": "arithmetic",
    },
    {
        "id": "TON-FUND-004",
        "pattern": r"raw_reserve\s*\(\s*0\s*,",
        "severity": "HIGH",
        "cwe": "CWE-400",
        "category": "Fund Flow",
        "description": "raw_reserve(0, ...) — reserving zero amount; contract has no balance protection",
        "recommendation": "Reserve at least min_storage_fee: raw_reserve(storage_fee, 2) before sending",
        "bounty_class": "fund_drain",
    },
    {
        "id": "TON-FUND-005",
        "pattern": r"(?i)ton_amount\s*==\s*0",
        "severity": "MEDIUM",
        "cwe": "CWE-20",
        "category": "Fund Flow",
        "description": "Zero TON amount check — ensure operations requiring payment reject zero-value transfers",
        "recommendation": "throw_unless(error::insufficient_funds, ton_amount > 0) at entry of paid operations",
        "bounty_class": "logic",
    },

    # ── REPLAY PROTECTION ─────────────────────────────────────────────────────

    {
        "id": "TON-REPLAY-001",
        "pattern": r"\brecv_external\b",
        "severity": "HIGH",
        "cwe": "CWE-294",
        "category": "Replay Protection",
        "description": "recv_external entry — verify seqno or query_id incremented and stored to prevent replay",
        "recommendation": "Load seqno from storage; throw_unless(err, msg_seqno == stored_seqno); increment and save before accept_message()",
        "bounty_class": "replay",
        "known_impact": "Replay attacks can re-execute signed transactions",
    },
    {
        "id": "TON-REPLAY-002",
        "pattern": r"\bseqno\b(?!.*==\s*\w+.*seqno|.*seqno.*==)",
        "severity": "MEDIUM",
        "cwe": "CWE-294",
        "category": "Replay Protection",
        "description": "seqno referenced but equality check not detected in context — verify replay guard logic",
        "recommendation": "Pattern: int stored_seqno = data~load_uint(32); throw_unless(err, msg_seqno == stored_seqno);",
        "bounty_class": "replay",
    },

    # ── ACCESS CONTROL ────────────────────────────────────────────────────────

    {
        "id": "TON-AC-001",
        "pattern": r"(?i)\b(only_owner|only_admin|require_owner|assert_owner)\b",
        "severity": "INFO",
        "cwe": "CWE-284",
        "category": "Access Control",
        "description": "Owner guard function — verify it checks sender, not a stored flag that can be manipulated",
        "recommendation": "Guard must compare sender address: throw_unless(error::unauthorized, equal_slices(sender, owner))",
        "bounty_class": "access_control",
    },
    {
        "id": "TON-AC-002",
        "pattern": r"(?i)\b(manager|governance|controller)\s*:",
        "severity": "INFO",
        "cwe": "CWE-284",
        "category": "Access Control",
        "description": "Privileged role declared — verify all state-changing handlers check this role",
        "recommendation": "Centralise access checks in a single modifier-equivalent function called at entry",
        "bounty_class": "access_control",
    },
    {
        "id": "TON-AC-003",
        "pattern": r"slice_empty\?\s*\(",
        "severity": "LOW",
        "cwe": "CWE-284",
        "category": "Access Control",
        "description": "slice_empty? used as guard — empty slice may be valid sender in some contexts",
        "recommendation": "Use equal_slices() with a known address, not slice_empty? for access control",
        "bounty_class": "access_control",
    },
    {
        "id": "TON-AC-004",
        "pattern": r"(?i)force_chain\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-284",
        "category": "Access Control",
        "description": "force_chain — verify sender workchain before trusting address identity",
        "recommendation": "Call force_chain(workchain()) on all external addresses to prevent cross-chain spoofing",
        "bounty_class": "access_control",
    },

    # ── STATE MANAGEMENT (CEI violations / reentrancy-like) ───────────────────

    {
        "id": "TON-STATE-001",
        "pattern": r"send_raw_message\s*\(",
        "severity": "INFO",
        "cwe": "CWE-362",
        "category": "State Management",
        "description": "send_raw_message before set_data — check-effects-interactions: save state BEFORE sending",
        "recommendation": "Order: (1) validate, (2) compute new state, (3) set_data(pack()), (4) send_raw_message()",
        "bounty_class": "reentrancy",
        "known_impact": "If callback triggers re-entry, stale state is read — logic bugs possible",
    },
    {
        "id": "TON-STATE-002",
        "pattern": r"(?i)storage::\w+\s*=",
        "severity": "INFO",
        "cwe": "CWE-362",
        "category": "State Management",
        "description": "Storage field mutated — verify set_data() called to persist before any send",
        "recommendation": "Never mutate in-memory storage variables without calling set_data() before outgoing messages",
        "bounty_class": "reentrancy",
    },
    {
        "id": "TON-STATE-003",
        "pattern": r"(?i)\bin_msg_cell\b.*\bbegin_parse\b",
        "severity": "LOW",
        "cwe": "CWE-20",
        "category": "State Management",
        "description": "Parsing in_msg_cell directly — verify slice exhaustion checked after parsing",
        "recommendation": "Call slice.end_parse() after extracting all fields to detect malformed messages early",
        "bounty_class": "input_validation",
    },

    # ── GAS CONTROL ───────────────────────────────────────────────────────────

    {
        "id": "TON-GAS-001",
        "pattern": r"accept_message\s*\(\s*\)",
        "severity": "HIGH",
        "cwe": "CWE-400",
        "category": "Gas Control",
        "description": "accept_message() charges gas to contract — attacker can spam to exhaust balance",
        "recommendation": "Validate sender AND message content before accept_message(); add proof-of-work or whitelist",
        "bounty_class": "dos",
        "known_impact": "Gas drain DoS — drains contract balance through repeated external calls",
    },
    {
        "id": "TON-GAS-002",
        "pattern": r"\bwhile\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-400",
        "category": "Gas Control",
        "description": "while loop in contract — unbounded iteration may exceed block gas limit (TVM exception 13)",
        "recommendation": "Add iteration counter and cap: throw_if(error::gas_limit, iter > MAX_ITER)",
        "bounty_class": "dos",
    },
    {
        "id": "TON-GAS-003",
        "pattern": r"cell_depth\s*\(",
        "severity": "LOW",
        "cwe": "CWE-400",
        "category": "Gas Control",
        "description": "cell_depth accessed — deeply nested cells can cause exponential gas costs",
        "recommendation": "Cap cell depth <= 3; validate user-supplied cells with cell_depth check before traversal",
        "bounty_class": "dos",
    },
    {
        "id": "TON-GAS-004",
        "pattern": r"idict_get_next|udict_get_next",
        "severity": "LOW",
        "cwe": "CWE-400",
        "category": "Gas Control",
        "description": "Dictionary iteration — unbounded dict traversal can exhaust gas on large dictionaries",
        "recommendation": "Paginate with limit: track last_key and stop after MAX_ITEMS per transaction",
        "bounty_class": "dos",
    },

    # ── JETTON SAFETY (TEP-74) ────────────────────────────────────────────────

    {
        "id": "TON-JET-001",
        "pattern": r"op::transfer\s*=\s*0x0f8a7ea5",
        "severity": "INFO",
        "cwe": "CWE-20",
        "category": "Jetton Safety",
        "description": "Jetton transfer op-code — verify full TEP-74 message layout is parsed correctly",
        "recommendation": "Parse: query_id, amount, destination, response_destination, custom_payload, forward_ton_amount, forward_payload",
        "bounty_class": "token_safety",
    },
    {
        "id": "TON-JET-002",
        "pattern": r"op::transfer_notification\s*=\s*0x7362d09c",
        "severity": "INFO",
        "cwe": "CWE-20",
        "category": "Jetton Safety",
        "description": "Transfer notification handler — verify sender IS the expected jetton wallet, not any arbitrary contract",
        "recommendation": "Recompute expected_wallet = calculate_jetton_wallet(jetton_master, self_addr); throw_unless(err, sender == expected_wallet)",
        "bounty_class": "token_safety",
        "known_impact": "Fake jetton notification can spoof deposit events — critical in DeFi protocols",
    },
    {
        "id": "TON-JET-003",
        "pattern": r"(?i)jetton_amount\s*[+\-\*]=?\s*\w+",
        "severity": "MEDIUM",
        "cwe": "CWE-190",
        "category": "Jetton Safety",
        "description": "Jetton amount arithmetic — integer overflow/underflow can corrupt balances",
        "recommendation": "Verify jetton_amount + delta <= max_jetton_supply; use muldiv for scaling",
        "bounty_class": "arithmetic",
    },
    {
        "id": "TON-JET-004",
        "pattern": r"(?i)balance\s*-=\s*amount",
        "severity": "MEDIUM",  # Line rule; guard check done by TON-JET-UNDERFLOW context rule
        "cwe": "CWE-191",
        "category": "Jetton Safety",
        "description": "Balance decrement — must throw if balance < amount, not silently underflow",
        "recommendation": "throw_unless(error::insufficient_balance, balance >= amount); balance -= amount;",
        "bounty_class": "fund_drain",
        "known_impact": "Underflow can create infinite token supply — critical severity",
    },
    {
        "id": "TON-JET-005",
        "pattern": r"(?i)forward_ton_amount\s*==\s*0",
        "severity": "LOW",
        "cwe": "CWE-20",
        "category": "Jetton Safety",
        "description": "Zero forward_ton_amount — forward payload will not be processed if insufficient TON forwarded",
        "recommendation": "Ensure forward_ton_amount >= gas for callback; document minimum in contract interface",
        "bounty_class": "logic",
    },

    # ── NFT SAFETY (TEP-62) ───────────────────────────────────────────────────

    {
        "id": "TON-NFT-001",
        "pattern": r"op::transfer\s*=\s*0x5fcc3d14",
        "severity": "INFO",
        "cwe": "CWE-284",
        "category": "NFT Safety",
        "description": "NFT transfer op-code — verify new_owner address validated and ownership stored atomically",
        "recommendation": "Parse full TEP-62 layout; store new_owner before sending ownership notification",
        "bounty_class": "token_safety",
    },
    {
        "id": "TON-NFT-002",
        "pattern": r"op::get_static_data\s*=\s*0x2fcb26a2",
        "severity": "INFO",
        "cwe": "CWE-200",
        "category": "NFT Safety",
        "description": "NFT static data request — verify response sent back to correct address with correct query_id",
        "recommendation": "Always respond to get_static_data with op::report_static_data including original query_id",
        "bounty_class": "logic",
    },
    {
        "id": "TON-NFT-003",
        "pattern": r"(?i)individual_content",
        "severity": "LOW",
        "cwe": "CWE-20",
        "category": "NFT Safety",
        "description": "NFT individual content — verify content cell format matches TEP-64 metadata standard",
        "recommendation": "Follow TEP-64: snake-format or chunk-format; validate off-chain URI if used",
        "bounty_class": "logic",
    },

    # ── UPGRADE SAFETY ────────────────────────────────────────────────────────

    {
        "id": "TON-UPG-001",
        "pattern": r"\bset_code\s*\(",
        "severity": "CRITICAL",
        "cwe": "CWE-284",
        "category": "Upgrade Safety",
        "description": "set_code() — contract logic can be fully replaced; verify multisig or timelock",
        "recommendation": "Require N-of-M signatures or 48h timelock before upgrade; emit event for off-chain monitoring",
        "bounty_class": "upgrade",
        "known_impact": "Unrestricted set_code = complete contract takeover",
    },
    {
        "id": "TON-UPG-002",
        "pattern": r"(?i)upgrade\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-284",
        "category": "Upgrade Safety",
        "description": "Upgrade function — verify caller is multisig/DAO, not single EOA",
        "recommendation": "Require admin != single_address; implement 2-step upgrade with commit/apply phases",
        "bounty_class": "upgrade",
    },
    {
        "id": "TON-UPG-003",
        "pattern": r"(?i)migrate\s*\(",
        "severity": "HIGH",
        "cwe": "CWE-284",
        "category": "Upgrade Safety",
        "description": "Migration function — state migration must be atomic; partial migration leaves contract in broken state",
        "recommendation": "Pause contract during migration; verify new storage layout backward-compatible with old data",
        "bounty_class": "upgrade",
    },

    # ── RANDOMNESS ────────────────────────────────────────────────────────────

    {
        "id": "TON-RAND-001",
        "pattern": r"\brandomize_lt\s*\(\s*\)",
        "severity": "LOW",
        "cwe": "CWE-338",
        "category": "Randomness",
        "description": "randomize_lt() seeds PRNG with logical time — same block = same seed; validator-manipulable",
        "recommendation": "Mix external entropy: randomize(cell_hash(in_msg_cell) ^ lt ^ block_seed())",
        "bounty_class": "randomness",
        "known_impact": "Validators can predict or manipulate outcomes in same block (gambling, lotteries)",
    },
    {
        "id": "TON-RAND-002",
        "pattern": r"\bblock_seed\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-338",
        "category": "Randomness",
        "description": "block_seed() — seed is shared across all contracts in same block; predictable by validators",
        "recommendation": "Never use block_seed() alone for high-value randomness; use commit-reveal scheme",
        "bounty_class": "randomness",
    },

    # ── TACT SPECIFIC ─────────────────────────────────────────────────────────

    {
        "id": "TON-TACT-001",
        "pattern": r"(?i)\bself\.\w+\s*=\s*context\(\)\.sender",
        "severity": "MEDIUM",
        "cwe": "CWE-284",
        "category": "Tact Specific",
        "description": "Assigning context().sender to state — verify this is intentional ownership transfer, not initialization bug",
        "recommendation": "Owner should be set only in init(); subsequent changes require explicit owner check",
        "bounty_class": "access_control",
    },
    {
        "id": "TON-TACT-002",
        "pattern": r"(?i)\bnativeSendMessage\b",
        "severity": "HIGH",
        "cwe": "CWE-691",
        "category": "Tact Specific",
        "description": "nativeSendMessage() in Tact — low-level send bypasses Tact safety checks; verify mode and value",
        "recommendation": "Prefer Tact's send() / reply() / forward() which enforce type safety; use nativeSendMessage only if necessary",
        "bounty_class": "fund_drain",
    },
    {
        "id": "TON-TACT-003",
        "pattern": r"(?i)\bemit\s*\(",
        "severity": "INFO",
        "cwe": "CWE-200",
        "category": "Tact Specific",
        "description": "emit() in Tact — events are public; verify no sensitive data (keys, private addresses) in payload",
        "recommendation": "Emit only necessary data; hash sensitive values before emitting",
        "bounty_class": "information_disclosure",
    },
    {
        "id": "TON-TACT-004",
        "pattern": r"(?i)\brequire\s*\(\s*\w+\s*!=\s*null",
        "severity": "LOW",
        "cwe": "CWE-476",
        "category": "Tact Specific",
        "description": "Null check via require() — Tact null dereference throws exception 128; verify all optionals",
        "recommendation": "Use let x: Type? = ...; require(x != null, 'msg'); let val = x!!; pattern consistently",
        "bounty_class": "input_validation",
    },
    {
        "id": "TON-TACT-005",
        "pattern": r"(?i)\binit\s*\([^)]*\)\s*\{",
        "severity": "INFO",
        "cwe": "CWE-284",
        "category": "Tact Specific",
        "description": "Tact init() function — verify deployer address stored and used as initial owner",
        "recommendation": "Store self.owner = sender(); in init() or accept explicit owner parameter with validation",
        "bounty_class": "access_control",
    },

    # ── CELL HANDLING ─────────────────────────────────────────────────────────

    {
        "id": "TON-CELL-001",
        "pattern": r"\bbegin_cell\(\)",
        "severity": "INFO",
        "cwe": "CWE-20",
        "category": "Cell Handling",
        "description": "Cell builder started — verify total bits <= 1023 and refs <= 4 (TVM cell limits)",
        "recommendation": "Split large data across multiple cells using nested refs; validate layout at compile time",
        "bounty_class": "input_validation",
    },
    {
        "id": "TON-CELL-002",
        "pattern": r"slice_refs\s*\(",
        "severity": "LOW",
        "cwe": "CWE-125",
        "category": "Cell Handling",
        "description": "slice_refs() — verify expected number of refs present before loading",
        "recommendation": "throw_unless(err, slice_refs(s) >= expected_refs) before load_ref()",
        "bounty_class": "input_validation",
    },
    {
        "id": "TON-CELL-003",
        "pattern": r"\.skip_bits\s*\(",
        "severity": "LOW",
        "cwe": "CWE-125",
        "category": "Cell Handling",
        "description": "skip_bits() — may throw exception 9 if slice has fewer bits than requested",
        "recommendation": "Check slice_bits(s) >= N before skip_bits(N); wrap external message parsing in CATCH",
        "bounty_class": "input_validation",
    },

    # ── CROSS-CONTRACT INTERACTION ────────────────────────────────────────────

    {
        "id": "TON-CROSS-001",
        "pattern": r"(?i)calculate_\w+_address\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-345",
        "category": "Cross-Contract",
        "description": "Computed contract address — verify state_init matches expected code+data; don't trust user input",
        "recommendation": "Recompute address from known code cell + expected initial data; compare with sender",
        "bounty_class": "cross_contract",
        "known_impact": "Fake contract at computed address can impersonate trusted child contract",
    },
    {
        "id": "TON-CROSS-002",
        "pattern": r"(?i)deploy_contract\s*\(",
        "severity": "MEDIUM",
        "cwe": "CWE-284",
        "category": "Cross-Contract",
        "description": "Contract deployment — verify deployer authorization; arbitrary deployments waste contract gas",
        "recommendation": "Restrict who can trigger deployments; validate state_init code matches expected hash",
        "bounty_class": "access_control",
    },
    {
        "id": "TON-CROSS-003",
        "pattern": r"(?i)on_bounce\s*\(",
        "severity": "INFO",
        "cwe": "CWE-754",
        "category": "Cross-Contract",
        "description": "Bounce handler — verify it correctly reverses state changes made before the failed send",
        "recommendation": "Bounce handler must undo balance/state changes atomically; re-read storage inside handler",
        "bounty_class": "logic",
        "known_impact": "Missing bounce handling causes permanent fund loss when sub-calls fail",
    },
    {
        "id": "TON-CROSS-004",
        "pattern": r"(?i)(?:master|factory|router)\s*:\s*(?:Address|MsgAddress)",
        "severity": "INFO",
        "cwe": "CWE-345",
        "category": "Cross-Contract",
        "description": "Trusted contract address stored — verify it cannot be updated by unauthorized party",
        "recommendation": "Make master/router immutable after init; if mutable, require multisig to change",
        "bounty_class": "access_control",
    },
]


# ══════════════════════════════════════════════════════════════════════════════
# РАСШИРЕННЫЕ CONTEXT_RULES (многострочный анализ)
# ══════════════════════════════════════════════════════════════════════════════

EXTENDED_CONTEXT_RULES: List[Dict] = [

    # Jetton wallet: transfer_notification без проверки jetton_wallet
    {
        "id": "TON-JET-FAKE",
        "trigger_pattern": r"op::transfer_notification",
        "missing_pattern": r"calculate_jetton_wallet_address|equal_slices.*jetton|jetton.*equal_slices",
        "severity": "CRITICAL",
        "cwe": "CWE-345",
        "category": "Jetton Safety",
        "description": "transfer_notification accepted without verifying sender IS the legitimate jetton wallet",
        "recommendation": "Recompute wallet_address = calc_wallet(jetton_master, user); throw_unless(err, equal_slices(sender, wallet_address))",
        "scope_lines": 40,
        "bounty_class": "token_safety",
        "known_impact": "Attacker deploys fake jetton contract, sends transfer_notification, protocol credits non-existent tokens — CRITICAL",
    },

    # recv_external без valid_until (replay window)
    {
        "id": "TON-REPLAY-EXT",
        "trigger_pattern": r"\brecv_external\b",
        "missing_pattern": r"valid_until|expire_at|expiration",
        "severity": "HIGH",
        "cwe": "CWE-294",
        "category": "Replay Protection",
        "description": "recv_external has no valid_until expiry — signed messages replayable indefinitely",
        "recommendation": "Add: int valid_until = msg~load_uint(32); throw_if(error::expired, now() >= valid_until);",
        "scope_lines": 35,
        "bounty_class": "replay",
    },

    # send_raw_message mode=128 без raw_reserve защиты
    {
        "id": "TON-DRAIN-RESERVE",
        "trigger_pattern": r"send_raw_message\s*\([^,]+,\s*128\s*\)",
        "missing_pattern": r"raw_reserve\s*\(",
        "severity": "CRITICAL",
        "cwe": "CWE-691",
        "category": "Fund Flow",
        "description": "Mode-128 send with no raw_reserve() — contract will drain its entire balance including storage reserve",
        "recommendation": "Before mode-128: raw_reserve(min_storage_fee, 0); — this protects the minimum balance",
        "scope_lines": 15,
        "look_before": True,
        "bounty_class": "fund_drain",
        "known_impact": "Contract self-destructs economically after single call — HIGH/CRITICAL severity",
    },

    # set_code без equal_slices проверки owner
    {
        "id": "TON-UPG-UNAUTH",
        "trigger_pattern": r"\bset_code\s*\(",
        "missing_pattern": r"equal_slices|throw_unless.*owner|require.*owner|check_owner",
        "severity": "CRITICAL",
        "cwe": "CWE-284",
        "category": "Upgrade Safety",
        "description": "set_code() called without verifiable owner check in surrounding context",
        "recommendation": "throw_unless(error::unauthorized, equal_slices(sender, owner)); BEFORE set_code()",
        "scope_lines": 20,
        "look_before": True,
        "bounty_class": "upgrade",
        "known_impact": "Anyone can replace contract code — complete takeover",
    },

    # accept_message без check_signature (внешние вызовы)
    {
        "id": "TON-GAS-UNAUTH",
        "trigger_pattern": r"accept_message\s*\(\s*\)",
        "missing_pattern": r"check_signature|is_signature_valid|equal_slices.*owner|throw_unless",
        "severity": "CRITICAL",
        "cwe": "CWE-400",
        "category": "Gas Control",
        "description": "accept_message() without prior authorization check — anyone can drain contract gas balance",
        "recommendation": "ALWAYS validate before accept_message: check signature or verify sender in whitelist",
        "scope_lines": 15,
        "look_before": True,
        "bounty_class": "dos",
        "known_impact": "Gas drain attack — spammer depletes contract TON balance at no personal cost",
    },

    # Jetton balance -= без underflow check
    {
        "id": "TON-JET-UNDERFLOW",
        "trigger_pattern": r"(?i)jetton_balance\s*-=",
        "missing_pattern": r"throw_unless.*balance|balance.*>=.*amount|assert.*balance",
        "severity": "CRITICAL",
        "cwe": "CWE-191",
        "category": "Jetton Safety",
        "description": "Jetton balance decremented without underflow guard — negative balance wraps in 257-bit TVM",
        "recommendation": "throw_unless(error::insufficient_balance, jetton_balance >= jetton_amount); before -=",
        "scope_lines": 5,
        "look_before": True,
        "bounty_class": "fund_drain",
        "known_impact": "Balance underflow creates virtually infinite tokens — CRITICAL, highest bug bounty tier",
    },

    # recv_internal без bounce flag check
    {
        "id": "TON-BOUNCE-MISSING",
        "trigger_pattern": r"\brecv_internal\b",
        "missing_pattern": r"0xFFFFFFFF|bounce.*flag|in_msg_body\.skip_bits\s*\(\s*1|bounced",
        "severity": "MEDIUM",
        "cwe": "CWE-754",
        "category": "State Management",
        "description": "recv_internal does not handle bounced messages (0xFFFFFFFF op) — failed sub-calls not reversed",
        "recommendation": "At entry: int bounced = in_msg_body~load_uint(1); if(bounced) { handle_bounce(); return(); }",
        "scope_lines": 30,
        "bounty_class": "logic",
    },

    # Tact: receive с state mutation без owner check
    {
        "id": "TON-TACT-UNAUTH",
        "trigger_pattern": r"(?i)\breceive\s*\(\s*msg\s*:",
        "missing_pattern": r"require\s*\(.*sender|self\.owner|throw_unless.*owner",
        "severity": "HIGH",
        "cwe": "CWE-284",
        "category": "Tact Specific",
        "description": "Tact receive() handler processes typed message without sender authorization",
        "recommendation": "First line: require(context().sender == self.owner, 'Unauthorized');",
        "scope_lines": 20,
        "bounty_class": "access_control",
    },
]


# ══════════════════════════════════════════════════════════════════════════════
# DATAFLOW АНАЛИЗ — отслеживание потока значений между функциями
# ══════════════════════════════════════════════════════════════════════════════

class TONDataflowAnalyzer:
    """
    Межфункциональный dataflow анализ для FunC/Tact.
    Отслеживает: sender → storage, msg_value → arithmetic, user_input → send.
    """

    def analyze(self, content: str, filepath: str) -> List[Dict]:
        findings = []
        findings += self._check_sender_stored_unchecked(content, filepath)
        findings += self._check_msg_value_arithmetic(content, filepath)
        findings += self._check_user_controlled_send_amount(content, filepath)
        findings += self._check_op_dispatch_completeness(content, filepath)
        return findings

    def _check_sender_stored_unchecked(self, code: str, fp: str) -> List[Dict]:
        """sender адрес записывается в хранилище без предварительной проверки."""
        findings = []
        # Ищем паттерн: get_sender/parse_sender → сохранение без equal_slices до этого
        sender_assign = re.finditer(
            r"(?:slice\s+)?(\w+)\s*=\s*(?:cs~load_msg_addr|sender|get_sender)\s*\(\s*\)",
            code
        )
        for m in sender_assign:
            var_name = m.group(1)
            pos = m.start()
            # Смотрим следующие 15 строк
            following = code[pos:pos + 600]
            # Есть ли проверка перед сохранением?
            has_check = bool(re.search(
                r"equal_slices|throw_unless|throw_if|check_|require", following[:200]
            ))
            # Есть ли сохранение этой переменной?
            is_stored = bool(re.search(
                rf"(?:storage::{var_name}|pack.*{var_name}|{var_name}.*store_slice)", following
            ))
            if is_stored and not has_check:
                lineno = code[:pos].count("\n") + 1
                findings.append({
                    "rule_id": "TON-DF-001",
                    "severity": "MEDIUM",
                    "cwe": "CWE-284",
                    "category": "Dataflow",
                    "file": fp,
                    "line": lineno,
                    "message": f"Sender address '{var_name}' stored to state without prior validation",
                    "description": f"Variable '{var_name}' receives sender address and is stored to contract state without authorization check",
                    "recommendation": "Verify sender == existing_owner before updating stored addresses",
                    "evidence": m.group(0),
                    "bounty_class": "access_control",
                })
        return findings

    def _check_msg_value_arithmetic(self, code: str, fp: str) -> List[Dict]:
        """msg_value используется в арифметике без проверки минимума."""
        findings = []
        for m in re.finditer(r"\bmsg_value\b", code):
            pos = m.end()
            context_after = code[pos:pos + 150]
            # Арифметика с msg_value без preceding check
            if re.search(r"\s*[-+*/]\s*\w+", context_after[:50]):
                preceding = code[max(0, m.start() - 200):m.start()]
                has_check = bool(re.search(r"msg_value\s*>=|throw.*msg_value|require.*msg_value", preceding))
                if not has_check:
                    lineno = code[:m.start()].count("\n") + 1
                    findings.append({
                        "rule_id": "TON-DF-002",
                        "severity": "LOW",
                        "cwe": "CWE-191",
                        "category": "Dataflow",
                        "file": fp,
                        "line": lineno,
                        "message": "msg_value used in arithmetic without minimum value check",
                        "description": "msg_value participates in arithmetic before being validated — underflow if fee > msg_value",
                        "recommendation": "throw_unless(err, msg_value >= min_fee) before any arithmetic on msg_value",
                        "evidence": code[m.start():m.start() + 60].strip(),
                        "bounty_class": "arithmetic",
                    })
        return findings

    def _check_user_controlled_send_amount(self, code: str, fp: str) -> List[Dict]:
        """Пользовательский input попадает в amount отправляемого сообщения."""
        findings = []
        # Ищем: user_input загружается из msg → используется в send без cap
        load_vars = set()
        for m in re.finditer(r"(?:slice|int)\s+(\w+)\s*=\s*(?:\w+~load_(?:uint|int|coins))\s*\(", code):
            load_vars.add(m.group(1))

        for var in load_vars:
            # Попадает ли эта переменная в send_raw_message amount?
            pattern = rf"send_raw_message.*{re.escape(var)}|{re.escape(var)}.*send_raw_message"
            for m in re.finditer(pattern, code):
                lineno = code[:m.start()].count("\n") + 1
                # Есть ли cap/check на эту переменную?
                preceding = code[max(0, m.start() - 400):m.start()]
                has_cap = bool(re.search(
                    rf"{re.escape(var)}\s*(?:<=|<)\s*\w+|throw.*{re.escape(var)}|min\s*\(.*{re.escape(var)}", preceding
                ))
                if not has_cap:
                    findings.append({
                        "rule_id": "TON-DF-003",
                        "severity": "HIGH",
                        "cwe": "CWE-20",
                        "category": "Dataflow",
                        "file": fp,
                        "line": lineno,
                        "message": f"User-controlled variable '{var}' flows into send amount without cap",
                        "description": f"'{var}' is loaded from user message and reaches send_raw_message amount without validation",
                        "recommendation": f"Cap amount: throw_unless(err, {var} <= max_allowed_amount);",
                        "evidence": code[m.start():m.start() + 80].strip(),
                        "bounty_class": "fund_drain",
                    })
        return findings

    def _check_op_dispatch_completeness(self, code: str, fp: str) -> List[Dict]:
        """Проверяет что все op-коды имеют else/default обработчик."""
        findings = []
        # Ищем op dispatch: if (op == X) ... elif (op == Y) ...
        op_dispatches = list(re.finditer(
            r"if\s*\(\s*op\s*==\s*0x[0-9a-fA-F]+\s*\)", code
        ))
        if len(op_dispatches) >= 2:
            # Есть ли финальный else { throw } ?
            last_pos = op_dispatches[-1].end()
            tail = code[last_pos:last_pos + 300]
            has_default = bool(re.search(r"\belse\b\s*\{[^}]*throw\b", tail, re.DOTALL))
            if not has_default:
                lineno = code[:op_dispatches[0].start()].count("\n") + 1
                findings.append({
                    "rule_id": "TON-DF-004",
                    "severity": "MEDIUM",
                    "cwe": "CWE-755",
                    "category": "Dataflow",
                    "file": fp,
                    "line": lineno,
                    "message": "Op-code dispatch has no default throw — unknown ops silently accepted",
                    "description": f"Found {len(op_dispatches)} op== branches but no final else{{ throw() }} — unrecognised op-codes pass through",
                    "recommendation": "Add: else { throw(error::unknown_op); } as final branch",
                    "evidence": f"Op dispatch at line {lineno} with {len(op_dispatches)} branches",
                    "bounty_class": "logic",
                })
        return findings
