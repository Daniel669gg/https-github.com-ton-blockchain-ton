# TON Bug Bounty — Self-Check Report

**Assessment:** DO NOT SEND!!! — no attacker-controlled, reproducible, in-scope vulnerability was confirmed in the fresh commits. What I looked at is either hardening (some of it fixing latent bugs *in the same commits*), version-gated consensus changes that behave correctly, or code that is already defended against the obvious bug classes. Nothing here is submittable as-is.

**Report status:** `incorrect` (no confirmed finding)
**Final verdict:** `REJECTED`

---

## 0. What this is

I went through the commits that landed on `ton-blockchain/ton` over the last couple of weeks looking for something that (a) sits in an in-scope component, (b) is triggered by input an external attacker actually controls, and (c) I could back with a real PoC. This report walks the 11-point checklist over the candidates I actually chased down, and records why each one dies before it becomes a submission.

I am writing this the way I'd write my own notes, so it's blunt. If a thing didn't pan out, I say so.

**Target snapshot**
- Repo: `ton-blockchain/ton`, branch `master`
- HEAD at review time: `ca7d6e45` (`Merge pull request #2481 from ton-blockchain/testnet`, 2026-07-16)
- Reviewed range: roughly `97337f45..ca7d6e45` (2026-06-23 → 2026-07-16), plus the two June consensus commits `2b187fd0` and `5f454cd2` that ship behind global version 15.

**Fresh surfaces that actually process untrusted input, and got touched recently:**
1. Plumtree gossip broadcast — brand new subsystem: `overlay/broadcast-plumtree.cpp` / `.hpp` (`cab516be` and the whole 07-02…07-08 security series).
2. External-message admission pipeline: `validator/impl/ext-message-checker.cpp`, `ext-message-pool.cpp`, `external-message.cpp` (`d508c890`, `f4925b3e`, `908a5903`).
3. BoC / cell deserialization + TLB helpers touched by `9c07336d` (`crypto/vm/boc.*`, `crypto/common/bitstring.cpp`, `crypto/tl/tlblib.hpp`, `crypto/block/block-parse.cpp`, `crypto/block/mc-config.cpp`, `crypto/vm/db/StaticBagOfCellsDb.cpp`).
4. Transaction executor consensus changes: `crypto/block/transaction.cpp` (`2b187fd0` "Library reform", `5f454cd2` "Collect action fine correctly when action phase fails").

---

## 1. Target identification

- **Component:** primarily the overlay/broadcast layer (network) and the transaction/cell layer (crypto/block, crypto/vm). All are inside `ton-blockchain/ton`, which is in scope.
- **Repository / branch:** `ton-blockchain/ton` @ `master`, HEAD `ca7d6e45`.
- **Affected commits reviewed:** listed in §0.
- **Vulnerable code:** none confirmed. Candidates and their exact locations are in §6.

## 2. Rules and scope loading

- `ton-blockchain/ton` core — **in scope.**
- Catchain, deprecated wallets (Highload v1/v2, Multisig v1), pure Fift/FunC compiler issues without proven critical node impact, frontends, third-party services — **out of scope.** I did not chase anything that lands there.
- Everything I dug into (plumtree overlay, ext-message admission, BoC parsing, transaction executor) is squarely in the node and in scope. So scope is fine; the problem is I don't have a confirmed bug, not that the bug is out of scope.

## 3. Code verification (does the "vulnerable" path exist on latest?)

This is where several tempting leads died, because the fresh commits are the fix, not the bug:

- `crypto/common/bitstring.cpp` — `bits_load_long()` used to do `(long long)bits_load_long_top(from, bits) >> (64 - bits)`. For `bits == 0` that's a shift by 64 → UB. **Already fixed in `9c07336d`** (`bits == 0 ? 0LL : …`). Reporting it against latest would be `REJECTED: already fixed`.
- `crypto/tl/tlblib.hpp` — `unpack_cell` / `unpack_cell_inexact` / `type_unpack_cell` now null-check the cell before `load_cell_slice_quiet`. That's a latent null-deref hardening, **also already in `9c07336d`.**
- `crypto/vm/excno.hpp` `try_f()` now also catches `CellBuilder::CellCreateError/CellWriteError`, `std::exception`, and `...`. Again: the fresh commit is closing a hole, not opening one.

So the "obvious" wins in this range are already patched on the branch I'm supposed to test against. Dead on arrival for a submission.

## 4. Exploitability validation (attacker actually controls the trigger?)

The two surfaces where an external attacker genuinely controls the bytes:

- **Plumtree** (`overlay/broadcast-plumtree.cpp`) — any overlay peer can send `overlay.broadcastPlumtree*` / `overlay.repairPlumtreePart` / `overlay.plumtreeStatsPush`. Real attacker input. But the parsing is defended hard (see §6): timestamps are range-checked (`check_timestamp`, ±20s), control fields are validated (`validate_control_fields` bounds `tree_index`/`part_index` and enforces the tree↔part relationship), `full_data_size`/`part_size` are bounded by `max_fec_broadcast_size()` and must match `ceil(full_data_size/k)`, payloads are signature-checked (`check_signature_from_peer`) before any state is committed, IHAVEs are signed (that was the `07b4c00a` fix), payloads from non-eager peers are rejected (`189ff146`/`29ead1c4`), and repair responses must match the exact `MissingPartKey` they were requested for. Negative int32 fields wrap to huge uint32 and fall out on the size/bounds checks. I could not turn any of this into memory corruption, a consensus split, or an unbounded resource blow-up. The DoS-ish angles (stats-store poisoning, missing-part table) are all bounded (`STATS_STORE_LIMIT=100`, `MAX_PENDING_REPAIR_PARTS=1024`, `MAX_ACTIVE_REPAIR_QUERIES=512`) and dominated by the honest broadcast cost.
- **External messages** (`external-message.cpp::create_ext_message`) — attacker sends a BoC. But it's size-capped (`limits.max_size`), depth-capped (`limits.max_depth`), level-checked (must be 0), and run through both `block::gen::t_Message_Any.validate_ref` and the hand-written `block::tlb::t_Message.validate_ref` before anything trusts it. The wallet body parsers all check `body.size()` before `fetch_ulong`. The VM run is gas-bounded and behind the pool's backpressure/rate-limit (`MAX_INFLIGHT_CHECKS`, `MAX_EXT_MSG_PER_ADDR`).

The transaction-executor changes (`transaction.cpp`) are attacker-reachable in principle (a message can drive an account into the action phase), **but** they're gated behind `global_version >= 15`, meaning every node applies the same rule at the same time — no divergence from the change itself.

## 5. Reproduction requirement

The bounty requires reproduction artifacts (`ton-bug-triage`) for any crash/consensus claim. I have **none**, because I have no confirmed crash/consensus bug to reproduce. Separately, I could not stand up the full node in this environment to fuzz the network paths end-to-end (submodules `rocksdb`/`openssl`/`abseil`/`blst`/… are not vendored in the working tree and a from-scratch build blows past the disk/time budget here). For BoC/cell parsing — the one thing that is realistically fuzzable standalone — the recent diff is `const`-correctness plus the already-shipped hardening above, not a new bug to target. So there is nothing to attach an artifact to. This alone is enough to keep the verdict at REJECTED even if a candidate had looked stronger.

## 6. Behavior vs. vulnerability (counterintuitive ≠ exploitable)

The candidates I actually chased and why they're behavior, not bugs:

- **`repair_query_finished()` `CHECK(active_repair_queries_ > 0)`** (`broadcast-plumtree.cpp:1839`). A tripped `CHECK` is an `abort()` = remote crash, so I traced the counter. It's balanced: `send_repair_requests` does one `++active_repair_queries_` per `send_query_via`, and the query's promise fires `receive_plumtree_repair_response` exactly once (on response *or* timeout), which calls `repair_query_finished()` once (`overlay.cpp:908`). td guarantees single-fire. Can't drive it negative. Not a bug.
- **`ExtMessageChecker::check` reference into `exec_configs_`** (`ext-message-checker.cpp:66-75`). Takes `auto &exec_config = exec_configs_[…]` then calls `std::erase_if(exec_configs_, …)`. Looks like a use-after-invalidation, but the current entry's `nolog` was just set non-null and its utime is current, so the predicate never erases it; node-based/`unordered_map` erase of *other* elements doesn't invalidate the surviving reference, and the `CO_TRY`s in between don't actually suspend. The devs even left a comment about exactly this. Not a bug.
- **Plumtree stats push** (`process_stats_push`, line ~1990). A malicious eager peer can inject records with an arbitrary `src_`. But it only lands if `tree_index == rotating_slot`, `epoch` matches, the sender is an eager peer on the simple tree, the store isn't full (`>=100`), and it dedups by `src_`. Worst case is ~100 bogus stats rows for one epoch — cosmetic, self-limiting. Not worth a report.
- **`msg_envelope_v2#5` unpack tightening** (`block-parse.cpp`, `9c07336d`) — now requires at least one of `emitted_lt`/`metadata`, else it "should be `msg_envelope#4`". This is a serialization-canonicity fix; the fresh commit closes it. Nothing to submit.

## 7. Bug bounty eligibility (impact + realistic prerequisites + attacker path)

To be eligible I need concrete impact (node crash / consensus split / fund loss / meaningful DoS beyond honest cost), realistic prerequisites, and an attacker-controlled path. I have the attacker-controlled path in two places (plumtree, ext-msg) but **no concrete impact** — every lead terminated in an existing check, a bound, or an already-shipped fix. No eligibility.

## 8. Report completeness

There is no positive finding to complete (title / summary / PoC / impact / remediation). The one field I can fill honestly is "PoC" = none, which by itself sinks the submission.

## 9. Common error detection (self-audit of my own leads)

I explicitly checked myself for the usual junk-report patterns, and caught myself on:
- **"Crash" with no execution** — the `CHECK` lead (§6) had no path to actually trip it. Dropped.
- **Already-fixed** — the `bits_load_long` UB shift and the tlblib null-derefs are fixed on `master` (§3). Dropped.
- **Operator/local-only** — nothing I kept relied on local/operator access; but nothing I kept had impact either.
- **Hallucinated code** — every location above is a real line in the current tree (paths + line numbers are from `ca7d6e45`).

## 10. Simplex validation

No simplex-specific claim here. `97337f45 "Simplex-related refactorings"` is in the reviewed range; I skimmed it and it didn't surface an attacker-controlled defect. Nothing to validate against the simplex docs.

## 11. Smart-contract audit note

No smart-contract (FunC/Tolk) finding in this pass. If a contract-level report comes later, run it through `acton` before submitting. The wallet-code paths I did touch (`external-message.cpp` `WalletV1..V5` body parsers) are node-side parsers, not the contracts themselves, and they bounds-check before every `fetch`.

---

## Bottom line

I did a genuine pass over the fresh in-scope network/parsing/consensus code. It holds up. The recent commits are mostly the maintainers *removing* footguns (UB shift, null-derefs, missing exception catches, missing envelope-canonicity check) and shipping version-gated consensus tweaks that behave correctly. I found nothing that is simultaneously attacker-controlled, impactful, present on latest, and reproducible — and with no reproduction artifact there's no case to make.

**Status:** `incorrect` — no confirmed finding.
**Verdict:** `REJECTED`.

Do not submit anything from this pass. If we want a real shot, the highest-value next step is standing up a full node build with the submodules and fuzzing the live plumtree message handlers (`process_fec_payload` / `process_ihave` / `process_repair_response`) with a signing oracle, because that's the newest code and the only place where a subtle state-machine bug could still be hiding behind the signature checks. That needs an environment that can actually build and run the node.
