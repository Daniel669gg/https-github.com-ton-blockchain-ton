# TON Bug Bounty Self-Check Report
**Date:** 2026-05-24  
**Analyst:** Ghost Security Platform v10 + Claude Code  
**Overall Verdict:** PASS WITH WARNINGS  
**Confidence:** 72%

---

## Finding: TON-BUG-001 — FEC Broadcast Rate Limiter Bypass via Unverified Certificate Issuer Hash

### Short Assessment
**Status:** `partially correct` — Technically valid design flaw with clear code evidence, but the practical impact depends on the delta between `auth_broadcast_rate_limit_` and the fallback unauthorized limiter, and whether `certificate_check_rate_limiter_` inside `check_source_eligible` fully compensates. Reproducible locally without targeting live systems.

---

### Repository State
- **Repository:** `ton-blockchain/ton`
- **Branch:** `master`
- **Commit reference (analysis base):** post-`1b05d62` (Broadcast limiting in overlays, Apr 27 2026)
- **Files:** `overlay/overlay.cpp`, `overlay/broadcast-fec.cpp`, `overlay/overlay.hpp`

---

### Scope Validation
| Check | Result |
|-------|--------|
| Component | TON core — overlay network |
| In-scope per bug-bounty rules | **YES** — TON core and testnet branches are in scope |
| Catchain? | No — this is the overlay broadcast layer, not Catchain consensus |
| Frontend only? | No — this is C++ node code |
| Already fixed? | No — commit `1b05d62` added rate limiting but the cert-order issue remains |

---

### Vulnerability Details

#### Component
`overlay/overlay.cpp` — `OverlayImpl::get_broadcasts_limiter()`  
`overlay/broadcast-fec.cpp` — `BroadcastsFec::process()`

#### Root Cause

The rate limiter selection in `get_broadcasts_limiter()` uses the certificate's `issuer_hash()` field **before** the certificate's signature has been verified:

```cpp
// overlay/overlay.cpp
BroadcastsLimiter& OverlayImpl::get_broadcasts_limiter(
    PublicKeyHash source, const Certificate* certificate) {
  if (certificate) {
    source = certificate->issuer_hash();   // ← field from UNVERIFIED certificate
  }
  if (rules_.is_authorized_key(source)) {
    // Returns PER-KEY limiter with permissive auth_broadcast_rate_limit_
    AuthorizedKeyLimiter& limiter = authorized_key_limiters_[source];
    ...
    return limiter.broadcasts_;
  }
  return unauthorized_broadcasts_limiter_;  // ← strict limit — BYPASSED
}
```

In `BroadcastsFec::process()`, this limiter is queried **before** `run_checks()`:

```cpp
// overlay/broadcast-fec.cpp
BroadcastsLimiter& limiter =
    overlay->get_broadcasts_limiter(part.source_.compute_short_id(),
                                    part.cert_.get());   // cert NOT yet verified
if (!is_ours) {
    TRY_STATUS(limiter.precheck_new_broadcast(part.broadcast_size_));  // uses wrong limiter
}
TRY_STATUS(part.run_checks(overlay, nullptr));   // signature verified HERE, too late
// ...
limiter.register_broadcast(part.broadcast_size_);  // ← only reached on success
// On failure: reached never → limiter counter stays at 0 → next broadcast also passes
```

#### Attack Scenario

1. Attacker learns the `PublicKeyHash` of any authorized overlay key (validator ADNL keys are public on-chain).
2. Attacker constructs FEC broadcast parts with a **structurally valid but cryptographically invalid certificate** whose `issuer` field is set to the authorized key hash.
3. `get_broadcasts_limiter()` returns the **authorized key's per-key limiter** (permissive `auth_broadcast_rate_limit_`), bypassing the strict `unauthorized_broadcasts_limiter_`.
4. `precheck_new_broadcast()` passes (counter = 0, never increments on failure).
5. `run_checks()` fails → certificate signature invalid.
6. `register_broadcast()` is **never called** → counter stays 0.
7. Go to step 2 — loop is unbounded by the intended rate limit.

**Net effect:** The attacker forces expensive Ed25519 signature verification operations (in `check_source_eligible`) at a rate controlled only by the looser `auth_broadcast_rate_limit_`, not by `unauthorized_broadcasts_limiter_`. If the difference between these two limits is large, this is an effective CPU-exhaustion DoS against validators.

---

### Exploitability Assessment

| Criterion | Assessment |
|-----------|------------|
| Attacker controls trigger | **YES** — any node on the network can send crafted packets |
| Local-only / operator-only | **NO** — fully remote, no local access needed |
| Requires special privilege | **NO** — authorized key hashes are publicly derivable from on-chain validator set (config param 34) |
| Realistic prerequisites | Low: attacker needs a TON node and internet connectivity |
| Concrete impact | **YES** — CPU exhaustion on validators → missed block proposals, slashing risk |

#### Partial Mitigations (Uncertainty Factors)
- `certificate_check_rate_limiter_` inside `check_source_eligible()` may limit how often a specific issuer's cert is re-verified. If this is per-issuer, the attack rate per authorized key is bounded.
- Signature caching may reduce the cost of re-verifying the same invalid cert.
- ADNL connection-level throttling limits packets per TCP session.

These mitigations reduce impact but do **not** fix the root cause: the unauthorized strict limiter is still bypassed for the pre-check.

---

### Reproduction (Local)

The vulnerability can be verified locally without targeting live systems:

1. Build `ton-blockchain/ton` from master branch.
2. Run a local overlay node pair (use `adnl-test-loopback-implementation` or the overlay test suite).
3. Craft an `overlay_broadcastFec` TL object with:
   - `src` set to any key pair you control
   - `certificate` with `issuer` set to a known authorized overlay key hash
   - Invalid certificate `signature` bytes
4. Send the crafted packet to the overlay node.
5. Observe: `precheck_new_broadcast()` passes (in debug logs or via counter inspection).
6. Observe: `run_checks()` fails with cert signature error.
7. Repeat — confirm counter stays at 0 after each failed attempt.

**No mainnet/testnet interaction required.**

---

### Eligibility
- **Severity:** HIGH (network DoS, affects all validators)
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **CVSS:** 7.5 — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **Payout estimate (ghost triage):** $1,000–$15,000
- **Triage score:** 90/100

---

### Report Completeness Checklist

- [x] Title: "FEC Broadcast Rate Limiter Bypass via Unverified Certificate Issuer Hash"
- [x] Summary: Root cause and attack description provided
- [x] Component: `overlay/overlay.cpp`, `overlay/broadcast-fec.cpp`
- [x] Commit reference: master post-`1b05d62`
- [x] Vulnerable files and functions: `get_broadcasts_limiter()`, `BroadcastsFec::process()`
- [x] Steps to reproduce (local, no live systems)
- [x] Impact: CPU exhaustion DoS of validators
- [x] Remediation: see Recommended Fix below
- [x] Common error checks:
  - NOT a crash without untrusted input path ✓
  - NOT debug-only or local-tool-only ✓
  - NOT already fixed in latest branch ✓
  - NOT a hallucinated function — all functions confirmed in fetched source ✓

---

### Recommended Fix

**Option A (preferred):** Move limiter selection after certificate authentication:

```cpp
// In BroadcastsFec::process():
// Step 1: Apply unauthorized limiter first (strict)
BroadcastsLimiter& pre_limiter = overlay->unauthorized_broadcasts_limiter_;
if (!is_ours) {
    TRY_STATUS(pre_limiter.precheck_new_broadcast(part.broadcast_size_));
}
// Step 2: Verify the broadcast (cert, signature, etc.)
TRY_STATUS(part.run_checks(overlay, nullptr));
// Step 3: Now get the correct (possibly authorized) limiter and register
BroadcastsLimiter& limiter =
    overlay->get_broadcasts_limiter(part.source_.compute_short_id(), part.cert_.get());
limiter.register_broadcast(part.broadcast_size_);
```

**Option B:** Use the ADNL peer's node ID (not the cert issuer) as the rate limit key for the pre-check, so the unauthorized sender's connection is always subject to the strict limit regardless of the cert's claimed issuer.

---

### Final Verdict
**PASS WITH WARNINGS**  

The technical finding is valid and the code evidence is confirmed. The main uncertainty is whether the secondary `certificate_check_rate_limiter_` fully neutralizes the bypass. Submit as MEDIUM–HIGH and let the TON security team evaluate the practical rate-limit values.

> **Note:** Do NOT send this report without:
> 1. Confirming the `certificate_check_rate_limiter_` behavior in `check_source_eligible()`
> 2. Measuring the actual `auth_broadcast_rate_limit_` vs `unauthorized` limit values from default node configuration
> 3. Running the local reproduction steps to confirm the counter stays at 0

---

## Additional Finding: TON-BUG-002 — Payment Channel Missing Authentication for Payout Trigger

### Short Assessment
**Status:** `out-of-scope but technically valid`

The payment channel contract (`crypto/smartcont/payment-channel-code.fc`) has a design flaw: when the channel is in `state:payout()`, calling `with_payout()` does **not** verify any signature. The `unwrap_signatures()` function allows messages with neither A nor B signature flag set, returning `(msg_signed_A?=0, msg_signed_B?=0)` without performing any cryptographic check. `with_payout()` then executes if the balance threshold is met.

**Impact:** Anyone can trigger payout from a settled channel if TON has been sent to it post-settlement, causing accidentally-deposited funds to be distributed to A and B rather than returned.

**Why out of scope:** The contract file begins with `";; WARINIG: NOT READY FOR A PRODUCTION!"` — the TON team has explicitly marked this as an experimental/unfinished contract. It is not listed in the bug bounty's in-scope standard contracts (wallet, multisig, tokens, DNS, nominator pool).

**Evidence (raw source):**
```
;; WARINIG: NOT READY FOR A PRODUCTION!
...
(slice, (int, int)) unwrap_signatures(slice cs, int a_key, int b_key) {
  int a? = cs~load_int(1);
  ...
  if (a?) { throw_unless(err:wrong_a_signature(), ...); }
  if (b?) { throw_unless(err:wrong_b_signature(), ...); }
  return (cs, (a?, b?));  ;; returns (0, 0) if neither flag set — no sig check!
}
...
if (state_type == state:payout()) {
    with_payout(cs, msg, a_addr, b_addr, channel_id);
    ;; ← no msg_signed_A? / msg_signed_B? check before calling
}
```

**Recommendation:** If the payment channel is promoted to production, add a check in `recv_any` before dispatching to `with_payout`:
```
throw_unless(err:no_signature(), msg_signed_A? | msg_signed_B?);
```

**DO NOT SEND this finding** — it is out of scope (contract explicitly marked not production-ready). It may be worth a note to the TON team but not a formal bug bounty submission.

---

*Report generated by Ghost Security Platform v10 (ghost_v10_hardened) + Claude Code analysis.*  
*Static analysis only. No live mainnet or testnet systems were accessed or targeted.*
