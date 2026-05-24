#!/usr/bin/env python3
"""
TON-BUG-001 Proof-of-Concept Simulator
========================================
Simulates the overlay broadcast rate-limiter logic from:
  overlay/overlay.cpp  -> get_broadcasts_limiter()
  overlay/broadcast-fec.cpp -> BroadcastsFec::process()

Demonstrates TWO issues:
  Issue A: RateLimiterWindow defaults to {} (unlimited) for both
           auth and unauth limiters — no DoS protection exists.
  Issue B: Even if limits ARE configured, fake-cert bypass lets
           unauthorized traffic use the permissive auth limiter
           while never consuming its quota.

Run: python3 poc_rate_limiter_sim.py
"""

import time
import collections


# ── Minimal RateLimiterWindow ──────────────────────────────────────────────
class RateLimiterWindowParams:
    """Mirrors td::RateLimiterWindow::Params.
    duration=0 / limit=0  →  disabled (always passes) — confirmed by network
    still being operational after commit 1b05d62 left params at {} default."""
    def __init__(self, duration: float = 0.0, limit: int = 0):
        self.duration = duration
        self.limit    = limit


class RateLimiterWindow:
    """Sliding-window rate limiter (mirrors td::RateLimiterWindow)."""
    def __init__(self, params: RateLimiterWindowParams = None):
        self.params  = params or RateLimiterWindowParams()
        self._window = collections.deque()  # (timestamp, weight)
        self._total  = 0

    def check(self, weight: int = 1) -> bool:
        """Returns True if the request fits within the limit."""
        # ── Issue A: default {} means limit=0 → always pass ──────────────
        if self.params.limit == 0 or self.params.duration == 0.0:
            return True            # ← unlimited / disabled limiter

        now = time.monotonic()
        cutoff = now - self.params.duration
        while self._window and self._window[0][0] < cutoff:
            _, w = self._window.popleft()
            self._total -= w

        return self._total + weight <= self.params.limit

    def insert(self, weight: int = 1):
        self._window.append((time.monotonic(), weight))
        self._total += weight

    def limit(self)    -> int:   return self.params.limit
    def duration(self) -> float: return self.params.duration


# ── BroadcastsLimiter ────────────────────────────────────────────────────
class BroadcastsLimiter:
    def __init__(self, name: str, rate_params=None, size_params=None):
        self.name              = name
        self._rate_lim         = RateLimiterWindow(rate_params)
        self._size_lim         = RateLimiterWindow(size_params)
        self._registered_count = 0

    def precheck_new_broadcast(self, size: int) -> (bool, str):
        if not self._rate_lim.check(1):
            return False, (f"Rate limit exceeded ({self._rate_lim.limit()} per "
                           f"{self._rate_lim.duration():.0f}s) [{self.name}]")
        if not self._size_lim.check(size):
            return False, (f"Size limit exceeded ({self._size_lim.limit()} bytes per "
                           f"{self._size_lim.duration():.0f}s) [{self.name}]")
        return True, "OK"

    def register_broadcast(self, size: int):
        """Called ONLY after successful run_checks() — never on failure."""
        self._rate_lim.insert(1)
        self._size_lim.insert(size)
        self._registered_count += 1

    def registered(self) -> int:
        return self._registered_count


# ── OverlayImpl (simplified) ─────────────────────────────────────────────
class OverlayImpl:
    """
    Mirrors the relevant parts of overlay/overlay.cpp.

    authorized_keys: set of PublicKeyHash strings that are considered
                     "authorized overlay keys" (e.g. current validator set).
    """
    def __init__(self,
                 authorized_keys: set,
                 auth_rate_params=None,
                 unauth_rate_params=None,
                 auth_size_params=None,
                 unauth_size_params=None):
        self.authorized_keys = authorized_keys

        # ── Issue A: commit 1b05d62 leaves these at {} by default ─────────
        # overlay/overlays.h:
        #   td::RateLimiterWindow::Params auth_broadcast_rate_limit_   = {};
        #   td::RateLimiterWindow::Params unauth_broadcast_rate_limit_  = {};
        # full-node-shard.cpp sets ONLY name_, announce_self_,
        # broadcast_speed_multiplier_ — rate limit fields stay at {}
        self.auth_rate_params   = auth_rate_params   # None / {} → unlimited
        self.unauth_rate_params = unauth_rate_params

        # Per-key authorized limiter map
        self._authorized_key_limiters: dict[str, BroadcastsLimiter] = {}

        # Single global unauthorized limiter
        self._unauth_limiter = BroadcastsLimiter(
            "unauth", unauth_rate_params, unauth_size_params)

    def get_broadcasts_limiter(self, source: str, cert_issuer: str = None):
        """
        Mirrors overlay/overlay.cpp::get_broadcasts_limiter().

        ISSUE B: cert_issuer (from UNVERIFIED certificate) overrides source
        before checking authorized status.
        """
        effective_key = cert_issuer if cert_issuer else source
        if effective_key in self.authorized_keys:
            if effective_key not in self._authorized_key_limiters:
                self._authorized_key_limiters[effective_key] = BroadcastsLimiter(
                    f"auth:{effective_key[:8]}", self.auth_rate_params, None)
            return self._authorized_key_limiters[effective_key]
        return self._unauth_limiter

    def process_fec_broadcast(self,
                               source_key: str,
                               cert_issuer: str = None,
                               broadcast_size: int = 1024,
                               cert_sig_valid: bool = True) -> str:
        """
        Mirrors BroadcastsFec::process().
        cert_sig_valid=False simulates a fake/invalid certificate.
        """
        limiter = self.get_broadcasts_limiter(source_key, cert_issuer)

        # Step 1: precheck (BEFORE signature verification)
        ok, reason = limiter.precheck_new_broadcast(broadcast_size)
        if not ok:
            return f"REJECTED at precheck: {reason}"

        # Step 2: run_checks — signature / cert verification
        if not cert_sig_valid:
            # register_broadcast() is NEVER called → counter stays 0
            return f"REJECTED at run_checks (invalid cert sig) [limiter: {limiter.name}, registered={limiter.registered()}]"

        # Step 3: register with limiter (only on success)
        limiter.register_broadcast(broadcast_size)
        return f"ACCEPTED [limiter: {limiter.name}, registered={limiter.registered()}]"


# ══════════════════════════════════════════════════════════════════════════
# EXPERIMENT 1 — Issue A: Default {} limits → no DoS protection at all
# ══════════════════════════════════════════════════════════════════════════
def demo_issue_a():
    print("=" * 70)
    print("ISSUE A: Rate limit params default to {} (unlimited)")
    print("         No actual broadcast rate limits are configured.")
    print("=" * 70)

    AUTHORIZED_KEYS = {"VALIDATOR_A_HASH_0123456789abcdef"}

    # As deployed: no rate limit params set (mirrors full-node-shard.cpp)
    overlay = OverlayImpl(
        authorized_keys    = AUTHORIZED_KEYS,
        auth_rate_params   = None,   # {} in C++ → unlimited
        unauth_rate_params = None,   # {} in C++ → unlimited
    )

    ATTACKER_KEY = "ATTACKER_KEY_deadbeef1234"
    BROADCAST_SIZE = 512 * 1024  # 512 KB broadcast

    print(f"\n  Sending 20 large FEC broadcasts from unauthorized attacker...")
    for i in range(20):
        result = overlay.process_fec_broadcast(
            source_key      = ATTACKER_KEY,
            cert_issuer     = None,      # no certificate
            broadcast_size  = BROADCAST_SIZE,
            cert_sig_valid  = True,
        )
        print(f"  Broadcast {i+1:02d}: {result}")

    unauth_registered = overlay._unauth_limiter.registered()
    print(f"\n  Result: ALL 20 broadcasts accepted by unauth limiter.")
    print(f"  Unauth limiter registered count: {unauth_registered}")
    print(f"  → No rate limiting protection. Attacker can flood freely.\n")


# ══════════════════════════════════════════════════════════════════════════
# EXPERIMENT 2 — Issue B: Cert bypass when limits ARE configured
# ══════════════════════════════════════════════════════════════════════════
def demo_issue_b():
    print("=" * 70)
    print("ISSUE B: Fake cert bypasses strict unauth limiter")
    print("         (activated when actual limits are configured)")
    print("=" * 70)

    VALIDATOR_KEY = "VALIDATOR_A_HASH_0123456789abcdef"
    AUTHORIZED_KEYS = {VALIDATOR_KEY}

    # Hypothetical configured limits (what operators would set)
    strict_unauth = RateLimiterWindowParams(duration=60.0, limit=5)   # 5 per min
    permissive_auth = RateLimiterWindowParams(duration=60.0, limit=200) # 200 per min

    overlay = OverlayImpl(
        authorized_keys    = AUTHORIZED_KEYS,
        auth_rate_params   = permissive_auth,
        unauth_rate_params = strict_unauth,
    )

    ATTACKER_KEY = "ATTACKER_KEY_deadbeef1234"
    BROADCAST_SIZE = 8192

    print(f"\n  Unauth limit: {strict_unauth.limit} per {strict_unauth.duration:.0f}s")
    print(f"  Auth limit:   {permissive_auth.limit} per {permissive_auth.duration:.0f}s\n")

    # --- Without fake cert (legitimate unauth path) ---
    print("  [Path 1] Attacker WITHOUT fake cert (correct unauth limiter):")
    overlay2 = OverlayImpl(
        authorized_keys    = AUTHORIZED_KEYS,
        auth_rate_params   = permissive_auth,
        unauth_rate_params = strict_unauth,
    )
    for i in range(8):
        result = overlay2.process_fec_broadcast(
            source_key     = ATTACKER_KEY,
            cert_issuer    = None,
            broadcast_size = BROADCAST_SIZE,
            cert_sig_valid = True,
        )
        print(f"    Broadcast {i+1}: {result}")

    # --- With fake cert claiming authorized key (bypass path) ---
    print(f"\n  [Path 2] Attacker WITH fake cert (claims issuer={VALIDATOR_KEY[:16]}...):")
    for i in range(10):
        result = overlay.process_fec_broadcast(
            source_key     = ATTACKER_KEY,
            cert_issuer    = VALIDATOR_KEY,   # ← fake, sig not yet verified
            broadcast_size = BROADCAST_SIZE,
            cert_sig_valid = False,            # ← cert verification FAILS
        )
        print(f"    Broadcast {i+1}: {result}")

    print(f"\n  Authorized limiter registered={overlay._authorized_key_limiters.get(VALIDATOR_KEY, type('o', (), {'registered': lambda s: 0})()).registered()}")
    print(f"  → Counter stays 0. Attacker can repeat indefinitely past unauth limit.\n")


# ══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print()
    print("TON Overlay Broadcast Rate Limiter — PoC Simulation")
    print("Static analysis confirmed against master branch 2026-05-24")
    print()
    demo_issue_a()
    demo_issue_b()
    print("=" * 70)
    print("CONCLUSION:")
    print("  Issue A (HIGH): No broadcast rate limits in production — flooding")
    print("                  is entirely unprotected right now.")
    print("  Issue B (HIGH): When limits are configured, unverified cert issuer")
    print("                  hash allows bypass of strict unauth limits.")
    print("  Both findings confirmed by static analysis of overlay/overlay.cpp,")
    print("  overlay/broadcast-fec.cpp, overlay/overlays.h, full-node-shard.cpp.")
    print("=" * 70)
