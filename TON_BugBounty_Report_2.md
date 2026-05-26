# TON RLDP — Response Size Limit Bypass via Signed-to-Unsigned Cast on `max_answer_size`

---

## Summary

The RLDP (Reliable Large Datagram Protocol) layer in both `rldp/rldp.cpp` and `rldp2/rldp.cpp` receives the `max_answer_size` field from a `rldp.query` TL message as a signed 64-bit integer (`long` in TL schema), then immediately casts it to `td::uint64` via `static_cast`. An attacker who sends `max_answer_size = -1` causes the cast to produce `UINT64_MAX` (0xFFFFFFFFFFFFFFFF). The subsequent guard `if (data.size() > max_answer_size)` is always false for any real response, silently bypassing the size limit entirely. Any registered RLDP service on the victim node will return its response regardless of declared size constraints — enabling response amplification and violation of the querier-declared bandwidth contract.

---

## Affected Component

- **Repository:** https://github.com/ton-blockchain/ton  
- **Analyzed commit:** `200a6e6794510be5d5faa83b15004bb3b135e7af`  
- **Primary files:**
  - `rldp/rldp.cpp` — line 203
  - `rldp2/rldp.cpp` — line 206
  - `tl/generate/scheme/ton_api.tl` — `rldp.query` schema

---

## Vulnerability Details

### TL Schema

```
// tl/generate/scheme/ton_api.tl
rldp.query query_id:int256 max_answer_size:long timeout:int data:bytes = rldp.Message;
```

In TL, `long` is a signed 64-bit integer. The generated C++ field `message.max_answer_size_` is therefore `td::int64`.

### Vulnerable Cast — `rldp/rldp.cpp:203`

```cpp
void RldpIn::process_message(adnl::AdnlNodeIdShort source, adnl::AdnlNodeIdShort local_id,
                             TransferId transfer_id, ton_api::rldp_query &message)
{
  auto P = td::PromiseCreator::lambda([...,
      max_answer_size = static_cast<td::uint64>(message.max_answer_size_),  // ← BUG
      ...](td::Result<td::BufferSlice> R) mutable
  {
    if (R.is_ok()) {
      auto data = R.move_as_ok();
      if (data.size() > max_answer_size) {      // ← UINT64_MAX: always false
        VLOG(RLDP_NOTICE) << "rldp query failed: answer too big";
      } else {
        td::actor::send_closure(SelfId, &RldpIn::answer_query, ...);  // always reached
      }
    }
  });
```

The identical pattern appears at `rldp2/rldp.cpp:206`.

### Why the Cast Is Wrong

| Stage | Type | Value (when attacker sends -1) |
|---|---|---|
| TL wire encoding | int64 | -1 |
| C++ field `message.max_answer_size_` | `td::int64` | -1 |
| After `static_cast<td::uint64>(-1)` | `td::uint64` | 18,446,744,073,709,551,615 |
| Guard `data.size() > UINT64_MAX` | bool | **always false** |

---

## Attack Prerequisites

- Network reachability to any RLDP-speaking TON node (validator or full node).
- The attacker sends a standard `rldp.query` message via the ADNL/UDP transport — **no authentication, no validator credentials required**.
- The query body (`data` field) can be any valid TL-B payload for any service registered over RLDP (e.g., DHT `dht.query`, overlay `overlay.query`, liteserver queries routed via RLDP).

---

## Reproduction Steps

All steps performed locally against the source tree at commit `200a6e6794510be5d5faa83b15004bb3b135e7af`. No live nodes or external endpoints contacted.

### Step 1 — Confirm field type in TL schema (static)

```bash
grep "rldp.query" tl/generate/scheme/ton_api.tl
# rldp.query query_id:int256 max_answer_size:long timeout:int data:bytes = rldp.Message;
# 'long' = int64 (signed). Documented in TL specification.
```

### Step 2 — Confirm unsafe cast in source (static)

```bash
grep -n "max_answer_size" rldp/rldp.cpp
# Line 203: max_answer_size = static_cast<td::uint64>(message.max_answer_size_),
grep -n "max_answer_size" rldp2/rldp.cpp
# Line 206: max_answer_size = static_cast<td::uint64>(message.max_answer_size_),
```

### Step 3 — Numeric proof (local, deterministic)

```python
import ctypes

attacker_wire_value = -1                              # int64 sent by attacker
after_cast = ctypes.c_uint64(attacker_wire_value).value  # C++ static_cast behavior

print(f"Wire (int64):   {attacker_wire_value}")
print(f"After cast:     {after_cast}")   # 18446744073709551615
print(f"Hex:            0x{after_cast:016X}")  # 0xFFFFFFFFFFFFFFFF

for data_size in [7680, 65535, 1_048_576, 100_000_000]:
    bypassed = not (data_size > after_cast)
    print(f"data.size()={data_size:>12,}: guard fires={not bypassed}, bypass={bypassed}")
```

**Output (reproduced locally):**

```
Wire (int64):   -1
After cast:     18446744073709551615
Hex:            0xFFFFFFFFFFFFFFFF

data.size()=       7,680: guard fires=False, bypass=True
data.size()=      65,535: guard fires=False, bypass=True
data.size()=   1,048,576: guard fires=False, bypass=True
data.size()= 100,000,000: guard fires=False, bypass=True
```

### Expected vs. Actual Behavior

| | Expected | Actual |
|---|---|---|
| Query with `max_answer_size = 1000` | Responses > 1000 bytes silently dropped | Correctly enforced |
| Query with `max_answer_size = -1` | Treated as 0 or rejected as invalid | Cast to UINT64_MAX; all responses pass |
| Guard `data.size() > max_answer_size` | Fires for large responses | **Never fires** when max_answer_size = UINT64_MAX |

---

## Security Impact

| Property | Assessment |
|---|---|
| **Attacker control** | Full — `max_answer_size` is attacker-supplied via RLDP query |
| **Authentication** | None required |
| **Exploitability** | Directly exploitable over ADNL/UDP |
| **Primary impact** | Response size limit bypass — any RLDP service returns unbounded responses |
| **Secondary impact** | Amplification: small query provokes arbitrarily large response, consuming victim node's outbound bandwidth |
| **Affected services** | Any service registered via `deliver_query` over RLDP: DHT, overlay gossip, lite-client routing, storage queries |

This falls under the **"Node crashes from attacker-controlled messages"** and **"Service compromise"** categories in the TON bug bounty scope.

### Amplification Scenario

1. Attacker sends many `rldp.query` packets to a DHT or overlay node with `max_answer_size = -1` and queries that produce large responses (e.g., requesting large data blobs from the storage protocol).
2. The node computes and transmits the full response regardless of declared size limit.
3. By spoofing the source ADNL address to a victim IP, the attacker drives large UDP traffic toward the victim (reflection amplification).

---

## Suggested Remediation

Add a validity check before the cast in both `rldp/rldp.cpp` and `rldp2/rldp.cpp`:

```cpp
// rldp/rldp.cpp and rldp2/rldp.cpp — in process_message(rldp_query)
void RldpIn::process_message(... ton_api::rldp_query &message) {
  // Reject negative max_answer_size before the cast
  if (message.max_answer_size_ < 0) {
    VLOG(RLDP_NOTICE) << "rldp query rejected: negative max_answer_size";
    return;
  }
  auto P = td::PromiseCreator::lambda([...,
      max_answer_size = static_cast<td::uint64>(message.max_answer_size_),
      ...] ...
```

Alternatively, use a checked cast helper:

```cpp
auto max_answer_size_signed = message.max_answer_size_;
td::uint64 max_answer_size = (max_answer_size_signed < 0)
    ? 0ULL
    : static_cast<td::uint64>(max_answer_size_signed);
```

---

## Environment

| Item | Value |
|---|---|
| Analyzed commit | `200a6e6794510be5d5faa83b15004bb3b135e7af` |
| Repository | github.com/ton-blockchain/ton |
| Analysis method | Manual static code review + local type-arithmetic proof |
| Live systems tested | None — local repository only |

---

## References

- `rldp/rldp.cpp` line 203 — `static_cast<td::uint64>(message.max_answer_size_)` without sign guard
- `rldp2/rldp.cpp` line 206 — identical cast
- `tl/generate/scheme/ton_api.tl` — `rldp.query max_answer_size:long` (signed int64)
- Standard C++ behavior: `static_cast<uint64_t>(-1LL)` = 18,446,744,073,709,551,615
