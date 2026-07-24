# BoC / ext-message fuzz harnesses (TON node)

Three standalone ASan fuzzers I built to try to break the attacker-controlled
parsing paths in `ton-blockchain/ton` (master @ `ca7d6e45`). They link against
the real node crypto libraries (`ton_crypto`, `ton_block`, `ton_crypto_core`,
`tdutils`) — no reimplementation, the exact code a node runs.

| harness | target | attacker reaches it via |
|---|---|---|
| `fuzz_boc.cpp`  | `vm::std_boc_deserialize` + cell walk + reserialize + `std_boc_deserialize_multi` | any bag-of-cells: external message, liteserver query, block/state download |
| `fuzz_msg.cpp`  | `t_Message_Any.validate_ref` + `t_Message.validate_ref` + `t_MsgEnvelope` unpack/validate + ext_in header unpack + `extract_std_address` | inbound external message (`ExtMessageQ::create_ext_message`) |
| `fuzz_bocz.cpp` | `boc_decompress` / `boc_decompress_baseline_lz4` / `boc_decompress_improved_structure_lz4` + header parsers | compressed broadcast / block transfer |

Each is a self-contained mutation fuzzer: it builds a seed corpus of valid cells
with `CellBuilder`, mutates (bit flips, splices, size-field smashing, truncation),
and feeds the bytes to the target under `-fsanitize=address`. A crash writes the
exact input to `crash.bin`; `./fuzz_x -r crash.bin` replays a single input for
triage.

## Build

The node's own build system is monolithic, so configure it once with the heavy,
irrelevant deps switched off and system OpenSSL, then build just the crypto libs.

```bash
# from a fresh clone of ton-blockchain/ton
git submodule update --init --depth 1 \
    third-party/crc32c third-party/secp256k1 third-party/blst third-party/tl-parser \
    third-party/libbacktrace third-party/zlib third-party/sodium third-party/lz4

# secp256k1 via its own cmake into the path TON expects
cmake -S third-party/secp256k1 -B third-party/secp256k1/_b -G Ninja \
    -DBUILD_SHARED_LIBS=OFF -DSECP256K1_ENABLE_MODULE_RECOVERY=ON \
    -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON -DSECP256K1_BUILD_TESTS=OFF \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_C_FLAGS=-fPIC \
    -DCMAKE_INSTALL_PREFIX=$PWD/build-gcc/third-party/secp256k1 -DCMAKE_INSTALL_LIBDIR=lib
ninja -C third-party/secp256k1/_b install

cmake -G Ninja -B build-gcc \
    -DCMAKE_BUILD_TYPE=Debug -DTON_USE_ASAN=ON \
    -DTON_USE_ROCKSDB=OFF -DTON_USE_ABSEIL=OFF -DUSE_QUIC=OFF \
    -DOPENSSL_FOUND=TRUE -DOPENSSL_INCLUDE_DIR=/usr/include \
    -DOPENSSL_CRYPTO_LIBRARY=/lib/x86_64-linux-gnu/libcrypto.so \
    -DOPENSSL_SSL_LIBRARY=/lib/x86_64-linux-gnu/libssl.so \
    -DSECP256K1_LIBRARY=$PWD/build-gcc/third-party/secp256k1/lib/libsecp256k1.a \
    -DSECP256K1_INCLUDE_DIR=$PWD/build-gcc/third-party/secp256k1/include \
    -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++
ninja -C build-gcc ton_crypto ton_block ton_crypto_core
```

Then compile a harness (example for `fuzz_msg`, needs the full `ton_crypto`):

```bash
B=build-gcc
g++ -std=c++20 -g -fsanitize=address -fno-omit-frame-pointer \
  -I crypto -I tdutils -I tdactor -I tddb -I tl -I tl/generate -I . -I $B/tdutils -I third-party/crc32c/include \
  fuzz/fuzz_msg.cpp -o $B/fuzz_msg \
  -Wl,--start-group $B/crypto/libton_crypto.a $B/crypto/libton_block.a $B/crypto/libton_crypto_core.a \
    $B/tl/libtl_api.a $B/tddb/libtddb_utils.a $B/tdactor/libtdactor.a $B/tdutils/libtdutils.a -Wl,--end-group \
  $B/third-party/crc32c/libcrc32c.a $B/third-party/secp256k1/lib/libsecp256k1.a $B/third-party/blst/libblst.a \
  $B/third-party/sodium/lib/libsodium.a $B/third-party/lz4/lib/liblz4.a $B/third-party/zlib/lib/libz.a \
  $B/libbacktrace/lib/libbacktrace.a /lib/x86_64-linux-gnu/libcrypto.so -lpthread -ldl
```

(`fuzz_boc` only needs `ton_crypto_core` + tdutils; `fuzz_bocz` needs full `ton_crypto`.)

## Run

```bash
export ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:allocator_may_return_null=1
./build-gcc/fuzz_msg <seed> <iterations>      # fuzz
./build-gcc/fuzz_msg -r crash.bin             # replay one input
```

## Result (this run)

~127k exec/s per core for `fuzz_boc`, run 4-wide on a 4-core box.

- `fuzz_boc`  : ~1.52e8 executions, 0 crashes, 0 ASan reports
- `fuzz_msg`  : 1.6e8 executions, 0 crashes, 0 ASan reports
- `fuzz_bocz` : 1.6e8 executions, 0 crashes, 0 ASan reports
- total       : ~4.7e8 executions, clean

No memory-safety issue surfaced in the deserialization / validation / decompression
paths on the current master.
