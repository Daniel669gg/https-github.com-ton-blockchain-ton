// Standalone mutation fuzzer for TON BoC / cell deserialization.
// Target: vm::std_boc_deserialize + cell traversal + reserialize.
// Reachable from external messages, liteserver queries, block download - any
// untrusted bag-of-cells fed to a node passes through this code.
//
// Built with g++ -fsanitize=address. A memory error makes ASan abort; the
// SIGABRT/SIGSEGV handler dumps the exact input that triggered it to crash.bin.

#include "vm/boc.h"
#include "vm/cells.h"
#include "vm/cellslice.h"
#include "vm/cells/CellBuilder.h"
#include "td/utils/buffer.h"
#include "td/utils/Slice.h"

#include <atomic>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

// ---- current input, captured on crash --------------------------------------
const unsigned char* g_cur_data = nullptr;
size_t g_cur_size = 0;
volatile std::sig_atomic_t g_in_target = 0;

void dump_and_die(int sig) {
  if (g_cur_data && g_in_target) {
    int fd = ::open("crash.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
      auto _ = ::write(fd, g_cur_data, g_cur_size);
      (void)_;
      ::close(fd);
    }
    const char msg[] = "\n[fuzzer] crashing input written to crash.bin\n";
    auto _ = ::write(2, msg, sizeof(msg) - 1);
    (void)_;
  }
  signal(sig, SIG_DFL);
  raise(sig);
}

// ---- exercise a deserialized cell tree -------------------------------------
void walk(const td::Ref<vm::Cell>& cell, int depth) {
  if (cell.is_null() || depth > 40) {
    return;
  }
  vm::CellSlice cs = vm::load_cell_slice(cell);
  cs.size();
  cs.size_refs();
  // touch the data bits
  if (cs.size() > 0) {
    cs.prefetch_ulong(cs.size() > 64 ? 64 : (unsigned)cs.size());
  }
  unsigned n = cs.size_refs();
  for (unsigned i = 0; i < n; i++) {
    walk(cs.prefetch_ref(i), depth + 1);
  }
}

void run_one(const unsigned char* data, size_t size) {
  g_cur_data = data;
  g_cur_size = size;
  g_in_target = 1;

  td::Slice s(reinterpret_cast<const char*>(data), size);

  // Primary target: standard single-root deserialization.
  auto r = vm::std_boc_deserialize(s, /*can_be_empty=*/true, /*allow_nonzero_level=*/true);
  if (r.is_ok()) {
    auto cell = r.move_as_ok();
    if (cell.not_null()) {
      cell->get_hash();
      cell->get_depth();
      cell->get_level();
      walk(cell, 0);
      auto rs = vm::std_boc_serialize(cell, 0);
      if (rs.is_ok()) {
        // round-trip the produced bytes once more
        auto rr = vm::std_boc_deserialize(rs.ok().as_slice(), true, true);
        (void)rr;
      }
    }
  }

  // Secondary target: multi-root path (different index/root handling).
  auto rm = vm::std_boc_deserialize_multi(s, 1024);
  (void)rm;

  g_in_target = 0;
}

// ---- corpus / seeds --------------------------------------------------------
std::vector<std::string> g_seeds;

void add_seed_cell(const td::Ref<vm::Cell>& c) {
  auto r = vm::std_boc_serialize(c, 0);
  if (r.is_ok()) {
    auto s = r.move_as_ok();
    g_seeds.emplace_back(s.as_slice().data(), s.size());
  }
  // also a crc32c-flagged variant (mode 2) and indexed variant (mode 1)
  for (int mode : {1, 2, 3}) {
    auto r2 = vm::std_boc_serialize(c, mode);
    if (r2.is_ok()) {
      auto s2 = r2.move_as_ok();
      g_seeds.emplace_back(s2.as_slice().data(), s2.size());
    }
  }
}

td::Ref<vm::Cell> mk(std::string bits, std::vector<td::Ref<vm::Cell>> refs = {}) {
  vm::CellBuilder cb;
  for (char ch : bits) {
    cb.store_long(ch == '1' ? 1 : 0, 1);
  }
  for (auto& r : refs) {
    cb.store_ref(r);
  }
  return cb.finalize();
}

void build_seeds() {
  // empty cell
  add_seed_cell(vm::CellBuilder().finalize());
  // simple data cells of various bit widths
  add_seed_cell(mk("1"));
  add_seed_cell(mk("10101010"));
  add_seed_cell(mk(std::string(1023, '1')));  // full cell
  // a small tree
  auto leaf1 = mk("11110000");
  auto leaf2 = mk(std::string(300, '0'));
  add_seed_cell(mk("1010", {leaf1, leaf2}));
  // 4-ref cell
  add_seed_cell(mk("1", {mk("0"), mk("1"), mk("00"), mk("11")}));
  // a deep chain
  {
    td::Ref<vm::Cell> c = mk("1");
    for (int i = 0; i < 30; i++) {
      c = mk("01", {c});
    }
    add_seed_cell(c);
  }
  // shared subcell (diamond)
  {
    auto shared = mk("10101010101010101010");
    add_seed_cell(mk("0", {shared, mk("1", {shared})}));
  }
  fprintf(stderr, "[fuzzer] built %zu seeds\n", g_seeds.size());
}

// ---- tiny RNG --------------------------------------------------------------
uint64_t g_rng;
uint64_t xrand() {
  g_rng ^= g_rng << 13;
  g_rng ^= g_rng >> 7;
  g_rng ^= g_rng << 17;
  return g_rng;
}
size_t rnd(size_t n) { return n ? (size_t)(xrand() % n) : 0; }

void mutate(std::string& s) {
  int rounds = 1 + (int)rnd(6);
  for (int i = 0; i < rounds; i++) {
    if (s.empty()) {
      s.push_back((char)rnd(256));
      continue;
    }
    switch (rnd(9)) {
      case 0: s[rnd(s.size())] ^= (char)(1u << rnd(8)); break;               // bit flip
      case 1: s[rnd(s.size())] = (char)rnd(256); break;                      // random byte
      case 2: {                                                              // interesting byte
        static const unsigned char it[] = {0, 1, 0x7f, 0x80, 0xff, 0xfe};
        s[rnd(s.size())] = (char)it[rnd(sizeof(it))];
        break;
      }
      case 3: s.insert(rnd(s.size() + 1), 1, (char)rnd(256)); break;         // insert
      case 4: if (s.size() > 1) s.erase(rnd(s.size()), 1); break;            // delete
      case 5: {                                                              // dup chunk
        size_t p = rnd(s.size()), l = 1 + rnd(s.size() - p);
        s.insert(p, s.substr(p, l));
        break;
      }
      case 6: {                                                             // overwrite u32 (sizes/counts)
        if (s.size() >= 4) {
          size_t p = rnd(s.size() - 3);
          uint32_t v = (uint32_t)xrand();
          memcpy(&s[p], &v, 4);
        }
        break;
      }
      case 7: {                                                             // splice another seed
        if (!g_seeds.empty()) {
          const std::string& o = g_seeds[rnd(g_seeds.size())];
          if (!o.empty()) {
            size_t p = rnd(s.size() + 1);
            size_t l = 1 + rnd(o.size());
            s.insert(p, o.substr(rnd(o.size()), l));
          }
        }
        break;
      }
      case 8: if (s.size() > 8) s.resize(1 + rnd(s.size())); break;          // truncate
    }
    if (s.size() > (1u << 20)) {
      s.resize(1u << 20);
    }
  }
}

}  // namespace

int main(int argc, char** argv) {
  // reproduce a single file (crash triage): fuzz_boc <file>
  struct sigaction sa {};
  sa.sa_handler = dump_and_die;
  sigemptyset(&sa.sa_mask);
  for (int sig : {SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL}) {
    sigaction(sig, &sa, nullptr);
  }

  if (argc >= 2 && strcmp(argv[1], "-r") == 0 && argc >= 3) {
    FILE* f = fopen(argv[2], "rb");
    if (!f) { perror("open"); return 1; }
    std::string buf;
    char tmp[4096];
    size_t n;
    while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0) buf.append(tmp, n);
    fclose(f);
    fprintf(stderr, "[fuzzer] replay %zu bytes from %s\n", buf.size(), argv[2]);
    run_one((const unsigned char*)buf.data(), buf.size());
    fprintf(stderr, "[fuzzer] replay finished cleanly\n");
    return 0;
  }

  uint64_t seed = (argc >= 2) ? strtoull(argv[1], nullptr, 0) : (uint64_t)time(nullptr);
  long long iters = (argc >= 3) ? atoll(argv[2]) : 5000000;
  g_rng = seed ? seed : 0x9e3779b97f4a7c15ull;
  fprintf(stderr, "[fuzzer] seed=%llu iters=%lld\n", (unsigned long long)seed, iters);

  build_seeds();
  if (g_seeds.empty()) {
    fprintf(stderr, "[fuzzer] no seeds!\n");
    return 1;
  }

  std::string cur;
  for (long long i = 0; i < iters; i++) {
    if ((i & 0x3ffff) == 0) {
      cur = g_seeds[rnd(g_seeds.size())];  // reseed periodically
    }
    mutate(cur);
    run_one((const unsigned char*)cur.data(), cur.size());
    if ((i & 0xfffff) == 0 && i) {
      fprintf(stderr, "[fuzzer] %lld execs\n", i);
    }
  }
  fprintf(stderr, "[fuzzer] done, no crash in %lld execs\n", iters);
  return 0;
}
