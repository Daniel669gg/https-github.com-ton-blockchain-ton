// Standalone fuzzer for the external-message parse path (TL-B validation).
// Mirrors ExtMessageQ::create_ext_message: deserialize a bag-of-cells, then run
// the automated + hand-written TL-B validators on it as a (Message Any), unpack
// the ext_in header, and extract the destination address. This is the exact code
// an attacker hits by sending an inbound external message to a node's liteserver.

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "vm/boc.h"
#include "vm/cells.h"
#include "vm/cells/CellBuilder.h"
#include "td/utils/buffer.h"
#include "td/utils/Slice.h"

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

const unsigned char* g_cur_data = nullptr;
size_t g_cur_size = 0;
volatile std::sig_atomic_t g_in_target = 0;

void dump_and_die(int sig) {
  if (g_cur_data && g_in_target) {
    int fd = ::open("crash.bin", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) { auto _ = ::write(fd, g_cur_data, g_cur_size); (void)_; ::close(fd); }
    const char msg[] = "\n[fuzzer] crashing input written to crash.bin\n";
    auto _ = ::write(2, msg, sizeof(msg) - 1); (void)_;
  }
  signal(sig, SIG_DFL);
  raise(sig);
}

void run_one(const unsigned char* data, size_t size) {
  g_cur_data = data; g_cur_size = size; g_in_target = 1;
  td::Slice s(reinterpret_cast<const char*>(data), size);

  auto r = vm::std_boc_deserialize(s, /*can_be_empty=*/true, /*allow_nonzero_level=*/true);
  if (r.is_ok()) {
    auto cell = r.move_as_ok();
    if (cell.not_null()) {
      // automated (generated) validator, as in create_ext_message
      block::gen::t_Message_Any.validate_ref(1024, cell);
      // hand-written validator
      block::tlb::t_Message.validate_ref(1024, cell);
      // message-envelope validator (block-parse.cpp, recently changed unpack)
      block::tlb::t_MsgEnvelope.validate_ref(1024, cell);

      // ext_in header unpack + address extraction path
      vm::CellSlice cs{vm::NoVmOrd{}, cell};
      if (cs.prefetch_ulong(2) == 2) {
        block::gen::CommonMsgInfo::Record_ext_in_msg_info info;
        if (tlb::unpack_cell_inexact(cell, info)) {
          auto pfx = block::tlb::t_MsgAddressInt.get_prefix(info.dest);
          (void)pfx;
          ton::WorkchainId wc;
          ton::StdSmcAddress addr;
          block::tlb::t_MsgAddressInt.extract_std_address(info.dest, wc, addr);
        }
      }

      // MsgEnvelope structured unpack (v1/v2/std records)
      {
        vm::CellSlice cs2{vm::NoVmOrd{}, cell};
        block::tlb::MsgEnvelope::Record_std env;
        block::tlb::t_MsgEnvelope.unpack(cs2, env);
      }
    }
  }
  g_in_target = 0;
}

// ---------- seeds / mutate (shared pattern) ----------
std::vector<std::string> g_seeds;
void add_seed_cell(const td::Ref<vm::Cell>& c) {
  for (int mode : {0, 1, 2}) {
    auto r = vm::std_boc_serialize(c, mode);
    if (r.is_ok()) { auto b = r.move_as_ok(); g_seeds.emplace_back(b.as_slice().data(), b.size()); }
  }
}
td::Ref<vm::Cell> mk(std::string bits, std::vector<td::Ref<vm::Cell>> refs = {}) {
  vm::CellBuilder cb;
  for (char ch : bits) cb.store_long(ch == '1' ? 1 : 0, 1);
  for (auto& r : refs) cb.store_ref(r);
  return cb.finalize();
}
td::Ref<vm::Cell> mkbytes(const std::string& hexbits, std::vector<td::Ref<vm::Cell>> refs = {}) {
  return mk(hexbits, std::move(refs));
}
void build_seeds() {
  add_seed_cell(vm::CellBuilder().finalize());
  add_seed_cell(mk("1"));
  // looks-like ext_in_msg_info$10 prefix + some payload
  add_seed_cell(mk("10" + std::string(200, '0')));
  add_seed_cell(mk("10" + std::string(600, '1'), {mk(std::string(400, '0'))}));
  // internal msg prefix 0
  add_seed_cell(mk("0" + std::string(300, '1'), {mk("101010"), mk(std::string(200, '0'))}));
  // address-like slices
  add_seed_cell(mk("100" + std::string(8 + 256, '1')));   // addr_std
  add_seed_cell(mk("11010" + std::string(9 + 32, '0')));  // addr_var-ish
  // MsgEnvelope tag 4 / 5 shapes
  auto inner = mk("10" + std::string(100, '1'), {mk("111000")});
  add_seed_cell(mk("0100" + std::string(64, '1'), {inner}));
  add_seed_cell(mk("0101" + std::string(80, '1'), {inner}));
  // deep chain + wide refs to stress recursion in validate
  {
    td::Ref<vm::Cell> c = mk("1");
    for (int i = 0; i < 24; i++) c = mk("01", {c});
    add_seed_cell(c);
  }
  add_seed_cell(mk("1", {mk("0"), mk("1"), mk("00"), mk("11")}));
  fprintf(stderr, "[fuzzer] built %zu seeds\n", g_seeds.size());
}

uint64_t g_rng;
uint64_t xrand() { g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17; return g_rng; }
size_t rnd(size_t n) { return n ? (size_t)(xrand() % n) : 0; }
void mutate(std::string& s) {
  int rounds = 1 + (int)rnd(6);
  for (int i = 0; i < rounds; i++) {
    if (s.empty()) { s.push_back((char)rnd(256)); continue; }
    switch (rnd(9)) {
      case 0: s[rnd(s.size())] ^= (char)(1u << rnd(8)); break;
      case 1: s[rnd(s.size())] = (char)rnd(256); break;
      case 2: { static const unsigned char it[] = {0,1,0x7f,0x80,0xff,0xfe}; s[rnd(s.size())] = (char)it[rnd(sizeof(it))]; break; }
      case 3: s.insert(rnd(s.size()+1), 1, (char)rnd(256)); break;
      case 4: if (s.size()>1) s.erase(rnd(s.size()),1); break;
      case 5: { size_t p=rnd(s.size()), l=1+rnd(s.size()-p); s.insert(p, s.substr(p,l)); break; }
      case 6: if (s.size()>=4){ size_t p=rnd(s.size()-3); uint32_t v=(uint32_t)xrand(); memcpy(&s[p],&v,4);} break;
      case 7: if (!g_seeds.empty()){ const std::string&o=g_seeds[rnd(g_seeds.size())]; if(!o.empty()){ size_t p=rnd(s.size()+1); size_t l=1+rnd(o.size()); s.insert(p,o.substr(rnd(o.size()),l)); } } break;
      case 8: if (s.size()>8) s.resize(1+rnd(s.size())); break;
    }
    if (s.size() > (1u<<20)) s.resize(1u<<20);
  }
}

}  // namespace

int main(int argc, char** argv) {
  struct sigaction sa{}; sa.sa_handler = dump_and_die; sigemptyset(&sa.sa_mask);
  for (int sig : {SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL}) sigaction(sig, &sa, nullptr);

  if (argc >= 3 && strcmp(argv[1], "-r") == 0) {
    FILE* f = fopen(argv[2], "rb"); if (!f) { perror("open"); return 1; }
    std::string buf; char tmp[4096]; size_t n;
    while ((n = fread(tmp,1,sizeof(tmp),f))>0) buf.append(tmp,n);
    fclose(f);
    fprintf(stderr, "[fuzzer] replay %zu bytes\n", buf.size());
    run_one((const unsigned char*)buf.data(), buf.size());
    fprintf(stderr, "[fuzzer] replay finished cleanly\n");
    return 0;
  }

  uint64_t seed = (argc>=2)?strtoull(argv[1],nullptr,0):(uint64_t)time(nullptr);
  long long iters = (argc>=3)?atoll(argv[2]):5000000;
  g_rng = seed ? seed : 0x9e3779b97f4a7c15ull;
  fprintf(stderr, "[fuzzer] seed=%llu iters=%lld\n", (unsigned long long)seed, iters);
  build_seeds();
  std::string cur;
  for (long long i=0;i<iters;i++) {
    if ((i & 0x3ffff)==0) cur = g_seeds[rnd(g_seeds.size())];
    mutate(cur);
    run_one((const unsigned char*)cur.data(), cur.size());
    if ((i & 0xfffff)==0 && i) fprintf(stderr, "[fuzzer] %lld execs\n", i);
  }
  fprintf(stderr, "[fuzzer] done, no crash in %lld execs\n", iters);
  return 0;
}
