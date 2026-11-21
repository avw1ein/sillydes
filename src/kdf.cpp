// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "kdf.h"

#include <cstdio>
#include <cstring>
#include <new>
#include <sys/resource.h>
#include <unistd.h>

#include "blake2b.h"

namespace {

enum { BLOCK_WORDS = 128, SYNC_POINTS = 4, ARGON2_VERSION = 0x13, ARGON2_ID = 2 };

struct Block { uint64_t v[BLOCK_WORDS]; };

inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

// BlaMka: BLAKE2b's G with a multiplication of the low halves added.
inline uint64_t fbla(uint64_t x, uint64_t y) { return x + y + 2 * (x & 0xffffffffull) * (y & 0xffffffffull); }

inline void G(uint64_t &a, uint64_t &b, uint64_t &c, uint64_t &d)
{
  a = fbla(a, b); d = rotr64(d ^ a, 32);
  c = fbla(c, d); b = rotr64(b ^ c, 24);
  a = fbla(a, b); d = rotr64(d ^ a, 16);
  c = fbla(c, d); b = rotr64(b ^ c, 63);
}

inline void P(uint64_t &v0, uint64_t &v1, uint64_t &v2, uint64_t &v3, uint64_t &v4, uint64_t &v5, uint64_t &v6, uint64_t &v7,
              uint64_t &v8, uint64_t &v9, uint64_t &v10, uint64_t &v11, uint64_t &v12, uint64_t &v13, uint64_t &v14, uint64_t &v15)
{
  G(v0, v4, v8, v12); G(v1, v5, v9, v13); G(v2, v6, v10, v14); G(v3, v7, v11, v15);
  G(v0, v5, v10, v15); G(v1, v6, v11, v12); G(v2, v7, v8, v13); G(v3, v4, v9, v14);
}

// next = (with_xor ? next : 0) ^ G(prev, ref), RFC 9106 section 3.5.
void compress(const Block &prev, const Block &ref, Block &next, bool with_xor)
{
  Block R, Z;
  for (int i = 0; i < BLOCK_WORDS; i++) R.v[i] = prev.v[i] ^ ref.v[i];
  Z = R;
  for (int i = 0; i < 8; i++) {
    uint64_t *r = Z.v + 16 * i;
    P(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]);
  }
  for (int i = 0; i < 8; i++) {
    uint64_t *c = Z.v + 2 * i;
    P(c[0], c[1], c[16], c[17], c[32], c[33], c[48], c[49], c[64], c[65], c[80], c[81], c[96], c[97], c[112], c[113]);
  }
  for (int i = 0; i < BLOCK_WORDS; i++) next.v[i] = (with_xor ? next.v[i] : 0) ^ R.v[i] ^ Z.v[i];
  wipe(&R, sizeof R);
  wipe(&Z, sizeof Z);
}

void store32(SecretBuf &b, uint32_t w) { for (int i = 0; i < 4; i++) b.push_back((uint8_t)(w >> (8 * i))); }

void block_from_bytes(Block &b, const uint8_t *p)
{
  for (int i = 0; i < BLOCK_WORDS; i++) {
    uint64_t w = 0;
    for (int j = 7; j >= 0; j--) w = w << 8 | p[8 * i + j];
    b.v[i] = w;
  }
}

void block_to_bytes(uint8_t *p, const Block &b)
{
  for (int i = 0; i < BLOCK_WORDS; i++)
    for (int j = 0; j < 8; j++) p[8 * i + j] = (uint8_t)(b.v[i] >> (8 * j));
}

// Refuses rather than letting the kernel overcommit and kill the process later.
void require_memory(uint64_t need)
{
  uint64_t avail = UINT64_MAX;
  if (FILE *f = fopen("/proc/meminfo", "r")) {
    char line[128];
    while (fgets(line, sizeof line, f)) {
      unsigned long long kb;
      if (sscanf(line, "MemAvailable: %llu kB", &kb) == 1) { avail = kb * 1024ull; break; }
    }
    fclose(f);
  }
  if (avail == UINT64_MAX) {
    long pages = sysconf(_SC_AVPHYS_PAGES), psize = sysconf(_SC_PAGESIZE);
    if (pages > 0 && psize > 0) avail = (uint64_t)pages * (uint64_t)psize;
  }
  struct rlimit rl;
  for (auto res : { RLIMIT_AS, RLIMIT_DATA })
    if (getrlimit(res, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur < avail) avail = rl.rlim_cur;
  if (need + (64ull << 20) > avail) errorexit(7);  // 64 MiB headroom for the rest of the process
}

struct Argon2 {
  uint32_t passes, lanes, mblocks, lane_len, seg_len;
  std::vector<Block, SecureAllocator<Block>> mem;  // wiped by the allocator on every path out

  Block &at(uint32_t lane, uint32_t idx) { return mem[(size_t)lane * lane_len + idx]; }

  uint32_t index_alpha(uint32_t pass, uint32_t slice, uint32_t index, uint32_t j1, bool same_lane) const
  {
    uint32_t area;
    if (pass == 0) {
      if (slice == 0) area = index - 1;
      else if (same_lane) area = slice * seg_len + index - 1;
      else area = slice * seg_len - (index == 0);
    } else {
      if (same_lane) area = lane_len - seg_len + index - 1;
      else area = lane_len - seg_len - (index == 0);
    }
    uint64_t rel = (uint64_t)j1 * j1 >> 32;
    rel = area - 1 - ((uint64_t)area * rel >> 32);
    uint32_t start = (pass == 0 || slice == SYNC_POINTS - 1) ? 0 : (slice + 1) * seg_len;
    return (uint32_t)((start + rel) % lane_len);
  }

  void fill_segment(uint32_t pass, uint32_t lane, uint32_t slice)
  {
    const bool independent = pass == 0 && slice < SYNC_POINTS / 2;
    Block zero{}, input{}, addr{};
    if (independent) {
      input.v[0] = pass; input.v[1] = lane; input.v[2] = slice;
      input.v[3] = mblocks; input.v[4] = passes; input.v[5] = ARGON2_ID;
    }
    auto next_addresses = [&]() {
      input.v[6]++;
      compress(zero, input, addr, false);
      compress(zero, addr, addr, false);
    };
    uint32_t start = 0;
    if (pass == 0 && slice == 0) {
      start = 2;
      if (independent) next_addresses();
    }
    uint32_t cur = slice * seg_len + start;
    uint32_t prev = cur == 0 ? lane_len - 1 : cur - 1;
    for (uint32_t i = start; i < seg_len; i++, cur++, prev++) {
      if (cur % lane_len == 1) prev = cur - 1;
      uint64_t rnd;
      if (independent) {
        if (i % BLOCK_WORDS == 0) next_addresses();
        rnd = addr.v[i % BLOCK_WORDS];
      } else {
        rnd = at(lane, prev).v[0];
      }
      uint32_t ref_lane = (uint32_t)((rnd >> 32) % lanes);
      if (pass == 0 && slice == 0) ref_lane = lane;
      uint32_t ref_idx = index_alpha(pass, slice, i, (uint32_t)rnd, ref_lane == lane);
      compress(at(lane, prev), at(ref_lane, ref_idx), at(lane, cur), pass != 0);
    }
    wipe(&input, sizeof input);
    wipe(&addr, sizeof addr);
  }
};

}  // namespace

SecretBuf argon2id(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t slen, uint32_t m_kib, uint32_t t, uint32_t p,
                   size_t outlen, const uint8_t *secret, size_t seclen, const uint8_t *ad, size_t adlen)
{
  Argon2 a;
  a.passes = t;
  a.lanes = p;
  a.seg_len = m_kib / (SYNC_POINTS * p);
  a.lane_len = a.seg_len * SYNC_POINTS;
  a.mblocks = a.lane_len * p;

  // H0 over the parameters and all inputs, each variable-length input preceded by its length.
  SecretBuf h0in;
  h0in.reserve(10 * 4 + pwlen + slen + seclen + adlen);  // exact, so the password is never copied on growth
  store32(h0in, p); store32(h0in, (uint32_t)outlen); store32(h0in, m_kib); store32(h0in, t);
  store32(h0in, ARGON2_VERSION); store32(h0in, ARGON2_ID);
  store32(h0in, (uint32_t)pwlen); h0in.insert(h0in.end(), pw, pw + pwlen);
  store32(h0in, (uint32_t)slen); h0in.insert(h0in.end(), salt, salt + slen);
  store32(h0in, (uint32_t)seclen); if (seclen) h0in.insert(h0in.end(), secret, secret + seclen);
  store32(h0in, (uint32_t)adlen); if (adlen) h0in.insert(h0in.end(), ad, ad + adlen);
  uint8_t h0[72];
  { Blake2b b(64); b.update(h0in.data(), h0in.size()); b.final(h0); }
  wipe(h0in.data(), h0in.size());

  require_memory((uint64_t)a.mblocks * sizeof(Block));
  try {
    a.mem.reserve(a.mblocks);
    // Every block derives from the phrase, so a swapped-out page is as good as a key. Locked before
    // it is first touched; without the privilege or limit for 2 GiB this fails and is skipped.
    lock_memory(a.mem.data(), a.mblocks * sizeof(Block));
    a.mem.resize(a.mblocks);
  } catch (const std::bad_alloc &) { errorexit(7); }

  uint8_t blk[sizeof(Block)];
  for (uint32_t l = 0; l < p; l++) {
    for (uint32_t j = 0; j < 2; j++) {
      for (int i = 0; i < 4; i++) { h0[64 + i] = (uint8_t)(j >> (8 * i)); h0[68 + i] = (uint8_t)(l >> (8 * i)); }
      blake2b_long(blk, sizeof blk, h0, sizeof h0);
      block_from_bytes(a.at(l, j), blk);
    }
  }
  wipe(h0, sizeof h0);

  for (uint32_t r = 0; r < t; r++)
    for (uint32_t s = 0; s < SYNC_POINTS; s++)
      for (uint32_t l = 0; l < p; l++) a.fill_segment(r, l, s);

  Block c = a.at(0, a.lane_len - 1);
  for (uint32_t l = 1; l < p; l++)
    for (int i = 0; i < BLOCK_WORDS; i++) c.v[i] ^= a.at(l, a.lane_len - 1).v[i];
  block_to_bytes(blk, c);
  SecretBuf out(outlen);
  blake2b_long(out.data(), outlen, blk, sizeof blk);

  wipe(&c, sizeof c);
  wipe(blk, sizeof blk);
  return out;
}
