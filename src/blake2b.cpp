// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "blake2b.h"

#include <algorithm>
#include <cstring>

#include "common.h"

namespace {

const uint64_t IV[8] = {
  0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
  0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull
};

const uint8_t SIGMA[10][16] = {
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};

inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

inline uint64_t load64(const uint8_t *p)
{
  uint64_t w = 0;
  for (int i = 7; i >= 0; i--) w = w << 8 | p[i];
  return w;
}

inline void store32(uint8_t *p, uint32_t w)
{
  for (int i = 0; i < 4; i++) p[i] = (uint8_t)(w >> (8 * i));
}

inline void G(uint64_t v[16], int a, int b, int c, int d, uint64_t x, uint64_t y)
{
  v[a] += v[b] + x; v[d] = rotr64(v[d] ^ v[a], 32);
  v[c] += v[d];     v[b] = rotr64(v[b] ^ v[c], 24);
  v[a] += v[b] + y; v[d] = rotr64(v[d] ^ v[a], 16);
  v[c] += v[d];     v[b] = rotr64(v[b] ^ v[c], 63);
}

}  // namespace

Blake2b::Blake2b(size_t n) : outlen(n)
{
  memcpy(h, IV, sizeof h);
  h[0] ^= 0x01010000ull ^ (uint64_t)outlen;
}

void Blake2b::block(const uint8_t *p, bool last)
{
  uint64_t m[16], v[16];
  for (int i = 0; i < 16; i++) m[i] = load64(p + 8 * i);
  memcpy(v, h, 64);
  memcpy(v + 8, IV, 64);
  v[12] ^= total;
  if (last) v[14] = ~v[14];
  for (int r = 0; r < 12; r++) {
    const uint8_t *s = SIGMA[r % 10];
    G(v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
    G(v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
    G(v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
    G(v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);
    G(v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
    G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    G(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
    G(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
  }
  for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
  wipe(m, sizeof m);
  wipe(v, sizeof v);
}

// A full buffer is only compressed when more data follows, because the last block is flagged.
void Blake2b::update(const uint8_t *p, size_t n)
{
  while (n > 0) {
    if (fill == sizeof buf) {
      total += sizeof buf;
      block(buf, false);
      fill = 0;
    }
    size_t k = std::min(n, sizeof buf - fill);
    memcpy(buf + fill, p, k);
    fill += k; p += k; n -= k;
  }
}

void Blake2b::final(uint8_t *out)
{
  total += fill;
  memset(buf + fill, 0, sizeof buf - fill);
  block(buf, true);
  uint8_t full[64];
  for (int i = 0; i < 8; i++)
    for (int j = 0; j < 8; j++) full[8 * i + j] = (uint8_t)(h[i] >> (8 * j));
  memcpy(out, full, outlen);
  wipe(full, sizeof full);
}

// Hash states carry key-derivation intermediates.
Blake2b::~Blake2b()
{
  wipe(h, sizeof h);
  wipe(buf, sizeof buf);
}

void blake2b_long(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
  uint8_t len[4];
  store32(len, (uint32_t)outlen);
  if (outlen <= 64) {
    Blake2b b(outlen);
    b.update(len, 4);
    b.update(in, inlen);
    b.final(out);
    return;
  }
  uint8_t v[64];
  {
    Blake2b b(64);
    b.update(len, 4);
    b.update(in, inlen);
    b.final(v);
  }
  size_t r = (outlen + 31) / 32 - 2;
  for (size_t i = 0; i < r; i++) {
    memcpy(out + 32 * i, v, 32);
    if (i + 1 < r) {
      Blake2b b(64);
      b.update(v, 64);
      b.final(v);
    }
  }
  Blake2b b(outlen - 32 * r);
  b.update(v, 64);
  b.final(out + 32 * r);
  wipe(v, sizeof v);
}
