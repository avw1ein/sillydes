// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "des.h"

#include <cstring>

#include "common.h"
#include "des_sbox_ct.h"

namespace {

// FIPS 46 tables, 1-based bit numbers.
const uint8_t ip[64] = {
  58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12,  4,
  62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16,  8,
  57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
  61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7
};

const uint8_t fp[64] = {
  40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31,
  38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29,
  36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
  34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25
};

const uint8_t p32[32] = {
  16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
   2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};

const uint8_t pc1[56] = {
  57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
  10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
  14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

const uint8_t totrot[16] = { 1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28 };

const uint8_t pc2[48] = {
  14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
  23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

// In-place transpose of a 32x32 bit matrix: a[r] bit (31-c) <-> a[c] bit (31-r).
void transpose(uint32_t a[32])
{
  uint32_t m = 0x0000ffffu;
  for (int j = 16; j; j >>= 1, m ^= m << j)
    for (int k = 0; k < 32; k = (k + j + 1) & ~j) {
      uint32_t t = (a[k] ^ (a[k + j] >> j)) & m;
      a[k] ^= t;
      a[k + j] ^= t << j;
    }
}

// Expansion E for S-box S reads R bits 4S-1 .. 4S+4 (mod 32, 1-based).
template <int S>
inline void sbox(const uint32_t *r, const uint32_t *k, uint32_t *f)
{
  uint32_t b1 = r[(4 * S + 31) & 31] ^ k[6 * S];
  uint32_t b2 = r[4 * S] ^ k[6 * S + 1];
  uint32_t b3 = r[4 * S + 1] ^ k[6 * S + 2];
  uint32_t b4 = r[4 * S + 2] ^ k[6 * S + 3];
  uint32_t b5 = r[4 * S + 3] ^ k[6 * S + 4];
  uint32_t b6 = r[(4 * S + 4) & 31] ^ k[6 * S + 5];
  uint32_t *o = f + 4 * S;
  switch (S) {
    case 0: des_sbox1(b1, b2, b3, b4, b5, b6, o[0], o[1], o[2], o[3]); break;
    case 1: des_sbox2(b1, b2, b3, b4, b5, b6, o[0], o[1], o[2], o[3]); break;
    case 2: des_sbox3(b1, b2, b3, b4, b5, b6, o[0], o[1], o[2], o[3]); break;
    case 3: des_sbox4(b1, b2, b3, b4, b5, b6, o[0], o[1], o[2], o[3]); break;
    case 4: des_sbox5(b1, b2, b3, b4, b5, b6, o[0], o[1], o[2], o[3]); break;
    case 5: des_sbox6(b1, b2, b3, b4, b5, b6, o[0], o[1], o[2], o[3]); break;
    case 6: des_sbox7(b1, b2, b3, b4, b5, b6, o[0], o[1], o[2], o[3]); break;
    case 7: des_sbox8(b1, b2, b3, b4, b5, b6, o[0], o[1], o[2], o[3]); break;
  }
}

// L ^= P(S(E(R) ^ K)) over all 32 lanes.
void round_(uint32_t *l, const uint32_t *r, const uint32_t *k)
{
  uint32_t f[32];
  sbox<0>(r, k, f);
  sbox<1>(r, k, f);
  sbox<2>(r, k, f);
  sbox<3>(r, k, f);
  sbox<4>(r, k, f);
  sbox<5>(r, k, f);
  sbox<6>(r, k, f);
  sbox<7>(r, k, f);
  for (int i = 0; i < 32; i++) l[i] ^= f[p32[i] - 1];
}

}  // namespace

Des::~Des()
{
  wipe(ks_, sizeof ks_);
}

void Des::setkey(const uint8_t key[8])
{
  uint32_t cd[56], rot[56];
  for (int j = 0; j < 56; j++) {
    int l = pc1[j] - 1;
    cd[j] = 0u - ((key[l >> 3] >> (7 - (l & 7))) & 1u);
  }
  for (int i = 0; i < 16; i++) {
    for (int j = 0; j < 56; j++) {
      int l = j + totrot[i];
      rot[j] = cd[l < (j < 28 ? 28 : 56) ? l : l - 28];
    }
    for (int j = 0; j < 48; j++) ks_[i][j] = rot[pc2[j] - 1];
  }
  wipe(cd, sizeof cd);
  wipe(rot, sizeof rot);
}

void Des::layer(uint8_t *b, bool encrypt) const
{
  // t[i] holds bit i+1 (FIPS numbering) of all 32 words, one word per lane.
  uint32_t t[64], lr[64], out[64];
  for (int w = 0; w < 32; w++) {
    const uint8_t *p = b + 8 * w;
    t[w] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
    t[32 + w] = (uint32_t)p[4] << 24 | (uint32_t)p[5] << 16 | (uint32_t)p[6] << 8 | p[7];
  }
  transpose(t);
  transpose(t + 32);

  for (int i = 0; i < 64; i++) lr[i] = t[ip[i] - 1];
  uint32_t *l = lr, *r = lr + 32;
  for (int i = 0; i < 16; i++) {
    round_(l, r, ks_[encrypt ? i : 15 - i]);
    uint32_t *x = l; l = r; r = x;
  }
  // The final swap: the preoutput is R16 || L16.
  for (int i = 0; i < 64; i++) {
    int src = fp[i] - 1;
    out[i] = src < 32 ? r[src] : l[src - 32];
  }

  transpose(out);
  transpose(out + 32);
  for (int w = 0; w < 32; w++) {
    uint8_t *p = b + 8 * w;
    uint32_t hi = out[w], lo = out[32 + w];
    p[0] = hi >> 24; p[1] = hi >> 16; p[2] = hi >> 8; p[3] = hi;
    p[4] = lo >> 24; p[5] = lo >> 16; p[6] = lo >> 8; p[7] = lo;
  }
}

void Des::block(uint8_t *block, bool encrypt) const
{
  uint8_t b[256] = {};
  memcpy(b, block, 8);
  layer(b, encrypt);
  memcpy(block, b, 8);
}
