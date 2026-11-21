// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Andy van Wezel
//
// Generates src/des_sbox_ct.h: each DES S-box as a straight-line boolean circuit over 32-bit
// lanes, derived from the FIPS 46 tables by the Moebius transform (algebraic normal form).
// Build and run with `make gen`.
#include <cstdint>
#include <cstdio>
#include <set>
#include <vector>

namespace {

const uint8_t si[8][64] = {
  { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
     0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
     4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
    15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 },
  { 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
     3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
     0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 },
  { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
     1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 },
  {  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
     3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 },
  {  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
     4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 },
  { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
     9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
     4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 },
  {  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
     1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
     6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 },
  { 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
     1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
     7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
     2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 }
};

// Input x has b1 in bit 5 ... b6 in bit 0; FIPS 46 selects row by b1b6 and column by b2b3b4b5.
int sbox_out(int s, int x, int k)
{
  int row = ((x >> 4) & 2) | (x & 1), col = (x >> 1) & 15;
  return (si[s][16 * row + col] >> (3 - k)) & 1;
}

// Moebius transform: coefficient of monomial m is the XOR of f over all x that are subsets of m.
std::vector<int> anf(int s, int k)
{
  std::vector<int> a(64);
  for (int x = 0; x < 64; x++) a[x] = sbox_out(s, x, k);
  for (int i = 0; i < 6; i++)
    for (int x = 0; x < 64; x++)
      if (x & (1 << i)) a[x] ^= a[x ^ (1 << i)];
  return a;
}

// The number of set bits of m.
int popcount(unsigned m)
{
  int n = 0;
  for (; m; m >>= 1) n += m & 1;
  return n;
}

// The index of the lowest set bit of a mask of six variables.
int lowest_bit(unsigned m)
{
  for (int i = 0; i < 6; i++)
    if (m >> i & 1) return i;
  return 0;
}

const char *name(int m, char *buf)
{
  if (popcount(m) == 1) snprintf(buf, 8, "b%d", 6 - lowest_bit(m));
  else snprintf(buf, 8, "t%02x", m);
  return buf;
}

int total_and, total_xor, total_not;

void emit(int s)
{
  std::vector<int> a[4];
  std::set<int> need;
  for (int k = 0; k < 4; k++) {
    a[k] = anf(s, k);
    for (int m = 1; m < 64; m++)
      if (a[k][m]) need.insert(m);
  }
  // Every product needs the product without its lowest variable.
  for (bool grew = true; grew;) {
    grew = false;
    for (int m : std::set<int>(need))
      if (popcount(m) >= 2 && need.insert(m & (m - 1)).second) grew = true;
  }
  int ands = 0, xors = 0, nots = 0;
  char n1[8], n2[8], n3[8];
  printf("static inline void des_sbox%d(uint32_t b1, uint32_t b2, uint32_t b3, uint32_t b4, uint32_t b5, uint32_t b6,\n"
         "                              uint32_t &o1, uint32_t &o2, uint32_t &o3, uint32_t &o4)\n{\n", s + 1);
  for (int deg = 2; deg <= 6; deg++)
    for (int m : need)
      if (popcount(m) == deg) {
        int low = m & -m;
        printf("  uint32_t %s = %s & %s;\n", name(m, n1), name(m & (m - 1), n2), name(low, n3));
        ands++;
      }
  for (int k = 0; k < 4; k++) {
    printf("  o%d = ", k + 1);
    if (a[k][0]) { printf("~("); nots++; }
    bool first = true;
    for (int m = 1; m < 64; m++)
      if (a[k][m]) {
        printf("%s%s", first ? "" : " ^ ", name(m, n1));
        if (!first) xors++;
        first = false;
      }
    printf("%s;\n", a[k][0] ? ")" : "");
  }
  printf("}\n\n");
  fprintf(stderr, "S%d: %d and, %d xor, %d not\n", s + 1, ands, xors, nots);
  total_and += ands; total_xor += xors; total_not += nots;
}

}  // namespace

int main()
{
  printf("// SPDX-License-Identifier: MIT\n"
         "// Copyright (c) 2026 Andy van Wezel\n"
         "//\n"
         "// GENERATED by tools/gen_des_sbox.cpp (make gen); do not edit.\n"
         "// The eight DES S-boxes in algebraic normal form over 32 parallel lanes: b1 is the\n"
         "// first (row) input bit, b6 the last; o1 is the most significant output bit.\n"
         "#pragma once\n\n#include <cstdint>\n\n");
  for (int s = 0; s < 8; s++) emit(s);
  printf("// Total per S-box layer: %d and, %d xor, %d not.\n", total_and, total_xor, total_not);
  return 0;
}
