// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Andy van Wezel
//
// A scaled model of the cipher core for ANALYSIS.md section 6.2: 32 words of 16 bits instead of
// 64, the nibble swaps of sillydes_cipher.cpp at that size, and an independent random permutation
// for every layer and word in place of DES_k(x ^ W). With 16-bit words a whole structure (every
// value of one input word of layer 0, the rest constant) has 65536 texts and can be enumerated.
//
// It measures, and compares with what the analysis predicts:
//   - how many words vary after each layer, and how often two texts agree in a word;
//   - the same for random texts, as a control: they must show nothing;
//   - how a guess of the first layer's word, and of the last layer's two words, is told from wrong ones;
//   - how often a difference in one word is in one word again after a swap.
// The predictions scale with the half word h (here 2^8, in the cipher 2^32): a factor 36 after
// layer 6 at every size, and 1 + 122/h after layer 7, which is 1.48 here and 1 + 2^-25 in the cipher.
//
// Exit code 0 when every figure is in its range. The random numbers are raw mt19937_64 output and
// the shuffle is written out, so every platform computes the same figures.
//
// Not part of the program or of the default tests: -DSILLYDES_ANALYSIS_TOOLS=ON, target check_analysis.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <utility>
#include <vector>

namespace {

enum { NW = 32, BL = 2 * NW, NLAY = 8, N = 1 << 16 };
const int GROUPS[5] = { BL >> 4, BL >> 3, BL >> 2, BL >> 1, BL };   // 16, 32, 64, 128, 256 bytes in the cipher

std::mt19937_64 rng(20261125);
uint16_t perm[NLAY][NW][N];
uint16_t state[N][NLAY][NW];   // word k after layer l, for text t
int failures = 0;

void swap_nibbles(uint8_t *work, int bs)
{
  for (int i = 0, j = bs / 2; i < bs / 2; i++, j++) {
    uint8_t h1 = (uint8_t)((work[i] & 0xF0) >> 4), l1 = (uint8_t)(work[i] & 0x0F);
    uint8_t h2 = (uint8_t)(work[j] & 0xF0), l2 = (uint8_t)((work[j] & 0x0F) << 4);
    work[i] = (uint8_t)(l2 | l1);
    work[j] = (uint8_t)(h2 | h1);
  }
}

void swap_groups(uint8_t *blk, int bs)
{
  for (int off = 0; off < BL; off += bs) swap_nibbles(blk + off, bs);
}

uint16_t getw(const uint8_t *b, int k) { return (uint16_t)((b[2 * k] << 8) | b[2 * k + 1]); }
void putw(uint8_t *b, int k, uint16_t v) { b[2 * k] = (uint8_t)(v >> 8); b[2 * k + 1] = (uint8_t)(v & 0xFF); }

void random_permutation(uint16_t *p)
{
  for (int i = 0; i < N; i++) p[i] = (uint16_t)i;
  for (int i = N - 1; i > 0; i--) std::swap(p[i], p[(size_t)(rng() % (uint64_t)(i + 1))]);
}

void new_key()
{
  for (int l = 0; l < NLAY; l++)
    for (int k = 0; k < NW; k++) random_permutation(perm[l][k]);
}

// The core, as encrypt_block: swap, then per layer the word permutations and the swap between layers.
void encrypt(int t, const uint8_t *plain)
{
  uint8_t s[BL];
  memcpy(s, plain, BL);
  swap_groups(s, BL);
  for (int l = 0; l < NLAY; l++) {
    for (int k = 0; k < NW; k++) {
      uint16_t v = perm[l][k][getw(s, k)];
      putw(s, k, v);
      state[t][l][k] = v;
    }
    if (l < NLAY - 1) swap_groups(s, GROUPS[l % 5]);
  }
}

// Every value of the input word w0 of layer 0; the swap is its own inverse.
void encrypt_structure(int w0)
{
  uint8_t base[BL];
  for (int i = 0; i < BL; i++) base[i] = (uint8_t)rng();
  for (int v = 0; v < N; v++) {
    uint8_t s[BL];
    memcpy(s, base, BL);
    putw(s, w0, (uint16_t)v);
    swap_groups(s, BL);
    encrypt(v, s);
  }
}

void encrypt_random_texts()
{
  for (int t = 0; t < N; t++) {
    uint8_t s[BL];
    for (int i = 0; i < BL; i++) s[i] = (uint8_t)rng();
    encrypt(t, s);
  }
}

double colliding_pairs(std::vector<uint16_t> v)
{
  std::sort(v.begin(), v.end());
  double c = 0;
  for (size_t i = 0; i < v.size();) {
    size_t j = i;
    while (j < v.size() && v[j] == v[i]) j++;
    c += (double)(j - i) * (double)(j - i - 1) / 2;
    i = j;
  }
  return c;
}

// Pairs of texts with an equal word after the layer, over the words that vary, as a multiple of the random rate.
double excess(int layer, int texts, int *active)
{
  double pairs = 0;
  *active = 0;
  for (int k = 0; k < NW; k++) {
    std::vector<uint16_t> v((size_t)texts);
    for (int t = 0; t < texts; t++) v[(size_t)t] = state[t][layer][k];
    double c = colliding_pairs(v);
    if (c < (double)texts * (texts - 1) / 2) { (*active)++; pairs += c; }
  }
  return *active ? pairs / *active / ((double)texts * (texts - 1) / 2 / N) : 0;
}

void check(bool ok, const char *what)
{
  if (!ok) { failures++; fprintf(stderr, "FAIL: %s\n", what); }
}

}  // namespace

int main()
{
  static const int words[NLAY] = { 1, 2, 4, 8, 16, 32, 32, 32 };
  const int keys = 3;
  double after6 = 0, after7 = 0, control6 = 0, control7 = 0, part6 = 0;
  long hit = 0, total = 0;

  for (int n = 0; n < keys; n++) {
    new_key();
    int w0 = (int)(rng() % NW), active = 0;
    encrypt_structure(w0);
    bool spread = true;
    for (int l = 0; l < NLAY; l++) {
      double e = excess(l, N, &active);
      spread = spread && active == words[l];
      if (l == 6) after6 += e / keys;
      if (l == 7) after7 += e / keys;
    }
    check(spread, "the words that vary after layers 0 to 7 are not 1 2 4 8 16 32 32 32");
    part6 += excess(6, N / 8, &active) / keys;   // the first 8192 texts of the structure: the excess is a property of pairs

    // A difference in one word (here: of the output of layer 0) is in one word again after the swap when it
    // lies in one nibble half: it stays, or it moves to the partner word as a whole.
    for (int i = 0; i < 1000000; i++) {
      int a = (int)(rng() % N), b = (int)(rng() % N);
      if (a == b) continue;
      uint16_t d = (uint16_t)(state[a][0][w0] ^ state[b][0][w0]);
      total++;
      hit += (d & 0xF0F0) == 0 || (d & 0x0F0F) == 0;
    }

    // Guess of the first layer's word. The pairs with an equal ciphertext word are listed without any key;
    // under the right guess many of them share a nibble half of the output of layer 0.
    std::vector<std::pair<int, int> > listed;
    for (int k = 0; k < NW; k++) {
      std::vector<std::pair<uint16_t, int> > v((size_t)N);
      for (int t = 0; t < N; t++) v[(size_t)t] = std::make_pair(state[t][7][k], t);
      std::sort(v.begin(), v.end());
      for (size_t i = 0; i < v.size();) {
        size_t j = i;
        while (j < v.size() && v[j].first == v[i].first) j++;
        for (size_t a = i; a < j; a++)
          for (size_t b = a + 1; b < j; b++) listed.push_back(std::make_pair(v[a].second, v[b].second));
        i = j;
      }
    }
    std::vector<uint16_t> guess((size_t)N), guess2((size_t)N);
    long right = 0, wrong_max = 0;
    for (int g = 0; g <= 50; g++) {
      const uint16_t *p = perm[0][w0];
      if (g) { random_permutation(guess.data()); p = guess.data(); }
      long score = 0;
      for (size_t i = 0; i < listed.size(); i++) {
        uint16_t d = (uint16_t)(p[listed[i].first] ^ p[listed[i].second]);
        score += (d & 0xF0F0) == 0 || (d & 0x0F0F) == 0;
      }
      if (g) wrong_max = std::max(wrong_max, score); else right = score;
    }
    printf("info: key %d, first layer: %lu listed pairs; sharing a half under the right guess %ld, under 50 wrong guesses at most %ld\n",
           n, (unsigned long)listed.size(), right, wrong_max);
    check(right > 10 * wrong_max, "the right guess of the first layer does not stand out");

    // Guess of the last layer's words w and w^2: rebuild word w of the output of layer 6 and count equal pairs.
    int w = (int)(rng() % NW);
    double right7 = 0, wrong7 = 0;
    for (int g = 0; g <= 20; g++) {
      std::vector<uint16_t> ia((size_t)N), ib((size_t)N), v((size_t)N);
      if (g) { random_permutation(ia.data()); random_permutation(ib.data()); }
      else
        for (int i = 0; i < N; i++) { ia[perm[7][w][i]] = (uint16_t)i; ib[perm[7][w ^ 2][i]] = (uint16_t)i; }
      for (int t = 0; t < N; t++) {
        uint8_t x[BL] = { 0 };
        putw(x, w, ia[state[t][7][w]]);
        putw(x, w ^ 2, ib[state[t][7][w ^ 2]]);
        swap_groups(x, GROUPS[6 % 5]);
        v[(size_t)t] = getw(x, w);
      }
      double c = colliding_pairs(v);
      if (g) wrong7 = std::max(wrong7, c); else right7 = c;
    }
    printf("info: key %d, last layer: equal pairs in the rebuilt word under the right guess %.0f, under 20 wrong guesses at most %.0f\n", n, right7, wrong7);
    check(right7 > 10 * wrong7, "the right guess of the last layer does not stand out");

    encrypt_random_texts();
    control6 += excess(6, N, &active) / keys;
    control7 += excess(7, N, &active) / keys;
  }

  printf("info: equal words between texts of a structure, as a multiple of the random rate: after layer 6 %.1f (predicted 36), "
         "in an eighth of the structure %.1f, after layer 7 %.2f (predicted 1.48)\n", after6, part6, after7);
  printf("info: control, random texts: after layer 6 %.3f, after layer 7 %.3f (1 expected)\n", control6, control7);
  check(after6 > 30 && after6 < 45, "the excess after layer 6 is not near 36");
  check(part6 > 30 && part6 < 45, "the excess after layer 6 in a part of the structure is not near 36");
  check(after7 > 1.35 && after7 < 1.60, "the excess after layer 7 is not near 1.48");
  check(control6 > 0.97 && control6 < 1.03 && control7 > 0.97 && control7 < 1.03, "control: random texts show an excess");

  double p = (double)hit / (double)total;
  printf("info: a difference in one word is in one word after a swap with probability %.5f (2^-7 = %.5f)\n", p, 1.0 / 128);
  check(p > 0.0074 && p < 0.0082, "the probability for one word across a swap is not near 2^-7");

  if (!failures) printf("ok: the scaled model shows what ANALYSIS.md section 6.2 predicts\n");
  return failures ? 1 : 0;
}
