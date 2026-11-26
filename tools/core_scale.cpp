// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Andy van Wezel
//
// The exponent behind ANALYSIS.md section 6.2. The last layer and the swap before it take the two
// words p and p ^ 2 of the output of layer 6 one-to-one to the ciphertext words p and p ^ 2, so two
// texts of a structure agree in both of them when they agree in a half of the output of layer 0 and
// the other half collides on the way to both words: 48/h^3 of the pairs of texts for a half word of
// h values, against 1/h^4 for a random permutation. The cipher has h = 2^32, where nothing can be
// counted. core_model.cpp counts at h = 2^8; this program counts at h = 2^12 and h = 2^16, with the
// nibble swaps of sillydes_cipher.cpp at those word sizes (words of 24 and 32 bits) and a keyed Feistel
// permutation for every layer and word in place of DES_k(x ^ W). If the rate follows 48/h^3 over these three sizes, a factor
// of 2^24 in the rate, the figure for the cipher is an extrapolation of a checked law.
//
// It also counts how many of the pairs found share a nibble half of the output of layer 0, which is what
// the key recovery uses, and random texts as a control.
//
// Exit code 0 when every figure is in its range. The random numbers are raw mt19937_64 output, so every
// platform computes the same figures. About 300 MB of memory.
//
// Not part of the program or of the default tests: -DSILLYDES_ANALYSIS_TOOLS=ON, target check_analysis.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

namespace {

enum { NW = 32, NLAY = 8 };

std::mt19937_64 rng(20261126);
int failures = 0;

void check(bool ok, const char *what)
{
  if (!ok) { failures++; fprintf(stderr, "FAIL: %s\n", what); }
}

struct Model {
  int hb;                   // bits in a half word: 12 or 16
  uint32_t half, lo, hi;    // a Feistel half; the low and the high nibbles of every byte of a word
  uint32_t key[NLAY][NW][4];
  uint32_t in[NLAY][NW], out[NLAY][NW];   // the last value of every word: most words of a structure do not change
  bool seen[NLAY][NW];
  uint32_t base[NW];
  int w0;

  explicit Model(int word_bytes) : hb(4 * word_bytes), half((1u << (4 * word_bytes)) - 1), w0(0)
  {
    lo = 0x0F0F0F0Fu >> (32 - 8 * word_bytes);
    hi = lo << 4;
  }

  void new_key()
  {
    for (int l = 0; l < NLAY; l++)
      for (int k = 0; k < NW; k++) {
        for (int i = 0; i < 4; i++) key[l][k][i] = (uint32_t)rng();
        seen[l][k] = false;
      }
    for (int k = 0; k < NW; k++) base[k] = (uint32_t)rng() & (lo | hi);
    w0 = (int)(rng() % NW);
  }

  // swap_nibbles of sillydes_cipher.cpp on groups of 2 * stride words: byte i of the first half of a group
  // keeps its low nibble and takes the low nibble of byte i of the second half as its high nibble; the
  // second half keeps its high nibble and takes the high nibble of the first as its low nibble.
  void swap_groups(uint32_t *s, int stride) const
  {
    for (int k = 0; k < NW; k++)
      if (!(k & stride)) {
        uint32_t a = s[k], b = s[k + stride];
        s[k] = (a & lo) | (b & lo) << 4;
        s[k + stride] = (b & hi) | (a & hi) >> 4;
      }
  }

  // A permutation of the word for every layer and word: four Feistel rounds on its two halves.
  uint32_t permute(const uint32_t *k, uint32_t x) const
  {
    uint32_t l = x >> hb, r = x & half;
    for (int i = 0; i < 4; i++) {
      uint32_t f = (r ^ k[i]) * 0x9E3779B1u;
      f ^= f >> 15;
      f *= 0x85EBCA77u;
      f ^= f >> 13;
      uint32_t t = l ^ (f & half);
      l = r;
      r = t;
    }
    return l << hb | r;
  }

  // The eight layers on the state s at the input of layer 0, which becomes the ciphertext. Returns the
  // output of layer 0 at word w0. The swaps after layers 0 to 6 join words 1, 2, 4, 8, 16, 1, 2 apart.
  uint32_t encrypt(uint32_t *s)
  {
    uint32_t first = 0;
    for (int l = 0; l < NLAY; l++) {
      for (int k = 0; k < NW; k++) {
        if (!seen[l][k] || in[l][k] != s[k]) {
          in[l][k] = s[k];
          out[l][k] = permute(key[l][k], s[k]);
          seen[l][k] = true;
        }
        s[k] = out[l][k];
      }
      if (l == 0) first = s[w0];
      if (l < NLAY - 1) swap_groups(s, 1 << (l % 5));
    }
    return first;
  }

  // Text t: of a structure (the input word w0 of layer 0 takes a different value for every t), or random.
  uint32_t text(uint32_t t, bool structure, uint64_t seed, uint32_t *cipher)
  {
    if (structure) {
      memcpy(cipher, base, sizeof base);
      cipher[w0] = (t * 0x9E3779B1u + 12345u) & (lo | hi);   // odd multiplier: one-to-one
    } else {
      std::mt19937_64 r(seed + t);
      for (int k = 0; k < NW; k++) cipher[k] = (uint32_t)r() & (lo | hi);
    }
    return encrypt(cipher);
  }

  bool shares_half(uint32_t a, uint32_t b) const
  {
    uint32_t d = a ^ b;
    return (d & hi) == 0 || (d & lo) == 0;
  }
};

struct Count { double pairs, shared; };

// Pairs of texts that agree in both ciphertext words of a pair (p, p ^ 2), over the 16 pairs of words.
// A 32-bit hash of the two words is kept for every text; texts with an equal hash are encrypted again
// and compared word for word.
Count count(Model &m, uint32_t texts, bool structure)   // texts: a power of two
{
  const uint64_t seed = rng();
  std::vector<uint32_t> first(texts);
  std::vector<std::vector<uint32_t> > hash(NW / 2, std::vector<uint32_t>(texts));
  int word[NW / 2];
  for (int p = 0, i = 0; p < NW; p++)
    if (!(p & 2)) word[i++] = p;
  uint32_t c[NW], d[NW];
  for (uint32_t t = 0; t < texts; t++) {
    first[t] = m.text(t, structure, seed, c);
    for (int i = 0; i < NW / 2; i++)
      hash[(size_t)i][t] = (uint32_t)((((uint64_t)c[word[i]] << 32 | c[word[i] ^ 2]) * 0x9E3779B97F4A7C15ull) >> 32);
  }
  Count r = { 0, 0 };
  std::vector<uint32_t> start((size_t)texts + 1), order(texts);   // the texts in buckets by the low bits of the hash
  for (int i = 0; i < NW / 2; i++) {
    const std::vector<uint32_t> &h = hash[(size_t)i];
    std::fill(start.begin(), start.end(), 0u);
    for (uint32_t t = 0; t < texts; t++) start[(h[t] & (texts - 1)) + 1]++;
    for (uint32_t b = 0; b < texts; b++) start[b + 1] += start[b];
    for (uint32_t t = 0; t < texts; t++) order[start[h[t] & (texts - 1)]++] = t;   // start[b] is now the end of bucket b
    for (uint32_t b = 0, from = 0; b < texts; from = start[b++])
      for (uint32_t x = from; x < start[b]; x++)
        for (uint32_t y = x + 1; y < start[b]; y++) {
          uint32_t ta = order[x], tb = order[y];
          if (h[ta] != h[tb]) continue;
          m.text(ta, structure, seed, c);
          m.text(tb, structure, seed, d);
          if (c[word[i]] != d[word[i]] || c[word[i] ^ 2] != d[word[i] ^ 2]) continue;
          r.pairs++;
          r.shared += m.shares_half(first[ta], first[tb]);
        }
  }
  return r;
}

double run(int word_bytes, int log_texts, int keys, bool with_control)
{
  Model m(word_bytes);
  const uint32_t texts = 1u << log_texts;
  const double h = (double)(1u << m.hb), text_pairs = (double)texts * (texts - 1) / 2;
  const double predicted = text_pairs * (NW / 2) * 48 / (h * h * h), random = text_pairs * (NW / 2) / (h * h * h * h);
  Count sum = { 0, 0 };
  double control = 0;
  for (int n = 0; n < keys; n++) {
    m.new_key();
    Count c = count(m, texts, true);
    sum.pairs += c.pairs / keys;
    sum.shared += c.shared / keys;
    if (with_control && n == 0) control = count(m, texts, false).pairs;
  }
  printf("info: %d-bit words (h = 2^%d), 2^%d texts of a structure, mean of %d key%s: %.0f pairs of texts agree in both ciphertext words "
         "of a pair (p, p ^ 2); 16 * 48/h^3 predicts %.0f, a random permutation %.2g; %.0f of them share a half of the output of layer 0\n",
         8 * word_bytes, m.hb, log_texts, keys, keys > 1 ? "s" : "", sum.pairs, predicted, random, sum.shared);
  if (with_control) {
    printf("info: control, 2^%d random texts under the first key: %.0f\n", log_texts, control);
    check(control <= 1, "control: random texts agree in both words of a pair");
  }
  check(sum.shared >= 0.97 * sum.pairs, "the pairs found do not share a half of the output of layer 0");
  return sum.pairs / predicted;
}

}  // namespace

int main()
{
  // One pair of texts often agrees in several pairs of words at once, so the counts scatter more than a
  // Poisson count would: single keys by about a tenth at h = 2^12 and by about a third at h = 2^16. An
  // exponent of 2 or 4 in place of 3 would change the second count by a factor of 16.
  double r12 = run(3, 19, 6, true);    // 1536 pairs predicted for each key
  double r16 = run(4, 22, 3, false);   // 24 predicted for each key
  check(r12 > 0.9 && r12 < 1.1, "h = 2^12: the pairs are not near 48/h^3");
  check(r16 > 0.4 && r16 < 1.8, "h = 2^16: the pairs are not near 48/h^3");
  if (!failures) printf("ok: the rate of pairs that agree in two ciphertext words follows 48/h^3 at h = 2^12 and h = 2^16\n");
  return failures ? 1 : 0;
}
