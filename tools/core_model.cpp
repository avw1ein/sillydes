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
//   - how often two texts agree in both ciphertext words of a pair (p, p ^ 2), which the last layer
//     and the swap before it take one-to-one from two words of the output of layer 6, and how many of
//     those pairs of texts share a half of the output of layer 0;
//   - how a guess of the first layer's word, and of the last layer's two words, is told from wrong ones;
//   - how often a difference in one word is in one word again after a swap;
//   - for section 12.4, the guesses when only one value in f of the layer cipher may be evaluated: how
//     many more texts make up for the smaller table. Here the first layer is a small keyed cipher
//     (a 4-bit key and a 16-bit whitening word) and every one of its 2^20 guesses is tried.
// The predictions scale with the half word h (here 2^8, in the cipher 2^32): 5h times the random rate
// after layer 5, a factor 36 after layer 6 at every size, 1 + 122/h after layer 7 (1.48 here,
// 1 + 2^-25 in the cipher), and 48/h^3 of the pairs of texts for a pair of words (core_scale.cpp
// checks that exponent at two larger sizes).
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

template <class T> double colliding_pairs(std::vector<T> v)
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

typedef std::vector<std::pair<uint16_t, uint16_t> > Pairs;

// Pairs of the first texts that agree in both ciphertext words of a pair (p, p ^ 2). No key is used.
void two_word_pairs(int texts, Pairs &out)
{
  out.clear();
  for (int p = 0; p < NW; p++) {
    if (p & 2) continue;
    std::vector<std::pair<uint32_t, uint16_t> > v((size_t)texts);
    for (int t = 0; t < texts; t++)
      v[(size_t)t] = std::make_pair((uint32_t)state[t][7][p] << 16 | state[t][7][p ^ 2], (uint16_t)t);
    std::sort(v.begin(), v.end());
    for (size_t i = 0; i < v.size();) {
      size_t j = i;
      while (j < v.size() && v[j].first == v[i].first) j++;
      for (size_t a = i; a < j; a++)
        for (size_t b = a + 1; b < j; b++) out.push_back(std::make_pair(v[a].second, v[b].second));
      i = j;
    }
  }
}

bool shares_half(uint16_t a, uint16_t b)
{
  uint16_t d = (uint16_t)(a ^ b);
  return (d & 0xF0F0) == 0 || (d & 0x0F0F) == 0;
}

// ---- Counted in evaluations of the layer cipher (ANALYSIS.md section 12.4) ----
// The attacker's table of the layer cipher holds one value in f: those with the low bits zero.

enum { KEYBITS = 4, KEYS = 1 << KEYBITS };
uint16_t cipher[KEYS][N];        // the layer cipher of the first layer: a random permutation for every key
uint16_t inverse[2][NW][N];      // a guess of layers 6 and 7, backwards

struct Scores { long right, wrong; };   // the right guess, and the best of the wrong ones

int log2i(int f) { int n = 0; while ((1 << n) < f) n++; return n; }

// The first layer with a table of KEYS * N / f entries, and every guess of key and whitening word.
// A text can be used under a guess when its input to the cipher is in the table, so the pairs that
// count have both texts in the class of the guessed whitening word. The score of a guess is the
// number of listed pairs that share a half of the output of layer 0 under it.
Scores first_layer(int texts, int f, int k0, int W0)
{
  const int lf = log2i(f), size = N >> lf;
  Pairs listed;
  two_word_pairs(texts, listed);
  std::sort(listed.begin(), listed.end());   // a pair of texts counts once, in however many pairs of words it agrees
  listed.erase(std::unique(listed.begin(), listed.end()), listed.end());
  std::vector<Pairs> pairs((size_t)f);
  for (size_t i = 0; i < listed.size(); i++)
    if (((listed[i].first ^ listed[i].second) & (f - 1)) == 0) pairs[(size_t)(listed[i].first & (f - 1))].push_back(listed[i]);
  std::vector<uint16_t> table((size_t)KEYS * (size_t)size);   // all that the attacker knows of the cipher
  for (int k = 0; k < KEYS; k++)
    for (int i = 0; i < size; i++) table[(size_t)k * (size_t)size + (size_t)i] = cipher[k][i << lf];
  Scores r = { 0, 0 };
  for (int k = 0; k < KEYS; k++) {
    const uint16_t *t = &table[(size_t)k * (size_t)size];
    for (int W = 0; W < N; W++) {
      const Pairs &p = pairs[(size_t)(W & (f - 1))];
      long score = 0;
      for (size_t i = 0; i < p.size(); i++) score += shares_half(t[(p[i].first ^ W) >> lf], t[(p[i].second ^ W) >> lf]);
      if (k == k0 && W == W0) r.right = score; else r.wrong = std::max(r.wrong, score);
    }
  }
  return r;
}

// The words of layer l that word w of the output of layer 7 - depth is rebuilt from, as a bit mask.
uint32_t needed[NLAY];
void needed_words(int depth, int w)
{
  uint32_t m = 1u << w;
  for (int l = NLAY - depth; l < NLAY; l++) {
    int stride = GROUPS[(l - 1) % 5] / 4;   // the swap after layer l - 1 joins word k and word k ^ stride
    uint32_t n = 0;
    for (int k = 0; k < NW; k++)
      if (m >> k & 1) n |= 1u << k | 1u << (k ^ stride);
    needed[l] = m = n;
  }
}

// Pairs of texts with an equal word w at the output of layer 7 - depth, rebuilt from the ciphertext with
// the guess in inverse[]. A text counts when every value that has to be looked up is in the table. Texts
// that agree in all the ciphertext words used give equal words under every guess and are not counted.
long rebuilt_pairs(int texts, int f, int depth, int w)
{
  std::vector<uint16_t> v;
  std::vector<uint64_t> same;
  for (int t = 0; t < texts; t++) {
    uint8_t x[BL] = { 0 };
    uint64_t used = 0;
    bool known = true;
    for (int k = 0; k < NW; k++)
      if (needed[NLAY - 1] >> k & 1) {
        putw(x, k, state[t][7][k]);
        used = used << 16 | state[t][7][k];
      }
    for (int l = NLAY - 1; l >= NLAY - depth && known; l--) {
      for (int k = 0; k < NW; k++)
        if (needed[l] >> k & 1) {
          uint16_t y = getw(x, k);
          if (y & (f - 1)) known = false;
          putw(x, k, inverse[l - 6][k][y]);
        }
      swap_groups(x, GROUPS[(l - 1) % 5]);
    }
    if (known) { v.push_back(getw(x, w)); same.push_back(used); }
  }
  return (long)(colliding_pairs(v) - colliding_pairs(same));
}

// The guess of the last layer (depth 1: two words) or of the last two (depth 2: four words and two),
// against 20 wrong guesses.
Scores from_the_end(int texts, int f, int depth, int w)
{
  Scores r = { 0, 0 };
  needed_words(depth, w);
  for (int g = 0; g <= 20; g++) {
    for (int l = NLAY - depth; l < NLAY; l++)
      for (int k = 0; k < NW; k++)
        if (needed[l] >> k & 1) {
          if (g) random_permutation(inverse[l - 6][k]);
          else
            for (int i = 0; i < N; i++) inverse[l - 6][k][perm[l][k][i]] = (uint16_t)i;
        }
    long score = rebuilt_pairs(texts, f, depth, w);
    if (g) r.wrong = std::max(r.wrong, score); else r.right = score;
  }
  return r;
}

// One line of the trade between table and texts. As the table shrinks the texts grow, and the right guess
// must stand out as before; the control is the smallest table with the texts of the largest.
bool report(const char *what, int f, int texts, bool control, Scores r)
{
  printf("info: %s, 1/%d of the table of the layer cipher, %d texts%s: right guess %ld, best wrong guess %ld\n",
         what, f, texts, control ? " (control)" : "", r.right, r.wrong);
  return (r.right > 4 * r.wrong && r.right >= 40) != control;
}

}  // namespace

int main()
{
  static const int words[NLAY] = { 1, 2, 4, 8, 16, 32, 32, 32 };
  const int keys = 3;
  double after5 = 0, after6 = 0, after7 = 0, control6 = 0, control7 = 0, part6 = 0;
  double two = 0, two_share = 0, two_control = 0;
  Pairs listed2;
  long hit = 0, total = 0;

  for (int n = 0; n < keys; n++) {
    new_key();
    int w0 = (int)(rng() % NW), active = 0;
    encrypt_structure(w0);
    bool spread = true;
    for (int l = 0; l < NLAY; l++) {
      double e = excess(l, N, &active);
      spread = spread && active == words[l];
      if (l == 5) after5 += e / keys;
      if (l == 6) after6 += e / keys;
      if (l == 7) after7 += e / keys;
    }
    check(spread, "the words that vary after layers 0 to 7 are not 1 2 4 8 16 32 32 32");
    part6 += excess(6, N / 8, &active) / keys;   // the first 8192 texts of the structure: the excess is a property of pairs

    // Both ciphertext words of a pair (p, p ^ 2), per pair of words, and how many of these pairs of texts
    // share a nibble half of the output of layer 0.
    two_word_pairs(N, listed2);
    long share = 0;
    for (size_t i = 0; i < listed2.size(); i++) share += shares_half(state[listed2[i].first][0][w0], state[listed2[i].second][0][w0]);
    two += (double)listed2.size() / (NW / 2) / keys;
    two_share += (double)share / (double)listed2.size() / keys;

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
    two_word_pairs(N, listed2);
    two_control += (double)listed2.size() / (NW / 2) / keys;
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

  const double text_pairs = (double)N * (N - 1) / 2;
  printf("info: equal words after layer 5, as a multiple of the random rate: %.0f (predicted 5h = 1280)\n", after5);
  printf("info: pairs of texts of a structure that agree in both ciphertext words of a pair (p, p ^ 2): %.0f for a pair of words "
         "(predicted 48/h^3 of the pairs of texts: %.0f; a random permutation: %.1f), %.1f%% of them share a half of the output of layer 0\n",
         two, 48.0 / 16777216 * text_pairs, text_pairs / 4294967296.0, 100 * two_share);
  printf("info: control, random texts: %.2f for a pair of words\n", two_control);
  check(after5 > 1150 && after5 < 1400, "the excess after layer 5 is not near 5h");
  check(two > 5000 && two < 7500, "the pairs that agree in both words of a pair are not near 48/h^3");
  check(two_share > 0.93, "the pairs that agree in both words of a pair do not share a half of the output of layer 0");
  check(two_control < 3, "control: random texts agree in both words of a pair");

  // Counted in evaluations of the layer cipher. The first layer of one word is a keyed cipher with a whitening word.
  {
    new_key();
    const int w0 = (int)(rng() % NW), k0 = (int)(rng() % KEYS), W0 = (int)(rng() % N), w = (int)(rng() % NW);
    for (int k = 0; k < KEYS; k++) random_permutation(cipher[k]);
    for (int x = 0; x < N; x++) perm[0][w0][x] = cipher[k0][x ^ W0];
    encrypt_structure(w0);

    static const int first[][2] = { { 1, 4096 }, { 4, 16384 }, { 16, 65536 }, { 16, 4096 } };  // table 1/f, texts times f
    static const int last[][2] = { { 1, 1024 }, { 2, 4096 }, { 4, 16384 }, { 4, 1024 } };      // texts times f^2
    static const int last2[][2] = { { 1, 128 }, { 2, 8192 }, { 2, 128 } };                     // texts times f^6
    bool ok = true;
    for (int i = 0; i < 4; i++)
      ok = report("first layer, all 2^20 guesses", first[i][0], first[i][1], i == 3, first_layer(first[i][1], first[i][0], k0, W0)) && ok;
    check(ok, "the first layer with a part of the table: f times the texts do not make up for a table of 1/f");
    ok = true;
    for (int i = 0; i < 4; i++)
      ok = report("last layer, 20 wrong guesses", last[i][0], last[i][1], i == 3, from_the_end(last[i][1], last[i][0], 1, w)) && ok;
    check(ok, "the last layer with a part of the table: f^2 times the texts do not make up for a table of 1/f");
    ok = true;
    for (int i = 0; i < 3; i++)
      ok = report("last two layers, 20 wrong guesses", last2[i][0], last2[i][1], i == 2, from_the_end(last2[i][1], last2[i][0], 2, w)) && ok;
    check(ok, "the last two layers with a part of the table: f^6 times the texts do not make up for a table of 1/f");
  }

  if (!failures) printf("ok: the scaled model shows what ANALYSIS.md sections 6.2 and 12.4 predict\n");
  return failures ? 1 : 0;
}
