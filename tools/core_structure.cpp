// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Andy van Wezel
//
// ANALYSIS.md section 6.2, on the real cipher. Two texts whose inputs to layer 0 differ in one
// word, and whose outputs of layer 0 agree in one nibble half of that word, are followed through
// the eight layers with the project's Des and its whitening. The claim: the two halves of a word
// travel on separate branches, so the words that differ at the input of layers 0 to 7 number
// 1, 1, 2, 4, 8, 16, 32, 32, and at the input of layer 6 the difference of every word lies in one
// nibble half. The control is a pair that differs in both halves: it must not show this.
//
// A second claim, on the last layer: the swap after layer 6 exchanges halves between the words p and
// p ^ 2 only, and layer 7 works on every word by itself, so two texts that agree in exactly these two
// words at the input of layer 6 agree in exactly the ciphertext words p and p ^ 2. The control changes
// word p as well: then no ciphertext word may agree.
//
// The walk uses its own copy of the swaps and derives the whitening itself with Hmac512; it must
// give the same block as SillyDesCipher::encrypt_block, or it says nothing about the cipher.
//
// Not part of the program or of the default tests: -DSILLYDES_ANALYSIS_TOOLS=ON, target check_analysis.

#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

#include "des.h"
#include "sha512.h"
#include "sillydes_cipher.h"

namespace {

void swap_nibbles(uint8_t *work, size_t bs)
{
  for (size_t i = 0, j = bs / 2; i < bs / 2; i++, j++) {
    uint8_t h1 = (uint8_t)((work[i] & 0xF0) >> 4), l1 = (uint8_t)(work[i] & 0x0F);
    uint8_t h2 = (uint8_t)(work[j] & 0xF0), l2 = (uint8_t)((work[j] & 0x0F) << 4);
    work[i] = (uint8_t)(l2 | l1);
    work[j] = (uint8_t)(h2 | h1);
  }
}

void swap_groups(uint8_t *blk, size_t bs)
{
  for (size_t off = 0; off < 256; off += bs) swap_nibbles(blk + off, bs);
}

void xor256(uint8_t *b, const uint8_t *w)
{
  for (int i = 0; i < 256; i++) b[i] ^= w[i];
}

bool word_differs(const uint8_t *a, const uint8_t *b, int w)
{
  return memcmp(a + 8 * w, b + 8 * w, 8) != 0;
}

// One instance of the core: eight random keys, a random salt, and the whitening derived as the cipher does.
struct Instance {
  uint8_t key[NL][8], salt[SALT_LEN], white[NL + 1][256];
  Des des[NL];

  explicit Instance(std::mt19937_64 &rng)
  {
    for (int n = 0; n < NL; n++)
      for (int i = 0; i < 8; i++) key[n][i] = (uint8_t)rng();
    for (int i = 0; i < SALT_LEN; i++) salt[i] = (uint8_t)rng();
    for (int n = 0; n < NL; n++) des[n].setkey(key[n]);
    static const char label[] = FORMAT_NAME " white";
    Hmac512 mac(&key[0][0], NL * 8);
    for (int j = 0; j <= NL; j++)
      for (int c = 0; c < 4; c++) {
        std::vector<uint8_t> msg(label, label + sizeof label - 1);
        msg.insert(msg.end(), salt, salt + SALT_LEN);
        msg.push_back((uint8_t)j);
        msg.push_back((uint8_t)c);
        mac.mac(msg.data(), msg.size(), &white[j][64 * c]);
      }
  }
};

struct Walk {
  int words_in[NL];     // words that differ at the input of each layer
  int both_halves;      // words at the input of layer 6 whose difference touches both nibble halves
  bool same_as_cipher;  // the walk of the first text equals encrypt_block
  bool one_structure;   // the two plaintexts differ only in the 64 bits that feed word w0 of layer 0
};

// shared_half: the outputs of layer 0 agree in the low or in the high nibbles of word w0.
Walk walk(std::mt19937_64 &rng, bool shared_half)
{
  Instance in(rng);
  Des *des = in.des;
  uint8_t (*white)[256] = in.white;

  // Two outputs of layer 0 that differ in word w0 only, then back to the plaintexts.
  int w0 = (int)(rng() % 32);
  uint8_t keep = (rng() & 1) ? 0xF0 : 0x0F;
  uint8_t s[2][256];
  for (int i = 0; i < 256; i++) s[0][i] = (uint8_t)rng();
  memcpy(s[1], s[0], 256);
  for (int i = 0; i < 8; i++) {
    uint8_t d = (uint8_t)(rng() | 0x11);                         // both nibbles of every byte change
    s[1][8 * w0 + i] ^= (uint8_t)(shared_half ? d & keep : d);
  }
  uint8_t u[2][256];
  for (int t = 0; t < 2; t++) {
    memcpy(u[t], s[t], 256);
    des[0].layer(u[t], false);
    xor256(u[t], white[0]);
  }
  Walk r;
  r.one_structure = true;
  for (int w = 0; w < 32; w++)
    if (w != w0 && word_differs(u[0], u[1], w)) r.one_structure = false;
  for (int t = 0; t < 2; t++) swap_nibbles(u[t], 256);

  uint8_t st[2][256];
  for (int t = 0; t < 2; t++) {
    memcpy(st[t], u[t], 256);
    swap_nibbles(st[t], 256);
  }
  r.both_halves = 0;
  for (int l = 0; l < NL; l++) {
    for (int t = 0; t < 2; t++) xor256(st[t], white[l]);
    r.words_in[l] = 0;
    for (int w = 0; w < 32; w++) r.words_in[l] += word_differs(st[0], st[1], w);
    if (l == 6)
      for (int w = 0; w < 32; w++) {
        uint8_t lo = 0, hi = 0;
        for (int i = 0; i < 8; i++) {
          uint8_t d = (uint8_t)(st[0][8 * w + i] ^ st[1][8 * w + i]);
          lo |= (uint8_t)(d & 0x0F);
          hi |= (uint8_t)(d & 0xF0);
        }
        r.both_halves += lo && hi;
      }
    for (int t = 0; t < 2; t++) des[l].layer(st[t], true);
    if (l < NL - 1)
      for (int t = 0; t < 2; t++) swap_groups(st[t], (size_t)16 << (l % 5));
  }
  for (int t = 0; t < 2; t++) xor256(st[t], white[NL]);

  uint8_t chk[256];
  memcpy(chk, u[0], 256);
  SillyDesCipher(in.key, in.salt).encrypt_block(chk);
  r.same_as_cipher = memcmp(chk, st[0], 256) == 0;
  return r;
}

struct LastLayer {
  int equal_words;      // ciphertext words in which the two texts agree
  bool the_pair;        // they agree in the words p and p ^ 2
  bool same_as_cipher;  // both ciphertexts are what encrypt_block gives for the plaintexts
};

// Two states at the input of layer 6 that agree in the words p and p ^ 2 only (keep_pair), or in word p ^ 2 only.
LastLayer last_layer(std::mt19937_64 &rng, bool keep_pair)
{
  Instance in(rng);
  int p = (int)(rng() % 32);
  uint8_t s6[2][256], c[2][256];
  for (int i = 0; i < 256; i++) s6[0][i] = (uint8_t)rng();
  memcpy(s6[1], s6[0], 256);
  for (int w = 0; w < 32; w++) {
    if (w == (p ^ 2) || (keep_pair && w == p)) continue;
    for (int i = 0; i < 8; i++) s6[1][8 * w + i] ^= (uint8_t)(rng() | 0x11);
  }

  LastLayer r;
  r.same_as_cipher = true;
  for (int t = 0; t < 2; t++) {
    memcpy(c[t], s6[t], 256);
    for (int l = 6; l < NL; l++) {
      xor256(c[t], in.white[l]);
      in.des[l].layer(c[t], true);
      if (l < NL - 1) swap_groups(c[t], (size_t)16 << (l % 5));
    }
    xor256(c[t], in.white[NL]);

    uint8_t u[256];                       // back through layers 5 to 0 to the plaintext
    memcpy(u, s6[t], 256);
    for (int l = 5; l >= 0; l--) {
      swap_groups(u, (size_t)16 << (l % 5));
      in.des[l].layer(u, false);
      xor256(u, in.white[l]);
    }
    swap_nibbles(u, 256);
    SillyDesCipher(in.key, in.salt).encrypt_block(u);
    r.same_as_cipher = r.same_as_cipher && memcmp(u, c[t], 256) == 0;
  }
  r.equal_words = 0;
  for (int w = 0; w < 32; w++) r.equal_words += !word_differs(c[0], c[1], w);
  r.the_pair = !word_differs(c[0], c[1], p) && !word_differs(c[0], c[1], p ^ 2);
  return r;
}

}  // namespace

int main()
{
  static const int expected[NL] = { 1, 1, 2, 4, 8, 16, 32, 32 };
  static const int control[NL] = { 1, 2, 4, 8, 16, 32, 32, 32 };
  const int trials = 400;
  std::mt19937_64 rng(20261125);
  int fail = 0, control_mixed = 0;

  for (int n = 0; n < trials; n++) {
    Walk r = walk(rng, true);
    bool ok = r.same_as_cipher && r.one_structure && r.both_halves == 0;
    for (int l = 0; l < NL; l++) ok = ok && r.words_in[l] == expected[l];
    if (!ok) {
      fail++;
      fprintf(stderr, "FAIL: trial %d: cipher %d structure %d both halves %d, words", n, r.same_as_cipher, r.one_structure, r.both_halves);
      for (int l = 0; l < NL; l++) fprintf(stderr, " %d", r.words_in[l]);
      fprintf(stderr, "\n");
    }
  }
  if (!fail)
    printf("ok: %d random keys, salts and words: the words that differ at the input of layers 0 to 7 are 1 1 2 4 8 16 32 32,\n"
           "    every word at the input of layer 6 differs in one nibble half only, and the walk equals encrypt_block\n", trials);

  // The control: without a shared half the branches are not separate, and the check above must see that.
  for (int n = 0; n < trials; n++) {
    Walk r = walk(rng, false);
    bool spread = r.same_as_cipher && r.one_structure && r.both_halves == 32;
    for (int l = 0; l < NL; l++) spread = spread && r.words_in[l] == control[l];
    control_mixed += spread;
  }
  if (control_mixed == trials)
    printf("ok: control, %d pairs that differ in both halves: 1 2 4 8 16 32 32 32 words, and both halves of all 32 words at layer 6\n", trials);
  else {
    fail++;
    fprintf(stderr, "FAIL: control: only %d of %d pairs without a shared half spread over both branches\n", control_mixed, trials);
  }

  // The last layer: agreement in the words p and p ^ 2 at the input of layer 6 is agreement in the ciphertext words p and p ^ 2.
  int pair_ok = 0, pair_control = 0;
  for (int n = 0; n < trials; n++) {
    LastLayer r = last_layer(rng, true);
    pair_ok += r.same_as_cipher && r.equal_words == 2 && r.the_pair;
    r = last_layer(rng, false);
    pair_control += r.same_as_cipher && r.equal_words == 0;
  }
  if (pair_ok == trials && pair_control == trials)
    printf("ok: %d pairs that agree in the words p and p ^ 2 only at the input of layer 6 agree in the ciphertext words p and p ^ 2 only;\n"
           "    control, %d pairs that agree in word p ^ 2 only: no ciphertext word agrees; every ciphertext equals encrypt_block\n", trials, trials);
  else {
    fail++;
    fprintf(stderr, "FAIL: last layer: %d of %d pairs keep exactly the two words, %d of %d controls keep none\n", pair_ok, trials, pair_control, trials);
  }
  return fail ? 1 : 0;
}
