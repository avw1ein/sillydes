// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Andy van Wezel
//
// The time of one classical key guess, ANALYSIS.md sections 5.4 and 10.3. Against SillyDES in key-file
// mode the cheapest test of a guess K is the tag check: HMAC-SHA-512 under K of FORMAT_NAME " mac" gives
// the MAC key, and HMAC-SHA-512 under that key of everything before the tag gives the tag. The smallest
// file has 280 header bytes and one 256-byte block before its 64-byte tag, 12 SHA-512 compressions in
// all. Against AES-256 a guess is a key expansion and the encryption of one block.
//
// Both sides use the fastest code at hand: OpenSSL's SHA-512 for the tag check, AES-NI intrinsics with
// eight keys interleaved for AES-256. The program checks its AES against OpenSSL's AES_encrypt and its tag
// check against the project's Hmac512, so the timed work is what the program and AES compute.
//
// x86-64 with AES-NI and OpenSSL 3 only. Not part of the program or of the tests:
// -DSILLYDES_GUESS_COST=ON, target guess_cost. Run it on one core, e.g. taskset -c 2 ./guess_cost.

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/aes.h>
#include <openssl/sha.h>

#include <immintrin.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "sha512.h"
#include "version.h"

namespace {

double seconds()
{
  return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

// AES-256 key expansion without aeskeygenassist, which is microcoded and slow on recent Intel cores:
// pshufb broadcasts the rotated (or plain) last word, aesenclast with the round constant applies SubWord.
__m128i spread(__m128i k)
{
  k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
  k = _mm_xor_si128(k, _mm_slli_si128(k, 4));
  return _mm_xor_si128(k, _mm_slli_si128(k, 4));
}

__m128i aes256_trial(const uint8_t key[32], __m128i b)
{
  const __m128i rotword = _mm_set1_epi32(0x0c0f0e0d), word3 = _mm_set1_epi32(0x0f0e0d0c);
  __m128i k0 = _mm_loadu_si128((const __m128i *)key), k1 = _mm_loadu_si128((const __m128i *)(key + 16));
  __m128i rcon = _mm_set1_epi32(1);
  b = _mm_aesenc_si128(_mm_xor_si128(b, k0), k1);
  for (int r = 0; r < 7; r++) {
    k0 = _mm_xor_si128(spread(k0), _mm_aesenclast_si128(_mm_shuffle_epi8(k1, rotword), rcon));
    rcon = _mm_slli_epi32(rcon, 1);
    if (r == 6) return _mm_aesenclast_si128(b, k0);
    b = _mm_aesenc_si128(b, k0);
    k1 = _mm_xor_si128(spread(k1), _mm_aesenclast_si128(_mm_shuffle_epi8(k0, word3), _mm_setzero_si128()));
    b = _mm_aesenc_si128(b, k1);
  }
  return b;
}

void hmac(const uint8_t key[64], const uint8_t *msg, size_t n, uint8_t out[64])
{
  uint8_t pad[128], inner[64];
  SHA512_CTX c;
  for (int i = 0; i < 128; i++) pad[i] = (uint8_t)((i < 64 ? key[i] : 0) ^ 0x36);
  SHA512_Init(&c);
  SHA512_Update(&c, pad, 128);
  SHA512_Update(&c, msg, n);
  SHA512_Final(inner, &c);
  for (int i = 0; i < 128; i++) pad[i] = (uint8_t)((i < 64 ? key[i] : 0) ^ 0x5c);
  SHA512_Init(&c);
  SHA512_Update(&c, pad, 128);
  SHA512_Update(&c, inner, 64);
  SHA512_Final(out, &c);
}

const char label[] = FORMAT_NAME " mac";
const size_t FILE_BEFORE_TAG = 280 + 256;

void tag_check(const uint8_t key[64], const uint8_t *file, uint8_t tag[64])
{
  uint8_t mackey[64];
  hmac(key, (const uint8_t *)label, sizeof label - 1, mackey);
  hmac(mackey, file, FILE_BEFORE_TAG, tag);
}

bool check_aes()
{
  uint8_t key[32], block[16], want[16], got[16];
  for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 1);
  for (int i = 0; i < 16; i++) block[i] = (uint8_t)(i * 13 + 5);
  AES_KEY ak;
  AES_set_encrypt_key(key, 256, &ak);
  AES_encrypt(block, want, &ak);
  _mm_storeu_si128((__m128i *)got, aes256_trial(key, _mm_loadu_si128((const __m128i *)block)));
  return memcmp(want, got, 16) == 0;
}

bool check_tag()
{
  uint8_t key[64], file[FILE_BEFORE_TAG], mackey[64], want[64], got[64];
  for (int i = 0; i < 64; i++) key[i] = (uint8_t)(i * 11 + 3);
  for (size_t i = 0; i < sizeof file; i++) file[i] = (uint8_t)(i * 29 + 7);
  Hmac512(key, 64).mac((const uint8_t *)label, sizeof label - 1, mackey);
  Hmac512(mackey, 64).mac(file, sizeof file, want);
  tag_check(key, file, got);
  return memcmp(want, got, 64) == 0;
}

}  // namespace

int main()
{
  if (!check_aes() || !check_tag()) {
    fprintf(stderr, "guess_cost: self-check failed\n");
    return 1;
  }

  volatile uint32_t sink = 0;
  const long aes_rounds = 20000000;
  uint8_t akey[8][32];
  memset(akey, 0, sizeof akey);
  const __m128i plain = _mm_set1_epi32(9);
  double t0 = seconds();
  for (long i = 0; i < aes_rounds; i++) {
    __m128i c[8];
    for (int j = 0; j < 8; j++) {
      akey[j][0] = (uint8_t)i;
      akey[j][1] = (uint8_t)(i >> 8);
      akey[j][2] = (uint8_t)j;
    }
    for (int j = 0; j < 8; j++) c[j] = aes256_trial(akey[j], plain);
    for (int j = 0; j < 8; j++) sink += (uint32_t)_mm_cvtsi128_si32(c[j]);
  }
  const double aes_ns = (seconds() - t0) / (aes_rounds * 8.0) * 1e9;

  const long tag_rounds = 500000;
  uint8_t skey[64] = { 1 }, file[FILE_BEFORE_TAG] = { 0 }, tag[64];
  t0 = seconds();
  for (long i = 0; i < tag_rounds; i++) {
    skey[0] = (uint8_t)i;
    skey[1] = (uint8_t)(i >> 8);
    skey[2] = (uint8_t)(i >> 16);
    tag_check(skey, file, tag);
    sink += tag[0];
  }
  const double tag_ns = (seconds() - t0) / tag_rounds * 1e9;

  printf("AES-256 trial (AES-NI, 8 keys interleaved): %.1f ns\n", aes_ns);
  printf("SillyDES tag check, 600-byte file (OpenSSL SHA-512): %.1f ns\n", tag_ns);
  printf("ratio: %.0f\n", tag_ns / aes_ns);
  return 0;
}
