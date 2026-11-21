// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// Constant-time check in the style of ctgrind (PORTPLAN.md 5.3, item 1): the secret inputs are marked
// as uninitialised for Valgrind's Memcheck, which reports every conditional jump and every memory
// address that depends on them. Run under Valgrind with --error-exitcode, any report fails the test:
//
//   valgrind --error-exitcode=99 ./ct_valgrind
//
// Run alone the program only exercises the same code and prints ok.
//
// In scope: the key schedule and the layer of DES, SHA-512, HMAC, BLAKE2b, the MAC compare, the hex
// decoding of key files, key derivation from a key file, the cipher in CBC mode, padding.
// Out of scope, by design (PORTPLAN.md 5.1): Argon2id in phrase mode (data-dependent addressing),
// the normalisation of a phrase, and what runs after authentication (unpad256 branches on the
// length, which is public).
//
// Plaintext and keys are marked undefined; whatever is meant to be public, a ciphertext, a tag, the
// outcome of a comparison, is declassified before the program looks at it.

#include <cstdio>
#include <cstring>
#include <valgrind/memcheck.h>

#include "blake2b.h"
#include "common.h"
#include "container.h"
#include "des.h"
#include "keys.h"
#include "sha512.h"
#include "sillydes_cipher.h"

static int fails;

static void secret(void *p, size_t n) { VALGRIND_MAKE_MEM_UNDEFINED(p, n); }
static void declassify(void *p, size_t n) { VALGRIND_MAKE_MEM_DEFINED(p, n); }

static void fill(uint8_t *p, size_t n, uint8_t seed)
{
  for (size_t i = 0; i < n; i++) p[i] = (uint8_t)(seed + i * 37u);
}

static void expect(bool ok, const char *what)
{
  if (!ok) { printf("FAIL: %s\n", what); fails++; }
}

// The control: a branch and a table index on a secret. Valgrind must report both; the test
// ct_valgrind_detects_a_leak expects this run to fail, so that a silent harness cannot pass.
static int leak()
{
  static const uint8_t table[256] = { 1 };
  volatile uint8_t byte = 7;
  secret((void *)&byte, 1);
  int n = 0;
  if (byte == 7) n++;
  n += table[byte];
  return n;
}

int main(int argc, char **argv)
{
  if (argc > 1 && strcmp(argv[1], "--leak") == 0) return leak() > 100;
  // DES: a secret key, then a secret key and secret data, both directions.
  {
    uint8_t key[8], data[256], copy[256];
    fill(key, sizeof key, 1);
    fill(data, sizeof data, 9);
    secret(key, sizeof key);
    Des d;
    d.setkey(key);
    for (int dir = 0; dir < 2; dir++) {
      memcpy(copy, data, sizeof copy);
      secret(copy, sizeof copy);
      d.layer(copy, dir == 0);
      declassify(copy, sizeof copy);
    }
    uint8_t one[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    secret(one, sizeof one);
    d.block(one, true);
    declassify(one, sizeof one);
  }

  // SHA-512, HMAC and BLAKE2b over secret input; HMAC with a secret key.
  {
    uint8_t msg[300], key[64], out[64];
    fill(msg, sizeof msg, 3);
    fill(key, sizeof key, 5);
    secret(msg, sizeof msg);
    secret(key, sizeof key);
    Sha512 s;
    s.update(msg, sizeof msg);
    s.final(out);
    declassify(out, sizeof out);
    Hmac512(key, sizeof key).mac(msg, sizeof msg, out);
    declassify(out, sizeof out);
    Blake2b b(64);
    b.update(msg, sizeof msg);
    b.final(out);
    declassify(out, sizeof out);
    uint8_t longout[200];
    blake2b_long(longout, sizeof longout, msg, 100);
    declassify(longout, sizeof longout);
  }

  // The MAC compare: a secret on either side; the outcome is the one thing that may become public.
  {
    uint8_t a[64], b[64];
    fill(a, sizeof a, 7);
    memcpy(b, a, sizeof b);
    secret(a, sizeof a);
    volatile bool eq = ct_equal(a, b, sizeof a);
    declassify((void *)&eq, sizeof eq);
    expect(eq, "ct_equal of equal arrays");
    b[63] ^= 1;
    secret(b, sizeof b);
    declassify(a, sizeof a);
    volatile bool ne = ct_equal(a, b, sizeof a);
    declassify((void *)&ne, sizeof ne);
    expect(!ne, "ct_equal of different arrays");
  }

  // The hex decoding of a key file, every byte value with the byte secret.
  for (int c = 0; c < 256; c++) {
    uint8_t byte = (uint8_t)c;
    secret(&byte, 1);
    volatile uint32_t v = hex_digit(byte);
    declassify((void *)&v, sizeof v);
    bool digit = c >= '0' && c <= '9', lower = c >= 'a' && c <= 'f', upper = c >= 'A' && c <= 'F';
    uint32_t want = digit ? c - '0' : lower ? c - 'a' + 10 : upper ? c - 'A' + 10 : 0x100;
    if (!digit && !lower && !upper) {
      if (!(v & 0x100)) { printf("FAIL: hex_digit(0x%02X)\n", c); fails++; }
    } else if (v != want) {
      printf("FAIL: hex_digit(0x%02X)\n", c);
      fails++;
    }
  }

  // Key derivation from a key file and the cipher: a secret key file, plaintext and padding.
  {
    KeyInput in;
    in.usephrase = false;
    for (int n = 0; n < NL; n++) fill(in.key[n], 8, (uint8_t)(11 * n + 1));
    uint8_t salt[SALT_LEN], iv[IV_LEN];
    fill(salt, sizeof salt, 21);
    fill(iv, sizeof iv, 22);
    uint8_t keycopy[NL][8];
    memcpy(keycopy, in.key, sizeof keycopy);
    secret(in.key, sizeof in.key);
    KeyMaterial km = derive_keys(in, salt, DEFAULT_KDF);

    SillyDesCipher c(km.key, salt);
    Buf plain(700);
    fill(plain.data(), plain.size(), 33);
    Buf data = plain;
    pad256(data, km.lenmask);  // the length byte is masked with a secret
    secret(data.data(), data.size());
    c.cbc_encrypt(data.data(), data.size(), iv);
    uint8_t tw[256];
    c.tweak(5, tw);
    declassify(tw, sizeof tw);
    declassify(data.data(), data.size());  // a ciphertext is public
    uint8_t tag[TAG_LEN], again[TAG_LEN];
    Hmac512(km.mackey, sizeof km.mackey).mac(data.data(), data.size(), tag);
    declassify(tag, sizeof tag);

    // What unseal does with a ciphertext: the same keys, the tag compare, the decryption.
    Hmac512(km.mackey, sizeof km.mackey).mac(data.data(), data.size(), again);
    volatile bool same = ct_equal(tag, again, TAG_LEN);
    declassify((void *)&same, sizeof same);
    expect(same, "tag compare");
    Buf back = data;
    c.cbc_decrypt(back.data(), back.size(), iv);
    declassify(back.data(), back.size());
    declassify(&km.lenmask, 1);
    unpad256(back, km.lenmask);
    expect(back == plain, "key file round trip");
    declassify(in.key, sizeof in.key);
    declassify(km.key, sizeof km.key);
    (void)keycopy;
  }

  // The whole seal with a secret key file and secret plaintext (no Argon2id: key file mode).
  {
    KeyInput in;
    in.usephrase = false;
    for (int n = 0; n < NL; n++) fill(in.key[n], 8, (uint8_t)(5 * n + 2));
    secret(in.key, sizeof in.key);
    Buf d(1000);
    fill(d.data(), d.size(), 44);
    secret(d.data(), d.size());
    seal(d, in, DEFAULT_KDF);
    declassify(d.data(), d.size());
    declassify(in.key, sizeof in.key);
    expect(d.size() == HDR_LEN + 1024 + TAG_LEN, "sealed size");
  }

  if (fails) return 1;
  puts("ok: no branch or address depends on a secret in DES, SHA-512, HMAC, BLAKE2b, ct_equal, the hex decoder, key derivation, the cipher and seal");
  return 0;
}
