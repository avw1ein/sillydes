// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include "common.h"
#include "des.h"
#include "sha512.h"

// The 2048-bit wide-block cipher: eight DES layers with per-layer whitening and nibble permutations,
// wrapped in CBC with a per-block XEX tweak. Whitening and tweak depend on every key bit and the salt.
class SillyDesCipher {
public:
  SillyDesCipher(const uint8_t key[NL][8], const uint8_t salt[SALT_LEN]);
  ~SillyDesCipher();

  void encrypt_block(uint8_t *b) const;
  void decrypt_block(uint8_t *b) const;

  // Per-block 2048-bit XEX mask: a PRF of the key, the salt and the block index.
  void tweak(uint64_t index, uint8_t out[256]) const;

  // In place; n must be a multiple of 256.
  void cbc_encrypt(uint8_t *p, size_t n, const uint8_t *iv) const;
  void cbc_decrypt(uint8_t *p, size_t n, const uint8_t *iv) const;

private:
  Des des_[NL];
  uint8_t white_[NL + 1][256];
  Hmac512 tweakmac_;  // keyed once; pad states are reused for every block
  uint8_t salt_[SALT_LEN];
};

// In place. Random fill plus a masked length byte, always at least one byte of padding; unpad
// wipes the bytes it removes.
void pad256(Buf &b, uint8_t lenmask);
void unpad256(Buf &b, uint8_t lenmask);
