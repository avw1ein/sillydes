// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include <cstdint>

// Single DES, bitsliced over 32 lanes: one call runs the same key over the 32 words of a
// 256-byte block. No memory access or branch depends on key or data.
class Des {
public:
  ~Des();
  void setkey(const uint8_t key[8]);
  void layer(uint8_t *b256, bool encrypt) const;
  // One word; the other 31 lanes run on zeros. For tests.
  void block(uint8_t *block, bool encrypt) const;

private:
  uint32_t ks_[16][48] = {};  // every subkey bit as an all-ones or all-zeros lane mask
};
