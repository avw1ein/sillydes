// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include "common.h"

// Where the keys come from: eight 64-bit keys from a key file, or a phrase run through Argon2id (or Argon2i).
struct KeyInput {
  bool usephrase = false;
  bool require_lock = false;  // error 15 if the table of the phrase KDF cannot be locked in RAM
  SecretBuf phrase;  // wiped by its allocator, also when it grows
  uint8_t key[NL][8] = {};  // only meaningful when !usephrase

  ~KeyInput();
};

// Everything the cipher and the container need once the salt is known.
struct KeyMaterial {
  uint8_t key[NL][8];
  uint8_t mackey[64];
  uint8_t lenmask;  // masks the length byte in the padding

  ~KeyMaterial();
};

void readkeyfile(const std::string &name, uint8_t key[NL][8]);

// Reads a phrase (no echo on a terminal); asks twice on a terminal when confirm is set. Reads
// stdin with read(2) a byte at a time, so no stdio buffer ever holds a copy. The line is brought
// into the canonical form of the file format (canonical_phrase in text.h); a phrase that has
// none is asked again on a terminal and is error 10 otherwise.
SecretBuf getphrase(bool confirm);

bool kdf_ok(const KdfParams &k);

KeyMaterial derive_keys(const KeyInput &in, const uint8_t *salt, const KdfParams &kdf);

// The value of a hexadecimal digit, with bit 8 set if c is none, computed without a branch or a table
// index on c (key digits are secret). Public for test/ct_valgrind.cpp.
uint32_t hex_digit(uint8_t c);
