// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include "common.h"

// Where the keys come from: eight 64-bit keys from a key file, or a phrase run through Argon2id.
struct KeyInput {
  bool usephrase = false;
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

// Reads a phrase (no echo on a terminal); asks twice on a terminal when confirm is set.
// Trailing spaces are removed; at least 20 other characters are required. Reads stdin with
// read(2) a byte at a time, so no stdio buffer ever holds a copy.
SecretBuf getphrase(bool confirm);

bool kdf_ok(const KdfParams &k);

KeyMaterial derive_keys(const KeyInput &in, const uint8_t *salt, const KdfParams &kdf);
