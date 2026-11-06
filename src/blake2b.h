// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include <cstddef>
#include <cstdint>

// Unkeyed BLAKE2b (RFC 7693) with a digest of 1 to 64 bytes.
struct Blake2b {
  uint64_t h[8];
  uint8_t buf[128];
  uint64_t total = 0;
  size_t fill = 0;
  size_t outlen;

  explicit Blake2b(size_t outlen = 64);
  void update(const uint8_t *p, size_t n);
  void final(uint8_t *out);
  ~Blake2b();

private:
  void block(const uint8_t *p, bool last);
};

// Argon2's variable-length hash H' (RFC 9106, section 3.3).
void blake2b_long(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
