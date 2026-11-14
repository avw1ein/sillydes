// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "container.h"

#include <cstring>

#include "sillydes_cipher.h"
#include "sha512.h"

namespace {

bool all_zero(const uint8_t *p, size_t n)
{
  uint8_t acc = 0;
  for (size_t i = 0; i < n; i++) acc |= p[i];
  return acc == 0;
}

}  // namespace

// Salt and IV are always drawn here; no caller can supply them. A fixed salt or IV would let two
// files share a permutation instance, which is the one thing the analysis requires never happens.
void seal(Buf &data, const KeyInput &keys, const KdfParams &kdf)
{
  uint8_t iv[IV_LEN], salt[SALT_LEN];
  randbytes(salt, SALT_LEN);
  randbytes(iv, IV_LEN);
  if (all_zero(salt, SALT_LEN) || all_zero(iv, IV_LEN)) errorexit(14);
  KeyMaterial km = derive_keys(keys, salt, kdf);
  SillyDesCipher cipher(km.key, salt);

  // One allocation for the whole container, so the plaintext is never copied.
  reserve_wiped(data, HDR_LEN + data.size() + 256 + TAG_LEN);
  pad256(data, km.lenmask);
  cipher.cbc_encrypt(data.data(), data.size(), iv);

  uint8_t hdr[HDR_LEN] = {};
  memcpy(hdr, MAGIC, 4);
  hdr[4] = (uint8_t)kdf.logm; hdr[5] = (uint8_t)kdf.t; hdr[6] = (uint8_t)kdf.p;
  memcpy(hdr + 8, salt, SALT_LEN);
  memcpy(hdr + 8 + SALT_LEN, iv, IV_LEN);
  data.insert(data.begin(), hdr, hdr + HDR_LEN);
  uint8_t tag[TAG_LEN];
  Hmac512(km.mackey, sizeof km.mackey).mac(data.data(), data.size(), tag);
  data.insert(data.end(), tag, tag + TAG_LEN);
}

void unseal(Buf &d, const KeyInput &keys)
{
  size_t body = d.size() >= HDR_LEN + TAG_LEN ? d.size() - HDR_LEN - TAG_LEN : 0;
  if (body < 256 || body % 256 != 0 || memcmp(d.data(), MAGIC, 4) != 0) errorexit(13);
  KdfParams kdf = { d[4], d[5], d[6] };
  if (d[7] != 0 || !kdf_ok(kdf)) errorexit(13);
  uint8_t iv[IV_LEN], salt[SALT_LEN];
  memcpy(salt, &d[8], SALT_LEN);
  memcpy(iv, &d[8 + SALT_LEN], IV_LEN);
  KeyMaterial km = derive_keys(keys, salt, kdf);

  uint8_t tag[TAG_LEN], diff = 0;
  Hmac512(km.mackey, sizeof km.mackey).mac(d.data(), d.size() - TAG_LEN, tag);
  for (int i = 0; i < TAG_LEN; i++) diff |= tag[i] ^ d[d.size() - TAG_LEN + i];
  if (diff) errorexit(13);

  SillyDesCipher cipher(km.key, salt);
  cipher.cbc_decrypt(d.data() + HDR_LEN, body, iv);
  // Slide the plaintext down over the header; wipe the stale tail and the tag, then unpad.
  memmove(d.data(), d.data() + HDR_LEN, body);
  wipe(d.data() + body, d.size() - body);
  d.resize(body);
  unpad256(d, km.lenmask);
}
