// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "odette_cipher.h"

#include <cstring>

namespace {

void xor256(uint8_t *b, const uint8_t *w)
{
  for (int i = 0; i < 256; i++) b[i] ^= w[i];
}

void swap_nibbles(uint8_t *work, size_t bs)
{
  for (size_t i = 0, j = bs / 2; i < bs / 2; i++, j++) {
    uint8_t h1 = (work[i] & 0xF0) >> 4, l1 = work[i] & 0x0F;
    uint8_t h2 = work[j] & 0xF0, l2 = (work[j] & 0x0F) << 4;
    work[i] = l2 | l1;
    work[j] = h2 | h1;
  }
}

void swap_groups(uint8_t *blk, size_t bs)
{
  for (size_t off = 0; off < 256; off += bs) swap_nibbles(blk + off, bs);
}

const char WHITE_LABEL[] = "Odette 5.1.0 white";
const char TWEAK_LABEL[] = "Odette 5.1.0 tweak";

}  // namespace

OdetteCipher::OdetteCipher(const uint8_t key[NL][8], const uint8_t salt[SALT_LEN])
  : tweakmac_(&key[0][0], NL * 8)
{
  for (int i = 0; i < NL; i++) des_[i].setkey(key[i]);
  for (int j = 0; j <= NL; j++)
    for (int c = 0; c < 4; c++) {
      Buf msg(WHITE_LABEL, WHITE_LABEL + sizeof WHITE_LABEL - 1);
      msg.insert(msg.end(), salt, salt + SALT_LEN);
      msg.push_back((uint8_t)j);
      msg.push_back((uint8_t)c);
      tweakmac_.mac(msg.data(), msg.size(), &white_[j][64 * c]);
    }
  memcpy(salt_, salt, SALT_LEN);
}

OdetteCipher::~OdetteCipher()
{
  wipe(white_, sizeof white_);
}

void OdetteCipher::tweak(uint64_t index, uint8_t out[256]) const
{
  uint8_t msg[sizeof TWEAK_LABEL - 1 + SALT_LEN + 9];
  memcpy(msg, TWEAK_LABEL, sizeof TWEAK_LABEL - 1);
  memcpy(msg + sizeof TWEAK_LABEL - 1, salt_, SALT_LEN);
  for (int k = 0; k < 8; k++) msg[sizeof TWEAK_LABEL - 1 + SALT_LEN + k] = (uint8_t)(index >> (56 - 8 * k));
  for (int c = 0; c < 4; c++) {
    msg[sizeof msg - 1] = (uint8_t)c;
    tweakmac_.mac(msg, sizeof msg, out + 64 * c);
  }
}

// P256, then per layer: XOR, DES, and P16, P32, P64, P128, P256, P16, P32 between layers; final XOR.
void OdetteCipher::encrypt_block(uint8_t *b) const
{
  swap_nibbles(b, 256);
  for (int l = 0; l < NL; l++) {
    xor256(b, white_[l]);
    des_[l].layer(b, true);
    if (l < NL - 1) swap_groups(b, (size_t)16 << (l % 5));
  }
  xor256(b, white_[NL]);
}

void OdetteCipher::decrypt_block(uint8_t *b) const
{
  xor256(b, white_[NL]);
  for (int l = NL - 1; l >= 0; l--) {
    des_[l].layer(b, false);
    xor256(b, white_[l]);
    if (l > 0) swap_groups(b, (size_t)16 << ((l - 1) % 5));
    else swap_nibbles(b, 256);
  }
}

// CBC around all layers, with an XEX tweak per block: every block is its own permutation instance,
// and no single layer sees a known input difference.
void OdetteCipher::cbc_encrypt(uint8_t *p, size_t n, const uint8_t *iv) const
{
  uint8_t prev[256], tw[256];
  memcpy(prev, iv, 256);
  for (size_t b = 0; b + 256 <= n; b += 256) {
    uint8_t *blk = p + b;
    tweak(b / 256, tw);
    for (int i = 0; i < 256; i++) blk[i] ^= prev[i] ^ tw[i];
    encrypt_block(blk);
    for (int i = 0; i < 256; i++) blk[i] ^= tw[i];
    memcpy(prev, blk, 256);
  }
  wipe(tw, sizeof tw);
}

void OdetteCipher::cbc_decrypt(uint8_t *p, size_t n, const uint8_t *iv) const
{
  uint8_t prev[256], cur[256], tw[256];
  memcpy(prev, iv, 256);
  for (size_t b = 0; b + 256 <= n; b += 256) {
    uint8_t *blk = p + b;
    tweak(b / 256, tw);
    memcpy(cur, blk, 256);
    for (int i = 0; i < 256; i++) blk[i] ^= tw[i];
    decrypt_block(blk);
    for (int i = 0; i < 256; i++) blk[i] ^= prev[i] ^ tw[i];
    memcpy(prev, cur, 256);
  }
  wipe(tw, sizeof tw);
}

void pad256(Buf &b, uint8_t lenmask)
{
  size_t cnt = b.size() % 256, len = b.size();
  reserve_wiped(b, len - cnt + 256);
  b.resize(len - cnt + 256);
  if (cnt + 1 < 256) randbytes(&b[len], 255 - cnt);
  b[b.size() - 1] = (uint8_t)(cnt ^ lenmask);
}

void unpad256(Buf &b, uint8_t lenmask)
{
  size_t cnt = (uint8_t)(b[b.size() - 1] ^ lenmask);
  if (cnt > 255) cnt = 255;
  size_t len = b.size() - 256 + cnt;
  wipe(b.data() + len, b.size() - len);
  b.resize(len);
}
