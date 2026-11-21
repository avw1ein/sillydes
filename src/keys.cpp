// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "keys.h"

#include <cstring>

#include "kdf.h"
#include "platform.h"
#include "sha512.h"
#include "text.h"

namespace {

int htoa(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + c - 'a';
  if (c >= 'A' && c <= 'F') return 10 + c - 'A';
  return -1;
}

uint8_t length_mask(const uint8_t key[NL][8])
{
  uint8_t m = 0;
  for (int n = 0, k = 1; n < NL; n += 2, k += 2) {
    for (int i = 0; i < 8; i++) m ^= key[n][i] & 0x7F;
    for (int i = 0; i < 8; i++) m ^= (uint8_t)(key[k][i] << 1);
  }
  return m;
}

}  // namespace

KeyInput::~KeyInput()
{
  wipe(key, sizeof key);
}

KeyMaterial::~KeyMaterial()
{
  wipe(key, sizeof key);
  wipe(mackey, sizeof mackey);
}

// The file is read through readfile, so no stdio buffer holds a copy of the key text, and the Buf
// wipes it on every path out of here, errors included. Lines may end in LF, CR LF or CR.
void readkeyfile(const std::string &name, uint8_t key[NL][8])
{
  Buf f = readfile(name);
  f.resize(decode_text(f.data(), f.size()));
  const size_t size = f.size();
  size_t pos = 0;
  for (int n = 0; n < NL; n++) {
    size_t tok = 0, len = 0;
    while (pos < size) {
      size_t end = pos;
      while (end < size && f[end] != '\n' && f[end] != '\r') end++;
      size_t s = pos;
      while (s < end && (f[s] == ' ' || f[s] == '\t')) s++;
      size_t t = s;
      while (t < end && f[t] != ' ' && f[t] != '\t') t++;
      pos = end < size ? end + 1 : end;
      if (t > s && f[s] != ';') { tok = s; len = t - s; break; }
    }
    errarg = name;  // never echo key material
    if (len != 16) errorexit(5);
    for (int i = 0; i < 16; i += 2) {
      int hi = htoa((char)f[tok + i]), lo = htoa((char)f[tok + i + 1]);
      if (hi < 0 || lo < 0) errorexit(5);
      key[n][i / 2] = (uint8_t)((hi << 4) | lo);
    }
  }
}

namespace {

// What to tell the user about a phrase that cannot be used.
const char *fault_text(PhraseFault f)
{
  switch (f) {
    case PHRASE_NOT_UTF8: return "Phrase is not valid UTF-8 text.\n";
    case PHRASE_CONTROL:  return "Phrase holds a control character (a tab or an arrow key, for example).\n";
    case PHRASE_SHORT:    return "Phrase too short.\n";
    default:              return nullptr;
  }
}

}  // namespace

SecretBuf getphrase(bool confirm)
{
  SecretBuf s, again;
  bool tty = stdin_is_terminal();
  for (;;) {
    if (!read_secret_line("Enter key phrase (minimum 20 characters): ", s)) { errarg = "phrase"; errorexit(10); }
    if (const char *fault = fault_text(canonical_phrase(s))) {
      write_message(MSG_ERR, fault);
      if (!tty) { errarg = "phrase"; errorexit(10); }
      continue;
    }
    if (confirm && tty) {
      if (!read_secret_line("Repeat key phrase: ", again)) { errarg = "phrase"; errorexit(10); }
      if (canonical_phrase(again) != PHRASE_OK || again != s) { write_message(MSG_ERR, "Phrases differ.\n"); continue; }
    }
    break;
  }
  return s;
}

bool kdf_ok(const KdfParams &k)
{
  if (k.logm < 10 || k.logm > 21 || k.t < 1 || k.t > 4 || k.p < 1 || k.p > 8) return false;
  return (1024ull << k.logm) <= MAX_KDF_BYTES;
}

KeyMaterial derive_keys(const KeyInput &in, const uint8_t *salt, const KdfParams &kdf)
{
  KeyMaterial km;
  if (in.usephrase) {
    SecretBuf dk = argon2id(in.phrase.data(), in.phrase.size(), salt, SALT_LEN, 1u << kdf.logm, kdf.t, kdf.p, NL * 8 + sizeof km.mackey);
    memcpy(km.key, dk.data(), NL * 8);
    memcpy(km.mackey, dk.data() + NL * 8, sizeof km.mackey);
    wipe(dk.data(), dk.size());
  } else {
    memcpy(km.key, in.key, NL * 8);
    static const char label[] = FORMAT_NAME " mac";
    Hmac512(&km.key[0][0], NL * 8).mac((const uint8_t *)label, sizeof label - 1, km.mackey);
  }
  km.lenmask = length_mask(km.key);
  return km;
}
