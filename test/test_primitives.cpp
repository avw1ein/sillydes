// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// Unit tests for the hash primitives, the block cipher and the handling of text from outside.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>

#include "armor.h"
#include "blake2b.h"
#include "common.h"
#include "container.h"
#include "crc32.h"
#include "des.h"
#include "des_sbox_ct.h"
#include "kdf.h"
#include "keys.h"
#include "platform.h"
#include "sillydes_cipher.h"
#include "sha512.h"
#include "test_os.h"
#include "text.h"
#include "unicode_tables.h"

static std::string hex(const uint8_t *p, size_t n)
{
  static const char d[] = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
  return s;
}

static void unhex(const char *s, uint8_t *out, size_t n)
{
  for (size_t i = 0; i < n; i++) {
    unsigned v = 0;
    for (int k = 0; k < 2; k++) {
      char c = s[2 * i + k];
      v = v * 16 + (unsigned)(c >= 'a' ? c - 'a' + 10 : c >= 'A' ? c - 'A' + 10 : c - '0');
    }
    out[i] = (uint8_t)v;
  }
}

static int fails;

// FIPS 46 S-boxes, the reference for the generated circuits in des_sbox_ct.h.
static const uint8_t fips_sbox[8][64] = {
  { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
     0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
     4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
    15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 },
  { 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
     3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
     0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 },
  { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
     1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 },
  {  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
     3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 },
  {  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
     4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 },
  { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
     9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
     4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 },
  {  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
     1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
     6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 },
  { 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
     1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
     7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
     2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 }
};

// Evaluates generated S-box s+1 on the 6-bit input x (b1 is the top bit) in lane 0.
static int circuit_sbox(int s, int x)
{
  uint32_t b[6], o[4];
  for (int j = 0; j < 6; j++) b[j] = 0u - ((x >> (5 - j)) & 1u);
  switch (s) {
    case 0: des_sbox1(b[0], b[1], b[2], b[3], b[4], b[5], o[0], o[1], o[2], o[3]); break;
    case 1: des_sbox2(b[0], b[1], b[2], b[3], b[4], b[5], o[0], o[1], o[2], o[3]); break;
    case 2: des_sbox3(b[0], b[1], b[2], b[3], b[4], b[5], o[0], o[1], o[2], o[3]); break;
    case 3: des_sbox4(b[0], b[1], b[2], b[3], b[4], b[5], o[0], o[1], o[2], o[3]); break;
    case 4: des_sbox5(b[0], b[1], b[2], b[3], b[4], b[5], o[0], o[1], o[2], o[3]); break;
    case 5: des_sbox6(b[0], b[1], b[2], b[3], b[4], b[5], o[0], o[1], o[2], o[3]); break;
    case 6: des_sbox7(b[0], b[1], b[2], b[3], b[4], b[5], o[0], o[1], o[2], o[3]); break;
    default: des_sbox8(b[0], b[1], b[2], b[3], b[4], b[5], o[0], o[1], o[2], o[3]); break;
  }
  int v = 0;
  for (int k = 0; k < 4; k++) {
    if (o[k] != 0 && o[k] != 0xffffffffu) return -1;  // every lane must agree
    v |= (o[k] & 1) << (3 - k);
  }
  return v;
}

static int diffbytes(const uint8_t *a, const uint8_t *b)
{
  int n = 0;
  for (int i = 0; i < 256; i++) n += a[i] != b[i];
  return n;
}

static int diffbits(const uint8_t *a, const uint8_t *b, int n)
{
  int c = 0;
  for (int i = 0; i < n; i++)
    for (unsigned x = a[i] ^ b[i]; x; x >>= 1) c += x & 1;
  return c;
}

static int activewords(const uint8_t *a, const uint8_t *b)
{
  int n = 0;
  for (int w = 0; w < 32; w++) n += memcmp(a + 8 * w, b + 8 * w, 8) != 0;
  return n;
}

// Flips one bit or one random word of the input and demands that every output word changes and
// that the number of flipped output bits is near 1024. Covers the forward and backward cones.
static void avalanche(const SillyDesCipher &c, bool enc, const char *name)
{
  for (int t = 0; t < 64; t++) {
    uint8_t x[256], y[256];
    randbytes(x, 256);
    memcpy(y, x, 256);
    if (t & 1) randbytes(y + 8 * (t % 32), 8);          // a difference confined to one word
    else y[t % 256] ^= (uint8_t)(1 << (t / 8 % 8));      // a single bit
    if (!memcmp(x, y, 256)) continue;
    enc ? c.encrypt_block(x) : c.decrypt_block(x);
    enc ? c.encrypt_block(y) : c.decrypt_block(y);
    int words = activewords(x, y), bits = diffbits(x, y, 256);
    if (words != 32 || bits < 896 || bits > 1152) { printf("FAIL: %s avalanche: %d words, %d bits\n", name, words, bits); fails++; return; }
  }
}

static void check(const char *name, const std::string &got, const char *want)
{
  if (got != want) { printf("FAIL: %s\n  got  %s\n  want %s\n", name, got.c_str(), want); fails++; }
}

static std::string blake2b(const std::string &m, size_t n)
{
  Blake2b b(n);
  uint8_t o[64];
  b.update((const uint8_t *)m.data(), m.size());
  b.final(o);
  return hex(o, n);
}

static std::string sha512(const std::string &m)
{
  Sha512 s;
  uint8_t o[64];
  s.update((const uint8_t *)m.data(), m.size());
  s.final(o);
  return hex(o, 64);
}

static std::string a2(const char *pw, const char *salt, uint32_t m, uint32_t t, uint32_t p, uint32_t variant = KDF_ARGON2ID)
{
  SecretBuf b = argon2(variant, (const uint8_t *)pw, strlen(pw), (const uint8_t *)salt, strlen(salt), m, t, p, 32);
  return hex(b.data(), b.size());
}

// Error messages go to stderr; the tests that provoke them keep the output readable.
struct QuietStderr {
  intptr_t saved;
  QuietStderr() : saved(silence_stderr()) {}
  ~QuietStderr() { restore_stderr(saved); }
};

// The ExitError code that fn() throws, or -1 if it returns.
template <class F>
static int exit_code(F fn)
{
  QuietStderr q;
  try { fn(); } catch (const ExitError &e) { return e.code; }
  return -1;
}

// The sanitizers replace mlock by a call that succeeds and locks nothing.
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define SANITIZED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer) || __has_feature(memory_sanitizer)
#define SANITIZED 1
#endif
#endif

#ifdef _WIN32
const size_t STACK_LEFT_MAX = 80;
#else
const size_t STACK_LEFT_MAX = 16;
#endif

// Leaves a pattern in a large stack frame, and counts how much of it a frame of the same size
// finds in uninitialised memory at the same place.
SILLYDES_NOINLINE static void leave_pattern()
{
  volatile uint8_t junk[30000];
  for (size_t i = 0; i < sizeof junk; i++) junk[i] = 0xA7;
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#ifndef __clang__
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#endif
SILLYDES_NOINLINE static size_t find_pattern()
{
  volatile uint8_t probe[30000];  // read on purpose before it is written
  size_t n = 0;
  for (size_t i = 0; i < sizeof probe; i++) n += probe[i] == 0xA7;
  return n;
}
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

static std::string write_temp(const std::string &text)
{
  std::string name = temp_file_name();
  FileHandle f = open_output(name);
  if (f != NO_FILE) {
    write_output(f, (const uint8_t *)text.data(), text.size());
    close_file(f);
  }
  return name;
}

// UTF-8 of a list of code points; the tests name every character by its number, so that this
// file stays ASCII.
static std::string utf8(std::initializer_list<uint32_t> cps)
{
  std::string s;
  for (uint32_t c : cps) {
    if (c < 0x80) s += (char)c;
    else if (c < 0x800) { s += (char)(0xC0 | (c >> 6)); s += (char)(0x80 | (c & 0x3F)); }
    else if (c < 0x10000) { s += (char)(0xE0 | (c >> 12)); s += (char)(0x80 | ((c >> 6) & 0x3F)); s += (char)(0x80 | (c & 0x3F)); }
    else { s += (char)(0xF0 | (c >> 18)); s += (char)(0x80 | ((c >> 12) & 0x3F)); s += (char)(0x80 | ((c >> 6) & 0x3F)); s += (char)(0x80 | (c & 0x3F)); }
  }
  return s;
}

// ASCII text as UTF-16 with a byte order mark.
static std::string utf16(const std::string &ascii, bool little_endian)
{
  std::string s = little_endian ? "\xFF\xFE" : "\xFE\xFF";
  for (char c : ascii) {
    if (!little_endian) s += '\0';
    s += c;
    if (little_endian) s += '\0';
  }
  return s;
}

static std::string replace_all(std::string s, const std::string &from, const std::string &to)
{
  for (size_t pos = 0; (pos = s.find(from, pos)) != std::string::npos; pos += to.size()) s.replace(pos, from.size(), to);
  return s;
}

// canonical_phrase on a copy of `in`: the fault, and in `out` the canonical bytes.
static PhraseFault canon(const std::string &in, std::string &out)
{
  SecretBuf s(in.begin(), in.end());
  PhraseFault f = canonical_phrase(s);
  out.assign(s.begin(), s.end());
  return f;
}

static void hash32(Sha512 &h, uint32_t v)
{
  const uint8_t b[4] = { (uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24) };
  h.update(b, 4);
}

int main()
{
  check("blake2b abc", blake2b("abc", 64),
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
  check("blake2b empty", blake2b("", 64),
        "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
  check("blake2b abc 20 bytes", blake2b("abc", 20), "384264f676f39536840523f284921cdc68b6846b");
  {
    std::string m;
    for (int i = 0; i < 300; i++) m += (char)i;
    check("blake2b three blocks", blake2b(m, 64),
          "d9cf5983dc6b34c0fa1f0226926855ad3eccd2bcdcd8f8053b9a80664d33b5afcc32fd21c70ea14f4ef50ca97c3203c4d1803159f0e01bb6cb1d1c83db52b63c");
    check("blake2b exactly one block", blake2b(m.substr(0, 128), 64),
          "2319e3789c47e2daa5fe807f61bec2a1a6537fa03f19ff32e87eecbfd64b7e0e8ccff439ac333b040f19b0c4ddd11a61e24ac1fe0f10a039806c5dcc0da3d115");
    uint8_t l[100];
    blake2b_long(l, 100, (const uint8_t *)"abc", 3);
    check("argon2 H' 100 bytes", hex(l, 100),
          "4c9ba23bcafae5e571a5d41673bb8084a4a1de2688416ed390f669d33d364f3d4d9bfa7fe762680c6b2362711c4ce5b2c60ddcd14c1277ec1369c79f44c28966"
          "98a2b0773a3ce2e410532fa7c72f0bb61ccca0c24c362f337555cbf2998f2d3601be70d1");
  }

  check("sha512 empty", sha512(""),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
  check("sha512 abc", sha512("abc"),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  check("sha512 two blocks", sha512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");

  uint8_t mac512[64];
  const std::string msg = "what do ya want for nothing?";
  Hmac512((const uint8_t *)"Jefe", 4).mac((const uint8_t *)msg.data(), msg.size(), mac512);
  check("hmac-sha512 rfc4231 #2", hex(mac512, 64),
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
  const std::string longmsg = "Test Using Larger Than Block-Size Key - Hash Key First";
  Hmac512(Buf(131, 0xaa).data(), 131).mac((const uint8_t *)longmsg.data(), longmsg.size(), mac512);
  check("hmac-sha512 rfc4231 #6", hex(mac512, 64),
        "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");

  // Argon2id: the RFC 9106 vector (with secret and associated data) and the reference
  // implementation's test vectors (phc-winner-argon2, src/test.c, version 0x13).
  {
    std::string pw(32, '\x01');
    uint8_t salt[16], sec[8], ad[12];
    memset(salt, 2, sizeof salt); memset(sec, 3, sizeof sec); memset(ad, 4, sizeof ad);
    SecretBuf o = argon2id((const uint8_t *)pw.data(), pw.size(), salt, sizeof salt, 32, 3, 4, 32, sec, sizeof sec, ad, sizeof ad);
    check("argon2id rfc9106", hex(o.data(), o.size()), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
  }
  check("argon2id m=256 t=2 p=1", a2("password", "somesalt", 256, 2, 1), "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe");
  check("argon2id m=256 t=2 p=2", a2("password", "somesalt", 256, 2, 2), "6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037");
  check("argon2id m=64 MiB t=1 p=1", a2("password", "somesalt", 65536, 1, 1), "f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98");
  check("argon2id m=64 MiB t=2 p=1", a2("password", "somesalt", 65536, 2, 1), "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7");
  check("argon2id m=64 MiB t=4 p=1", a2("password", "somesalt", 65536, 4, 1), "9025d48e68ef7395cca9079da4c4ec3affb3c8911fe4f86d1a2520856f63172c");
  check("argon2id other password", a2("differentpassword", "somesalt", 65536, 2, 1), "0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde");
  check("argon2id other salt", a2("password", "diffsalt", 65536, 2, 1), "bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c");

  // Argon2i: the RFC 9106 section 5.2 vector, the reference implementation's m=64 MiB t=2 vector and two
  // more computed with argon2-cffi (the reference C library), one of them with the passes and lanes
  // shape of our mode. The same input under the other variant must give another result.
  {
    std::string pw(32, '\x01');
    uint8_t salt[16], sec[8], ad[12];
    memset(salt, 2, sizeof salt); memset(sec, 3, sizeof sec); memset(ad, 4, sizeof ad);
    SecretBuf o = argon2(KDF_ARGON2I, (const uint8_t *)pw.data(), pw.size(), salt, sizeof salt, 32, 3, 4, 32, sec, sizeof sec, ad, sizeof ad);
    check("argon2i rfc9106", hex(o.data(), o.size()), "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8");
  }
  check("argon2i m=256 t=2 p=1", a2("password", "somesalt", 256, 2, 1, KDF_ARGON2I), "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f");
  check("argon2i m=64 MiB t=2 p=1", a2("password", "somesalt", 65536, 2, 1, KDF_ARGON2I), "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0");
  check("argon2i m=1024 t=3 p=4", a2("password", "somesalt", 1024, 3, 4, KDF_ARGON2I), "3380af9ea4088a6568f235dd5ae23afbfff0ac7ad166df91186d50ddc244e200");
  check("argon2i m=1024 t=6 p=2", a2("differentpassword", "somesalt", 1024, 6, 2, KDF_ARGON2I), "d0af9446f1bc8628ddbb3102b01068cc305ec600489fab446ee65bff3c969ad9");
  if (a2("password", "somesalt", 256, 2, 1, KDF_ARGON2I) == a2("password", "somesalt", 256, 2, 1)) { puts("FAIL: argon2i equals argon2id"); fails++; }

  // Header bounds: the default passes, and each limit is enforced on its own.
  {
    if (!kdf_ok(DEFAULT_KDF)) { puts("FAIL: default KDF parameters rejected"); fails++; }
    if (!kdf_ok(ARGON2I_KDF)) { puts("FAIL: Argon2i KDF parameters rejected"); fails++; }
    KdfParams bad[] = { { 9, 1, 1, 0 }, { 22, 1, 1, 0 }, { 21, 0, 1, 0 }, { 21, 5, 1, 0 }, { 21, 1, 0, 0 }, { 21, 1, 9, 0 },
                        { 21, 2, 4, 1 }, { 21, 9, 4, 1 }, { 9, 6, 4, 1 }, { 22, 6, 4, 1 }, { 21, 6, 0, 1 }, { 21, 6, 9, 1 },  // Argon2i
                        { 21, 1, 4, 2 }, { 21, 6, 4, 255 } };                                                                  // unknown variant
    for (auto &k : bad)
      if (kdf_ok(k)) { printf("FAIL: KDF parameters %u %u %u %u accepted\n", k.logm, k.t, k.p, k.variant); fails++; }
    KdfParams good[] = { { 10, 1, 1, 0 }, { 11, 4, 8, 0 }, { 21, 4, 8, 0 }, { 10, 3, 1, 1 }, { 11, 8, 8, 1 }, { 21, 8, 8, 1 } };
    for (auto &k : good)
      if (!kdf_ok(k)) { printf("FAIL: KDF parameters %u %u %u %u rejected\n", k.logm, k.t, k.p, k.variant); fails++; }
  }

  // CRC-32 (IEEE 802.3, as in zlib): the standard check value for "123456789" is 0xCBF43926 after the
  // final inversion, which the class leaves to the armor code.
  {
    Crc32 crc;
    for (const char *p = "123456789"; *p; p++) crc.update((uint8_t)*p);
    char got[9];
    snprintf(got, sizeof got, "%08x", crc.value() ^ 0xFFFFFFFFu);
    check("crc32 check value", got, "cbf43926");
  }

  // Single DES against published vectors (FIPS 46 / SP 800-17), both directions.
  {
    // First the generated S-box circuits, exhaustively, against the FIPS 46 tables.
    for (int s = 0; s < 8; s++)
      for (int x = 0; x < 64; x++) {
        int row = ((x >> 4) & 2) | (x & 1), col = (x >> 1) & 15;
        int want = fips_sbox[s][16 * row + col], got = circuit_sbox(s, x);
        if (got != want) { printf("FAIL: S%d(%02o) = %d, want %d\n", s + 1, x, got, want); fails++; }
      }
    struct { const char *k, *p, *c; } v[] = {
      { "0000000000000000", "0000000000000000", "8ca64de9c1b123a7" },
      { "133457799bbcdff1", "0123456789abcdef", "85e813540f0ab405" },
      { "0123456789abcdef", "4e6f772069732074", "3fa40e8a984d4815" },
      { "ffffffffffffffff", "ffffffffffffffff", "7359b2163e4edc58" },
    };
    for (auto &t : v) {
      uint8_t k[8], x[8];
      unhex(t.k, k, 8);
      unhex(t.p, x, 8);
      Des d;
      d.setkey(k);
      d.block(x, true);
      check((std::string("des encrypt ") + t.k).c_str(), hex(x, 8), t.c);
      d.block(x, false);
      check((std::string("des decrypt ") + t.k).c_str(), hex(x, 8), t.p);
    }
  }

  // The bitsliced layer must treat its 32 lanes as 32 independent DES words.
  {
    uint8_t k[8], x[256], y[256], z[256];
    randbytes(k, 8);
    randbytes(x, 256);
    Des d;
    d.setkey(k);
    memcpy(y, x, 256);
    d.layer(y, true);
    memcpy(z, x, 256);
    for (int w = 0; w < 32; w++) d.block(z + 8 * w, true);
    if (memcmp(y, z, 256)) { puts("FAIL: layer differs from 32 single words"); fails++; }
    memcpy(z, y, 256);
    d.layer(z, false);
    if (memcmp(x, z, 256)) { puts("FAIL: layer decrypt is not the inverse"); fails++; }
    memcpy(z, x, 256);
    z[8 * 13 + 2] ^= 0x10;
    d.layer(z, true);
    if (activewords(y, z) != 1 || !memcmp(y + 8 * 13, z + 8 * 13, 8)) { puts("FAIL: lanes not independent"); fails++; }
  }

  // One block through the core with a fixed key and salt: pins the whitening and the DES layers.
  {
    uint8_t k[NL][8], s[SALT_LEN], x[256];
    for (int i = 0; i < NL * 8; i++) k[i / 8][i % 8] = (uint8_t)i;
    for (int i = 0; i < SALT_LEN; i++) s[i] = (uint8_t)(0xa0 + i);
    for (int i = 0; i < 256; i++) x[i] = (uint8_t)(255 - i);
    SillyDesCipher c(k, s);
    c.encrypt_block(x);
    check("encrypt_block known answer", hex(x, 256),
          "ea3faee23ef0e679663baff373b8950f315087293345cd6e00b92b237d6056a032ddbf25970463cd825639fc6dffa13eb04330f4098221eba8fa07f34a25a069"
          "c2407f1a1ed6baffda3a5f67adf120dde95df51cbbdc657de64915b4df6da730f68ad6981a5971bd46951bdff91e5c0267da511b45411b0727437f963258412a"
          "99318316745ad9c82e7aa27f913b6d863de3353bf6ff9b91a17e31017b46756b26e6c961a98db4751a7af7186deb0365a88b7b20fcdcde59bcab2e7c36787a9a"
          "23efba70c1b159663910929ee7c7cfb7a0d5fc37a6e552efeea7e46a61051dd31b16475ffde2c38d45c8e119b2c954a7d164e4f9c1faa103cdcaf45dbd10be6c");
    c.decrypt_block(x);
    bool id = true;
    for (int i = 0; i < 256; i++) id &= x[i] == (uint8_t)(255 - i);
    if (!id) { puts("FAIL: decrypt_block known answer"); fails++; }
  }

  uint8_t key[NL][8], iv[IV_LEN], salt[SALT_LEN];
  randbytes(&key[0][0], NL * 8);
  randbytes(iv, IV_LEN);
  randbytes(salt, SALT_LEN);
  SillyDesCipher cipher(key, salt);
  // Copying wrappers around the in-place primitives.
  auto enc = [](const SillyDesCipher &c, Buf x, const uint8_t *v) { c.cbc_encrypt(x.data(), x.size(), v); return x; };
  auto dec = [](const SillyDesCipher &c, Buf x, const uint8_t *v) { c.cbc_decrypt(x.data(), x.size(), v); return x; };

  Buf a(256), b(256);
  randbytes(a.data(), 256);
  randbytes(b.data(), 256);
  Buf blocks = a;
  blocks.insert(blocks.end(), b.begin(), b.end());
  blocks.insert(blocks.end(), a.begin(), a.end());
  Buf ct = enc(cipher, blocks, iv);
  if (dec(cipher, ct, iv) != blocks) { puts("FAIL: cbc round trip"); fails++; }

  const uint8_t lenmask = 0x5a;
  for (size_t n : { 0, 1, 255, 256, 257, 700 }) {
    Buf p(n), q;
    randbytes(p.data(), n);
    q = p;
    pad256(q, lenmask);
    if (q.size() != (n / 256 + 1) * 256) { printf("FAIL: pad size %zu\n", n); fails++; }
    q = dec(cipher, enc(cipher, q, iv), iv);
    unpad256(q, lenmask);
    if (q != p) { printf("FAIL: pad round trip %zu\n", n); fails++; }
  }

  // Equal plaintext blocks must give unrelated ciphertext blocks.
  if (diffbytes(&ct[0], &ct[512]) < 200) { puts("FAIL: equal blocks give related ciphertext"); fails++; }
  for (int i = 0; i < 256; i += 8)
    if (!memcmp(&ct[i], &ct[512 + i], 8)) { puts("FAIL: repeated 8-byte word"); fails++; break; }

  // Every key bit, parity bits included, must change the ciphertext (whitening uses all of them).
  Buf first(blocks.begin(), blocks.begin() + 256);
  Buf base = enc(cipher, first, iv);
  for (int k = 0; k < NL; k++)
    for (int bit = 0; bit < 64; bit += 9) {
      uint8_t alt[NL][8];
      memcpy(alt, key, sizeof alt);
      alt[k][bit / 8] ^= (uint8_t)(0x80 >> (bit % 8));
      Buf c2 = enc(SillyDesCipher(alt, salt), first, iv);
      if (diffbytes(base.data(), c2.data()) < 200) { printf("FAIL: key %d bit %d has no effect\n", k, bit); fails++; }
    }

  // The salt must change whitening and tweak, so the same key gives an unrelated ciphertext.
  uint8_t salt2[SALT_LEN];
  memcpy(salt2, salt, SALT_LEN);
  salt2[SALT_LEN - 1] ^= 1;
  if (diffbytes(base.data(), enc(SillyDesCipher(key, salt2), first, iv).data()) < 200) { puts("FAIL: salt has no effect"); fails++; }

  // The tweak must differ per block index: equal inputs to G at different positions give unrelated outputs.
  {
    uint8_t zero[IV_LEN] = {0};
    Buf two(512, 0);
    Buf c = enc(cipher, two, zero);                                  // block 0: u = 0; block 1: u = c_0
    Buf c1 = enc(cipher, Buf(c.begin(), c.begin() + 256), zero);    // block 0 with u = c_0
    if (diffbytes(&c[256], c1.data()) < 200) { puts("FAIL: tweak does not depend on block index"); fails++; }
    uint8_t t0[256], t1[256];
    cipher.tweak(0, t0); cipher.tweak(1, t1);
    if (diffbytes(t0, t1) < 200) { puts("FAIL: tweak values related"); fails++; }
  }

  // Diffusion in both directions: one changed input bit or word changes every output word.
  avalanche(cipher, true, "encrypt");
  avalanche(cipher, false, "decrypt");

  // Eight identical DES keys must still give eight distinct layers: the whitening carries the
  // layer index, so the cipher has no slid structure and no involution even for this key file.
  {
    uint8_t same[NL][8];
    for (int i = 0; i < NL; i++) memcpy(same[i], key[0], 8);
    SillyDesCipher weak(same, salt);
    avalanche(weak, true, "identical-keys encrypt");
    uint8_t x[256], y[256];
    randbytes(x, 256);
    memcpy(y, x, 256);
    weak.encrypt_block(y);
    if (diffbytes(x, y) < 200) { puts("FAIL: identical keys: output related to input"); fails++; }
    weak.encrypt_block(y);
    if (diffbytes(x, y) < 200) { puts("FAIL: identical keys: encrypt twice is the identity"); fails++; }
  }

  // The container must draw a fresh salt and IV every time: equal input never yields a shared
  // permutation instance, which is what keeps every block a single-use pair of its cipher.
  {
    KeyInput ki;
    memcpy(ki.key, key, sizeof ki.key);
    Buf msg(300);
    randbytes(msg.data(), msg.size());
    Buf f1 = msg, f2 = msg;
    seal(f1, ki, DEFAULT_KDF);
    seal(f2, ki, DEFAULT_KDF);
    size_t want = HDR_LEN + 256 * (msg.size() / 256 + 1) + TAG_LEN;
    if (f1.size() != want || memcmp(f1.data(), MAGIC, 4) != 0 || f1[7] != 0) { puts("FAIL: container format"); fails++; }
    if (!memcmp(&f1[8], &f2[8], SALT_LEN)) { puts("FAIL: salt repeated"); fails++; }
    if (diffbytes(&f1[8 + SALT_LEN], &f2[8 + SALT_LEN]) < 200) { puts("FAIL: IV repeated"); fails++; }
    if (diffbytes(&f1[HDR_LEN], &f2[HDR_LEN]) < 200) { puts("FAIL: first blocks related across encryptions"); fails++; }
    // In-place sealing must leave no plaintext in the buffer: search the whole container for a
    // 16-byte window of the message (a random message cannot occur in ciphertext by chance).
    for (size_t i = 0; i + 16 <= f1.size(); i++)
      if (!memcmp(&f1[i], msg.data(), 16) || !memcmp(&f1[i], msg.data() + msg.size() - 16, 16)) { puts("FAIL: plaintext left in sealed buffer"); fails++; break; }
    unseal(f1, ki);
    unseal(f2, ki);
    if (f1 != msg || f2 != msg) { puts("FAIL: seal/unseal round trip"); fails++; }
  }

  // Phrase mode through the container with small KDF parameters: the header carries them and
  // unseal must honour them, so a file made with other parameters than the default still opens.
  {
    KeyInput ki;
    ki.usephrase = true;
    const char phr[] = "a phrase of twenty+ characters";
    ki.phrase.assign(phr, phr + strlen(phr));
    Buf msg(100);
    randbytes(msg.data(), msg.size());
    Buf f = msg;
    KdfParams small = { 10, 1, 1, KDF_ARGON2ID };
    seal(f, ki, small);
    if (f[4] != 10 || f[5] != 1 || f[6] != 1 || f[7] != 0) { puts("FAIL: KDF parameters not in header"); fails++; }
    unseal(f, ki);
    if (f != msg) { puts("FAIL: phrase seal/unseal round trip"); fails++; }

    // Argon2i: the variant is in the header, unseal needs nothing else, and flipping the byte (to the
    // other variant, or to an unknown one) is error 13 and never a decryption.
    Buf fi = msg;
    KdfParams small_i = { 10, 3, 1, KDF_ARGON2I };
    seal(fi, ki, small_i);
    if (fi[4] != 10 || fi[5] != 3 || fi[6] != 1 || fi[7] != 1) { puts("FAIL: Argon2i parameters not in header"); fails++; }
    Buf tampered = fi;
    for (uint8_t v : { (uint8_t)0, (uint8_t)2 }) {
      tampered[7] = v;
      Buf t = tampered;
      if (exit_code([&] { unseal(t, ki); }) != 13) { printf("FAIL: variant byte %u accepted\n", v); fails++; }
    }
    unseal(fi, ki);
    if (fi != msg) { puts("FAIL: Argon2i seal/unseal round trip"); fails++; }
  }


  // Errors are exceptions, so the destructors on the way out wipe the keys and the data.
  {
    Buf junk(HDR_LEN + 256 + TAG_LEN, 0x42);
    KeyInput ki;
    memcpy(ki.key, key, sizeof ki.key);
    if (exit_code([&] { unseal(junk, ki); }) != 13) { puts("FAIL: unseal of garbage does not throw ExitError 13"); fails++; }
    if (exit_code([] { errorexit(14); }) != 14) { puts("FAIL: errorexit does not throw its code"); fails++; }
  }

  // ct_equal: a difference at any place, in any bit, is seen; equal is equal; nothing is equal to nothing.
  {
    uint8_t a[64], b[64];
    for (int i = 0; i < 64; i++) a[i] = b[i] = (uint8_t)(i * 7 + 1);
    bool ok = ct_equal(a, b, 64) && ct_equal(a, b, 0) && ct_equal(a, a, 64);
    for (int i = 0; i < 64; i++)
      for (int bit = 0; bit < 8; bit++) {
        b[i] ^= (uint8_t)(1 << bit);
        if (ct_equal(a, b, 64)) ok = false;
        b[i] ^= (uint8_t)(1 << bit);
      }
    if (!ok) { puts("FAIL: ct_equal"); fails++; }
  }

  // The key file parser: comments, blank lines, tabs and a missing final newline are fine;
  // anything else that is not exactly eight 16-digit hexadecimal keys is error 5.
  {
    const char *good = "; comment\n\n  0001020304050607 trailing words\n\t08090A0B0C0D0E0F\n"
                       "1011121314151617\n1819202122232425\n2627282930313233\n3435363738394041\n"
                       "4243444546474849\n; no newline after the last key\n5051525354555657";
    std::string f = write_temp(good);
    uint8_t k[NL][8];
    readkeyfile(f, k);
    if (k[0][0] != 0x00 || k[0][7] != 0x07 || k[1][0] != 0x08 || k[1][7] != 0x0F || k[7][0] != 0x50 || k[7][7] != 0x57)
      { puts("FAIL: key file parsed wrongly"); fails++; }
    remove_file(f);
    const struct { const char *first; int more; } bad[] = {
      { "0001020304050607\n", 6 },  // seven keys
      { "000102030405060\n", 7 },   // 15 digits
      { "000102030405060G\n", 7 },  // not hexadecimal
      { "00010203040506070\n", 7 }  // 17 digits
    };
    for (const auto &c : bad) {
      std::string text = c.first;
      for (int i = 0; i < c.more; i++) text += "0001020304050607\n";
      f = write_temp(text);
      uint8_t kk[NL][8];
      if (exit_code([&] { readkeyfile(f, kk); }) != 5) { puts("FAIL: faulty key file accepted"); fails++; }
      remove_file(f);
    }
    // Every byte value in a digit place: only 0-9, a-f and A-F are accepted, with the right value. The
    // decoder works without branches, so this covers the whole table, the neighbours of each range included.
    for (int c = 0; c < 256; c++) {
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') continue;  // they split lines and tokens
      std::string text = "0";
      text += (char)c;
      text += std::string(14, '0') + "\n";
      for (int i = 1; i < NL; i++) text += "0001020304050607\n";
      f = write_temp(text);
      uint8_t kk[NL][8] = {};
      int rc = exit_code([&] { readkeyfile(f, kk); });
      remove_file(f);
      int want = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
      if (want < 0 ? rc != 5 : (rc != -1 || kk[0][0] != want)) { printf("FAIL: key file digit 0x%02X\n", c); fails++; }
    }
    uint8_t kk[NL][8];
    if (exit_code([&] { readkeyfile("/nonexistent/sillydes.key", kk); }) != 1) { puts("FAIL: missing key file is not error 1"); fails++; }
  }

  // Text made on another system. decode_text undoes the encoding that an editor or a shell gave a
  // key file or an e-mail text: a byte order mark, or UTF-16.
  {
    const struct { std::string in, want; } cases[] = {
      { "abc\n", "abc\n" },
      { "", "" },
      { "\xEF\xBB\xBF" "abc", "abc" },
      { "\xEF\xBB\xBF", "" },
      { utf16("ab\r\n", true), "ab\r\n" },
      { utf16("ab\r\n", false), "ab\r\n" },
      { std::string("\xFF\xFE\xE9\x00" "a\x00\x3D\xD8", 8), "?a?" },  // e acute, a, half of a surrogate pair
      { std::string("\xFE\xFF\x00" "a\x01\x00", 6), "a?" },
      { std::string("\xFF\xFE" "a\x00" "b", 5), "a" }                   // an odd last byte is dropped
    };
    for (const auto &c : cases) {
      std::string t = c.in;
      t.resize(decode_text((uint8_t *)&t[0], t.size()));
      if (t != c.want) { printf("FAIL: decode_text of %s\n", hex((const uint8_t *)c.in.data(), c.in.size()).c_str()); fails++; }
    }
  }

  // One key file, as the editors and shells of other systems write it, must give the same keys.
  {
    const std::string lf = "; a comment\n0001020304050607 first key\n\n\t08090A0B0C0D0E0F\n1011121314151617\n1819202122232425\n"
                           "2627282930313233\n3435363738394041\n4243444546474849\n5051525354555657\n";
    const std::string crlf = replace_all(lf, "\n", "\r\n"), cr = replace_all(lf, "\n", "\r");
    const std::string variants[] = { lf, crlf, cr, "\xEF\xBB\xBF" + lf, "\xEF\xBB\xBF" + crlf,
                                     utf16(lf, true), utf16(crlf, true), utf16(crlf, false), utf16(cr, false) };
    uint8_t first[NL][8];
    for (size_t i = 0; i < sizeof variants / sizeof variants[0]; i++) {
      std::string f = write_temp(variants[i]);
      uint8_t k[NL][8] = {};
      int rc = exit_code([&] { readkeyfile(f, k); });
      remove_file(f);
      if (i == 0) memcpy(first, k, sizeof first);
      if (rc != -1 || memcmp(first, k, sizeof k) != 0 || k[7][7] != 0x57) { printf("FAIL: key file variant %zu\n", i); fails++; }
    }
  }

  // E-mail text is written with LF only, the same bytes on every system, and is read back with
  // any line ending, with a byte order mark, as UTF-16 and inside a message.
  {
    check("armor known answer", [] { Buf a = high2low(Buf{ 'S', 'i', 'l', 'l', 'y', 'D', 'E', 'S' }); return std::string(a.begin(), a.end()); }().c_str(),
          "\n*BEGIN " FORMAT_NAME " message, valid char: 12\n\nIqZgP7Z4FJDz\n\n*END " FORMAT_NAME " message, CRC: -2065946841\n\n");
    Buf msg;
    for (int i = 0; i < 100; i++) msg.push_back((uint8_t)(i * 37 + 11));
    const Buf arm = high2low(msg);
    const std::string lf(arm.begin(), arm.end());
    check("armor of three lines", lf,
          "\n*BEGIN " FORMAT_NAME " message, valid char: 135\n\n2n1JSdz4uEsnK7qWlykFBZi0dQfj53ZSUuXBwVQwMMOfoDIODqG9fhDs7I9b\n"
          "X;7Kym15OcyoqTsXG6qGhxk19YhkZPfT12ZCQtWxsUQgILOPkCI:;pFtbgDc\n3H9LT:76ul0pKjw\n\n*END " FORMAT_NAME " message, CRC: -499477409\n\n");
    const std::string crlf = replace_all(lf, "\n", "\r\n"), cr = replace_all(lf, "\n", "\r");
    const std::string variants[] = { lf, crlf, cr, "\xEF\xBB\xBF" + lf.substr(1), "\xEF\xBB\xBF" + crlf,
                                     utf16(lf, true), utf16(crlf, true), utf16(crlf, false), utf16(cr, false),
                                     "Subject: a message\r\n\r\nSee below.\r\n" + crlf + "-- \r\nsent from somewhere\r\n" };
    for (size_t i = 0; i < sizeof variants / sizeof variants[0]; i++) {
      Buf out;
      int rc = exit_code([&] { out = low2high(Buf(variants[i].begin(), variants[i].end()), "test"); });
      if (rc != -1 || out != msg) { printf("FAIL: e-mail text variant %zu (error %d)\n", i, rc); fails++; }
    }
    const std::string old = replace_all(lf, FORMAT_NAME, "SillyDES 5.1.0");
    if (exit_code([&] { low2high(Buf(old.begin(), old.end()), "test"); }) != 8) { puts("FAIL: e-mail text of another format accepted"); fails++; }

    // The counts are 64-bit numbers on every system (unsigned long and long are 32 bits on Windows):
    // a count of 2^32 + n is not n, a count too large for 64 bits is only damage, and so is a CRC
    // that is not a 32-bit number.
    const struct { const char *name; const char *from, *to; int want; } damaged[] = {
      { "character count above 2^32", "valid char: 135", "valid char: 4294967431", 11 },
      { "character count above 2^64", "valid char: 135", "valid char: 99999999999999999999999", 11 },
      { "CRC above 2^32", "CRC: -499477409", "CRC: 3795489887", 12 },
    };
    for (const auto &d : damaged) {
      const std::string t = replace_all(lf, d.from, d.to);
      if (t == lf || exit_code([&] { low2high(Buf(t.begin(), t.end()), "test"); }) != d.want) { printf("FAIL: e-mail text with a %s\n", d.name); fails++; }
    }
  }

  // Size arithmetic stops at the largest size instead of wrapping around.
  {
    bool ok = checked_add(SIZE_MAX - 1, 1) == SIZE_MAX && checked_mul(SIZE_MAX / 2, 2) == SIZE_MAX - 1 && checked_mul(0, SIZE_MAX) == 0;
    int thrown = 0;
    try { checked_add(SIZE_MAX, 1); } catch (const std::bad_alloc &) { thrown++; }
    try { checked_mul(SIZE_MAX / 2 + 1, 2); } catch (const std::bad_alloc &) { thrown++; }
    if (!ok || thrown != 2) { puts("FAIL: checked_add or checked_mul"); fails++; }
  }

  // Normalisation (NFKC) on cases whose answers come from the Unicode conformance file and from
  // Python's unicodedata; the complete file is run by the CMake target check_unicode.
  {
    typedef std::initializer_list<uint32_t> L;
    const struct { const char *name; L in, want; } cases[] = {
      { "composition", { 0x41, 0x30A }, { 0xC5 } },
      { "singleton", { 0x212B }, { 0xC5 } },
      { "canonical ordering", { 0x61, 0x315, 0x300, 0x5AE, 0x62 }, { 0xE0, 0x5AE, 0x315, 0x62 } },
      { "blocked by an equal class", { 0x61, 0x301, 0x301 }, { 0xE1, 0x301 } },
      { "not blocked by a lower class", { 0x61, 0x5AE, 0x300 }, { 0xE0, 0x5AE } },
      { "composition exclusion", { 0x958 }, { 0x915, 0x93C } },
      { "excluded mark", { 0x344 }, { 0x308, 0x301 } },
      { "decompose, reorder, compose", { 0x1E9B, 0x323 }, { 0x1E69 } },
      { "two starters", { 0x9C7, 0x9BE }, { 0x9CB } },
      { "text starting with a mark", { 0x301, 0x41, 0x30A }, { 0x301, 0xC5 } },
      { "full-width letter", { 0xFF21 }, { 0x41 } },
      { "half-width katakana", { 0xFF76, 0xFF9E }, { 0x30AC } },
      { "ligature", { 0xFB01 }, { 0x66, 0x69 } },
      { "superscript", { 0xB2 }, { 0x32 } },
      { "no-break space", { 0xA0 }, { 0x20 } },
      { "ideographic space", { 0x3000 }, { 0x20 } },
      { "spacing diaeresis", { 0xA8 }, { 0x20, 0x308 } },
      { "ohm sign", { 0x2126 }, { 0x3A9 } },
      { "outside the BMP, folded", { 0x1D400 }, { 0x41 } },
      { "outside the BMP, kept", { 0x1D11E }, { 0x1D11E } },
      { "Hangul jamo", { 0x1100, 0x1161, 0x11A8 }, { 0xAC01 } },
      { "Hangul LV and T", { 0xAC00, 0x11A8 }, { 0xAC01 } },
      { "Hangul LVT and T", { 0xAC01, 0x11A8 }, { 0xAC01, 0x11A8 } },
      { "longest decomposition", { 0xFDFA }, { 0x635, 0x644, 0x649, 0x20, 0x627, 0x644, 0x644, 0x647, 0x20, 0x639, 0x644, 0x64A, 0x647, 0x20, 0x648, 0x633, 0x644, 0x645 } },
      { "joiner kept by NFKC", { 0x65, 0x200D, 0x301 }, { 0x65, 0x200D, 0x301 } }
    };
    for (const auto &c : cases) {
      CodePoints cp(c.in), want(c.want);
      normalize(cp, false);
      if (cp != want) { printf("FAIL: normalisation: %s\n", c.name); fails++; }
      normalize(cp, false);
      if (cp != want) { printf("FAIL: normalisation not stable: %s\n", c.name); fails++; }
    }
    // Without the invisible characters, as a phrase is folded: what they kept apart now composes.
    const struct { const char *name; L in, want; } folded[] = {
      { "joiner between letter and mark", { 0x65, 0x200D, 0x301 }, { 0xE9 } },
      { "grapheme joiner between letter and mark", { 0x65, 0x34F, 0x301 }, { 0xE9 } },
      { "byte order mark", { 0xFEFF, 0x41 }, { 0x41 } },
      { "soft hyphen and zero width space", { 0x61, 0xAD, 0x62, 0x200B, 0x63 }, { 0x61, 0x62, 0x63 } },
      { "variation selector", { 0x2764, 0xFE0F }, { 0x2764 } },
      { "half-width Hangul filler", { 0x61, 0xFFA0, 0x62 }, { 0x61, 0x62 } },
      { "only invisible characters", { 0x200B, 0xFEFF }, {} }
    };
    for (const auto &c : folded) {
      CodePoints cp(c.in), want(c.want);
      normalize(cp, true);
      if (cp != want) { printf("FAIL: folding: %s\n", c.name); fails++; }
    }
  }

  // The canonical form of a phrase: what is refused, and what is the same phrase.
  {
    const std::string base = "correct horse battery staple";
    std::string out;
    const struct { const char *name; std::string in; PhraseFault want; } faults[] = {
      { "tab", "correct horse\tbattery staple", PHRASE_CONTROL },
      { "arrow key", base + "\x1B[D", PHRASE_CONTROL },
      { "NUL", std::string("correct horse\0battery staple", 28), PHRASE_CONTROL },
      { "DEL", base + "\x7F", PHRASE_CONTROL },
      { "two CR", base + "\r\r", PHRASE_CONTROL },
      { "C1 control", base + utf8({ 0x85 }), PHRASE_CONTROL },
      { "control in a short phrase", "short\t", PHRASE_CONTROL },
      { "Latin-1", "cr\xE8me br\xFBl\xE9" "e \xE0 la carte", PHRASE_NOT_UTF8 },
      { "UTF-16", utf16(base, true), PHRASE_NOT_UTF8 },
      { "overlong, two bytes", base + "\xC0\x80", PHRASE_NOT_UTF8 },
      { "overlong, three bytes", base + "\xE0\x80\x80", PHRASE_NOT_UTF8 },
      { "overlong, four bytes", base + "\xF0\x80\x80\x80", PHRASE_NOT_UTF8 },
      { "surrogate", base + "\xED\xA0\x80", PHRASE_NOT_UTF8 },
      { "above U+10FFFF", base + "\xF4\x90\x80\x80", PHRASE_NOT_UTF8 },
      { "five-byte form", base + "\xF8\x88\x80\x80\x80", PHRASE_NOT_UTF8 },
      { "cut off", base + "\xC3", PHRASE_NOT_UTF8 },
      { "lone continuation byte", base + "\x80", PHRASE_NOT_UTF8 },
      { "19 characters", "nineteen characters", PHRASE_SHORT },
      { "19 characters and spaces", "nineteen characters      ", PHRASE_SHORT },
      { "19 characters of three bytes", utf8({ 0x65E5, 0x672C, 0x8A9E, 0x65E5, 0x672C, 0x8A9E, 0x65E5, 0x672C, 0x8A9E, 0x65E5, 0x672C, 0x8A9E,
                                               0x65E5, 0x672C, 0x8A9E, 0x65E5, 0x672C, 0x8A9E, 0x65E5 }), PHRASE_SHORT },
      { "only invisible characters", utf8({ 0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B,
                                            0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B, 0x200B }), PHRASE_SHORT },
      { "empty", "", PHRASE_SHORT }
    };
    for (const auto &c : faults)
      if (canon(c.in, out) != c.want) { printf("FAIL: phrase with %s is not refused as expected\n", c.name); fails++; }

    // Each of these is the phrase on the right, typed, piped or pasted in another way.
    const std::string creme = utf8({ 'c', 'r', 0xE8, 'm', 'e', ' ', 'b', 'r', 0xFB, 'l', 0xE9, 'e', ' ', 0xE0, ' ', 'l', 'a', ' ', 'c', 'a', 'r', 't', 'e' });
    const std::string twenty = "exactly 20 character";
    const std::string kanji20 = utf8({ 0x65E5, 0x672C, 0x8A9E, 0x65E5, 0x672C, 0x8A9E, 0x65E5, 0x672C, 0x8A9E, 0x65E5, 0x672C, 0x8A9E,
                                       0x65E5, 0x672C, 0x8A9E, 0x65E5, 0x672C, 0x8A9E, 0x65E5, 0x672C });
    const struct { const char *name; std::string in, want; } same[] = {
      { "plain ASCII", base, base },
      { "CR", base + "\r", base },
      { "trailing spaces", base + "   ", base },
      { "trailing spaces and CR", base + "  \r", base },
      { "leading spaces are kept", "  " + base, "  " + base },
      { "exactly 20 characters", twenty, twenty },
      { "20 characters of three bytes", kanji20, kanji20 },
      { "NFC", creme, creme },
      { "NFD", utf8({ 'c', 'r', 'e', 0x300, 'm', 'e', ' ', 'b', 'r', 'u', 0x302, 'l', 'e', 0x301, 'e', ' ', 'a', 0x300, ' ', 'l', 'a', ' ', 'c', 'a', 'r', 't', 'e' }), creme },
      { "byte order mark and CR", "\xEF\xBB\xBF" + creme + "\r", creme },
      { "no-break spaces", replace_all(creme, " ", utf8({ 0xA0 })), creme },
      { "trailing ideographic space", creme + utf8({ 0x3000 }), creme },
      { "invisible characters", replace_all(creme, "br", utf8({ 'b', 0x200B, 0xAD, 'r', 0x200E })), creme },
      { "full-width letters", utf8({ 0xFF43, 0xFF52, 0xE8, 0xFF4D, 0xFF45, 0x3000, 'b', 'r', 0xFB, 'l', 0xE9, 'e', ' ', 0xE0, ' ', 'l', 'a', ' ', 0xFF43, 0xFF41, 0xFF52, 0xFF54, 0xFF45 }), creme },
      { "outside the BMP", base + utf8({ ' ', 0x1D11E }), base + utf8({ ' ', 0x1D11E }) },
      { "mathematical letters", utf8({ 0x1D41C, 0x1D428, 0x1D42B, 0x1D42B, 0x1D41E, 0x1D41C, 0x1D42D }) + base.substr(7), base }
    };
    for (const auto &c : same) {
      std::string again;
      if (canon(c.in, out) != PHRASE_OK || out != c.want) { printf("FAIL: phrase canonical form: %s\n", c.name); fails++; }
      if (canon(out, again) != PHRASE_OK || again != out) { printf("FAIL: phrase canonical form not stable: %s\n", c.name); fails++; }
    }
    // What stays different: case, and look-alikes that Unicode keeps apart.
    std::string a, b;
    canon(base, a);
    canon("Correct horse battery staple", b);
    if (a == b) { puts("FAIL: phrase folding ignores case"); fails++; }
    canon(replace_all(base, "c", utf8({ 0x441 })), b);  // Cyrillic es
    if (a == b) { puts("FAIL: phrase folding confuses Latin and Cyrillic"); fails++; }
  }

  // The Unicode tables are part of the file format: other tables give other keys for some phrases.
  // If this fails, the tables were regenerated; that needs a new format (see version.h).
  {
    Sha512 h;
    h.update((const uint8_t *)UNICODE_VERSION, sizeof UNICODE_VERSION);
    for (uint32_t v : UNI_DECOMP_POOL) hash32(h, v);
    for (const UniDecomp &d : UNI_DECOMP) { hash32(h, d.cp); hash32(h, d.pos); hash32(h, d.len); }
    for (const UniClass &c : UNI_CCC) { hash32(h, c.first); hash32(h, c.last); hash32(h, c.ccc); }
    for (const UniPair &p : UNI_COMPOSE) { hash32(h, p.first); hash32(h, p.second); hash32(h, p.composed); }
    for (const UniRange &r : UNI_IGNORABLE) { hash32(h, r.first); hash32(h, r.last); }
    uint8_t o[64];
    h.final(o);
    check("Unicode tables of format " FORMAT_NAME, hex(o, 64),
          "443ae981d8ff0cced092ab53044bd7b53f5e083055c5f254f0178b32d0e359e535ba846ec793940295b4cecf1b8204709bc166067da0bac77bfb7f73ebe0c6f1");
  }

  // Both secret buffer types keep their contents while they grow, across the page and the
  // 64 KiB mapping thresholds.
  {
    Buf a;
    SecretBuf b;
    for (size_t i = 0; i < 200000; i++) { a.push_back((uint8_t)(i * 7)); b.push_back((uint8_t)(i * 13)); }
    bool ok = true;
    for (size_t i = 0; i < 200000; i++) ok = ok && a[i] == (uint8_t)(i * 7) && b[i] == (uint8_t)(i * 13);
    Buf c = a;
    ok = ok && c == a;
    if (!ok) { puts("FAIL: secret buffers lose data when they grow"); fails++; }
  }

  // scrub_stack must remove what finished functions left on the stack. The control first shows that
  // the pattern is there, since under a sanitizer or another optimiser the frames may not line up.
  {
    leave_pattern();
#ifdef SANITIZED
    // The sanitizers move locals into red zones and fake stacks of their own: no layout to compare.
    if (true) {
#else
    if (find_pattern() < 1000) {
#endif
      puts("skipped: stack scrub test (the stack frames do not line up in this build)");
    } else {
      // scrub_stack cannot wipe its own frame, which is live while it works; its alignment padding
      // may keep a word, so a few bytes are allowed (Windows x64 also keeps 32 bytes of home space
      // for the callees below that frame).
      scrub_stack();
      size_t left = find_pattern();
      if (left > STACK_LEFT_MAX) { printf("FAIL: scrub_stack left %zu bytes of the pattern on the stack\n", left); fails++; }
    }
  }

  // Locking is best effort, so these run only when RLIMIT_MEMLOCK leaves room for them.
  {
    long limit_kb = memlock_limit_kb();
    long before = locked_kb();
#ifdef SANITIZED
    before = -1;
#endif
    if (before < 0 || limit_kb < 1024) {
      puts("skipped: memory locking tests (the lock limit is below 1 MiB, the OS does not report locked memory, or a sanitizer build)");
    } else {
      lock_stack();
      long after_stack = locked_kb();
      if (after_stack <= before) { puts("FAIL: lock_stack locked nothing"); fails++; }
      {
        SecretBuf s(100);
        if (locked_kb() < after_stack + 4) { puts("FAIL: SecretBuf is not locked"); fails++; }
      }
      if (locked_kb() != after_stack) { puts("FAIL: SecretBuf stays locked after it is freed"); fails++; }
      if (limit_kb < (512L << 10)) {
        size_t big = (size_t)(limit_kb + (64 << 10)) * 1024;  // 64 MiB over the limit
        void *p = secure_alloc(big);
        if (lock_memory(p, big) || locked_kb() != after_stack) { puts("FAIL: lock_memory past the limit"); fails++; }
        secure_free(p, big);
      }
    }
  }

  // A secret mapping exists only where the OS has one (Linux with memfd_secret) and is limited by
  // RLIMIT_MEMLOCK like mlock; it must be zero-filled and writable, and must refuse, not crash, past the limit.
  {
    const size_t n = 2 << 20;
    uint8_t *p = (uint8_t *)secret_map(n);
    if (!p) {
      puts("skipped: secret_map (this OS has no memfd_secret, the kernel or a filter refuses it, or the lock limit is below 2 MiB)");
    } else {
      bool zero = true;
      for (size_t i = 0; i < n; i += 4096) zero = zero && p[i] == 0;
      if (!zero) { puts("FAIL: secret_map is not zero-filled"); fails++; }
      memset(p, 0xA5, n);
      secure_free(p, n);
      puts("ok: secret_map gave a zero-filled mapping");
    }
    long limit_kb = memlock_limit_kb();
    if (limit_kb < (1L << 20)) {
      // The caller may hold CAP_IPC_LOCK, so a mapping past the limit is not wrong; a crash is.
      size_t big = (size_t)(limit_kb + (64 << 10)) * 1024;
      void *q = secret_map(big);
      if (q) secure_free(q, big);
      puts("ok: secret_map past the lock limit did not crash");
    }
  }

  // What the OS says is free decides error 7. It must be a real figure on every OS (UINT64_MAX is
  // "unknown", which the other systems must not need), and below what any machine has.
  {
    uint64_t avail = available_memory();
    printf("info: available_memory() reports %llu MiB\n", (unsigned long long)(avail >> 20));
    if (avail == 0) { puts("FAIL: available_memory reports nothing"); fails++; }
#if defined(_WIN32) || defined(__APPLE__)
    if (avail == UINT64_MAX) { puts("FAIL: available_memory does not know"); fails++; }
#endif
    if (avail != UINT64_MAX && avail > ((uint64_t)1 << 50)) { puts("FAIL: available_memory is beyond any machine"); fails++; }
  }

  // harden_process, last because it changes the process for good (no dumps, no debugger of the same user, and on
  // Windows no new code and no child process): the OS is asked what is in force.
  {
    harden_process();
    std::string detail;
    int state = check_hardening(detail);
    if (state > 0) { printf("FAIL: process hardening: %s\n", detail.c_str()); fails++; }
    else printf("info: process hardening: %s%s\n", state == 0 ? "" : "cannot be read back: ", detail.c_str());
  }

  if (fails) return 1;
  puts("ok: BLAKE2b, SHA-512, HMAC, Argon2id, DES and CRC-32 known answers; KDF bounds; S-box circuits exhaustive; bitsliced lanes independent; core block known answer; "
       "cipher round trips; whitening, salt, tweak and key-bit dependence; "
       "avalanche both ways; identical keys give distinct layers; fresh salt and IV per container; "
       "errors as exceptions; key file parser; secret buffers; "
       "key files and e-mail text in other line endings and encodings; normalisation; phrase canonical form; Unicode tables");
  return 0;
}
