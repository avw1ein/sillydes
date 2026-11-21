// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// Unit tests for the hash primitives and the block cipher.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/resource.h>
#include <unistd.h>

#include "blake2b.h"
#include "common.h"
#include "container.h"
#include "crc32.h"
#include "des.h"
#include "des_sbox_ct.h"
#include "kdf.h"
#include "keys.h"
#include "sillydes_cipher.h"
#include "sha512.h"

static std::string hex(const uint8_t *p, size_t n)
{
  static const char d[] = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
  return s;
}

static void unhex(const char *s, uint8_t *out, size_t n)
{
  for (size_t i = 0; i < n; i++) sscanf(s + 2 * i, "%2hhx", &out[i]);
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
  for (int i = 0; i < n; i++) c += __builtin_popcount(a[i] ^ b[i]);
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

static std::string a2(const char *pw, const char *salt, uint32_t m, uint32_t t, uint32_t p)
{
  SecretBuf b = argon2id((const uint8_t *)pw, strlen(pw), (const uint8_t *)salt, strlen(salt), m, t, p, 32);
  return hex(b.data(), b.size());
}

// Error messages go to stderr; the tests that provoke them keep the output readable.
struct QuietStderr {
  int saved;
  QuietStderr() : saved(dup(STDERR_FILENO))
  {
    int nul = open("/dev/null", O_WRONLY);
    dup2(nul, STDERR_FILENO);
    close(nul);
  }
  ~QuietStderr()
  {
    dup2(saved, STDERR_FILENO);
    close(saved);
  }
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

// Leaves a pattern in a large stack frame, and counts how much of it a frame of the same size
// finds in uninitialised memory at the same place.
__attribute__((noinline)) static void leave_pattern()
{
  volatile uint8_t junk[30000];
  for (size_t i = 0; i < sizeof junk; i++) junk[i] = 0xA7;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
__attribute__((noinline)) static size_t find_pattern()
{
  volatile uint8_t probe[30000];  // read on purpose before it is written
  size_t n = 0;
  for (size_t i = 0; i < sizeof probe; i++) n += probe[i] == 0xA7;
  return n;
}
#pragma GCC diagnostic pop

static long vmlck_kb()
{
  FILE *f = fopen("/proc/self/status", "r");
  long kb = -1;
  char line[128];
  while (f && fgets(line, sizeof line, f))
    if (sscanf(line, "VmLck: %ld kB", &kb) == 1) break;
  if (f) fclose(f);
  return kb;
}

static std::string write_temp(const std::string &text)
{
  char name[] = "/tmp/sillydes_test_XXXXXX";
  int fd = mkstemp(name);
  if (fd >= 0) { if (write(fd, text.data(), text.size()) < 0) {} close(fd); }
  return name;
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

  // Header bounds: the default passes, and each limit is enforced on its own.
  {
    if (!kdf_ok(DEFAULT_KDF)) { puts("FAIL: default KDF parameters rejected"); fails++; }
    KdfParams bad[] = { { 9, 1, 1 }, { 22, 1, 1 }, { 21, 0, 1 }, { 21, 5, 1 }, { 21, 1, 0 }, { 21, 1, 9 } };
    for (auto &k : bad)
      if (kdf_ok(k)) { printf("FAIL: KDF parameters %u %u %u accepted\n", k.logm, k.t, k.p); fails++; }
    KdfParams good[] = { { 10, 1, 1 }, { 11, 4, 8 }, { 21, 4, 8 } };
    for (auto &k : good)
      if (!kdf_ok(k)) { printf("FAIL: KDF parameters %u %u %u rejected\n", k.logm, k.t, k.p); fails++; }
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
          "4a1dfbfc3c1f082fcd57415047d3477ba8d61895335d908942dc71955fe648e7af3fec5857cd17a2d511b96d150684b470f93e0d7be09f5c2319dc3da222ff9a"
          "18e5be22f049eea96a09bb581268a70cab5baf6ca31d4d1b260eda302333c1c738a3da939156db07462f7aa01e09b27c8d5faebf3350bd10274b7c1ec8514089"
          "022485fde43dba20fc762d149f75766600b54ad39c4e6af9e770c8a28157f8cde7b388ae4c6ae17fcef8153fdbf045d3db5747d0b385c2214bfb0a7fe5b7974b"
          "f2209573bf7792686981b9d1baa38138415585b44de38f54d8acdd6328728f42b860938a883d97c34c65dae51ddfa05569a605c7b167b0b792545b95a4464349");
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
    KdfParams small = { 10, 1, 1 };
    seal(f, ki, small);
    if (f[4] != 10 || f[5] != 1 || f[6] != 1) { puts("FAIL: KDF parameters not in header"); fails++; }
    unseal(f, ki);
    if (f != msg) { puts("FAIL: phrase seal/unseal round trip"); fails++; }
  }


  // Errors are exceptions, so the destructors on the way out wipe the keys and the data.
  {
    Buf junk(HDR_LEN + 256 + TAG_LEN, 0x42);
    KeyInput ki;
    memcpy(ki.key, key, sizeof ki.key);
    if (exit_code([&] { unseal(junk, ki); }) != 13) { puts("FAIL: unseal of garbage does not throw ExitError 13"); fails++; }
    if (exit_code([] { errorexit(14); }) != 14) { puts("FAIL: errorexit does not throw its code"); fails++; }
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
    unlink(f.c_str());
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
      unlink(f.c_str());
    }
    uint8_t kk[NL][8];
    if (exit_code([&] { readkeyfile("/nonexistent/sillydes.key", kk); }) != 1) { puts("FAIL: missing key file is not error 1"); fails++; }
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
    if (find_pattern() < 1000) {
      puts("skipped: stack scrub test (the stack frames do not line up in this build)");
    } else {
      scrub_stack();
      if (find_pattern() != 0) { puts("FAIL: scrub_stack left data on the stack"); fails++; }
    }
  }

  // Locking is best effort, so these run only when RLIMIT_MEMLOCK leaves room for them.
  {
    rlimit rl;
    long limit_kb = getrlimit(RLIMIT_MEMLOCK, &rl) != 0 ? 0 : rl.rlim_cur == RLIM_INFINITY ? 1L << 40 : (long)(rl.rlim_cur / 1024);
    long before = vmlck_kb();
#ifdef SANITIZED
    before = -1;
#endif
    if (before < 0 || limit_kb < 1024) {
      puts("skipped: memory locking tests (RLIMIT_MEMLOCK below 1 MiB, no /proc, or a sanitizer build)");
    } else {
      lock_stack();
      long after_stack = vmlck_kb();
      if (after_stack <= before) { puts("FAIL: lock_stack locked nothing"); fails++; }
      {
        SecretBuf s(100);
        if (vmlck_kb() < after_stack + 4) { puts("FAIL: SecretBuf is not locked"); fails++; }
      }
      if (vmlck_kb() != after_stack) { puts("FAIL: SecretBuf stays locked after it is freed"); fails++; }
      if (limit_kb < (512L << 10)) {
        size_t big = (size_t)(limit_kb + (64 << 10)) * 1024;  // 64 MiB over the limit
        void *p = secure_alloc(big);
        if (lock_memory(p, big) || vmlck_kb() != after_stack) { puts("FAIL: lock_memory past the limit"); fails++; }
        secure_free(p, big);
      }
    }
  }

  if (fails) return 1;
  puts("ok: BLAKE2b, SHA-512, HMAC, Argon2id, DES and CRC-32 known answers; KDF bounds; S-box circuits exhaustive; bitsliced lanes independent; core block known answer; "
       "cipher round trips; whitening, salt, tweak and key-bit dependence; "
       "avalanche both ways; identical keys give distinct layers; fresh salt and IV per container; "
       "errors as exceptions; key file parser; secret buffers");
  return 0;
}
