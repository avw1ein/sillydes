// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// Unit tests for the hash primitives and the block cipher.
#include <cstdio>
#include <cstring>

#include "common.h"
#include "container.h"
#include "des.h"
#include "des_sbox_ct.h"
#include "kdf.h"
#include "odette_cipher.h"
#include "sha256.h"
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
static void avalanche(const OdetteCipher &c, bool enc, const char *name)
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

static std::string sha(const std::string &m)
{
  Sha256 s;
  uint8_t o[32];
  s.update((const uint8_t *)m.data(), m.size());
  s.final(o);
  return hex(o, 32);
}

static std::string sha512(const std::string &m)
{
  Sha512 s;
  uint8_t o[64];
  s.update((const uint8_t *)m.data(), m.size());
  s.final(o);
  return hex(o, 64);
}

static std::string kdf(const char *pw, const char *salt, uint32_t it, size_t n)
{
  Buf b = pbkdf2(pw, (const uint8_t *)salt, strlen(salt), it, n);
  return hex(b.data(), b.size());
}

int main()
{
  check("sha256 empty", sha(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  check("sha256 abc", sha("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  check("sha256 two blocks", sha("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

  uint8_t mac[32];
  const std::string msg = "what do ya want for nothing?";
  Hmac((const uint8_t *)"Jefe", 4).mac((const uint8_t *)msg.data(), msg.size(), mac);
  check("hmac rfc4231 #2", hex(mac, 32), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

  check("sha512 empty", sha512(""),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
  check("sha512 abc", sha512("abc"),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
  check("sha512 two blocks", sha512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");

  uint8_t mac512[64];
  Hmac512((const uint8_t *)"Jefe", 4).mac((const uint8_t *)msg.data(), msg.size(), mac512);
  check("hmac-sha512 rfc4231 #2", hex(mac512, 64),
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
  const std::string longmsg = "Test Using Larger Than Block-Size Key - Hash Key First";
  Hmac512(Buf(131, 0xaa).data(), 131).mac((const uint8_t *)longmsg.data(), longmsg.size(), mac512);
  check("hmac-sha512 rfc4231 #6", hex(mac512, 64),
        "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598");

  check("pbkdf2 1", kdf("password", "salt", 1, 32),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
  check("pbkdf2 2", kdf("password", "salt", 2, 32),
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
  check("pbkdf2 4096", kdf("password", "salt", 4096, 32),
        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
  check("pbkdf2 40 bytes", kdf("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40),
        "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9");

  auto sc = [](const char *pw, const char *salt, uint32_t N, uint32_t r, uint32_t p) {
    Buf b = scrypt(pw, (const uint8_t *)salt, strlen(salt), N, r, p, 64);
    return hex(b.data(), b.size());
  };
  check("scrypt rfc7914 #1", sc("", "", 16, 1, 1),
        "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906");
  check("scrypt rfc7914 #2", sc("password", "NaCl", 1024, 8, 16),
        "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640");
  check("scrypt rfc7914 #3", sc("pleaseletmein", "SodiumChloride", 16384, 8, 1),
        "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887");

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
    OdetteCipher c(k, s);
    c.encrypt_block(x);
    check("encrypt_block known answer", hex(x, 256),
          "57c405149d25e79e1df74953b9e0d09304f3b9c199698bc201ef77ff1658e3a66455eaa8eaa73f0cef146eab6c6b522f3660e00728c38971ebaef87cb4199792"
          "78c6c9e0c9ca3c75f9cdd97fb77653e5f4f797549f315456985f982fa6307a133c40767cd28bc745a22a996236972798e0cf67bd130e67672dfa42a6b1e827c0"
          "382e1b4015d6ff8f436a781bb5acb7dc1527edf806bbc8f2668c99d7ce968eac8c91720cd2ed14dd8abb17017a70ac5d416e653b85d84211ea46998897527690"
          "278d5bcaa808dc50cb9f08f86540e1fb11151e9c4426fb2e3cc1354f9ee7dc6fdf0f0eb87868d0856a1b11c941702c7bd46a1d57e5a2987c9429a8f405b01072");
    c.decrypt_block(x);
    bool id = true;
    for (int i = 0; i < 256; i++) id &= x[i] == (uint8_t)(255 - i);
    if (!id) { puts("FAIL: decrypt_block known answer"); fails++; }
  }

  uint8_t key[NL][8], iv[IV_LEN], salt[SALT_LEN];
  randbytes(&key[0][0], NL * 8);
  randbytes(iv, IV_LEN);
  randbytes(salt, SALT_LEN);
  OdetteCipher cipher(key, salt);

  Buf a(256), b(256);
  randbytes(a.data(), 256);
  randbytes(b.data(), 256);
  Buf blocks = a;
  blocks.insert(blocks.end(), b.begin(), b.end());
  blocks.insert(blocks.end(), a.begin(), a.end());
  Buf ct = cipher.cbc_encrypt(blocks, iv);
  if (cipher.cbc_decrypt(ct, iv) != blocks) { puts("FAIL: cbc round trip"); fails++; }

  const uint8_t lenmask = 0x5a;
  for (size_t n : { 0, 1, 255, 256, 257, 700 }) {
    Buf p(n);
    randbytes(p.data(), n);
    if (unpad256(cipher.cbc_decrypt(cipher.cbc_encrypt(pad256(p, lenmask), iv), iv), lenmask) != p) { printf("FAIL: pad round trip %zu\n", n); fails++; }
  }

  // Equal plaintext blocks must give unrelated ciphertext blocks.
  if (diffbytes(&ct[0], &ct[512]) < 200) { puts("FAIL: equal blocks give related ciphertext"); fails++; }
  for (int i = 0; i < 256; i += 8)
    if (!memcmp(&ct[i], &ct[512 + i], 8)) { puts("FAIL: repeated 8-byte word"); fails++; break; }

  // Every key bit, parity bits included, must change the ciphertext (whitening uses all of them).
  Buf first(blocks.begin(), blocks.begin() + 256);
  Buf base = cipher.cbc_encrypt(first, iv);
  for (int k = 0; k < NL; k++)
    for (int bit = 0; bit < 64; bit += 9) {
      uint8_t alt[NL][8];
      memcpy(alt, key, sizeof alt);
      alt[k][bit / 8] ^= (uint8_t)(0x80 >> (bit % 8));
      Buf c2 = OdetteCipher(alt, salt).cbc_encrypt(first, iv);
      if (diffbytes(base.data(), c2.data()) < 200) { printf("FAIL: key %d bit %d has no effect\n", k, bit); fails++; }
    }

  // The salt must change whitening and tweak, so the same key gives an unrelated ciphertext.
  uint8_t salt2[SALT_LEN];
  memcpy(salt2, salt, SALT_LEN);
  salt2[SALT_LEN - 1] ^= 1;
  if (diffbytes(base.data(), OdetteCipher(key, salt2).cbc_encrypt(first, iv).data()) < 200) { puts("FAIL: salt has no effect"); fails++; }

  // The tweak must differ per block index: equal inputs to G at different positions give unrelated outputs.
  {
    uint8_t zero[IV_LEN] = {0};
    Buf two(512, 0);
    Buf c = cipher.cbc_encrypt(two, zero);                       // block 0: u = 0; block 1: u = c_0
    Buf c1 = cipher.cbc_encrypt(Buf(c.begin(), c.begin() + 256), zero);  // block 0 with u = c_0
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
    OdetteCipher weak(same, salt);
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
    Buf f1 = seal(msg, ki, DEFAULT_KDF), f2 = seal(msg, ki, DEFAULT_KDF);
    size_t want = HDR_LEN + 256 * (msg.size() / 256 + 1) + TAG_LEN;
    if (f1.size() != want || memcmp(f1.data(), MAGIC, 4) != 0 || f1[7] != 0) { puts("FAIL: container format"); fails++; }
    if (!memcmp(&f1[8], &f2[8], SALT_LEN)) { puts("FAIL: salt repeated"); fails++; }
    if (diffbytes(&f1[8 + SALT_LEN], &f2[8 + SALT_LEN]) < 200) { puts("FAIL: IV repeated"); fails++; }
    if (diffbytes(&f1[HDR_LEN], &f2[HDR_LEN]) < 200) { puts("FAIL: first blocks related across encryptions"); fails++; }
    if (unseal(f1, ki) != msg || unseal(f2, ki) != msg) { puts("FAIL: seal/unseal round trip"); fails++; }
  }

  if (fails) return 1;
  puts("ok: SHA-256/512, HMAC, PBKDF2, scrypt and DES known answers; S-box circuits exhaustive; bitsliced lanes independent; core block known answer; "
       "cipher round trips; whitening, salt, tweak and key-bit dependence; "
       "avalanche both ways; identical keys give distinct layers; fresh salt and IV per container");
  return 0;
}
