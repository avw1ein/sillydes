// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// Timing check in the style of dudect (PORTPLAN.md 5.3, items 3 and 4): two classes of input are
// timed in random order and compared with Welch's t-test. For code that runs in constant time the
// two distributions are the same, and |t| stays small however long one measures; a leak shows as a
// |t| that grows with the number of measurements.
//
// Classes: differences of a MAC at its first byte and at its last (the compare and a whole unseal),
// digits against non-digits (the hex decoder), fixed against random data (DES, HMAC), a zero key
// against a random one (the key schedule). The program exits 1 if some test has |t| above 10 in
// every one of 3 rounds: noise on a shared machine passes in some round, a leak does not.
//
// Not a proof, and not a replacement for test/ct_valgrind.cpp, which sees every branch but not what
// the CPU does with them; it is what can be run on every OS. Not constant-time on purpose and not
// tested: Argon2id in phrase mode and the normalisation of a phrase.

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <random>
#include <vector>

#include "common.h"
#include "container.h"
#include "des.h"
#include "keys.h"
#include "sha512.h"
#include "test_os.h"

namespace {

typedef std::chrono::steady_clock Clock;

struct Welch {
  double n[2] = { 0, 0 }, mean[2] = { 0, 0 }, m2[2] = { 0, 0 };
  void add(int cls, double x)
  {
    n[cls] += 1;
    double d = x - mean[cls];
    mean[cls] += d / n[cls];
    m2[cls] += d * (x - mean[cls]);
  }
  double t() const
  {
    if (n[0] < 2 || n[1] < 2) return 0;
    double v0 = m2[0] / (n[0] - 1), v1 = m2[1] / (n[1] - 1);
    double se = std::sqrt(v0 / n[0] + v1 / n[1]);
    return se > 0 ? (mean[0] - mean[1]) / se : 0;
  }
};

struct Sample { int cls; double ns; };

// One round: `samples` timings of `run(cls)`, classes in random order, the slowest 5 % dropped
// (interrupts and cache misses of the machine, not of the code).
double round_t(const std::function<void(int)> &run, int samples, std::mt19937 &rng)
{
  std::vector<Sample> all;
  all.reserve((size_t)samples);
  for (int i = 0; i < 50; i++) run(i & 1);  // warm up
  for (int i = 0; i < samples; i++) {
    int cls = (int)(rng() & 1);
    Clock::time_point a = Clock::now();
    run(cls);
    Clock::time_point b = Clock::now();
    all.push_back({ cls, (double)std::chrono::duration_cast<std::chrono::nanoseconds>(b - a).count() });
  }
  std::vector<double> sorted;
  for (const Sample &s : all) sorted.push_back(s.ns);
  std::sort(sorted.begin(), sorted.end());
  double cut = sorted[sorted.size() * 95 / 100];
  Welch w;
  for (const Sample &s : all)
    if (s.ns <= cut) w.add(s.cls, s.ns);
  return w.t();
}

int failures;

void check(const char *name, const std::function<void(int)> &run, int samples)
{
  std::mt19937 rng(12345);
  double t[3] = { 0, 0, 0 };
  bool ok = false;
  for (int r = 0; r < 3 && !ok; r++) {
    t[r] = round_t(run, samples, rng);
    ok = std::fabs(t[r]) < 10;
  }
  printf("%-46s t = %7.2f%s\n", name, t[0], ok ? "" : "   (not below 10 in every round)");
  if (!ok) failures++;
}

// The control: the test must see a leak where there is one. Detected if |t| is above 10 in the first round.
void check_detects(const char *name, const std::function<void(int)> &run, int samples)
{
  std::mt19937 rng(54321);
  double t = round_t(run, samples, rng);
  bool seen = std::fabs(t) > 10;
  printf("%-46s t = %7.2f%s\n", name, t, seen ? "   (detected, as it must be)" : "   (NOT detected: the test is blind)");
  if (!seen) failures++;
}

volatile uint64_t sink;
int scale = 1;  // argument 1: more samples for a more sensitive run

}  // namespace

int main(int argc, char **argv)
{
  if (argc > 1) scale = std::max(1, atoi(argv[1]));
  std::mt19937 rng(777);
  auto random_bytes = [&](uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) p[i] = (uint8_t)rng(); };

  // The MAC compare: one array differs from the other at the first byte, or at the last.
  {
    uint8_t a[64], b0[64], b1[64];
    random_bytes(a, 64);
    memcpy(b0, a, 64); b0[0] ^= 0x55;
    memcpy(b1, a, 64); b1[63] ^= 0x55;
    uint8_t b[64];  // both classes compare against the same buffer: a different address is a timing difference of its own
    check("ct_equal, difference first or last byte", [&](int cls) {
      uint64_t acc = 0;
      memcpy(b, cls ? b1 : b0, 64);
      for (int i = 0; i < 2000; i++) acc += ct_equal(a, b, 64);
      sink = acc;
    }, 3000 * scale);
  }

  // The control: a comparison that stops at the first difference. It must be detected.
  {
    uint8_t a[64], b0[64], b1[64];
    random_bytes(a, 64);
    memcpy(b0, a, 64); b0[0] ^= 0x55;
    memcpy(b1, a, 64); b1[63] ^= 0x55;
    check_detects("control: early-exit compare", [&](int cls) {
      uint64_t acc = 0;
      const uint8_t *b = cls ? b1 : b0;
      for (int i = 0; i < 2000; i++) {
        bool eq = true;
        for (int k = 0; k < 64; k++) {
          if (a[k] != b[k]) { eq = false; break; }
        }
        acc += eq;
      }
      sink = acc;
    }, 3000 * scale);
  }

  // Hex decoding: 256 digits or 256 bytes that are none.
  {
    uint8_t digits[256], others[256];
    for (int i = 0; i < 256; i++) { digits[i] = (uint8_t)"0123456789abcdefABCDEF"[i % 22]; others[i] = (uint8_t)"ghijklmnopqrstuvwxyz!?"[i % 22]; }
    check("hex_digit, digits or other bytes", [&](int cls) {
      uint32_t acc = 0;
      const uint8_t *p = cls ? others : digits;
      for (int rep = 0; rep < 8; rep++)
        for (int i = 0; i < 256; i++) acc += hex_digit(p[i]);
      sink = acc;
    }, 3000 * scale);
  }

  // DES: the key schedule of a zero key or a random key, the layer on zero data or random data.
  {
    uint8_t zero[8] = {}, rnd[8];
    random_bytes(rnd, 8);
    Des d;
    check("Des::setkey, zero key or random key", [&](int cls) {
      for (int i = 0; i < 20; i++) d.setkey(cls ? rnd : zero);
    }, 2000 * scale);
    d.setkey(rnd);
    std::vector<uint8_t> zdata(256, 0), rdata(256);
    random_bytes(rdata.data(), 256);
    std::vector<uint8_t> work(256);
    check("Des::layer, zero data or random data", [&](int cls) {
      for (int i = 0; i < 10; i++) {
        memcpy(work.data(), cls ? rdata.data() : zdata.data(), 256);
        d.layer(work.data(), true);
      }
      sink = work[0];
    }, 2000 * scale);
  }

  // HMAC-SHA-512: zero or random message, zero or random key.
  {
    uint8_t zkey[64] = {}, rkey[64], out[64];
    random_bytes(rkey, 64);
    std::vector<uint8_t> zmsg(512, 0), rmsg(512);
    random_bytes(rmsg.data(), 512);
    check("Hmac512, zero or random message", [&](int cls) {
      for (int i = 0; i < 20; i++) Hmac512(rkey, 64).mac(cls ? rmsg.data() : zmsg.data(), 512, out);
      sink = out[0];
    }, 2000 * scale);
    check("Hmac512, zero key or random key", [&](int cls) {
      for (int i = 0; i < 20; i++) Hmac512(cls ? rkey : zkey, 64).mac(rmsg.data(), 512, out);
      sink = out[0];
    }, 2000 * scale);
  }

  // Unseal of a container whose tag is wrong in the first or in the last byte: the time to the
  // error must not say where the tags differ (key file mode, no Argon2id).
  {
    KeyInput in;
    in.usephrase = false;
    for (int n = 0; n < NL; n++) random_bytes(in.key[n], 8);
    Buf sealed(300);
    random_bytes(sealed.data(), sealed.size());
    seal(sealed, in, DEFAULT_KDF);
    Buf first = sealed, last = sealed;
    first[first.size() - TAG_LEN] ^= 0x55;
    last[last.size() - 1] ^= 0x55;
    intptr_t saved = silence_stderr();  // errorexit reports to stderr
    check("unseal, tag wrong in first or last byte", [&](int cls) {
      for (int i = 0; i < 5; i++) {
        Buf d = cls ? last : first;
        try { unseal(d, in); } catch (const ExitError &) {}
      }
    }, 1500 * scale);
    restore_stderr(saved);
  }

  if (failures) { printf("FAIL: %d timing tests\n", failures); return 1; }
  puts("ok: no timing difference found between the input classes");
  return 0;
}
