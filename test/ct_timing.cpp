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

// One round: `samples` timings of `run()` after `prepare(cls)`, classes in random order, the slowest 5 % dropped
// (interrupts and cache misses of the machine, not of the code). Both classes must read the same
// buffer: an input in another place is a timing difference of its own (alignment, caches), and one
// the test would report as a leak.
double round_t(const std::function<void(int)> &prepare, const std::function<void()> &run, int samples, std::mt19937 &rng)
{
  std::vector<Sample> all;
  all.reserve((size_t)samples);
  for (int i = 0; i < 50; i++) { prepare(i & 1); run(); }  // warm up
  for (int i = 0; i < samples; i++) {
    int cls = (int)(rng() & 1);
    prepare(cls);  // not timed: puts the class's input into the one buffer that run() reads
    Clock::time_point a = Clock::now();
    run();
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

void check(const char *name, const std::function<void(int)> &prepare, const std::function<void()> &run, int samples)
{
  std::mt19937 rng(12345);
  double t[3] = { 0, 0, 0 };
  bool ok = false;
  for (int r = 0; r < 3 && !ok; r++) {
    t[r] = round_t(prepare, run, samples, rng);
    ok = std::fabs(t[r]) < 10;
  }
  printf("%-46s t = %7.2f%s\n", name, t[0], ok ? "" : "   (not below 10 in every round)");
  if (!ok) failures++;
}

// The control: the test must see a leak where there is one. Detected if |t| is above 10 in the first round.
void check_detects(const char *name, const std::function<void(int)> &prepare, const std::function<void()> &run, int samples)
{
  std::mt19937 rng(54321);
  double t = round_t(prepare, run, samples, rng);
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
  uint8_t cmp_a[64], cmp_b[64], cmp_first[64], cmp_last[64];
  random_bytes(cmp_a, 64);
  memcpy(cmp_first, cmp_a, 64); cmp_first[0] ^= 0x55;
  memcpy(cmp_last, cmp_a, 64); cmp_last[63] ^= 0x55;
  auto prepare_cmp = [&](int cls) { memcpy(cmp_b, cls ? cmp_last : cmp_first, 64); };
  check("ct_equal, difference first or last byte", prepare_cmp, [&] {
    uint64_t acc = 0;
    for (int i = 0; i < 2000; i++) acc += ct_equal(cmp_a, cmp_b, 64);
    sink = acc;
  }, 3000 * scale);

  // The control: a comparison that stops at the first difference. It must be detected.
  check_detects("control: early-exit compare", prepare_cmp, [&] {
    uint64_t acc = 0;
    for (int i = 0; i < 2000; i++) {
      bool eq = true;
      for (int k = 0; k < 64; k++) {
        if (cmp_a[k] != cmp_b[k]) { eq = false; break; }
      }
      acc += eq;
    }
    sink = acc;
  }, 3000 * scale);

  // Hex decoding: 256 digits or 256 bytes that are none.
  {
    uint8_t digits[256], others[256], work[256];
    for (int i = 0; i < 256; i++) { digits[i] = (uint8_t)"0123456789abcdefABCDEF"[i % 22]; others[i] = (uint8_t)"ghijklmnopqrstuvwxyz!?"[i % 22]; }
    check("hex_digit, digits or other bytes", [&](int cls) { memcpy(work, cls ? others : digits, 256); }, [&] {
      uint32_t acc = 0;
      for (int rep = 0; rep < 8; rep++)
        for (int i = 0; i < 256; i++) acc += hex_digit(work[i]);
      sink = acc;
    }, 3000 * scale);
  }

  // DES: the key schedule of a zero key or a random key, the layer on zero data or random data.
  {
    uint8_t zero[8] = {}, rnd[8], key[8];
    random_bytes(rnd, 8);
    Des d;
    check("Des::setkey, zero key or random key", [&](int cls) { memcpy(key, cls ? rnd : zero, 8); }, [&] {
      for (int i = 0; i < 20; i++) d.setkey(key);
    }, 2000 * scale);
    d.setkey(rnd);
    std::vector<uint8_t> zdata(256, 0), rdata(256), input(256), work(256);
    random_bytes(rdata.data(), 256);
    check("Des::layer, zero data or random data", [&](int cls) { input = cls ? rdata : zdata; }, [&] {
      for (int i = 0; i < 10; i++) {
        memcpy(work.data(), input.data(), 256);
        d.layer(work.data(), true);
      }
      sink = work[0];
    }, 2000 * scale);
  }

  // HMAC-SHA-512: zero or random message, zero or random key.
  {
    uint8_t zkey[64] = {}, rkey[64], key[64], out[64];
    random_bytes(rkey, 64);
    std::vector<uint8_t> zmsg(512, 0), rmsg(512), msg(512);
    random_bytes(rmsg.data(), 512);
    memcpy(key, rkey, 64);
    check("Hmac512, zero or random message", [&](int cls) { msg = cls ? rmsg : zmsg; }, [&] {
      for (int i = 0; i < 20; i++) Hmac512(key, 64).mac(msg.data(), 512, out);
      sink = out[0];
    }, 2000 * scale);
    msg = rmsg;
    check("Hmac512, zero key or random key", [&](int cls) { memcpy(key, cls ? rkey : zkey, 64); }, [&] {
      for (int i = 0; i < 20; i++) Hmac512(key, 64).mac(msg.data(), 512, out);
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
    Buf d;
    d.reserve(sealed.size());
    intptr_t saved = silence_stderr();  // errorexit reports to stderr
    check("unseal, tag wrong in first or last byte", [&](int cls) {
      d = sealed;  // the same buffer for both classes; the capacity is already there
      d[cls ? d.size() - 1 : d.size() - TAG_LEN] ^= 0x55;
    }, [&] {
      for (int i = 0; i < 1; i++) {
        try { unseal(d, in); } catch (const ExitError &) {}
      }
    }, 4000 * scale);
    restore_stderr(saved);
  }

  if (failures) { printf("FAIL: %d timing tests\n", failures); return 1; }
  puts("ok: no timing difference found between the input classes");
  return 0;
}
