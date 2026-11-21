// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// LD_PRELOAD helper for test.sh. When the program has finished, it searches its own writable memory
// (heap, stack, mappings) for the byte strings in SCAN_MARKS and reports how many copies are left:
//
//   RESIDUE-SCAN: <n> hit(s)
//
// With SCAN_VERBOSE set it also prints, for every hit, the number of the mark, the mapping it is in
// and the bytes around it; SCAN_VERBOSE=2 adds a hex dump of 320 bytes on either side.
//
// The marks are comma separated hexadecimal strings with every byte XORed with 0x5a. The environment
// is part of the scanned memory, so a plain mark in it would find itself.
//
// This runs after main has returned, on the stack the program has just left. Two things keep it from
// disturbing what it measures: scan() first moves its own frames 96 KiB down, below the part of the
// dead stack that matters (the program wipes 256 KiB), and the bytes around a hit are copied into
// a buffer before anything is printed, because printing overwrites the stack too. The scanner's own
// frames sit in the memory it scans, so anything it leaves there can look like residue of the program.
// The preloaded program stays the one thing that is measured: a leak injected into main's frames
// (a 400-byte and a 30 KB stack array left unwiped) is still found, and scrub_stack removes it.

#include <alloca.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

unsigned char marks[16][128];
unsigned char snap[768];  // the bytes around a hit, copied before anything is printed (printing overwrites the stack)
size_t snaplen;
const unsigned char *snapfrom;
size_t marklen[16];
int nmarks;
bool verbose;
bool hexdump;

// A plain search. memmem is not used: for a needle longer than 32 bytes glibc's version left working
// data on the stack that this scan then found in its own frames, which looked like residue of the
// program (the hits moved with the scanner's frames, and only the 33-byte mark ever hit).
const unsigned char *find(const unsigned char *p, const unsigned char *end, const unsigned char *needle, size_t n)
{
  if (n == 0 || (size_t)(end - p) < n) return nullptr;
  for (const unsigned char *last = end - n; p <= last; p++)
    if (*p == needle[0] && memcmp(p, needle, n) == 0) return p;
  return nullptr;
}

void scan()
{
  // The dead frames of the program sit just below main's. Put this function's own frames far below
  // them (still inside the window the program wipes), or they would overwrite what is looked for.
  volatile char *gap = (volatile char *)alloca(96 * 1024);
  gap[0] = 0;
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps) return;
  char line[512];
  int hits = 0;
  while (fgets(line, sizeof line, maps)) {
    unsigned long lo, hi;
    char perm[8];
    if (sscanf(line, "%lx-%lx %7s", &lo, &hi, perm) != 3 || perm[0] != 'r' || perm[1] != 'w') continue;
    if (strstr(line, "[vvar]") || strstr(line, "[vsyscall]")) continue;
    for (int k = 0; k < nmarks; k++) {
      const unsigned char *p = (const unsigned char *)lo, *end = (const unsigned char *)hi;
      while (p < end) {
        const unsigned char *q = find(p, end, marks[k], marklen[k]);
        if (!q) break;
        if ((q < &marks[0][0] || q >= &marks[0][0] + sizeof marks) && (q < snap || q >= snap + sizeof snap)) {  // our own copies do not count
          hits++;
          if (hexdump) {
            snapfrom = q - 320 < (const unsigned char *)lo ? (const unsigned char *)lo : q - 320;
            const unsigned char *to = q + marklen[k] + 320 > end ? end : q + marklen[k] + 320;
            snaplen = (size_t)(to - snapfrom) < sizeof snap ? (size_t)(to - snapfrom) : sizeof snap;
            memcpy(snap, snapfrom, snaplen);
          }
          if (verbose) {
            line[strcspn(line, "\n")] = 0;
            fprintf(stderr, "\nRESIDUE mark#%d at %p in %s  context: ", k, (const void *)q, line);
            for (const unsigned char *c = q < (const unsigned char *)lo + 32 ? (const unsigned char *)lo : q - 32;
                 c < q + marklen[k] + 32 && c < end; c++)
              fputc(*c >= 32 && *c < 127 ? *c : '.', stderr);
            fputc('\n', stderr);
            if (hexdump) {
              fprintf(stderr, "SNAPSHOT of %p..%p (taken before printing); hit at offset %ld\n", (const void *)snapfrom,
                      (const void *)(snapfrom + snaplen), (long)(q - snapfrom));
              for (size_t r = 0; r < snaplen; r += 16) {
                fprintf(stderr, "HEX %p ", (const void *)(snapfrom + r));
                for (size_t i = 0; i < 16 && r + i < snaplen; i++) fprintf(stderr, "%02x ", snap[r + i]);
                fputc(' ', stderr);
                for (size_t i = 0; i < 16 && r + i < snaplen; i++) fputc(snap[r + i] >= 32 && snap[r + i] < 127 ? snap[r + i] : '.', stderr);
                fputc('\n', stderr);
              }
            }
          }
        }
        p = q + marklen[k];
      }
    }
  }
  fclose(maps);
  fprintf(stderr, "RESIDUE-SCAN: %d hit(s)\n", hits);
}

__attribute__((constructor)) void init()
{
  const char *v = getenv("SCAN_VERBOSE");
  verbose = v != nullptr;
  hexdump = v && *v == '2';
  const char *env = getenv("SCAN_MARKS");
  if (!env) return;
  const char *p = env;
  while (*p && nmarks < 16) {
    size_t n = 0;
    unsigned v;
    while (n < sizeof marks[0] && sscanf(p, "%2x", &v) == 1) {
      marks[nmarks][n++] = (unsigned char)(v ^ 0x5a);
      p += 2;
    }
    marklen[nmarks++] = n;
    if (*p == ',') p++;
  }
  atexit(scan);
}

}  // namespace
