// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// LD_PRELOAD helper for test.sh. When the program has finished, it searches its own writable memory
// (heap, stack, mappings) for the byte strings in SCAN_MARKS and reports how many copies are left:
//
//   RESIDUE-SCAN: <n> hit(s)
//
// With SCAN_VERBOSE set it also prints, for every hit, the number of the mark, the mapping it is in
// and the bytes around it.
//
// The marks are comma separated hexadecimal strings with every byte XORed with 0x5a. The environment
// is part of the scanned memory, so a plain mark in it would find itself.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

unsigned char marks[16][128];
size_t marklen[16];
int nmarks;
bool verbose;

void scan()
{
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
        const unsigned char *q = (const unsigned char *)memmem(p, (size_t)(end - p), marks[k], marklen[k]);
        if (!q) break;
        if (q < &marks[0][0] || q >= &marks[0][0] + sizeof marks) {  // our own copy does not count
          hits++;
          if (verbose) {
            fprintf(stderr, "\nRESIDUE mark#%d at %p in %s  context: ", k, (const void *)q, line);
            for (const unsigned char *c = q < (const unsigned char *)lo + 32 ? (const unsigned char *)lo : q - 32;
                 c < q + marklen[k] + 32 && c < end; c++)
              fputc(*c >= 32 && *c < 127 ? *c : '.', stderr);
            fputc('\n', stderr);
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
  verbose = getenv("SCAN_VERBOSE") != nullptr;
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
