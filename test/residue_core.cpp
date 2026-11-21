// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// The residue scanner of test_e2e, for every OS. When the program has finished, it searches its own
// writable memory (heap, stack, mappings) for the byte strings in SCAN_MARKS and reports how many
// copies are left:
//
//   RESIDUE-SCAN: <n> hit(s)
//
// With SCAN_VERBOSE set it also prints, for every hit, the number of the mark, the mapping it is in
// and the bytes around it; SCAN_VERBOSE=2 adds a hex dump of 320 bytes on either side.
//
// The marks are comma separated hexadecimal strings with every byte XORed with 0x5a. The environment
// is part of the scanned memory, so a plain mark in it would find itself. With SCAN_CONTROL set the
// scanner keeps a plain copy of the first mark on the heap, which it must then find (a control that the
// search itself works).
//
// Two ways to run it. Linux: residue_scan.cpp makes a library for LD_PRELOAD that calls
// residue_scan_at_exit when the real binary ends. Every OS: the scan binary (CMake target
// sillydes_scan) is the program built with SILLYDES_RESIDUE_SCAN, which makes exit_process call
// residue_scan_at_exit, at the very place the program would end, after scrub_stack. The memory is
// listed per OS (Regions below); everything else is the same code.
//
// This runs after main has returned, on the stack the program has just left. Two things keep it from
// disturbing what it measures: scan() first moves its own frames 96 KiB down, below the part of the
// dead stack that matters (the program wipes 256 KiB), and the bytes around a hit are copied into
// a buffer before anything is printed, because printing overwrites the stack too. The scanner's own
// frames sit in the memory it scans, so anything it leaves there can look like residue of the program;
// hits in the zone of its own frames are therefore not counted (SCANNER-OWN line with SCAN_VERBOSE).
// The preloaded program stays the one thing that is measured: a leak injected into main's frames
// (a 400-byte and a 30 KB stack array left unwiped) is still found, and scrub_stack removes it.

#if defined(_WIN32) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS  // sscanf and getenv are fine here
#endif

#include "residue_core.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <malloc.h>
#include <windows.h>
#define SCAN_ALLOCA _alloca
#elif defined(__APPLE__)
#include <alloca.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#define SCAN_ALLOCA alloca
#else
#include <alloca.h>
#define SCAN_ALLOCA alloca
#endif

namespace {

unsigned char marks[16][128];
unsigned char snap[768];  // the bytes around a hit, copied before anything is printed (printing overwrites the stack)
size_t snaplen;
const unsigned char *snapfrom;
size_t marklen[16];
int nmarks;
bool verbose;
bool hexdump;
bool scanned;
bool parsed;
unsigned char *volatile control_copy;  // the plain first mark, for SCAN_CONTROL (volatile: the compiler must not drop a store nobody reads)

// The writable memory of this process, one region after another.
class Regions {
 public:
  Regions();
  ~Regions();
  // The next region that can be read and written; desc names it for the verbose output.
  bool next(uintptr_t *lo, uintptr_t *hi, char *desc, size_t desc_len);

 private:
#if defined(_WIN32) || defined(__APPLE__)
  uintptr_t at;
#else
  FILE *maps;
#endif
};

#if defined(_WIN32)

Regions::Regions() : at(0) {}
Regions::~Regions() {}

bool Regions::next(uintptr_t *lo, uintptr_t *hi, char *desc, size_t desc_len)
{
  MEMORY_BASIC_INFORMATION mbi;
  while (VirtualQuery((const void *)at, &mbi, sizeof mbi) == sizeof mbi) {
    const uintptr_t base = (uintptr_t)mbi.BaseAddress, end = base + mbi.RegionSize;
    at = end;
    const DWORD writable = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (mbi.State == MEM_COMMIT && mbi.Type != MEM_MAPPED && (mbi.Protect & writable) && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
      *lo = base;
      *hi = end;
      snprintf(desc, desc_len, "%p-%p type %lx protect %lx", (void *)base, (void *)end, (unsigned long)mbi.Type, (unsigned long)mbi.Protect);
      return true;
    }
    if (end <= base) break;
  }
  return false;
}

#elif defined(__APPLE__)

Regions::Regions() : at(0) {}
Regions::~Regions() {}

bool Regions::next(uintptr_t *lo, uintptr_t *hi, char *desc, size_t desc_len)
{
  for (;;) {
    mach_vm_address_t addr = at;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    if (mach_vm_region(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object) != KERN_SUCCESS)
      return false;
    at = (uintptr_t)(addr + size);
    if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)) {
      *lo = (uintptr_t)addr;
      *hi = (uintptr_t)(addr + size);
      snprintf(desc, desc_len, "%p-%p protection %x max %x", (void *)*lo, (void *)*hi, (unsigned)info.protection, (unsigned)info.max_protection);
      return true;
    }
  }
}

#else

Regions::Regions() : maps(fopen("/proc/self/maps", "r")) {}
Regions::~Regions()
{
  if (maps) fclose(maps);
}

bool Regions::next(uintptr_t *lo, uintptr_t *hi, char *desc, size_t desc_len)
{
  if (!maps) return false;
  char line[512];
  while (fgets(line, sizeof line, maps)) {
    unsigned long a, b;
    char perm[8];
    if (sscanf(line, "%lx-%lx %7s", &a, &b, perm) != 3 || perm[0] != 'r' || perm[1] != 'w') continue;
    if (strstr(line, "[vvar]") || strstr(line, "[vsyscall]")) continue;
    line[strcspn(line, "\n")] = 0;
    *lo = a;
    *hi = b;
    snprintf(desc, desc_len, "%s", line);
    return true;
  }
  return false;
}

#endif

// A plain search, so that what the scanner does with a mark (and where it keeps it) is visible here and
// not hidden in a library function. Hits in this scanner's own frames were what failed CI before; whether
// the library's memmem was the one holding a copy of the 33-byte mark was never established.
const unsigned char *find(const unsigned char *p, const unsigned char *end, const unsigned char *needle, size_t n)
{
  if (n == 0 || (size_t)(end - p) < n) return nullptr;
  for (const unsigned char *last = end - n; p <= last; p++)
    if (*p == needle[0] && memcmp(p, needle, n) == 0) return p;
  return nullptr;
}

void parse_marks()
{
  if (parsed) return;
  parsed = true;
  const char *v = getenv("SCAN_VERBOSE");
  verbose = v != nullptr;
  hexdump = v && *v == '2';
  const char *env = getenv("SCAN_MARKS");
  if (!env) return;
  const char *p = env;
  while (*p && nmarks < 16) {
    size_t n = 0;
    unsigned x;
    while (n < sizeof marks[0] && sscanf(p, "%2x", &x) == 1) {
      marks[nmarks][n++] = (unsigned char)(x ^ 0x5a);
      p += 2;
    }
    marklen[nmarks++] = n;
    if (*p == ',') p++;
  }
  if (nmarks > 0 && getenv("SCAN_CONTROL")) {
    control_copy = (unsigned char *)malloc(marklen[0]);
    if (control_copy) memcpy(control_copy, marks[0], marklen[0]);
  }
}

// Reads the marks when the program starts, so that the scan at its end has nothing left to prepare.
struct Startup {
  Startup() { parse_marks(); }
} startup;

}  // namespace

bool residue_scan_enabled()
{
  parse_marks();
  return nmarks > 0;
}

void residue_scan_at_exit()
{
  if (scanned || !residue_scan_enabled()) return;
  scanned = true;
  // The dead frames of the program sit just below main's. Put this function's own frames far below
  // them (still inside the window the program wipes), or they would overwrite what is looked for.
  volatile char *gap = (volatile char *)SCAN_ALLOCA(96 * 1024);
  gap[0] = 0;
  // This function and what it calls run just below the gap. Hits in that zone are its own data, not
  // the program's: on CI they sat exactly there, 260 bytes apart, however the program was built, and
  // the program itself never reaches below 40 KiB. They are counted apart and shown, never hidden.
  const unsigned char *own_lo = (const unsigned char *)gap - 16 * 1024, *own_hi = (const unsigned char *)gap + 64;
  int own = 0;
  Regions regions;
  char line[512];
  int hits = 0;
  uintptr_t lo, hi;
  while (regions.next(&lo, &hi, line, sizeof line)) {
    for (int k = 0; k < nmarks; k++) {
      const unsigned char *p = (const unsigned char *)lo, *end = (const unsigned char *)hi;
      while (p < end) {
        const unsigned char *q = find(p, end, marks[k], marklen[k]);
        if (!q) break;
        if (q >= own_lo && q < own_hi) {
          own++;
        } else if ((q < &marks[0][0] || q >= &marks[0][0] + sizeof marks) && (q < snap || q >= snap + sizeof snap)) {  // our own copies do not count
          hits++;
          if (hexdump) {
            snapfrom = q - 320 < (const unsigned char *)lo ? (const unsigned char *)lo : q - 320;
            const unsigned char *to = q + marklen[k] + 320 > end ? end : q + marklen[k] + 320;
            snaplen = (size_t)(to - snapfrom) < sizeof snap ? (size_t)(to - snapfrom) : sizeof snap;
            memcpy(snap, snapfrom, snaplen);
          }
          if (verbose) {
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
  if (verbose && own) fprintf(stderr, "SCANNER-OWN: %d hit(s) in the scanner's own frames, not counted\n", own);
  fprintf(stderr, "RESIDUE-SCAN: %d hit(s)\n", hits);
}
