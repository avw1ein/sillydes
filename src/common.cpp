// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "common.h"

#include <alloca.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

std::string errarg;

void report_error(int numer)
{
  const char *a = errarg.c_str();
  switch (numer) {
    case 1:  fprintf(stderr, "ERROR#1: Can't read from: %s\n", a); break;
    case 2:  fprintf(stderr, "ERROR#2: Can't write to: %s\n", a); break;
    case 3:  fputs("ERROR#3: Wrong number of parameters.\nType sillydes for help.\n", stderr); break;
    case 4:  fprintf(stderr, "ERROR#4: Invalid option: %s\nType sillydes for help.\n", a); break;
    case 5:  fprintf(stderr, "ERROR#5: Faulty keyfile: %s\n", a); break;
    case 6:  fputs("ERROR#6: Inputfile and outputfile must differ.\nType sillydes for help.\n", stderr); break;
    case 7:  fputs("ERROR#7: Not enough memory (phrase mode needs 2 GiB free).\n", stderr); break;
    case 8:  fprintf(stderr, "ERROR#8: Can't find begin of code in: %s\n", a); break;
    case 9:  fprintf(stderr, "ERROR#9: Duplicate argument on commandline: %s\nType sillydes for help.\n", a); break;
    case 10: fprintf(stderr, "ERROR#10: Argument missing: %s\nType sillydes for help.\n", a); break;
    case 11: fprintf(stderr, "ERROR#11: Can't find end of code in: %s\n", a); break;
    case 12: fprintf(stderr, "ERROR#12: CRC error in: %s\n", a); break;
    case 13: fputs("ERROR#13: Authentication failed (wrong key, or data damaged or not in the " FORMAT_NAME " format).\n", stderr); break;
    case 14: fputs("ERROR#14: System random generator failed.\n", stderr); break;
    default: break;
  }
}

[[noreturn]] void errorexit(int numer)
{
  report_error(numer);
  throw ExitError{numer};
}

// Unbuffered, so no stdio copy of the data exists; a regular file is read straight into a
// buffer of its size, anything else grows by doubling (Buf wipes the storage it leaves behind).
Buf readfile(const std::string &name)
{
  errarg = name;
  int fd = open(name.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) errorexit(1);
  struct stat st;
  if (fstat(fd, &st) != 0 || S_ISDIR(st.st_mode)) { close(fd); errorexit(1); }
  Buf data;
  if (S_ISREG(st.st_mode) && st.st_size >= 0) data.resize((size_t)st.st_size + 1);  // +1: EOF read fits without growing
  size_t n = 0;
  for (;;) {
    if (n == data.size()) {
      data.reserve(data.size() < 65536 ? 65536 : 2 * data.size());
      data.resize(data.capacity());
    }
    ssize_t k = read(fd, data.data() + n, data.size() - n);
    if (k < 0) {
      if (errno == EINTR) continue;
      close(fd);
      errorexit(1);
    }
    if (k == 0) break;
    n += (size_t)k;
  }
  close(fd);
  data.resize(n);
  return data;
}

void writefile(const std::string &name, const Buf &data)
{
  errarg = name;
  int fd = open(name.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0) errorexit(2);
  for (size_t off = 0; off < data.size();) {
    ssize_t k = write(fd, data.data() + off, data.size() - off);
    if (k < 0) {
      if (errno == EINTR) continue;
      close(fd);
      errorexit(2);
    }
    off += (size_t)k;
  }
  if (close(fd) != 0) errorexit(2);
}

void randbytes(uint8_t *p, size_t n)
{
  while (n > 0) {
    ssize_t k = getrandom(p, n, 0);
    if (k < 0) {
      if (errno == EINTR) continue;
      errorexit(14);
    }
    p += k;
    n -= (size_t)k;
  }
}

void wipe(void *p, size_t n)
{
  if (n) explicit_bzero(p, n);
}

void lockdown()
{
  const rlimit nocore = { 0, 0 };
  setrlimit(RLIMIT_CORE, &nocore);
  prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

namespace {

const size_t MAPPED_MIN = 64 * 1024;  // from here on a block gets a mapping of its own

size_t page_size()
{
  long ps = sysconf(_SC_PAGESIZE);
  return ps > 0 ? (size_t)ps : 4096;
}

size_t round_up(size_t n, size_t unit) { return (n + unit - 1) / unit * unit; }

void *map_pages(size_t n)
{
  void *p = mmap(nullptr, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) throw std::bad_alloc();
  madvise(p, n, MADV_DONTDUMP);
  return p;
}

// Faults in `window` bytes of stack below this frame, then locks them together with the page that
// holds this frame; the caller's frame, which holds the long-lived secrets, is above it.
__attribute__((noinline)) bool lock_stack_window(size_t window, size_t page)
{
  volatile uint8_t *low = (volatile uint8_t *)alloca(window);
  for (size_t off = window; off >= page; off -= page) low[off - 1] = 0;  // top down: the stack grows downwards
  low[0] = 0;
  uintptr_t lo = ((uintptr_t)low + page - 1) & ~(uintptr_t)(page - 1);
  uintptr_t hi = ((uintptr_t)__builtin_frame_address(0) | (page - 1)) + 1;
  return mlock((void *)lo, hi - lo) == 0;
}

}  // namespace

void *secure_alloc(size_t n)
{
  if (n == 0) n = 1;
  if (n >= MAPPED_MIN) return map_pages(round_up(n, page_size()));
  void *p = malloc(n);
  if (!p) throw std::bad_alloc();
  return p;
}

void secure_free(void *p, size_t n) noexcept
{
  if (!p) return;
  if (n == 0) n = 1;
  if (n >= MAPPED_MIN) {
    size_t len = round_up(n, page_size());
    wipe(p, len);
    munmap(p, len);
  } else {
    wipe(p, n);
    free(p);
  }
}

void *locked_alloc(size_t n)
{
  size_t len = round_up(n ? n : 1, page_size());
  void *p = map_pages(len);
  mlock(p, len);  // best effort: past RLIMIT_MEMLOCK the block stays unlocked, but is still wiped and not dumped
  return p;
}

void locked_free(void *p, size_t n) noexcept
{
  if (!p) return;
  size_t len = round_up(n ? n : 1, page_size());
  wipe(p, len);
  munlock(p, len);
  munmap(p, len);
}

bool lock_memory(void *p, size_t n)
{
  size_t page = page_size();
  uintptr_t lo = (uintptr_t)p & ~(uintptr_t)(page - 1);
  uintptr_t hi = round_up((uintptr_t)p + n, page);
  if (mlock((void *)lo, hi - lo) == 0) return true;
  munlock((void *)lo, hi - lo);
  return false;
}

void lock_stack()
{
  size_t page = page_size(), cap = 256 * 1024;
  rlimit rl;
  if (getrlimit(RLIMIT_STACK, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur / 4 < cap) cap = rl.rlim_cur / 4;
  for (size_t w = cap / page * page; w >= 4 * page; w = w / 2 / page * page)
    if (lock_stack_window(w, page)) return;
}
