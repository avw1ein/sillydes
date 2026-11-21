// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// The platform layer for Linux (and, later, other POSIX systems). See platform.h.

#include "platform.h"

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
#include <termios.h>
#include <unistd.h>

void secure_zero(void *p, size_t n)
{
  if (n) explicit_bzero(p, n);
}

bool os_random(uint8_t *p, size_t n)
{
  while (n > 0) {
    ssize_t k = getrandom(p, n, 0);
    if (k < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    p += k;
    n -= (size_t)k;
  }
  return true;
}

FileHandle open_input(const std::string &name, uint64_t *size)
{
  int fd = open(name.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return NO_FILE;
  struct stat st;
  if (fstat(fd, &st) != 0 || S_ISDIR(st.st_mode)) {
    close(fd);
    return NO_FILE;
  }
  *size = S_ISREG(st.st_mode) && st.st_size >= 0 ? (uint64_t)st.st_size : UNKNOWN_SIZE;
  return fd;
}

int64_t read_input(FileHandle f, uint8_t *p, size_t n)
{
  for (;;) {
    ssize_t k = read((int)f, p, n);
    if (k >= 0) return k;
    if (errno != EINTR) return -1;
  }
}

FileHandle open_output(const std::string &name)
{
  int fd = open(name.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
  return fd < 0 ? NO_FILE : fd;
}

bool write_output(FileHandle f, const uint8_t *p, size_t n)
{
  for (size_t off = 0; off < n;) {
    ssize_t k = write((int)f, p + off, n - off);
    if (k < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    off += (size_t)k;
  }
  return true;
}

bool close_file(FileHandle f)
{
  return close((int)f) == 0;
}

bool same_file(const std::string &a, const std::string &b)
{
  struct stat s1, s2;
  return stat(a.c_str(), &s1) == 0 && stat(b.c_str(), &s2) == 0 && s1.st_dev == s2.st_dev && s1.st_ino == s2.st_ino;
}

uint64_t available_memory()
{
  uint64_t avail = UINT64_MAX;
  if (FILE *f = fopen("/proc/meminfo", "r")) {
    char line[128];
    while (fgets(line, sizeof line, f)) {
      unsigned long long kb;
      if (sscanf(line, "MemAvailable: %llu kB", &kb) == 1) { avail = kb * 1024ull; break; }
    }
    fclose(f);
  }
  if (avail == UINT64_MAX) {
    long pages = sysconf(_SC_AVPHYS_PAGES), psize = sysconf(_SC_PAGESIZE);
    if (pages > 0 && psize > 0) avail = (uint64_t)pages * (uint64_t)psize;
  }
  struct rlimit rl;
  for (auto res : { RLIMIT_AS, RLIMIT_DATA })
    if (getrlimit(res, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur < avail) avail = rl.rlim_cur;
  return avail;
}

void harden_process()
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

// The stack window that lock_stack locks and scrub_stack wipes: 256 KiB, less under a small stack limit.
size_t stack_window(size_t page)
{
  size_t cap = 256 * 1024;
  rlimit rl;
  if (getrlimit(RLIMIT_STACK, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur / 4 < cap) cap = rl.rlim_cur / 4;
  return cap / page * page;
}

__attribute__((noinline)) void wipe_below(size_t window)
{
  wipe(alloca(window), window);
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
  size_t page = page_size();
  for (size_t w = stack_window(page); w >= 4 * page; w = w / 2 / page * page)
    if (lock_stack_window(w, page)) return;
}

void scrub_stack()
{
  size_t page = page_size();
  size_t w = stack_window(page);
  if (w >= 4 * page) wipe_below(w);
}

void write_message(MessageStream stream, const std::string &text)
{
  const int fd = stream == MSG_OUT ? STDOUT_FILENO : STDERR_FILENO;
  for (size_t off = 0; off < text.size();) {
    ssize_t k = write(fd, text.data() + off, text.size() - off);
    if (k < 0) {
      if (errno == EINTR) continue;
      return;  // nowhere to report a failure to report
    }
    off += (size_t)k;
  }
}

bool stdin_is_terminal()
{
  return isatty(STDIN_FILENO);
}

namespace {

// Puts the terminal back in its old mode however the scope is left.
struct NoEcho {
  bool on;
  termios old;
  explicit NoEcho(bool tty) : on(tty), old()
  {
    if (!on) return;
    tcgetattr(STDIN_FILENO, &old);
    termios t = old;
    t.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
  }
  ~NoEcho()
  {
    if (!on) return;
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    write_message(MSG_ERR, "\n");
  }
};

}  // namespace

// Reads with read(2) a byte at a time, so that no stdio buffer holds a copy of the phrase.
bool read_secret_line(const char *prompt, SecretBuf &s)
{
  write_message(MSG_ERR, prompt);
  NoEcho noecho(stdin_is_terminal());
  s.clear();
  s.reserve(4096);  // a page; growth beyond it is wiped by the allocator
  uint8_t c = 0;
  bool eof = false;
  for (;;) {
    ssize_t k = read(STDIN_FILENO, &c, 1);
    if (k < 0 && errno == EINTR) continue;
    if (k <= 0) { eof = true; break; }
    if (c == '\n') break;
    s.push_back(c);
  }
  wipe(&c, sizeof c);
  return !(eof && s.empty());
}
