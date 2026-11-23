// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// The platform layer for Linux and macOS. See platform.h. What differs on macOS is marked __APPLE__.

#ifdef __APPLE__
#define __STDC_WANT_LIB_EXT1__ 1  // for memset_s
#endif

#include "platform.h"

#include <alloca.h>
#include <cerrno>
#include <csetjmp>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach/mach.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#else
#include <linux/capability.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#endif

namespace {

// arm64: the data-independent timing mode (DIT, ARMv8.4) makes the CPU run the data-processing
// instructions in a time that does not depend on their operands. The program is single-threaded and
// the bit is never cleared. Without the feature the instruction is undefined, so ask first.
void enable_dit()
{
#if defined(__aarch64__)
#ifdef __APPLE__
  int has = 0;
  size_t len = sizeof has;
  if (sysctlbyname("hw.optional.arm.FEAT_DIT", &has, &len, nullptr, 0) != 0 || !has) return;
#else
  const unsigned long HWCAP_DIT_BIT = 1ul << 24;
  if (!(getauxval(AT_HWCAP) & HWCAP_DIT_BIT)) return;
#endif
  __asm__ __volatile__(".inst 0xd503415f");  // msr dit, #1; spelled as a number: older assemblers do not know the name
#endif
}

}  // namespace

void secure_zero(void *p, size_t n)
{
  if (!n) return;
#ifdef __APPLE__
  memset_s(p, n, 0, n);
#else
  explicit_bzero(p, n);
#endif
}

bool os_random(uint8_t *p, size_t n)
{
#ifdef __APPLE__
  while (n > 0) {
    size_t k = n < 256 ? n : 256;  // getentropy takes at most 256 bytes
    if (getentropy(p, k) != 0) return false;
    p += k;
    n -= k;
  }
#else
  while (n > 0) {
    ssize_t k = getrandom(p, n, 0);
    if (k < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    p += k;
    n -= (size_t)k;
  }
#endif
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
#ifdef __APPLE__
  // Free pages and the ones the system can reclaim at once.
  vm_statistics64_data_t vm;
  mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
  vm_size_t page = 0;
  if (host_statistics64(mach_host_self(), HOST_VM_INFO64, (host_info64_t)&vm, &count) == KERN_SUCCESS &&
      host_page_size(mach_host_self(), &page) == KERN_SUCCESS)
    avail = ((uint64_t)vm.free_count + vm.inactive_count + vm.purgeable_count) * page;
#else
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
#endif
  struct rlimit rl;
  for (auto res : { RLIMIT_AS, RLIMIT_DATA })
    if (getrlimit(res, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY && rl.rlim_cur < avail) avail = rl.rlim_cur;
  return avail;
}

void harden_process()
{
  enable_dit();
  const rlimit nocore = { 0, 0 };
  setrlimit(RLIMIT_CORE, &nocore);
#ifdef __APPLE__
  // No debugger can attach afterwards, and a process that is being debugged already exits (ENOTSUP).
  // Not a boundary: root can still read the process.
  ptrace(PT_DENY_ATTACH, 0, nullptr, 0);
#else
  prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
#endif
}

void exit_process(int code)
{
#ifdef SILLYDES_RESIDUE_SCAN
  residue_scan_at_exit();
#endif
  _exit(code);
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
#ifdef MADV_DONTDUMP
  madvise(p, n, MADV_DONTDUMP);
#endif
  return p;
}

#ifdef __linux__
#ifndef SYS_memfd_secret
#if defined(__x86_64__) || defined(__aarch64__) || defined(__riscv)
#define SYS_memfd_secret 447
#endif
#endif

const size_t SECRET_MIN = 1 << 20;  // a smaller secret is not worth taking pages out of the kernel's direct map

bool has_ipc_lock()
{
  __user_cap_header_struct head = { _LINUX_CAPABILITY_VERSION_3, 0 };
  __user_cap_data_struct data[2] = {};
  return syscall(SYS_capget, &head, data) == 0 && (data[CAP_IPC_LOCK / 32].effective >> (CAP_IPC_LOCK % 32) & 1);
}

// The kernel counts a secret mapping against RLIMIT_MEMLOCK like mlock, and past it the first touch of
// a page is a SIGBUS rather than an error.
bool may_lock(size_t len)
{
  rlimit rl;
  if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0 && (rl.rlim_cur == RLIM_INFINITY || rl.rlim_cur >= len)) return true;
  return has_ipc_lock();
}

sigjmp_buf bus_jump;

void on_bus(int) { siglongjmp(bus_jump, 1); }

// Touches every page of the mapping, so that a refusal by the kernel shows here instead of in the
// middle of the key derivation; false if one page was refused.
bool touch_pages(void *p, size_t len, size_t page)
{
  struct sigaction sa, old;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_bus;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGBUS, &sa, &old) != 0) return false;
  volatile bool ok = true;
  if (sigsetjmp(bus_jump, 1) == 0) {
    for (size_t off = 0; off < len; off += page) ((volatile uint8_t *)p)[off] = 0;
  } else {
    ok = false;
  }
  sigaction(SIGBUS, &old, nullptr);
  return ok;
}
#endif

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

void *secret_map(size_t n)
{
#if defined(__linux__) && defined(SYS_memfd_secret)
  if (n < SECRET_MIN) return nullptr;
  const size_t page = page_size(), len = round_up(n, page);
  if (!may_lock(len)) return nullptr;
  int fd = (int)syscall(SYS_memfd_secret, (unsigned)O_CLOEXEC);  // ENOSYS before Linux 5.14, EPERM under some seccomp filters
  if (fd < 0) return nullptr;
  void *p = MAP_FAILED;
  if (ftruncate(fd, (off_t)len) == 0) p = mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  close(fd);  // the mapping keeps the pages
  if (p == MAP_FAILED) return nullptr;
  if (!touch_pages(p, len, page)) {
    munmap(p, len);
    return nullptr;
  }
  return p;
#else
  (void)n;
  return nullptr;
#endif
}

bool lock_required()
{
  const char *v = getenv("SILLYDES_REQUIRE_LOCK");
  return v && v[0] == '1' && v[1] == '\0';
}

bool argon2i_requested()
{
  const char *v = getenv("SILLYDES_ARGON2I");
  return v && v[0] == '1' && v[1] == '\0';
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
