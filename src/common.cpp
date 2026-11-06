// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "common.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

std::string errarg;

[[noreturn]] void errorexit(int numer)
{
  const char *a = errarg.c_str();
  switch (numer) {
    case 1:  fprintf(stderr, "ERROR#1: Can't read from: %s\n", a); break;
    case 2:  fprintf(stderr, "ERROR#2: Can't write to: %s\n", a); break;
    case 3:  fputs("ERROR#3: Wrong number of parameters.\nType odette for help.\n", stderr); break;
    case 4:  fprintf(stderr, "ERROR#4: Invalid option: %s\nType odette for help.\n", a); break;
    case 5:  fprintf(stderr, "ERROR#5: Faulty keyfile: %s\n", a); break;
    case 6:  fputs("ERROR#6: Inputfile and outputfile must differ.\nType odette for help.\n", stderr); break;
    case 7:  fputs("ERROR#7: Not enough memory (phrase mode needs 2 GiB free).\n", stderr); break;
    case 8:  fprintf(stderr, "ERROR#8: Can't find begin of code in: %s\n", a); break;
    case 9:  fprintf(stderr, "ERROR#9: Duplicate argument on commandline: %s\nType odette for help.\n", a); break;
    case 10: fprintf(stderr, "ERROR#10: Argument missing: %s\nType odette for help.\n", a); break;
    case 11: fprintf(stderr, "ERROR#11: Can't find end of code in: %s\n", a); break;
    case 12: fprintf(stderr, "ERROR#12: CRC error in: %s\n", a); break;
    case 13: fputs("ERROR#13: Authentication failed (wrong key, or data damaged or not Odette 5.1.0).\n", stderr); break;
    case 14: fputs("ERROR#14: System random generator failed.\n", stderr); break;
    default: break;
  }
  exit(numer);
}

// Unbuffered, so no stdio copy of the data exists; a regular file is read straight into a
// buffer of its size, anything else grows by doubling with the old storage wiped.
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
      reserve_wiped(data, data.size() < 65536 ? 65536 : 2 * data.size());
      data.resize(data.capacity());
    }
    ssize_t k = read(fd, data.data() + n, data.size() - n);
    if (k < 0) {
      if (errno == EINTR) continue;
      wipe(data.data(), n);
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

void reserve_wiped(Buf &b, size_t cap)
{
  if (cap <= b.capacity()) return;
  Buf next;
  next.reserve(cap);
  next.assign(b.begin(), b.end());
  wipe(b.data(), b.size());
  b.swap(next);
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
