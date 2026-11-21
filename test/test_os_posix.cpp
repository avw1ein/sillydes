// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// test_os.h for POSIX systems.

#include "test_os.h"

#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <sys/resource.h>
#include <unistd.h>

std::string temp_file_name()
{
  char name[] = "/tmp/sillydes_test_XXXXXX";
  int fd = mkstemp(name);
  if (fd >= 0) close(fd);
  return name;
}

void remove_file(const std::string &name)
{
  unlink(name.c_str());
}

intptr_t silence_stderr()
{
  int saved = dup(STDERR_FILENO);
  int nul = open("/dev/null", O_WRONLY);
  dup2(nul, STDERR_FILENO);
  close(nul);
  return saved;
}

void restore_stderr(intptr_t saved)
{
  dup2((int)saved, STDERR_FILENO);
  close((int)saved);
}

long locked_kb()
{
  FILE *f = fopen("/proc/self/status", "r");
  long kb = -1;
  char line[128];
  while (f && fgets(line, sizeof line, f))
    if (sscanf(line, "VmLck: %ld kB", &kb) == 1) break;
  if (f) fclose(f);
  return kb;
}

long memlock_limit_kb()
{
  rlimit rl;
  if (getrlimit(RLIMIT_MEMLOCK, &rl) != 0) return 0;
  return rl.rlim_cur == RLIM_INFINITY ? 1L << 40 : (long)(rl.rlim_cur / 1024);
}
