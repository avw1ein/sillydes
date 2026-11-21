// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// LD_PRELOAD helper for test_e2e on Linux: runs the residue scan (residue_core.cpp) when the real
// binary ends, so that the program that is measured is the one that is shipped.

#include "residue_core.h"

#include <cstdlib>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

__attribute__((constructor)) void init()
{
  if (residue_scan_enabled()) atexit(residue_scan_at_exit);
}

}  // namespace

// The program ends with _exit (platform.h, exit_process), which does not run the atexit handlers,
// so the scan runs from here as well. Nothing but the scan happens before the process is gone.
extern "C" void _exit(int status)
{
  residue_scan_at_exit();
  syscall(SYS_exit_group, status);
  for (;;) {}
}
