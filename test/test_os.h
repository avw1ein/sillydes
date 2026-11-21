// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// What the unit tests need from the operating system and the program does not: a name for a
// temporary file, deleting it, silencing the error stream, and the memory-lock figures. One
// implementation per OS (test_os_posix.cpp, test_os_win32.cpp), so that test_primitives.cpp
// includes no OS header.

#pragma once

#include <cstdint>
#include <string>

// A name that does not exist yet, in the temporary directory; UTF-8.
std::string temp_file_name();
// Deletes the file; no error if it is not there.
void remove_file(const std::string &name);

// Points the error stream at the null device and returns what restore_stderr needs to undo it.
intptr_t silence_stderr();
void restore_stderr(intptr_t saved);

// The memory this process has locked in RAM, in KiB; -1 if the OS does not tell.
long locked_kb();
// How much the process may lock, in KiB; 0 if it may not lock at all.
long memlock_limit_kb();
