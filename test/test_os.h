// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// What the unit tests need from the operating system and the program does not: a name for a
// temporary file, deleting it, silencing the error stream, the memory-lock figures, what the
// hardening of the process did, and a terminal to run the program in. One implementation per OS
// (test_os_posix.cpp, test_os_win32.cpp), so that test_primitives.cpp includes no OS header.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

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

// For test_e2e.cpp. Names are UTF-8 and may be joined with '/' on every OS.

// A new empty directory in the temporary directory; empty string if that fails.
std::string make_temp_dir();
bool make_dir(const std::string &name);
// Deletes a file or a whole directory tree; no error if it is not there.
void remove_tree(const std::string &name);
bool file_exists(const std::string &name);
// The names (not the paths) in a directory, without . and ..; false if it cannot be read.
bool list_dir(const std::string &dir, std::vector<std::string> &names);
bool is_directory(const std::string &name);
// False where the OS or the account does not allow it (symbolic links on Windows need a privilege).
bool make_hard_link(const std::string &existing, const std::string &link);
bool make_symlink(const std::string &target, const std::string &link);

// Runs a program and waits for it.
struct RunOptions {
  std::string stdin_data;           // given to the program, then its standard input is closed
  std::vector<std::string> env;     // "NAME=value", added to the environment
  long address_space_limit_kb = 0;  // 0: none; honoured only where can_limit_address_space()
};
struct RunResult {
  bool started = false;  // false: the program could not be started
  int code = -1;         // exit code
  std::string out, err;  // what it wrote to standard output and standard error
};
RunResult run_program(const std::string &exe, const std::vector<std::string> &args, const RunOptions &opt = RunOptions());
// True where run_program can limit the memory of the program: the address space on Linux, the commit
// charge of a job object on Windows. macOS has no such limit that a test can set (setrlimit fails with EINVAL, measured on the runners).
bool can_limit_address_space();

// A program run with a terminal for standard input, output and error, as a person would use it: a
// pseudo-terminal on POSIX, a pseudo-console (ConPTY) on Windows.
struct TypedLine {
  std::string after;  // typed once the output of the program, from the previous line on, contains this
  std::string text;   // UTF-8; "\r" is the Enter key (Ctrl+D is "\x04" on POSIX, Ctrl+Z "\x1a" on Windows)
};
struct TerminalResult {
  bool started = false;
  bool timed_out = false;  // the program was killed after timeout_ms
  int code = -1;
  std::string output;      // what the terminal showed, escape sequences included
};
// False where the OS has no such thing (Windows before 10 1809).
bool can_run_on_terminal();
TerminalResult run_on_terminal(const std::string &exe, const std::vector<std::string> &args, const std::vector<TypedLine> &lines,
                               int timeout_ms = 90000);

// The full path of a program found through the search path of the OS, or an empty string.
std::string find_program(const std::string &name);

// What harden_process (called first) did to this process, as the OS reports it: 0 if everything it
// should have done is visible, 1 if something is missing, -1 if the OS has no way to tell. `detail`
// says what was checked or what is missing.
int check_hardening(std::string &detail);
