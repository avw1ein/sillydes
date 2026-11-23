// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// The platform layer: everything that needs an operating system. It is implemented once per OS
// (platform_posix.cpp today), and no other file of the program includes an OS header. The rest of
// the program sees text as UTF-8 and data as bytes; converting at the edge is the job of this layer
// (see STRUCTURE.md, sections 2 and 11).
//
// Also part of the layer, but declared in common.h because the containers need them: secure_alloc,
// secure_free, locked_alloc and locked_free.

#pragma once

#include "common.h"

// Zeroises memory in a way the compiler will not remove (wipe() calls this).
void secure_zero(void *p, size_t n);

// Fills p with n bytes from the system random generator; false if it fails.
bool os_random(uint8_t *p, size_t n);

// Files. Data is bytes: nothing is translated, on any OS. Names are UTF-8.
typedef intptr_t FileHandle;
static const FileHandle NO_FILE = -1;
static const uint64_t UNKNOWN_SIZE = UINT64_MAX;
// Opens for reading. NO_FILE if that is not possible or the name is a directory. *size is the size
// of a regular file and UNKNOWN_SIZE for anything else (a pipe, a device).
FileHandle open_input(const std::string &name, uint64_t *size);
// Reads at most n bytes: the number read, 0 at the end of the file, -1 if it fails.
int64_t read_input(FileHandle f, uint8_t *p, size_t n);
// Creates the file or truncates it; readable by its owner only where the OS has such a thing.
// Refuses a symbolic link as the last part of the name. NO_FILE if that is not possible.
FileHandle open_output(const std::string &name);
// Writes all n bytes; false if that is not possible.
bool write_output(FileHandle f, const uint8_t *p, size_t n);
// Closes the file; false if that reports an error (it matters for a file that was written).
bool close_file(FileHandle f);
// True if both names exist and are one file (also through links and different spellings).
bool same_file(const std::string &a, const std::string &b);

// The memory the process could still use, in bytes, with its own limits taken into account;
// UINT64_MAX if the OS does not tell.
uint64_t available_memory();

// Disables core dumps and the attaching of debuggers by other processes of the same user, as far
// as the OS lets a program do that, and switches the CPU to data-independent timing where it has
// such a mode (arm64 DIT). Best effort, never fatal.
void harden_process();
// Ends the process with this exit code without running the exit handlers, the destructors of
// static objects or any other code of the C library. Call it last, after scrub_stack: the vector
// registers can still hold plaintext (glibc's memmove copies through them), and code that runs
// after the scrub may save them on the stack, for example the dynamic linker when it resolves a
// symbol of a library that is bound lazily. Nothing here is flushed: the program writes no stdio.
[[noreturn]] void exit_process(int code);
#ifdef SILLYDES_RESIDUE_SCAN
// Test builds only (the CMake target sillydes_scan): exit_process calls this first, so that
// test/residue_core.cpp can search the memory the program leaves behind.
void residue_scan_at_exit();
#endif
// Locks the pages of [p, p + n) in RAM; false (and nothing locked) if the limit does not allow it.
bool lock_memory(void *p, size_t n);
// A zero-filled mapping of n bytes that the OS keeps out of swap, hibernation images and its own
// view of memory, for a very large secret; release it with secure_free(p, n). Null if the OS has no
// such thing (Linux 5.14 and later: memfd_secret) or the lock limit of the process does not allow n
// bytes. Nothing is thrown and nothing is partly mapped.
void *secret_map(size_t n);
// True if the environment says that a secret that cannot be locked in RAM is an error
// (SILLYDES_REQUIRE_LOCK=1).
bool lock_required();
// True if the environment selects Argon2i for encryption in phrase mode (SILLYDES_ARGON2I=1).
bool argon2i_requested();
// Faults in and locks a window of stack below the caller, so that keys, key schedules and hash
// intermediates held in local variables cannot be swapped out. Call once, early in main; best effort.
void lock_stack();
// Wipes the stack window below the caller. Call it from main once everything has returned: the
// compiler may leave plaintext or key bytes in spilled registers and temporaries of functions that
// have returned, and which ones differs from compiler to compiler.
void scrub_stack();

// Messages for the user. The text is UTF-8; the program's own messages are ASCII.
enum MessageStream { MSG_OUT, MSG_ERR };
void write_message(MessageStream stream, const std::string &text);

// True if standard input is a terminal (a person types the phrase), false for a pipe or a file.
bool stdin_is_terminal();
// Writes the prompt to the error stream and reads one line from standard input, without echo on a
// terminal. The bytes are returned as they came, without the LF: they are checked and normalised by
// canonical_phrase, which also removes a CR. False at the end of input before any byte.
bool read_secret_line(const char *prompt, SecretBuf &line);

#ifdef _WIN32
#include <vector>
// Windows only: the arguments of wmain as UTF-8. False if one is not valid UTF-16 (an unpaired surrogate).
bool utf8_args(int argc, wchar_t **argv, std::vector<std::string> &out);
#endif
