// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include <cstddef>
#include <cstdint>
#include <new>
#include <string>
#include <vector>

#include "version.h"

static_assert(sizeof(void *) == 8, "SillyDES is for 64-bit targets only");

// For the functions whose stack frame must stay apart from their caller's (see main.cpp).
#if defined(_MSC_VER)
#define SILLYDES_NOINLINE __declspec(noinline)
#else
#define SILLYDES_NOINLINE __attribute__((noinline))
#endif

// Backing store of the allocators below, implemented by the platform layer (platform.h). Both
// wipe the whole block before it is released, so a vector that grows, shrinks or is destroyed
// never leaves a copy of its contents behind. Blocks of 64 KiB and more get their own mapping
// and are excluded from core dumps.
void *secure_alloc(size_t n);
void secure_free(void *p, size_t n) noexcept;
// For small secrets: a private mapping of whole pages, locked in RAM (best effort, limited by
// RLIMIT_MEMLOCK) and excluded from core dumps.
void *locked_alloc(size_t n);
void locked_free(void *p, size_t n) noexcept;

template <class T>
struct SecureAllocator {
  typedef T value_type;
  SecureAllocator() noexcept {}
  template <class U> SecureAllocator(const SecureAllocator<U> &) noexcept {}
  T *allocate(size_t n)
  {
    if (n > SIZE_MAX / sizeof(T)) throw std::bad_alloc();
    return static_cast<T *>(secure_alloc(n * sizeof(T)));
  }
  void deallocate(T *p, size_t n) noexcept { secure_free(p, n * sizeof(T)); }
};
template <class T, class U> bool operator==(const SecureAllocator<T> &, const SecureAllocator<U> &) { return true; }
template <class T, class U> bool operator!=(const SecureAllocator<T> &, const SecureAllocator<U> &) { return false; }

template <class T>
struct LockedAllocator {
  typedef T value_type;
  LockedAllocator() noexcept {}
  template <class U> LockedAllocator(const LockedAllocator<U> &) noexcept {}
  T *allocate(size_t n)
  {
    if (n > SIZE_MAX / sizeof(T)) throw std::bad_alloc();
    return static_cast<T *>(locked_alloc(n * sizeof(T)));
  }
  void deallocate(T *p, size_t n) noexcept { locked_free(p, n * sizeof(T)); }
};
template <class T, class U> bool operator==(const LockedAllocator<T> &, const LockedAllocator<U> &) { return true; }
template <class T, class U> bool operator!=(const LockedAllocator<T> &, const LockedAllocator<U> &) { return false; }

// Data (plaintext, ciphertext) and small secrets (phrase, derived keys). Neither is a std::string,
// whose short-string buffer lives inside the object and is not wiped when it is destroyed.
typedef std::vector<uint8_t, SecureAllocator<uint8_t>> Buf;
typedef std::vector<uint8_t, LockedAllocator<uint8_t>> SecretBuf;

// Container: MAGIC | log2(memory in KiB), passes, lanes, 0 | salt | IV | ciphertext | HMAC-SHA-512 tag.
enum { SALT_LEN = 16, IV_LEN = 256, HDR_LEN = 4 + 4 + SALT_LEN + IV_LEN, TAG_LEN = 64, NL = 8 };
struct KdfParams { uint32_t logm, t, p; };
static const KdfParams DEFAULT_KDF = { 21, 1, 4 };  // Argon2id, 2 GiB of memory per guess (RFC 9106 first recommendation)
static const uint64_t MAX_KDF_BYTES = 1ull << 31;

// Names the file or argument that the next errorexit message refers to.
extern std::string errarg;

// Thrown by errorexit and caught in main, so that every destructor between the failure and main
// runs and wipes its secrets; exit() would skip them.
struct ExitError { int code; };

// Prints the message of error `numer` to stderr.
void report_error(int numer);
// report_error, then throw ExitError.
[[noreturn]] void errorexit(int numer);

Buf readfile(const std::string &name);
void writefile(const std::string &name, const Buf &data);
// Throws ExitError{14} if the system random generator fails.
void randbytes(uint8_t *p, size_t n);
// Zeroises memory in a way the compiler will not remove.
void wipe(void *p, size_t n);

// Constant-time helpers (STRUCTURE.md section 12). value_barrier returns v, but the compiler may assume nothing
// about the result: wrapped around a mask or an accumulator it stops the optimiser from turning
// branch-free code into branches (or a loop into an early exit) on a secret.
#if defined(__GNUC__) || defined(__clang__)
static inline uint32_t value_barrier(uint32_t v)
{
  __asm__ __volatile__("" : "+r"(v));
  return v;
}
#else
static inline uint32_t value_barrier(uint32_t v)
{
  volatile uint32_t t = v;
  return t;
}
#endif

// True if the n bytes at a and at b are equal; the time does not depend on where they differ.
bool ct_equal(const uint8_t *a, const uint8_t *b, size_t n);

// Size arithmetic that cannot wrap around: the result, or std::bad_alloc (reported as error 7) if it
// does not fit in a size_t. Used wherever a size is computed from the size of a file.
inline size_t checked_add(size_t a, size_t b)
{
  if (b > SIZE_MAX - a) throw std::bad_alloc();
  return a + b;
}
inline size_t checked_mul(size_t a, size_t b)
{
  if (b != 0 && a > SIZE_MAX / b) throw std::bad_alloc();
  return a * b;
}
