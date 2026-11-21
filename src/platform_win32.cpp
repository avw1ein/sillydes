// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// The platform layer for Windows (MSVC and MinGW-w64). See platform.h. Only the W functions are
// used, never the ANSI or OEM code page, and no CRT file descriptor touches data: there is no text
// mode, so a file is read and written as the bytes it is. Names, arguments and the phrase are UTF-8
// inside the program (PORTPLAN.md, 3.4).
//
// Not done yet, and best effort in the meantime (PORTPLAN.md, todo 4): locking the stack, raising the
// working set so that VirtualLock succeeds, keeping the secret pages out of crash dumps.

#include "platform.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <bcrypt.h>
#include <malloc.h>

namespace {

const size_t MAPPED_MIN = 64 * 1024;  // from here on a block gets pages of its own
const size_t IO_CHUNK = (size_t)1 << 30;

// UTF-8 to UTF-16; false if the text is not valid UTF-8. For names and messages, never for a secret.
bool widen(const std::string &s, std::wstring &w)
{
  w.clear();
  if (s.empty()) return true;
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), (int)s.size(), nullptr, 0);
  if (n <= 0) return false;
  w.resize((size_t)n);
  return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), (int)s.size(), &w[0], n) == n;
}

bool is_console(HANDLE h)
{
  DWORD mode;
  return h != INVALID_HANDLE_VALUE && h != nullptr && GetConsoleMode(h, &mode) != 0;
}

size_t page_size()
{
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  return si.dwPageSize ? si.dwPageSize : 4096;
}

size_t round_up(size_t n, size_t unit) { return (n + unit - 1) / unit * unit; }

void *map_pages(size_t n)
{
  void *p = VirtualAlloc(nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!p) throw std::bad_alloc();
  return p;
}

SILLYDES_NOINLINE void wipe_below(size_t window)
{
  wipe(_alloca(window), window);
}

}  // namespace

void secure_zero(void *p, size_t n)
{
  if (n) SecureZeroMemory(p, n);
}

bool os_random(uint8_t *p, size_t n)
{
  while (n > 0) {
    ULONG k = n > IO_CHUNK ? (ULONG)IO_CHUNK : (ULONG)n;
    if (BCryptGenRandom(nullptr, p, k, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return false;
    p += k;
    n -= k;
  }
  return true;
}

FileHandle open_input(const std::string &name, uint64_t *size)
{
  std::wstring w;
  if (!widen(name, w)) return NO_FILE;
  HANDLE h = CreateFileW(w.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return NO_FILE;  // a directory cannot be opened without FILE_FLAG_BACKUP_SEMANTICS
  LARGE_INTEGER sz;
  *size = GetFileType(h) == FILE_TYPE_DISK && GetFileSizeEx(h, &sz) && sz.QuadPart >= 0 ? (uint64_t)sz.QuadPart : UNKNOWN_SIZE;
  return (FileHandle)h;
}

int64_t read_input(FileHandle f, uint8_t *p, size_t n)
{
  DWORD got = 0;
  if (n > IO_CHUNK) n = IO_CHUNK;
  if (ReadFile((HANDLE)f, p, (DWORD)n, &got, nullptr)) return got;
  return GetLastError() == ERROR_BROKEN_PIPE ? 0 : -1;  // the writer of a pipe has closed it: the end of the file
}

FileHandle open_output(const std::string &name)
{
  std::wstring w;
  if (!widen(name, w)) return NO_FILE;
  // Opens a link as the link itself instead of following it, and truncates only after it has been
  // seen that the name is no link (O_NOFOLLOW | O_TRUNC on POSIX).
  HANDLE h = CreateFileW(w.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (h == INVALID_HANDLE_VALUE) return NO_FILE;
  BY_HANDLE_FILE_INFORMATION info;
  if (!GetFileInformationByHandle(h, &info) || (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
      !SetEndOfFile(h)) {
    CloseHandle(h);
    return NO_FILE;
  }
  return (FileHandle)h;
}

bool write_output(FileHandle f, const uint8_t *p, size_t n)
{
  while (n > 0) {
    DWORD k = n > IO_CHUNK ? (DWORD)IO_CHUNK : (DWORD)n, done = 0;
    if (!WriteFile((HANDLE)f, p, k, &done, nullptr) || done == 0) return false;
    p += done;
    n -= done;
  }
  return true;
}

bool close_file(FileHandle f)
{
  return CloseHandle((HANDLE)f) != 0;
}

namespace {

bool file_identity(const std::string &name, BY_HANDLE_FILE_INFORMATION &info)
{
  std::wstring w;
  if (!widen(name, w)) return false;
  HANDLE h = CreateFileW(w.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                         FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  if (h == INVALID_HANDLE_VALUE) return false;
  bool ok = GetFileInformationByHandle(h, &info) != 0;
  CloseHandle(h);
  return ok;
}

}  // namespace

bool same_file(const std::string &a, const std::string &b)
{
  BY_HANDLE_FILE_INFORMATION x, y;
  return file_identity(a, x) && file_identity(b, y) && x.dwVolumeSerialNumber == y.dwVolumeSerialNumber &&
         x.nFileIndexHigh == y.nFileIndexHigh && x.nFileIndexLow == y.nFileIndexLow;
}

uint64_t available_memory()
{
  MEMORYSTATUSEX ms;
  ms.dwLength = sizeof ms;
  if (!GlobalMemoryStatusEx(&ms)) return UINT64_MAX;
  // Physical memory that is free or can be freed at once, and what the commit limit still allows.
  return ms.ullAvailPhys < ms.ullAvailPageFile ? ms.ullAvailPhys : ms.ullAvailPageFile;
}

void harden_process()
{
  // No dialog boxes: a crash ends the process instead of waiting for a person.
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
}

void exit_process(int code)
{
  TerminateProcess(GetCurrentProcess(), (UINT)code);  // no DLL detach code, no CRT exit handlers
  ExitProcess((UINT)code);
}

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
    wipe(p, round_up(n, page_size()));
    VirtualFree(p, 0, MEM_RELEASE);
  } else {
    wipe(p, n);
    free(p);
  }
}

void *locked_alloc(size_t n)
{
  size_t len = round_up(n ? n : 1, page_size());
  void *p = map_pages(len);
  VirtualLock(p, len);  // best effort: past the working set the block stays unlocked, but is still wiped
  return p;
}

void locked_free(void *p, size_t n) noexcept
{
  if (!p) return;
  size_t len = round_up(n ? n : 1, page_size());
  wipe(p, len);
  VirtualUnlock(p, len);
  VirtualFree(p, 0, MEM_RELEASE);
}

bool lock_memory(void *p, size_t n)
{
  size_t page = page_size();
  uintptr_t lo = (uintptr_t)p & ~(uintptr_t)(page - 1);
  uintptr_t hi = round_up((uintptr_t)p + n, page);
  if (VirtualLock((void *)lo, hi - lo)) return true;
  VirtualUnlock((void *)lo, hi - lo);
  return false;
}

void lock_stack()
{
}

void scrub_stack()
{
  // The stack is one reserved region; its base is the lowest address the stack can grow to.
  volatile char here = 0;
  uintptr_t top = (uintptr_t)&here, low = 0;
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQuery((const void *)top, &mbi, sizeof mbi) != 0) low = (uintptr_t)mbi.AllocationBase;
  size_t room = top > low ? (size_t)(top - low) : 0;
  size_t window = room / 4 < 256 * 1024 ? room / 4 : 256 * 1024;
  window = window / 4096 * 4096;
  if (window >= 4 * 4096) wipe_below(window);
}

void write_message(MessageStream stream, const std::string &text)
{
  HANDLE h = GetStdHandle(stream == MSG_OUT ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
  if (h == INVALID_HANDLE_VALUE || h == nullptr) return;
  std::wstring w;
  if (is_console(h) && widen(text, w)) {
    // WriteConsoleW leaves the code page of the console alone, unlike SetConsoleOutputCP.
    for (size_t off = 0; off < w.size();) {
      DWORD done = 0;
      if (!WriteConsoleW(h, w.data() + off, (DWORD)(w.size() - off), &done, nullptr) || done == 0) return;
      off += done;
    }
    return;
  }
  write_output((FileHandle)h, (const uint8_t *)text.data(), text.size());
}

bool stdin_is_terminal()
{
  return is_console(GetStdHandle(STD_INPUT_HANDLE));
}

bool utf8_args(int argc, wchar_t **argv, std::vector<std::string> &out)
{
  out.clear();
  for (int i = 0; i < argc; i++) {
    int len = (int)wcslen(argv[i]);
    std::string s;
    if (len > 0) {
      // WC_ERR_INVALID_CHARS: an unpaired surrogate fails instead of becoming U+FFFD.
      int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i], len, nullptr, 0, nullptr, nullptr);
      if (n <= 0) return false;
      s.resize((size_t)n);
      if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i], len, &s[0], n, nullptr, nullptr) != n) return false;
    }
    out.push_back(s);
  }
  return true;
}

namespace {

typedef std::vector<wchar_t, LockedAllocator<wchar_t>> WideSecret;

// Switches the echo of the console off, and puts the mode back however the scope is left.
struct NoEcho {
  HANDLE in;
  DWORD old;
  bool on;
  explicit NoEcho(HANDLE h) : in(h), old(0), on(GetConsoleMode(h, &old) != 0)
  {
    if (on) SetConsoleMode(in, old & ~(DWORD)ENABLE_ECHO_INPUT);
  }
  ~NoEcho()
  {
    if (!on) return;
    SetConsoleMode(in, old);
    write_message(MSG_ERR, "\n");
  }
};

void append_utf8(SecretBuf &s, uint32_t c)
{
  if (c < 0x80) {
    s.push_back((uint8_t)c);
  } else if (c < 0x800) {
    s.push_back((uint8_t)(0xC0 | (c >> 6)));
    s.push_back((uint8_t)(0x80 | (c & 0x3F)));
  } else if (c < 0x10000) {
    s.push_back((uint8_t)(0xE0 | (c >> 12)));
    s.push_back((uint8_t)(0x80 | ((c >> 6) & 0x3F)));
    s.push_back((uint8_t)(0x80 | (c & 0x3F)));
  } else {
    s.push_back((uint8_t)(0xF0 | (c >> 18)));
    s.push_back((uint8_t)(0x80 | ((c >> 12) & 0x3F)));
    s.push_back((uint8_t)(0x80 | ((c >> 6) & 0x3F)));
    s.push_back((uint8_t)(0x80 | (c & 0x3F)));
  }
}

// The line of a console: UTF-16 from ReadConsoleW, kept in a locked buffer that is wiped, and turned
// into UTF-8 here, because the system converters allocate buffers of their own. An unpaired
// surrogate becomes the three bytes of its number, which canonical_phrase refuses as invalid UTF-8.
bool read_console_line(HANDLE in, SecretBuf &s)
{
  WideSecret w;
  w.reserve(4096);
  bool eof = false;
  for (;;) {
    size_t at = w.size();
    if (at + 256 > w.capacity()) w.reserve(w.capacity() * 2);  // the old block is wiped as it is freed
    w.resize(at + 256);
    DWORD got = 0;
    if (!ReadConsoleW(in, &w[at], 256, &got, nullptr) || got == 0) { eof = true; w.resize(at); break; }
    w.resize(at + got);
    if (w.back() == L'\n') { w.pop_back(); break; }
  }
  // Ctrl+Z at the start of a line is the end of the input, as Ctrl+D is on a Unix terminal.
  if (!w.empty() && w[0] == 0x1A) { eof = true; w.clear(); }
  for (size_t i = 0; i < w.size(); i++) {
    uint32_t c = w[i];
    if (c >= 0xD800 && c < 0xDC00 && i + 1 < w.size() && w[i + 1] >= 0xDC00 && w[i + 1] < 0xE000) {
      c = 0x10000 + ((c - 0xD800) << 10) + (w[i + 1] - 0xDC00);
      i++;
    }
    append_utf8(s, c);
  }
  secure_zero(w.data(), w.size() * sizeof(wchar_t));
  return !(eof && s.empty());
}

}  // namespace

// A pipe or a file is read with ReadFile a byte at a time: no CRT text mode, no buffer that holds a
// copy of the phrase, and the bytes are what the writer sent (PORTPLAN.md: a pipe carries UTF-8).
bool read_secret_line(const char *prompt, SecretBuf &s)
{
  write_message(MSG_ERR, prompt);
  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  s.clear();
  s.reserve(4096);
  if (is_console(in)) {
    NoEcho noecho(in);
    return read_console_line(in, s);
  }
  uint8_t c = 0;
  bool eof = false;
  for (;;) {
    DWORD got = 0;
    if (in == INVALID_HANDLE_VALUE || !ReadFile(in, &c, 1, &got, nullptr) || got == 0) { eof = true; break; }
    if (c == '\n') break;
    s.push_back(c);
  }
  wipe(&c, sizeof c);
  return !(eof && s.empty());
}
