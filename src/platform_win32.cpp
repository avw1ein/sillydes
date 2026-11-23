// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// The platform layer for Windows (MSVC and MinGW-w64). See platform.h. Only the W functions are
// used, never the ANSI or OEM code page, and no CRT file descriptor touches data: there is no text
// mode, so a file is read and written as the bytes it is. Names, arguments and the phrase are UTF-8
// inside the program (STRUCTURE.md section 11).
//
// Memory hygiene is best effort and silent (STRUCTURE.md section 12): the pages that hold secrets are
// locked with VirtualLock, after the working set has been raised far enough for that (the limit of
// VirtualLock is the minimum working set), and they are registered with WerRegisterExcludedMemoryBlock,
// so that a Windows Error Reporting dump of a crash leaves them out.

#include "platform.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <aclapi.h>
#include <bcrypt.h>
#include <malloc.h>

#include <cstring>

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

// Room in the working set for what is about to be locked, and 256 KiB over: VirtualLock may lock the
// size of the minimum working set less a small overhead. Raising the minimum needs no privilege
// (a user may do it, within the memory the machine has free); it commits nothing.
bool grow_working_set(size_t n)
{
  HANDLE self = GetCurrentProcess();
  SIZE_T lo = 0, hi = 0;
  if (!GetProcessWorkingSetSize(self, &lo, &hi)) return false;
  const SIZE_T add = n + 256 * 1024;
  return SetProcessWorkingSetSize(self, lo + add, hi + add) != 0;
}

// VirtualLock; false (and nothing locked) if the working set cannot be made large enough.
bool lock_pages(void *p, size_t n)
{
  if (VirtualLock(p, n)) return true;
  if (GetLastError() == ERROR_WORKING_SET_QUOTA && grow_working_set(n) && VirtualLock(p, n)) return true;
  VirtualUnlock(p, n);
  return false;
}

// Keeps a block out of the crash dump of Windows Error Reporting (Windows 10 1703 and later; the
// function is looked up, so that an older system just goes without). At most 512 blocks can be
// registered, and a failure is of no concern.
void dump_exclusion(const void *p, size_t n, bool on)
{
  typedef HRESULT(WINAPI * Register)(const void *, DWORD);
  typedef HRESULT(WINAPI * Unregister)(const void *);
  static Register reg;
  static Unregister unreg;
  static bool looked_up;
  if (!looked_up) {
    looked_up = true;
    if (HMODULE k = GetModuleHandleW(L"kernel32.dll")) {
      // memcpy: neither compiler likes a cast between a function pointer and another type.
      FARPROC a = GetProcAddress(k, "WerRegisterExcludedMemoryBlock"), b = GetProcAddress(k, "WerUnregisterExcludedMemoryBlock");
      memcpy(&reg, &a, sizeof reg);
      memcpy(&unreg, &b, sizeof unreg);
    }
  }
  if (on && reg && n <= 0xffffffffu) reg(p, (DWORD)n);
  if (!on && unreg) unreg(p);
}

void *map_pages(size_t n)
{
  void *p = VirtualAlloc(nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!p) throw std::bad_alloc();
  dump_exclusion(p, n, true);
  return p;
}

void unmap_pages(void *p)
{
  dump_exclusion(p, 0, false);
  VirtualFree(p, 0, MEM_RELEASE);
}

// The stack window that lock_stack locks and scrub_stack wipes: 256 KiB, less if the stack is small.
size_t stack_window()
{
  // The stack is one reserved region; its base is the lowest address the stack can grow to.
  volatile char here = 0;
  uintptr_t top = (uintptr_t)&here, low = 0;
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQuery((const void *)top, &mbi, sizeof mbi) != 0) low = (uintptr_t)mbi.AllocationBase;
  size_t room = top > low ? (size_t)(top - low) : 0;
  size_t window = room / 4 < 256 * 1024 ? room / 4 : 256 * 1024;
  return window / 4096 * 4096;
}

// Faults in `window` bytes of stack below this frame, then locks them together with the page that
// holds this frame; the caller's frame, which holds the long-lived secrets, is above it.
SILLYDES_NOINLINE bool lock_stack_window(size_t window, size_t page)
{
  volatile uint8_t *low = (volatile uint8_t *)_alloca(window);
  for (size_t off = window; off >= page; off -= page) low[off - 1] = 0;  // top down: the stack grows downwards
  low[0] = 0;
  volatile char here = 0;
  uintptr_t lo = ((uintptr_t)low + page - 1) & ~(uintptr_t)(page - 1);
  uintptr_t hi = ((uintptr_t)&here | (page - 1)) + 1;
  if (!lock_pages((void *)lo, hi - lo)) return false;
  dump_exclusion((void *)lo, hi - lo, true);
  return true;
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
  uint64_t avail = ms.ullAvailPhys < ms.ullAvailPageFile ? ms.ullAvailPhys : ms.ullAvailPageFile;
  // The limit of a job object this process is in (what RLIMIT_AS is on POSIX).
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION job;
  if (QueryInformationJobObject(nullptr, JobObjectExtendedLimitInformation, &job, sizeof job, nullptr) &&
      (job.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_PROCESS_MEMORY) && job.ProcessMemoryLimit < avail)
    avail = job.ProcessMemoryLimit;
  return avail;
}

namespace {

// The policies of SetProcessMitigationPolicy that this program sets (PROCESS_MITIGATION_POLICY in
// winnt.h). Each one takes a single DWORD of flags, so the structures are not needed, and the
// function is looked up: it exists from Windows 8, and the later policies need a later Windows 10.
const int POLICY_DYNAMIC_CODE = 2;     // bit 0: ProhibitDynamicCode
const int POLICY_EXTENSION_POINT = 6;  // bit 0: DisableExtensionPoints
const int POLICY_IMAGE_LOAD = 10;      // bit 0: NoRemoteImages, bit 2: PreferSystem32Images
const int POLICY_CHILD_PROCESS = 13;   // bit 0: NoChildProcessCreation

void set_policy(int policy, DWORD flags)
{
  typedef BOOL(WINAPI * SetPolicy)(int, PVOID, SIZE_T);
  FARPROC f = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetProcessMitigationPolicy");
  SetPolicy set = nullptr;
  memcpy(&set, &f, sizeof set);  // neither compiler likes a cast between a function pointer and another type
  if (set) set(policy, &flags, sizeof flags);
}

// Another process of the same user can read this one's memory (a debugger, a dump tool) because the
// default access control list of a process allows its owner everything. Replace it by one that gives
// the owner only what ending the process and asking about it needs. An administrator or a process with
// SeDebugPrivilege still gets in: this keeps out the programs of the same user, nothing more.
void restrict_process_access()
{
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return;
  alignas(8) BYTE user[256];  // a TOKEN_USER and its SID (at most 68 bytes)
  DWORD got = 0;
  if (GetTokenInformation(token, TokenUser, user, sizeof user, &got)) {
    alignas(8) BYTE acl_space[128];  // an ACL of one entry with that SID
    PACL acl = (PACL)acl_space;
    if (InitializeAcl(acl, sizeof acl_space, ACL_REVISION) &&
        AddAccessAllowedAce(acl, ACL_REVISION, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE, ((TOKEN_USER *)user)->User.Sid))
      SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr,
                      acl, nullptr);
  }
  CloseHandle(token);
}

}  // namespace

void harden_process()
{
  // No dialog boxes: a crash ends the process instead of waiting for a person.
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
  restrict_process_access();
  // No code generated at run time, no extension points (AppInit DLLs, global hooks, legacy IMEs), no
  // images from network shares, no child process. The program needs none of them, and each is a way
  // to get code into it. The strict handle check (an exception for an invalid handle) is left out on
  // purpose: a single-threaded program that closes every handle once gains little, and a crash is
  // worse than a failed call.
  set_policy(POLICY_DYNAMIC_CODE, 1);
  set_policy(POLICY_EXTENSION_POINT, 1);
  set_policy(POLICY_IMAGE_LOAD, 1 | 4);
  set_policy(POLICY_CHILD_PROCESS, 1);
}

void exit_process(int code)
{
#ifdef SILLYDES_RESIDUE_SCAN
  residue_scan_at_exit();
#endif
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
    unmap_pages(p);
  } else {
    wipe(p, n);
    free(p);
  }
}

void *locked_alloc(size_t n)
{
  size_t len = round_up(n ? n : 1, page_size());
  void *p = map_pages(len);
  lock_pages(p, len);  // best effort: if the machine has no room, the block stays unlocked, but is still wiped
  return p;
}

void locked_free(void *p, size_t n) noexcept
{
  if (!p) return;
  size_t len = round_up(n ? n : 1, page_size());
  wipe(p, len);
  VirtualUnlock(p, len);
  unmap_pages(p);
}

bool lock_memory(void *p, size_t n)
{
  size_t page = page_size();
  uintptr_t lo = (uintptr_t)p & ~(uintptr_t)(page - 1);
  uintptr_t hi = round_up((uintptr_t)p + n, page);
  return lock_pages((void *)lo, hi - lo);
}

void *secret_map(size_t)
{
  return nullptr;  // Windows has nothing like memfd_secret
}

bool lock_required()
{
  wchar_t v[2] = {};
  return GetEnvironmentVariableW(L"SILLYDES_REQUIRE_LOCK", v, 2) == 1 && v[0] == L'1';
}

bool argon2i_requested()
{
  wchar_t v[2] = {};
  return GetEnvironmentVariableW(L"SILLYDES_ARGON2I", v, 2) == 1 && v[0] == L'1';
}

void lock_stack()
{
  size_t page = page_size();
  for (size_t w = stack_window(); w >= 4 * page; w = w / 2 / page * page)
    if (lock_stack_window(w, page)) return;
}

void scrub_stack()
{
  size_t window = stack_window();
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
// copy of the phrase, and the bytes are what the writer sent (README section 7: a pipe carries UTF-8).
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
    if (in == INVALID_HANDLE_VALUE || in == nullptr || !ReadFile(in, &c, 1, &got, nullptr) || got == 0) { eof = true; break; }
    if (c == '\n') break;
    s.push_back(c);
  }
  wipe(&c, sizeof c);
  return !(eof && s.empty());
}
