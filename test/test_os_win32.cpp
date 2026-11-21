// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// test_os.h for Windows. Names are UTF-16 for the OS and UTF-8 for the tests.

#include "test_os.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <aclapi.h>
#include <psapi.h>
#include <sddl.h>

#include <cstring>
#include <thread>

namespace {

std::wstring widen(const std::string &s)
{
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
  std::wstring w((size_t)n, L'\0');
  if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
  return w;
}

std::string narrow(const std::wstring &w)
{
  int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
  std::string s((size_t)n, '\0');
  if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr);
  return s;
}

}  // namespace

std::string temp_file_name()
{
  wchar_t dir[MAX_PATH + 1], name[MAX_PATH + 1];
  if (GetTempPathW(MAX_PATH, dir) == 0 || GetTempFileNameW(dir, L"sdt", 0, name) == 0) return std::string();
  return narrow(name);
}

void remove_file(const std::string &name)
{
  DeleteFileW(widen(name).c_str());
}

intptr_t silence_stderr()
{
  HANDLE saved = GetStdHandle(STD_ERROR_HANDLE);
  HANDLE nul = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (nul != INVALID_HANDLE_VALUE) SetStdHandle(STD_ERROR_HANDLE, nul);
  return (intptr_t)saved;
}

void restore_stderr(intptr_t saved)
{
  HANDLE nul = GetStdHandle(STD_ERROR_HANDLE);
  SetStdHandle(STD_ERROR_HANDLE, (HANDLE)saved);
  if (nul != (HANDLE)saved && nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
}

// The locked pages are counted through the working set: QueryWorkingSetEx says per page whether it is locked.
long locked_kb()
{
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  const size_t page = si.dwPageSize ? si.dwPageSize : 4096;
  const HANDLE self = GetCurrentProcess();
  std::vector<PSAPI_WORKING_SET_EX_INFORMATION> batch(1024);
  size_t locked = 0;
  uintptr_t at = 0;
  MEMORY_BASIC_INFORMATION mbi;
  while (VirtualQuery((const void *)at, &mbi, sizeof mbi) == sizeof mbi) {
    const uintptr_t base = (uintptr_t)mbi.BaseAddress, end = base + mbi.RegionSize;
    at = end;
    if (end <= base) break;
    const DWORD writable = PAGE_READWRITE | PAGE_EXECUTE_READWRITE;
    if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE || !(mbi.Protect & writable) || (mbi.Protect & PAGE_GUARD)) continue;
    for (uintptr_t a = base; a < end;) {
      size_t n = (end - a) / page < batch.size() ? (end - a) / page : batch.size();
      for (size_t i = 0; i < n; i++) batch[i].VirtualAddress = (PVOID)(a + i * page);
      if (!QueryWorkingSetEx(self, batch.data(), (DWORD)(n * sizeof batch[0]))) return -1;
      for (size_t i = 0; i < n; i++)
        if (batch[i].VirtualAttributes.Valid && batch[i].VirtualAttributes.Locked) locked++;
      a += n * page;
    }
  }
  return (long)(locked * page / 1024);
}

// There is no fixed limit: the working set grows as far as the machine has memory free.
long memlock_limit_kb() { return 1L << 30; }  // 1 TiB, as far as a long of 32 bits goes

namespace {

std::wstring join_path(const std::wstring &a, const wchar_t *b) { return a + L"\\" + b; }

void read_all(HANDLE h, std::string *into)
{
  char buf[4096];
  DWORD got;
  while (ReadFile(h, buf, sizeof buf, &got, nullptr) && got > 0) into->append(buf, got);
}

// The inverse of what CommandLineToArgvW and the C runtime do with a command line.
void quote_argument(const std::wstring &a, std::wstring &out)
{
  if (!a.empty() && a.find_first_of(L" \t\n\v\"") == std::wstring::npos) { out += a; return; }
  out += L'"';
  for (size_t i = 0;; i++) {
    size_t backslashes = 0;
    while (i < a.size() && a[i] == L'\\') { i++; backslashes++; }
    if (i == a.size()) { out.append(backslashes * 2, L'\\'); break; }
    if (a[i] == L'"') out.append(backslashes * 2 + 1, L'\\');
    else out.append(backslashes, L'\\');
    out += a[i];
  }
  out += L'"';
}

}  // namespace

std::string make_temp_dir()
{
  wchar_t dir[MAX_PATH + 1];
  if (GetTempPathW(MAX_PATH, dir) == 0) return std::string();
  for (int i = 0; i < 100; i++) {
    std::wstring name = join_path(dir, (L"sillydes_e2e_" + std::to_wstring(GetCurrentProcessId()) + L"_" + std::to_wstring(GetTickCount() + (DWORD)i)).c_str());
    if (CreateDirectoryW(name.c_str(), nullptr)) return narrow(name);
  }
  return std::string();
}

bool make_dir(const std::string &name)
{
  return CreateDirectoryW(widen(name).c_str(), nullptr) != 0;
}

bool file_exists(const std::string &name)
{
  return GetFileAttributesW(widen(name).c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool is_directory(const std::string &name)
{
  DWORD a = GetFileAttributesW(widen(name).c_str());
  return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) && !(a & FILE_ATTRIBUTE_REPARSE_POINT);
}

bool list_dir(const std::string &dir, std::vector<std::string> &names)
{
  WIN32_FIND_DATAW fd;
  HANDLE h = FindFirstFileW((widen(dir) + L"\\*").c_str(), &fd);
  if (h == INVALID_HANDLE_VALUE) return false;
  names.clear();
  do {
    std::wstring n = fd.cFileName;
    if (n != L"." && n != L"..") names.push_back(narrow(n));
  } while (FindNextFileW(h, &fd));
  FindClose(h);
  return true;
}

void remove_tree(const std::string &name)
{
  std::wstring w = widen(name);
  DWORD a = GetFileAttributesW(w.c_str());
  if (a == INVALID_FILE_ATTRIBUTES) return;
  if ((a & FILE_ATTRIBUTE_DIRECTORY) && !(a & FILE_ATTRIBUTE_REPARSE_POINT)) {
    std::vector<std::string> names;
    if (list_dir(name, names))
      for (const std::string &n : names) remove_tree(name + "/" + n);
    RemoveDirectoryW(w.c_str());
  } else if (a & FILE_ATTRIBUTE_DIRECTORY) {
    RemoveDirectoryW(w.c_str());  // a link to a directory: the link, not what it points at
  } else {
    SetFileAttributesW(w.c_str(), FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(w.c_str());
  }
}

bool make_hard_link(const std::string &existing, const std::string &link)
{
  return CreateHardLinkW(widen(link).c_str(), widen(existing).c_str(), nullptr) != 0;
}

bool make_symlink(const std::string &target, const std::string &link)
{
  // Needs the privilege to create symbolic links (administrators, or developer mode): the caller
  // says so loudly when this fails. The target is relative to the directory of the link.
  return CreateSymbolicLinkW(widen(link).c_str(), widen(target).c_str(), SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) != 0;
}

bool can_limit_address_space() { return true; }  // through a job object

RunResult run_program(const std::string &exe, const std::vector<std::string> &args, const RunOptions &opt)
{
  RunResult r;
  SECURITY_ATTRIBUTES sa = { sizeof sa, nullptr, TRUE };
  HANDLE in_r = nullptr, in_w = nullptr, out_r = nullptr, out_w = nullptr, err_r = nullptr, err_w = nullptr;
  if (!CreatePipe(&in_r, &in_w, &sa, 0) || !CreatePipe(&out_r, &out_w, &sa, 0) || !CreatePipe(&err_r, &err_w, &sa, 0)) return r;
  // The parent's ends must not be inherited, or the child never sees the end of its input.
  SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(err_r, HANDLE_FLAG_INHERIT, 0);

  std::wstring wexe = widen(exe), cmd;
  quote_argument(wexe, cmd);
  for (const std::string &a : args) {
    cmd += L' ';
    quote_argument(widen(a), cmd);
  }
  // The environment of this process plus the additions, as one block of NUL-terminated UTF-16 strings.
  std::wstring env_block;
  if (!opt.env.empty()) {
    wchar_t *cur = GetEnvironmentStringsW();
    for (const wchar_t *p = cur; *p; p += wcslen(p) + 1) env_block.append(p, wcslen(p) + 1);
    FreeEnvironmentStringsW(cur);
    for (const std::string &e : opt.env) {
      std::wstring we = widen(e);
      env_block.append(we.c_str(), we.size() + 1);
    }
    env_block += L'\0';
  }

  STARTUPINFOW si = {};
  si.cb = sizeof si;
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = in_r;
  si.hStdOutput = out_w;
  si.hStdError = err_w;
  PROCESS_INFORMATION pi = {};
  std::vector<wchar_t> cmdline(cmd.begin(), cmd.end());
  cmdline.push_back(L'\0');
  const bool limited = opt.address_space_limit_kb > 0;
  BOOL ok = CreateProcessW(wexe.c_str(), cmdline.data(), nullptr, nullptr, TRUE, CREATE_UNICODE_ENVIRONMENT | (limited ? CREATE_SUSPENDED : 0),
                           env_block.empty() ? nullptr : (void *)env_block.data(), nullptr, &si, &pi);
  CloseHandle(in_r);
  CloseHandle(out_w);
  CloseHandle(err_w);
  if (!ok) {
    CloseHandle(in_w);
    CloseHandle(out_r);
    CloseHandle(err_r);
    return r;
  }
  HANDLE job = nullptr;
  if (limited) {
    // The limit is on the memory the process may commit (RLIMIT_AS of the POSIX side), set before it runs.
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION li = {};
    li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    li.ProcessMemoryLimit = (SIZE_T)opt.address_space_limit_kb * 1024;
    job = CreateJobObjectW(nullptr, nullptr);
    if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation, &li, sizeof li) ||
        !AssignProcessToJobObject(job, pi.hProcess)) {
      TerminateProcess(pi.hProcess, 1);
      if (job) CloseHandle(job);
      CloseHandle(pi.hProcess);
      CloseHandle(pi.hThread);
      CloseHandle(in_w);
      CloseHandle(out_r);
      CloseHandle(err_r);
      return r;
    }
    ResumeThread(pi.hThread);
  }
  r.started = true;
  std::thread t_out(read_all, out_r, &r.out), t_err(read_all, err_r, &r.err);
  for (size_t off = 0; off < opt.stdin_data.size();) {
    DWORD done = 0;
    if (!WriteFile(in_w, opt.stdin_data.data() + off, (DWORD)(opt.stdin_data.size() - off), &done, nullptr) || done == 0) break;
    off += done;
  }
  CloseHandle(in_w);
  t_out.join();
  t_err.join();
  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD code = 0;
  GetExitCodeProcess(pi.hProcess, &code);
  r.code = (int)code;
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  if (job) CloseHandle(job);
  CloseHandle(out_r);
  CloseHandle(err_r);
  return r;
}

namespace {

template <class F>
F kernel32_function(const char *name)
{
  FARPROC p = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), name);
  F f = nullptr;
  memcpy(&f, &p, sizeof f);  // neither compiler likes a cast between a function pointer and another type
  return f;
}

// The pseudo-console functions are looked up, so that the tests build with every header set and a
// Windows without them just skips.
typedef HRESULT(WINAPI *CreatePseudoConsoleFn)(COORD, HANDLE, HANDLE, DWORD, void **);
typedef void(WINAPI *ClosePseudoConsoleFn)(void *);
const DWORD_PTR PSEUDOCONSOLE_ATTRIBUTE = 0x00020016;  // PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE

void append_available(HANDLE pipe, std::string &into)
{
  DWORD avail = 0;
  while (PeekNamedPipe(pipe, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
    char buf[4096];
    DWORD n = 0;
    if (!ReadFile(pipe, buf, avail < sizeof buf ? avail : (DWORD)sizeof buf, &n, nullptr) || n == 0) break;
    into.append(buf, n);
  }
}

void type_text(HANDLE pipe, const std::string &text)
{
  for (size_t off = 0; off < text.size();) {
    DWORD done = 0;
    if (!WriteFile(pipe, text.data() + off, (DWORD)(text.size() - off), &done, nullptr) || done == 0) return;
    off += done;
  }
}

}  // namespace

bool can_run_on_terminal()
{
  return kernel32_function<CreatePseudoConsoleFn>("CreatePseudoConsole") != nullptr;
}

// The program gets a pseudo-console (ConPTY), as the terminal of Windows Terminal has. What is typed
// goes in as UTF-8 and VT sequences, and the console turns it into key events: a character outside the
// BMP reaches ReadConsoleW as a surrogate pair, as it does from a real keyboard.
TerminalResult run_on_terminal(const std::string &exe, const std::vector<std::string> &args, const std::vector<TypedLine> &lines, int timeout_ms)
{
  TerminalResult r;
  CreatePseudoConsoleFn create = kernel32_function<CreatePseudoConsoleFn>("CreatePseudoConsole");
  ClosePseudoConsoleFn close_console = kernel32_function<ClosePseudoConsoleFn>("ClosePseudoConsole");
  if (!create || !close_console) return r;
  HANDLE in_r = nullptr, in_w = nullptr, out_r = nullptr, out_w = nullptr;
  if (!CreatePipe(&in_r, &in_w, nullptr, 0) || !CreatePipe(&out_r, &out_w, nullptr, 0)) return r;
  void *console = nullptr;
  COORD size = { 120, 30 };
  HRESULT hr = create(size, in_r, out_w, 0, &console);
  CloseHandle(in_r);
  CloseHandle(out_w);
  if (FAILED(hr)) {
    CloseHandle(in_w);
    CloseHandle(out_r);
    return r;
  }

  SIZE_T attr_size = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
  std::vector<char> attr_space(attr_size);
  LPPROC_THREAD_ATTRIBUTE_LIST list = (LPPROC_THREAD_ATTRIBUTE_LIST)attr_space.data();
  bool ok = InitializeProcThreadAttributeList(list, 1, 0, &attr_size) != 0;
  if (ok) ok = UpdateProcThreadAttribute(list, 0, PSEUDOCONSOLE_ATTRIBUTE, console, sizeof console, nullptr, nullptr) != 0;
  std::wstring wexe = widen(exe), cmd;
  quote_argument(wexe, cmd);
  for (const std::string &a : args) {
    cmd += L' ';
    quote_argument(widen(a), cmd);
  }
  std::vector<wchar_t> cmdline(cmd.begin(), cmd.end());
  cmdline.push_back(L'\0');
  STARTUPINFOEXW si = {};
  si.StartupInfo.cb = sizeof si;
  si.lpAttributeList = list;
  // Without this the program can get the standard handles of this process (pipes of the test runner)
  // instead of the console.
  si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  si.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
  si.StartupInfo.hStdOutput = INVALID_HANDLE_VALUE;
  si.StartupInfo.hStdError = INVALID_HANDLE_VALUE;
  PROCESS_INFORMATION pi = {};
  if (ok) ok = CreateProcessW(wexe.c_str(), cmdline.data(), nullptr, nullptr, FALSE, EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &si.StartupInfo, &pi) != 0;
  if (!ok) {
    close_console(console);
    CloseHandle(in_w);
    CloseHandle(out_r);
    return r;
  }
  r.started = true;

  const ULONGLONG deadline = GetTickCount64() + (ULONGLONG)timeout_ms;
  size_t next = 0, from = 0, queries = 0;
  bool exited = false;
  while (!exited) {
    append_available(out_r, r.output);
    // The console may ask the terminal for the position of the cursor and wait for the answer.
    for (size_t at; (at = r.output.find("\x1b[6n", queries)) != std::string::npos;) {
      queries = at + 4;
      type_text(in_w, "\x1b[1;1R");
    }
    while (next < lines.size()) {
      size_t at = r.output.find(lines[next].after, from);
      if (at == std::string::npos) break;
      from = at + lines[next].after.size();
      type_text(in_w, lines[next].text);
      next++;
    }
    if (WaitForSingleObject(pi.hProcess, 20) == WAIT_OBJECT_0) exited = true;
    if (!exited && GetTickCount64() > deadline) {
      r.timed_out = true;
      TerminateProcess(pi.hProcess, 1);
      WaitForSingleObject(pi.hProcess, 5000);
      exited = true;
    }
  }
  // Closing the console ends the output pipe; it can block until the output has been read.
  std::thread closer([&] { close_console(console); });
  for (;;) {
    char buf[4096];
    DWORD n = 0;
    if (!ReadFile(out_r, buf, sizeof buf, &n, nullptr) || n == 0) break;
    r.output.append(buf, n);
  }
  closer.join();
  DWORD code = 0;
  GetExitCodeProcess(pi.hProcess, &code);
  r.code = (int)code;
  DeleteProcThreadAttributeList(list);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  CloseHandle(in_w);
  CloseHandle(out_r);
  return r;
}

std::string find_program(const std::string &name)
{
  wchar_t path[MAX_PATH + 1];
  DWORD n = SearchPathW(nullptr, widen(name).c_str(), nullptr, MAX_PATH, path, nullptr);
  return n > 0 && n <= MAX_PATH ? narrow(std::wstring(path, n)) : std::string();
}

namespace {

// For a failure: the access control list of this process as text, and whether SeDebugPrivilege is
// enabled in its token (which would let anybody of this user in whatever the list says).
std::string describe_access()
{
  std::string text;
  PSECURITY_DESCRIPTOR sd = nullptr;
  if (GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr, &sd) ==
      ERROR_SUCCESS) {
    wchar_t *sddl = nullptr;
    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &sddl, nullptr)) {
      text += "; security descriptor " + narrow(sddl);
      LocalFree(sddl);
    }
    LocalFree(sd);
  } else {
    text += "; security descriptor unreadable";
  }
  HANDLE token = nullptr;
  LUID debug;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) && LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &debug)) {
    std::vector<char> buf(4096);
    DWORD n = 0;
    if (GetTokenInformation(token, TokenPrivileges, buf.data(), (DWORD)buf.size(), &n)) {
      const TOKEN_PRIVILEGES *tp = (const TOKEN_PRIVILEGES *)buf.data();
      text += "; SeDebugPrivilege absent";
      for (DWORD i = 0; i < tp->PrivilegeCount; i++)
        if (tp->Privileges[i].Luid.LowPart == debug.LowPart && tp->Privileges[i].Luid.HighPart == debug.HighPart)
          text = text.substr(0, text.size() - 7) + ((tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "enabled" : "present but disabled");
    }
  }
  if (token) CloseHandle(token);
  return text;
}

}  // namespace

// An administrator's token usually has SeDebugPrivilege enabled, and with it a process opens any other
// whatever its access control list says: the case the program cannot and does not claim to stop. To see
// what the list does, this process (which is the opener here) switches the privilege off first.
void disable_debug_privilege()
{
  HANDLE token = nullptr;
  TOKEN_PRIVILEGES tp = {};
  tp.PrivilegeCount = 1;
  tp.Privileges[0].Attributes = 0;  // not SE_PRIVILEGE_ENABLED: disabled
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
    if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp.Privileges[0].Luid)) AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr);
    CloseHandle(token);
  }
}

int check_hardening(std::string &detail)
{
  detail.clear();
  disable_debug_privilege();
  // The access control list: no other process of this user may read the memory, but it may still ask.
  HANDLE h = OpenProcess(PROCESS_VM_READ, FALSE, GetCurrentProcessId());
  if (h) {
    CloseHandle(h);
    detail = "a process of the same user can still open this one to read its memory" + describe_access();
    return 1;
  }
  if (GetLastError() != ERROR_ACCESS_DENIED) {
    detail = "opening this process for reading its memory failed with error " + std::to_string((unsigned)GetLastError()) + ", not access denied";
    return 1;
  }
  h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
  if (!h) {
    detail = "the access control list leaves the owner without even the right to ask about the process";
    return 1;
  }
  CloseHandle(h);
  detail = "memory of the process cannot be opened by its owner";

  typedef BOOL(WINAPI * GetPolicy)(HANDLE, int, PVOID, SIZE_T);
  GetPolicy get = kernel32_function<GetPolicy>("GetProcessMitigationPolicy");
  struct Expected {
    int policy;
    DWORD bits;
    const char *name;
  };
  const Expected expected[] = { { 2, 1, "dynamic code prohibited" }, { 6, 1, "extension points disabled" },
                                { 10, 5, "no remote images, system32 first" }, { 13, 1, "no child processes" } };
  for (const Expected &e : expected) {
    DWORD flags = 0;
    if (!get || !get(GetCurrentProcess(), e.policy, &flags, sizeof flags)) {
      detail += std::string("; not readable: ") + e.name;
    } else if ((flags & e.bits) != e.bits) {
      detail = std::string("the mitigation policy is not set: ") + e.name + " (flags " + std::to_string((unsigned)flags) + ")";
      return 1;
    } else {
      detail += std::string("; ") + e.name;
    }
  }
  return 0;
}
