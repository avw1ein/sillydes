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

// Windows keeps no count of locked pages and the limit is the working set: the locking tests skip.
long locked_kb() { return -1; }
long memlock_limit_kb() { return 0; }

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

bool can_limit_address_space() { return false; }

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
  BOOL ok = CreateProcessW(wexe.c_str(), cmdline.data(), nullptr, nullptr, TRUE, CREATE_UNICODE_ENVIRONMENT,
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
  CloseHandle(out_r);
  CloseHandle(err_r);
  return r;
}
