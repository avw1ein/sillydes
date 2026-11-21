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
