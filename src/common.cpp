// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "common.h"

#include "platform.h"

std::string errarg;

void report_error(int numer)
{
  const std::string &a = errarg;
  std::string m;
  switch (numer) {
    case 1:  m = "ERROR#1: Can't read from: " + a + "\n"; break;
    case 2:  m = "ERROR#2: Can't write to: " + a + "\n"; break;
    case 3:  m = "ERROR#3: Wrong number of parameters.\nType sillydes for help.\n"; break;
    case 4:  m = "ERROR#4: Invalid option: " + a + "\nType sillydes for help.\n"; break;
    case 5:  m = "ERROR#5: Faulty keyfile: " + a + "\n"; break;
    case 6:  m = "ERROR#6: Inputfile and outputfile must differ.\nType sillydes for help.\n"; break;
    case 7:  m = "ERROR#7: Not enough memory (phrase mode needs 2 GiB free).\n"; break;
    case 8:  m = "ERROR#8: Can't find begin of code in: " + a + "\n"; break;
    case 9:  m = "ERROR#9: Duplicate argument on commandline: " + a + "\nType sillydes for help.\n"; break;
    case 10: m = "ERROR#10: Argument missing: " + a + "\nType sillydes for help.\n"; break;
    case 11: m = "ERROR#11: Can't find end of code in: " + a + "\n"; break;
    case 12: m = "ERROR#12: CRC error in: " + a + "\n"; break;
    case 13: m = "ERROR#13: Authentication failed (wrong key, or data damaged or not in the " FORMAT_NAME " format).\n"; break;
    case 14: m = "ERROR#14: System random generator failed.\n"; break;
    default: return;
  }
  write_message(MSG_ERR, m);
}

[[noreturn]] void errorexit(int numer)
{
  report_error(numer);
  throw ExitError{numer};
}

namespace {

// Closes the file on every way out of readfile and writefile, errors included.
struct OpenFile {
  FileHandle f;
  explicit OpenFile(FileHandle h) : f(h) {}
  ~OpenFile() { if (f != NO_FILE) close_file(f); }
  OpenFile(const OpenFile &) = delete;
  OpenFile &operator=(const OpenFile &) = delete;
};

}  // namespace

// Unbuffered, so no stdio copy of the data exists; a regular file is read straight into a
// buffer of its size, anything else grows by doubling (Buf wipes the storage it leaves behind).
Buf readfile(const std::string &name)
{
  errarg = name;
  uint64_t size = UNKNOWN_SIZE;
  OpenFile in(open_input(name, &size));
  if (in.f == NO_FILE) errorexit(1);
  Buf data;
  if (size != UNKNOWN_SIZE) {
    if (size > SIZE_MAX - 1) throw std::bad_alloc();
    data.resize((size_t)size + 1);  // +1: EOF read fits without growing
  }
  size_t n = 0;
  for (;;) {
    if (n == data.size()) {
      data.reserve(data.size() < 65536 ? 65536 : checked_mul(data.size(), 2));
      data.resize(data.capacity());
    }
    int64_t k = read_input(in.f, data.data() + n, data.size() - n);
    if (k < 0) errorexit(1);
    if (k == 0) break;
    n += (size_t)k;
  }
  data.resize(n);
  return data;
}

void writefile(const std::string &name, const Buf &data)
{
  errarg = name;
  OpenFile out(open_output(name));
  if (out.f == NO_FILE) errorexit(2);
  if (!write_output(out.f, data.data(), data.size())) errorexit(2);
  FileHandle f = out.f;
  out.f = NO_FILE;
  if (!close_file(f)) errorexit(2);
}

void randbytes(uint8_t *p, size_t n)
{
  if (!os_random(p, n)) errorexit(14);
}

void wipe(void *p, size_t n)
{
  secure_zero(p, n);
}
