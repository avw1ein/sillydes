// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// SillyDES - Linux command line port of the DOS program Odette by Andy van Wezel (1993 - 1994),
// ported and updated 2026.
//
// Build: cmake --preset default && cmake --build --preset default
//
// The file format differs from the MS DOS original and is not compatible with it.

#include <cctype>
#include <new>
#include <string>
#include <vector>

#include "armor.h"
#include "common.h"
#include "container.h"
#include "keys.h"
#include "platform.h"

namespace {

struct Args {
  bool encrypt = true;
  bool binary = true;  // false: e-mail (armored) text
  bool usephrase = false;
  bool requirelock = false;
  std::string in, out, keyfile;
};

void usage()
{
  write_message(MSG_OUT,
    "SillyDES " PACKAGE_VERSION " Copyright (C) by Andy van Wezel 1993 - 1994, 2026\n\n"
    "Usage: sillydes act=e|d|em|dm in=infile out=outfile phrase|key=keyfile [requirelock]\n"
    " e            Encryption.\n"
    " d            Decryption.\n"
    " em           Encryption to e-mail message.\n"
    " dm           Decryption from e-mail message.\n"
    " infile       Data to be en/decrypted.\n"
    " outfile      Result of en/decryption.\n"
    " keyfile      Contains the eight keys.\n"
    " phrase       Prompt for a phrase (min. 20 characters, 2 GiB of memory).\n"
    " requirelock  Optional, with phrase: stop (error 15) if the 2 GiB cannot be locked in RAM.\n\n"
    "*SillyDES performs a DES8 encryption with 2048-bit whitening on textfiles or\n"
    " executables. The block size grows to 2048 bits. Eight 64-bit keys feed\n"
    " every layer. Output is authenticated (HMAC-SHA-512).\n"
    "*SillyDES is free software released under the MIT License (see the LICENSE file),\n"
    " and provided as is. Andy van Wezel makes no claims and offers no warranties\n"
    " of any sort with SillyDES.\n");
}

// argv[0] is the program name; the arguments are UTF-8 (the platform's entry point converts them).
Args parse_args(const std::vector<std::string> &argv)
{
  Args a;
  int bewerking = -1;  // 1 = encrypt, 2 = decrypt, 0 = invalid

  if (argv.size() != 5 && argv.size() != 6) errorexit(3);

  for (size_t i = 1; i < argv.size(); i++) {
    const std::string &arg = argv[i];
    size_t eq = arg.find('=');
    std::string name = arg.substr(0, eq == std::string::npos ? arg.size() : eq + 1);
    std::string val = eq == std::string::npos ? "" : arg.substr(eq + 1);
    for (char &c : name) c = (char)tolower((unsigned char)c);

    if (name == "act=") {
      if (bewerking != -1) { errarg = "act="; errorexit(9); }
      for (char &c : val) c = (char)tolower((unsigned char)c);
      bewerking = 0;
      if (val == "e")  { bewerking = 1; a.binary = true; }
      if (val == "d")  { bewerking = 2; a.binary = true; }
      if (val == "em") { bewerking = 1; a.binary = false; }
      if (val == "dm") { bewerking = 2; a.binary = false; }
    } else if (name == "in=") {
      if (!a.in.empty()) { errarg = "in="; errorexit(9); }
      a.in = val;
    } else if (name == "out=") {
      if (!a.out.empty()) { errarg = "out="; errorexit(9); }
      a.out = val;
    } else if (name == "key=") {
      if (!a.keyfile.empty()) { errarg = "key="; errorexit(9); }
      a.keyfile = val;
    } else if (name == "requirelock") {
      if (a.requirelock) { errarg = "requirelock"; errorexit(9); }
      a.requirelock = true;
    } else if (name == "phrase") {
      if (a.usephrase) { errarg = "phrase"; errorexit(9); }
      a.usephrase = true;
    } else {
      errarg = arg;
      errorexit(4);
    }
  }

  if (bewerking == -1) { errarg = "act="; errorexit(10); }
  if (bewerking == 0)  { errarg = "act="; errorexit(4); }
  if (a.in.empty())    { errarg = "in="; errorexit(10); }
  if (a.out.empty())   { errarg = "out="; errorexit(10); }
  if (a.keyfile.empty() && !a.usephrase) { errarg = "phrase;key="; errorexit(10); }
  a.encrypt = bewerking == 1;
  return a;
}

// Not inlined into main: everything run() keeps on the stack (and what its callees were inlined
// into it) must lie below main's frame, because scrub_stack wipes below main and cannot reach main's own frame.
SILLYDES_NOINLINE int run(const std::vector<std::string> &argv)
{
  if (argv.size() == 1) { usage(); return 3; }
  Args args = parse_args(argv);

  KeyInput keys;
  keys.usephrase = args.usephrase;
  keys.require_lock = args.requirelock || lock_required();
  if (args.usephrase) keys.phrase = getphrase(args.encrypt);

  if (args.in == args.out || same_file(args.in, args.out)) errorexit(6);

  if (!args.keyfile.empty()) readkeyfile(args.keyfile, keys.key);

  Buf d = readfile(args.in);
  if (args.encrypt) {
    seal(d, keys, DEFAULT_KDF);
    if (!args.binary) d = high2low(d);
  } else {
    if (!args.binary) d = low2high(d, args.in);
    unseal(d, keys);
  }
  writefile(args.out, d);
  return 0;
}

}  // namespace

// Every failure is an exception that ends up here, so the destructors of the keys, the cipher and
// the data buffer have run and wiped before the process exits. Windows has no UTF-8 arguments:
// wmain gets UTF-16, which utf8_args converts, and then calls run() the same way.
#ifdef _WIN32
int wmain(int argc, wchar_t *argv[])
#else
int main(int argc, char *argv[])
#endif
{
  harden_process();
  lock_stack();
  int rc;
  try {
#ifdef _WIN32
    std::vector<std::string> args;
    if (!utf8_args(argc, argv, args)) { errarg = "argument"; errorexit(4); }
    rc = run(args);
#else
    rc = run(std::vector<std::string>(argv, argv + argc));
#endif
  } catch (const ExitError &e) {
    rc = e.code;
  } catch (const std::bad_alloc &) {
    report_error(7);
    rc = 7;
  }
  scrub_stack();
  exit_process(rc);
}
