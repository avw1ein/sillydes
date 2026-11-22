// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// End-to-end tests: runs the real binary, on every OS the same way (PORTPLAN.md todo 10). It replaces
// test.sh, which only ran on Linux. The operating system comes in through test_os.h only.
//
//   test_e2e <sillydes binary> <source root> [--scan-lib <residue_scan.so>] [--scan-exe <sillydes_scan>]
//            [--no-address-limit]
//   test_e2e --nfc-phrase       prints the non-ASCII phrase of the fixtures (for the release skill)
//   test_e2e <sillydes binary> <source root> --interop-make <directory> <label>
//   test_e2e <sillydes binary> <source root> --interop-check <directory> <label>,<label>...
//            files made by this system for the others, and files of the others opened here (the interop job of CI)
//
// The residue scan (does a secret survive in the memory of the exited process?) searches the process
// as it ends, in one of two ways: a library that is preloaded into the real binary (Linux), or the
// scan binary, which is the program built so that it scans itself at the end (every OS). Both use
// the same search code (residue_core.cpp). Where a part cannot run, the test says so and why, so that
// a skip is never silent.

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "platform.h"
#include "test_os.h"

namespace {

std::string exe, root, tmp, scan_log;

// One way to scan: a library for LD_PRELOAD, or another binary in place of the program.
struct Scanner {
  std::string name, lib, program;
};
std::vector<Scanner> scanners;
Scanner current;
bool use_limit = true;  // limit the address space of a child where the OS can (not under a sanitizer, which reserves a lot)

bool limit_possible() { return use_limit && can_limit_address_space(); }

[[noreturn]] void die(const std::string &what)
{
  printf("FAIL: %s\n", what.c_str());
  if (!scan_log.empty()) printf("%s\n", scan_log.c_str());
  fflush(stdout);
  exit(1);
}

void need(bool ok, const std::string &what)
{
  if (!ok) die(what);
}

void passed(const char *what) { printf("ok: %s\n", what); }
void skipped(const std::string &why) { printf("skipped: %s\n", why.c_str()); }

std::string T(const std::string &name) { return tmp + "/" + name; }
std::string R(const std::string &name) { return root + "/" + name; }

// ---- bytes and text. The sources are ASCII: every non-ASCII character is named by its number.

std::string B(std::initializer_list<int> bytes)
{
  std::string s;
  for (int b : bytes) s += (char)b;
  return s;
}

std::string utf8(std::initializer_list<uint32_t> cps)
{
  std::string s;
  for (uint32_t c : cps) {
    if (c < 0x80) s += (char)c;
    else if (c < 0x800) { s += (char)(0xC0 | (c >> 6)); s += (char)(0x80 | (c & 0x3F)); }
    else if (c < 0x10000) { s += (char)(0xE0 | (c >> 12)); s += (char)(0x80 | ((c >> 6) & 0x3F)); s += (char)(0x80 | (c & 0x3F)); }
    else { s += (char)(0xF0 | (c >> 18)); s += (char)(0x80 | ((c >> 12) & 0x3F)); s += (char)(0x80 | ((c >> 6) & 0x3F)); s += (char)(0x80 | (c & 0x3F)); }
  }
  return s;
}

std::string cat(const std::string &a, const std::string &b) { return a + b; }

// Latin, Greek, Japanese and one character outside the BMP: what the fixture hello-utf8-phrase.sdes was made with.
std::string nfc_phrase()
{
  return utf8({ 'C', 'r', 0xE8, 'm', 'e', ' ', 'b', 'r', 0xFB, 'l', 0xE9, 'e', ',', ' ', 0x3A9, 0x3BC, 0x3AD, 0x3B3, 0x3B1, ',', ' ',
                0x65E5, 0x672C, 0x8A9E, 0x306E, 0x30C6, 0x30B9, 0x30C8, ',', ' ', 0x1D11E, ' ', 'c', 'l', 'e', 'f' });
}

// The same text typed another way: a byte order mark, decomposed accents, a no-break space, the ohm and
// micro signs, a full-width comma and letters, half-width katakana, a zero width space, a soft hyphen,
// a trailing ideographic space.
std::string other_phrase()
{
  return utf8({ 0xFEFF, 'C', 'r', 'e', 0x300, 'm', 'e', 0xA0, 'b', 'r', 'u', 0x302, 'l', 'e', 0x301, 'e', ',', ' ', 0x2126, 0xB5, 0x3B5, 0x301,
                0x3B3, 0x3B1, 0xFF0C, ' ', 0x65E5, 0x672C, 0x200B, 0x8A9E, 0x306E, 0xFF83, 0xFF7D, 0xFF84, ',', ' ', 0x1D11E, ' ', 0xFF43, 0xFF4C, 0xAD,
                0xFF45, 0xFF46, 0x3000 });
}

std::string replace_all(std::string s, const std::string &from, const std::string &to)
{
  for (size_t at = 0; (at = s.find(from, at)) != std::string::npos; at += to.size()) s.replace(at, from.size(), to);
  return s;
}

std::string crlf(const std::string &s) { return replace_all(s, "\n", "\r\n"); }
std::string cr_only(const std::string &s) { return replace_all(s, "\n", "\r"); }
std::string with_bom(const std::string &s) { return B({ 0xEF, 0xBB, 0xBF }) + s; }
std::string utf16le(const std::string &s)  // ASCII text as UTF-16 with a byte order mark
{
  std::string o = B({ 0xFF, 0xFE });
  for (char c : s) { o += c; o += '\0'; }
  return o;
}

std::vector<std::string> lines_of(const std::string &s)
{
  std::vector<std::string> v;
  size_t at = 0;
  while (at < s.size()) {
    size_t nl = s.find('\n', at);
    if (nl == std::string::npos) nl = s.size();
    v.push_back(s.substr(at, nl - at));
    at = nl + 1;
  }
  return v;
}

// ---- files

bool slurp(const std::string &name, std::string &data)
{
  uint64_t size = 0;
  FileHandle f = open_input(name, &size);
  if (f == NO_FILE) return false;
  data.clear();
  uint8_t buf[65536];
  for (;;) {
    int64_t k = read_input(f, buf, sizeof buf);
    if (k <= 0) break;
    data.append((const char *)buf, (size_t)k);
  }
  close_file(f);
  return true;
}

std::string get(const std::string &name)
{
  std::string d;
  need(slurp(name, d), "cannot read " + name);
  return d;
}

void put(const std::string &name, const std::string &data)
{
  FileHandle f = open_output(name);
  need(f != NO_FILE, "cannot write " + name);
  need(write_output(f, (const uint8_t *)data.data(), data.size()), "cannot write " + name);
  close_file(f);
}

// ---- running the program

RunResult sd(const std::vector<std::string> &args, const RunOptions &opt = RunOptions())
{
  RunResult r = run_program(exe, args, opt);
  need(r.started, "cannot start " + exe);
  return r;
}

RunOptions with_stdin(const std::string &s)
{
  RunOptions o;
  o.stdin_data = s;
  return o;
}

std::string str(int n) { return std::to_string(n); }

// Expects the program to end with this exit code.
RunResult sd_rc(int want, const std::vector<std::string> &args, const RunOptions &opt, const std::string &what)
{
  RunResult r = sd(args, opt);
  if (r.code != want) die(what + " (exit code " + str(r.code) + ", wanted " + str(want) + "): " + r.err);
  return r;
}

void sd_ok(const std::vector<std::string> &args, const std::string &what, const RunOptions &opt = RunOptions())
{
  sd_rc(0, args, opt, what);
}

std::vector<std::string> act(const char *a, const std::string &in, const std::string &out, const std::string &key)
{
  std::vector<std::string> v = { std::string("act=") + a, "in=" + in, "out=" + out };
  v.push_back(key == "phrase" ? key : "key=" + key);
  return v;
}

std::mt19937 rng(20260521);
std::string random_bytes(size_t n)
{
  std::string s(n, '\0');
  for (char &c : s) c = (char)rng();
  return s;
}

size_t differing_bytes(const std::string &a, const std::string &b)
{
  size_t n = 0;
  for (size_t i = 0; i < a.size() && i < b.size(); i++) n += a[i] != b[i];
  return n;
}

// ---- the tests

const size_t HDR = 280;  // header: magic, parameters, salt, IV

std::string hello_txt;  // what hello.sdes holds

void golden_files(const std::string &phrase, const std::string &utf8_phrase)
{
  sd_ok(act("dm", R("hello.sdes"), T("hello.txt"), R("sample.key")), "hello.sdes does not decrypt");
  hello_txt = get(T("hello.txt"));
  need(hello_txt.compare(0, 6, "Hello,") == 0, "hello.sdes decrypts to something else");
  passed("hello.sdes decrypts");

  // Written when format 5.2.0 was introduced and never regenerated: these fail as soon as the file
  // format changes, and the phrase rules are part of it.
  sd_ok(act("d", R("test/format-5.2.0/hello.bin"), T("f1.txt"), R("sample.key")), "format 5.2.0 binary fixture does not decrypt");
  need(get(T("f1.txt")) == hello_txt, "format 5.2.0 binary fixture decrypts to something else");
  sd_ok(act("dm", R("test/format-5.2.0/hello-phrase.sdes"), T("f2.txt"), "phrase"), "format 5.2.0 phrase fixture does not decrypt", with_stdin(phrase + "\n"));
  need(get(T("f2.txt")) == hello_txt, "format 5.2.0 phrase fixture decrypts to something else");
  sd_ok(act("dm", R("test/format-5.2.0/hello-utf8-phrase.sdes"), T("f3.txt"), "phrase"), "format 5.2.0 non-ASCII phrase fixture does not decrypt",
        with_stdin(utf8_phrase + "\n"));
  need(get(T("f3.txt")) == hello_txt, "format 5.2.0 non-ASCII phrase fixture decrypts to something else");
  passed("files of format 5.2.0 decrypt (binary, and e-mail style with an ASCII and a non-ASCII phrase)");
}

void round_trips()
{
  for (size_t size : { 0, 1, 255, 256, 257, 1000, 5000 }) {
    std::string data = random_bytes(size);
    put(T("in.bin"), data);
    sd_ok(act("e", T("in.bin"), T("e.bin"), R("sample.key")), "encryption of " + str((int)size) + " bytes");
    sd_ok(act("d", T("e.bin"), T("d.bin"), R("sample.key")), "decryption of " + str((int)size) + " bytes");
    need(get(T("d.bin")) == data, "binary round trip of " + str((int)size) + " bytes");
    sd_ok(act("em", T("in.bin"), T("e.txt"), R("sample.key")), "e-mail encryption of " + str((int)size) + " bytes");
    sd_ok(act("dm", T("e.txt"), T("d2.bin"), R("sample.key")), "e-mail decryption of " + str((int)size) + " bytes");
    need(get(T("d2.bin")) == data, "e-mail round trip of " + str((int)size) + " bytes");
  }
  passed("round trips (binary and e-mail style)");

  put(T("in.bin"), random_bytes(1));
  sd_ok(act("e", T("in.bin"), T("e.bin"), R("sample.key")), "encryption of one byte");
  need(get(T("e.bin")).size() == HDR + 256 + 64, "unexpected container size");
  passed("container is header + one block + 64-byte tag");
}

void phrases(const std::string &phrase)
{
  sd_ok(act("em", R("hello.sdes"), T("p.txt"), "phrase"), "phrase encryption", with_stdin(phrase + "\n"));
  sd_ok(act("dm", T("p.txt"), T("p.out"), "phrase"), "phrase decryption", with_stdin(phrase + "\n"));
  need(get(T("p.out")) == get(R("hello.sdes")), "phrase round trip mismatch");
  passed("phrase round trip");

  sd_rc(10, act("e", R("hello.sdes"), T("short"), "phrase"), with_stdin("nineteen chars 123\n"), "short phrase accepted");
  need(!file_exists(T("short")), "short phrase left an output file");
  if (limit_possible()) {
    RunOptions o = with_stdin(phrase + "\n");
    o.address_space_limit_kb = 1500000;
    sd_rc(7, act("e", R("hello.sdes"), T("nomem"), "phrase"), o, "phrase mode without 2 GiB did not stop with error 7");
    need(!file_exists(T("nomem")), "error 7 left an output file");
    passed("short phrase and missing memory are refused");
  } else {
    passed("short phrase is refused");
    skipped("error 7 with too little memory (the address space of a child cannot be limited on this OS or under a sanitizer)");
  }
}

void wrong_keys()
{
  put(T("otherkey"), "0123456789abcdef\nfedcba9876543210\n13579bdf02468ace\na1b2c3d4e5f60718\n"
                     "0f1e2d3c4b5a6978\n1122334455667788\n99aabbccddeeff00\n0011223344556677\n");
  sd_rc(13, act("dm", T("p.txt"), T("bad"), T("otherkey")), RunOptions(), "wrong key accepted");
  passed("wrong key fails authentication");

  std::string key = get(R("sample.key")), parity = key;
  size_t at = parity.find("BA7CDE4350091ADE");
  need(at != std::string::npos, "sample.key has changed: the parity test needs its line BA7CDE4350091ADE");
  parity[at + 15] = 'F';
  put(T("paritykey"), parity);
  sd_rc(13, act("dm", R("hello.sdes"), T("bad"), T("paritykey")), RunOptions(), "key differing in a parity bit accepted");
  passed("every key bit matters");

  std::string six;
  int n = 0;
  for (const std::string &l : lines_of(key)) {
    bool hex = l.size() >= 16;
    for (size_t i = 0; hex && i < 16; i++) hex = (l[i] >= '0' && l[i] <= '9') || (l[i] >= 'A' && l[i] <= 'F');
    if (hex && n < 6) { six += l.substr(0, 16) + "\n"; n++; }
  }
  put(T("sixkeys"), six);
  sd_rc(5, act("dm", R("hello.sdes"), T("bad"), T("sixkeys")), RunOptions(), "key file with too few keys accepted");
  passed("key file needs eight keys");

  std::string corrupt;
  for (const std::string &l : lines_of(get(T("p.txt")))) {
    std::string c = l;
    if (c.size() >= 21) c[20] = 'A';
    corrupt += c + "\n";
  }
  need(corrupt != get(T("p.txt")), "corrupted e-mail text not built");
  put(T("corrupt.txt"), corrupt);
  RunResult r = sd(act("dm", T("corrupt.txt"), T("bad2"), R("sample.key")));
  need(r.code != 0, "corruption not detected");
  passed("corruption detected (CRC)");
}

void block_tests()
{
  // Nine identical plaintext blocks used to make ciphertext block 3 equal DES(k6, 0).
  std::string blk = random_bytes(256), rep;
  for (int i = 0; i < 9; i++) rep += blk;
  put(T("rep.bin"), rep);
  sd_ok(act("e", T("rep.bin"), T("rep.enc"), R("sample.key")), "encryption of repeated blocks");
  std::string enc = get(T("rep.enc"));
  auto block = [&](const std::string &file, int i) { return file.substr(HDR + 256 * (size_t)i, 256); };
  std::set<std::string> distinct;
  for (int i = 0; i < 9; i++) {
    std::string c = block(enc, i);
    distinct.insert(c);
    std::set<std::string> words;
    for (size_t w = 0; w < 256; w += 8) words.insert(c.substr(w, 8));
    need(words.size() > 1, "a ciphertext block repeats one 8-byte word");
  }
  need(distinct.size() == 9, "repeated plaintext blocks give equal ciphertext blocks");
  passed("repeated plaintext blocks leave no pattern");

  sd_ok(act("e", T("rep.bin"), T("rep2.enc"), R("sample.key")), "second encryption of repeated blocks");
  std::string enc2 = get(T("rep2.enc"));
  for (int i = 0; i < 9; i++) need(differing_bytes(block(enc, i), block(enc2, i)) > 200, "the same block is nearly equal in two encryptions");
  passed("random IV makes every block differ between runs");

  // value -1: truncate by 256 bytes; -2: flip bits (the byte may happen to have the value, so a flip, not an assignment)
  struct Tamper { const char *name; size_t at; int value; };
  const Tamper tampers[] = { { "bit flip in a block", HDR + 300, -2 }, { "truncation", 0, -1 }, { "header byte 7", 7, 0x01 },
                             { "KDF memory parameter too large", 4, 0x1e }, { "KDF time parameter zero", 5, 0x00 } };
  for (const Tamper &t : tampers) {
    std::string bad = enc;
    if (t.value == -1) bad.resize(bad.size() - 256);
    else if (t.value == -2) bad[t.at] = (char)(bad[t.at] ^ 0x55);
    else bad[t.at] = (char)t.value;
    put(T("tampered"), bad);
    sd_rc(13, act("d", T("tampered"), T("x"), R("sample.key")), RunOptions(), std::string(t.name) + " not rejected");
  }
  passed("bit flip, truncation, header change and out-of-range KDF parameters fail");

  // The magic and the e-mail tags of the previous format, 5.1.0.
  std::string old = enc;
  old[3] = 0x10;
  put(T("t5"), old);
  sd_rc(13, act("d", T("t5"), T("x"), R("sample.key")), RunOptions(), "magic of another version accepted");
  std::string armor = replace_all(get(T("p.txt")), "SillyDES 5.2.0", "SillyDES 5.1.0");
  need(armor != get(T("p.txt")), "e-mail text of another version not built");
  put(T("old.txt"), armor);
  sd_rc(8, act("dm", T("old.txt"), T("x"), R("sample.key")), RunOptions(), "e-mail tags of another version accepted");
  passed("files of another version are rejected");

  need(differing_bytes(enc.substr(8, 16), enc2.substr(8, 16)) > 8, "salt repeated");
  passed("fresh salt for every encryption");
}

void wrong_phrase()
{
  const std::string w = "A completely different phrase that is long enough to be accepted.";
  sd_rc(13, act("dm", T("p.txt"), T("x"), "phrase"), with_stdin(w + "\n"), "wrong phrase accepted");
  passed("wrong phrase fails authentication");
}

// Text from other systems: a key file, an e-mail text or a phrase that was made, saved or piped on
// another system must work as it is.
void text_interchange(const std::string &phrase, const std::string &nfc, const std::string &other)
{
  const std::string key = get(R("sample.key")), hello = get(R("hello.sdes"));
  const std::string key_variants[] = { crlf(key), cr_only(key), with_bom(key), utf16le(crlf(key)) };
  const char *key_names[] = { "CR LF", "CR", "byte order mark", "UTF-16" };
  for (int i = 0; i < 4; i++) {
    put(T("kv"), key_variants[i]);
    sd_ok(act("dm", R("hello.sdes"), T("ti.out"), T("kv")), std::string("key file with ") + key_names[i]);
    need(get(T("ti.out")) == hello_txt, std::string("key file with ") + key_names[i] + " gives other keys");
  }
  size_t nl = hello.find('\n');
  const std::string msg_variants[] = { crlf(hello), cr_only(hello), with_bom(hello.substr(nl + 1)), utf16le(crlf(hello)) };
  for (int i = 0; i < 4; i++) {
    put(T("mv"), msg_variants[i]);
    sd_ok(act("dm", T("mv"), T("ti.out"), R("sample.key")), std::string("e-mail text with ") + key_names[i]);
    need(get(T("ti.out")) == hello_txt, std::string("e-mail text with ") + key_names[i] + " decrypts to something else");
  }
  put(T("mv"), msg_variants[3]);
  put(T("kv"), key_variants[3]);
  sd_ok(act("dm", T("mv"), T("ti.out"), T("kv")), "UTF-16 e-mail text with a UTF-16 key file");
  need(get(T("ti.out")) == hello_txt, "UTF-16 e-mail text with a UTF-16 key file decrypts to something else");
  need(hello.find('\r') == std::string::npos && get(T("p.txt")).find('\r') == std::string::npos, "e-mail text is written with CR");
  passed("key files and e-mail text with CR LF, CR, a byte order mark and as UTF-16 are read");

  // The same phrase from a Windows pipe: a byte order mark, trailing spaces and CR LF.
  sd_ok(act("dm", R("test/format-5.2.0/hello-phrase.sdes"), T("ti.out"), "phrase"), "phrase with a byte order mark, spaces and CR LF",
        with_stdin(with_bom(phrase + "   \r\n")));
  need(get(T("ti.out")) == hello_txt, "phrase with a byte order mark, spaces and CR LF gives other keys");
  sd_ok(act("dm", R("test/format-5.2.0/hello-utf8-phrase.sdes"), T("ti.out"), "phrase"), "phrase typed another way",
        with_stdin(other + "\r\n"));
  need(get(T("ti.out")) == hello_txt, "phrase typed another way gives other keys");
  need(other != nfc, "the other phrase is the same bytes");
  passed("a phrase piped or typed in another way gives the same keys");
}

// A phrase that no other system could reproduce is refused, for encryption and for decryption, and
// before the key derivation (where the address space can be limited, that would end in error 7).
void refused_phrases()
{
  struct Case { std::string stdin_data; const char *act; std::string in; const char *message; const char *what; };
  std::string utf16_phrase = B({ 0xFF, 0xFE });
  for (char c : std::string("correct horse battery")) { utf16_phrase += c; utf16_phrase += '\0'; }
  utf16_phrase += B({ '\n', 0 });
  const std::string latin1 = cat(cat(B({ 'c', 'r', 0xE8 }), "me br"), cat(B({ 0xFB }), cat("l", cat(B({ 0xE9 }), cat("e ", cat(B({ 0xE0 }), " la carte, please\n"))))));
  const std::string nine = utf8({ 0x65E5, 0x672C, 0x8A9E, 0x65E5, 0x672C, 0x8A9E, 0x65E5, 0x672C, 0x8A9E }) + "\n";
  const Case cases[] = {
    { latin1, "e", R("hello.sdes"), "not valid UTF-8", "Latin-1 phrase accepted" },
    { utf16_phrase, "e", R("hello.sdes"), "not valid UTF-8", "UTF-16 phrase accepted" },
    { "correct horse\tbattery staple\n", "e", R("hello.sdes"), "control character", "phrase with a tab accepted" },
    { "correct horse battery staple\x1b[D\n", "e", R("hello.sdes"), "control character", "phrase with an arrow key accepted" },
    { "correct horse\tbattery staple\n", "dm", T("p.txt"), "control character", "phrase with a tab accepted for decryption" },
    { nine, "e", R("hello.sdes"), "too short", "phrase of nine characters in 27 bytes accepted" },
  };
  for (const Case &c : cases) {
    RunOptions o = with_stdin(c.stdin_data);
    if (limit_possible()) o.address_space_limit_kb = 1500000;
    RunResult r = sd(act(c.act, c.in, T("refused"), "phrase"), o);
    need(r.code == 10 && !file_exists(T("refused")) && r.err.find(c.message) != std::string::npos, c.what);
  }
  passed("phrases that are not UTF-8, hold a control character or are too short are refused before the key derivation");
}

void data_is_bytes()
{
  // Data is never translated: line endings, a DOS end-of-file mark and a NUL come back as they went in.
  const std::string dos = std::string("one\r\ntwo\nthree\r\x1a", 16) + std::string("\0four\r\n\x1a", 8);
  put(T("dos.in"), dos);
  sd_ok(act("e", T("dos.in"), T("dos.enc"), R("sample.key")), "encryption of data with CR, LF, 0x1A and NUL");
  sd_ok(act("d", T("dos.enc"), T("dos.out"), R("sample.key")), "decryption of data with CR, LF, 0x1A and NUL");
  need(get(T("dos.out")) == dos, "binary data is translated");
  sd_ok(act("em", T("dos.in"), T("dos.txt"), R("sample.key")), "e-mail encryption of data with CR, LF, 0x1A and NUL");
  sd_ok(act("dm", T("dos.txt"), T("dos.out"), R("sample.key")), "e-mail decryption of data with CR, LF, 0x1A and NUL");
  need(get(T("dos.out")) == dos, "e-mail data is translated");

  // File names are UTF-8, in composed and in decomposed form.
  const std::string n1 = utf8({ 'c', 'r', 0xE8, 'm', 'e', '-', 0x65E5, 0x672C }), n2 = utf8({ 'c', 'r', 'e', 0x300, 'm', 'e', '-', 0x1D11E });
  put(T(n1 + ".key"), get(R("sample.key")));
  sd_ok(act("e", T("dos.in"), T(n1 + ".enc"), T(n1 + ".key")), "encryption with non-ASCII file names");
  sd_ok(act("d", T(n1 + ".enc"), T(n2 + ".out"), T(n1 + ".key")), "decryption with non-ASCII file names");
  need(get(T(n2 + ".out")) == dos, "data with non-ASCII file names comes back changed");
  passed("data with CR, LF, 0x1A and NUL is not translated; file names outside ASCII work");
}

void same_file()
{
  // The same file under another spelling, through a hard link or through a symbolic link is still the
  // same file: the output would destroy the input, so every one of them is error 6.
  const std::string hello = get(R("hello.sdes"));
  put(T("same.in"), hello);
  std::vector<std::string> outs = { T("./same.in") };
  need(make_dir(T("sub")), "cannot make a directory");
  outs.push_back(T("sub/../same.in"));
  if (make_hard_link(T("same.in"), T("same.hard"))) outs.push_back(T("same.hard"));
  else skipped("same file through a hard link (the file system or the account does not allow it)");
  if (make_symlink("same.in", T("same.sym"))) outs.push_back(T("same.sym"));
  else skipped("same file through a symbolic link (the file system or the account does not allow it)");
  // Windows and macOS file systems are usually case-insensitive: then another case is the same file too.
  std::string upper = T("SAME.IN");
  if (file_exists(upper) && upper != T("same.in")) outs.push_back(upper);
  else skipped("same file in another case (case-sensitive file system)");
  for (const std::string &out : outs) {
    RunResult r = sd(act("dm", T("same.in"), out, R("sample.key")));
    need(r.code == 6, "input and output are one file (" + out + ") but the exit code is " + str(r.code));
  }
  need(get(T("same.in")) == hello, "a refused output destroyed the input");
  passed("input and output that are one file are refused, also through links and other spellings");
}

void sources_are_ascii()
{
  // The sources stay ASCII with LF line endings, so that every compiler and every checkout sees the same
  // bytes (the labels in them are hashed into the keys).
  struct Dir { const char *dir; std::vector<std::string> suffixes; };
  const Dir dirs[] = { { "src", { ".cpp", ".h" } }, { "tools", { ".cpp", ".sh" } }, { "test", { ".cpp", ".h", ".sh" } }, { "cmake", { "" } } };
  std::vector<std::string> files = { "CMakeLists.txt", "CMakePresets.json" };
  for (const Dir &d : dirs) {
    std::vector<std::string> names;
    need(list_dir(R(d.dir), names), std::string("cannot read the directory ") + d.dir);
    for (const std::string &n : names) {
      if (is_directory(R(std::string(d.dir) + "/" + n))) continue;
      for (const std::string &suffix : d.suffixes)
        if (n.size() >= suffix.size() && n.compare(n.size() - suffix.size(), suffix.size(), suffix) == 0) { files.push_back(std::string(d.dir) + "/" + n); break; }
    }
  }
  for (const std::string &f : files) {
    const std::string data = get(R(f));
    for (char c : data)
      if (!(c == '\n' || c == '\t' || (c >= ' ' && c <= '~'))) die(f + " holds a CR or a character outside ASCII");
  }
  passed("the sources are ASCII with LF line endings");
}

// ---- messages

// A message with a file name outside ASCII, redirected, holds the name as UTF-8 on every OS (on a
// Windows console it is written as UTF-16, which cannot be tested here without a console).
void messages_are_utf8()
{
  const std::string name = T("missing-") + utf8({ 0xE9, 0x65E5, 0x672C, 0x1D11E });
  RunResult r = sd(act("e", name, T("never"), R("sample.key")), RunOptions());
  need(r.code == 1, "a missing input file is not error 1");
  need(r.err.find(name) != std::string::npos, "the message about a missing file does not hold the name as UTF-8: " + r.err);
  need(!file_exists(T("never")), "an output file for a missing input file");
  passed("a message with a file name outside ASCII is UTF-8 when redirected");
}

// ---- a phrase typed into a terminal

void terminal_tests(const std::string &nfc)
{
  if (!can_run_on_terminal()) {
    skipped("phrase typed into a terminal (this OS has no pseudo-terminal that a test can use)");
    return;
  }
  put(T("t.txt"), "typed phrase test\n");
  // Pieces of the phrase that would show if the program echoed what is typed.
  const std::string probe1 = utf8({ 0x3A9, 0x3BC, 0x3AD, 0x3B3, 0x3B1 }), probe2 = utf8({ 'C', 'r', 0xE8, 'm', 'e' });
  auto silent = [&](const TerminalResult &t) { return t.output.find(probe1) == std::string::npos && t.output.find(probe2) == std::string::npos; };
  auto ran = [&](const TerminalResult &t, int code, const std::string &what) {
    need(t.started, what + ": the program did not start");
    need(!t.timed_out, what + ": the program waited for input that did not come; it showed: " + t.output);
    need(t.code == code, what + ": exit code " + str(t.code) + ", wanted " + str(code) + "; it showed: " + t.output);
  };
  const std::string enter = "\r";

  // The harness first: what the program writes to its terminal must come back, and the usage text is
  // the shortest thing to show it.
  TerminalResult t = run_on_terminal(exe, {}, {});
  need(t.started && !t.timed_out && t.output.find("Usage:") != std::string::npos,
       "the output of a program in a terminal does not come back (exit code " + str(t.code) + "): " + t.output);

  // Encryption asks twice. The phrase has Latin, Greek and Japanese text and a character outside the
  // BMP (a surrogate pair on Windows), and must be the same keys as the same text through a pipe.
  t = run_on_terminal(exe, act("e", T("t.txt"), T("t.bin"), "phrase"), { { "minimum", nfc + enter }, { "Repeat", nfc + enter } });
  ran(t, 0, "encryption with a typed phrase");
  need(silent(t), "the typed phrase was echoed");
  sd_ok(act("d", T("t.bin"), T("t.out"), "phrase"), "decryption through a pipe of a file made with a typed phrase", with_stdin(nfc + "\n"));
  need(get(T("t.out")) == get(T("t.txt")), "typed phrase and piped phrase give different keys");
  t = run_on_terminal(exe, act("d", T("t.bin"), T("t.out2"), "phrase"), { { "minimum", nfc + enter } });
  ran(t, 0, "decryption with a typed phrase");
  need(silent(t), "the typed phrase was echoed on decryption");
  need(get(T("t.out2")) == get(T("t.txt")), "typed decryption mismatch");
  passed("a phrase typed into a terminal, with a character outside the BMP, is not echoed and gives the keys of the same phrase piped");

  // A phrase that is too short, then one that does not match its repetition, then a good pair.
  t = run_on_terminal(exe, act("e", T("t.txt"), T("t2.bin"), "phrase"),
                      { { "minimum", "too short" + enter }, { "minimum", nfc + enter }, { "Repeat", nfc + "x" + enter },
                        { "minimum", nfc + enter }, { "Repeat", nfc + enter } });
  ran(t, 0, "retries at the prompt");
  need(t.output.find("too short") != std::string::npos, "no message for a short phrase: " + t.output);
  need(t.output.find("differ") != std::string::npos, "no message for phrases that differ: " + t.output);
  sd_ok(act("d", T("t2.bin"), T("t2.out"), "phrase"), "decryption after retries", with_stdin(nfc + "\n"));
  need(get(T("t2.out")) == get(T("t.txt")), "the pair accepted after the retries is not the phrase");
  passed("a short phrase and a repetition that differs are asked again");

  // The end of input: Ctrl+D on a Unix terminal, Ctrl+Z on Windows.
#ifdef _WIN32
  const std::string eof = "\x1a" + enter;
#else
  const std::string eof = "\x04";
#endif
  t = run_on_terminal(exe, act("e", T("t.txt"), T("t3.bin"), "phrase"), { { "minimum", eof } });
  ran(t, 10, "the end of input at the prompt");
  need(!file_exists(T("t3.bin")), "an output file after the end of input");
  passed("the end of input at the phrase prompt is error 10");
}

#ifdef _WIN32
// ---- PowerShell: what its pipe and its redirection hand to the program (README, section 7)

// Runs a PowerShell script and returns what it exited with.
RunResult powershell(const std::string &shell, const std::string &script)
{
  return run_program(shell, { "-NoProfile", "-NonInteractive", "-Command", script }, RunOptions());
}

void powershell_tests(const std::string &nfc)
{
  const std::string ps5 = find_program("powershell.exe"), ps7 = find_program("pwsh.exe");
  if (ps5.empty() && ps7.empty()) {
    skipped("PowerShell (not installed)");
    return;
  }
  put(T("ps.txt"), "powershell test\n");
  const std::string q = "'";
  auto encrypt = [&](const std::string &shell, const std::string &prefix, const std::string &out) {
    // The phrase is a literal of the script, which arrives as UTF-16; only the pipe to the program is in question.
    const std::string script = prefix + q + nfc + q + " | & " + q + exe + q + " act=e in=" + q + T("ps.txt") + q + " out=" + q + out + q +
                               " phrase; exit $LASTEXITCODE";
    return powershell(shell, script);
  };
  auto decrypts = [&](const std::string &file) {
    RunResult r = sd(act("d", file, T("ps.out"), "phrase"), with_stdin(nfc + "\n"));
    return r.code == 0 && get(T("ps.out")) == get(T("ps.txt"));
  };
  // cmd.exe: echo writes in the code page of the console, which chcp 65001 turns into UTF-8 (the runners
  // start with 65001, so 437 is set to see the other case). Reported, not required: this is what the
  // README can say about it.
  const std::string cmd = find_program("cmd.exe");
  if (!cmd.empty()) printf("info: the code page of cmd.exe here: %s", run_program(cmd, { "/c", "chcp" }, RunOptions()).out.c_str());
  for (int i = 0; i < 2 && !cmd.empty(); i++) {
    const std::string out = T(i ? "cmd65001.bin" : "cmd.bin");
    // cmd takes a / for the start of an option: the paths need backslashes.
    auto bs = [](const std::string &path) { return replace_all(path, "/", "\\"); };
    const std::string script = std::string(i ? "chcp 65001>nul & " : "chcp 437>nul & ") + "echo " + nfc + "| " + bs(exe) + " act=e in=" + bs(T("ps.txt")) + " out=" + bs(out) + " phrase";
    RunResult r = run_program(cmd, { "/c", script }, RunOptions());
    printf("info: cmd.exe%s piped the phrase: encryption exit code %d, a file that %s with the phrase as UTF-8\n", i ? " after chcp 65001" : " after chcp 437 (the default of many installations)", r.code,
           r.code == 0 && decrypts(out) ? "decrypts" : "does not decrypt");
  }
  if (!ps5.empty()) {
    // The default of Windows PowerShell 5.1 is ASCII for what it pipes to a program: every other character is a ?.
    RunResult r = encrypt(ps5, "", T("ps5.bin"));
    printf("info: Windows PowerShell 5.1 piped the phrase as ASCII: encryption exit code %d, a file that %s with the phrase as UTF-8\n", r.code,
           r.code == 0 && decrypts(T("ps5.bin")) ? "decrypts" : "does not decrypt");
    // The advice of the README.
    r = encrypt(ps5, "$OutputEncoding = New-Object System.Text.UTF8Encoding $false; ", T("ps5u.bin"));
    need(r.code == 0, "Windows PowerShell 5.1 with a UTF-8 $OutputEncoding: encryption failed: " + r.err + r.out);
    need(decrypts(T("ps5u.bin")), "Windows PowerShell 5.1 with a UTF-8 $OutputEncoding does not give the keys of the UTF-8 phrase");
    // > writes UTF-16 with a byte order mark; the key file must still be read.
    const std::string redirect = "Get-Content -Raw " + q + R("sample.key") + q + " > " + q + T("ps5.key") + q;
    powershell(ps5, redirect);
    need(get(T("ps5.key")).compare(0, 2, B({ 0xFF, 0xFE })) == 0, "Windows PowerShell 5.1 did not write UTF-16 with >");
    sd_ok(act("dm", R("hello.sdes"), T("ps5.hello"), T("ps5.key")), "decryption with a key file written by Windows PowerShell 5.1");
    need(get(T("ps5.hello")).compare(0, 6, "Hello,") == 0, "a key file written by Windows PowerShell 5.1 decrypts to something else");
  }
  if (!ps7.empty()) {
    RunResult r = encrypt(ps7, "", T("ps7.bin"));
    need(r.code == 0, "PowerShell 7: encryption failed: " + r.err + r.out);
    need(decrypts(T("ps7.bin")), "PowerShell 7 does not pipe the phrase as UTF-8");
    powershell(ps7, "Get-Content -Raw " + q + R("sample.key") + q + " > " + q + T("ps7.key") + q);
    sd_ok(act("dm", R("hello.sdes"), T("ps7.hello"), T("ps7.key")), "decryption with a key file written by PowerShell 7");
    need(get(T("ps7.hello")).compare(0, 6, "Hello,") == 0, "a key file written by PowerShell 7 decrypts to something else");
  }
  passed("PowerShell: the pipe with a UTF-8 $OutputEncoding (and PowerShell 7 by default) gives the keys of the UTF-8 phrase; a key file written with > is read");
}
#endif

// ---- memory residue (Linux: a preloaded library searches the exited process)

std::string mask(const std::string &s)
{
  std::string hex;
  char buf[4];
  for (char c : s) { snprintf(buf, sizeof buf, "%02x", (unsigned)((unsigned char)c ^ 0x5a)); hex += buf; }
  return hex;
}

std::string maskhex(const std::string &hex)
{
  std::string o;
  char buf[4];
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    unsigned v = (unsigned)strtoul(hex.substr(i, 2).c_str(), nullptr, 16);
    snprintf(buf, sizeof buf, "%02x", v ^ 0x5au);
    o += buf;
  }
  return o;
}

// The number of marks still in the memory of the program when it exits; -1 if the scanner said nothing.
// The program is run as the current scanner says: the binary under test is replaced by the scan binary.
int scan_run(const std::string &program, const std::vector<std::string> &args, std::vector<std::string> env, const std::string &stdin_data)
{
  RunOptions o = with_stdin(stdin_data);
  env.push_back("SCAN_VERBOSE=1");
  if (!current.lib.empty()) env.push_back("LD_PRELOAD=" + current.lib);
  o.env = env;
  RunResult r = run_program(program == exe && !current.program.empty() ? current.program : program, args, o);
  size_t at = r.err.rfind("RESIDUE-SCAN: ");
  int n = at == std::string::npos ? -1 : atoi(r.err.c_str() + at + 14);
  scan_log.clear();
  if (n != 0) {
    for (char &c : r.err) if ((unsigned char)c < 32 && c != '\n') c = '.';
    scan_log = r.err.substr(0, 3000);
  }
  return n;
}

int hits(const std::string &marks, const std::string &program, const std::vector<std::string> &args, const std::string &stdin_data = std::string())
{
  return scan_run(program, args, { "SCAN_MARKS=" + marks }, stdin_data);
}

// A process that holds the mark must be found: the scan binary keeps a copy on the heap, and one on the
// stack, when it is told to; a preloaded library is shown a shell with the mark in a variable. The
// smaller of the counts is returned.
int control_hits(const std::string &marks)
{
  if (current.program.empty()) return hits(marks, "/bin/sh", { "-c", "v=SecretMarker42; :" });
  int heap = scan_run(exe, {}, { "SCAN_MARKS=" + marks, "SCAN_CONTROL=heap" }, std::string());
  int stack = scan_run(exe, {}, { "SCAN_MARKS=" + marks, "SCAN_CONTROL=stack" }, std::string());
  return heap < stack ? heap : stack;
}

void residue_with(const Scanner &sc, const std::string &nfc, const std::string &other)
{
  current = sc;
  const std::string PT = "PLAINTEXT-MARKER-XYZZY-0123456789";
  std::string rin;
  for (int i = 0; i < 10; i++) rin += PT + "\n";
  put(T("rin.txt"), rin);
  need(control_hits(mask("SecretMarker42")) > 0, "residue scanner finds nothing in a process that holds the mark (" + sc.name + ")");

  std::string key1;
  for (const std::string &l : lines_of(get(R("sample.key"))))
    if (l.size() >= 16 && l.find_first_not_of("0123456789ABCDEF") >= 16) { key1 = l.substr(0, 16); break; }
  need(key1.size() == 16, "no key in sample.key");
  const std::string kmarks = mask(key1) + "," + maskhex(key1) + "," + mask(PT);
  need(hits(kmarks, exe, act("e", T("rin.txt"), T("r.bin"), R("sample.key"))) == 0, "key or plaintext left in memory after key file encryption");
  need(hits(kmarks, exe, act("d", T("r.bin"), T("r.out"), R("sample.key"))) == 0, "key or plaintext left in memory after key file decryption");
  need(get(T("r.out")) == rin, "residue test round trip");
  put(T("scankey"), "a5c3e1f0d2b49687\n1122334455667788\n99aabbccddeeff00\n0011223344556677\n"
                    "13579bdf02468ace\na1b2c3d4e5f60718\n0f1e2d3c4b5a6978\nfedcba9876543210\n");
  const std::string wmarks = mask("a5c3e1f0d2b49687") + "," + maskhex("a5c3e1f0d2b49687") + "," + mask(PT);
  need(hits(wmarks, exe, act("d", T("r.bin"), T("x"), T("scankey"))) == 0, "key left in memory after authentication failure");
  passed("no key or plaintext left in memory, also after an error");

  // A phrase longer than the 4096-byte read buffer, so that the buffer grows; random, so that a stale
  // partial copy is recognisable by 16 bytes taken from the start and from the middle.
  const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string lng;
  for (int i = 0; i < 5000; i++) lng += alphabet[rng() % alphabet.size()];
  const std::string pmarks = mask(lng.substr(0, 16)) + "," + mask(lng.substr(2500, 16)) + "," + mask(PT);
  need(hits(pmarks, exe, act("e", T("rin.txt"), T("lp.bin"), "phrase"), lng + "\n") == 0, "phrase or plaintext left in memory after encryption");
  need(hits(pmarks, exe, act("d", T("lp.bin"), T("lp.out"), "phrase"), lng + "\n") == 0, "phrase or plaintext left in memory after decryption");
  need(get(T("lp.out")) == rin, "residue test phrase round trip");
  need(hits(pmarks, exe, act("d", T("lp.bin"), T("x"), "phrase"), lng.substr(0, 4999) + "\n") == 0, "phrase left in memory after authentication failure");
  passed("no phrase left in memory, also after an error; a 5000-character phrase round-trips");

  // A phrase outside ASCII goes through the normalisation, which holds it as code points too. The marks:
  // the Japanese part of the phrase as UTF-8, and its first four characters as 32-bit values.
  const std::string umarks = maskhex("e697a5e69cace8aa9ee381aee38386e382b9e38388") + "," + maskhex("e56500002c6700009e8a00006e300000") + "," + mask(PT);
  need(hits(umarks, exe, act("e", T("rin.txt"), T("up.bin"), "phrase"), other + "\r\n") == 0, "non-ASCII phrase or plaintext left in memory after encryption");
  need(hits(umarks, exe, act("d", T("up.bin"), T("up.out"), "phrase"), nfc + "\n") == 0, "non-ASCII phrase or plaintext left in memory after decryption");
  need(get(T("up.out")) == rin, "residue test non-ASCII round trip");
  passed(("no phrase left in memory after its normalisation (" + sc.name + ")").c_str());
}

void residue(const std::string &nfc, const std::string &other)
{
  if (scanners.empty()) {
    skipped("memory residue scan (no scanner given: a sanitizer build, or a system without one)");
    return;
  }
  for (const Scanner &sc : scanners) residue_with(sc, nfc, other);
}

// ---- files and phrases that travel between operating systems (PORTPLAN.md todo 11)
//
// Every OS makes files with its own build of the program, and every OS opens the files of all of them,
// which is what "interchange" means. The CI job uploads what --interop-make wrote and runs
// --interop-check with everything. The text has every byte value and all three line endings, so that
// nothing along the way may touch it.

std::string interop_plain()
{
  std::string s;
  for (int i = 0; i < 70001; i++) s += (char)((i * 7 + i / 256) & 0xFF);
  return s + "\r\nline\rline\n";
}

enum InteropKey { KEY_FILE, ASCII_PHRASE, NFC_PHRASE };
struct InteropCase {
  const char *name;
  bool armored;
  InteropKey key;
  bool shell;  // made through PowerShell or cmd.exe: Windows only
};
const InteropCase interop_cases[] = {
  { "binary-keyfile", false, KEY_FILE, false },
  { "armored-keyfile", true, KEY_FILE, false },
  { "binary-ascii-phrase", false, ASCII_PHRASE, false },
  { "armored-ascii-phrase", true, ASCII_PHRASE, false },
  { "binary-nfc-phrase", false, NFC_PHRASE, false },
  { "armored-nfc-phrase", true, NFC_PHRASE, false },
  { "armored-other-phrase", true, NFC_PHRASE, false },  // made with the same text typed another way, read with the NFC form
  { "ps51-keyfile", false, KEY_FILE, true },              // the key file written by Windows PowerShell 5.1 with >: UTF-16
  { "ps51-utf8-phrase", false, NFC_PHRASE, true },
  { "ps7-keyfile", false, KEY_FILE, true },
  { "ps7-phrase", false, NFC_PHRASE, true },
  { "cmd-phrase", false, NFC_PHRASE, true },
};
const std::string interop_ascii_phrase = "The quick brown fox jumps over the lazy dog, again and again.";

long long milliseconds_since(std::chrono::steady_clock::time_point t0)
{
  return (long long)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
}

void interop_make(const std::string &dir, const std::string &label)
{
  need(make_dir(dir) || is_directory(dir), "cannot make the directory " + dir);
  tmp = make_temp_dir();
  need(!tmp.empty(), "cannot make a temporary directory");
  const std::string plain = interop_plain();
  put(T("plain.bin"), plain);
  auto out_of = [&](const InteropCase &c) { return dir + "/" + label + "." + c.name + ".sdes"; };
  auto made = [&](const InteropCase &c, long long ms) { printf("ok: %s %s (%lld ms)\n", label.c_str(), c.name, ms); };
  for (const InteropCase &c : interop_cases) {
    if (c.shell) continue;
    const std::string phrase = c.key == ASCII_PHRASE ? interop_ascii_phrase : strcmp(c.name, "armored-other-phrase") == 0 ? other_phrase() : nfc_phrase();
    auto t0 = std::chrono::steady_clock::now();
    sd_ok(act(c.armored ? "em" : "e", T("plain.bin"), out_of(c), c.key == KEY_FILE ? R("sample.key") : "phrase"), label + " " + c.name,
          with_stdin(c.key == KEY_FILE ? std::string() : phrase + "\n"));
    made(c, milliseconds_since(t0));
  }
#ifdef _WIN32
  const std::string ps5 = find_program("powershell.exe"), ps7 = find_program("pwsh.exe"), cmd = find_program("cmd.exe");
  const std::string q = "'";
  auto shell_case = [&](const char *name, const std::string &shell, const std::string &script) {
    for (const InteropCase &c : interop_cases) {
      if (strcmp(c.name, name) != 0) continue;
      auto t0 = std::chrono::steady_clock::now();
      RunResult r = run_program(shell, { "-NoProfile", "-NonInteractive", "-Command", script }, RunOptions());
      need(r.code == 0, label + " " + name + ": " + r.err + r.out);
      need(file_exists(out_of(c)), label + " " + name + ": no file");
      made(c, milliseconds_since(t0));
    }
  };
  auto key_file_case = [&](const char *name, const std::string &shell, const std::string &key) {
    run_program(shell, { "-NoProfile", "-NonInteractive", "-Command", "Get-Content -Raw " + q + R("sample.key") + q + " > " + q + key + q }, RunOptions());
    for (const InteropCase &c : interop_cases) {
      if (strcmp(c.name, name) != 0) continue;
      auto t0 = std::chrono::steady_clock::now();
      sd_ok(act("e", T("plain.bin"), out_of(c), key), label + " " + name);
      made(c, milliseconds_since(t0));
    }
  };
  auto piped = [&](const std::string &prefix, const std::string &out) {
    return prefix + q + nfc_phrase() + q + " | & " + q + exe + q + " act=e in=" + q + T("plain.bin") + q + " out=" + q + out + q + " phrase; exit $LASTEXITCODE";
  };
  auto path_of = [&](const char *name) {
    for (const InteropCase &c : interop_cases)
      if (strcmp(c.name, name) == 0) return out_of(c);
    return std::string();
  };
  if (!ps5.empty()) {
    key_file_case("ps51-keyfile", ps5, T("ps5.key"));
    shell_case("ps51-utf8-phrase", ps5, piped("$OutputEncoding = New-Object System.Text.UTF8Encoding $false; ", path_of("ps51-utf8-phrase")));
  } else skipped(label + ": Windows PowerShell 5.1 is not installed");
  if (!ps7.empty()) {
    key_file_case("ps7-keyfile", ps7, T("ps7.key"));
    shell_case("ps7-phrase", ps7, piped("", path_of("ps7-phrase")));
  } else skipped(label + ": PowerShell 7 is not installed");
  if (!cmd.empty()) {
    auto bs = [](const std::string &path) { return replace_all(path, "/", "\\"); };
    auto t0 = std::chrono::steady_clock::now();
    const std::string script = "chcp 65001>nul & echo " + nfc_phrase() + "| " + bs(exe) + " act=e in=" + bs(T("plain.bin")) + " out=" + bs(path_of("cmd-phrase")) + " phrase";
    RunResult r = run_program(cmd, { "/c", script }, RunOptions());
    need(r.code == 0 && file_exists(path_of("cmd-phrase")), label + " cmd-phrase: " + r.err + r.out);
    for (const InteropCase &c : interop_cases)
      if (strcmp(c.name, "cmd-phrase") == 0) made(c, milliseconds_since(t0));
  } else skipped(label + ": cmd.exe not found");
#endif
  remove_tree(tmp);
}

// Opens every file in `dir` (named <label>.<case>.sdes) and compares it with the text it was made from;
// every label in `labels` must have all the portable cases, and the Windows ones also those of the shells.
void interop_check(const std::string &dir, const std::string &labels)
{
  tmp = make_temp_dir();
  need(!tmp.empty(), "cannot make a temporary directory");
  const std::string plain = interop_plain();
  std::vector<std::string> names;
  need(list_dir(dir, names), "cannot read the directory " + dir);
  std::set<std::string> seen;
  int failures = 0;
  for (const std::string &file : names) {
    const std::string tail = ".sdes";
    if (file.size() <= tail.size() || file.compare(file.size() - tail.size(), tail.size(), tail) != 0) continue;
    const size_t dot = file.find('.');
    const std::string label = file.substr(0, dot), name = file.substr(dot + 1, file.size() - tail.size() - dot - 1);
    const InteropCase *found = nullptr;
    for (const InteropCase &c : interop_cases)
      if (name == c.name) found = &c;
    if (!found) {
      printf("FAIL: %s: not a case that is known\n", file.c_str());
      failures++;
      continue;
    }
    seen.insert(file);
    const std::string phrase = found->key == ASCII_PHRASE ? interop_ascii_phrase : nfc_phrase();
    auto t0 = std::chrono::steady_clock::now();
    RunResult r = sd(act(found->armored ? "dm" : "d", dir + "/" + file, T("out.bin"), found->key == KEY_FILE ? R("sample.key") : "phrase"),
                     with_stdin(found->key == KEY_FILE ? std::string() : phrase + "\n"));
    std::string got;
    if (r.code == 0 && slurp(T("out.bin"), got) && got == plain) printf("ok: %s (%lld ms)\n", file.c_str(), milliseconds_since(t0));
    else {
      printf("FAIL: %s (exit code %d, %zu bytes): %s\n", file.c_str(), r.code, got.size(), r.err.c_str());
      failures++;
    }
    remove_file(T("out.bin"));
  }
  for (size_t at = 0; at < labels.size();) {
    size_t comma = labels.find(',', at);
    if (comma == std::string::npos) comma = labels.size();
    const std::string label = labels.substr(at, comma - at);
    at = comma + 1;
    for (const InteropCase &c : interop_cases) {
      if (c.shell && label.compare(0, 7, "windows") != 0) continue;
      if (!seen.count(label + "." + c.name + ".sdes")) {
        printf("FAIL: the file %s.%s.sdes is missing\n", label.c_str(), c.name);
        failures++;
      }
    }
  }
  remove_tree(tmp);
  need(failures == 0, std::to_string(failures) + " files of other systems do not open here");
  printf("ok: %zu files of other systems open here\n", seen.size());
}

}  // namespace

int main(int argc, char **argv)
{
  if (argc == 2 && strcmp(argv[1], "--nfc-phrase") == 0) {
    fputs(nfc_phrase().c_str(), stdout);
    return 0;
  }
  if (argc < 3) {
    fprintf(stderr, "usage: test_e2e <sillydes binary> <source root> [--scan-lib <residue_scan.so>] [--scan-exe <sillydes_scan>] [--no-address-limit]\n");
    return 2;
  }
  exe = argv[1];
  root = argv[2];
  if (argc == 6 && strcmp(argv[3], "--interop-make") == 0) {
    interop_make(argv[4], argv[5]);
    return 0;
  }
  if (argc == 6 && strcmp(argv[3], "--interop-check") == 0) {
    interop_check(argv[4], argv[5]);
    return 0;
  }
  for (int i = 3; i < argc; i++) {
    if (strcmp(argv[i], "--no-address-limit") == 0) use_limit = false;
    else if (strcmp(argv[i], "--scan-lib") == 0 && i + 1 < argc) scanners.push_back({ "preloaded library", argv[++i], std::string() });
    else if (strcmp(argv[i], "--scan-exe") == 0 && i + 1 < argc) scanners.push_back({ "scan binary", std::string(), argv[++i] });
    else {
      fprintf(stderr, "unknown argument %s\n", argv[i]);
      return 2;
    }
  }
  tmp = make_temp_dir();
  need(!tmp.empty(), "cannot make a temporary directory");

  const std::string phrase = "The quick brown fox jumps over the lazy dog, again and again.";
  const std::string nfc = nfc_phrase(), other = other_phrase();
  golden_files(phrase, nfc);
  round_trips();
  phrases(phrase);
  wrong_keys();
  block_tests();
  wrong_phrase();
  text_interchange(phrase, nfc, other);
  refused_phrases();
  data_is_bytes();
  same_file();
  sources_are_ascii();
  messages_are_utf8();
  terminal_tests(nfc);
#ifdef _WIN32
  powershell_tests(nfc);
#endif
  residue(nfc, other);

  remove_tree(tmp);
  puts("all tests passed");
  return 0;
}
