// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Andy van Wezel
//
// Checks the normalisation in src/text.cpp and the tables in src/unicode_tables.h against the
// conformance file of the Unicode Character Database:
//
//   test/unicode_conformance DIRECTORY/NormalizationTest.txt      (or: make unicode-check UCD=DIRECTORY)
//
// The file is not part of the repository, so this is not part of `make test`; run it whenever the
// tables or the normalisation change. It checks that
//   - every line of the file gives its NFKC column, from each of its five columns;
//   - every code point that part 1 of the file does not list is left alone by NFKC;
//   - the folding of a phrase (NFKC without the default-ignorable code points) gives one result for
//     the five columns of a line, holds no ignorable code point, and does nothing when it is
//     applied a second time, for every line and for every single code point.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "text.h"
#include "unicode_tables.h"

namespace {

typedef std::vector<uint32_t> Seq;

long fails;

void fail(const char *what, const Seq &in)
{
  if (fails++ < 20) {
    printf("FAIL: %s:", what);
    for (uint32_t c : in) printf(" %04X", c);
    printf("\n");
  }
}

Seq fold(const Seq &in, bool drop)
{
  static CodePoints work;
  work.assign(in.begin(), in.end());
  normalize(work, drop);
  return Seq(work.begin(), work.end());
}

bool is_ignorable(uint32_t c)
{
  for (const UniRange &r : UNI_IGNORABLE)
    if (c >= r.first && c <= r.last) return true;
  return false;
}

void check_fold(const Seq &in, const Seq *same_as)
{
  Seq f = fold(in, true);
  if (fold(f, true) != f) fail("folding twice differs from folding once", in);
  for (uint32_t c : f)
    if (is_ignorable(c)) { fail("an ignorable code point is left", in); break; }
  if (same_as && f != *same_as) fail("the columns of a line fold differently", in);
}

}  // namespace

int main(int argc, char *argv[])
{
  if (argc != 2) { fprintf(stderr, "usage: unicode_conformance NormalizationTest.txt\n"); return 2; }
  std::ifstream file(argv[1]);
  if (!file) { fprintf(stderr, "unicode_conformance: cannot read %s\n", argv[1]); return 2; }

  std::string line;
  std::getline(file, line);
  const std::string want = "# NormalizationTest-" UNICODE_VERSION ".txt";
  if (line.compare(0, want.size(), want) != 0) {
    fprintf(stderr, "unicode_conformance: %s is not the file of Unicode " UNICODE_VERSION ", which the tables are made of\n", argv[1]);
    return 2;
  }

  std::vector<bool> listed(0x110000, false);
  bool part1 = false;
  long cases = 0;
  while (std::getline(file, line)) {
    if (line.empty() || line[0] == '#') continue;
    if (line[0] == '@') { part1 = line.compare(0, 6, "@Part1") == 0; continue; }
    Seq col[5];
    const char *p = line.c_str();
    for (int k = 0; k < 5; k++) {
      while (*p && *p != ';') {
        char *end;
        col[k].push_back((uint32_t)strtoul(p, &end, 16));
        if (end == p) { fprintf(stderr, "unicode_conformance: cannot parse: %s\n", line.c_str()); return 2; }
        p = end;
        while (*p == ' ') p++;
      }
      if (*p != ';') { fprintf(stderr, "unicode_conformance: cannot parse: %s\n", line.c_str()); return 2; }
      p++;
    }
    cases++;
    if (part1 && col[0].size() == 1) listed[col[0][0]] = true;
    for (int k = 0; k < 5; k++)
      if (fold(col[k], false) != col[3]) fail("NFKC of a column is not column 4", col[k]);
    const Seq folded = fold(col[0], true);
    for (int k = 0; k < 5; k++) check_fold(col[k], &folded);
  }
  if (cases < 15000) { printf("FAIL: only %ld cases read\n", cases); fails++; }

  long alone = 0;
  for (uint32_t c = 0; c < 0x110000; c++) {
    if (c >= 0xD800 && c <= 0xDFFF) continue;
    const Seq one(1, c);
    if (!listed[c]) {
      alone++;
      if (fold(one, false) != one) fail("NFKC changes a code point that part 1 does not list", one);
    }
    check_fold(one, nullptr);
  }

  if (fails) { printf("%ld failure(s)\n", fails); return 1; }
  printf("ok: Unicode " UNICODE_VERSION ": %ld conformance cases; %ld other code points unchanged by NFKC; "
         "phrase folding consistent, free of ignorable code points and stable\n", cases, alone);
  return 0;
}
