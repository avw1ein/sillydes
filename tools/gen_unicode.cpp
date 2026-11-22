// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Andy van Wezel
//
// Generates src/unicode_tables.h: the data that src/text.cpp needs to bring a phrase into its
// canonical form (compatibility decompositions, combining classes, composition pairs and the
// default-ignorable code points), taken from the Unicode Character Database.
//
//   tools/gen_unicode DIRECTORY LICENSE.Unicode > src/unicode_tables.h     (or: the CMake target regenerate_unicode)
//
// DIRECTORY holds UnicodeData.txt, DerivedNormalizationProps.txt and DerivedCoreProperties.txt of
// one Unicode version (tools/fetch_ucd.sh downloads them); the second argument is the notice the
// data comes under, which is copied into the output. The output is committed, and it is part of
// the file format: see the comment it writes at the top.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace {

typedef std::vector<uint32_t> Seq;

std::map<uint32_t, Seq> mapping;    // one step of decomposition, canonical or compatibility
std::set<uint32_t> canonical;       // the code points whose mapping is canonical
std::map<uint32_t, int> ccc;        // combining classes other than 0
std::set<uint32_t> excluded;        // Full_Composition_Exclusion
std::set<uint32_t> ignorable;       // Default_Ignorable_Code_Point

[[noreturn]] void fail(const std::string &what)
{
  fprintf(stderr, "gen_unicode: %s\n", what.c_str());
  exit(1);
}

std::vector<std::string> lines(const std::string &name)
{
  std::ifstream f(name.c_str());
  if (!f) fail("cannot read " + name);
  std::vector<std::string> v;
  for (std::string s; std::getline(f, s);) {
    if (!s.empty() && s[s.size() - 1] == '\r') s.erase(s.size() - 1);
    v.push_back(s);
  }
  return v;
}

std::vector<std::string> split(const std::string &s, char sep)
{
  std::vector<std::string> v(1);
  for (char c : s) {
    if (c == sep) v.push_back("");
    else v.back() += c;
  }
  return v;
}

uint32_t hexval(const std::string &s)
{
  char *end = nullptr;
  unsigned long v = strtoul(s.c_str(), &end, 16);
  if (s.empty() || *end || v > 0x10FFFF) fail("not a code point: " + s);
  return (uint32_t)v;
}

// "# Name-18.0.0.txt" on the first line of a derived file.
std::string version_of(const std::vector<std::string> &file, const std::string &name)
{
  const std::string head = "# " + name + "-", tail = ".txt";
  if (file.empty() || file[0].compare(0, head.size(), head) != 0 || file[0].size() <= head.size() + tail.size())
    fail(name + ".txt does not start with its name and version");
  return file[0].substr(head.size(), file[0].size() - head.size() - tail.size());
}

// The code points that a derived file gives the property `prop`.
std::set<uint32_t> property(const std::vector<std::string> &file, const std::string &prop)
{
  std::set<uint32_t> out;
  for (const std::string &raw : file) {
    std::string s = raw.substr(0, raw.find('#'));
    std::vector<std::string> f = split(s, ';');
    if (f.size() < 2) continue;
    std::string range, name;
    for (char c : f[0]) if (c != ' ') range += c;
    for (char c : f[1]) if (c != ' ') name += c;
    if (name != prop) continue;
    size_t dots = range.find("..");
    uint32_t lo = hexval(range.substr(0, dots)), hi = dots == std::string::npos ? lo : hexval(range.substr(dots + 2));
    for (uint32_t c = lo; c <= hi; c++) out.insert(c);
  }
  if (out.empty()) fail("no code point has the property " + prop);
  return out;
}

void expand(uint32_t c, Seq &out)
{
  std::map<uint32_t, Seq>::const_iterator m = mapping.find(c);
  if (m == mapping.end()) { out.push_back(c); return; }
  for (uint32_t d : m->second) expand(d, out);
}

// Consecutive code points with the same value become one range.
template <class Value>
std::vector<std::pair<std::pair<uint32_t, uint32_t>, Value>> ranges(const std::map<uint32_t, Value> &m)
{
  std::vector<std::pair<std::pair<uint32_t, uint32_t>, Value>> out;
  for (const auto &e : m) {
    if (!out.empty() && out.back().first.second + 1 == e.first && out.back().second == e.second) out.back().first.second = e.first;
    else out.push_back(std::make_pair(std::make_pair(e.first, e.first), e.second));
  }
  return out;
}

}  // namespace

int main(int argc, char *argv[])
{
  if (argc != 3) fail("usage: gen_unicode DIRECTORY LICENSE.Unicode > src/unicode_tables.h");
  const std::string dir = std::string(argv[1]) + "/";

  const std::vector<std::string> norm = lines(dir + "DerivedNormalizationProps.txt");
  const std::vector<std::string> core = lines(dir + "DerivedCoreProperties.txt");
  const std::string version = version_of(norm, "DerivedNormalizationProps");
  if (version_of(core, "DerivedCoreProperties") != version) fail("the data files are of different Unicode versions");
  excluded = property(norm, "Full_Composition_Exclusion");
  ignorable = property(core, "Default_Ignorable_Code_Point");

  // UnicodeData.txt carries no version; the caller keeps the files of one version together.
  for (const std::string &s : lines(dir + "UnicodeData.txt")) {
    std::vector<std::string> f = split(s, ';');
    if (f.size() < 6) continue;
    uint32_t c = hexval(f[0]);
    int cls = atoi(f[3].c_str());
    if (cls < 0 || cls > 254) fail("combining class out of range at " + f[0]);
    if (cls) ccc[c] = cls;
    if (f[5].empty()) continue;
    std::vector<std::string> d = split(f[5], ' ');
    size_t first = 0;
    if (d[0][0] == '<') first = 1;
    else canonical.insert(c);
    Seq seq;
    for (size_t i = first; i < d.size(); i++) seq.push_back(hexval(d[i]));
    if (seq.empty()) fail("empty decomposition at " + f[0]);
    mapping[c] = seq;
  }
  if (mapping.count(0xAC00) || !mapping.count(0x00C5)) fail("UnicodeData.txt is not what was expected");

  // Full compatibility decomposition (NFKD) of every code point that has a mapping.
  std::vector<uint32_t> pool;
  struct Entry { uint32_t cp, pos, len; };
  std::vector<Entry> decomp;
  size_t longest = 0;
  for (const auto &m : mapping) {
    Seq full;
    expand(m.first, full);
    for (uint32_t d : full)
      if (d >= 0xAC00 && d < 0xAC00 + 11172) fail("a decomposition contains a Hangul syllable");
    decomp.push_back(Entry{ m.first, (uint32_t)pool.size(), (uint32_t)full.size() });
    pool.insert(pool.end(), full.begin(), full.end());
    if (full.size() > longest) longest = full.size();
  }
  if (pool.size() > 0xFFFF || longest > 0xFFFF) fail("the decomposition pool does not fit 16-bit offsets");

  // Primary composites: canonical pairs that are not excluded from composition.
  std::map<std::pair<uint32_t, uint32_t>, uint32_t> pairs;
  for (uint32_t c : canonical) {
    if (excluded.count(c)) continue;
    const Seq &d = mapping[c];
    if (d.size() != 2) fail("a primary composite does not decompose into two code points");
    if (!pairs.insert(std::make_pair(std::make_pair(d[0], d[1]), c)).second) fail("two composites share one pair");
  }

  std::map<uint32_t, int> ign;
  for (uint32_t c : ignorable) ign[c] = 1;
  const auto cccr = ranges(ccc);
  const auto ignr = ranges(ign);

  printf("// SPDX-License-Identifier: Unicode-3.0\n//\n");
  printf("// GENERATED by tools/gen_unicode.cpp (target regenerate_unicode); do not edit.\n");
  printf("// Normalisation data of the Unicode Character Database, version %s.\n//\n", version.c_str());
  printf("// These tables are part of the file format: the canonical form of a phrase is computed with\n");
  printf("// them, so other tables give other keys for some phrases. They change only together with\n");
  printf("// FORMAT_NAME in version.h; test_primitives checks their hash.\n//\n");
  printf("// Derived from UnicodeData.txt, DerivedNormalizationProps.txt and DerivedCoreProperties.txt,\n");
  printf("// which come under this notice:\n//\n");
  for (const std::string &raw : lines(argv[2])) {
    std::string s;
    for (size_t i = 0; i < raw.size(); i++) {
      unsigned char c = (unsigned char)raw[i];
      if (c == 0xC2 && i + 1 < raw.size() && (unsigned char)raw[i + 1] == 0xA9) { s += "(c)"; i++; }
      else if (c >= 0x80 || (c < 0x20 && c != '\t')) fail("the notice holds a character that cannot be written in ASCII");
      else s += (char)c;
    }
    if (s.empty()) printf("//\n");
    else printf("// %s\n", s.c_str());
  }
  printf("#pragma once\n\n#include <cstdint>\n\n");
  printf("#define UNICODE_VERSION \"%s\"\n\n", version.c_str());

  printf("// Full compatibility decomposition (NFKD) of the code points that have one, at UNI_DECOMP_POOL[pos]\n");
  printf("// and len code points long. Hangul syllables are not listed; they are computed.\n");
  printf("struct UniDecomp { uint32_t cp; uint16_t pos, len; };\n");
  printf("static const uint32_t UNI_DECOMP_POOL[%zu] = {", pool.size());
  for (size_t i = 0; i < pool.size(); i++) printf("%s0x%X,", i % 12 ? " " : "\n  ", pool[i]);
  printf("\n};\nstatic const UniDecomp UNI_DECOMP[%zu] = {", decomp.size());
  for (size_t i = 0; i < decomp.size(); i++) printf("%s{0x%X, %u, %u},", i % 6 ? " " : "\n  ", decomp[i].cp, decomp[i].pos, decomp[i].len);
  printf("\n};\n\n");

  printf("// Canonical combining class; code points outside these ranges have class 0.\n");
  printf("struct UniClass { uint32_t first, last; uint8_t ccc; };\n");
  printf("static const UniClass UNI_CCC[%zu] = {", cccr.size());
  for (size_t i = 0; i < cccr.size(); i++) printf("%s{0x%X, 0x%X, %d},", i % 5 ? " " : "\n  ", cccr[i].first.first, cccr[i].first.second, cccr[i].second);
  printf("\n};\n\n");

  printf("// Primary composites, sorted by first and then second: first + second compose into composed.\n");
  printf("struct UniPair { uint32_t first, second, composed; };\n");
  printf("static const UniPair UNI_COMPOSE[%zu] = {", pairs.size());
  size_t n = 0;
  for (const auto &p : pairs) printf("%s{0x%X, 0x%X, 0x%X},", n++ % 5 ? " " : "\n  ", p.first.first, p.first.second, p.second);
  printf("\n};\n\n");

  printf("// Default_Ignorable_Code_Point: invisible characters, removed from a phrase.\n");
  printf("struct UniRange { uint32_t first, last; };\n");
  printf("static const UniRange UNI_IGNORABLE[%zu] = {", ignr.size());
  for (size_t i = 0; i < ignr.size(); i++) printf("%s{0x%X, 0x%X},", i % 6 ? " " : "\n  ", ignr[i].first.first, ignr[i].first.second);
  printf("\n};\n");

  fprintf(stderr, "gen_unicode: Unicode %s: %zu decompositions (%zu code points, longest %zu), %zu combining class ranges, "
          "%zu composition pairs, %zu ignorable ranges\n", version.c_str(), decomp.size(), pool.size(), longest, cccr.size(), pairs.size(), ignr.size());
  return 0;
}
