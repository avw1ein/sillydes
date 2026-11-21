// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Andy van Wezel

#include "text.h"

#include "unicode_tables.h"

namespace {

// Hangul syllables are decomposed and composed by arithmetic (Unicode Standard, section 3.12).
const uint32_t S_BASE = 0xAC00, L_BASE = 0x1100, V_BASE = 0x1161, T_BASE = 0x11A7;
const uint32_t L_COUNT = 19, V_COUNT = 21, T_COUNT = 28, S_COUNT = L_COUNT * V_COUNT * T_COUNT;

// While a phrase is being reordered, a code point carries its combining class in the top byte.
const uint32_t CODE_MASK = 0x1FFFFF;
const int CLASS_SHIFT = 24;

// Everything below U+00A0 has no decomposition, class 0 and is not ignorable.
const uint32_t PLAIN_BELOW = 0xA0;

const UniDecomp *decomposition(uint32_t c)
{
  size_t lo = 0, hi = sizeof UNI_DECOMP / sizeof UNI_DECOMP[0];
  while (lo < hi) {
    size_t mid = (lo + hi) / 2;
    if (UNI_DECOMP[mid].cp < c) lo = mid + 1;
    else hi = mid;
  }
  return lo < sizeof UNI_DECOMP / sizeof UNI_DECOMP[0] && UNI_DECOMP[lo].cp == c ? &UNI_DECOMP[lo] : nullptr;
}

uint32_t combining_class(uint32_t c)
{
  if (c < PLAIN_BELOW) return 0;
  size_t lo = 0, hi = sizeof UNI_CCC / sizeof UNI_CCC[0];
  while (lo < hi) {
    size_t mid = (lo + hi) / 2;
    if (UNI_CCC[mid].last < c) lo = mid + 1;
    else hi = mid;
  }
  return lo < sizeof UNI_CCC / sizeof UNI_CCC[0] && UNI_CCC[lo].first <= c ? UNI_CCC[lo].ccc : 0;
}

bool ignorable(uint32_t c)
{
  if (c < PLAIN_BELOW) return false;
  size_t lo = 0, hi = sizeof UNI_IGNORABLE / sizeof UNI_IGNORABLE[0];
  while (lo < hi) {
    size_t mid = (lo + hi) / 2;
    if (UNI_IGNORABLE[mid].last < c) lo = mid + 1;
    else hi = mid;
  }
  return lo < sizeof UNI_IGNORABLE / sizeof UNI_IGNORABLE[0] && UNI_IGNORABLE[lo].first <= c;
}

// The code point that a and b compose into, or 0.
uint32_t compose(uint32_t a, uint32_t b)
{
  if (a - L_BASE < L_COUNT && b - V_BASE < V_COUNT) return S_BASE + ((a - L_BASE) * V_COUNT + (b - V_BASE)) * T_COUNT;
  if (a - S_BASE < S_COUNT && (a - S_BASE) % T_COUNT == 0 && b - T_BASE - 1 < T_COUNT - 1) return a + (b - T_BASE);
  size_t lo = 0, hi = sizeof UNI_COMPOSE / sizeof UNI_COMPOSE[0];
  while (lo < hi) {
    size_t mid = (lo + hi) / 2;
    const UniPair &p = UNI_COMPOSE[mid];
    if (p.first < a || (p.first == a && p.second < b)) lo = mid + 1;
    else hi = mid;
  }
  if (lo < sizeof UNI_COMPOSE / sizeof UNI_COMPOSE[0] && UNI_COMPOSE[lo].first == a && UNI_COMPOSE[lo].second == b) return UNI_COMPOSE[lo].composed;
  return 0;
}

// Well-formed UTF-8 only (Unicode Standard, table 3-7): shortest form, no surrogates, at most U+10FFFF.
bool utf8_decode(const uint8_t *p, size_t n, CodePoints &out)
{
  out.clear();
  out.reserve(n);
  for (size_t i = 0; i < n;) {
    uint32_t c = p[i++];
    if (c >= 0x80) {
      int more;
      uint32_t least;
      if (c >= 0xC2 && c <= 0xDF) { more = 1; least = 0x80; c &= 0x1F; }
      else if (c >= 0xE0 && c <= 0xEF) { more = 2; least = 0x800; c &= 0x0F; }
      else if (c >= 0xF0 && c <= 0xF4) { more = 3; least = 0x10000; c &= 0x07; }
      else return false;
      for (; more > 0; more--) {
        if (i == n || (p[i] & 0xC0) != 0x80) return false;
        c = (c << 6) | (p[i++] & 0x3F);
      }
      if (c < least || c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF)) return false;
    }
    out.push_back(c);
  }
  return true;
}

void utf8_encode(const CodePoints &cp, SecretBuf &out)
{
  out.clear();
  for (uint32_t c : cp) {
    if (c < 0x80) out.push_back((uint8_t)c);
    else if (c < 0x800) {
      out.push_back((uint8_t)(0xC0 | (c >> 6)));
      out.push_back((uint8_t)(0x80 | (c & 0x3F)));
    } else if (c < 0x10000) {
      out.push_back((uint8_t)(0xE0 | (c >> 12)));
      out.push_back((uint8_t)(0x80 | ((c >> 6) & 0x3F)));
      out.push_back((uint8_t)(0x80 | (c & 0x3F)));
    } else {
      out.push_back((uint8_t)(0xF0 | (c >> 18)));
      out.push_back((uint8_t)(0x80 | ((c >> 12) & 0x3F)));
      out.push_back((uint8_t)(0x80 | ((c >> 6) & 0x3F)));
      out.push_back((uint8_t)(0x80 | (c & 0x3F)));
    }
  }
}

bool is_control(uint32_t c) { return c < 0x20 || (c >= 0x7F && c <= 0x9F); }

}  // namespace

size_t decode_text(uint8_t *p, size_t n)
{
  if (n >= 3 && p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF) {
    for (size_t i = 3; i < n; i++) p[i - 3] = p[i];
    return n - 3;
  }
  bool le = n >= 2 && p[0] == 0xFF && p[1] == 0xFE, be = n >= 2 && p[0] == 0xFE && p[1] == 0xFF;
  if (!le && !be) return n;
  size_t out = 0;
  for (size_t i = 2; i + 1 < n; i += 2) {
    uint8_t hi = le ? p[i + 1] : p[i], lo = le ? p[i] : p[i + 1];
    p[out++] = hi == 0 && lo < 0x80 ? lo : (uint8_t)'?';
  }
  return out;
}

// UAX #15. The intermediate copies live in locked buffers that are wiped when they are released.
void normalize(CodePoints &cp, bool drop_ignorable)
{
  CodePoints d;
  d.reserve(cp.size() + cp.size() / 2 + 16);
  for (uint32_t c : cp) {
    if (c < PLAIN_BELOW) {
      d.push_back(c);
    } else if (c - S_BASE < S_COUNT) {
      uint32_t s = c - S_BASE;
      d.push_back(L_BASE + s / (V_COUNT * T_COUNT));
      d.push_back(V_BASE + s % (V_COUNT * T_COUNT) / T_COUNT);
      if (s % T_COUNT) d.push_back(T_BASE + s % T_COUNT);
    } else {
      const UniDecomp *e = decomposition(c);
      const uint32_t *part = e ? UNI_DECOMP_POOL + e->pos : &c;
      for (size_t i = 0, len = e ? e->len : 1; i < len; i++)
        if (!drop_ignorable || !ignorable(part[i])) d.push_back(part[i] | combining_class(part[i]) << CLASS_SHIFT);
    }
  }

  // Canonical ordering: a stable sort of every run of combining marks by class.
  for (size_t i = 1; i < d.size(); i++) {
    uint32_t x = d[i], cls = x >> CLASS_SHIFT;
    if (cls == 0) continue;
    size_t j = i;
    for (; j > 0 && (d[j - 1] >> CLASS_SHIFT) > cls; j--) d[j] = d[j - 1];
    d[j] = x;
  }

  // Canonical composition: a mark joins the last starter unless a mark of the same or a higher
  // class, or another starter, stands in between.
  size_t n = d.size(), w = 0;
  if (n) {
    size_t starter = 0;
    uint32_t last = d[0] >> CLASS_SHIFT;
    if (last) last = 256;  // the text begins with a mark: nothing composes with it
    d[0] &= CODE_MASK;
    w = 1;
    for (size_t i = 1; i < n; i++) {
      uint32_t c = d[i] & CODE_MASK, cls = d[i] >> CLASS_SHIFT;
      uint32_t joined = compose(d[starter], c);
      if (joined && (last < cls || last == 0)) {
        d[starter] = joined;
      } else {
        if (cls == 0) starter = w;
        last = cls;
        d[w++] = c;
      }
    }
  }
  d.resize(w);
  cp.swap(d);
}

PhraseFault canonical_phrase(SecretBuf &s)
{
  if (!s.empty() && s.back() == '\r') s.pop_back();
  bool ascii = true;
  for (uint8_t b : s) ascii = ascii && b < 0x80;
  size_t count;
  if (ascii) {  // nothing to normalise, and no table is touched
    for (uint8_t b : s)
      if (is_control(b)) return PHRASE_CONTROL;
    while (!s.empty() && s.back() == ' ') s.pop_back();
    count = s.size();
  } else {
    CodePoints cp;
    if (!utf8_decode(s.data(), s.size(), cp)) return PHRASE_NOT_UTF8;
    for (uint32_t c : cp)
      if (is_control(c)) return PHRASE_CONTROL;
    normalize(cp, true);
    while (!cp.empty() && cp.back() == ' ') cp.pop_back();
    count = cp.size();
    utf8_encode(cp, s);
  }
  return count < 20 ? PHRASE_SHORT : PHRASE_OK;
}
