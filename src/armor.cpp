// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#include "armor.h"

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "crc32.h"
#include "text.h"

namespace {

const char *BEGIN_TAG = "*BEGIN " FORMAT_NAME " message, valid char:";
const char *END_TAG = "*END " FORMAT_NAME " message, CRC:";
const char *LINE_ENDS = "\r\n";  // either one ends a line, so LF, CR LF and CR text all work

// The position of the line that starts with tag, searching line by line from pos; npos if none.
size_t find_tag(const std::string &text, size_t pos, const char *tag)
{
  while (pos < text.size()) {
    if (!text.compare(pos, strlen(tag), tag)) return pos;
    size_t nl = text.find_first_of(LINE_ENDS, pos);
    if (nl == std::string::npos) break;
    pos = nl + 1;
  }
  return std::string::npos;
}

}  // namespace

Buf high2low(const Buf &in)
{
  char tabel[64];
  for (int i = 0; i < 12; i++) tabel[i] = '0' + i;
  for (int i = 0; i < 26; i++) tabel[12 + i] = 'A' + i;
  for (int i = 0; i < 26; i++) tabel[38 + i] = 'a' + i;

  // The EOF marker (0xFF) is encoded as a final byte; low2high strips it.
  Buf data(in);
  data.push_back(0xFF);

  Crc32 crc;
  std::string o;
  char hdr[128];
  // The count of characters is a 64-bit number on every OS (unsigned long is 32 bits on Windows).
  const uint64_t fl = checked_add(checked_mul(data.size(), 4), 2) / 3;
  snprintf(hdr, sizeof hdr, "\n%s %" PRIu64 "\n\n", BEGIN_TAG, fl);
  o += hdr;

  int wvdd = 0, posi = 0;
  uint8_t chb = 0, chc = 0;
  for (uint8_t cha : data) {
    crc.update(cha);
    switch (wvdd++) {
      case 0: chb = cha & 0x3; o += tabel[cha >> 2]; break;
      case 1: chc = cha & 0xF; o += tabel[(cha >> 4) | (chb << 4)]; break;
      case 2: o += tabel[((cha & 0xC0) >> 6) | (chc << 2)]; o += tabel[cha & 0x3F]; wvdd = 0; break;
    }
    if (posi++ >= 44) { posi = 0; o += '\n'; }
  }
  if (wvdd == 1) o += tabel[(chb << 4) & 0xFF];
  else if (wvdd == 2) o += tabel[(chc << 2) & 0xFF];

  snprintf(hdr, sizeof hdr, "\n\n%s %d\n\n", END_TAG, (int32_t)crc.value());
  o += hdr;
  return Buf(o.begin(), o.end());
}

Buf low2high(const Buf &in, const std::string &name)
{
  uint8_t tabel[256];
  memset(tabel, 255, sizeof tabel);
  for (int i = 0; i < 12; i++) tabel['0' + i] = i;
  for (int i = 0; i < 26; i++) tabel['A' + i] = 12 + i;
  for (int i = 0; i < 26; i++) tabel['a' + i] = 38 + i;

  std::string text(in.begin(), in.end());
  text.resize(decode_text((uint8_t *)&text[0], text.size()));
  errarg = name;

  size_t pos = find_tag(text, 0, BEGIN_TAG);
  if (pos == std::string::npos) errorexit(8);
  // A count that does not fit (strtoull gives the largest value) is read to the end of the text and then ends in error 11.
  const uint64_t valchr = strtoull(text.c_str() + pos + strlen(BEGIN_TAG), nullptr, 10);
  size_t nl = text.find_first_of(LINE_ENDS, pos);
  pos = (nl == std::string::npos) ? text.size() : nl + 1;

  Crc32 crc;
  Buf out;
  uint64_t fl = 0;
  int wvdd = 0;
  uint8_t chb = 0, chc = 0;
  while (fl < valchr) {
    if (pos >= text.size()) errorexit(11);
    uint8_t cha = tabel[(uint8_t)text[pos++]];
    if (cha == 255) continue;
    fl++;
    switch (wvdd++) {
      case 0: chb = cha << 2; break;
      case 1: chc = cha & 0xF; cha = (cha >> 4) | chb; crc.update(cha); out.push_back(cha); break;
      case 2: chb = cha & 0x3; cha = (cha >> 2) | (chc << 4); crc.update(cha); out.push_back(cha); break;
      case 3: cha |= (chb << 6); crc.update(cha); out.push_back(cha); wvdd = 0; break;
    }
  }

  pos = find_tag(text, pos, END_TAG);
  if (pos == std::string::npos) errorexit(11);
  // The number is the signed value that high2low wrote, so anything out of range is damage (long is 32 bits on Windows).
  if (strtoll(text.c_str() + pos + strlen(END_TAG), nullptr, 10) != (long long)(int32_t)crc.value()) errorexit(12);
  if (!out.empty()) out.pop_back();  // EOF marker added by high2low
  return out;
}
