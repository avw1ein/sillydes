#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 1993-1994, 2026 Andy van Wezel
#
# Self-test for the Linux port. Run after `make`; works from any directory.
set -e
cd "$(dirname "$0")/.."
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

./sillydes act=dm in=hello.sdes out="$T/hello.txt" key=sample.key
grep -q "^Hello," "$T/hello.txt"
echo "ok: hello.sdes decrypts"

# Written when format 5.2.0 was introduced and never regenerated: these fail as soon as the file
# format changes, and the phrase rules are part of it. The third file was made with a phrase of
# Latin, Greek, Japanese and one character outside the BMP (U_NFC, escaped to keep this file ASCII).
P="The quick brown fox jumps over the lazy dog, again and again."
U_NFC=$'Cr\xc3\xa8me br\xc3\xbbl\xc3\xa9e, \xce\xa9\xce\xbc\xce\xad\xce\xb3\xce\xb1, \xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\xe3\x81\xae\xe3\x83\x86\xe3\x82\xb9\xe3\x83\x88, \xf0\x9d\x84\x9e clef'
./sillydes act=d in=test/format-5.2.0/hello.bin out="$T/f1.txt" key=sample.key
cmp "$T/hello.txt" "$T/f1.txt"
echo "$P" | ./sillydes act=dm in=test/format-5.2.0/hello-phrase.sdes out="$T/f2.txt" phrase 2>/dev/null
cmp "$T/hello.txt" "$T/f2.txt"
printf '%s\n' "$U_NFC" | ./sillydes act=dm in=test/format-5.2.0/hello-utf8-phrase.sdes out="$T/f3.txt" phrase 2>/dev/null
cmp "$T/hello.txt" "$T/f3.txt"
echo "ok: files of format 5.2.0 decrypt (binary, and e-mail style with an ASCII and a non-ASCII phrase)"

for size in 0 1 255 256 257 1000 5000; do
  head -c "$size" /dev/urandom > "$T/in.bin"
  ./sillydes act=e  in="$T/in.bin" out="$T/e.bin"  key=sample.key
  ./sillydes act=d  in="$T/e.bin"  out="$T/d.bin"  key=sample.key
  cmp "$T/in.bin" "$T/d.bin"
  ./sillydes act=em in="$T/in.bin" out="$T/e.txt"  key=sample.key
  ./sillydes act=dm in="$T/e.txt"  out="$T/d2.bin" key=sample.key
  cmp "$T/in.bin" "$T/d2.bin"
done
echo "ok: round trips (binary and e-mail style)"

head -c 1 /dev/urandom > "$T/in.bin"
./sillydes act=e in="$T/in.bin" out="$T/e.bin" key=sample.key
[ "$(stat -c %s "$T/e.bin")" -eq $((280 + 256 + 64)) ] || { echo "FAIL: unexpected container size"; exit 1; }
echo "ok: container is header + one block + 64-byte tag"

echo "$P" | ./sillydes act=em in=hello.sdes out="$T/p.txt" phrase 2>/dev/null
echo "$P" | ./sillydes act=dm in="$T/p.txt" out="$T/p.out" phrase 2>/dev/null
echo "ok: phrase round trip"

rc=0; echo "nineteen chars 123" | ./sillydes act=e in=hello.sdes out="$T/short" phrase 2>/dev/null || rc=$?
[ "$rc" -eq 10 ] && [ ! -e "$T/short" ] || { echo "FAIL: short phrase accepted"; exit 1; }
rc=0; (ulimit -v 1500000; echo "$P" | ./sillydes act=e in=hello.sdes out="$T/nomem" phrase 2>/dev/null) || rc=$?
[ "$rc" -eq 7 ] && [ ! -e "$T/nomem" ] || { echo "FAIL: phrase mode without 2 GiB did not stop with error 7"; exit 1; }
echo "ok: short phrase and missing memory are refused"

cmp -s hello.sdes "$T/p.out" || { echo "FAIL: phrase round trip mismatch"; exit 1; }
printf '%s\n' 0123456789abcdef fedcba9876543210 13579bdf02468ace a1b2c3d4e5f60718 \
  0f1e2d3c4b5a6978 1122334455667788 99aabbccddeeff00 0011223344556677 > "$T/otherkey"
rc=0; ./sillydes act=dm in="$T/p.txt" out="$T/bad" key="$T/otherkey" 2>/dev/null || rc=$?
[ "$rc" -eq 13 ] || { echo "FAIL: wrong key accepted"; exit 1; }
echo "ok: wrong key fails authentication"

sed 's/^BA7CDE4350091ADE/BA7CDE4350091ADF/' sample.key > "$T/paritykey"
if cmp -s sample.key "$T/paritykey"; then echo "FAIL: parity key not built"; exit 1; fi
rc=0; ./sillydes act=dm in=hello.sdes out="$T/bad" key="$T/paritykey" 2>/dev/null || rc=$?
[ "$rc" -eq 13 ] || { echo "FAIL: key differing in a parity bit accepted"; exit 1; }
echo "ok: every key bit matters"

grep -E '^[0-9A-F]{16}' sample.key | head -n 6 > "$T/sixkeys"
rc=0; ./sillydes act=dm in=hello.sdes out="$T/bad" key="$T/sixkeys" 2>/dev/null || rc=$?
[ "$rc" -eq 5 ] || { echo "FAIL: key file with too few keys accepted"; exit 1; }
echo "ok: key file needs eight keys"

sed 's/^\(.\{20\}\)./\1A/' "$T/p.txt" > "$T/corrupt.txt"
if ./sillydes act=dm in="$T/corrupt.txt" out="$T/bad2" key=sample.key 2>/dev/null; then
  echo "FAIL: corruption not detected"; exit 1
fi
echo "ok: corruption detected (CRC)"

HDR=280
block() { tail -c +$((HDR + 256 * $2 + 1)) "$1" | head -c 256; }
fail13() { local rc=0; "$@" 2>/dev/null || rc=$?; [ "$rc" -eq 13 ]; }

# Nine identical plaintext blocks used to make ciphertext block 3 equal DES(k6, 0).
head -c 256 /dev/urandom > "$T/blk"
for i in 1 2 3 4 5 6 7 8 9; do cat "$T/blk"; done > "$T/rep.bin"
./sillydes act=e in="$T/rep.bin" out="$T/rep.enc" key=sample.key
for i in 0 1 2 3 4 5 6 7 8; do block "$T/rep.enc" $i > "$T/c$i"; done
[ "$(md5sum "$T"/c? | cut -d' ' -f1 | sort -u | wc -l)" -eq 9 ]
for i in 0 1 2 3 4 5 6 7 8; do
  [ "$(od -An -v -tx1 -w8 "$T/c$i" | sort -u | wc -l)" -gt 1 ]
done
echo "ok: repeated plaintext blocks leave no pattern"

./sillydes act=e in="$T/rep.bin" out="$T/rep2.enc" key=sample.key
for i in 0 1 2 3 4 5 6 7 8; do
  [ "$(cmp -l "$T/c$i" <(block "$T/rep2.enc" $i) | wc -l)" -gt 200 ]
done
echo "ok: random IV makes every block differ between runs"

cp "$T/rep.enc" "$T/t1"
printf '\x55' | dd of="$T/t1" bs=1 seek=$((HDR + 300)) conv=notrunc 2>/dev/null
fail13 ./sillydes act=d in="$T/t1" out="$T/x" key=sample.key
head -c -256 "$T/rep.enc" > "$T/t2"
fail13 ./sillydes act=d in="$T/t2" out="$T/x" key=sample.key
cp "$T/rep.enc" "$T/t3"
printf '\x01' | dd of="$T/t3" bs=1 seek=7 conv=notrunc 2>/dev/null
fail13 ./sillydes act=d in="$T/t3" out="$T/x" key=sample.key
cp "$T/rep.enc" "$T/t4"
printf '\x1e' | dd of="$T/t4" bs=1 seek=4 conv=notrunc 2>/dev/null
fail13 ./sillydes act=d in="$T/t4" out="$T/x" key=sample.key
cp "$T/rep.enc" "$T/t6"
printf '\x00' | dd of="$T/t6" bs=1 seek=5 conv=notrunc 2>/dev/null
fail13 ./sillydes act=d in="$T/t6" out="$T/x" key=sample.key
echo "ok: bit flip, truncation, header change and out-of-range KDF parameters fail"

# The magic and the tags of the previous format, 5.1.0.
cp "$T/rep.enc" "$T/t5"
printf '\x10' | dd of="$T/t5" bs=1 seek=3 conv=notrunc 2>/dev/null
fail13 ./sillydes act=d in="$T/t5" out="$T/x" key=sample.key
sed 's/SillyDES 5\.2\.0/SillyDES 5.1.0/' "$T/p.txt" > "$T/old.txt"
if cmp -s "$T/p.txt" "$T/old.txt"; then echo "FAIL: e-mail text of another version not built"; exit 1; fi
rc=0; ./sillydes act=dm in="$T/old.txt" out="$T/x" key=sample.key 2>/dev/null || rc=$?
[ "$rc" -eq 8 ] || { echo "FAIL: e-mail tags of another version accepted"; exit 1; }
echo "ok: files of another version are rejected"

[ "$(cmp -l <(head -c 24 "$T/rep.enc" | tail -c 16) <(head -c 24 "$T/rep2.enc" | tail -c 16) | wc -l)" -gt 8 ] || { echo "FAIL: salt repeated"; exit 1; }
echo "ok: fresh salt for every encryption"

W="A completely different phrase that is long enough to be accepted."
rc=0; echo "$W" | ./sillydes act=dm in="$T/p.txt" out="$T/x" phrase 2>/dev/null || rc=$?
[ "$rc" -eq 13 ] || { echo "FAIL: wrong phrase accepted"; exit 1; }
echo "ok: wrong phrase fails authentication"

# Text from other systems. A key file, an e-mail text or a phrase that was made, saved or piped
# on another system must work as it is: other line endings, a byte order mark, UTF-16 (what
# Windows PowerShell 5.1 writes with `>`), and for a phrase another way of typing the same text.
crlf() { sed 's/$/\r/' "$1"; }
cronly() { tr '\n' '\r' < "$1"; }
bom() { printf '\xef\xbb\xbf'; cat "$1"; }
utf16le() { printf '\xff\xfe'; printf "$(od -An -v -tx1 "$1" | tr -d '\n' | sed 's/ \(..\)/\\x\1\\x00/g')"; }
crlf sample.key > "$T/k-crlf"; cronly sample.key > "$T/k-cr"; bom sample.key > "$T/k-bom"
crlf sample.key > "$T/k.tmp"; utf16le "$T/k.tmp" > "$T/k-utf16"
for k in k-crlf k-cr k-bom k-utf16; do
  ./sillydes act=dm in=hello.sdes out="$T/ti.out" key="$T/$k" || { echo "FAIL: key file variant $k"; exit 1; }
  cmp "$T/hello.txt" "$T/ti.out"
done
crlf hello.sdes > "$T/m-crlf"; cronly hello.sdes > "$T/m-cr"
tail -n +2 hello.sdes > "$T/m.tmp"; bom "$T/m.tmp" > "$T/m-bom"   # the mark directly before *BEGIN
utf16le "$T/m-crlf" > "$T/m-utf16"
for m in m-crlf m-cr m-bom m-utf16; do
  ./sillydes act=dm in="$T/$m" out="$T/ti.out" key=sample.key || { echo "FAIL: e-mail text variant $m"; exit 1; }
  cmp "$T/hello.txt" "$T/ti.out"
done
./sillydes act=dm in="$T/m-utf16" out="$T/ti.out" key="$T/k-utf16"
cmp "$T/hello.txt" "$T/ti.out"
if grep -q "$(printf '\r')" hello.sdes "$T/p.txt"; then echo "FAIL: e-mail text is written with CR"; exit 1; fi
echo "ok: key files and e-mail text with CR LF, CR, a byte order mark and as UTF-16 are read"

# The same phrase from a Windows pipe: a byte order mark, trailing spaces and CR LF.
printf '\xef\xbb\xbf%s   \r\n' "$P" | ./sillydes act=dm in=test/format-5.2.0/hello-phrase.sdes out="$T/ti.out" phrase 2>/dev/null
cmp "$T/hello.txt" "$T/ti.out"
# The non-ASCII phrase typed in another way: decomposed accents, a no-break space, the ohm and
# micro signs, a full-width comma and letters, half-width katakana, a zero width space, a soft
# hyphen, a trailing ideographic space, a byte order mark and CR LF.
U_OTHER=$'\xef\xbb\xbfCre\xcc\x80me\xc2\xa0bru\xcc\x82le\xcc\x81e, \xe2\x84\xa6\xc2\xb5\xce\xb5\xcc\x81\xce\xb3\xce\xb1\xef\xbc\x8c \xe6\x97\xa5\xe6\x9c\xac\xe2\x80\x8b\xe8\xaa\x9e\xe3\x81\xae\xef\xbe\x83\xef\xbd\xbd\xef\xbe\x84, \xf0\x9d\x84\x9e \xef\xbd\x83\xef\xbd\x8c\xc2\xad\xef\xbd\x85\xef\xbd\x86\xe3\x80\x80'
[ "$U_OTHER" != "$U_NFC" ]
printf '%s\r\n' "$U_OTHER" | ./sillydes act=dm in=test/format-5.2.0/hello-utf8-phrase.sdes out="$T/ti.out" phrase 2>/dev/null
cmp "$T/hello.txt" "$T/ti.out"
echo "ok: a phrase piped or typed in another way gives the same keys"

# A phrase that no other system could reproduce is refused, for encryption and for decryption,
# and before the key derivation: with 1.5 GB of address space that would end in error 7.
refused() {  # refused ACT INFILE MESSAGE: the phrase on stdin must end in error 10 with that message
  local rc=0
  (ulimit -v 1500000; ./sillydes act="$1" in="$2" out="$T/refused" phrase 2>"$T/refused.err") || rc=$?
  [ "$rc" -eq 10 ] && [ ! -e "$T/refused" ] && grep -q "$3" "$T/refused.err"
}
printf 'cr\xe8me br\xfbl\xe9e \xe0 la carte, please\n' | refused e hello.sdes "not valid UTF-8" || { echo "FAIL: Latin-1 phrase accepted"; exit 1; }
printf '\xff\xfec\x00o\x00r\x00r\x00e\x00c\x00t\x00 \x00h\x00o\x00r\x00s\x00e\x00 \x00b\x00a\x00t\x00t\x00e\x00r\x00y\x00\n\x00' | refused e hello.sdes "not valid UTF-8" || { echo "FAIL: UTF-16 phrase accepted"; exit 1; }
printf 'correct horse\tbattery staple\n' | refused e hello.sdes "control character" || { echo "FAIL: phrase with a tab accepted"; exit 1; }
printf 'correct horse battery staple\x1b[D\n' | refused e hello.sdes "control character" || { echo "FAIL: phrase with an arrow key accepted"; exit 1; }
printf 'correct horse\tbattery staple\n' | refused dm "$T/p.txt" "control character" || { echo "FAIL: phrase with a tab accepted for decryption"; exit 1; }
printf '\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\n' | refused e hello.sdes "too short" || { echo "FAIL: phrase of nine characters in 27 bytes accepted"; exit 1; }
echo "ok: phrases that are not UTF-8, hold a control character or are too short are refused before the key derivation"

# Data is never translated: line endings, a DOS end-of-file mark and a NUL come back as they went in.
printf 'one\r\ntwo\nthree\r\x1a\x00four\r\n\x1a' > "$T/dos.in"
./sillydes act=e  in="$T/dos.in"  out="$T/dos.enc" key=sample.key
./sillydes act=d  in="$T/dos.enc" out="$T/dos.out" key=sample.key
cmp "$T/dos.in" "$T/dos.out"
./sillydes act=em in="$T/dos.in"  out="$T/dos.txt" key=sample.key
./sillydes act=dm in="$T/dos.txt" out="$T/dos.out" key=sample.key
cmp "$T/dos.in" "$T/dos.out"
# File names are bytes: these are UTF-8, in composed and in decomposed form.
N1=$'cr\xc3\xa8me-\xe6\x97\xa5\xe6\x9c\xac'; N2=$'cre\xcc\x80me-\xf0\x9d\x84\x9e'
cp sample.key "$T/$N1.key"
./sillydes act=e in="$T/dos.in" out="$T/$N1.enc" key="$T/$N1.key"
./sillydes act=d in="$T/$N1.enc" out="$T/$N2.out" key="$T/$N1.key"
cmp "$T/dos.in" "$T/$N2.out"
echo "ok: data with CR, LF, 0x1A and NUL is not translated; file names outside ASCII work"

# The same file under another spelling, through a hard link or through a symbolic link is still
# the same file: the output would destroy the input, so every one of them is error 6.
cp hello.sdes "$T/same.in"
ln "$T/same.in" "$T/same.hard"
ln -s same.in "$T/same.sym"
mkdir "$T/sub"
for out in "$T/./same.in" "$T/sub/../same.in" "$T/same.hard" "$T/same.sym"; do
  rc=0; ./sillydes act=dm in="$T/same.in" out="$out" key=sample.key 2>/dev/null || rc=$?
  [ "$rc" -eq 6 ] || { echo "FAIL: input and output are one file ($out) but the exit code is $rc"; exit 1; }
done
cmp hello.sdes "$T/same.in"
echo "ok: input and output that are one file are refused, also through links and other spellings"

# The sources stay ASCII with LF line endings, so that every compiler and every checkout sees the
# same bytes (the labels in them are hashed into the keys).
if LC_ALL=C grep -l "[^$(printf '\t') -~]" src/*.cpp src/*.h tools/*.cpp tools/*.sh test/*.cpp test/test.sh Makefile CMakeLists.txt CMakePresets.json cmake/*; then
  echo "FAIL: the files above hold a CR or a character outside ASCII"; exit 1
fi
echo "ok: the sources are ASCII with LF line endings"

# Linked with -z now: every symbol is bound at load. With lazy binding the dynamic linker's trampoline
# saves all vector registers on the stack at the first call of a library function, and those registers
# can still hold plaintext from a glibc memmove (seen on AVX-512 machines with clang). The scan below
# is what finds such a copy; this check names the cause when the build loses the flag.
if command -v readelf >/dev/null 2>&1; then
  readelf -d ./sillydes | grep -q 'BIND_NOW\|FLAGS.*NOW' || { echo "FAIL: sillydes is not linked with -z now"; exit 1; }
  echo "ok: the binary binds its symbols at load"
fi

# Memory residue: once the program has exited, normally or on an error, no copy of the phrase, the
# key text, the key bytes or the plaintext may be left in its heap, stack or mappings. The preloaded
# scanner (test/residue_scan.cpp) searches the process for them as it exits; marks are masked with
# 0x5a so that the environment does not contain them.
SCAN="$PWD/test/residue_scan.so"
mask() { local i; for ((i = 0; i < ${#1}; i++)); do printf '%02x' $(( $(printf '%d' "'${1:i:1}") ^ 0x5a )); done; }
maskhex() { local i; for ((i = 0; i < ${#1}; i += 2)); do printf '%02x' $(( 0x${1:i:2} ^ 0x5a )); done; }
hits() {  # hits MARKS COMMAND...: the number of marks still in memory when COMMAND exits
  local marks=$1 n; shift
  LD_PRELOAD="$SCAN" SCAN_VERBOSE=1 SCAN_MARKS="$marks" "$@" 2>&1 >/dev/null | tr -c '[:print:]\n' '.' > "$T/scan.log" || true
  n=$(sed -n 's/.*RESIDUE-SCAN: \([0-9]*\) hit.*/\1/p' "$T/scan.log" | tail -n 1)
  echo "${n:-none}"
}
residue_fail() { echo "FAIL: $1"; grep -a 'RESIDUE\|SCANNER-OWN\|ERROR' "$T/scan.log" | cut -c1-300; exit 1; }
PT="PLAINTEXT-MARKER-XYZZY-0123456789"
for i in 1 2 3 4 5 6 7 8 9 10; do echo "$PT"; done > "$T/rin.txt"
[ "$(hits "$(mask SecretMarker42)" bash -c 'v=SecretMarker42; :')" -gt 0 ] || residue_fail "residue scanner finds nothing in a process that holds the mark"

K1=$(grep -E '^[0-9A-F]{16}' sample.key | head -n 1 | cut -c1-16)
KMARKS="$(mask "$K1"),$(maskhex "$K1"),$(mask "$PT")"
[ "$(hits "$KMARKS" ./sillydes act=e in="$T/rin.txt" out="$T/r.bin" key=sample.key)" = 0 ] || residue_fail "key or plaintext left in memory after key file encryption"
[ "$(hits "$KMARKS" ./sillydes act=d in="$T/r.bin" out="$T/r.out" key=sample.key)" = 0 ] || residue_fail "key or plaintext left in memory after key file decryption"
cmp "$T/rin.txt" "$T/r.out"
printf '%s\n' a5c3e1f0d2b49687 1122334455667788 99aabbccddeeff00 0011223344556677 \
  13579bdf02468ace a1b2c3d4e5f60718 0f1e2d3c4b5a6978 fedcba9876543210 > "$T/scankey"
WMARKS="$(mask a5c3e1f0d2b49687),$(maskhex a5c3e1f0d2b49687),$(mask "$PT")"
[ "$(hits "$WMARKS" ./sillydes act=d in="$T/r.bin" out="$T/x" key="$T/scankey")" = 0 ] || residue_fail "key left in memory after authentication failure"
echo "ok: no key or plaintext left in memory, also after an error"

# A phrase longer than the 4096-byte read buffer, so that the buffer grows; random, so that a stale
# partial copy is recognisable by 16 bytes taken from the start and from the middle.
LONG=$(head -c 4000 /dev/urandom | base64 -w0 | head -c 5000)
PMARKS="$(mask "${LONG:0:16}"),$(mask "${LONG:2500:16}"),$(mask "$PT")"
[ "$(echo "$LONG" | hits "$PMARKS" ./sillydes act=e in="$T/rin.txt" out="$T/lp.bin" phrase)" = 0 ] || residue_fail "phrase or plaintext left in memory after encryption"
[ "$(echo "$LONG" | hits "$PMARKS" ./sillydes act=d in="$T/lp.bin" out="$T/lp.out" phrase)" = 0 ] || residue_fail "phrase or plaintext left in memory after decryption"
cmp "$T/rin.txt" "$T/lp.out"
[ "$(echo "${LONG:0:4999}" | hits "$PMARKS" ./sillydes act=d in="$T/lp.bin" out="$T/x" phrase)" = 0 ] || residue_fail "phrase left in memory after authentication failure"
echo "ok: no phrase left in memory, also after an error; a 5000-character phrase round-trips"

# A phrase outside ASCII goes through the normalisation, which holds it as code points too. The
# marks: the Japanese part of the phrase as UTF-8, and its first four characters as 32-bit values.
UMARKS="$(maskhex e697a5e69cace8aa9ee381aee38386e382b9e38388),$(maskhex e56500002c6700009e8a00006e300000),$(mask "$PT")"
[ "$(printf '%s\r\n' "$U_OTHER" | hits "$UMARKS" ./sillydes act=e in="$T/rin.txt" out="$T/up.bin" phrase)" = 0 ] || residue_fail "non-ASCII phrase or plaintext left in memory after encryption"
[ "$(printf '%s\n' "$U_NFC" | hits "$UMARKS" ./sillydes act=d in="$T/up.bin" out="$T/up.out" phrase)" = 0 ] || residue_fail "non-ASCII phrase or plaintext left in memory after decryption"
cmp "$T/rin.txt" "$T/up.out"
echo "ok: no phrase left in memory after its normalisation"

echo "all tests passed"
