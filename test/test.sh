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

# Written by release 5.1.0 and never regenerated: these fail as soon as the file format changes.
P="The quick brown fox jumps over the lazy dog, again and again."
./sillydes act=d in=test/format-5.1.0/hello.bin out="$T/f1.txt" key=sample.key
cmp "$T/hello.txt" "$T/f1.txt"
echo "$P" | ./sillydes act=dm in=test/format-5.1.0/hello-phrase.sdes out="$T/f2.txt" phrase 2>/dev/null
cmp "$T/hello.txt" "$T/f2.txt"
echo "ok: files written by release 5.1.0 decrypt (binary, and e-mail style with a phrase)"

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

cp "$T/rep.enc" "$T/t5"
printf '\x01' | dd of="$T/t5" bs=1 seek=3 conv=notrunc 2>/dev/null
fail13 ./sillydes act=d in="$T/t5" out="$T/x" key=sample.key
sed 's/SillyDES 5\.1\.0/SillyDES 5.0.0/' "$T/p.txt" > "$T/old.txt"
rc=0; ./sillydes act=dm in="$T/old.txt" out="$T/x" key=sample.key 2>/dev/null || rc=$?
[ "$rc" -eq 8 ] || { echo "FAIL: e-mail tags of another version accepted"; exit 1; }
echo "ok: files of another version are rejected"

[ "$(cmp -l <(head -c 24 "$T/rep.enc" | tail -c 16) <(head -c 24 "$T/rep2.enc" | tail -c 16) | wc -l)" -gt 8 ] || { echo "FAIL: salt repeated"; exit 1; }
echo "ok: fresh salt for every encryption"

W="A completely different phrase that is long enough to be accepted."
rc=0; echo "$W" | ./sillydes act=dm in="$T/p.txt" out="$T/x" phrase 2>/dev/null || rc=$?
[ "$rc" -eq 13 ] || { echo "FAIL: wrong phrase accepted"; exit 1; }
echo "ok: wrong phrase fails authentication"

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

echo "all tests passed"
