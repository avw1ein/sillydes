#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 1993-1994, 2026 Andy van Wezel
#
# The disassembly gate of PORTPLAN.md 5.3 (item 2). Counts the conditional branches of every
# function of a built binary that handles secrets, prints them as a report, and fails if a function
# that must be free of them has one. Whether a branch depends on a secret cannot be seen in the
# disassembly (a loop over a public length branches, and so does any bounds check), so only the
# functions listed in MUST_BE_BRANCHFREE are enforced; the rest is for the reader, and
# test/ct_valgrind.cpp is the check that sees data.
#
#   tools/ct_branches.sh <binary>
#
# x86-64 (jcc except jmp) and arm64 (b.cond, cbz, cbnz, tbz, tbnz). Needs objdump for the binary's
# architecture; where it has none the script says so and succeeds.
set -eu
BIN=${1:?usage: ct_branches.sh binary}

# Mangled names of functions that must not contain a conditional branch.
MUST_BE_BRANCHFREE="_Z9hex_digith"
# What the report covers, as extended regular expressions on the mangled names.
REPORT='Des|Sha512|Hmac512|Blake2b|blake2b_long|ct_equal|hex_digit|SillyDesCipher|pad256|derive_keys|length_mask'

OBJDUMP=${OBJDUMP:-objdump}
if ! command -v "$OBJDUMP" >/dev/null 2>&1; then echo "ct_branches: no objdump, nothing checked"; exit 0; fi
DUMP=$("$OBJDUMP" -d --no-show-raw-insn -w "$BIN" 2>&1) || true
if ! grep -q '^[0-9a-f]* <' <<<"$DUMP"; then echo "ct_branches: objdump cannot read this binary, nothing checked"; exit 0; fi

COUNTS=$(awk '
  /^[0-9a-f]+ <.*>:$/ { fn = $2; gsub(/[<>:]/, "", fn); count[fn] = 0; insns[fn] = 0; next }
  fn != "" && /^ +[0-9a-f]+:/ {
    insns[fn]++
    op = $2
    if (op ~ /^(b\.[a-z]+|cbz|cbnz|tbz|tbnz)$/ || (op ~ /^j[a-z]+$/ && op != "jmp")) count[fn]++
  }
  END { for (f in count) printf "%d %d %s\n", count[f], insns[f], f }
' <<<"$DUMP" | sort -k3)

printf '%-8s %-8s %s\n' branches insns function
awk -v re="$REPORT" '$3 ~ re { printf "%-8d %-8d %s\n", $1, $2, $3 }' <<<"$COUNTS"

status=0
for f in $MUST_BE_BRANCHFREE; do
  line=$(awk -v f="$f" '$3 == f' <<<"$COUNTS")
  if [ -z "$line" ]; then echo "ct_branches: $f is not in the binary (inlined or renamed?); not checked"; continue; fi
  n=${line%% *}
  if [ "$n" != 0 ]; then echo "FAIL: $f has $n conditional branches and must have none"; status=1; fi
done
[ "$status" = 0 ] && echo "ok: the functions that must be free of conditional branches are"
exit $status
