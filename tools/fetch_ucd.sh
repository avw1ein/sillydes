#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Andy van Wezel
#
# Downloads the files of the Unicode Character Database that src/unicode_tables.h is made of, and
# the conformance file that goes with them, into a directory, and checks their SHA-256:
#
#   tools/fetch_ucd.sh DIRECTORY
#   cmake -S . -B build -DSILLYDES_REGENERATE_UNICODE=DIRECTORY && cmake --build build --target check_unicode
#
# The version and the sums belong to the tables that are committed. For tables of another Unicode
# version (which means a new file format, see src/version.h) change both here first.
set -eu
DIR=${1:?usage: tools/fetch_ucd.sh DIRECTORY}
VERSION=18.0.0

mkdir -p "$DIR"
while read -r sum name; do
  curl -fsS --retry 3 -o "$DIR/$name" "https://www.unicode.org/Public/$VERSION/ucd/$name"
  echo "$sum  $DIR/$name" | sha256sum -c -
done <<SUMS
0736451de439ae7baf1425136617da495e09ee5afbe6e394374db7009ea08950 UnicodeData.txt
98ac7f67d985fe781e317f6182e885e94cabb0c314769e6dd73e48b226931ccd DerivedNormalizationProps.txt
09c928886a178fcafd93c29e4bd59073a058e5a100b716d425cb563ab50f68c9 DerivedCoreProperties.txt
25a50d816764b04abfb4a646d3eb2b2a803284c3873d9a06757b94fe4513dde3 NormalizationTest.txt
SUMS
