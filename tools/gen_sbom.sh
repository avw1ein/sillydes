#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 1993-1994, 2026 Andy van Wezel
#
# Writes a CycloneDX 1.5 SBOM (JSON) for a built sillydes binary to stdout: the binary with its
# SHA-256, the shared libraries it really loads, the Unicode data that is compiled in, and the
# compiler that built it. Runs in bash on Linux, macOS and Windows (Git Bash, MSYS2).
#   Linux:   the libraries from ldd, with their distribution package, version and SHA-256 where
#            dpkg or rpm knows them.
#   macOS:   the libraries from otool -L, with their version (they live in the system's shared
#            cache, so there is no file to hash).
#   Windows: none; the C and C++ runtimes are linked in, the rest belongs to the system.
#
#   tools/gen_sbom.sh ./sillydes > sillydes.cdx.json        (or: cmake --build <dir> --target sbom, Linux)
#
# SOURCE_DATE_EPOCH, if set, fixes the timestamp. SBOM_COMPILER_NAME and SBOM_COMPILER_VERSION name
# the compiler where it cannot be asked (MSVC); otherwise it is asked with --version. SBOM_PLATFORM
# names the platform (linux-arm64, windows-arm64, ...) where uname and the environment would be wrong,
# as for an x86-64 shell that runs under emulation on Windows arm64.
set -eu
BIN=${1:-./sillydes}
cd "$(dirname "$0")/.."
[ -x "$BIN" ] || { echo "gen_sbom: $BIN is not built; build it first" >&2; exit 1; }

esc() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; printf '%s' "$s"; }
if command -v sha256sum >/dev/null 2>&1; then
  sha() { sha256sum "$1" | cut -d' ' -f1; }
else
  sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi
SYSTEM=$(uname -s)

VERSION=$(sed -n 's/^#define PACKAGE_VERSION "\(.*\)"/\1/p' src/version.h)
FORMAT=$(sed -n 's/^#define FORMAT_NAME "SillyDES \(.*\)"/\1/p' src/version.h)
UNICODE=$(sed -n 's/^#define UNICODE_VERSION "\(.*\)"/\1/p' src/unicode_tables.h)
REPO=$(git config --get remote.origin.url 2>/dev/null | sed 's#\.git$##; s#^git@github.com:#https://github.com/#' || true)
COMMIT=$(git rev-parse HEAD 2>/dev/null || true)
DIRTY=false
if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then DIRTY=true; fi
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
  STAMP=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
else
  STAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
fi
# A random (version 4) UUID, from the random device that every one of these systems has.
HEX=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
VARIANT=$(printf '%s' "89ab" | cut -c$(( $(printf '%d' "0x${HEX:16:1}") % 4 + 1 )))
SERIAL="${HEX:0:8}-${HEX:8:4}-4${HEX:13:3}-${VARIANT}${HEX:17:3}-${HEX:20:12}"
DISTRO_ID=$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | tr -d '"' || true)
DISTRO_ID=${DISTRO_ID:-linux}
DISTRO_VER=$(sed -n 's/^VERSION_ID=//p' /etc/os-release 2>/dev/null | tr -d '"' || true)
case "$SYSTEM" in
  Linux) PLATFORM="linux-$(uname -m)" ;;
  Darwin)
    ARCHS=$(lipo -archs "$BIN" 2>/dev/null | tr ' ' '\n' | sort | tr '\n' ' ' | sed 's/ $//')
    if [ "$ARCHS" = "arm64 x86_64" ]; then PLATFORM=macos-universal; else PLATFORM="macos-${ARCHS:-$(uname -m)}"; fi ;;
  *)
    case "${PROCESSOR_ARCHITECTURE:-}" in ARM64) WARCH=arm64 ;; *) WARCH=x86_64 ;; esac
    PLATFORM="windows-$WARCH" ;;
esac
PLATFORM=${SBOM_PLATFORM:-$PLATFORM}

CXX_BIN=${CXX:-g++}
if [ -n "${SBOM_COMPILER_NAME:-}" ]; then
  CXX_NAME=$SBOM_COMPILER_NAME
  CXX_VER=${SBOM_COMPILER_VERSION:-}
  CXX_FULL="$CXX_NAME ${CXX_VER}"
else
  CXX_FULL=$("$CXX_BIN" --version 2>/dev/null | head -n 1 || true)
  CXX_VER=$("$CXX_BIN" -dumpfullversion 2>/dev/null || true)
  CXX_NAME=$(basename "$CXX_BIN")
fi

# Packages (name, version, arch) that own a file, empty if the file belongs to none we can query.
owner() {
  local f=$1 pkg=""
  if command -v dpkg >/dev/null 2>&1; then
    pkg=$(dpkg -S "$f" 2>/dev/null | head -n 1 | cut -d: -f1 || true)
    if [ -n "$pkg" ]; then
      dpkg-query -W -f='deb\t${Package}\t${Version}\t${Architecture}\n' "$pkg" 2>/dev/null | head -n 1 || true
      return
    fi
  fi
  if command -v rpm >/dev/null 2>&1; then
    rpm -qf --qf 'rpm\t%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n' "$f" 2>/dev/null | head -n 1 || true
  fi
}

order=()
LIBDESC="Loaded dynamically at run time"
PROPS=""
maclibs=""
macdeps=""
if [ "$SYSTEM" = Linux ]; then
  # One line per distinct file the binary loads; the dynamic loader is listed by ldd without "=>".
  # A static binary loads nothing: what was linked into it is the archives of the C and C++ runtime.
  if ldd "$BIN" 2>&1 | grep -q "not a dynamic executable\|statically linked"; then
    LIBDESC="Linked statically into the binary"
    LIBS=""
    for a in libstdc++.a libgcc.a libgcc_eh.a libc.a; do
      path=$("$CXX_BIN" -print-file-name="$a" 2>/dev/null || true)
      if [ -f "$path" ]; then LIBS+="$(readlink -f "$path")"$'\n'; fi
    done
    LIBS=$(printf '%s' "$LIBS" | sort -u)
    PROPS+='{ "name": "linking", "value": "static" },'
  else
    LIBDESC="Loaded dynamically at run time"
    LIBS=$(ldd "$BIN" | awk '/=>/ { print $3 } !/=>/ && $1 ~ /^\// { print $1 }' | while read -r p; do readlink -f "$p"; done | sort -u)
  fi

  # One component per package (a package may own several loaded files); a file no package manager
  # knows becomes a component of its own.
  declare -A pkgmeta pkgfiles
  order=()
  for f in $LIBS; do
    name=$(basename "$f")
    info=$(owner "$f")
    kind=""; pname=""; pver=""; parch=""
    if [ -n "$info" ]; then IFS=$'\t' read -r kind pname pver parch <<<"$info"; fi
    key="${kind:-file}|${pname:-$name}|$pver|$parch"
    if [ -z "${pkgmeta[$key]+x}" ]; then pkgmeta[$key]=$key; pkgfiles[$key]=""; order+=("$key"); fi
    pkgfiles[$key]+="${pkgfiles[$key]:+,
}        { \"name\": \"file\", \"value\": \"$(esc "$f")\" },
        { \"name\": \"file-sha256\", \"value\": \"$(sha "$f")\" }"
  done
fi
if [ "$SYSTEM" = Darwin ]; then
  # One component per library, from "<path> (compatibility version X, current version Y)".
  # Library lines start with a tab; a universal binary lists them once per architecture.
  while IFS= read -r line; do
    case "$line" in $'\t'*) ;; *) continue ;; esac
    path=${line%% (*}
    path=${path#"${path%%[![:space:]]*}"}
    ver=${line##*current version }
    ver=${ver%)}
    [ -n "$path" ] || continue
    ref="lib:$path"
    case ", $macdeps" in *"\"$(esc "$ref")\""*) continue ;; esac
    entry="    {
      \"bom-ref\": \"$(esc "$ref")\",
      \"type\": \"library\",
      \"name\": \"$(esc "$(basename "$path")")\",
      \"version\": \"$(esc "$ver")\",
      \"description\": \"Loaded dynamically at run time; part of macOS\",
      \"properties\": [ { \"name\": \"path\", \"value\": \"$(esc "$path")\" } ]
    }"
    maclibs+="${maclibs:+,
}$entry"
    macdeps+="${macdeps:+, }\"$(esc "$ref")\""
  done < <(otool -L "$BIN")
fi

# The only third-party material in the binary: tables generated from the Unicode Character Database.
comp="    {
      \"bom-ref\": \"data:unicode-character-database\",
      \"type\": \"data\",
      \"name\": \"Unicode Character Database\",
      \"version\": \"$(esc "$UNICODE")\",
      \"description\": \"Normalisation data, compiled in as src/unicode_tables.h (generated by tools/gen_unicode.cpp); used for the canonical form of a phrase\",
      \"licenses\": [ { \"license\": { \"name\": \"Unicode License v3\", \"url\": \"https://www.unicode.org/license.txt\" } } ],
      \"externalReferences\": [ { \"type\": \"distribution\", \"url\": \"https://www.unicode.org/Public/$(esc "$UNICODE")/ucd/\" } ]
    }"
deps="\"data:unicode-character-database\""
for key in ${order[@]+"${order[@]}"}; do
  IFS='|' read -r kind pname pver parch <<<"$key"
  ref="pkg:$pname"
  entry="    {
      \"bom-ref\": \"$(esc "$ref")\",
      \"type\": \"library\",
      \"name\": \"$(esc "$pname")\","
  [ -n "$pver" ] && entry+="
      \"version\": \"$(esc "$pver")\","
  entry+="
      \"description\": \"$LIBDESC\","
  if [ "$kind" != file ]; then
    qual="arch=$parch"
    [ -n "$DISTRO_VER" ] && qual="$qual&distro=$DISTRO_ID-$DISTRO_VER"
    entry+="
      \"purl\": \"pkg:$kind/$DISTRO_ID/$(esc "$pname")@$(esc "$pver")?$qual\","
  fi
  entry+="
      \"properties\": [
${pkgfiles[$key]}
      ]
    }"
  comp+="${comp:+,
}$entry"
  deps+="${deps:+, }\"$(esc "$ref")\""
done
if [ -n "${maclibs:-}" ]; then
  comp+=",
$maclibs"
  deps+=", $macdeps"
fi

cat <<EOF
{
  "\$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:$SERIAL",
  "version": 1,
  "metadata": {
    "timestamp": "$STAMP",
    "tools": {
      "components": [
        { "type": "application", "name": "$(esc "$CXX_NAME")"$([ -n "$CXX_VER" ] && printf ', "version": "%s"' "$(esc "$CXX_VER")"), "description": "$(esc "$CXX_FULL")" },
        { "type": "application", "name": "tools/gen_sbom.sh", "description": "Generated this document from the binary and the libraries it loads" }
      ]
    },
    "component": {
      "bom-ref": "sillydes",
      "type": "application",
      "name": "SillyDES",
      "version": "$VERSION",
      "description": "Command line file encryption: eight DES layers on 2048-bit blocks, HMAC-SHA-512 authentication, Argon2id phrase derivation. DES, SHA-512, HMAC, BLAKE2b, Argon2id and CRC-32 are implemented in this repository from their standards; no cryptographic library is linked.",
      "author": "Andy van Wezel",
      "licenses": [ { "license": { "id": "MIT" } } ],
      "purl": "pkg:github/avw1ein/sillydes@$VERSION",
      "hashes": [ { "alg": "SHA-256", "content": "$(sha "$BIN")" } ],
      "externalReferences": [ { "type": "vcs", "url": "$(esc "$REPO")" } ],
      "properties": [
        $PROPS
        { "name": "platform", "value": "$PLATFORM" },
        { "name": "file-format", "value": "$(esc "$FORMAT")" },
        { "name": "source-commit", "value": "$COMMIT" },
        { "name": "source-tree-modified", "value": "$DIRTY" },
        { "name": "bundled-implementations", "value": "DES (FIPS 46-3), SHA-512 (FIPS 180-4), HMAC (RFC 2104), BLAKE2b (RFC 7693), Argon2id (RFC 9106), CRC-32 (IEEE 802.3), Unicode normalisation (UAX #15)" }
      ]
    }
  },
  "components": [
$comp
  ],
  "dependencies": [
    { "ref": "sillydes", "dependsOn": [ $deps ] }
  ]
}
EOF
