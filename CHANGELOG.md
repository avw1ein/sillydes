# Changelog

All notable changes to SillyDES, newest first. Every release says whether the **file format**
changed, because that decides whether files written by one release can be read by another.
The format is named after the release that introduced it (currently 5.2.0); see section 1 of the
[README](README.md).

Maintainers: add the entry for a release here before tagging it. The release workflow publishes
the section of the tag's version as the text of the GitHub Release.

## [Unreleased]

**File format: unchanged (5.2.0).**

### Added

- Linux: the 2 GiB Argon2id table is a `memfd_secret` mapping when the kernel has one (5.14 and later)
  and `RLIMIT_MEMLOCK` or `CAP_IPC_LOCK` allows its size: it is never swapped, blocks hibernation while
  it exists and is out of the kernel's own view of memory. Otherwise nothing changes (`mlock` as far as
  the limit allows).
- The command-line word `requirelock` (or `SILLYDES_REQUIRE_LOCK=1` in the environment): the program
  stops with the new error level 15, before it writes anything, if the 2 GiB table could not be locked
  in RAM. The command line may now have a sixth word; five words work as before.
- Argon2i for the phrase, for a machine that shares its processor with code you do not trust: the
  command-line word `argon2i` (or `SILLYDES_ARGON2I=1`, exactly `1`) when encrypting with `phrase`.
  Argon2i addresses the 2 GiB table independently of the phrase, so a cache observer learns nothing
  from the key derivation, where Argon2id reads memory at phrase-dependent places (README section 7,
  ANALYSIS section 8). It uses 6 passes, 2 GiB and 4 lanes and takes about four times as long (7.5 s
  against 1.8 s on one Linux PC). Argon2id stays the default. Decryption needs neither word nor
  variable: the variant is header byte 7, which was reserved and zero, so no file changes. A key file
  has no Argon2i: the word is error 10 with `key=` when encrypting, the variable is ignored. The command
  line may now have a seventh word. A release before this one stops with error 13 on an Argon2i file.
- Windows on arm64: the data-independent timing mode (DIT) is switched on in the process, as on Linux and
  macOS. Windows has no way to ask whether the CPU has it, so the program tries the instruction and ignores
  a refusal. The hardening test reads the bit back on the runner.

## [5.2.1] - 2026-11-22

**File format: unchanged (5.2.0).** Files written by 5.2.0 and by 5.2.1 open in each other, with a
key file or a phrase, and the e-mail text still starts with `*BEGIN SillyDES 5.2.0 message`.

SillyDES now runs on Linux, macOS and Windows, on x86-64 and arm64, and a file made on any of them
opens on all the others. This is the first release with binaries for all of these systems (Linux
x86-64 and arm64 as static executables that need no library of the system, macOS as one universal
file, Windows x86-64 and arm64), each with an SBOM and attestations, and with hardening of the
process and of the build on every system. The macOS binary is signed ad hoc and not notarized, and
the Windows binaries are not signed with a certificate.

### Added

- A CMake build (`cmake --preset default`, see the README), tested with gcc and clang by the
  `build` workflow. The program is unchanged by it. It replaces the Makefile, which is gone: the
  tests, the SBOM, the regeneration of the S-box header and of the Unicode tables, and the release
  workflow all use CMake now (the targets `sbom`, `regenerate_sbox`, `regenerate_unicode` and
  `check_unicode`). The program built for a release now has the build hardening of the CMake build
  (the same list the Makefile had).
- Windows (`src/platform_win32.cpp`, `wmain`; x86-64 and arm64, MSVC and MinGW-w64) and macOS
  (arm64 and Intel), built and tested by the `build` workflow on GitHub's runners, together with a
  native arm64 Linux runner and AddressSanitizer and UndefinedBehaviorSanitizer runs. Files are
  opened as bytes on Windows, arguments and file names are Unicode, and a phrase is read from the
  console as Unicode.
- Memory hygiene on Windows and macOS, as on Linux: pages that hold keys, phrase and plaintext are
  locked in RAM (on Windows the working set is raised first, which `VirtualLock` needs), the
  stack window is locked, secret blocks are kept out of Windows Error Reporting dumps, and on macOS
  a debugger cannot attach (`PT_DENY_ATTACH`). Error 7 (not enough memory) also honours the memory
  limit of a Windows job object.
- macOS: the program is signed with the hardened runtime and without entitlements (ad hoc by
  default; `SILLYDES_CODESIGN_IDENTITY` takes a real identity), and a universal build
  (`cmake --preset universal`, arm64 and x86_64) is built and tested on both runner types. The
  `hardening` test checks every slice for PIE and the stack protector and the signature for the
  runtime flag and the absence of `get-task-allow`. Notarization is not done.
- Interchange is tested between all systems: the `build` workflow makes files with each build (Linux
  x64 and arm64, macOS arm64 and Intel, Windows MSVC, MinGW and arm64), binary and armored, with a
  key file, an ASCII phrase and a non-ASCII phrase, and every build opens the files of all the
  others; on Windows also files made through PowerShell 5.1, PowerShell 7 and `cmd.exe`. The
  workflow also builds and tests on Windows arm64, and runs the unit tests of an s390x build
  (big endian) under QEMU and opens its files on x86-64.
- Windows process hardening: the access control list of the process leaves the owner no right to
  read or write its memory (a debugger or dump tool of the same user is refused; an administrator
  with SeDebugPrivilege is not stopped), and the process allows no code generated at run time, no
  extension points, no images from network shares and no child process. The unit tests read all of
  it back from the OS. The end-to-end tests search the memory of the finished process for
  keys, phrases and plaintext on Windows and macOS too, and found none.
- Releases after 5.2.0 also carry a build provenance attestation: which workflow, commit and
  runner built the binary. `gh attestation verify <binary> --repo avw1ein/sillydes` checks it;
  the SBOM attestation is checked with `--predicate-type https://cyclonedx.org/bom` added.

- The release workflow builds, tests and publishes five binaries: Linux x86-64 and arm64 (static
  PIEs: they need no library of the system and run on any 64-bit Linux), macOS
  (one universal file, arm64 and x86-64), and Windows x86-64 and arm64, each with a CycloneDX SBOM
  and a build provenance and an SBOM attestation, and one `SHA256SUMS`. The Windows binaries are
  not signed with a certificate and the macOS binary is not notarized. Started by hand, the
  workflow is a dry run that publishes nothing. `tools/gen_sbom.sh` now runs on macOS and Windows
  too.
- Linux: `-DSILLYDES_STATIC=ON` links the program as a static PIE, which needs no library of the system.
  The released Linux binaries are built that way, and the `linux-static` job tests that very binary
  (the hardening test checks that it has no interpreter and needs no library). The SBOM of a static
  binary lists the archives of the C and C++ runtime that went into it.
- `SECURITY.md`: how to report a problem, what the program is meant to protect, what it does not,
  what has not been verified, and how to verify a download.

### Changed

- Internal: the end-to-end tests type the phrase into a terminal (a pseudo-terminal on Linux and
  macOS, a pseudo-console on Windows), including a character outside the BMP, and on Windows run
  the program from Windows PowerShell 5.1, PowerShell 7 and cmd.exe to see what their pipes and
  `>` hand to it.
- Internal: the residue scanner of the end-to-end tests is one source for every system
  (`test/residue_core.cpp`), run through a test build of the program (`sillydes_scan`) and, on
  Linux, also preloaded into the real binary.
- Internal: everything that needs an operating system moved into one platform layer
  (`src/platform.h`), a first step towards other systems. Messages, files and the phrase prompt
  behave as before; the usage text and every error message are unchanged.
- The binary is linked with `-z relro -z now` on every compiler (every symbol is bound at load
  time, the relocations are read-only); Ubuntu's gcc already did this, clang did not.
- Build hardening on every compiler and system: stack protector, stack clash protection, control-flow
  markers (IBT and shadow stack on x86-64, BTI and pointer authentication on arm64), fortified C
  library calls, PIE and a non-executable stack on Linux; ASLR, DEP and control flow guard on
  Windows. A test checks the finished binary for them.
- Internal: the end-to-end tests are a C++ program (`test/test_e2e.cpp`) instead of a shell script,
  so that they run on Windows and macOS as well as Linux; they test the same things, and more byte
  for byte on every system (a phrase with a byte order mark and CR LF, file names outside ASCII,
  links).
- Constant-time checks: a Valgrind test (secrets marked uninitialised), a branch report of the
  disassembly and a statistical timing test, run by the new `constant-time` workflow on x86-64 and
  arm64 Linux, macOS and Windows.
- Security: the MAC comparison and the hexadecimal decoding of a key file no longer branch on secret
  bytes, and on arm64 CPUs with the feature the data-independent timing mode (DIT) is switched on.

### Fixed

- Plaintext could be left on the stack after the program had wiped it. glibc copies data through
  the vector registers (on AVX-512 machines it does this with 512 bytes of the decrypted buffer),
  and code that runs after the wipe, here the dynamic linker resolving a symbol of a library at
  exit, saves those registers on the stack. The program now ends with `_exit` straight after
  wiping its stack, so no such code runs. The residue test of the CI found it, with clang, on
  runners that have AVX-512.
- A damaged e-mail text no longer slips through on some systems: the CRC on the END line must be
  exactly the 32-bit number that was written (before, a number 2^32 larger was accepted on Linux),
  and the character count is read as a 64-bit number everywhere. Texts the program wrote are
  read as before.
- Sizes computed from the size of a file are checked for overflow.

### Documentation

- The README says per system what is supported and how it is tested, what the program does about
  dumps, debuggers and locked memory on Linux, macOS and Windows (a table in section 8, with what
  is not verified), how error 7 is decided on each system, and what PowerShell 5.1, PowerShell 7
  and `cmd.exe` hand to the program as a phrase. ANALYSIS.md and STRUCTURE.md follow, and
  ANALYSIS.md lists the cross-system results and the time of the key derivation per system.
- README section 1 and the introduction say that SillyDES runs on Linux, macOS and Windows, with
  the way to download or build it, and to run it, per system. New: `TESTING.md` (tests, CI, the
  rules for writing a test, findings, what cannot be verified), STRUCTURE.md sections 11 and 12
  (the platform layer, per-system pitfalls, memory, process and build hardening), and a
  `runner-driven-development` skill for working with CI runners.

## [5.2.0] - 2026-11-21

**File format: new (5.2.0).** Files from earlier releases cannot be read, and files in the new
format cannot be read by earlier releases. To keep a file of format 5.1.0, decrypt it with release
5.1.1 and encrypt it again. Key files stay valid.

### Changed

- **One phrase now gives the same keys on every system.** Before the keys are derived, a phrase is
  brought into one canonical form: its line ending and trailing spaces are dropped, characters
  that can be entered in more than one way are folded to one (Unicode NFKC, version 18.0.0:
  accents typed as separate characters, full-width and half-width forms, the kinds of space,
  ligatures), and invisible characters are removed. These rules are part of the file format, which
  is why the format is new. They are meant to stay as they are when the program comes to Windows
  and macOS.
- A phrase that is not valid UTF-8, or that holds a control character such as a tab or what an
  arrow key sends, is refused for encryption and for decryption, before the keys are derived.
  Until now such a phrase was accepted and the file could be hard to open again.
- The minimum of 20 characters for a phrase is counted in characters, no longer in bytes.

### Added

- Key files and e-mail text made on other systems are read as they are: with CR LF or CR line
  endings, with a byte order mark, and as UTF-16 with a byte order mark. E-mail text is still
  written with LF only.
- `.gitattributes`, so that a checkout that converts line endings leaves the fixtures and the key
  file alone.
- The Unicode normalisation is implemented in this repository and passes the complete conformance
  file of Unicode 18.0.0 (`make unicode-check`). Its tables are generated from the Unicode
  Character Database, which comes under the Unicode License v3 (`LICENSE.Unicode`); the SBOM
  lists the data.

## [5.1.1] - 2026-11-21

**File format: unchanged (5.1.0).** Files written by 5.1.0 and 5.1.1 can be read by both.

### Security

- Secrets no longer stay behind in memory. Keys, phrases, the Argon2id working memory and the
  plaintext now live in buffers that are wiped before they are released. Small secrets sit in
  locked pages, large buffers have their own mapping, and both are excluded from core dumps.
- The phrase is read without stdio, and the stack is scrubbed before `main` returns.
- New tests search the exited process for the key, the phrase and the plaintext after
  encryption, decryption and a failed authentication.

### Added

- A CycloneDX SBOM (`make sbom`), published with every release.
- Releases are built by CI when a version tag is pushed. Each release has the Linux binary
  `sillydes-X.Y.Z-linux-x86_64`, its SBOM, `SHA256SUMS` and an attestation of the SBOM to the binary
  (`gh attestation verify <binary> --repo avw1ein/sillydes --predicate-type https://cyclonedx.org/bom`).
- The program version and the file format version are now separate (`src/version.h`), and
  `test/format-5.1.0/` holds fixtures that every release must still be able to decrypt.

### Documentation

- States that the program has no dependencies, that every algorithm is implemented from its
  standard, and how to make a release. This changelog was added.

## [5.1.0] - 2026-11-14

**File format: new (5.1.0).** Files from earlier releases cannot be read, and 5.1.0 files cannot be
read by earlier releases.

### Changed

- The program is now called **SillyDES** (formerly Odette) and its files start with `SD` instead
  of `OD`.
- Phrase mode uses **Argon2id** instead of scrypt.

## [5.03] - 2026-11-01

### Changed

- Constant-time bitsliced DES; every generated S-box circuit is tested against the FIPS 46 tables.
- The user's data is kept in one buffer, processed in place and wiped after use.

[Unreleased]: https://github.com/avw1ein/sillydes/compare/v5.2.1...HEAD
[5.2.1]: https://github.com/avw1ein/sillydes/compare/v5.2.0...v5.2.1
[5.2.0]: https://github.com/avw1ein/sillydes/compare/v5.1.1...v5.2.0
[5.1.1]: https://github.com/avw1ein/sillydes/compare/v5.1.0...v5.1.1
[5.1.0]: https://github.com/avw1ein/sillydes/compare/v5.03...v5.1.0
[5.03]: https://github.com/avw1ein/sillydes/releases/tag/v5.03
