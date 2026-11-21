# Changelog

All notable changes to SillyDES, newest first. Every release says whether the **file format**
changed, because that decides whether files written by one release can be read by another.
The format is named after the release that introduced it (currently 5.1.0); see section 1 of the
[README](README.md).

Maintainers: add the entry for a release here before tagging it. The release workflow publishes
the section of the tag's version as the text of the GitHub Release.

## [Unreleased]

### Added

- A CMake build next to the Makefile (`cmake --preset default`, see the README), tested with gcc
  and clang by the `build` workflow. The program is unchanged by it.
- First source for Windows (`src/platform_win32.cpp`, `wmain`) and macOS, built and tested by the
  `build` workflow on the Windows (MSVC, MinGW-w64) and macOS (arm64, Intel) runners. These
  builds are not released yet: the hardening and the console input of the Windows version, and
  the macOS version's packaging, are still to come (PORTPLAN.md). The workflow also runs on a
  native arm64 Linux runner and with AddressSanitizer and UndefinedBehaviorSanitizer.
- Memory hygiene on Windows and macOS, as on Linux: pages that hold keys, phrase and plaintext are
  locked in RAM (on Windows the working set is raised first, which `VirtualLock` needs), the
  stack window is locked, secret blocks are kept out of Windows Error Reporting dumps, and on macOS
  a debugger cannot attach (`PT_DENY_ATTACH`). Error 7 (not enough memory) also honours the memory
  limit of a Windows job object.
- Windows process hardening: the access control list of the process leaves the owner no right to
  read or write its memory (a debugger or dump tool of the same user is refused; an administrator
  with SeDebugPrivilege is not stopped), and the process allows no code generated at run time, no
  extension points, no images from network shares and no child process. The unit tests read all of
  it back from the OS. The end-to-end tests search the memory of the finished process for
  keys, phrases and plaintext on Windows and macOS too, and found none.
- Releases after 5.2.0 also carry a build provenance attestation: which workflow, commit and
  runner built the binary. `gh attestation verify <binary> --repo avw1ein/sillydes` checks it;
  the SBOM attestation is checked with `--predicate-type https://cyclonedx.org/bom` added.

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

[Unreleased]: https://github.com/avw1ein/sillydes/compare/v5.2.0...HEAD
[5.2.0]: https://github.com/avw1ein/sillydes/compare/v5.1.1...v5.2.0
[5.1.1]: https://github.com/avw1ein/sillydes/compare/v5.1.0...v5.1.1
[5.1.0]: https://github.com/avw1ein/sillydes/compare/v5.03...v5.1.0
[5.03]: https://github.com/avw1ein/sillydes/releases/tag/v5.03
