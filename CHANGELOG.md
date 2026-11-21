# Changelog

All notable changes to SillyDES, newest first. Every release says whether the **file format**
changed, because that decides whether files written by one release can be read by another.
The format is named after the release that introduced it (currently 5.1.0); see section 1 of the
[README](README.md).

Maintainers: add the entry for a release here before tagging it. The release workflow publishes
the section of the tag's version as the text of the GitHub Release.

## [Unreleased]

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
  `sillydes-X.Y.Z-linux-x86_64`, its SBOM, `SHA256SUMS` and a build attestation
  (`gh attestation verify <binary> --repo avw1ein/sillydes`).
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

[Unreleased]: https://github.com/avw1ein/sillydes/compare/v5.1.1...HEAD
[5.1.1]: https://github.com/avw1ein/sillydes/compare/v5.1.0...v5.1.1
[5.1.0]: https://github.com/avw1ein/sillydes/compare/v5.03...v5.1.0
[5.03]: https://github.com/avw1ein/sillydes/releases/tag/v5.03
