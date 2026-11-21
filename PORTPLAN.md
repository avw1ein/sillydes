# Plan: make SillyDES portable (Linux, macOS, Windows) and harden it

## Decisions
| Topic | Decision |
|---|---|
| Build system | CMake only; Makefile removed once CMake builds, tests and regenerates the S-box header |
| Targets | Linux x64 + arm64 (gcc, clang); macOS arm64 + x86-64; Windows x64 (MSVC), x64 (MinGW/MSYS2), arm64. 64-bit only |
| File format | Format 5.2.0, in the tree since step 0b (section 0b); release 5.2.0 is a separate step and must precede the first Windows or macOS release. It replaced 5.1.0 because the phrase rules changed (section 3.4), and the ports must not change it: 5.2.0 is byte-identical on every platform, and `test/format-5.2.0/*` and `hello.sdes` must decrypt everywhere. Files of 5.1.0 are not read; release 5.1.1 converts them |
| Text | UTF-8 inside the program (phrase, file names, messages). Windows uses only W functions, never the ANSI or OEM code page |
| Phrase | One canonical form, part of format 5.2.0 and the same for encryption and decryption: well-formed UTF-8, no control characters, NFKC without invisible characters. The Unicode tables are frozen per format |
| KDF side channel | Argon2id data-dependent addressing is documented only (ANALYSIS.md section 8); no Argon2i mode |

CMake fails on non-64-bit targets and `static_assert(sizeof(void*) == 8)`.

## 0. Step 0, done: memory hygiene on the current Linux platform
Done first and independent of the port (no platform layer, no CMake needed); the format is unchanged and every existing test still passes. Findings M1-M8 of section 4.3 are fixed on Linux; only M9 (Windows) is open. What changed:

| Area | Change |
|---|---|
| Containers | `Buf` is now `std::vector<uint8_t, SecureAllocator>` (wipes the whole block on release; blocks of 64 KiB and more get their own mmap and `MADV_DONTDUMP`). `SecretBuf` uses `LockedAllocator` (private pages, `mlock` best effort, `MADV_DONTDUMP`, wiped and unmapped on release) and holds the phrase, the H0 input and the derived keys. `reserve_wiped` is gone. Neither type is a `std::string`, whose short-string buffer is inside the object and cannot be wiped. |
| Errors | `errorexit` = `report_error` + `throw ExitError{code}`; `main` runs everything in one `try` and returns the code (`bad_alloc` gives error 7). No `exit` on an error path, so destructors wipe keys, cipher state and data on error 13 and the rest. |
| Phrase input | `read(2)` byte by byte into a `SecretBuf`, no stdio; terminal echo restored by a destructor. |
| Key file | `readkeyfile` parses a `readfile` buffer instead of `fopen`/`fgets`; a missing file is now error 1 from `readfile`, a directory error 1. |
| Argon2id | Takes pointer and length, not `std::string`; returns `SecretBuf`; the 2 GiB table is a `SecureAllocator` vector that is reserved, `lock_memory`d (best effort, only when `RLIMIT_MEMLOCK` allows) and then zeroed. |
| Locking | `lock_stack()` in `main` touches and `mlock`s a 256 KiB stack window below `main` (halves down to 16 KiB under a small limit), so every local variable of the program, key schedules and hash intermediates included, stays out of swap. Never unlocked; ends with the process. |
| Stack scrub | `scrub_stack()` wipes the same 256 KiB stack window before `main` returns. Defence in depth: which temporaries and spilled registers a compiler leaves behind cannot be audited from the source. Checked with an injected leak (a 400-byte and a 30 KB stack array): found without the scrub (1 and 871 hits), gone with it. It was first added because CI reported plaintext in the stack; that report turned out to come from the residue scanner and its test, not from the program (see the lesson below). |
| Small gaps | SHA-512 message schedule and the HMAC inner digest are wiped; the DES S-box output array is wiped once per layer. |

Differences from the original M6 idea: no single secret arena. Stack objects are covered by the stack window and heap secrets by the page-sized `LockedAllocator`, which needed no change of ownership in the cipher or the container.

Verified: all existing tests; new unit tests (errors as exceptions, key file parser, buffer growth across the thresholds, `lock_stack`/`SecretBuf`/`lock_memory` against `/proc/self/status` `VmLck`, skipped when `RLIMIT_MEMLOCK` is under 1 MiB); `test/residue_scan.cpp` (an `LD_PRELOAD` scanner of the exited process, marks XOR-masked in the environment) in `test.sh`: no key text, key bytes, phrase (5000 characters) or plaintext remains after encryption, decryption and error 13, with a positive control. The old binary fails this test (key left in memory after an authentication failure; the phrase left in the heap in every phrase run). ASan + UBSan clean. No speed or peak-memory change (64 MiB: 4.7 s either way; phrase mode 1.8 s and 2.1 GB).

Known limits that remain: the data buffer is never locked (it can be as large as the file); the 2 GiB table is locked only if the limit allows it; the lock is best effort and silent, so encrypted swap is still the advice; heap blocks below 64 KiB of `Buf` are wiped but not locked; `Sha512::block` locals in registers cannot be wiped. The SHA-512 schedule wipe has no measured effect (the slot is overwritten by the next block), it is only correct.

Lessons that carry into the port: the residue scanner runs on the very stack it inspects, so it must keep its own frames out of the way (it moves them 96 KiB down and ignores hits in its own frame zone, shown separately) and snapshot a hit before printing, or it reports its own data as residue; check any scanner against an injected leak before trusting a green or a red result; read re-run results per attempt (`gh api .../runs/ID/attempts/N`), since `gh run view` lags after a rerun; and when failures alternate on one commit, suspect the harness before the program (here the test read two numbers from the scanner's output). A stack window is needed on every OS (Windows: `_alloca` + `SecureZeroMemory`); sanitizers replace `mlock` by a no-op, so the locking tests must skip under them; the residue test relies on `LD_PRELOAD` and `/proc/self/maps` (Linux only).

## 0b. Step 0b, done: file format 5.2.0 and text interchange on Linux
Done on Linux before the port, like step 0 (todo 14; no platform layer and no CMake needed). It gives the Linux version a file format that the Windows and macOS ports do not have to change: the rules that turn a phrase into keys are fixed, and they are the same code on every OS. The release of 5.2.0 is a separate step: `PACKAGE_VERSION` and the document titles still say 5.1.1 and the changelog entry stands under Unreleased. What changed:

| Area | Change |
|---|---|
| Format | `FORMAT_NAME "SillyDES 5.2.0"`, `MAGIC` `S D 5 0x20`. The layouts of the container, the armor and the key file are unchanged; only the labels and the phrase rules differ, and key files stay valid. Fixtures regenerated into `test/format-5.2.0/`, with a new `hello-utf8-phrase.sdes`; `test/format-5.1.0/` removed. A 5.1.0 file gives error 13 (container) or error 8 (armor). |
| Phrase | `canonical_phrase` in the new unit `src/text.cpp`, called by `getphrase` for encryption and decryption: the six steps of section 3.4. A refusal uses the old "Phrase too short" path (ask again on a terminal, error 10 otherwise) and comes before the KDF. |
| Unicode | `tools/gen_unicode.cpp` writes `src/unicode_tables.h` from Unicode 18.0.0: 5982 decompositions, 422 ranges of combining classes, 961 composition pairs, 17 ignorable ranges; 220 KB of source. `LICENSE.Unicode` holds the notice and the SBOM lists the data. |
| Key file, armor | `decode_text` (UTF-8 BOM; UTF-16 LE and BE with BOM), in place on pointer and length. CR ends a line in `readkeyfile` and in the tag search of `low2high`. The armor writer is unchanged. |
| Repository | `.gitattributes`; `tools/fetch_ucd.sh` (data files with pinned SHA-256 sums); Makefile targets `unicode` and `unicode-check`; workflow `unicode.yml`. |
| Documents | README 1, 5, 6, 7, 9, 10; STRUCTURE (units, 6.2, 6.3, 7.1, 9, 10); ANALYSIS 8 and its table of checks; CHANGELOG (Unreleased); the release skill. |

Differences from the plan of section 3.4:
- The conformance file is run by a program of its own, `test/unicode_conformance.cpp` (`make unicode-check`), not by the generator, so that the code under test is the `normalize` of the program and not a second copy.
- The licence notice is read from `LICENSE.Unicode` in the repository. The `license.txt` of unicode.org has no version and changes with the year, which would make the header unreproducible.
- The check against the data files is a workflow of its own, triggered by the paths it depends on, so that an outage of unicode.org cannot turn the `build` workflow red before a release.

Verified:
- All existing tests; `make test` takes 23 s.
- `make unicode-check`: the committed tables are byte for byte what the generator makes of the downloaded files; 20171 conformance cases give their NFKC column from each of their five columns; the 1094910 code points the file does not list are unchanged; the phrase folding gives one result per line, leaves no ignorable code point and is stable under a second pass, for every line and every code point.
- 200000 random strings against Python's `unicodedata` (Unicode 16.0.0, characters assigned there): equal, for NFKC and for the folding. The expected values of the unit tests come from Python and from a separate re-implementation of the armor, not from the new code.
- No visible character of 18.0.0 decomposes into an invisible one, so the folding equals "NFKC of the text without its invisible characters".
- ASan + UBSan clean: the unit tests, the conformance run, and 420000 random and damaged phrases, armor texts and key files.
- Residue scan with a non-ASCII phrase (UTF-8 bytes and 32-bit code points): 0 hits. Control: with the code points in an ordinary vector the scan finds 2.
- Control on the tables: one changed composition pair fails the table hash and 35 conformance cases.
- The 5.1.1 binary refuses a 5.2.0 file and the new binary a 5.1.0 file (error 13, error 8).
- `.gitattributes` renormalises nothing.

Known limits that remain: those of section 3.4 (look-alikes, characters assigned after 18.0.0, UTF-16 without a BOM, quoted armor tag lines); the normalisation is not constant-time; a 5.1.0 file needs release 5.1.1.

What is left for the ports: only the calls at the edge (section 3.4, "Data files, file names and messages"). The format, the phrase rules, the tables and their tests are finished and must not change. The new unit tests are plain C++ and port as they are; the new parts of `test.sh` move to `test_e2e.cpp` with the rest.

Lessons that carry into the port: "strip a trailing CR" looked like a bug fix and was a format change, so settle anything that touches the bytes of a phrase before the first release on a new OS; take expected test values from an independent source; pin every downloaded input by hash and keep unversioned inputs (the licence text) in the repository; `writefile` makes fixtures with mode 0600, so set 0644 before committing them.

## 1. State of the code
The crypto core is portable C++11: byte-wise (de)serialisation, no asm, intrinsics, `__int128` or libraries.
Non-portable code is in the OS layer.

### 1.1 Linux-only code
| Where | Linux-ism |
|---|---|
| src/common.cpp | open/read/write/fstat, O_NOFOLLOW, O_CLOEXEC, mode 0600, getrandom, prctl, setrlimit, explicit_bzero, no O_BINARY |
| src/kdf.cpp `require_memory` | /proc/meminfo, sysconf(_SC_AVPHYS_PAGES), RLIMIT_AS/DATA |
| src/keys.cpp | termios, isatty, STDIN_FILENO, fopen(name,"r") |
| src/main.cpp | stat() st_dev/st_ino same-file test; argv as bytes |
| src/sha512.cpp, src/blake2b.cpp | call explicit_bzero directly instead of wipe() |
| test/test_primitives.cpp, tools/gen_des_sbox.cpp | __builtin_popcount, __builtin_ctz |
| test/test.sh | bash, stat -c, head -c -N, od, md5sum, ulimit -v, /dev/urandom |
| Makefile, .github/workflows/build.yml | GNU make; ubuntu only |

### 1.2 Latent bugs a port would trigger
Items 2, 3, 4, 7, 9, 10 and 11 to 16 are about character sets and line endings; section 3.4 solves them. Step 0b fixed 2, 3, 7 and 11 to 16 (section 0b). Open for the Windows port: 4, 9, and of 10 the conversion at the console, since the phrase rules themselves are done. "Measured" means reproduced on Linux with the 5.1.1 binary, before step 0b. Those bugs are not Windows-only: a key file or a phrase file made on Windows fails on Linux today.

1. Same-file check: on Windows st_ino is 0, so every run fails with error 6.
2. CRLF key files: `\r` is not treated as whitespace, giving error 5 (measured).
3. CRLF phrase: a piped phrase keeps a trailing `\r` and derives different keys, so decryption ends in error 13 (measured, also for a `\r` at the end of input and for spaces followed by CRLF, where the trimming of trailing spaces stops at the `\r`).
4. Binary mode: Windows text mode translates CRLF and treats 0x1A as EOF; use `CreateFileW`, so that no text mode exists. On Linux, data with 0D 0A 1A 00 round-trips byte-exact (measured).
5. `unsigned long`/`%lu`/`strtoul` in armor.cpp is 32-bit on Windows x64; breaks above about 4 Gi characters.
6. Unchecked size arithmetic in container.cpp and readfile; add overflow checks.
7. No `.gitattributes`: a checkout with `core.autocrlf=true` gives `sample.key`, `hello.sdes` and `test/format-5.1.0/hello-phrase.sdes` CRLF line endings (measured). The two armored files still decrypt, `sample.key` is then error 5 (item 2). `test/format-5.1.0/hello.bin` is detected as binary and stays intact, but only by git's guess; nothing guarantees it for the next fixture.
8. Error-7 test relies on `ulimit -v`, unavailable on macOS/Windows.
9. Windows argv is in the ANSI code page; non-ASCII file names fail.
10. Phrase bytes come from the OEM/ANSI code page on Windows but are UTF-8 on Linux/macOS: same phrase, different keys (measured on Linux with CP1252 and CP850 input). A piped phrase has no defined encoding on Windows at all: cmd writes the OEM code page, Windows PowerShell 5.1 writes ASCII and turns every other character into `?`, PowerShell 7 writes UTF-8, and a redirected file holds whatever the editor saved.
11. Byte order mark: a UTF-8 BOM gives error 5 in a key file, error 8 in armored text when it stands directly before `*BEGIN` (before the leading blank line it is harmless), and different keys at the start of a piped phrase (measured).
12. UTF-16: Windows PowerShell 5.1 `>` and the UTF-16 options of Notepad write UTF-16 with a BOM. Error 5 for a key file, error 8 for armored text, different keys for a phrase (measured).
13. CR-only line endings: error 5 for a key file, error 8 for armored text (measured).
14. Unicode equivalence: the same phrase as NFD instead of NFC derives different keys (measured). So do full-width forms from an East Asian input method, a no-break space, and an invisible character (zero-width space, soft hyphen) that came along with pasted text.
15. Encryption accepts a phrase that nobody can reproduce: a tab or the escape sequence of an arrow key becomes part of the phrase (measured: different keys), and so do bytes that are not UTF-8, such as UTF-16 from a pipe or what is left after a backspace over an accented letter on a terminal without `iutf8` (not measured). The file is made without a warning and is then very hard to open.
16. A fix for 3, 10, 11, 14 or 15 changes the keys of some phrases, so files written by one release are no longer read by another. By the project's own definition that is a new file format: "no format bump" and a phrase fix cannot both hold. Hence the decision above.
17. Observation, not solved here: an armor tag line that is quoted (`> `) or indented gives error 8 (measured). Not a character-set problem.

## 2. Architecture: thin platform layer
`src/platform.h` with `platform_posix.cpp` (Linux + macOS, `#ifdef __APPLE__`) and `platform_win32.cpp`. No other file includes OS headers. Keep `Buf`, `wipe`, `randbytes`, `readfile`, `writefile`, `errorexit` as the stable API.

| Function | Linux | macOS | Windows |
|---|---|---|---|
| secure_zero (backs wipe) | explicit_bzero | memset_s | SecureZeroMemory |
| os_random | getrandom (fallback /dev/urandom) | getentropy in 256-byte chunks | BCryptGenRandom (system preferred RNG) |
| file read/write | POSIX, O_NOFOLLOW, 0600 | same | CreateFileW, binary, refuse reparse points on output, UTF-8<->UTF-16 |
| same_file | st_dev+st_ino | same | GetFileInformationByHandle (volume serial + file index) |
| available_memory | MemAvailable + rlimits | hw.memsize, host_statistics64 (free+inactive+speculative), rlimit | GlobalMemoryStatusEx (ullAvailPhys and ullAvailPageFile), job limits |
| harden_process | existing lockdown() | RLIMIT_CORE=0, PT_DENY_ATTACH | see 4.1 |
| secure_alloc / locked_alloc / lock_memory / lock_stack (exist in common.cpp today; move into the layer) | mmap + mlock + MADV_DONTDUMP (+ alloca stack window) | mmap + mlock (no MADV_DONTDUMP there; RLIMIT_CORE=0 already prevents dumps; stack window the same; check the default RLIMIT_MEMLOCK) | VirtualAlloc + VirtualLock + WerRegisterExcludedMemoryBlock; stack window via `_alloca` + VirtualLock (VirtualLock is bounded by the minimum working set, so raise it with `SetProcessWorkingSetSize` first and verify) |
| read_secret_line (returns one raw line of bytes; the canonical form of 3.4 is made in keys.cpp) | termios, /dev/tty fallback; read(2) up to LF or end of input | same | console: SetConsoleMode without echo (restored by a destructor), ReadConsoleW into a locked, wiped buffer, strict UTF-16 -> UTF-8; pipe or file: ReadFile, bytes as they are |
| utf8_args | identity | identity | wmain (MinGW: `-municode`) -> UTF-8; not CommandLineToArgvW, which pulls in shell32 |
| write_message (usage, errors, prompts) | bytes to stdout/stderr | same | WriteConsoleW when the handle is a console, UTF-8 bytes when redirected |

## 3. Portability work
### 3.1 Portable code
- Route every explicit_bzero in sha512.cpp and blake2b.cpp through wipe().
- armor.cpp: uint64_t, PRIu64, strtoull; reject counts that overflow size_t.
- Checked-size helpers used by readfile, seal, unseal, high2low.
- Replace __builtin_* in tests/tools with portable loops.
- **Done (step 0b).** Text interchange (section 3.4, todo 14): format 5.2.0 in `src/version.h`; new unit `src/text.cpp` (`decode_text` for the key file and armor, the canonical form of the phrase); `tools/gen_unicode.cpp` and the generated `src/unicode_tables.h`; CR ends a line in `readkeyfile` and in the tag search of `low2high`.
- Never call `setlocale`, so that `tolower`, `strtoul` and `snprintf` behave the same on every OS.
- MSVC `/utf-8` so FORMAT_NAME and labels (hashed into keys) are identical bytes everywhere. The sources are ASCII, so this is a safeguard.

### 3.2 Windows
- MSVC x64/arm64 and MinGW-w64: wmain (MinGW: `-municode`) + UTF-8, CreateFileW for every file (no CRT text mode), link bcrypt, `_WIN32_WINNT >= 0x0A00`.
- Messages through WriteConsoleW when stdout or stderr is a console, as UTF-8 bytes when redirected. No SetConsoleOutputCP: it changes the user's console for the rest of the session. The program's own messages stay ASCII; the file names in them need not be.
- Phrase: ReadConsoleW on a console, ReadFile on a pipe or a redirected file (section 3.4).
- No 0600: output inherits directory ACL (document), optionally a current-user-only DACL.
- Replace O_NOFOLLOW with FILE_FLAG_OPEN_REPARSE_POINT and refuse reparse points on output.

### 3.3 macOS
- Universal binary via CMAKE_OSX_ARCHITECTURES.
- No getrandom, /proc, explicit_bzero; RLIMIT_AS not enforced (error-7 test needs another trigger).
- Hardened runtime + codesign (no get-task-allow); notarization optional.
- Memory policy: refuse if hw.memsize minus headroom is below 2 GiB or free+inactive+speculative is clearly insufficient.

### 3.4 Same bytes everywhere
Solves items 2, 3, 4, 7, 9, 10 and 11 to 16 of section 1.2. Everything here except the Windows calls is platform-independent and is done (step 0b, section 0b); headings marked "done" describe what is in the tree. The Windows calls remain for the port.

#### Principles
- Inside the program every text is UTF-8: phrase, file names, messages. The platform layer converts at the edge.
- Data is bytes. Plaintext and the binary container are never translated; a CRLF text file decrypts to CRLF on every OS.
- Text the program writes (armor) is the same on every OS: LF only.
- Text the program reads (key file, armor, phrase) is accepted with every line ending and in the common encodings.
- The phrase rules are part of the file format, so the format name says which rules a file follows.

#### File format 5.2.0 (done, not yet released)
- `FORMAT_NAME "SillyDES 5.2.0"` and `MAGIC` `S D 5 0x20` changed together. The labels of the whitening, the tweak and the key-file MAC key change with the name, so the two formats are also separated cryptographically.
- The container layout, the armor layout and the key file layout stay as they are, and existing key files keep working. Only the phrase rules below are new.
- Files of 5.1.0 are refused like those of any other version: error 13 for a container, error 8 for armored text. Release 5.1.1 decrypts them, and the changelog says so.
- Procedure followed: the format-change appendix of `.github/skills/make-release/SKILL.md` (fixtures regenerated into `test/format-5.2.0/`, `test/format-5.1.0/` removed, `hello.sdes` regenerated, the stored known answer of the core block replaced after confirming that only the label changed).
- Order: release 5.2.0 goes out before the first Windows or macOS release, so that no binary on those systems ever writes 5.1.0.

#### Phrase: canonical form of format 5.2.0 (done)
The platform layer delivers one raw line of bytes (`read_secret_line`, section 2). `keys.cpp` then applies these steps, the same ones for encryption and for decryption and on every OS:

| # | Step | If it fails |
|---|---|---|
| 1 | Remove one trailing CR | |
| 2 | Must be well-formed UTF-8: no overlong forms, no surrogates, at most U+10FFFF | refuse |
| 3 | No control characters (U+0000-001F, U+007F-009F), so no tab either | refuse |
| 4 | NFKC without invisible characters: compatibility decomposition, drop the code points with the property Default_Ignorable_Code_Point, canonical reordering, composition | |
| 5 | Remove trailing spaces (existing rule) | |
| 6 | At least 20 characters, counted as code points after steps 1 to 5 (5.1.0 counts bytes) | refuse |

- What the steps cover: CRLF and CR (1); other code pages, UTF-16 and a broken backspace (2); arrow keys, tabs and NUL (3); NFC against NFD, full-width against half-width forms, no-break and ideographic spaces, a BOM, zero-width space, soft hyphen, direction marks and variation selectors (4).
- A refusal follows the existing "Phrase too short" pattern: a message, ask again on a terminal, error 10 on a pipe. No new error number. It comes before the Argon2id run, so an impossible phrase costs neither 2 GiB nor an error 13.
- Leading spaces stay part of the phrase.
- A pure ASCII phrase takes a path that touches no table.
- The confirmation compares canonical forms.
- The result is only ever hashed, so folding shows nowhere. It lowers the entropy of a phrase only where two spellings look alike.

#### Unicode tables and code (done)
- `tools/gen_unicode.cpp` reads `UnicodeData.txt`, `DerivedNormalizationProps.txt` and `DerivedCoreProperties.txt` and writes `src/unicode_tables.h`, which is committed like `des_sbox_ct.h` (`make unicode UCD=directory`). The Unicode files are not committed and the build does not fetch them; `tools/fetch_ucd.sh` downloads them and checks their SHA-256.
- Tables of Unicode 18.0.0: 5982 full compatibility decompositions, 422 ranges of combining classes, 961 composition pairs, 17 default-ignorable ranges. Hangul is computed.
- `src/text.cpp`: the UTF-8 check, decoding, the steps above (UAX #15) and encoding. It works in locked, wiped buffers and uses no `std::string`.
- The tables are frozen for format 5.2.0; the header records the version. A newer Unicode version is a newer format. Characters assigned later are not folded, but that holds for every platform equally, so interchange does not suffer. A unit test compares a SHA-512 of the tables with a constant, so an accidental regeneration fails.
- Verification: `make unicode-check` confirms that the committed header is what the generator makes of the data files, and `test/unicode_conformance.cpp` runs the complete `NormalizationTest.txt` (NFKC column) through the program's own `normalize` and checks that the folding is stable under a second pass for every line and every code point. The unit tests carry a fixed subset: reordering, blocked composition, exclusions such as U+0958, singletons such as U+212B, full-width forms, Hangul, an ignorable between a base and a mark.
- The generated header carries the Unicode License v3 notice, copied from `LICENSE.Unicode`; README and SBOM name the data. It is data in the source tree, like the FIPS tables behind the S-box header, so the "no dependencies" claim holds.

#### Key file and armored text (done)
- One shared `decode_text`, used only by `readkeyfile` and `low2high` and never on data files: it removes a UTF-8 BOM and turns UTF-16 LE or BE with a BOM into bytes (a code unit above 0x7F becomes `?`). It works in place, so key text stays in the `Buf` that wipes it. UTF-16 without a BOM is not recognised.
- Key file: LF and CR both end a line. Everything else as today.
- Armor reader: the tag lines are found after LF or CR. The body already ignores every byte outside the alphabet.
- Armor writer: unchanged, LF on every OS, so equal containers give equal text. The alphabet `0-9 : ; A-Z a-z` is ASCII and survives every ASCII-based character set.

#### Data files, file names and messages (Windows: open)
- Data files on Windows: `CreateFileW`, so no text mode exists; no CRT file descriptor is used for data.
- Arguments on Windows: `wmain` (MinGW: `-municode`) to UTF-8. An argument that is not valid UTF-16 is error 4.
- File names are never normalised: Linux passes the bytes, macOS and Windows pass the name to the OS as given.
- Messages on Windows: `WriteConsoleW` when the handle is a console, UTF-8 bytes when redirected.
- Phrase on Windows: `ReadConsoleW` on a console, converted strictly to UTF-8 (an unpaired surrogate is refused); a line that starts with Ctrl+Z is end of input. On a pipe or a redirected file the bytes are taken as they are: a pipe carries UTF-8, and text in another encoding is refused by step 2 or 3 in nearly every case.

#### Repository (done)
- `.gitattributes`: `* text=auto eol=lf`, `*.bin binary`, `*.sdes -text`, `*.key text eol=lf`, `test/format-*/** -text`.
- No tracked file contains a CR or a BOM today and `src/`, `test/` and `tools/` are pure ASCII, so adding the file renormalises nothing. A test keeps the sources ASCII with LF.

#### Limits that remain (README section 7 has those that apply to Linux)
- Windows PowerShell 5.1 replaces non-ASCII characters by `?` before the program sees them, which cannot be detected. Advice: set `$OutputEncoding` to UTF-8, or use PowerShell 7; in cmd use `chcp 65001`.
- Look-alikes that Unicode keeps apart stay different: straight and curly quotes, hyphen and dashes, Latin and Cyrillic letters, upper and lower case.
- Characters assigned after the pinned Unicode version are not folded.
- mintty without ConPTY presents stdin as a pipe: the phrase is echoed and not confirmed. The keys are still right.

## 4. Security hardening
### 4.1 Process hardening
| Goal | Linux | macOS | Windows |
|---|---|---|---|
| No dumps | RLIMIT_CORE=0, PR_SET_DUMPABLE=0 | RLIMIT_CORE=0 | SetErrorMode(SEM_NOGPFAULTERRORBOX); WerRegisterExcludedMemoryBlock for keys/arena; verify, as WER ignores rlimit |
| Block same-user debugger | PR_SET_DUMPABLE=0 | PT_DENY_ATTACH + hardened runtime | restrictive DACL on own process (drop VM_READ/VM_WRITE); admin/SeDebug still bypasses: mitigation, not a boundary |
| Code injection | n/a | hardened runtime | SetProcessMitigationPolicy: dynamic code prohibited, extension points disabled, strict handle checks |

All best-effort, never fatal. README section 8 must state exactly what each OS does.

### 4.2 Build hardening (keep -Wall -Wextra -Werror in CI)
- GCC/Clang Linux: -fstack-protector-strong, -D_FORTIFY_SOURCE=3 (2 on old toolchains), -fstack-clash-protection, -fcf-protection (x86), -mbranch-protection=standard (arm64), PIE, -z relro -z now -z noexecstack.
- macOS: PIE, stack protector, hardened runtime at signing.
- MSVC: /GS /sdl /guard:cf /Qspectre, /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /CETCOMPAT. MinGW: -fstack-protector-strong -Wl,--dynamicbase,--nxcompat,--high-entropy-va.
- CI jobs with ASan+UBSan (Linux, macOS) and MSVC /fsanitize=address.

### 4.3 Memory hygiene gaps (M1-M8 fixed on Linux in step 0; M9 and the other OSes remain)
| # | Finding | Fix |
|---|---|---|
| M1 | **Done (Linux).** getphrase/read_hidden used getchar(); the stdin stdio buffer kept a copy of the phrase, never wiped | read() into a SecretBuf, no stdio. Windows: ReadConsoleW into the same type |
| M2 | **Done.** s.reserve(1024); longer phrases realloc and left an unwiped copy; `again` not reserved; short strings live inside the std::string object | SecretBuf (no short-string buffer, wipes on growth/destruction) |
| M3 | **Done.** readkeyfile used fopen/fgets; FILE buffer held key text; line/parse wiped only on success | parses a readfile Buf; wiped on every path (RAII) |
| M4 | **Done.** errorexit() called exit(), so destructors never ran: KeyInput, KeyMaterial, SillyDesCipher (keys, schedules, whitening) and the data buffer were not wiped on any error path (e.g. error 13); measured: key text left in memory | errorexit throws ExitError, caught in main, so RAII unwinds and wipes |
| M5 | **Done.** reserve_wiped workaround for std::vector growth | SecureAllocator wiping on deallocate; Buf keeps its name; reserve_wiped removed |
| M6 | **Done (Linux).** Secrets could be swapped | not one arena: lock_stack() window of 256 KiB (covers every stack-held secret: keys, 8 schedules about 24 KiB, whitenings, pad states, KDF blocks) + LockedAllocator pages for heap secrets; best-effort, silent |
| M7 | **Partly done (Linux).** 2 GiB Argon2 arena and whole-file plaintext are not lockable unprivileged; a swapped arena is key-equivalent | arena: lock_memory when the limit allows, MADV_DONTDUMP (blocks of 64 KiB and more); residual risk documented in README 8 and ANALYSIS 8; encrypted swap advised. Open: memfd_secret investigation |
| M8 | **Done.** Plaintext wiped only on main's success path | covered by M4 + M5 |
| M9 | Windows: vector<Block>::resize(2 GiB) needs 2 GiB commit | VirtualAlloc(MEM_COMMIT) with ullAvailPageFile check in require_memory |

### 4.4 KDF memory-hardness per platform
- Keep m = 2 GiB, t = 1, p = 4 and the RFC 9106 vectors.
- require_memory equivalent on all OSes; keep "fail with error 7, never overcommit and die".
- No large/huge pages by default. No SIMD (small audit surface, identical behaviour).
- Report KDF time on arm64 and Windows in CI logs (expect about 2 s).

## 5. Constant-time
### 5.1 Review
| Component | Status | Note |
|---|---|---|
| DES layer, setkey | Constant-time by construction | bitsliced, boolean S-boxes, constant indices, `0u - bit` masks |
| SHA-512 / HMAC / BLAKE2b | Constant-time by construction | K512[i] indexed by public counter |
| Tag compare in unseal | Correct pattern, but compiler may make it early-exit | ct_equal() helper with optimisation barrier |
| length_mask, pad256, unpad256 | Run after authentication; only leak is public length | keep; test that bad data never reaches them |
| readkeyfile / htoa | Not constant-time: branches per key character | branch-free hex decode |
| getphrase length check | Branches on length | leave |
| Phrase canonical form (text.cpp) | Not constant-time: table lookups and branches depend on the phrase | leave; same class as the Argon2id addressing, and an ASCII phrase touches no table |
| Argon2id | Data-dependent addressing in 2nd half of pass 0 | documented only; note same on all OSes, shared hosts/VMs are the exposure |

### 5.2 Compiler/arch risk
- value_barrier() (empty asm on GCC/Clang, volatile read on MSVC) around mask creation in setkey, ct_equal, hex decode.
- arm64: set DIT (`msr dit, #1`) around the cipher where available (Apple M, ARMv8.4+).
- Confirm BlaMka's 32x32->64 multiply stays constant-time per target.

### 5.3 Verification
1. Valgrind/ctgrind job (Linux x64): secrets marked undefined through setkey, layer, Hmac512, ct_equal, hex decode; gcc and clang at -O0/-O2/-O3.
2. Disassembly gate (CMake test): fail on data-dependent conditional jumps in des/sha512 objects outside an allow-list (x86-64, arm64). Start report-only.
3. Nightly dudect-style test on Linux, macOS arm64 and Windows.
4. Test that wrong-key vs right-key decrypt time does not depend on where the MAC differs.
5. Record results per compiler/arch in ANALYSIS.md section 8.

## 6. Tests
- Port test.sh to C++ `test_e2e.cpp` under CTest (library calls + a spawn helper for CLI runs); dependency-free, same on all OSes.
- Port, do not drop, the Linux-only checks of step 0: the unit tests of the key file parser, buffer growth and locking (skip under sanitizers), and the residue scan. The scan needs an equivalent per OS: `DYLD_INSERT_LIBRARIES` + `vm_region` on macOS; on Windows an in-process variant (a test-only hook in the binary that walks `VirtualQuery` regions at exit) is simpler than injecting a DLL. Prefer one in-process implementation (test build only) for all three, so the scanner is not itself a platform port.
- Keep: golden decrypts (hello.sdes, format-5.2.0/hello.bin, hello-phrase.sdes, hello-utf8-phrase.sdes); round trips at 0, 1, 255, 256, 257, 1000, 5000; tamper tests (bit flip, truncation, header, KDF params); wrong key/phrase; parity bit; short key file; short phrase; fresh salt/IV; repeated blocks.
- New: in/out same file via different path spellings, hard link, symlink, case-insensitive paths; armor counter above 2^32 (unit test); size-overflow guards.
- **Done (step 0b), in test_primitives.cpp; runs on every OS once ported.** Text interchange (section 3.4), unit tests: `decode_text`; one key file as LF, CRLF, CR, with a UTF-8 BOM and as UTF-16 LE and BE gives the same keys; the armored fixture in the same variants decrypts; an armor known answer without CR; the canonical phrase table (every step, accepted and refused); the normalisation subset and the hash of the tables.
- **Done (step 0b), in test.sh; port to test_e2e.cpp.** Text interchange, end to end: new fixture `test/format-5.2.0/hello-utf8-phrase.sdes` (Latin, Greek, CJK and one character outside the BMP) opened with NFC, NFD, full-width, CRLF and BOM input and with an invisible character inserted; a phrase that is not UTF-8 is refused without a KDF run; a 5.1.0 file is refused; a data file containing 0x0D 0x0A 0x1A; non-ASCII input, output and key file names; the residue scan with a non-ASCII phrase.
- New, Windows only: a phrase typed into a console through injected key events (WriteConsoleInputW), including a surrogate pair; a piped CRLF phrase; a redirected message is UTF-8.
- Error 7 without ulimit: injectable available_memory() in test builds; keep ulimit test on Linux.
- Cross-OS interop: CI uploads files encrypted on one OS (binary and armored; with a key file, an ASCII phrase and a non-ASCII phrase) and decrypts them on the others. The Windows job also writes a key file with PowerShell `>`.

## 7. Build, CI, release
- CMakeLists.txt: C++11, extensions off; targets sillydes, test_primitives, test_e2e, gen_des_sbox, gen_unicode; options SILLYDES_REGENERATE_SBOX and SILLYDES_REGENERATE_UNICODE (the latter takes a directory with the Unicode data files); per-compiler flags from 4.2; install rule; presets. Delete Makefile; update README section 1, STRUCTURE.md, and the "Linux command line port" comment in main.cpp.
- CI matrix: ubuntu (gcc, clang), Linux arm64, macOS arm64 and Intel, windows-latest (MSVC x64), Windows arm64, MSYS2 mingw64. Extras: sanitizers, valgrind ct test, interop, optionally s390x under QEMU for big-endian. Pick runner labels at implementation time.
- Keep the "no dependencies" claim: CI installs only compilers and CMake. The Unicode tables are generated data in the source tree, like the S-box header.
- **Done (step 0b)** as the workflow `unicode.yml` with the Makefile targets `unicode` and `unicode-check`: download the Unicode data files of the pinned version (checked against stored SHA-256 sums), confirm that the generator reproduces the committed `src/unicode_tables.h`, and run the complete `NormalizationTest.txt`. Port the two targets to CMake.
- Optional release: Authenticode, macOS codesign + notarization, SHA-256 sums, SBOM, reproducible-build check.
- SECURITY.md: threat model and known limits (swap, Argon2 cache timing, same-user admin on Windows).

## 8. Documentation
- README (the format, key file, armor and phrase parts are done in step 0b; the OS-specific parts remain): sections 1 (CMake, supported OS, format 5.2.0 and that 5.1.1 converts older files), 5 (line endings and encodings accepted in armored text), 7 (Windows quoting; key file line endings and encodings; the phrase rules: what is folded, what is refused, the PowerShell 5.1 advice and the other limits of 3.4; "every character your computer accepts is allowed" no longer holds), 8 (exact per-OS hardening), 9 (error 7 per OS).
- ANALYSIS.md section 8: per-OS wording and verification results; the phrase canonical form (folding and entropy, not constant-time).
- STRUCTURE.md: platform layer, units table (`text.cpp`, the generator, the generated header), build, 5.1 (phrase rules), 6.2 (armor reader), 7 (phrase input diagram).
- CHANGELOG.md and the release notes: "File format: new (5.2.0)", the reason, and that 5.1.1 decrypts older files (done, under Unreleased). The renaming of the labels in the other documents follows the format-change appendix of the release skill, whose own examples name 5.1.0 too.

## 9. Todos (dependencies)
0. memory-hygiene-linux: **done** (section 0)
1. cmake-baseline
2. platform-layer (after 1); move `secure_alloc`, `locked_alloc`, `lock_stack`, `lock_memory` and the secret-line input into it
3. portable-fixes (after 2)
4. memory-hygiene (after 2): now only the non-Linux parts (M9, Windows/macOS locking, WER exclusion, ReadConsoleW)
5. windows-port (after 3, 4, 14); includes the Windows calls of section 3.4 (wmain, CreateFileW, ReadConsoleW, WriteConsoleW)
6. macos-port (after 3, 4, 14)
7. ct-hardening (after 2)
8. ct-verification (after 7)
9. build-hardening (after 1)
10. tests-portable (after 3, 14)
11. ci-matrix (after 5, 6, 9, 10)
12. docs-update (after 8, 11)
13. remove-makefile (after 11)
14. text-interchange: **done** (section 0b), except the release of 5.2.0, which is a step of its own and must precede the release of 5 and 6

## 10. Risks
- errorexit -> exception: done in step 0, with the error table exercised by `test.sh`; keep nothing but `main` and the tests catching `ExitError`, and never call `exit` on an error path (it skips the wiping destructors).
- `mlock` limits differ by OS and distribution (macOS and Windows have small defaults; Windows needs a larger working set first); everything must stay best effort and silent, and the tests must skip below a limit.
- Windows process-DACL and WER APIs vary by version; use feature tests, treat as optional.
- Disassembly gate may be noisy across compilers; report-only first.
- Format 5.2.0 breaks every 5.1.0 file, also those made with a key file or an ASCII phrase. Release 5.1.1 must stay available and be named in the release notes.
- The Unicode tables are frozen per format. Characters assigned later are not folded, and regenerating the tables under the same format name would change keys; the table hash test guards against that.
- The normalisation code is new code that parses secret input, and an error in it changes keys without any message. Mitigation: the complete conformance file at generation time, the table hash, the unit subset, ASan + UBSan runs, and the cross-OS interop job with a non-ASCII phrase.
- Folding does not cover look-alikes that Unicode keeps apart, and Windows PowerShell 5.1 replaces non-ASCII characters by `?` before the program sees them. Both are documented limits; a random ASCII phrase avoids them.
- The Unicode data is under the Unicode License v3; the generated header must carry the notice.
- Argon2 timing leak remains by decision; docs must say so on every platform.