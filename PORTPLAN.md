# Plan: make SillyDES portable (Linux, macOS, Windows) and harden it

> **Status: finished working document.** The port is done, and what it taught is kept in the repository
> proper: design and per-system pitfalls in [STRUCTURE.md](STRUCTURE.md) sections 11 and 12, tests, CI,
> findings and what cannot be verified in [TESTING.md](TESTING.md), the threat model in
> [SECURITY.md](SECURITY.md), what a user sees in the [README](README.md), how to work with the runners in
> `.github/skills/runner-driven-development/SKILL.md`, and releases in `.github/skills/make-release/SKILL.md`.
> Nothing else refers to this file; it is the history (todo by todo, with the numbers and the dead ends)
> and may be deleted.

## Decisions
| Topic | Decision |
|---|---|
| Build system | CMake only; the Makefile is removed (0l) |
| Targets | Linux x64 + arm64 (gcc, clang); macOS arm64 + x86-64; Windows x64 (MSVC), x64 (MinGW/MSYS2), arm64. 64-bit only |
| File format | Format 5.2.0, made in step 0b (section 0b) and introduced by release 5.2.0, before any Windows or macOS release. It replaced 5.1.0 because the phrase rules changed (section 3.4), and the ports must not change it: 5.2.0 is byte-identical on every platform, and `test/format-5.2.0/*` and `hello.sdes` must decrypt everywhere. Files of 5.1.0 are not read; release 5.1.1 converts them |
| Text | UTF-8 inside the program (phrase, file names, messages). Windows uses only W functions, never the ANSI or OEM code page |
| Phrase | One canonical form, part of format 5.2.0 and the same for encryption and decryption: well-formed UTF-8, no control characters, NFKC without invisible characters. The Unicode tables are frozen per format |
| KDF side channel | Argon2id data-dependent addressing is documented (ANALYSIS.md section 8); the optional Argon2i mode (`argon2i` or `SILLYDES_ARGON2I=1`, header byte 7) removes it |
| Where things run | Everything that is not Linux is built, run and verified only on GitHub Actions runners (real Windows and macOS, section 7.1). No cross-compiler, Wine or osxcross is used, on this machine or in CI. This machine writes and tests the Linux side; a Windows or macOS result counts only when a runner has produced it |

CMake fails on non-64-bit targets and `static_assert(sizeof(void*) == 8)`.

## 0. Step 0, done: memory hygiene on the current Linux platform
Done first and independent of the port (no platform layer, no CMake needed); the format is unchanged and every existing test still passes. Findings M1-M8 of section 4.3 are fixed on Linux; M9 (Windows) was closed in 0h. What changed:

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

Lessons that carry into the port: the residue scanner runs on the very stack it inspects, so it must keep its own frames out of the way (it moves them 96 KiB down and ignores hits in its own frame zone, shown separately) and snapshot a hit before printing, or it reports its own data as residue; check any scanner against an injected leak before trusting a green or a red result; read re-run results per attempt (`gh api .../runs/ID/attempts/N`), since `gh run view` lags after a rerun; and when failures alternate on one commit, suspect the harness before the program (here the test read two numbers from the scanner's output). A stack window is needed on every OS (Windows: `_alloca` + `SecureZeroMemory`); sanitizers replace `mlock` by a no-op, so the locking tests must skip under them; the residue test relied on `LD_PRELOAD` and `/proc/self/maps` (Linux only until 0h).

## 0b. Step 0b, done: file format 5.2.0 and text interchange on Linux
Done on Linux before the port, like step 0 (todo 14; no platform layer and no CMake needed). It gives the Linux version a file format that the Windows and macOS ports do not have to change: the rules that turn a phrase into keys are fixed, and they are the same code on every OS. Release 5.2.0 introduced the format. What changed:

| Area | Change |
|---|---|
| Format | `FORMAT_NAME "SillyDES 5.2.0"`, `MAGIC` `S D 5 0x20`. The layouts of the container, the armor and the key file are unchanged; only the labels and the phrase rules differ, and key files stay valid. Fixtures regenerated into `test/format-5.2.0/`, with a new `hello-utf8-phrase.sdes`; `test/format-5.1.0/` removed. A 5.1.0 file gives error 13 (container) or error 8 (armor). |
| Phrase | `canonical_phrase` in the new unit `src/text.cpp`, called by `getphrase` for encryption and decryption: the six steps of section 3.4. A refusal uses the old "Phrase too short" path (ask again on a terminal, error 10 otherwise) and comes before the KDF. |
| Unicode | `tools/gen_unicode.cpp` writes `src/unicode_tables.h` from Unicode 18.0.0: 5982 decompositions, 422 ranges of combining classes, 961 composition pairs, 17 ignorable ranges; 220 KB of source. `LICENSE.Unicode` holds the notice and the SBOM lists the data. |
| Key file, armor | `decode_text` (UTF-8 BOM; UTF-16 LE and BE with BOM), in place on pointer and length. CR ends a line in `readkeyfile` and in the tag search of `low2high`. The armor writer is unchanged. |
| Repository | `.gitattributes`; `tools/fetch_ucd.sh` (data files with pinned SHA-256 sums); CMake targets `regenerate_unicode` and `check_unicode`; workflow `unicode.yml`. |
| Documents | README 1, 5, 6, 7, 9, 10; STRUCTURE (units, 6.2, 6.3, 7.1, 9, 10); ANALYSIS 8 and its table of checks; CHANGELOG; the release skill. |

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

## 0c. Steps 1 to 3, done: CMake baseline, platform layer, portable fixes
Done on Linux (todos 1, 2 and 3), before any Windows or macOS code. The behaviour of the program did not change: the format is the same 5.2.0, and the usage text and every error message are byte for byte what they were (compared with a binary of the previous commit). What changed:

| Area | Change |
|---|---|
| CMake (todo 1) | `CMakeLists.txt`, `CMakePresets.json` (`default`, `ci` with `-Werror`, `debug`), `cmake/generate.cmake`, `cmake/run_test_sh.cmake`. C++11 with extensions off, 64-bit only, `-O2` and no `-DNDEBUG` as in the Makefile. Targets: `sillydes_core` (library of every unit but `main.cpp`), `sillydes`, `test_primitives`, `residue_scan` (Linux), `sbom`; options `SILLYDES_WERROR`, `SILLYDES_BUILD_TESTS`, `SILLYDES_REGENERATE_SBOX` (target `regenerate_sbox`) and `SILLYDES_REGENERATE_UNICODE=<directory>` (targets `regenerate_unicode`, `check_unicode`, test `unicode_check`); `install` of the binary and the licences. CTest runs `primitives` and `e2e_shell` (`test.sh` against links in `build/.../test_root`, so that the source tree stays clean). The Makefile stays until todo 13; `build.yml` has a `cmake` job (g++ and clang++), `unicode.yml` runs the CMake check as well. |
| Platform layer (todo 2) | `src/platform.h` and `src/platform_posix.cpp`: `secure_zero`, `os_random`, the file calls (`open_input`, `read_input`, `open_output`, `write_output`, `close_file`, `same_file`), `available_memory`, `harden_process` (was `lockdown`), `exit_process`, `lock_memory`, `lock_stack`, `scrub_stack`, `secure_alloc` and `locked_alloc` with their `free`, `write_message`, `stdin_is_terminal`, `read_secret_line`. `common.cpp` keeps what is portable (`errarg`, the messages, `errorexit`, `readfile`, `writefile`, `randbytes`, `wipe`); `keys.cpp`, `kdf.cpp` and `main.cpp` no longer include OS headers. All messages go through `write_message`; no stdio is left in the program. `main.cpp` takes its arguments as a `std::vector<std::string>` of UTF-8 (`run`), so a `wmain` only has to convert and call it. |
| Portable fixes (todo 3) | `explicit_bzero` in `sha512.cpp` and `blake2b.cpp` replaced by `wipe`; `checked_add` and `checked_mul` (`std::bad_alloc`, error 7) in `readfile`, `seal` and `pad256`, and in the armor header; armor counts are `uint64_t` with `PRIu64` and `strtoull` (item 5 of section 1.2, at the user's request; the output is byte for byte the same on Linux); the CRC of the END line is read with `strtoll` and must equal the 32-bit value exactly, where `strtol` accepted 2^32 + n on Linux and clamped on Windows; `__builtin_popcount` and `__builtin_ctz` replaced in the tool and the test; `static_assert(sizeof(void *) == 8)`. |
| Tests | Unit tests for counts and a CRC above 2^32 and for the size helpers; `test.sh` checks that an output that is the same file (another spelling, a hard link, a symbolic link) is error 6, and that the new files are ASCII; the scrub test allows 16 bytes (see below). |

Not done here, on purpose: the Windows and macOS files (todos 4 to 6), and the OS headers that the tests themselves use (`test_primitives.cpp` still includes `fcntl.h`, `unistd.h` and `sys/resource.h` for the temporary files, the stderr redirection and the `VmLck` checks; they move with todo 10).

Differences from the plan of section 2:
- The entry point stays in `main.cpp` (`main` for POSIX; Windows adds a `wmain` beside it), because `test_primitives` links the same units without `main.cpp`.
- The file calls work on an opaque `FileHandle` with `open`, `read`, `write` and `close`, not on a `Buf`, so that `platform.h` does not need the containers and `readfile` keeps its growth strategy for every OS.
- The allocator back ends are still declared in `common.h`, because the allocator templates need them; they are implemented in the platform file.

Verified:
- `ctest --preset ci` (gcc) and the same with clang++ 21: all tests, including the residue scan; `make test` passes with `-std=c++11 -Werror`.
- A typed phrase through a pty: the prompt, no echo, a short phrase asked again, the confirmation, the terminal restored, and the file opens with the phrase piped.
- Usage text and 13 error cases (1 to 6, 8 to 11, 13, a short phrase, a control character, error 7 under `ulimit -v`): identical output and exit code to the previous binary.
- ASan and UBSan: build with `-fsanitize=address,undefined` of every source and round trips with a key file, e-mail text and a phrase.
- `regenerate_sbox` gives `src/des_sbox_ct.h` byte for byte; `check_unicode` passes the 20171 conformance cases; `sbom` names the compiler of the build; `install` puts the binary and three documents in place.

Lessons that carry into the port:
- `test_primitives` had one test that depended on the layout of the code: after a refactoring `scrub_stack` left 8 bytes, the alignment padding of its own frame, which it cannot wipe because the frame is live. The test now allows 16 bytes. A port needs its own check of the equivalent, and any change to `scrub_stack` or to the frames above it should be followed by a run of that test.
- A cross-platform difference hid in `strtol`: it is 64-bit on Linux and 32-bit on Windows, so a damaged CRC could be accepted on one and refused on the other. Look for `long` and `unsigned long` wherever text is parsed.
- With CMake, a custom command that carries a list needs `VERBATIM`, or the shell cuts it at the semicolons.
- **Vector registers keep plaintext, and code that runs after the wipe can save them on the stack.** CI found plaintext (a whole decrypted 512-byte buffer, with its padding) on the stack after a key file decryption, only with clang and only on runners whose CPU has AVX-512 (about two of three clang runs; the same binary never leaked on other runners, and `GLIBC_TUNABLES=glibc.cpu.hwcaps=-AVX512F,...` made the leak go away). The data sat in the dead stack just below `main`, in a zone that `scrub_stack` had wiped: a check right after the scrub found it clean, so it was written afterwards, while the process exited. `LD_BIND_NOW=1` made the leak go away although the program itself was already linked with `-z now`. The reading that fits: glibc's EVEX `memmove` copies through `zmm16` and up (512 bytes in eight registers), `vzeroupper` does not clear those, and at exit a lazily bound symbol of a system library (libstdc++ is not linked with `-z now`) ran the dynamic linker's resolver, which saves all vector registers on the stack. Why gcc did not show it was not established (its code probably overwrote the registers; the register contents depend on the compiler). Fix: `exit_process` (`_exit`) right after `scrub_stack`, so that no exit-time code runs; the residue scanner has its own `_exit` for that. The same applies to every OS: whatever runs after the scrub may spill registers (a signal handler, a loader), so end the process directly, and expect other vector widths (NEON on arm64, AVX on Windows) to hold secrets in the same way. The residue scan can only show this on a CPU with the wide registers: read the CPU model in the log, and rerun the job several times (`gh run rerun`, then `gh api .../attempts/N` for each result), since the runner pool mixes AVX2 and AVX-512 machines.
- Runner CPUs differ between runs of one job (AMD EPYC 7763, 9V74 and 9V45, Intel Xeon 8370C, 8573C and 6975P-C all appeared), so a test that passes once proves little for code that depends on the CPU; read the model from `/proc/cpuinfo` in the log, rerun a job several times (`gh run rerun`; read each attempt with `gh api .../attempts/N`), and compare variants inside one job.

## 0d. Step 15, done: the first Windows and macOS code, and the runner jobs

What exists now, all green on the runners (Linux g++ and clang++, Windows MSVC and MinGW-w64 UCRT64, macOS arm64 and Intel):
- `src/platform_win32.cpp`: the whole platform API with W functions only (`CreateFileW`, `BCryptGenRandom`, `VirtualAlloc`/`VirtualLock`, `ReadConsoleW` with echo off, `WriteConsoleW`, `SecureZeroMemory`, `TerminateProcess` as `exit_process`). `wmain` in `main.cpp` converts the arguments with `utf8_args` (unpaired surrogate: error 4) and calls `run`; MinGW links with `-municode`. A file is opened without sharing for writing, a link is refused by looking at the handle before the file is truncated (the equivalent of `O_NOFOLLOW`).
- `src/platform_posix.cpp` has `__APPLE__` branches: `memset_s`, `getentropy`, `host_statistics64` for the free memory, no `prctl`, no `MADV_DONTDUMP`.
- `test/test_os.h` with `test_os_posix.cpp` and `test_os_win32.cpp`: temporary file, delete, silence stderr, lock figures. `test_primitives.cpp` includes no OS header any more.
- `cmake/smoke.cmake`, the CTest test `smoke`: usage, binary and armored round trips with a key file (a plaintext with CR, LF and 0x1A), no CR in armor, the committed fixtures, a phrase from a file, error codes 1 and 6. It ran on every OS until `test_e2e.cpp` replaced it (0g).
- CI: `windows-msvc` (`/W4 /WX`, static runtime), `windows-mingw` (MSYS2 UCRT64, static), `macos` on `macos-latest` and `macos-15-intel`; each builds with CMake and runs `ctest`.
- The code was first compiled with a local MinGW cross compiler (compile only, never run); that caught nothing the runners did not also catch, so it is a convenience and not a step.

Not done at that point, all of it done in 0h (todo 4): `lock_stack` on Windows, the working set increase before `VirtualLock`, keeping secret pages out of crash dumps, `PT_DENY_ATTACH`, the memory-lock tests. The residue and end-to-end tests became portable in 0g and 0h. Still unverified: Windows arm64.

Findings that carry on:
- MSVC `/W4` found conversions in `armor.cpp` and `des.cpp` (`int` to `char`, `uint32_t` to `uint8_t`) that gcc and clang do not report with `-Wall -Wextra`; fixed with explicit casts. `/wd4456` (shadowing) is set for the test target only, where blocks reuse names on purpose.
- `file(WRITE)` of CMake is a text-mode write: on Windows `\n` becomes CR LF. Byte-exact input for the phrase and CR tests has to come from C++ (`test_e2e.cpp`) or a committed fixture.
- The scrub test allows 80 bytes on Windows instead of 16: 40 were measured, the 32 bytes of x64 home space of the callees live in the frame of `scrub_stack` itself. Whatever sits in those bytes in `main`'s old frame is not wiped; the residue scan of todo 4 (0h) found nothing there on either Windows build.
- `memset_s` needs `__STDC_WANT_LIB_EXT1__` before the first include on macOS.
- `GetCurrentThreadStackLimits` is not declared by the MSYS2 headers; the stack base comes from `VirtualQuery` (`AllocationBase`).
- MSYS2 marks MINGW64 as deprecated; the job uses UCRT64.

## 0e. Todos 9 and 7, done: build hardening and constant-time helpers

Build hardening (`cmake/harden.cmake`; the Makefile that carried the same list is gone, 0l):
- Linux, gcc and clang: `-fstack-protector-strong`, `-fstack-clash-protection`, `-fcf-protection=full` (x86-64) or `-mbranch-protection=standard` (arm64), `-D_FORTIFY_SOURCE=3` (not in Debug, not with the sanitizers), PIE, `-z relro -z now -z noexecstack`. macOS: stack protector and fortify level 2 (PIE is the default; clang reports the Linux-only flags as unused, which `-Werror` turns into errors, hence the Linux condition). MinGW: stack protector, `--dynamicbase --nxcompat --high-entropy-va`. MSVC: `/GS /sdl /guard:cf /Qspectre`, `/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /GUARD:CF /CETCOMPAT`.
- Every flag is tried first (`check_cxx_compiler_flag`); `SILLYDES_HARDEN=OFF` turns the block off.
- `cmake/check_hardening.cmake` (CTest `hardening`) reads the finished binary: ELF (PIE, stack not executable, RELRO, BIND_NOW, `__stack_chk_fail`, IBT and SHSTK, or BTI and PAC instructions on arm64) and PE (the DllCharacteristics bits for ASLR, high-entropy ASLR, DEP and, with MSVC, CFG). `test.sh` carries the ELF part for the Makefile build. Verified on all runners.
- `SILLYDES_SANITIZE=ON` (ASan and UBSan, gcc and clang): CI jobs on ubuntu-latest and macos-latest run `primitives`, `hardening` and (since 0g) the whole `e2e`, without the LD_PRELOAD residue scan (it does not go with the sanitizer's allocator) and without the address-space limit; the stack layout test is skipped (red zones).
- A new job `linux-arm64` (`ubuntu-24.04-arm`) runs the whole suite natively, residue scan included.

Constant-time: `value_barrier`, `ct_equal` (the MAC compare), the barrier around the key-bit masks in `Des::setkey`, a branch-free `hex_digit` for the key file (every byte value is tested), and DIT. Tests: `ct_equal` for a difference in every bit of every position; the key file with all 256 byte values in a digit place. Not verified yet: that the compiler keeps these branch-free (todo 8: ctgrind, disassembly gate, timing).

Findings:
- Ubuntu's arm64 toolchain does not leave a BTI marker in the GNU property note (the marker survives only if every input has it), so the arm64 check looks for `bti` and `paciasp` in the disassembly. Clang on macOS gives "unused argument" for Linux-only flags: with `-Werror` that is an error.
- **MSVC AddressSanitizer: tried, dropped.** With `/MT` and with `/MD` the link fails on the missing `clang_rt.asan_*_runtime_thunk-x86_64.lib` on the `windows-latest` image; MSVC ASan stays open (needs an image with that component or an explicit library path).
- An arm64 build can be run on this machine: `g++-aarch64-linux-gnu` and `qemu-user` (binfmt is registered), with `QEMU_LD_PREFIX=/usr/aarch64-linux-gnu`; the whole suite except the residue scan passes that way, which is a quick arm64 bench for todo 8.

## 0f. Todo 8, done: constant-time verification

- `test/ct_valgrind.cpp` (ctgrind style; CTest `ct_valgrind`, label `constant-time`; needs `valgrind` and `valgrind/memcheck.h`, Linux): secrets (keys, plaintext, key file bytes) marked undefined; DES, SHA-512, HMAC, BLAKE2b, `ct_equal`, `hex_digit` for every byte value, `derive_keys`, the cipher in CBC mode, `pad256` and a whole `seal` in key file mode run under `valgrind --error-exitcode=99`. `ct_valgrind_detects_a_leak` runs a deliberate branch and table index on a secret and must fail (`WILL_FAIL`), so that a silent harness cannot pass. Out of scope: Argon2id, the phrase normalisation, `unseal` as a whole (its tag branch and `unpad256` depend on public outcomes), so its pieces are run instead. `hex_digit` became a public function of `keys.h` for this.
- `tools/ct_branches.sh` (CTest `ct_branches`, Linux x86-64 and arm64): conditional branches per function of the binary as a report; only `hex_digit` is enforced to have none, since the disassembly cannot tell a loop over a public length from a branch on a secret. The report is the thing to read when a compiler changes.
- `test/ct_timing.cpp` (CMake `-DSILLYDES_TIMING_TESTS=ON`, `-DSILLYDES_TIMING_SCALE=n`): dudect-style Welch t-test, classes timed in random order, the slowest 5 % dropped, a test passes if |t| < 10 in any of 3 rounds. Covers `ct_equal`, `hex_digit`, `Des::setkey`, `Des::layer`, HMAC with a zero or random key and message, and `unseal` with the wrong tag in the first or last byte (item 4 of 5.3). A control (an early-exit compare) must be detected, with |t| in the thousands.
- `.github/workflows/constant-time.yml`: on changes to the code involved, and by hand (it had a nightly run until 2026-11-24, 0r). `valgrind`: ubuntu-latest and ubuntu-24.04-arm, g++ and clang++, `-DSILLYDES_OPT_LEVEL` 0, 2 and 3 (12 jobs, all clean). `timing`: ubuntu, ubuntu arm64, macos-latest (arm64) and windows-latest (MSVC), scale 10, all |t| below 4 except as below.
- Results are in ANALYSIS.md section 8.

Findings:
- A first timing run on Windows found |t| = -16 for `ct_equal` in every round. The two classes compared against two different arrays; the address (alignment, aliasing) was the difference. With both classes compared against one buffer the value is about 1. A timing test must keep the memory layout the same for both classes: the nightly arm64 run later gave |t| = 17 for the `unseal` test, which copied its input from two different buffers; since then every test prepares the class's input (untimed) in one shared buffer and times only the call, and three attempts on all four platforms were clean.
- Valgrind marks the return value of the program as undefined if it is derived from a secret (the control); results have to be declassified before they are used.
- Still open from 5.3: a macOS Valgrind equivalent does not exist (Valgrind does not run on current macOS), and Windows has only the timing test; BlaMka's multiply on each target (`mul` 32x32 to 64) is covered only by the timing test, which does not exercise Argon2id.

## 0g. Todo 10, done: `test_e2e.cpp` replaces `test.sh`

- `test/test_e2e.cpp` (`test_e2e <sillydes> <source root> [--scan-lib <residue_scan.so>] [--scan-exe <sillydes_scan>] [--no-address-limit]` (the scanner options came with 0h)) runs the real binary through a spawn helper in `test_os.h` (`run_program`: arguments in UTF-8, input bytes, extra environment, an address-space limit where the OS has one, exit code and both output streams; POSIX `fork`/`execv`/`poll`, Windows `CreateProcessW` and two reader threads), and the file helpers it needs (`make_temp_dir`, `remove_tree`, `list_dir`, hard links, symbolic links). Everything of `test.sh` is in it with the same `ok:` lines: the golden files, round trips, container size, phrase mode, wrong key, parity bit, six keys, CRC, repeated blocks, tampering, other versions, salt, wrong phrase, key files and e-mail text in other line endings and encodings, phrases piped and typed another way, refused phrases, data that is not translated, non-ASCII file names, the same file under other spellings (plus another case where the file system is case-insensitive), the ASCII-and-LF check of the sources, and the residue scan (Linux).
- The byte-exact tests that `cmake/smoke.cmake` could not do (CMake's `file(WRITE)` is text mode on Windows) now run on every OS: the phrase with a BOM, spaces and CR LF is written to the pipe as bytes.
- `test.sh`, `cmake/run_test_sh.cmake` and `cmake/smoke.cmake` are gone. The Makefile builds and runs `test_e2e`, and runs the hardening check through cmake when it is installed (the readelf lines of `test.sh` moved into `cmake/check_hardening.cmake`). The release skill and STRUCTURE.md name `test_e2e`; `test_e2e --nfc-phrase` prints the phrase of the fixtures for the format-change appendix.
- Where a part cannot run it prints `skipped:` and why, and CI runs the tests with `-V` so that these lines are in the log. On the runners: Windows and macOS skipped the residue scan and error 7 (no way to limit the address space of a child there; 0h did both, except error 7 on macOS); symbolic links, hard links and the case-insensitive spelling ran on Windows and macOS; Linux skips only the case-insensitive spelling.
- The sanitizer jobs now run the whole end-to-end test (ASan and UBSan, ubuntu and macOS), which found nothing.

Done since: the interoperability job between the OSes (0k). The in-process residue scanner and the error 7 test came with 0h (todo 4), the latter on Windows through a job object instead of an injected `available_memory()`; on macOS error 7 stays untested.

## 0h. Todo 4, done: memory hygiene on Windows and macOS, one residue scanner

- **Windows** (`platform_win32.cpp`): `lock_pages` is `VirtualLock`, and on `ERROR_WORKING_SET_QUOTA` it raises the minimum and maximum working set by the size plus 256 KiB (`SetProcessWorkingSetSize`; a user may do that, it commits nothing; the limit of `VirtualLock` is the minimum working set) and tries again. It serves `locked_alloc` (every `SecretBuf`), `lock_memory` (the 2 GiB arena) and `lock_stack`, which now faults in the 256 KiB window with `_alloca`, locks it with the page of its own frame, and halves the window if that fails, as on POSIX. `map_pages` registers every block it hands out (arena, plaintext buffer, locked pages) and `lock_stack` the stack window with `WerRegisterExcludedMemoryBlock` (looked up in kernel32, Windows 10 1703 and later, at most 512 blocks, failure ignored); `unmap_pages` unregisters. `available_memory()` also honours the process memory limit of the job object the process is in, which is what `RLIMIT_AS` is on POSIX. M9 needs nothing more: the arena is `VirtualAlloc(MEM_COMMIT)`, `available_memory()` is the smaller of free physical memory and the free commit limit, and a failed commit is `bad_alloc`, which is error 7.
- **macOS** (`platform_posix.cpp`): `PT_DENY_ATTACH` in `harden_process` (a debugger cannot attach afterwards, and a process that is being debugged already exits; root is not stopped). `mlock` and `RLIMIT_CORE` were there; `MADV_DONTDUMP` does not exist and is not needed with core dumps off.
- **Tests.** `locked_kb()` exists on every OS now (Linux `VmLck`; Windows `QueryWorkingSetEx` per page, the `Locked` bit; macOS the `user_wired_count` of the Mach regions), so the locking tests of `test_primitives` run on the runners instead of skipping: `lock_stack` locks something, a `SecretBuf` is locked and is unlocked when freed. Windows reports no fixed limit (`memlock_limit_kb()` is a large number), so the case "`lock_memory` past the limit" is Linux-only. `available_memory()` is checked on every OS (not 0, not "unknown" on Windows and macOS, below 1 PiB) and printed. `run_program` limits memory on Windows with a job object (`JOB_OBJECT_LIMIT_PROCESS_MEMORY`, assigned while the child is suspended), so **error 7 is tested on Windows without injecting anything**. macOS has no limit a program can set (`RLIMIT_AS` and `RLIMIT_DATA` are not enforced), so error 7 stays skipped there; what is checked is that `available_memory()` returns a figure.
- **One residue scanner for every OS** (`test/residue_core.cpp`, from the old `residue_scan.cpp`): the search, the marks, the frame placement and the own-zone rule are unchanged, and the list of writable regions is per OS (`/proc/self/maps`, `VirtualQuery`: committed, not mapped files, not guard pages; `mach_vm_region`). Two ways in: Linux keeps the `LD_PRELOAD` library (`residue_scan.cpp`, only `_exit` and the constructor) on the real binary; every OS uses the scan binary `sillydes_scan`, the sources built with `SILLYDES_RESIDUE_SCAN`, whose `exit_process` calls `residue_scan_at_exit()` first, so it runs where the program would end, after `scrub_stack`. That is the only test hook in the program: one `#ifdef` per platform file, absent from the real binary. `test_e2e` takes `--scan-lib` and `--scan-exe` and runs all checks with each scanner given; Linux runs both, which ties the new scanner to the old one. Controls: the preload scanner is shown a shell that holds the mark; the scan binary keeps a plain copy of the mark on the heap (`SCAN_CONTROL=heap`) and in the frame of the scan function, in the dead stack (`SCAN_CONTROL=stack`), and the test fails unless both are found. No scan under the sanitizers.
- **Result on the runners (first push, all green):** no key, phrase or plaintext remains on Windows (MSVC and MinGW) and macOS (arm64 and Intel) after encryption, decryption and a failed authentication, for key file, ASCII phrase (5000 characters) and non-ASCII phrase; the stack scrub with its 80 bytes of home space on Windows leaves nothing the scanner finds, and nothing runs after the scrub that spills registers there. The locking tests ran on both. Error 7 ran on both Windows jobs. `available_memory()` reported 13.7 and 13.2 GiB (Windows), 3.0 GiB (macOS arm64), 9.7 GiB (macOS Intel), 14.3 GiB (Linux arm64).
- **Not verified, and cannot be here:** that the WER exclusion keeps a block out of a dump (no API reads the registrations back; a crash with dumps switched on would show it), that `PT_DENY_ATTACH` stops a debugger, and that `VirtualLock` of the 2 GiB arena succeeds on a small machine (it is skipped silently, as `mlock` is on Linux). The macOS figure is an estimate (free, inactive and purgeable pages): under load it can be below what the system would free, which gives a spurious error 7 on a busy Mac. The DACL on the own process and the process mitigation policies are todo 5.

## 0i. Todo 5, done: the Windows port

- **Process hardening** (`harden_process` in `platform_win32.cpp`, first thing in `wmain`): the access control list of the process is replaced by one entry that gives the owner only `PROCESS_QUERY_LIMITED_INFORMATION`, `PROCESS_TERMINATE` and `SYNCHRONIZE` (`SetSecurityInfo`, protected), so that a debugger or dump tool of the same user cannot open the process for reading or writing its memory; and four mitigation policies are set through `SetProcessMitigationPolicy` (looked up, one DWORD of flags each): dynamic code prohibited, extension points disabled (AppInit DLLs, global hooks, legacy IMEs), no remote images and system32 first, no child process. **Left out on purpose:** the strict handle check (an exception on an invalid handle). The program is single-threaded and closes each handle once, so the gain is small, and a crash is worse than a failed call. An administrator, and any process with SeDebugPrivilege enabled, still gets in: the runner's token has it enabled, so the check has to switch it off in the checking process first. This is a mitigation, not a boundary (README must say so).
- **Verified on both Windows jobs** (`check_hardening` in `test_os.h`, called after `harden_process` at the end of `test_primitives`): `OpenProcess(PROCESS_VM_READ)` on the own process fails with access denied, `PROCESS_QUERY_LIMITED_INFORMATION` still works, and `GetProcessMitigationPolicy` reads back all four policies as set. Linux checks `RLIMIT_CORE` and `PR_GET_DUMPABLE`, macOS `RLIMIT_CORE` only (`PT_DENY_ATTACH` cannot be read back). The program itself runs the whole end-to-end suite with these policies in force, ConPTY included, so none of them breaks the console, the pipes, the files or the 2 GiB arena.
- **A phrase typed into a terminal, on every OS** (`run_on_terminal` in `test_os.h`): a pseudo-terminal on POSIX (`posix_openpt`, a controlling terminal, a typed line once its prompt has appeared, after the echo is off), a pseudo-console (ConPTY, `CreatePseudoConsole` looked up at run time) on Windows, where what is typed goes in as UTF-8 and the console turns it into key events. `test_e2e` types the non-ASCII phrase of the fixtures (Latin, Greek, Japanese and U+1D11E, a surrogate pair) twice for an encryption, and checks: the exit code, that the phrase is not echoed, that a file made with the typed phrase decrypts with the same phrase piped, and the other way round; a short phrase and a repetition that differs are asked again; Ctrl+D (POSIX) or Ctrl+Z and Enter (Windows) at the prompt is error 10 and leaves no output file. It also checks the harness (the usage text of the program must come back). This ran on Linux and macOS, both Windows builds, and was the first test of the terminal path anywhere. The plan said `WriteConsoleInputW`; ConPTY needs no console of the test process and goes through the same input path a terminal does.
- **ConPTY pitfalls found on the runner:** the program must be started with `STARTF_USESTDHANDLES` and three `INVALID_HANDLE_VALUE`, or it keeps the redirected handles of the test runner and sees no console (stdin read nothing, the prompt went nowhere: exit code 10 with only the start-up escape sequences in the output); the console may ask for the cursor position (`ESC [ 6 n`) and is answered; prompts are matched on one word, since the console renders spaces its own way.
- **What PowerShell and cmd hand to the program** (`powershell_tests`, Windows only, runs on the runners): Windows PowerShell 5.1 pipes ASCII by default, so every other character is a `?` and the keys are those of another phrase, with no error (encryption succeeds, the file does not decrypt with the real phrase); with `$OutputEncoding = New-Object System.Text.UTF8Encoding $false` it gives the keys of the UTF-8 phrase (asserted), and so does PowerShell 7 by default (asserted). `>` in 5.1 writes a key file as UTF-16 with a byte order mark (asserted) and the program reads it (asserted, for 5.1 and for PowerShell 7, which writes UTF-8). cmd.exe: with code page 65001 (the runner's default) `echo` pipes UTF-8 and the keys are right; after `chcp 437` the program refuses the phrase with error 10 (the bytes are not UTF-8), so the user gets an error and no wrong key. Not asserted: only the three facts that the README promises are.
- **Not done, by decision:** a user-only DACL on output files stays as documented in 3.2 (they inherit the directory's list, as every program's files do; README section 8 says so); Windows arm64 (no runner label tried yet; todo 11).
- **mintty without ConPTY** presents stdin as a pipe: the phrase is echoed and not confirmed. Not testable on a runner; stays in the list of limits (3.4).

## 0j. Todo 6, done: the macOS port

- **Signature and hardened runtime** (CMake, `SILLYDES_CODESIGN`, on by default on macOS): after the link, `codesign --force --options runtime --sign <identity>` signs `sillydes`; the identity is `-` (ad hoc) unless `SILLYDES_CODESIGN_IDENTITY` names one, which also adds the secure timestamp that notarization asks for. No entitlements are given, so there is no `get-task-allow` (the entitlement that lets any debugger attach) and nothing else relaxes the runtime. The signature is what makes the hardened runtime refuse a debugger, `DYLD_*` injection and unsigned code in the process, in addition to `PT_DENY_ATTACH`. The test binaries are not signed beyond what the linker does.
- **Checked by ctest on every macOS job** (`cmake/check_hardening.cmake`, Mach-O branch): `lipo -archs` equals `CMAKE_OSX_ARCHITECTURES` when that is set; every architecture has the PIE flag and the stack protector (`otool -arch all -hv`, `nm -arch all -u`: without `-arch all` both tools look at the host's slice only); `codesign --verify --strict` passes; every architecture's code directory has the `runtime` flag (`flags=0x10002(adhoc,runtime)` seen on the runners); and `get-task-allow` is not among the entitlements. The workflow also prints `lipo`, `codesign -dvv` and the entitlements.
- **Universal binary:** preset `universal` (`CMAKE_OSX_ARCHITECTURES=arm64;x86_64`, deployment target 11.0). The `macos` job runs it besides `ci` on both runner types, so the arm64 slice is tested on the arm64 runner and the x86_64 slice on the Intel runner, natively (no Rosetta needed): primitives, hardening and the whole end-to-end suite pass on both. Notarization and the distribution (a signed identity, a zip or pkg) stay out of scope; they need an Apple developer account.
- **Memory policy, decided:** unchanged and strict: `available_memory()` is free, inactive and purgeable pages (the plan's `hw.memsize` rule would only refuse on machines under 3 GiB and was not taken). Measured on the runners: about 3 GiB on arm64 and 10 GiB on Intel. A loaded Mac can get a spurious error 7 although macOS would have swapped; README must say so.
- **Error 7 stays untested on macOS.** Tried on the runners: `setrlimit` of `RLIMIT_AS` and of `RLIMIT_DATA` fails with `EINVAL` for a limit below the address space that is already mapped (which is well above 1.5 GiB), so no child can be limited. The program reads both limits and would refuse, but the test cannot set one. The skip is printed.
- **`PT_DENY_ATTACH` could not be shown to work.** An experiment attached to a child that had called `harden_process` and, as a control, to one that had not: the control was refused as well (a debugger of the same user gets in nowhere on the runner), so the experiment proves nothing, and the attach to the hardened child did not return an answer (it first blocked the test itself, then ended its helper process abnormally). It was removed. Stays in the unverified list.
- **Lessons:** `PT_ATTACH` is deprecated and an error under `-Werror` (`PT_ATTACHEXC`); a hung experiment costs a runner for as long as the job timeout, so every new experiment gets a `ctest --timeout` and diagnostics on stderr (stdout is lost when ctest kills the test).

## 0k. Todo 11, done: the CI matrix, interop between systems, Windows arm64, big endian

- **Interop** (`test_e2e --interop-make <dir> <label>` and `--interop-check <dir> <labels>`, job `interop` in `build.yml`): every build job (Linux x64, Linux arm64, macOS arm64, macOS Intel, Windows MSVC, MinGW, Windows arm64) makes files with its own binary and uploads them with the binaries; then one job per system downloads all files and opens them with its own binary. Cases: binary and armored with the key file `sample.key` (which a Windows checkout turns into CRLF: also a test), with an ASCII phrase, with the non-ASCII phrase, and armored with the same text typed another way (BOM, decomposed accents, no-break space, full-width and half-width forms: it must open with the NFC form). The text has all 256 byte values and all three line endings. Windows adds, through the shells: a key file written by Windows PowerShell 5.1 with `>` (UTF-16), the phrase piped by Windows PowerShell 5.1 with a UTF-8 `$OutputEncoding`, a key file written by PowerShell 7, the phrase piped by PowerShell 7 and by `cmd.exe` after `chcp 65001`. The check fails on a file that does not open, on a file name it does not know and on a missing file (a label that starts with `windows` must have the shell cases). **Result: all 7 x 7 combinations open, the first time they ran** (a missing PowerShell 7 in the MSYS2 shell was the only failure: the MinGW files are made in a `pwsh` step, since the program is linked statically).
- **Windows arm64** (`windows-11-arm`, job `windows-arm64`, the MSVC build): green on the first push with `/Qspectre`, `/guard:cf`, the process hardening of 0i, ConPTY, the terminal tests, the residue scan, and the interop files. DIT on Windows arm64 was open here and is done in 0q.
- **Big endian** (job `big-endian`): s390x, cross-compiled with `g++-s390x-linux-gnu` and run under QEMU user mode. `test_primitives` passes (all known answers, the Unicode table hash, the normaliser), and the files made on s390x open on x86-64 and the other way round. Run here first (qemu-s390x is registered on this machine), then in CI. The end-to-end test is not run there: QEMU does not limit the address space of a child (error 7), and the residue scan preloads a library.
- **KDF time** is in the log of every interop step (`ok: <label> <case> (<ms> ms)`): a 2 GiB, t = 1, p = 4 derivation takes about 2.1 s on Linux arm64, 2.4 s on Linux x64 and macOS arm64, 3.0 s on MinGW, 3.2 s on MSVC, 4.8 s on Windows arm64 and 6.2 s on the macOS Intel runner (a three-core virtual machine). The "about 2 s" of section 4.4 holds for Linux and macOS arm64 only; the README may say "a few seconds".
- **Not done:** pinning the runner labels (`windows-latest`, `macos-latest` still float; section 10), a nightly interop run, s390x in the interop matrix (it runs in its own job), and the end-to-end suite on s390x. *Later: the labels, the nightly run and s390x are done (section 0r and the review at the top).*

## 0l. Todo 13, done: the Makefile is gone

- **Removed:** `Makefile`. Everything it did is a CMake target or an option that was already there and is now checked against the Makefile's results: `regenerate_sbox` (`-DSILLYDES_REGENERATE_SBOX=ON`) rewrites `src/des_sbox_ct.h` to the committed bytes, `check_unicode` (`-DSILLYDES_REGENERATE_UNICODE=<dir>`) confirms the committed tables against the Unicode 18.0.0 files and the full conformance file, and `sbom` writes `sillydes.cdx.json` into the build directory (all three run here before the removal). The hardening check that only the Makefile ran is CTest's `hardening` on every build. `.gitignore` is `build/` alone.
- **Workflows:** `release.yml` builds with `cmake --preset ci`, runs `ctest --preset ci`, makes the SBOM with the target and copies `build/ci/sillydes` and `build/ci/sillydes.cdx.json` into `dist/`. `build.yml` lost its `build` job (the Makefile build); the `cmake` job (g++ and clang++) makes the SBOM for both and keeps the `sillydes-sbom` artifact from g++. `unicode.yml` lost the `make unicode-check` step and the Makefile paths.
- **The binary of a release changes in how it is built, not in what it is:** the `ci` preset is `Release` (`-O2`, no `-DNDEBUG`), `-Werror`, and the hardening flags of `cmake/harden.cmake`, which are the Makefile's list (`-fcf-protection=full`, stack protector strong, stack clash protection, fortify 3, PIE, relro, now, noexecstack); `ctest` checks them in the finished binary before the release step gets to run. Format 5.2.0 is untouched.
- **Comments in generated files** that said `make gen` and `make unicode UCD=` now name the targets; the generators and the committed headers changed together (comment only; the Unicode table hash covers the data, and `check_unicode` passes).
- **The release skill and STRUCTURE.md** use the CMake commands. The skill says how to build the previous release for the fixtures: v5.2.0 and older with `make` (they have a Makefile), later ones with CMake.
- **README** section 1 names CMake only; the per-OS statements stay todo 12.
- **Not done:** the release binary is still built on `ubuntu-latest`, which is now Ubuntu 26.04, so it needs that glibc or newer; building on an older image (or linking statically) is a decision for the release, not for this todo.

## 0m. Todo 12, done: the documents say what each system does; review of the whole plan

- **README:** section 1 names the supported systems (Linux and macOS 64-bit on arm64 and x86-64, Windows 10 or later on x86-64 and arm64), how they are tested (GitHub runners only, and what that does not cover), that the release is a Linux x86-64 binary so far and the macOS build is ad hoc signed and not notarized, and how to read the Unix examples on Windows; the format paragraph no longer says the phrase rules wait for other systems. Section 5: LF out, PowerShell UTF-16 in. Section 6: data is bytes on Windows, file names are not normalised. Section 7: key files from PowerShell, the key derivation time per system, the prompt (echo off, asked twice), and a list of what each pipe hands over (Unix shells, Windows PowerShell 5.1 and its `?`, PowerShell 7, `cmd.exe` and `chcp 65001`, terminals without ConPTY, Ctrl+Z), plus the limits that are not solved. Section 8: hibernation, and a table of dumps, debuggers, injected code, locked memory and file permissions per system, with what is not verified. Section 9: how error 7 is decided per system, error 4 on Windows, error 10 at the end of input.
- **ANALYSIS.md 8 and 12:** the memory hygiene row and the resource check per system, with the decision that macOS stays strict; new rows in the table of experiments (the build matrix, the 7 x 7 interop, big endian, the terminal tests, the hardening read back, the time of the derivation per system). **STRUCTURE.md:** the top-level flow and phrase input per system. **CHANGELOG.md:** the stale "first source" entry rewritten, a Documentation entry.
- **Statuses in this file** that had gone stale were brought up to date (sections 0, 1.1, 1.2, 2, 3.4, 5.2 and the todo list).

### Review of the plan: what is still open

Status after release 5.2.1 and the Argon2i mode (0p). Nothing is blocking. In order of value:

1. **SECURITY.md.** Done in 0n.
2. **Releases for the other systems.** Done: release 5.2.1 (tag run 45029843748) ran `prepare`, five builds, five attestations and `publish`, with `SHA256SUMS` and an SBOM per binary. The Linux binaries are static PIEs since then (`SILLYDES_STATIC`), so the `libstdc++` remark in 0n is out of date. Authenticode and notarization stay open (certificate, Apple account).
3. **Unverified behaviour** (cannot be shown on a runner; named in the release notes when it ships): that the WER exclusion keeps a block out of a dump, that `PT_DENY_ATTACH` stops a debugger, `VirtualLock` of the 2 GiB arena on a small machine, error 7 on macOS (no limit can be set) and the strict macOS memory estimate on a loaded Mac, real Windows 10 and older builds, a user's own terminal emulator and PowerShell profile, Gatekeeper on a downloaded macOS binary.
4. **Constant-time gaps** (0f, 5.2): DIT on Windows arm64 (**done, section 0q**), BlaMka's multiply covered only by a timing test that does not run Argon2id (Argon2i with a secret phrase is now run under Valgrind, which shows that no branch or address depends on it; Argon2id is excluded by design, it is data-dependent), no Valgrind-like tool on macOS and Windows, MSVC AddressSanitizer dropped (missing runtime library on the image). 5.3 item 4 (wrong-key against right-key decrypt time depending on where the MAC differs) has no test of its own; `ct_equal` has.
5. **CI hygiene.** Done in 0r: `windows-latest` and `macos-latest` are pinned in `build.yml`, `constant-time.yml` and `release.yml` (`windows-2025-vs2026`, `macos-26`), `build.yml` has a manual trigger (a nightly run was added and taken out again, 0r), and the procedure for changing a label is in TESTING.md section 7. s390x is in the interop matrix and runs the end-to-end suite. `ubuntu-latest` still floats on purpose.
6. **Small leftovers:** M7's `memfd_secret` investigation (**done, section 0o**; a swappable 2 GiB arena stays the largest residual risk without a locking limit), the KDF side channel (**done, section 0p**: the optional Argon2i mode), item 17 of 1.2 (a quoted armor tag line gives error 8; not a character-set problem), a user-only DACL for output files on Windows (decided against, again in section 0o), `cmake_minimum_required` 3.16 against the presets' 3.21.

## 0n. Items 1 and 2 of the review: SECURITY.md and the release for every system

- **SECURITY.md** (decided: reports go to public GitHub issues, titled `Security:`, since private reporting is off): scope and support, what the cipher is meant to protect and that the figures are the author's estimates, what it does not protect against (weak phrase, a same-user or administrator attacker, swap and hibernation, cache observation on a shared machine, look-alike phrases, deletion), the list of what has not been verified, how to verify a download, and the supply chain (no libraries, pinned actions, the Unicode data checked by hash).
- **release.yml** rebuilt as `prepare` (tag, version and changelog checks, the notes with a line that Windows and macOS binaries are unsigned) -> `build` (five targets: `ubuntu-22.04` and `ubuntu-22.04-arm` with the `ci` preset, `macos-latest` with `universal`, `windows-latest` and `windows-11-arm`; each runs the whole test suite, checks the banner, makes the SBOM, names the files) -> `attest` (one job per binary: build provenance and SBOM attestation) -> `publish` (checks 5 + 5 files, `SHA256SUMS`, `gh release create`). Started by hand it is a dry run: no attestation, no release. **Decided:** Linux on Ubuntu 22.04 (a binary built on `ubuntu-latest`, now 26.04, needs glibc 2.43; the 22.04 builds need 2.34 and passed `-Werror` with gcc 11), no Authenticode and no notarization (said in the release notes, README and SECURITY.md), macOS as one universal binary.
- **tools/gen_sbom.sh** runs on all three systems: `sha256sum` or `shasum`, a UUID from `/dev/urandom`, `ldd` (Linux, unchanged output), `otool -L` (macOS: the system libraries with their versions, once per library for a universal file), nothing on Windows (the runtimes are linked in); the compiler and platform can be given (`SBOM_COMPILER_NAME`, `SBOM_COMPILER_VERSION`, `SBOM_PLATFORM`), which the workflow does from CMake's own record, since MSVC cannot be asked with `--version` and the Git Bash on Windows arm64 may run under emulation. Bash 3.2 (macOS) has no associative arrays and fails on an empty array under `set -u`; both are avoided.
- **Dry run on the branch** (run 45021799235): all five builds green and tests green, SBOMs read back (platform, compiler, components right for each), `GLIBC_2.34` is the highest symbol version of the Linux binaries. The macOS list had duplicates (one per architecture) and a header line as a component; fixed, and the parsing checked with a stand-in `otool`.
- **Not done, and not possible without you or a tag:** the attestations and the release itself have not run (the first tag does it); Authenticode and notarization need a certificate and an Apple account; the Linux binaries still link `libstdc++` dynamically (`-static-libstdc++` would lower the floor further). *Later: the attestations and the release ran with 5.2.1, and the Linux binaries became static PIEs.*

## 0o. M7 `memfd_secret` and the Windows output DACL, done

- **Investigated on Linux 7.0, x86-64, unprivileged, `ulimit -l` 8 MiB:** `memfd_secret` needs no boot parameter since Linux 6.5 (5.14 to 6.4: `secretmem.enable=y`). It takes `O_CLOEXEC`, not `FD_CLOEXEC`. It obeys `RLIMIT_MEMLOCK` like `mlock`: a mapping up to the limit works, a larger one maps and then raises **SIGBUS at the first touch** past the limit. Other locked memory is not counted against it (7 MiB `mlock`ed plus a 2 MiB secret mapping worked), `mlock` on a secret mapping fails with ENOMEM, and the pages do not show in `VmLck`. So it does not remove the swap risk under a small limit; it adds protection (not swappable, no hibernation while it exists, out of the direct map, so root cannot read it through `/proc/<pid>/mem` or `ptrace`) only where 2 GiB is lockable anyway.
- **Done:** `secret_map` in the platform layer (Linux only; null on macOS and Windows): checks `RLIMIT_MEMLOCK` and `CAP_IPC_LOCK` (`capget`, no libcap, so the static PIE is unchanged), maps from `memfd_secret`, and touches every page under a SIGBUS handler, so a refusal shows before the key derivation; null on any failure. The table is an `Arena` in `kdf.cpp`: `secret_map`, else `secure_alloc` plus `lock_memory`; wiped and unmapped on every path. Only for 1 MiB and more (splitting the direct map is not worth it for less). Tested: `test_primitives` (a 2 MiB mapping is zero-filled; past the limit nothing crashes; skipped with a message when refused) and a scratch build without the limit check, which shows the handler catching the SIGBUS at 9 and 64 MiB. **Not shown here:** a real 2 GiB mapping (no runner has a lock limit of that size; the hard limit of this machine is 8 MiB).
- **Strict mode, opt-in:** the optional command-line word `requirelock` (an optional fifth argument, in any position; `parse_args` accepted 5 or 6 words; 5 to 7 since 0p) or `SILLYDES_REQUIRE_LOCK=1` in the environment, passed down as `KeyInput::require_lock` and a parameter of `argon2id`. The program reads no other environment variable; an unlocked table is error 15, raised before anything is written. Works on every OS (`lock_memory` on Windows and macOS). `test_e2e` accepts both outcomes (whether the lock succeeds depends on the machine) and checks that each is whole: error 15 with no output file, or exit 0 and a round trip.
- **Windows DACL on output files: decided against, again.** Weighed: a protected DACL (`D:P(A;;FA;;;<user>)(A;;FA;;;SY)(A;;FA;;;BA)` at `CreateFileW`, atomic, about 20 lines) would match mode 0600, but an encrypted file is made to be shared, a protected list drops inherited entries (group shares, enterprise policy, backup and scanners that run as SYSTEM), it does nothing on FAT and exFAT or for a file that already exists, and an administrator gets in regardless. The README tells a user who wants it to restrict the output folder once (`icacls <folder> /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F"`). If this is ever reversed: apply it only to the plaintext of a decryption, and read it back in a runner test like the process DACL.

## 0p. The KDF side channel, done: the optional Argon2i mode

- **Decision (yours):** Argon2i next to Argon2id, Argon2id stays the default. Chosen on encryption only, by the command-line word `argon2i` or `SILLYDES_ARGON2I=1` (exactly `1`, read by `argon2i_requested` of the platform layer); decryption reads the choice from the header. With `key=` the word is error 10 and the variable is ignored. Parameters: 2 GiB, 6 passes, 4 lanes (RFC 9106 section 7.2 asks for more passes than log2 of the memory minus 26, read in bytes; 7.5 s against 1.8 s on one Linux PC).
- **Format unchanged (5.2.0):** header byte 7, reserved and zero until now, is the variant (0 Argon2id, 1 Argon2i, else error 13). The tag covers it and the type is an input of Argon2's initial hash, so the variants give different keys. `kdf_ok` bounds per variant: Argon2id t 1 to 4, Argon2i t 3 to 8. A release before this one reads Argon2id files as before and stops with error 13 on an Argon2i file.
- **Code:** one `argon2(variant, ...)` in `kdf.cpp` (`argon2id` stays as a wrapper); Argon2i is the data-independent addressing of the first half pass applied to every pass, with type 1 in the address blocks and the initial hash.
- **Tests:** the RFC 9106 section 5.2 vector and reference vectors (argon2-cffi), bounds per variant, round trips and the byte 7 tamper, `test_e2e` for word, variable, key file and the 7 and 8 word limits, a golden fixture `test/format-5.2.0/hello-argon2i-phrase.sdes` (part of the fixture recipe of the make-release skill), and a Valgrind check that a secret phrase through Argon2i touches no secret-dependent branch or address (the same test with Argon2id was reported when tried by hand). `build`, `unicode` and `constant-time` green on all runners, on the branch and on `main`.
- **Not changed:** the normalisation of a phrase outside ASCII is still not constant-time; the mode does not help against a host that can read the process's memory. Documented in README section 7, ANALYSIS 8 and 12, SECURITY.md, STRUCTURE.md, TESTING.md and CHANGELOG.md (under Unreleased).

## 0q. DIT on Windows arm64, done

- **Investigated on a `windows-11-arm` runner** (Cobalt 100, Neoverse N2; a throwaway probe branch, deleted): `IsProcessorFeaturePresent` has no DIT bit (the list of Microsoft has none either); `mrs ID_AA64PFR0_EL1` raises an exception in user mode; the registry copy `CP 4020` of that register reports DIT as absent although the CPU has it (the virtual machine hides it); `msr dit, #1` executes without an exception and `mrs dit` then shows bit 24 set; the bit is still set after `Sleep(50)` and after 400 ms with all cores busy; a new thread starts with it clear.
- **Done:** `enable_dit` in `platform_win32.cpp` (MSVC arm64 only, `__emit(0xd503415f)` inside `__try`/`__except`, called from `harden_process`); a CPU without the feature is ignored silently (**decided**). `check_hardening` of `test_os_win32.cpp` reads the bit back; `SILLYDES_EXPECT_DIT=1` in the `windows-arm64` job of `build.yml` makes a clear bit a failure, elsewhere it is reported only.
- **Not shown:** the path of a CPU without DIT (the runner has no such CPU; the instruction should raise an illegal-instruction exception that the SEH block catches), and the timing effect itself (only the bit is verified).

## 0r. Item 5 of the review: CI hygiene, done

- **Pinned** to what the floating labels ran when this was done (read from the log of the last green `build` run, `Runner Image`: `windows-latest` was `windows-2025-vs2026`, Windows Server 2025 10.0.26100; `macos-latest` was `macos-26-arm64`, macOS 26.7): `windows-2025-vs2026` and `macos-26` in every job of `build.yml`, `constant-time.yml` and `release.yml` (labels of the runner-images README: `windows-latest`, `windows-2025` and `windows-2025-vs2026` are one image; so are `macos-latest` and `macos-26`). `windows-11-arm`, `macos-15-intel`, `ubuntu-24.04-arm` and the release's `ubuntu-22.04` were pinned already. **Decided:** `ubuntu-latest` stays floating for the development jobs (the plan named only the two labels; a new compiler there is worth seeing early), and `windows-2025-vs2026` rather than `windows-2025`, because the first names the toolchain (Visual Studio 2026) that the MSVC job has been tested with.
- **A trap removed:** the macOS jobs named their interop and binary artifacts with `matrix.os == 'macos-latest' && 'macos-arm64' || 'macos-x64'`, which after a relabel would have called the arm64 build `macos-x64` without any error. They now use `runner.arch == 'ARM64'`.
- **Nightly: added, then switched off by decision** while the code is being developed (every push runs `build.yml` anyway). `build.yml` keeps `workflow_dispatch`; the cron lines are in the header comments of `build.yml` (`43 4 * * *`) and `constant-time.yml` (`17 3 * * *`) to put back. **No workflow has a schedule now**, which also means that nothing shows a weekly image update until the next push. A scheduled run only covers the default branch, and GitHub switches schedules off after 60 days without activity.
- **Procedure** for changing a label: TESTING.md section 7 (look at what the label runs, one branch, every workflow and table at once, the whole `build` run twice more, the dry run of `release.yml`, then `main`), and the Workflows bullet of the runner-driven-development skill points there.
- **Not shown yet:** the changed workflows have been checked for YAML syntax and for leftovers of the old labels, and have not run on a runner; the first push of this change is the proof (the job names change, for example `macos (macos-26, ci)`).

## 1. State of the code
The crypto core is portable C++11: byte-wise (de)serialisation, no asm, intrinsics, `__int128` or libraries.
Non-portable code is in the OS layer.

### 1.1 Linux-only code
Steps 1 to 3 (section 0c) moved the OS calls of `common.cpp`, `kdf.cpp`, `keys.cpp` and `main.cpp` into `src/platform_posix.cpp` and removed the other items marked done. What the table lists is the state before; "now" says what is left.

| Where | Linux-ism | Now |
|---|---|---|
| src/common.cpp | open/read/write/fstat, O_NOFOLLOW, O_CLOEXEC, mode 0600, getrandom, prctl, setrlimit, explicit_bzero, no O_BINARY | in `platform_posix.cpp` and `platform_win32.cpp`; done on all three (0d, 0h, 0i, 0j) |
| src/kdf.cpp `require_memory` | /proc/meminfo, sysconf(_SC_AVPHYS_PAGES), RLIMIT_AS/DATA | `available_memory()`; done on all three (0h) |
| src/keys.cpp | termios, isatty, STDIN_FILENO, fopen(name,"r") | `read_secret_line`, `stdin_is_terminal`; the key file already goes through `readfile` |
| src/main.cpp | stat() st_dev/st_ino same-file test; argv as bytes | `same_file()`; argv is a vector of UTF-8 strings, `wmain` on Windows; done |
| src/sha512.cpp, src/blake2b.cpp | call explicit_bzero directly instead of wipe() | done |
| test/test_primitives.cpp, tools/gen_des_sbox.cpp | __builtin_popcount, __builtin_ctz | done; the test's OS needs (temporary files, stderr, lock figures) are in `test/test_os_posix.cpp` and `test_os_win32.cpp` (section 0d) |
| test/test.sh | bash, stat -c, head -c -N, od, md5sum, ulimit -v, /dev/urandom | done: `test/test_e2e.cpp` (section 0g) |
| Makefile, .github/workflows/build.yml | GNU make; ubuntu only | CMake, a `cmake` job (g++, clang++), `windows-msvc`, `windows-mingw` and `macos` jobs exist; the Makefile (Linux only) is gone (todo 13, 0l) |

### 1.2 Latent bugs a port would trigger
Items 2, 3, 4, 7, 9, 10 and 11 to 16 are about character sets and line endings; section 3.4 solves them. Step 0b fixed 2, 3, 7 and 11 to 16 (section 0b). All done now (0d, 0i): 4, 9, and of 10 the conversion at the console. "Measured" means reproduced on Linux with the 5.1.1 binary, before step 0b. Those bugs are not Windows-only: a key file or a phrase file made on Windows fails on Linux today.

1. Same-file check: on Windows st_ino is 0, so every run fails with error 6. **Done (step 3):** `same_file()` in the platform layer; the Windows version uses `GetFileInformationByHandle` (done, 0d).
2. CRLF key files: `\r` is not treated as whitespace, giving error 5 (measured).
3. CRLF phrase: a piped phrase keeps a trailing `\r` and derives different keys, so decryption ends in error 13 (measured, also for a `\r` at the end of input and for spaces followed by CRLF, where the trimming of trailing spaces stops at the `\r`).
4. Binary mode: Windows text mode translates CRLF and treats 0x1A as EOF; use `CreateFileW`, so that no text mode exists. On Linux, data with 0D 0A 1A 00 round-trips byte-exact (measured).
5. `unsigned long`/`%lu`/`strtoul` in armor.cpp is 32-bit on Windows x64; breaks above about 4 Gi characters. **Done (step 3, at the user's request):** `uint64_t`, `PRIu64`, `strtoull`; the END line's CRC is read with `strtoll`.
6. Unchecked size arithmetic in container.cpp and readfile; add overflow checks. **Done (step 3):** `checked_add` and `checked_mul` in `readfile`, `seal`, `pad256` and the armor header.
7. No `.gitattributes`: a checkout with `core.autocrlf=true` gives `sample.key`, `hello.sdes` and `test/format-5.1.0/hello-phrase.sdes` CRLF line endings (measured). The two armored files still decrypt, `sample.key` is then error 5 (item 2). `test/format-5.1.0/hello.bin` is detected as binary and stays intact, but only by git's guess; nothing guarantees it for the next fixture.
8. Error-7 test relies on `ulimit -v`, unavailable on macOS/Windows. **Done (0h, 0j):** Windows uses a job object; macOS cannot set a limit and skips.
9. Windows argv is in the ANSI code page; non-ASCII file names fail. **Done (0d):** `wmain`.
10. Phrase bytes come from the OEM/ANSI code page on Windows but are UTF-8 on Linux/macOS: same phrase, different keys (measured on Linux with CP1252 and CP850 input). A piped phrase has no defined encoding on Windows at all: cmd writes the OEM code page, Windows PowerShell 5.1 writes ASCII and turns every other character into `?`, PowerShell 7 writes UTF-8, and a redirected file holds whatever the editor saved.
11. Byte order mark: a UTF-8 BOM gives error 5 in a key file, error 8 in armored text when it stands directly before `*BEGIN` (before the leading blank line it is harmless), and different keys at the start of a piped phrase (measured).
12. UTF-16: Windows PowerShell 5.1 `>` and the UTF-16 options of Notepad write UTF-16 with a BOM. Error 5 for a key file, error 8 for armored text, different keys for a phrase (measured).
13. CR-only line endings: error 5 for a key file, error 8 for armored text (measured).
14. Unicode equivalence: the same phrase as NFD instead of NFC derives different keys (measured). So do full-width forms from an East Asian input method, a no-break space, and an invisible character (zero-width space, soft hyphen) that came along with pasted text.
15. Encryption accepts a phrase that nobody can reproduce: a tab or the escape sequence of an arrow key becomes part of the phrase (measured: different keys), and so do bytes that are not UTF-8, such as UTF-16 from a pipe or what is left after a backspace over an accented letter on a terminal without `iutf8` (not measured). The file is made without a warning and is then very hard to open.
16. A fix for 3, 10, 11, 14 or 15 changes the keys of some phrases, so files written by one release are no longer read by another. By the project's own definition that is a new file format: "no format bump" and a phrase fix cannot both hold. Hence the decision above.
17. Observation, not solved here: an armor tag line that is quoted (`> `) or indented gives error 8 (measured). Not a character-set problem.

## 2. Architecture: thin platform layer
`src/platform.h` with `platform_posix.cpp` (Linux + macOS, `#ifdef __APPLE__`) and `platform_win32.cpp`. No other file includes OS headers (the unit test is the exception until todo 10). Keep `Buf`, `wipe`, `randbytes`, `readfile`, `writefile`, `errorexit` as the stable API. **Done on Linux (step 2, section 0c):** `platform.h`, `platform_posix.cpp`, and a `main.cpp` that works on a vector of UTF-8 arguments; the table below is the plan for the other two columns.

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
- **Done (step 3).** Route every explicit_bzero in sha512.cpp and blake2b.cpp through wipe().
- **Done (step 3).** armor.cpp: uint64_t, PRIu64, strtoull; a count that does not fit is read to the end of the text and ends in error 11 (`size_t` is 64-bit on every target).
- **Done (step 3).** Checked-size helpers (`checked_add`, `checked_mul`) used by readfile, seal, pad256 and the armor header; `unseal` only subtracts after a length check.
- **Done (step 3).** Replace __builtin_* in tests/tools with portable loops.
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
- Universal binary via CMAKE_OSX_ARCHITECTURES: **done (0j)**, preset `universal`.
- No getrandom, /proc, explicit_bzero; RLIMIT_AS not enforced (error-7 test needs another trigger).
- Hardened runtime + codesign (no get-task-allow): **done (0j)**; notarization optional, not done.
- Memory policy: refuse if hw.memsize minus headroom is below 2 GiB or free+inactive+speculative is clearly insufficient.

### 3.4 Same bytes everywhere
Solves items 2, 3, 4, 7, 9, 10 and 11 to 16 of section 1.2. Everything here except the Windows calls is platform-independent and is done (step 0b, section 0b); headings marked "done" describe what is in the tree. The Windows calls are done too (0d, 0i).

#### Principles
- Inside the program every text is UTF-8: phrase, file names, messages. The platform layer converts at the edge.
- Data is bytes. Plaintext and the binary container are never translated; a CRLF text file decrypts to CRLF on every OS.
- Text the program writes (armor) is the same on every OS: LF only.
- Text the program reads (key file, armor, phrase) is accepted with every line ending and in the common encodings.
- The phrase rules are part of the file format, so the format name says which rules a file follows.

#### File format 5.2.0 (done, released as 5.2.0)
- `FORMAT_NAME "SillyDES 5.2.0"` and `MAGIC` `S D 5 0x20` changed together. The labels of the whitening, the tweak and the key-file MAC key change with the name, so the two formats are also separated cryptographically.
- The container layout, the armor layout and the key file layout stay as they are, and existing key files keep working. Only the phrase rules below are new.
- Files of 5.1.0 are refused like those of any other version: error 13 for a container, error 8 for armored text. Release 5.1.1 decrypts them, and the changelog says so.
- Procedure followed: the format-change appendix of `.github/skills/make-release/SKILL.md` (fixtures regenerated into `test/format-5.2.0/`, `test/format-5.1.0/` removed, `hello.sdes` regenerated, the stored known answer of the core block replaced after confirming that only the label changed).
- Order: release 5.2.0 came before the first Windows or macOS release, so no binary on those systems will ever write 5.1.0.

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

#### Data files, file names and messages (done: Windows in 0d and 0i)
- Data files on Windows: `CreateFileW`, so no text mode exists; no CRT file descriptor is used for data.
- Arguments on Windows: `wmain` (MinGW: `-municode`) to UTF-8. An argument that is not valid UTF-16 is error 4.
- File names are never normalised: Linux passes the bytes, macOS and Windows pass the name to the OS as given.
- Messages on Windows: `WriteConsoleW` when the handle is a console, UTF-8 bytes when redirected.
- Phrase on Windows: `ReadConsoleW` on a console, converted strictly to UTF-8 (an unpaired surrogate is refused); a line that starts with Ctrl+Z is end of input. On a pipe or a redirected file the bytes are taken as they are: a pipe carries UTF-8, and text in another encoding is refused by step 2 or 3 in nearly every case.

#### Repository (done)
- `.gitattributes`: `* text=auto eol=lf`, `*.bin binary`, `*.sdes -text`, `*.key text eol=lf`, `test/format-*/** -text`.
- No tracked file contains a CR or a BOM today and `src/`, `test/` and `tools/` are pure ASCII, so adding the file renormalises nothing. A test keeps the sources ASCII with LF.

#### Limits that remain (README section 7 has them, per system, since 0m)
- Windows PowerShell 5.1 replaces non-ASCII characters by `?` before the program sees them, which cannot be detected. Advice: set `$OutputEncoding` to UTF-8, or use PowerShell 7; in cmd use `chcp 65001`.
- Look-alikes that Unicode keeps apart stay different: straight and curly quotes, hyphen and dashes, Latin and Cyrillic letters, upper and lower case.
- Characters assigned after the pinned Unicode version are not folded.
- mintty without ConPTY presents stdin as a pipe: the phrase is echoed and not confirmed. The keys are still right.

## 4. Security hardening
### 4.1 Process hardening
| Goal | Linux | macOS | Windows |
|---|---|---|---|
| No dumps | RLIMIT_CORE=0, PR_SET_DUMPABLE=0 | RLIMIT_CORE=0 | **Done (0h):** SetErrorMode(SEM_NOGPFAULTERRORBOX); WerRegisterExcludedMemoryBlock for arena, locked pages and stack window; the exclusion is not verified (no read-back) |
| Block same-user debugger | PR_SET_DUMPABLE=0 | **PT_DENY_ATTACH done (0h)**; **hardened runtime signature done (0j)**; the attach itself is not shown to be refused **Done (0i):** restrictive DACL on own process (owner keeps query-limited, terminate, synchronize); admin/SeDebug still bypasses: mitigation, not a boundary |
| Code injection | n/a | **hardened runtime done (0j)** | **Done (0i):** SetProcessMitigationPolicy: dynamic code prohibited, extension points disabled, remote images refused, no child process; strict handle checks left out on purpose |

All best-effort, never fatal. README section 8 must state exactly what each OS does.

### 4.2 Build hardening (keep -Wall -Wextra -Werror in CI)
- GCC/Clang Linux: -fstack-protector-strong, -D_FORTIFY_SOURCE=3 (2 on old toolchains), -fstack-clash-protection, -fcf-protection (x86), -mbranch-protection=standard (arm64), PIE, -z relro -z now -z noexecstack. **`-z relro -z now` is already in place (section 0c); it does not by itself keep secrets out of the stack, see the lessons there (`exit_process`).**
- macOS: PIE, stack protector, hardened runtime at signing (done, 0j; checked by ctest).
- MSVC: /GS /sdl /guard:cf /Qspectre, /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /CETCOMPAT. MinGW: -fstack-protector-strong -Wl,--dynamicbase,--nxcompat,--high-entropy-va.
- CI jobs with ASan+UBSan (Linux, macOS) and MSVC /fsanitize=address.

### 4.3 Memory hygiene gaps (M1-M9 done; Linux in step 0, Windows and macOS in 0h)
| # | Finding | Fix |
|---|---|---|
| M1 | **Done (Linux).** getphrase/read_hidden used getchar(); the stdin stdio buffer kept a copy of the phrase, never wiped | read() into a SecretBuf, no stdio. Windows: ReadConsoleW into the same type |
| M2 | **Done.** s.reserve(1024); longer phrases realloc and left an unwiped copy; `again` not reserved; short strings live inside the std::string object | SecretBuf (no short-string buffer, wipes on growth/destruction) |
| M3 | **Done.** readkeyfile used fopen/fgets; FILE buffer held key text; line/parse wiped only on success | parses a readfile Buf; wiped on every path (RAII) |
| M4 | **Done.** errorexit() called exit(), so destructors never ran: KeyInput, KeyMaterial, SillyDesCipher (keys, schedules, whitening) and the data buffer were not wiped on any error path (e.g. error 13); measured: key text left in memory | errorexit throws ExitError, caught in main, so RAII unwinds and wipes |
| M5 | **Done.** reserve_wiped workaround for std::vector growth | SecureAllocator wiping on deallocate; Buf keeps its name; reserve_wiped removed |
| M6 | **Done (Linux).** Secrets could be swapped | not one arena: lock_stack() window of 256 KiB (covers every stack-held secret: keys, 8 schedules about 24 KiB, whitenings, pad states, KDF blocks) + LockedAllocator pages for heap secrets; best-effort, silent |
| M7 | **Partly done (Linux).** 2 GiB Argon2 arena and whole-file plaintext are not lockable unprivileged; a swapped arena is key-equivalent | arena: `memfd_secret` (Linux 5.14+) when `RLIMIT_MEMLOCK` or `CAP_IPC_LOCK` allows the size, else lock_memory when the limit allows, MADV_DONTDUMP (blocks of 64 KiB and more); residual risk documented in README 8 and ANALYSIS 8; encrypted swap advised; opt-in `SILLYDES_REQUIRE_LOCK=1` makes an unlocked arena error 15. **Investigated, done (0o):** `memfd_secret` obeys the lock limit like `mlock`, so it adds protection (no direct map, no hibernation, no swap) only where 2 GiB is lockable anyway |
| M8 | **Done.** Plaintext wiped only on main's success path | covered by M4 + M5 |
| M9 | **Done (0h).** Windows: vector<Block>::resize(2 GiB) needs 2 GiB commit | VirtualAlloc(MEM_COMMIT); `available_memory()` is the smaller of free physical memory, the free commit limit and the job limit; a failed commit is error 7; tested with a job limit |

### 4.4 KDF memory-hardness per platform
- Keep m = 2 GiB, t = 1, p = 4 and the RFC 9106 vectors.
- require_memory equivalent on all OSes; keep "fail with error 7, never overcommit and die".
- No large/huge pages by default. No SIMD (small audit surface, identical behaviour).
- Report KDF time on arm64 and Windows in CI logs (expect about 2 s). **Done (0k):** 2.1 to 6.2 s on the runners, see there.

## 5. Constant-time
### 5.1 Review
| Component | Status | Note |
|---|---|---|
| DES layer, setkey | Constant-time by construction | bitsliced, boolean S-boxes, constant indices, `0u - bit` masks |
| SHA-512 / HMAC / BLAKE2b | Constant-time by construction | K512[i] indexed by public counter |
| Tag compare in unseal | **Done (0e).** Correct pattern, but compiler may make it early-exit | `ct_equal()` with `value_barrier` |
| length_mask, pad256, unpad256 | Run after authentication; only leak is public length | keep; test that bad data never reaches them |
| readkeyfile / htoa | **Done (0e).** Branches per key character | branch-free `hex_digit`; an invalid digit is reported after the whole key is read |
| getphrase length check | Branches on length | leave |
| Phrase canonical form (text.cpp) | Not constant-time: table lookups and branches depend on the phrase | leave; same class as the Argon2id addressing, and an ASCII phrase touches no table |
| Argon2id | Data-dependent addressing in 2nd half of pass 0 | documented; same on all OSes, shared hosts/VMs are the exposure; the optional Argon2i mode (header byte 7) removes it |

### 5.2 Compiler/arch risk
- **Done (0e).** `value_barrier()` (empty asm on GCC/Clang, volatile read on MSVC) around mask creation in setkey, `ct_equal` and the hex decode.
- **Done on Linux and macOS arm64 (0e).** DIT (`msr dit, #1`) set once in `harden_process`, after asking the OS whether the CPU has it (`getauxval` HWCAP, `sysctl hw.optional.arm.FEAT_DIT`); the program has no threads. Windows arm64: done in 0q.
- Confirm BlaMka's 32x32->64 multiply stays constant-time per target.

### 5.3 Verification
1. Valgrind/ctgrind job (Linux x64): secrets marked undefined through setkey, layer, Hmac512, ct_equal, hex decode; gcc and clang at -O0/-O2/-O3.
2. Disassembly gate (CMake test): fail on data-dependent conditional jumps in des/sha512 objects outside an allow-list (x86-64, arm64). Start report-only.
3. Nightly dudect-style test on Linux, macOS arm64 and Windows.
4. Test that wrong-key vs right-key decrypt time does not depend on where the MAC differs.
5. Record results per compiler/arch in ANALYSIS.md section 8.

## 6. Tests
- **Done (0g).** Port test.sh to C++ `test_e2e.cpp` under CTest (a spawn helper for CLI runs); dependency-free, same on all OSes.
- **Done (0h).** Port, do not drop, the Linux-only checks of step 0: the unit tests of the key file parser, buffer growth and locking (skip under sanitizers), and the residue scan. The scan is one implementation for all three OSes, in-process (the scan binary, a test-only hook in `exit_process`), with the preload library kept for the real binary on Linux.
- Keep: golden decrypts (hello.sdes, format-5.2.0/hello.bin, hello-phrase.sdes, hello-utf8-phrase.sdes); round trips at 0, 1, 255, 256, 257, 1000, 5000; tamper tests (bit flip, truncation, header, KDF params); wrong key/phrase; parity bit; short key file; short phrase; fresh salt/IV; repeated blocks.
- New: in/out same file via different path spellings, hard link, symlink, case-insensitive paths; armor counter above 2^32 (unit test); size-overflow guards.
- **Done (step 0b), in test_primitives.cpp; runs on every OS once ported.** Text interchange (section 3.4), unit tests: `decode_text`; one key file as LF, CRLF, CR, with a UTF-8 BOM and as UTF-16 LE and BE gives the same keys; the armored fixture in the same variants decrypts; an armor known answer without CR; the canonical phrase table (every step, accepted and refused); the normalisation subset and the hash of the tables.
- **Done (step 0b; ported to test_e2e.cpp in 0g).** Text interchange, end to end: new fixture `test/format-5.2.0/hello-utf8-phrase.sdes` (Latin, Greek, CJK and one character outside the BMP) opened with NFC, NFD, full-width, CRLF and BOM input and with an invisible character inserted; a phrase that is not UTF-8 is refused without a KDF run; a 5.1.0 file is refused; a data file containing 0x0D 0x0A 0x1A; non-ASCII input, output and key file names; the residue scan with a non-ASCII phrase.
- **Done (0i).** New, Windows only: a phrase typed into a console, including a surrogate pair (through ConPTY, and on POSIX through a pty); a piped CRLF phrase (0g); PowerShell and cmd pipes; a redirected message is UTF-8 (`messages_are_utf8`, every OS).
- Error 7 without ulimit: **macOS: not possible (0j)**, the limits cannot be set below the mapped address space; Windows has the job object (0h). An injectable available_memory() in test builds would be a second test hook in the program and is not planned.
- **Done (0k).** Cross-OS interop: CI uploads files encrypted on one OS (binary and armored; with a key file, an ASCII phrase and a non-ASCII phrase) and decrypts them on the others. The Windows job also writes a key file with PowerShell `>`. This runs only on the GitHub runners (section 7.1).
- Windows and macOS tests exist only as runner results: write each test so that it also fails loudly when its precondition is missing (no console, `mlock` limit) instead of passing silently, and print the reason for every skip.

## 7. Build, CI, release
- **Done (step 1, section 0c), except for the per-compiler hardening flags (todo 9), `test_e2e` (todo 10) and deleting the Makefile (todo 13, done in 0l).** CMakeLists.txt: C++11, extensions off; targets sillydes, test_primitives, test_e2e, gen_des_sbox, gen_unicode; options SILLYDES_REGENERATE_SBOX and SILLYDES_REGENERATE_UNICODE (the latter takes a directory with the Unicode data files); per-compiler flags from 4.2; install rule; presets. Delete Makefile; update README section 1, STRUCTURE.md, and the "Linux command line port" comment in main.cpp.
- CI matrix: ubuntu (gcc, clang), Linux arm64, macOS arm64 and Intel, windows-latest (MSVC x64), Windows arm64, MSYS2 mingw64. Extras: sanitizers, valgrind ct test, interop, optionally s390x under QEMU for big-endian. Pick runner labels at implementation time.
- Keep the "no dependencies" claim: CI installs only compilers and CMake. The Unicode tables are generated data in the source tree, like the S-box header.
- **Done (step 0b)** as the workflow `unicode.yml` with the CMake targets `regenerate_unicode` and `check_unicode` (they were Makefile targets until 0l): download the Unicode data files of the pinned version (checked against stored SHA-256 sums), confirm that the generator reproduces the committed `src/unicode_tables.h`, and run the complete `NormalizationTest.txt`. Ported to CMake (done).
- Optional release: Authenticode, macOS codesign + notarization, SHA-256 sums, SBOM, reproducible-build check.
- SECURITY.md: threat model and known limits (swap, Argon2 cache timing, same-user admin on Windows).

### 7.1 Where each part runs (decision: non-Linux only on GitHub Actions)
The Windows and macOS code is written here but never built or run here: no MinGW cross-compiler, no Wine, no osxcross, not as a local check and not as a CI shortcut. The runners are real operating systems, so they test the things an emulator would only approximate (console input and echo, `VirtualQuery`, process DACL, WER, working-set locking, `mlock`, `vm_region`, hardened runtime).

| Part | Where | Notes |
|---|---|---|
| Linux x64 (gcc, clang), sanitizers, valgrind ct test and the CMake build | This machine and CI | Both give a result; CI decides |
| Linux arm64 | CI (arm64 runner) | Not needed locally |
| Windows MSVC x64, MSYS2 mingw64 | CI only (`windows-latest`) | The MinGW flags and `-municode` are checked by the MSYS2 job, which is native |
| Windows arm64 | CI only (`windows-11-arm`) | Available to this public repository; done (0k) |
| macOS arm64, macOS Intel | CI only (`macos-` runners) | codesign checked there; notarization needs the maintainer's Apple account and secrets and stays out of scope until chosen |
| Cross-OS interop | CI only | Jobs upload files and the others download them |
| Big-endian (s390x) | This machine and CI, under QEMU user mode | Done (0k): unit tests and interop with x86-64; no end-to-end test |

How the work proceeds, because there is no local test bench for the ports:
- A branch `port/<todo>` per Windows or macOS todo, pushed early; the runner log is the feedback. Merge to `main` only when the whole matrix is green.
- Windows and macOS code is kept small and behind the platform layer, so that most of each change compiles on Linux and only the thin OS calls are first compiled on the runner. Each platform file is compiled on Linux as far as it can be (the portable and POSIX parts), and the rest relies on the runner.
- Order of work: first a CI job that only builds and runs `test_primitives` on Windows and macOS (todo 1 and the platform layer give the stubs), then one OS feature per push (files, phrase input, memory, hardening), each with its own test.
- Runner logs must carry what a local run would have shown: compiler version, OS version, KDF time (section 4.4), the skipped tests and why (`mlock` limit, no console).
- Interactive checks (a phrase typed into a console) use a pseudo-console (ConPTY) in the Windows job and a pty on POSIX (0i). Nothing relies on a human at a keyboard.
- A runner is a server image, not a user's machine: small default `mlock` and working-set limits, no desktop session, possibly Defender slowing the 2 GiB test. Tests skip with a message below a limit. What a runner cannot show is listed in section 10.
- Cost and limits: public repository runners are free; the matrix runs the 2 GiB tests on every runner, so a run takes minutes. Keep Windows arm64 and macOS Intel jobs on pull requests and release tags if a quota ever bites.
- A release stays a Linux release until the Windows and macOS jobs, interop included, are green on the release commit; the release workflow then adds their binaries. **Done (0n):** the release workflow builds all five targets, and the release skill says to run it by hand as a dry run after the matrix is green.

## 8. Documentation
- **Done (0m).** README (the format, key file, armor and phrase parts were done in step 0b; the OS-specific parts in 0m): sections 1 (CMake, supported OS, format 5.2.0 and that 5.1.1 converts older files), 5 (line endings and encodings accepted in armored text), 7 (Windows quoting; key file line endings and encodings; the phrase rules: what is folded, what is refused, the PowerShell 5.1 advice and the other limits of 3.4; "every character your computer accepts is allowed" no longer holds), 8 (exact per-OS hardening), 9 (error 7 per OS).
- ANALYSIS.md section 8: per-OS wording and verification results; the phrase canonical form (folding and entropy, not constant-time).
- STRUCTURE.md: platform layer, units table (`text.cpp`, the generator, the generated header), build, 5.1 (phrase rules), 6.2 (armor reader), 7 (phrase input diagram).
- CHANGELOG.md and the release notes: "File format: new (5.2.0)", the reason, and that 5.1.1 decrypts older files (done, release 5.2.0). The renaming of the labels in the other documents follows the format-change appendix of the release skill, whose own examples name 5.1.0 too.

## 9. Todos (dependencies)
0. memory-hygiene-linux: **done** (section 0)
1. cmake-baseline: **done** (section 0c)
2. platform-layer (after 1): **done on Linux** (section 0c); move `secure_alloc`, `locked_alloc`, `lock_stack`, `lock_memory` and the secret-line input into it
3. portable-fixes (after 2): **done** (section 0c)
4. memory-hygiene (after 2, 15): **done** (section 0h). `ReadConsoleW` into a locked buffer was already part of 0d; the DACL and mitigation policies moved to todo 5
5. windows-port (after 3, 4, 14, 15): **done** (section 0i); includes the Windows calls of section 3.4 (wmain, CreateFileW, ReadConsoleW, WriteConsoleW); written here, built and tested only on the Windows runners (section 7.1)
6. macos-port (after 3, 4, 14, 15): **done** (section 0j); written here, built and tested only on the macOS runners (section 7.1)
7. ct-hardening (after 2): **done** (section 0e); the verification is todo 8
8. ct-verification (after 7): **done** (section 0f)
9. build-hardening (after 1): **done** (section 0e)
10. tests-portable (after 3, 14): **done** (section 0g)
11. ci-matrix (after 5, 6, 9, 10): **done** (section 0k); interop, Windows arm64, big endian
12. docs-update (after 8, 11): **done** (section 0m)
13. remove-makefile (after 11): **done** (section 0l)
14. text-interchange: **done** (section 0b), released as 5.2.0
15. ci-runners-early (after 1, 2): **done** (section 0d); a workflow that builds with CMake and runs `test_primitives` on the Windows and macOS runners (section 7.1), the only test bench the ports have; 4, 5 and 6 start after it, and it grows with them. It needs a first `platform_win32.cpp` (and the macOS branches of `platform_posix.cpp`) that compile and do the minimum, and the OS headers of `test_primitives.cpp` guarded or moved (todo 10 in part); start with those and let the runner log lead from there

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
- No local test bench for Windows and macOS: every defect there costs a push and a runner cycle, and a runner is a server image. What a runner cannot show stays unverified and is named in the release notes: real Windows 10 and older builds, a user's terminal emulator or mintty, real PowerShell 5.1 profiles, macOS Gatekeeper and notarization on a user's machine, machines with less than 2 GiB free. Mitigation: small platform files, early runner jobs (todo 15), one OS feature per push, loud skips, and no release of a Windows or macOS binary before the whole matrix is green on the release commit.
- Runner images and their labels change (`windows-latest`, `macos-latest` move to newer OS versions). *Done (section 0r):* the labels are pinned, nothing runs on a schedule at present (0r), and TESTING.md section 7 says how to change a label on purpose.