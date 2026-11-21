# Plan: make SillyDES portable (Linux, macOS, Windows) and harden it

## Decisions
| Topic | Decision |
|---|---|
| Build system | CMake only; Makefile removed once CMake builds, tests and regenerates the S-box header |
| Targets | Linux x64 + arm64 (gcc, clang); macOS arm64 + x86-64; Windows x64 (MSVC), x64 (MinGW/MSYS2), arm64. 64-bit only |
| File format | 5.1.0 stays byte-identical on every platform; `test/format-5.1.0/*` and `hello.sdes` must decrypt everywhere. No format bump |
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
| Stack scrub | `scrub_stack()` wipes the same 256 KiB stack window before `main` returns. Found by CI: with gcc 13 (ubuntu-latest) two copies of the plaintext survived in stale frames after decryption, where gcc 15 left none; which temporaries spill is compiler-dependent, so wiping the window is the robust fix. Checked with an injected leak: 811 hits without the scrub, 0 with it. |
| Small gaps | SHA-512 message schedule and the HMAC inner digest are wiped; the DES S-box output array is wiped once per layer. |

Differences from the original M6 idea: no single secret arena. Stack objects are covered by the stack window and heap secrets by the page-sized `LockedAllocator`, which needed no change of ownership in the cipher or the container.

Verified: all existing tests; new unit tests (errors as exceptions, key file parser, buffer growth across the thresholds, `lock_stack`/`SecretBuf`/`lock_memory` against `/proc/self/status` `VmLck`, skipped when `RLIMIT_MEMLOCK` is under 1 MiB); `test/residue_scan.cpp` (an `LD_PRELOAD` scanner of the exited process, marks XOR-masked in the environment) in `test.sh`: no key text, key bytes, phrase (5000 characters) or plaintext remains after encryption, decryption and error 13, with a positive control. The old binary fails this test (key left in memory after an authentication failure; the phrase left in the heap in every phrase run). ASan + UBSan clean. No speed or peak-memory change (64 MiB: 4.7 s either way; phrase mode 1.8 s and 2.1 GB).

Known limits that remain: the data buffer is never locked (it can be as large as the file); the 2 GiB table is locked only if the limit allows it; the lock is best effort and silent, so encrypted swap is still the advice; heap blocks below 64 KiB of `Buf` are wiped but not locked; `Sha512::block` locals in registers cannot be wiped. The SHA-512 schedule wipe has no measured effect (the slot is overwritten by the next block), it is only correct.

Lessons that carry into the port: the residue test must run on every compiler in the CI matrix, as stack residue depends on it; a stack window is needed on every OS (Windows: `_alloca` + `SecureZeroMemory`); sanitizers replace `mlock` by a no-op, so the locking tests must skip under them; the residue test relies on `LD_PRELOAD` and `/proc/self/maps` (Linux only).

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
1. Same-file check: on Windows st_ino is 0, so every run fails with error 6.
2. CRLF key files: `\r` is not treated as whitespace, giving error 5.
3. CRLF phrase: a piped phrase keeps a trailing `\r` and derives different keys.
4. Binary mode: Windows text mode translates CRLF and treats 0x1A as EOF; use `_O_BINARY`/`CreateFileW`.
5. `unsigned long`/`%lu`/`strtoul` in armor.cpp is 32-bit on Windows x64; breaks above about 4 Gi characters.
6. Unchecked size arithmetic in container.cpp and readfile; add overflow checks.
7. No `.gitattributes`: autocrlf corrupts `test/format-5.1.0/hello.bin` on Windows checkouts.
8. Error-7 test relies on `ulimit -v`, unavailable on macOS/Windows.
9. Windows argv is in the ANSI code page; non-ASCII file names fail.
10. Phrase bytes come from the OEM/ANSI code page on Windows but are UTF-8 on Linux/macOS: same phrase, different keys.

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
| read_secret_line | termios, /dev/tty fallback | same | GetConsoleMode/ReadConsoleW -> UTF-8; stdin binary when piped |
| utf8_args | identity | identity | wmain/CommandLineToArgvW -> UTF-8 |

## 3. Portability work
### 3.1 Portable code
- Route every explicit_bzero in sha512.cpp and blake2b.cpp through wipe().
- armor.cpp: uint64_t, PRIu64, strtoull; reject counts that overflow size_t.
- Checked-size helpers used by readfile, seal, unseal, high2low.
- Replace __builtin_* in tests/tools with portable loops.
- `\r` is whitespace in readkeyfile; strip trailing `\r` from phrase input.
- MSVC `/utf-8` so FORMAT_NAME and labels (hashed into keys) are identical bytes everywhere.

### 3.2 Windows
- MSVC x64/arm64 and MinGW-w64: wmain + UTF-8, binary stdio, CreateFileW, link bcrypt, `_WIN32_WINNT >= 0x0A00`.
- Console output UTF-8 (SetConsoleOutputCP); messages stay ASCII.
- No 0600: output inherits directory ACL (document), optionally a current-user-only DACL.
- Replace O_NOFOLLOW with FILE_FLAG_OPEN_REPARSE_POINT and refuse reparse points on output.

### 3.3 macOS
- Universal binary via CMAKE_OSX_ARCHITECTURES.
- No getrandom, /proc, explicit_bzero; RLIMIT_AS not enforced (error-7 test needs another trigger).
- Hardened runtime + codesign (no get-task-allow); notarization optional.
- Memory policy: refuse if hw.memsize minus headroom is below 2 GiB or free+inactive+speculative is clearly insufficient.

### 3.4 Same bytes everywhere
- Phrase = UTF-8 bytes of what was typed; Windows must convert from UTF-16, never ANSI/OEM.
- No Unicode normalisation (would change keys for existing files). Document: type accented phrases identically on both systems; prefer ASCII/random phrases. Known limit.
- Armor keeps `\n` on every OS; decoding already ignores `\r`.
- `.gitattributes`: `* text=auto eol=lf`, `*.bin binary`, `*.sdes -text`, `*.key text eol=lf`, `test/format-*/** -text`.

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
- Keep: golden decrypts (hello.sdes, format-5.1.0/hello.bin, hello-phrase.sdes); round trips at 0, 1, 255, 256, 257, 1000, 5000; tamper tests (bit flip, truncation, header, KDF params); wrong key/phrase; parity bit; short key file; short phrase; fresh salt/IV; repeated blocks.
- New: key file with CRLF; phrase with CRLF; non-ASCII UTF-8 phrase; armored text with CRLF; in/out same file via different path spellings, hard link, symlink, case-insensitive paths; non-ASCII output name; binary-mode file containing 0x0D 0x0A 0x1A; armor counter above 2^32 (unit test); size-overflow guards.
- Error 7 without ulimit: injectable available_memory() in test builds; keep ulimit test on Linux.
- Cross-OS interop: CI uploads files encrypted on one OS (binary, armored, key file, phrase) and decrypts on the others.

## 7. Build, CI, release
- CMakeLists.txt: C++11, extensions off; targets sillydes, test_primitives, test_e2e, gen_des_sbox; option SILLYDES_REGENERATE_SBOX; per-compiler flags from 4.2; install rule; presets. Delete Makefile; update README section 1, STRUCTURE.md, and the "Linux command line port" comment in main.cpp.
- CI matrix: ubuntu (gcc, clang), Linux arm64, macOS arm64 and Intel, windows-latest (MSVC x64), Windows arm64, MSYS2 mingw64. Extras: sanitizers, valgrind ct test, interop, optionally s390x under QEMU for big-endian. Pick runner labels at implementation time.
- Keep the "no dependencies" claim: CI installs only compilers and CMake.
- Optional release: Authenticode, macOS codesign + notarization, SHA-256 sums, SBOM, reproducible-build check.
- SECURITY.md: threat model and known limits (swap, Argon2 cache timing, same-user admin on Windows).

## 8. Documentation
- README: sections 1 (CMake, supported OS), 7 (Windows quoting, CRLF, UTF-8 phrase advice), 8 (exact per-OS hardening), 9 (error 7 per OS).
- ANALYSIS.md section 8: per-OS wording and verification results.
- STRUCTURE.md: platform layer, units table, build.

## 9. Todos (dependencies)
0. memory-hygiene-linux: **done** (section 0)
1. cmake-baseline
2. platform-layer (after 1); move `secure_alloc`, `locked_alloc`, `lock_stack`, `lock_memory` and the secret-line input into it
3. portable-fixes (after 2)
4. memory-hygiene (after 2): now only the non-Linux parts (M9, Windows/macOS locking, WER exclusion, ReadConsoleW)
5. windows-port (after 3, 4)
6. macos-port (after 3, 4)
7. ct-hardening (after 2)
8. ct-verification (after 7)
9. build-hardening (after 1)
10. tests-portable (after 3)
11. ci-matrix (after 5, 6, 9, 10)
12. docs-update (after 8, 11)
13. remove-makefile (after 11)

## 10. Risks
- errorexit -> exception: done in step 0, with the error table exercised by `test.sh`; keep nothing but `main` and the tests catching `ExitError`, and never call `exit` on an error path (it skips the wiping destructors).
- `mlock` limits differ by OS and distribution (macOS and Windows have small defaults; Windows needs a larger working set first); everything must stay best effort and silent, and the tests must skip below a limit.
- Windows process-DACL and WER APIs vary by version; use feature tests, treat as optional.
- Disassembly gate may be noisy across compilers; report-only first.
- NFC vs NFD for non-ASCII phrases remains a documented limit because the format must not change.
- Argon2 timing leak remains by decision; docs must say so on every platform.