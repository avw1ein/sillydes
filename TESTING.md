# SillyDES 5.2.0: tests, verification and CI

What is tested, how, why each test is built the way it is, and what the tests cannot show. For the
code layout see [STRUCTURE.md](STRUCTURE.md); for the cryptographic reasoning,
[ANALYSIS.md](ANALYSIS.md); for what the program promises, [SECURITY.md](SECURITY.md) and the
[README](README.md). Everything here was learned the hard way; the *Rules* and *Findings* are the
part to read before changing a test, a platform file or a workflow.

## 1. What runs

```sh
cmake --preset ci && cmake --build --preset ci && ctest --preset ci      # Linux, macOS (preset universal: both slices)
cmake -S . -B build -DSILLYDES_WERROR=ON && cmake --build build --config Release \
  && ctest --test-dir build -C Release --output-on-failure                  # Windows
```

The tests need 2 GiB of free memory and take about a minute. `-V` (the presets do it) puts every
`ok:`, `info:` and `skipped:` line in the log.

| Test | Source | What it proves |
|---|---|---|
| `primitives` | [test_primitives.cpp](test/test_primitives.cpp) | Known answers of every algorithm (RFC 7693, FIPS 180-4, RFC 4231, RFC 9106 and the reference implementation's vectors, FIPS 46 and CRC-32), the cipher's properties, the KDF bounds, errors as exceptions, the key file parser, buffer growth, memory locking, `scrub_stack`, `decode_text` and the phrase canonical form (also the hash of the Unicode tables), `available_memory`, and, last, `harden_process` read back from the operating system |
| `e2e` | [test_e2e.cpp](test/test_e2e.cpp) | The real binary, on every system the same way: golden files of format 5.2.0, round trips, phrase mode, tampering, wrong keys, key files and e-mail text in other encodings, phrases piped and typed another way, refused phrases, bytes that are not translated, file names outside ASCII, the same file under other spellings, a phrase typed into a terminal, PowerShell and `cmd` (Windows), the ASCII-and-LF rule for the sources, and the memory residue scan |
| `hardening` | [check_hardening.cmake](cmake/check_hardening.cmake) | The finished binary carries its build hardening: ELF (PIE, non-executable stack, RELRO, BIND_NOW, stack protector, IBT and SHSTK or BTI and PAC), PE (ASLR, high-entropy ASLR, DEP, control flow guard with MSVC), Mach-O (every slice PIE with stack protector, valid signature with the hardened runtime flag and without `get-task-allow`, the architectures asked for) |
| `ct_valgrind`, `ct_valgrind_detects_a_leak` | [ct_valgrind.cpp](test/ct_valgrind.cpp) | Linux, needs `valgrind`: with secrets marked uninitialised, no branch and no memory address depends on them in DES, SHA-512, HMAC, BLAKE2b, the MAC compare, `hex_digit`, key derivation from a key file, the cipher in CBC mode, padding, and `seal`; a deliberate leak must be caught |
| `ct_branches` | [ct_branches.sh](tools/ct_branches.sh) | Linux: the conditional branches per function of the binary, as a report; `hex_digit` must have none |
| `ct_timing` | [ct_timing.cpp](test/ct_timing.cpp) | Option `-DSILLYDES_TIMING_TESTS=ON`: a dudect-style Welch t-test of the same primitives and of `unseal` with a wrong tag; a deliberate early-exit compare must be detected |
| `unicode_check` | [unicode_conformance.cpp](test/unicode_conformance.cpp) | Option `-DSILLYDES_REGENERATE_UNICODE=<dir>` after `tools/fetch_ucd.sh <dir>`: the committed tables are what the generator makes of the data files, and the complete `NormalizationTest.txt` passes through the program's own normaliser |
| interop | `test_e2e --interop-make/--interop-check` | Files made by every system's build open on every other (section 6) |

CI ([build.yml](.github/workflows/build.yml), [constant-time.yml](.github/workflows/constant-time.yml),
[unicode.yml](.github/workflows/unicode.yml), [release.yml](.github/workflows/release.yml)) runs:

| Job | Where | Notes |
|---|---|---|
| `cmake` | ubuntu-latest, g++ and clang++ | the SBOM target, the SBOM artifact, interop files |
| `linux-arm64` | ubuntu-24.04-arm | the whole suite natively, residue scan included |
| `windows-msvc`, `windows-arm64` | windows-latest, windows-11-arm | `/W4 /WX`, static runtime |
| `windows-mingw` | windows-latest, MSYS2 UCRT64 | static; MINGW64 is deprecated by MSYS2 |
| `macos` | macos-latest (arm64), macos-15-intel; presets `ci` and `universal` | a universal binary runs its own slice on each runner, so both slices are tested natively |
| `sanitize` | ubuntu-latest, macos-latest | AddressSanitizer and UndefinedBehaviorSanitizer over the whole `e2e`, without the preload scan and the address-space limit |
| `big-endian` | ubuntu-latest | s390x cross-compiled, run under QEMU user mode: the unit tests, and files made there and on x86-64 open on the other |
| `interop` | all seven builds | section 6 |
| `constant-time` (workflow) | on changes, nightly, by hand | `valgrind` on x86-64 and arm64, g++ and clang++, `-O0`, `-O2`, `-O3`; `timing` on Linux, Linux arm64, macOS and Windows at scale 10 |
| `unicode` (workflow) | on changes to the tables and what they depend on | downloads the data from unicode.org, checks it against stored SHA-256 sums; a separate workflow so that an outage of unicode.org cannot turn `build` red |
| `release` (workflow) | on a version tag; by hand it is a dry run | five targets, each with the whole suite; see the make-release skill |

## 2. Rules for writing a test

These come from defects that cost a runner cycle each.

- **A skip is never silent.** A part that cannot run prints `skipped: <why>`; CI runs with `-V` so the
  line is in the log. A test must also fail loudly when its precondition is missing, not pass.
- **Every detector has a control.** A scanner or a harness is shown something it must find before its
  silence is believed: the residue scanner finds a mark that is there (a shell that holds it, a plain
  copy on the heap, one in the dead stack), `ct_valgrind` must catch a deliberate leak, `ct_timing` an
  early-exit compare, the terminal harness must get the usage text back, the table hash must fail on a
  changed composition pair.
- **Test sources are ASCII.** Non-ASCII text is built from code points (`utf8({...})`, `B({...})`), and a
  test checks that `src`, `tools`, `test`, `cmake` and the build files are ASCII with LF line endings,
  so that every compiler and every checkout sees the same bytes (labels in them are hashed into keys).
- **Bytes come from C++, not from CMake.** `file(WRITE)` is text mode on Windows (`\n` becomes CR LF),
  so byte-exact inputs (a phrase with a BOM and CR LF, CR, LF, 0x1A and NUL in data) are written by
  `test_e2e.cpp` or are committed fixtures. `.gitattributes` keeps fixtures and `*.sdes` untouched.
- **Take expected values from an independent source** (Python's `unicodedata`, a separate armor
  implementation, the RFCs), never from the code under test. A convenient "fix" such as stripping a
  trailing CR is a format change: settle everything that touches the bytes of a phrase before a release.
- **Tamper by XOR**, so that the byte always changes; a test that writes a constant sometimes writes
  what is already there.
- **Timing tests read one shared buffer.** Both classes must see the same memory layout: two arrays
  differ in alignment and aliasing, and that alone gave |t| = 16 (Windows, `ct_equal`) and |t| = 17
  (arm64, `unseal`). Prepare the class's input untimed, in one buffer, and time only the call.
- **Do not hard-code what the compiler decides.** The `scrub_stack` test depends on the frame layout:
  it allows 16 bytes on POSIX (the alignment padding of the live frame) and 80 on Windows (the 32 bytes
  of home space of the callees live in that frame). Any change to `scrub_stack` or the frames above it
  must be followed by that test, and by the residue test several times (section 3).
- **Pin every downloaded input by hash**, and keep unversioned inputs (the Unicode licence text, whose
  URL changes with the year) in the repository. `writefile` makes fixtures with mode 0600: set 0644
  before committing them.
- **Sanitizers turn `mlock` into a no-op and reserve address space**, so the locking tests, the stack
  layout test, the address-space limit and the preload scan are skipped under them.
- **Give a new experiment a timeout and diagnostics on stderr.** A hung test holds a runner until the job
  timeout, and ctest loses what the test had on stdout when it kills it: use `ctest --timeout 240` while
  the experiment is new, and `fprintf(stderr, ...)`. Remove both when it works.
- **Compiler-specific flags must not leak.** Apple clang reports Linux-only flags as unused arguments,
  which `-Werror` makes errors; MSVC `/W4` finds conversions gcc and clang do not
  (`/wd4456` is set for the test targets only, where blocks reuse names on purpose);
  `PT_ATTACH` is deprecated (`-Werror`) and `strtol` is 32-bit on Windows. See STRUCTURE.md section 11.
- **A CMake custom command that carries a list needs `VERBATIM`**, or the shell cuts it at the semicolons.

## 3. The memory residue scan

Question: after the program has ended, does a key, the phrase or the plaintext survive anywhere in its
memory? [residue_core.cpp](test/residue_core.cpp) searches every writable region of the process at the
moment it exits: `/proc/self/maps` on Linux, `VirtualQuery` on Windows (committed private memory, not
mapped files or guard pages), `mach_vm_region` on macOS. The marks (key text, key bytes, the phrase of
5000 characters, for a non-ASCII phrase also its 32-bit code points, the plaintext) are XOR-masked in the
environment and parsed at start-up in a static initialiser, so the scan does not disturb the dead stack.
It is run after encryption, after decryption and after a failed authentication.

Two ways in, sharing the same core:

- the **scan binary** `sillydes_scan` (every system): the program's sources built with
  `SILLYDES_RESIDUE_SCAN`, whose `exit_process` calls `residue_scan_at_exit()` first, so the search runs
  exactly where the program would end, after `scrub_stack`. That `#ifdef` is the only test hook in the
  program, one per platform file, and it is absent from the real binary;
- the **preloaded library** `residue_scan.so` (Linux): `LD_PRELOAD` into the real binary, hooking only
  `_exit` and a constructor. Linux runs both, which ties the new scanner to the old one.

Controls (the test fails unless they are found): the preload scanner is shown a shell that holds the mark;
the scan binary keeps a plain copy of the mark on the heap (`SCAN_CONTROL=heap`) and in the frame of the
scan function in the dead stack (`SCAN_CONTROL=stack`; the pointer is `volatile` so it is not optimised
away).

**The scanner runs on the very stack it inspects.** It moves its own frames 96 KiB down (`alloca`),
ignores hits inside its own zone (shown separately), and snapshots a hit before printing, or it reports
its own data as residue. Check any scanner against an injected leak (a 400-byte and a 30 KB stack array:
found without the scrub, gone with it) before believing green or red.

Findings that shaped the program:

- **Vector registers keep plaintext, and code that runs after the wipe can save them on the stack.** CI
  found a whole decrypted 512-byte buffer on the stack after a key file decryption, only with clang and
  only on runners whose CPU has AVX-512 (about two of three clang runs; never elsewhere).
  `GLIBC_TUNABLES=glibc.cpu.hwcaps=-AVX512F,...` and `LD_BIND_NOW=1` made it go away. The reading that fits:
  glibc's EVEX `memmove` copies through `zmm16` and up, `vzeroupper` does not clear those, and at exit a
  lazily bound symbol of a system library (libstdc++ is not linked with `-z now`) ran the dynamic
  linker's resolver, which saves all vector registers on the stack, after `scrub_stack` had cleaned the
  zone. Why gcc did not show it was not established. Fix: `exit_process` is `_exit`, straight after
  the scrub, so no exit-time code runs. The same holds on every system: whatever runs after the scrub
  (a signal handler, a loader) may spill registers; end the process directly, and expect NEON and AVX
  to hold secrets in the same way.
- A scan can only show this on a CPU with the wide registers. The runner pool mixes machines (AMD EPYC
  7763, 9V74, 9V45; Intel Xeon 8370C, 8573C, 6975P-C all appeared), so read the CPU model in the log and
  **rerun the job several times** after any change near `scrub_stack`, `exit_process`, the allocators or
  the vector-heavy code.
- The first alarm of this kind turned out to be the harness: failures that alternate on one commit mean
  the harness first (here the test read two numbers from the scanner's output, and the scanner printed
  its own data). A stack window is needed on every system (Windows: `_alloca` and `SecureZeroMemory`).
- On the runners no key, phrase or plaintext remained on any system: Windows (MSVC, MinGW, arm64) and
  macOS (arm64, Intel) as on Linux.

## 4. The terminal, PowerShell and cmd tests

`run_on_terminal` in [test_os.h](test/test_os.h) runs the program with a terminal for standard input and
output, as a person would: a pseudo-terminal on POSIX (`posix_openpt`, `setsid` plus `TIOCSCTTY`, typing
only once the echo is off), ConPTY on Windows (`CreatePseudoConsole`, looked up at run time). `test_e2e`
types the non-ASCII phrase of the fixtures (Latin, Greek, Japanese and U+1D11E, a surrogate pair) twice
for an encryption and checks the exit code, that nothing is echoed, that the file opens with the same
phrase piped and the other way round, that a short phrase and a repetition that differs are asked again,
and that Ctrl+D (POSIX) or Ctrl+Z and Enter (Windows) is error 10 and leaves no output file. It also
checks the harness: the program's usage text must come back.

ConPTY pitfalls: start the child with `STARTF_USESTDHANDLES` and three `INVALID_HANDLE_VALUE`, or it keeps
the runner's redirected handles and sees no console (stdin reads nothing, exit code 10); answer the
console's cursor position query (`ESC [ 6 n`, with `ESC [ 1;1 R`); match prompts on one word, since the
console renders spaces its own way.

What the Windows shells hand over (asserted only where the README promises it):

- Windows PowerShell 5.1 pipes ASCII, so every other character is `?` and the keys are those of another
  phrase, with no error. With `$OutputEncoding = New-Object System.Text.UTF8Encoding $false` it is right
  (asserted); PowerShell 7 is right by default (asserted).
- `>` in 5.1 writes a key file as UTF-16 with a byte order mark; the program reads it (asserted, also for
  PowerShell 7, which writes UTF-8).
- `cmd.exe` pipes in the code page of the console. With `chcp 65001` the keys are right; after
  `chcp 437` the program refuses the phrase with error 10, so there is an error and no wrong key.
  `cmd` scripts need backslash paths (`/` starts an option).
- mintty without ConPTY presents standard input as a pipe: the phrase is echoed and not confirmed.
  Not testable on a runner.

## 5. Constant-time verification

What is checked and how is in the table in section 1; the design is in STRUCTURE.md section 12 and the
results in ANALYSIS.md section 8. Things to know:

- Valgrind marks the return value of the program as undefined if it is derived from a secret (the
  control); results are declassified before use. Out of scope by design: Argon2id (data-dependent
  addressing), the phrase normalisation, and `unseal` as a whole (its tag branch and `unpad256` depend on
  public outcomes), so its pieces are run instead.
- The branch report cannot tell a loop over a public length from a branch on a secret, so only
  `hex_digit` is enforced. Read the report when a compiler changes.
- The timing test passes if |t| < 10 in any of 3 rounds (noise passes in some round; a leak does not),
  after dropping the slowest 5 %. At scale 10 all |t| were below 4 on Linux, Linux arm64, macOS and
  Windows.
- Valgrind does not run on current macOS, and Windows has only the timing test. BlaMka's 32x32 to 64
  multiply is covered only by the timing test, which does not exercise Argon2id. MSVC AddressSanitizer
  was tried and dropped: the link fails on a missing `clang_rt.asan_*_runtime_thunk` library on the
  `windows-latest` image.

## 6. Interop between systems

`test_e2e <binary> <source root> --interop-make <dir> <label>` writes files with this build;
`--interop-check <dir> <label>,<label>,...` opens every file in `<dir>` and compares it with the text it
was made from, failing on a file that does not open, a name it does not know and a missing file. The
`build` workflow runs the first in each build job and uploads the files and the binaries, then runs the
second in one job per system (seven builds: Linux x86-64 and arm64, macOS arm64 and Intel, Windows MSVC,
MinGW and arm64), so all 7 x 7 combinations are opened.

Cases: binary and armored, each with the key file `sample.key` (a Windows checkout turns it into CR LF:
also a test), an ASCII phrase and the non-ASCII phrase, and armored with the same text typed another way
(BOM, decomposed accents, no-break space, full-width and half-width forms; it must open with the NFC
form). The text has all 256 byte values and all three line endings. Windows adds a key file written by
Windows PowerShell 5.1 with `>`, the phrase piped by Windows PowerShell 5.1 (UTF-8 `$OutputEncoding`), a key
file written by PowerShell 7, the phrase piped by PowerShell 7 and by `cmd.exe` after `chcp 65001`.
The MinGW files are made in a `pwsh` step: the MSYS2 shell has no PowerShell 7 in its search path.

Big endian: the s390x job runs the unit tests (all known answers, the table hash, the normaliser) and
opens files made on s390x on x86-64 and the other way round; `test_e2e` is not run there, because QEMU
does not limit the address space of a child and the preload scan expects a native process. It can be
reproduced on a Linux machine with `g++-s390x-linux-gnu` and `qemu-user` (`QEMU_LD_PREFIX=/usr/s390x-linux-gnu`).
An arm64 build can be run the same way (`g++-aarch64-linux-gnu`); everything except the residue scan passes.

## 7. Reading and using the runner results

Non-Linux code can only be run on GitHub's runners (no cross-compiler, Wine or osxcross is used as a test,
here or in CI: only real systems count). The loop is described in the runner-driven-development skill
([.github/skills/runner-driven-development/SKILL.md](.github/skills/runner-driven-development/SKILL.md)).
Facts about the runners:

- A runner is a server image, not a user's machine: small default `mlock` and working-set limits, no
  desktop session, security software that may slow the 2 GiB test.
- The CPU differs between runs of one job (section 3), so a pass proves little for CPU-dependent code.
  Compare variants inside one job.
- `gh run rerun` and then `gh api repos/avw1ein/sillydes/actions/runs/<id>/attempts/N --jq .conclusion`
  for each attempt: `gh run view` shows a stale attempt right after a rerun.
- Runner labels (`windows-latest`, `macos-latest`) float to newer images; Linux release builds are pinned
  to `ubuntu-22.04` on purpose (glibc floor). The Windows and macOS labels should be pinned and updated
  on purpose.
- Public repositories have free runners; the whole matrix takes about ten minutes, the macOS Intel runner
  being the slowest.
- Measured on the runners: `available_memory()` 13 to 14 GiB (Windows, Linux arm64), 3.0 GiB (macOS arm64),
  9.7 GiB (macOS Intel). The key derivation (2 GiB, t = 1, p = 4) takes 2.1 s on Linux arm64, 2.4 s on Linux
  x86-64 and macOS arm64, 3.0 s on MinGW, 3.2 s on MSVC, 4.8 s on Windows arm64 and 6.2 s on macOS Intel
  (a three-core virtual machine); the interop step logs it for every system.

## 8. What the tests cannot show

Named in the release notes when it ships; none of it can be shown on a runner:

- that the Windows Error Reporting exclusion keeps a block out of a crash dump (no call reads the
  registrations back);
- that `PT_DENY_ATTACH` stops a debugger: an experiment attached to a hardened child and to an ordinary one,
  and the ordinary one was refused too (a debugger of the same user gets in nowhere on a runner), so it
  proved nothing and the attach to the hardened one did not return an answer; it was removed;
- that `VirtualLock` of the 2 GiB arena succeeds on a small machine (it fails silently, like `mlock`);
- error 7 on macOS: `setrlimit` of `RLIMIT_AS` and `RLIMIT_DATA` fails with `EINVAL` for a limit below the
  address space already mapped, so no child can be limited (the program reads both limits and would
  refuse). Windows tests it with a job object; Linux with `RLIMIT_AS`. QEMU does not enforce it;
- the macOS free-memory estimate (free, inactive and purgeable pages) on a loaded Mac;
- real older Windows 10 builds, a user's terminal emulator, mintty, real PowerShell profiles, macOS
  Gatekeeper and notarization on a user's machine;
- the data-independent timing mode (DIT) on Windows arm64, which is not set (no feature bit that
  `IsProcessorFeaturePresent` reports).
