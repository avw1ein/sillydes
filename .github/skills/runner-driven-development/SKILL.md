---
name: runner-driven-development
description: Develop and verify SillyDES changes that can only be tested on Windows, macOS or other CI runners, or that touch the platform layer, memory hygiene, process or build hardening, the residue scan, the phrase rules, the CI workflows or the CMake build. Use when editing src/platform_*.cpp, test/test_os_*.cpp, cmake/, CMakeLists.txt, .github/workflows/, or when a CI job fails on one system only. Gives the branch-push-read-log loop, the local checks that exist, how to handle flaky or CPU-dependent results, the changes that need extra care, and which documents to update.
---

# Working with CI runners

Windows and macOS (and arm64, s390x) code cannot be run on the usual development machine, and a
runner result is the only result that counts for it. There is no Wine, osxcross or cross-compiled run
used as a test, here or in CI. This skill is the loop that works. The knowledge behind it is in the
repository, not here:

- [TESTING.md](../../../TESTING.md): what is tested, the rules for writing a test, the residue scan, the
  runner facts, what cannot be verified;
- [STRUCTURE.md](../../../STRUCTURE.md) sections 11 and 12: the platform layer, per-system pitfalls,
  the memory and process hardening design;
- [SECURITY.md](../../../SECURITY.md): the threat model and the list of what is unverified.

Read the section that matches the file you are about to change before you change it.

## The loop

1. **Branch** `port/<topic>` (or `docs/<topic>`), one OS feature per push. Keep Windows and macOS code small and behind the platform layer,
   so that most of a change compiles here and only the thin OS calls are first compiled on a runner.
2. **Check locally what can be checked** (all optional tools; skip what is not installed):
   - `cmake --preset ci && cmake --build --preset ci && ctest --preset ci` (about a minute; needs 2 GiB free);
   - Windows files compile-only with MinGW: `x86_64-w64-mingw32-g++-posix -std=c++11 -O2 -Wall -Wextra -Werror -Isrc -Itest -c <file>`
     (it catches 32-bit `long` shifts and warnings; it never runs);
   - arm64 or s390x (big endian) under QEMU with `g++-aarch64-linux-gnu` or `g++-s390x-linux-gnu`
     and `QEMU_LD_PREFIX=/usr/<triple>`: configure with `-DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=<cpu>
     -DCMAKE_CXX_COMPILER=<triple>-g++`, run `test_primitives` and the interop files (TESTING.md section 6);
   - generators: `-DSILLYDES_REGENERATE_SBOX=ON` target `regenerate_sbox` must change nothing, and
     `tools/fetch_ucd.sh <dir>` with `-DSILLYDES_REGENERATE_UNICODE=<dir>` target `check_unicode` must pass.
3. **Push early** (`git push -u origin <branch>`) and let the runner log lead:
   ```sh
   id=$(gh run list --branch <branch> --workflow build.yml --limit 1 --json databaseId --jq '.[0].databaseId')
   gh run watch "$id" --exit-status          # in a long wait, use `timeout N` so the shell is not lost
   gh run view "$id" --json jobs --jq '.jobs[]|"\(.conclusion) \(.name) \(.databaseId)"'
   gh run view --job <jobid> --log | grep -i "FAIL\|error\|skipped:\|info:"
   gh run view --job <jobid> --log-failed
   ```
   A job's log is only available when the run has finished; `gh run cancel <id>` finishes it.
4. **Fix forward** with small commits. For something new and unproven, put `--timeout 240` on `ctest` and
   diagnostics on stderr, and remove both afterwards (a hung experiment holds a runner, and ctest drops
   stdout when it kills a test).
5. **Prove it is not luck.** Rerun the whole run two or three times (`gh run rerun <id>`) and read each
   attempt: `gh api repos/avw1ein/sillydes/actions/runs/<id>/attempts/N --jq .conclusion` (`gh run view`
   shows a stale attempt right after a rerun). When failures alternate on one commit, suspect the harness
   before the program. Results that depend on the CPU (the residue scan with AVX-512, timing tests) need
   several attempts, and the log should name the CPU.
6. **Document** (section below), commit, push, wait for the whole `build` workflow (and `unicode` or
   `constant-time` when their paths changed), then `git merge --ff-only`, push `main`, delete the branch,
   and check CI on `main`.
7. Commits carry `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>`.

## Changes that need extra care

- **`scrub_stack`, `exit_process`, the allocators, anything vector-heavy or run after the wipe:** run the
  residue test several times on the Linux runners (clang, AVX-512), and the `scrub_stack` unit test
  everywhere (TESTING.md sections 2 and 3).
- **The phrase rules, `canonical_phrase`, `src/unicode_tables.h`, `FORMAT_NAME`, `MAGIC`, the labels:**
  these are the file format. A change breaks every existing file; it needs the format-change appendix of the
  make-release skill and the owner's explicit decision. Never run `regenerate_unicode` or regenerate fixtures
  to make a test pass.
- **`platform_*.cpp`:** no OS header and no stdio outside the platform layer; every hardening call best
  effort and silent; check STRUCTURE.md section 11.3 for the pitfalls of the system you touch.
- **A new test:** follow TESTING.md section 2 (loud skip, a control, ASCII source, bytes from C++, XOR tamper,
  shared buffer in timing tests, an independent source for expected values).
- **Workflows:** actions are pinned to commit hashes; Linux release builds stay on `ubuntu-22.04`; the Windows
  and macOS labels float (pin them on purpose, not by accident); a release is tried with the workflow's dry
  run (`gh workflow run release.yml --ref <branch>`) before a tag.
- **A claim about a system you cannot run** (a debugger is refused, a dump excludes a block) is not a result.
  Add it to the unverified list in SECURITY.md and TESTING.md section 8 instead, or build the experiment
  with a control, as `PT_DENY_ATTACH` was tried and dropped when the control was refused too.

## Documents to update with a change

- README: sections 1 (build and run per system), 7 (phrase and key file per shell), 8 (the per-system table),
  9 (error 7 and the others) when behaviour a user sees changes.
- SECURITY.md: what is protected, what is not, what is unverified.
- STRUCTURE.md: sections 2, 11 and 12 when the platform layer or the hardening changes.
- TESTING.md: the test and job tables, new rules and findings.
- ANALYSIS.md: section 8 (per-system hygiene, resource check, measurements) and section 12 (experiments).
- CHANGELOG.md: under `[Unreleased]`; the release entry later begins with a bold line saying whether the
  file format changed.
- Memories: only durable facts (commands, conventions), and replace outdated ones.
