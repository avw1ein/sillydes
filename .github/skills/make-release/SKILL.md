---
name: make-release
description: Publish a new SillyDES release. Use when asked to make, cut, publish or tag a release, bump the version, or "release X.Y.Z". Knows the two separate versions (program version vs file format version), the files each one touches, the pre-flight checks, the tag-triggered release workflow with SBOM and attestation, and how to recover from a failed run.
---

# Making a SillyDES release

A release is a **version tag** `vX.Y.Z` on `main`. Pushing the tag runs
[release.yml](../../workflows/release.yml), which builds and tests on five targets, generates a
CycloneDX SBOM for each binary, attests the build provenance and the SBOM of each, and creates the
GitHub Release with the five binaries (`sillydes-X.Y.Z-linux-x86_64`, `-linux-arm64`,
`-macos-universal`, `-windows-x86_64.exe`, `-windows-arm64.exe`), their `.cdx.json` files and
`SHA256SUMS`. Everything before the tag is yours to do and verify; the tag is the point of no return.

The same procedure is summarised for humans in `STRUCTURE.md`, section 10 ("Making a release").
If you change this procedure, change both.

## Two versions, never mix them up

[src/version.h](../../../src/version.h) holds both:

| | Program version | File format version |
|---|---|---|
| Constant | `PACKAGE_VERSION` | `FORMAT_NAME` (`"SillyDES 5.2.0"`) and `MAGIC` (`'S','D', major, minor*16+patch`) |
| Meaning | The release you are making | The on-disk container, the e-mail tags, the key/whitening/tweak/MAC labels, and the rules that turn a phrase into bytes (with their Unicode tables) |
| Changes | Every release | Only when files written by one release cannot be read by another |
| Named after | The release | The release that *introduced* the format; later releases keep that name |
| Git tag | `vX.Y.Z` | none |

Facts that follow from this:

- A **patch release never changes the format** (for minor and major ones it is the user's decision).
  The default for "do not update the file format" is: edit `PACKAGE_VERSION` only, and leave
  `FORMAT_NAME`, `MAGIC`, `hello.sdes`, `test/format-*` and every test expectation alone.
- Example: program 5.1.1 read and wrote format **5.1.0**, so its e-mail messages started with
  `*BEGIN SillyDES 5.1.0 message`; a later 5.2.1 still writes `*BEGIN SillyDES 5.2.0 message`.
  That is correct, not a stale string.
- If `test_e2e` fails on the format fixtures during a release that was not meant to change the format,
  the format *was* changed by accident. Stop and tell the user; do not regenerate fixtures to make
  the test pass.
- `FORMAT_NAME` is hashed into the keys. Changing it makes every existing file unreadable.
- The canonical form of a phrase (`canonical_phrase` in `src/text.cpp`) and the Unicode tables in
  `src/unicode_tables.h` decide which keys a phrase gives, so they belong to the format. Never run
  the target `regenerate_unicode` (it regenerates the tables) in a release that keeps the format; `test_primitives`
  fails on changed tables, and that failure means the same as a failing fixture.
- `MAGIC[3]` is `minor*16+patch`, so minor and patch of a format number must each be 0-15.
- A format change can be prepared ahead of its release. Compare `FORMAT_NAME` in the tree with the
  last release (`git show vPREV:src/version.h`): if they differ, the release you are making
  introduces that format. Its version must then equal the format's number, the work of the appendix
  is already done (check it: fixtures in `test/format-N/`, no stale `SillyDES OLD`, `ctest --preset ci`), and
  what is left is section 3, with release notes that start by saying the format is new and which
  release converts older files. Format 5.2.0 was prepared this way, before release 5.2.0.

## 1. Find out what you need (ask what is missing)

Determine these before touching anything. Take them from the request; ask the user (use the
`ask_user` tool if you have it) only for what is still open.

1. **New program version `X.Y.Z`.** Must be higher than the current `PACKAGE_VERSION` and than the
   last tag (`git describe --tags --abbrev=0`; also `git ls-remote --tags origin`). The tag will be
   `vX.Y.Z` and must equal `v` + `PACKAGE_VERSION`: the workflow refuses a mismatch. If the user gives
   only "patch/minor/major", compute it and confirm it.
2. **Does the file format change?** Ask if not stated. "Do not update the file format" means no.
   A format change is a big step (it breaks all existing files): if it is yes, read the appendix
   first, and confirm the new format name with the user (normally the release version).
3. **Source.** "Latest on master" means the default branch, which is **`main`** here (check with
   `gh repo view --json defaultBranchRef --jq .defaultBranchRef.name`). Releases are made only from
   the tip of the default branch after `git fetch origin`; if the user names another branch or
   commit, ask.
4. **Release notes.** They live in `CHANGELOG.md` (step 3, item 4); the workflow publishes the
   section of the version as the GitHub Release text and stops if it is missing. Write the entry from
   `git log --oneline vPREV..HEAD`, grouped by what matters to a user (Security, Added, Changed,
   Fixed, Documentation), and show it to the user if they want to word it themselves. Every entry
   begins with a bold line saying whether the file format changed; for a format change it must say
   that files from earlier releases cannot be read.
5. **Go-ahead for the irreversible part** (step 5 below). If the request already says to publish,
   proceed after a one-paragraph summary; otherwise ask once, stating version, format decision and
   the commit SHA.

## 2. Pre-flight checks (stop and report on any failure)

```sh
git fetch origin --tags
git branch --show-current                      # main
git status --porcelain                         # empty: no uncommitted changes
git rev-parse HEAD origin/main                 # equal (fast-forward first if only behind)
git tag -l "vX.Y.Z"; git ls-remote --tags origin "vX.Y.Z"   # both empty: tag is new
gh run list --branch main --limit 1 --json headSha,conclusion --jq '.[0]'   # HEAD built green
```

- Untracked files that are not part of the release (for example a local plan) must not be added.
- If CI on `HEAD` is red, in progress or missing, do not release: look at
  `gh run view --log-failed`, fix or ask.
- Review what changed since the last release: `git log --oneline vPREV..HEAD` and
  `git diff --stat vPREV..HEAD -- src`. For a release that must not change the format, look
  specifically at `container.*`, `keys.*`, `kdf.*`, `sillydes_cipher.*`, `des.*`, `sha512.*`,
  `blake2b.*`, `armor.*`, `text.*`, `unicode_tables.h`, `version.h` and the constants in `common.h` (`SALT_LEN`, `IV_LEN`,
  `HDR_LEN`, `TAG_LEN`, `DEFAULT_KDF`). A change there that alters bytes on disk is a format change;
  refactors and memory hygiene are not. When in doubt, ask.

## 3. Prepare the release commit (no format change)

1. In `src/version.h` set `PACKAGE_VERSION "X.Y.Z"`. Nothing else in that file.
2. Update the **program version in the document titles** (line 1 of each):
   `README.md` (`# SillyDES X.Y.Z`), `STRUCTURE.md` (`# SillyDES X.Y.Z: software structure and flow`),
   `ANALYSIS.md` (`# Mathematical analysis of SillyDES X.Y.Z`) and `VISUALIZATION.md`
   (`# SillyDES X.Y.Z in pictures: ...`).
3. Leave every other `5.2.0` alone: those name the *format* (the labels `SillyDES 5.2.0 white/tweak/mac`
   in `ANALYSIS.md`, `STRUCTURE.md` and `VISUALIZATION.md`, the cipher names in the `ANALYSIS.md`
   tables, the README paragraph on the file format, `hello.sdes`, `test/format-5.2.0/`, and
   the strings in `test/test_e2e.cpp`). Check afterwards:
   ```sh
   grep -rn "SillyDES [0-9]\+\.[0-9]\+\.[0-9]\+" --include='*.md' --include='*.h' --include='*.cpp' --include='*.sh' . | grep -v '^./.git/'
   ```
   Every hit must be either one of the four new titles or a format reference.
4. Add the `## [X.Y.Z] - YYYY-MM-DD` section to `CHANGELOG.md` below `## [Unreleased]` (move anything
   that is listed under Unreleased into it) and update the compare links at the end of the file.
   Test the extraction the workflow uses:
   `awk -v v=X.Y.Z '/^## \[/ { on = (index($0, "## [" v "]") == 1); next } on { print }' CHANGELOG.md`
5. Nothing else carries the version: the usage banner and the SBOM read `PACKAGE_VERSION`.
6. Verify exactly as CI does, from a clean tree (the 2 GiB phrase tests need the memory):
   ```sh
   rm -rf build
   cmake --preset ci
   cmake --build --preset ci
   ctest --preset ci
   cmake --build --preset ci --target sbom
   ```
   `build/ci/sillydes` with no arguments must print the new version. Check the SBOM's
   `metadata.component.version` in `build/ci/sillydes.cdx.json`. The build directory is git-ignored;
   never commit anything from it.
7. Commit only the intended files with a message such as `Release X.Y.Z` (add the co-author trailer
   if the rules you work under require it). The commit must contain no unrelated changes.

## 4. Push the commit and wait for CI

```sh
git push origin main
id=$(gh run list --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
gh run watch "$id" --exit-status
```

CI runs on `ubuntu-latest`, which can differ from a developer machine (compiler, CPU, kernel limits).
If a failure does not reproduce locally, read `gh run view "$id" --log-failed` before assuming a program
bug: the residue test once failed on every other attempt because of its own harness, not the program.
When re-running to check for flakiness, read each attempt's own result with
`gh api repos/avw1ein/sillydes/actions/runs/$id/attempts/N --jq .conclusion`; `gh run view` shows a stale
attempt right after a rerun. Fix forward with a normal commit. Do not tag until the `build` workflow
(all of its jobs: Linux, macOS, Windows, the interop and big-endian jobs) is green on the release commit.
Then run the release workflow by hand on `main` as a dry run (`gh workflow run release.yml --ref main`,
then `gh run watch`): it does everything but attest and publish, and a failure on one of the five
targets (a new compiler warning on Ubuntu 22.04, a runner label that went away) is better found
before the tag. Its artifacts hold the five binaries and SBOMs for a look.

## 5. Tag and publish (the irreversible step: this is where the go-ahead is needed)

```sh
git tag -a vX.Y.Z -m "SillyDES X.Y.Z"
git push origin vX.Y.Z
gh run watch "$(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

The tag must point at the commit that passed CI. The workflow then: checks the tag against
`PACKAGE_VERSION` and the changelog (`prepare`); builds and tests on each target (`build`: the `ci`
preset with `-DSILLYDES_STATIC=ON` on Ubuntu 22.04 and its arm64 twin, the `universal` preset on macOS, the plain build on Windows
x64 and arm64), checks that the banner names the version, generates the SBOM with `tools/gen_sbom.sh`
and names the files after the release; attests the build provenance and the SBOM of each binary
(`attest`, one job per file, `actions/attest` without and with `sbom-path`); and, when all of that
succeeded, writes `SHA256SUMS` and runs `gh release create --verify-tag --notes-file` with the
changelog section and a note that Windows and macOS binaries are not signed (`publish`). The Linux
binaries are static PIEs (`file` must say `static`; `ldd` says `statically linked`; the workflow checks it), so
they need no library of the system, and they carry the glibc of the image that built them (Ubuntu 22.04, kept
for its conservative toolchain; the kernel needs only the syscalls the program uses).

## 6. Verify the release

```sh
gh release view vX.Y.Z --json url,assets --jq '.url, (.assets[].name)'   # 11 assets: 5 binaries, 5 SBOMs, SHA256SUMS
d=$(mktemp -d) && gh release download vX.Y.Z --dir "$d" && (cd "$d" && sha256sum -c SHA256SUMS)
gh attestation verify "$d/sillydes-X.Y.Z-linux-x86_64" --repo avw1ein/sillydes                                              # build provenance
gh attestation verify "$d/sillydes-X.Y.Z-linux-x86_64" --repo avw1ein/sillydes --predicate-type https://cyclonedx.org/bom   # SBOM
chmod +x "$d/sillydes-X.Y.Z-linux-x86_64" && "$d/sillydes-X.Y.Z-linux-x86_64" | head -1   # banner shows X.Y.Z
```

Do the two attestation commands for each of the five binaries, or at least for one per system.
A release has two attestations for each binary. Without a predicate type `gh` checks the build
provenance; the SBOM attestation needs its type named. Releases 5.1.1 and 5.2.0 have the SBOM
attestation only, so for them the first command ends in `HTTP 404`, which says nothing about the
release. The provenance step has never run on a tag yet (a dry run skips it): if it fails in the first release
that has it, nothing is published yet (section 7). `gh attestation` needs gh 2.49 or newer; Ubuntu's own package
is older (the packages of cli.github.com are current).

Report to the user: the release URL, the commit SHA, the SHA-256 of each binary, and whether the format
changed. Clean up the temp directory.

## 7. When something goes wrong

- **Fails before the release is created** (the `publish` job creates it; `attest` may already have
  attested files of a release that never appears, which is harmless): nothing is published.
  If the cause is the commit (tests, version mismatch), delete the tag, fix and re-tag:
  `git push origin :refs/tags/vX.Y.Z && git tag -d vX.Y.Z`, then repeat from step 3/4.
  If the cause is infrastructure, re-run the failed jobs: `gh run rerun <id> --failed`.
- **Release already exists** (even a bad one): never move or reuse the tag; users may have the files.
  Delete the release and tag only if it was never announced and the user says so; otherwise publish
  the next patch version.
- **Wrong notes or title only:** fix `CHANGELOG.md` with a normal commit, then update the release text with
  `gh release edit vX.Y.Z --notes-file <section>`; no new tag.
- A tag whose name is not `v<number>.<number>.<number>` does not trigger the workflow (the old tag
  `v5.03` is such a tag; `v5.1.0` predates the workflow and was published by hand).

## Appendix: a release that changes the file format

Only on explicit instruction. It breaks every existing file, so treat it like a major event.
What counts: the cipher, padding, header layout, what the MAC covers, the meaning of the KDF
parameter bytes, the Argon2/KDF construction, the labels, the e-mail encoding, or which bytes a
phrase becomes (`canonical_phrase`, the Unicode tables).

Let `N` be the new format name's number (normally the release version, e.g. `5.2.0`).

1. `src/version.h`: set `PACKAGE_VERSION`, `FORMAT_NAME "SillyDES N"` and
   `MAGIC = { 'S', 'D', major, (minor << 4) | patch }` together (5.2.0 is `{ 'S','D', 5, 0x20 }`).
2. Build the **previous release's** binary to be able to read the old fixtures:
   `git worktree add /tmp/sillydes-old vPREV`, then build it the way that release is built: `make -C /tmp/sillydes-old` and the binary is `/tmp/sillydes-old/sillydes` for releases up to 5.2.0 (they have a Makefile), `(cd /tmp/sillydes-old && cmake --preset ci && cmake --build --preset ci)` and the binary is `/tmp/sillydes-old/build/ci/sillydes` for later ones. Remove the worktree after.
3. Regenerate the fixtures with the new build, from the same plaintext (`test_e2e` expects it to start with
   `Hello,`):
   ```sh
   P="The quick brown fox jumps over the lazy dog, again and again."
   S=build/ci/sillydes   # the new build
   OLD=/tmp/sillydes-old/sillydes   # or /tmp/sillydes-old/build/ci/sillydes, see above
   $OLD act=dm in=hello.sdes out=/tmp/hello.txt key=sample.key
   $S act=em in=/tmp/hello.txt out=hello.sdes key=sample.key
   mkdir test/format-N
   $S act=e  in=/tmp/hello.txt out=test/format-N/hello.bin key=sample.key
   echo "$P" | $S act=em in=/tmp/hello.txt out=test/format-N/hello-phrase.sdes phrase
   U_NFC=$(build/ci/test_e2e --nfc-phrase)   # the non-ASCII phrase of the tests
   printf '%s\n' "$U_NFC" | $S act=em in=/tmp/hello.txt out=test/format-N/hello-utf8-phrase.sdes phrase
   chmod 644 test/format-N/*
   git rm -r test/format-OLD
   ```
4. `test/test_e2e.cpp`: point the fixture paths (`golden_files`) at `test/format-N`, update the comment and the `ok:` text
   (they name the format), and change the "another version is rejected" step so that the magic byte
   and the substituted name are those of the previous format.
5. Only if the new format is to follow a newer Unicode version: set the version and the SHA-256
   sums of its data files in `tools/fetch_ucd.sh`, run it, configure with `-DSILLYDES_REGENERATE_UNICODE=<directory>` and build the target
   `regenerate_unicode`, which regenerates `src/unicode_tables.h` and checks it against the conformance file. The table
   hash in `test/test_primitives.cpp` then changes too (next item). Without this the tables stay
   as they are, which is fine: a format does not have to follow the newest Unicode.
6. `test/test_primitives.cpp`: the `encrypt_block known answer` is derived from the labels and changes
   with `FORMAT_NAME`. Run the test, take the new value from the failure message, and only accept it
   if the change is explained by the label (or by the intended cipher change); then regenerate and
   review the other stored values the failure list shows.
7. Docs: every `SillyDES OLD` becomes `SillyDES N` where it names the format: labels and tables in
   `ANALYSIS.md`, `STRUCTURE.md`, `VISUALIZATION.md`; the experiments table in `ANALYSIS.md`; the
   file-format paragraph in `README.md` section 1 (current format, `*BEGIN SillyDES N message`,
   "releases before N cannot read this one"); `STRUCTURE.md` (fixtures, test descriptions, section 10).
   If the cipher itself changed, `ANALYSIS.md` must be re-reviewed, not just renamed.
8. `grep -rn "SillyDES OLD" .` must find nothing except deliberate history.
9. Then follow sections 3 (items 2, 4, 6, 7), 4, 5 and 6. State in the release notes that files of earlier
   releases cannot be read and which release to use to convert them.
