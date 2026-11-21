---
name: make-release
description: Publish a new SillyDES release. Use when asked to make, cut, publish or tag a release, bump the version, or "release X.Y.Z". Knows the two separate versions (program version vs file format version), the files each one touches, the pre-flight checks, the tag-triggered release workflow with SBOM and attestation, and how to recover from a failed run.
---

# Making a SillyDES release

A release is a **version tag** `vX.Y.Z` on `main`. Pushing the tag runs
[release.yml](../../workflows/release.yml), which builds, tests, generates the CycloneDX SBOM,
attests it, and creates the GitHub Release with `sillydes-X.Y.Z-linux-x86_64`, its `.cdx.json` and
`SHA256SUMS`. Everything before the tag is yours to do and verify; the tag is the point of no return.

The same procedure is summarised for humans in `STRUCTURE.md`, section 10 ("Making a release").
If you change this procedure, change both.

## Two versions, never mix them up

[src/version.h](../../../src/version.h) holds both:

| | Program version | File format version |
|---|---|---|
| Constant | `PACKAGE_VERSION` | `FORMAT_NAME` (`"SillyDES 5.1.0"`) and `MAGIC` (`'S','D', major, minor*16+patch`) |
| Meaning | The release you are making | The on-disk container, the e-mail tags and the key/whitening/tweak/MAC labels |
| Changes | Every release | Only when files written by one release cannot be read by another |
| Named after | The release | The release that *introduced* the format; later releases keep that name |
| Git tag | `vX.Y.Z` | none |

Facts that follow from this:

- A **patch release never changes the format** (for minor and major ones it is the user's decision).
  The default for "do not update the file format" is: edit `PACKAGE_VERSION` only, and leave
  `FORMAT_NAME`, `MAGIC`, `hello.sdes`, `test/format-*` and every test expectation alone.
- Example: program 5.1.1 still reads and writes format **5.1.0**, so e-mail messages still start with
  `*BEGIN SillyDES 5.1.0 message`. That is correct, not a stale string.
- If `test.sh` fails on the format fixtures during a release that was not meant to change the format,
  the format *was* changed by accident. Stop and tell the user; do not regenerate fixtures to make
  the test pass.
- `FORMAT_NAME` is hashed into the keys. Changing it makes every existing file unreadable.
- `MAGIC[3]` is `minor*16+patch`, so minor and patch of a format number must each be 0-15.

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
  `blake2b.*`, `armor.*`, `version.h` and the constants in `common.h` (`SALT_LEN`, `IV_LEN`,
  `HDR_LEN`, `TAG_LEN`, `DEFAULT_KDF`). A change there that alters bytes on disk is a format change;
  refactors and memory hygiene are not. When in doubt, ask.

## 3. Prepare the release commit (no format change)

1. In `src/version.h` set `PACKAGE_VERSION "X.Y.Z"`. Nothing else in that file.
2. Update the **program version in the document titles** (line 1 of each):
   `README.md` (`# SillyDES X.Y.Z`), `STRUCTURE.md` (`# SillyDES X.Y.Z: software structure and flow`),
   `ANALYSIS.md` (`# Mathematical analysis of SillyDES X.Y.Z`) and `VISUALIZATION.md`
   (`# SillyDES X.Y.Z in pictures: ...`).
3. Leave every other `5.1.0` alone: those name the *format* (the labels `SillyDES 5.1.0 white/tweak/mac`
   in `ANALYSIS.md`, `STRUCTURE.md` and `VISUALIZATION.md`, the cipher names in the `ANALYSIS.md`
   tables, the README paragraph on the file format, `hello.sdes`, `test/format-5.1.0/`, and
   the strings in `test/test.sh`). Check afterwards:
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
   make clean
   make CXXFLAGS="-O2 -Wall -Wextra -Werror -std=c++11"
   make test CXXFLAGS="-O2 -Wall -Wextra -Werror -std=c++11"
   make sbom
   ```
   `./sillydes` with no arguments must print the new version. Check the SBOM's
   `metadata.component.version`. `sillydes.cdx.json` is generated and git-ignored; never commit it.
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
attempt right after a rerun. Fix forward with a normal commit. Do not tag until `build` is green on the
release commit.

## 5. Tag and publish (the irreversible step: this is where the go-ahead is needed)

```sh
git tag -a vX.Y.Z -m "SillyDES X.Y.Z"
git push origin vX.Y.Z
gh run watch "$(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
```

The tag must point at the commit that passed CI. The workflow then: checks tag against
`PACKAGE_VERSION`, builds with the CI flags, runs the tests, generates the SBOM, names the files
after the release, attests the SBOM to the binary (`actions/attest-sbom`), and runs
`gh release create --verify-tag --notes-file` with the changelog section.

## 6. Verify the release

```sh
gh release view vX.Y.Z --json url,assets --jq '.url, (.assets[].name)'   # 3 assets
d=$(mktemp -d) && gh release download vX.Y.Z --dir "$d" && (cd "$d" && sha256sum -c SHA256SUMS)
gh attestation verify "$d/sillydes-X.Y.Z-linux-x86_64" --repo avw1ein/sillydes
chmod +x "$d/sillydes-X.Y.Z-linux-x86_64" && "$d/sillydes-X.Y.Z-linux-x86_64" | head -1   # banner shows X.Y.Z
```

Report to the user: the release URL, the commit SHA, the binary's SHA-256, and whether the format
changed. Clean up the temp directory.

## 7. When something goes wrong

- **Fails before the release is created** (the last step creates it): nothing is published.
  If the cause is the commit (tests, version mismatch), delete the tag, fix and re-tag:
  `git push origin :refs/tags/vX.Y.Z && git tag -d vX.Y.Z`, then repeat from step 3/4.
  If the cause is infrastructure, re-run the failed job: `gh run rerun <id> --failed`.
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
parameter bytes, the Argon2/KDF construction, the labels, or the e-mail encoding.

Let `N` be the new format name's number (normally the release version, e.g. `5.2.0`).

1. `src/version.h`: set `PACKAGE_VERSION`, `FORMAT_NAME "SillyDES N"` and
   `MAGIC = { 'S', 'D', major, (minor << 4) | patch }` together (5.2.0 is `{ 'S','D', 5, 0x20 }`).
2. Build the **previous release's** binary to be able to read the old fixtures:
   `git worktree add /tmp/sillydes-old vPREV && make -C /tmp/sillydes-old` (remove the worktree after).
3. Regenerate the fixtures with the new build, from the same plaintext (`test.sh` expects it to start with
   `Hello,`):
   ```sh
   P="The quick brown fox jumps over the lazy dog, again and again."
   /tmp/sillydes-old/sillydes act=dm in=hello.sdes out=/tmp/hello.txt key=sample.key
   ./sillydes act=em in=/tmp/hello.txt out=hello.sdes key=sample.key
   mkdir test/format-N
   ./sillydes act=e  in=/tmp/hello.txt out=test/format-N/hello.bin key=sample.key
   echo "$P" | ./sillydes act=em in=/tmp/hello.txt out=test/format-N/hello-phrase.sdes phrase
   git rm -r test/format-OLD
   ```
4. `test/test.sh`: point the fixture steps at `test/format-N`, update the comment and the `ok:` text
   ("written by release N"), and change the "another version is rejected" step so that the
   substituted name differs from `N`.
5. `test/test_primitives.cpp`: the `encrypt_block known answer` is derived from the labels and changes
   with `FORMAT_NAME`. Run the test, take the new value from the failure message, and only accept it
   if the change is explained by the label (or by the intended cipher change); then regenerate and
   review the other stored values the failure list shows.
6. Docs: every `SillyDES OLD` becomes `SillyDES N` where it names the format: labels and tables in
   `ANALYSIS.md`, `STRUCTURE.md`, `VISUALIZATION.md`; the experiments table in `ANALYSIS.md`; the
   file-format paragraph in `README.md` section 1 (current format, `*BEGIN SillyDES N message`,
   "releases before N cannot read this one"); `STRUCTURE.md` (fixtures, test descriptions, section 10).
   If the cipher itself changed, `ANALYSIS.md` must be re-reviewed, not just renamed.
7. `grep -rn "SillyDES OLD" .` must find nothing except deliberate history.
8. Then follow sections 3 (items 2, 4, 6, 7), 4, 5 and 6. State in the release notes that files of earlier
   releases cannot be read and which release to use to convert them.
