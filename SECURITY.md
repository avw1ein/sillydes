# Security policy

## Reporting a problem

Open an issue at <https://github.com/avw1ein/sillydes/issues>, with `Security:` at the start of
the title. GitHub's private vulnerability reporting is not switched on for this repository, so
what you write is public: give what is needed to understand and reproduce the problem (the
system, the version, the command, a file that shows it), and leave out anything that is a real
secret. If a flaw would put people's files at risk before it is fixed, say only that you have a
report and what it concerns, and ask in the issue how to hand it over.

SillyDES is a one-person project with no independent review. Expect a reply, not a service level.

## What is supported

The latest release and `main`. Files of format 5.2.0 are what every release since 5.2.0 reads and
writes; a change of the format is announced in the [changelog](CHANGELOG.md) and breaks older files
on purpose, so a security fix that needs one will say so.

## What SillyDES is meant to protect

A file at rest, against someone who gets the encrypted file and has no key: 2048-bit blocks of
eight DES layers with a whitening and a per-block tweak, HMAC-SHA-512 over everything (checked
before anything is decrypted), and, in phrase mode, Argon2id with 2 GiB of memory and a random
salt. [ANALYSIS.md](ANALYSIS.md) gives the reasoning and the measurements. **The strength figures
are estimates. The construction has not been reviewed by others, and it is not a
standard.**

The strength rests on two things: HMAC-SHA-512 with a 512-bit key, which makes the whitening, the
tweak and the authentication key, and a tweak, salt and IV that are never used twice, so that every
block has its own instance of the cipher. The eight DES layers without them are weaker than AES-256
(ANALYSIS.md, section 6.2). The program draws the salt and the IV itself for every file and has no
option to fix them; code that reuses the cipher core without the tweak, or with a fixed salt or IV,
is outside what is described here.

 If you need a reviewed cipher, use AES-256-GCM or ChaCha20-Poly1305 from a reviewed
library.

## What it does not protect against

- **A weak phrase.** The phrase is chosen by a person and is the weak point; the cipher cannot be
  stronger than it. Use a random string from a password manager, or a key file with eight random
  keys (README, section 7).
- **Weak DES keys that you allowed.** The program refuses weak and semi-weak DES keys, and the other
  keys with at most four round keys, when encrypting. `allowweak` and `SILLYDES_ALLOW_WEAK=1` switch that
  off and are for research only: never use them for data you want to protect (README, section 7).
- **Someone who can run code as you, or as an administrator or root.** That person can read the
  process's memory, the file you typed the phrase into, the plaintext before and after. The
  measures against debuggers and dumps (README, section 8) are mitigations, not boundaries; on
  Windows an administrator, and any process with the debug privilege enabled, still gets in.
- **Swap and hibernation.** Keys and the phrase are locked in RAM as far as the system allows, but
  the 2 GiB table and your data usually cannot be, and a hibernation file holds all of RAM. Use
  encrypted swap or an encrypted disk, and do not hibernate while you work with secrets. Where the
  limit allows 2 GiB on Linux the table is a `memfd_secret` mapping, which is never swapped and
  blocks hibernation while it exists; `requirelock` on the command line, or `SILLYDES_REQUIRE_LOCK=1`, makes the program stop (error 15)
  when it cannot lock the table.
- **Timing and cache observation on a shared machine.** The DES layers, the MAC compare and the key
  file decoding are free of secret-dependent branches and addresses (checked with Valgrind, a
  disassembly report and a timing test; measured, not proved). Argon2id reads memory at
  data-dependent addresses in its second half, by design (RFC 9106), and the normalisation of a
  phrase outside ASCII is not constant-time either. A local observer on the same machine could use
  both to test phrase guesses offline. If other, untrusted code runs on the processor you encrypt
  on (a shared server, a virtual machine on shared hardware, a CI runner), encrypt with `argon2i`
  on the command line or `SILLYDES_ARGON2I=1` and an ASCII phrase: Argon2i addresses memory
  independently of the phrase. It takes about four times as long, and it is no defence against a
  host that can read the process's memory. Opening a file needs no option.
- **Look-alike phrases.** Different characters that look alike (straight and curly quotes, a Latin
  and a Cyrillic letter) give different keys, and a shell that changes the encoding of a phrase
  before the program sees it (Windows PowerShell 5.1 turns every non-ASCII character into `?`)
  gives keys of another phrase, with no error. A random ASCII phrase avoids both.
- **Deletion.** The original file stays where it is.

## What has not been verified

Named, because a test machine cannot show them (details in [TESTING.md](TESTING.md), section 8):

- that the Windows Error Reporting exclusion keeps a block out of a crash dump;
- that `PT_DENY_ATTACH` stops a debugger on macOS (the test machines refuse every debugger);
- that `VirtualLock` of the 2 GiB table succeeds on a small machine (it fails silently);
- the `memfd_secret` mapping of the 2 GiB table itself: the test machines have a lock limit far below 2 GiB, so only the fallback and a 2 MiB mapping are exercised there;
- error 7 on macOS under a memory limit, and the macOS free-memory estimate on a loaded Mac;
- real older Windows 10 builds, your own terminal emulator and PowerShell profile, Gatekeeper on a
  downloaded macOS binary;
- on Windows: that `/DEPENDENTLOADFLAG:0x800` keeps `bcrypt.dll` from being loaded from the program's folder (it is a
  linker flag of the MSVC build; a MinGW build has none, so keep the program in a folder only you can write), that the
  access lists with the OWNER RIGHTS entry hold against a process of the same user, that the console handler
  restores the echo after Ctrl+C, and the replacement of the output through a temporary file;
- that BTI is enforced on Linux arm64: the marker is in the file, whether the kernel maps it `PROT_BTI` is not observed;
- the data-independent timing mode on Windows on arm64: it is switched on by trying the instruction (Windows reports no
  feature bit) and the runner's CPU, which has it, shows the bit set; a Windows arm64 CPU without the feature has not been
  seen, where the program is meant to skip the mode silently.

## Verifying a download

Every release carries `SHA256SUMS`, a CycloneDX SBOM for each binary, and two attestations for each
binary made by the release workflow: its build provenance and its SBOM.

```sh
sha256sum -c SHA256SUMS
gh attestation verify sillydes-X.Y.Z-linux-x86_64 --repo avw1ein/sillydes
gh attestation verify sillydes-X.Y.Z-linux-x86_64 --repo avw1ein/sillydes --predicate-type https://cyclonedx.org/bom
```

The Windows binaries are not signed with a certificate and the macOS binary is not notarized, so
SmartScreen and Gatekeeper may warn about a downloaded copy; the checks above are what replaces
that. Releases up to 5.2.0 are Linux x86-64 only and have the SBOM attestation only.

## Supply chain

SillyDES links no library other than the C and C++ runtime of the system, and that is linked into every released binary (a static PIE on Linux, the static runtime on Windows; on macOS the system libraries `libSystem` and `libc++` are used, as Apple requires);
every algorithm is implemented in this repository from its published standard. The Unicode tables
are generated from the Unicode Character Database, whose data files are checked against stored
SHA-256 sums (`tools/fetch_ucd.sh`) and whose result is compared with the committed header in CI.
The GitHub actions the workflows use are pinned to commit hashes.
