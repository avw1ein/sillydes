# SillyDES 5.2.0

Copyright (C) by Andy van Wezel, 1993 - 1994, 2026.
Released under the MIT License (see [LICENSE](LICENSE)).

## Contents

- [Introduction](#introduction)
- [History](#history)
- [Ethics](#ethics)

1. [Quick start](#1-quick-start)
2. [Why use SillyDES?](#2-why-use-sillydes)
3. [How does it work?](#3-how-does-it-work)
4. [The encryption scheme](#4-the-encryption-scheme)
5. [How to use SillyDES with e-mail software](#5-how-to-use-sillydes-with-e-mail-software)
6. [How to use SillyDES normal style](#6-how-to-use-sillydes-normal-style)
7. [Keys](#7-keys)
8. [Intramural security](#8-intramural-security)
9. [Error levels](#9-error-levels)
10. [Disclaimer](#10-disclaimer)

What changed in each release is in [CHANGELOG.md](CHANGELOG.md). See also [VISUALIZATION.md](VISUALIZATION.md) for diagrams of one block going through the cipher, [ANALYSIS.md](ANALYSIS.md) for the security reasoning, [STRUCTURE.md](STRUCTURE.md) for the code layout, [TESTING.md](TESTING.md) for the tests and the CI, and [SECURITY.md](SECURITY.md) for the threat model and how to report a problem. The analysis in ANALYSIS.md was written by Claude Fable 5.1 (Anthropic), working from the source code; it is not an independent human review.

---

## Introduction

**THIS IS A HOBBY PROJECT**

SillyDES gives you a way to protect your data, whether you keep it at home or send it throughout the world. The program provides two sorts of output, High-ASCII and Low-ASCII. You can use the first for security at home. The second one is aimed at e-mail. SillyDES was originally released as GPG, a DOS program (1993 - 1994).

It runs on Linux, macOS and Windows, on x86-64 and arm64, and a file made on one of them opens on all the others, with a key file or with a phrase typed in any language: the same phrase gives the same keys on every system. Section 1 shows how to get and build it on your system.

The program uses the Data Encryption Standard (DES). See section 2 for the reasoning behind this choice.

Every cryptographic algorithm in SillyDES is implemented in this repository from its published standard; the program links no cryptographic library. DES follows FIPS 46-3, SHA-512 FIPS 180-4, HMAC RFC 2104, BLAKE2b RFC 7693, Argon2id RFC 9106, and the CRC-32 is the IEEE 802.3 polynomial used by zlib. Each implementation is checked against the test vectors of its standard by the tests (`ctest`). The one piece of outside material is data: the Unicode tables behind the canonical form of a phrase (section 7), generated from the Unicode Character Database into a source file; the normalisation itself is implemented here too, from Unicode Standard Annex #15, and passes the complete conformance file of that standard. Only the composition of these pieces, the block expansion and the eight-layer DES construction described in section 4, is SillyDES's own.

Features:

- DES eight times over, with 2048-bit whitening between layers.
- A 2048-bit tweak per block, so every block is encrypted by its own instance of the cipher.
- HMAC-SHA-512 authentication (512-bit key and tag), checked before decryption.
- CRC-32 check on e-mail output.
- Key phrase (Argon2id, 2 GiB of memory, salted) or key file.
- One phrase gives the same keys on every system, however it was typed (Unicode NFKC).
- Constant-time DES: no key- or data-dependent memory access or branch during encryption.
- Linux, macOS and Windows (x86-64 and arm64), one file format: files made on one system open on every other.
- Self-contained: DES, SHA-512, HMAC, BLAKE2b, Argon2id and CRC-32 are implemented from their standards, with no external cryptographic library.
- Easy to use.
- Slow! Which is good!

---

## History

The first experiments with block expansion, the idea this project is built around, date from the early nineties, when the USA lifted the export embargo on DES and AES did not exist yet. I worked it out on my own at the time; related ideas have been explored by others before and since, and I make no claim to priority. Big Blue (IBM) placed an example implementation of DES into the public domain. I found it on Fidonet. My first program was called Lowkeyed. Lowkeyed used a homebrew DES3 variant based on block expansion. To transport ciphertext in e-mails, I added a translation to low-ASCII. Hence the name Lowkeyed. This translation was common in those days, since e-mail attachments only came later. Then came the General Privacy Guard, GPG. GPG used six layers of DES. I kept developing the project in my head, but didn't make updates for a long time. GPG is nowadays a synonym for GnuPG and not General Privacy Guard. So here comes Odette! Odette is an ode to Tchaikovsky's *Swan Lake*. At least, that's what I was thinking. The name Odette is already quite overloaded. So instead I settled on SillyDES!

---

## Ethics

Technology does not choose its users. Strong encryption protects people, and it can also shield people who do harm. That tension is why this section exists.

If the estimates in [ANALYSIS.md](ANALYSIS.md) hold, the key length puts SillyDES in the same range as AES-256; they are estimates from the author, not a review. Strength was the goal from the first version on, and for a long time I was not comfortable publishing a tool like this as a private person. With quantum computers on the horizon and encryption increasingly seen as a matter of human rights, I came to see it differently and decided to finish it and put it out.

---

## 1. Quick start

SillyDES has no dependencies. It needs only a C++11 compiler and CMake; it uses nothing beyond the C++ standard library and the system headers, which is why GitHub's dependency graph finds no manifest file. It is for 64-bit systems: Linux (x86-64, arm64), macOS (arm64, Intel) and Windows 10 or later (x86-64, arm64).

### Get the program

**Download.** The [releases](https://github.com/avw1ein/sillydes/releases) after 5.2.0 carry a binary for each system: `sillydes-X.Y.Z-linux-x86_64`, `-linux-arm64`, `-macos-universal`, `-windows-x86_64.exe` and `-windows-arm64.exe`, with `SHA256SUMS`, an SBOM and an attestation for each; release 5.2.0 itself is a Linux x86-64 binary only. The Windows binaries are not signed with a certificate and the macOS binary is signed ad hoc and not notarized, so SmartScreen and Gatekeeper may warn about a downloaded copy; [SECURITY.md](SECURITY.md) says how to check a download. The Linux binaries are static: they run on any 64-bit Linux, whatever its C library. Or build it yourself, which takes a minute.

**Build.** On every system the steps are the same three: configure, build, test (the tests need 2 GiB of free memory and take about a minute). The details differ:

*Linux*

```sh
# needs g++ or clang++ and cmake (3.21 or newer for the presets); use your distribution's packages
cmake --preset default
cmake --build --preset default
ctest --preset default
```

The program is `build/default/sillydes`. It uses the C and C++ libraries of your system; add `-DSILLYDES_STATIC=ON` to the first command to link them in (a static PIE that needs nothing from the system, which is how the released Linux binaries are made; it needs the static C and C++ libraries, which the compiler packages usually bring). Copy it to a directory in your `PATH`, or run it as `./build/default/sillydes`.

*macOS*

```sh
xcode-select --install          # Apple clang, once
brew install cmake              # or the installer from cmake.org
cmake --preset default          # for this Mac only
cmake --preset universal        # instead: one file for arm64 and Intel (macOS 11 or later)
cmake --build --preset default  # or: --preset universal
ctest --preset default
```

The program is `build/default/sillydes` (`build/universal/sillydes`). The build is signed with the hardened runtime, ad hoc, by the build itself. A copy you built is not quarantined; a downloaded one is, and Gatekeeper may refuse it until you remove the quarantine (`xattr -d com.apple.quarantine sillydes-...`) or build it yourself.

*Windows*

Install Visual Studio or the Build Tools for Visual Studio with the workload "Desktop development with C++" (it includes CMake), or MSYS2 with its UCRT64 gcc, cmake and ninja. In PowerShell or `cmd`:

```bat
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The program is `build\Release\sillydes.exe`. With MSYS2 (UCRT64 shell) use `cmake -S . -B build -G Ninja`, then `cmake --build build` and `ctest --test-dir build`; the program is `build/sillydes.exe`. Both are linked statically: no DLL needs to go with the program. The presets are for Unix-like shells; the commands above are what the project's tests on Windows run.

**Systems and tests.** Every push is built and tested on all of these systems by the [build workflow](.github/workflows/build.yml), on GitHub's own runners: the unit tests, the end-to-end tests with the real program (a phrase typed into a terminal included), a search of the exited process's memory for secrets, and a check that files made on every system open on every other. A runner is a server image, not your computer, so what depends on your setup (your terminal, your shell profile, a machine with less than 2 GiB free) is not covered. [TESTING.md](TESTING.md) says what is tested and what is not.

### First run

The examples in this file use a Unix shell (Linux, macOS). **On Windows** use PowerShell or `cmd`, and write `sillydes.exe` (or `.\sillydes.exe` in PowerShell) for `./sillydes` and `type` for `cat`:

```bat
sillydes.exe act=dm in=hello.sdes out=hello.txt key=sample.key
type hello.txt
```

A file name with spaces needs quotes, as for any program. Section 7 has what PowerShell 5.1 and `cmd` do to a phrase that is piped in.

For a quick e-mail-style demonstration:

```sh
./sillydes act=dm in=hello.sdes out=hello.txt key=sample.key
cat hello.txt
```

`hello.txt`, `hello.sdes` and `sample.key` are ASCII files.

For a quick demonstration in normal style, encrypt and decrypt a file:

```sh
./sillydes act=e in=myfile out=myfile.sdes key=sample.key
./sillydes act=d in=myfile.sdes out=myfile.out key=sample.key
```

To see how to make a key file:

```sh
cat sample.key
```

To get help:

```sh
./sillydes
```

The file format has its own version, which changes less often than the program's. A format is named after the release that introduced it: the current format is 5.2.0, and every later release reads and writes it until the format itself changes (the [changelog](CHANGELOG.md) says for each release whether it did). That is why an e-mail message starts with `*BEGIN SillyDES 5.2.0 message` whichever release made it.

Format 5.2.0 differs from 5.1.0 in one thing: the rules that turn a typed phrase into keys (section 7). They make a phrase give the same keys on every system, so that a file made on Linux opens on macOS and Windows and the other way round, and they are meant to stay as they are.

Files in older formats cannot be read, and releases before 5.2.0 cannot read this one. To keep a file of format 5.1.0, decrypt it with release 5.1.1 and encrypt it again; key files stay valid. Files made by the program under its former name, Odette, up to and including Odette 5.1.0, cannot be read either.

---

## 2. Why use SillyDES?

At this moment a single DES encryption can be cracked in a few hours (minutes?). You need a good computer to do it, but... The next step in line is triple DES (DES3). This is also within reach of modern computers. That's why some of us want something stronger than DES or triple DES, and SillyDES is one way to build it out of DES. In return you have to be more patient, because it is slower. The slowness is part of the design: an attacker who tries keys pays for every one of them. Modern CPUs accelerate AES for user and attacker alike; nothing accelerates SillyDES.

The eight keys feed eight DES layers and a 2048-bit whitening that is derived from every bit of every key. Without the whitening, a meet-in-the-middle attack on a cascade of eight ciphers would need about 2^224 operations. The whitening keeps both halves of such an attack from being tried alone, so the best known approach is to try all 2^512 key values. This is an estimate, not a proof, and the construction has not been reviewed by others. It also assumes random keys; how to get them is the subject of section 7.

Don't think single DES is bad just because it can be cracked. In the end every code can be cracked; it's just a matter of resources. DES has been studied for almost 50 years. Its security properties, including the shortcomings, are well known. This is the reason why DES can be used as a building block for something stronger. Instead of beginning from scratch, SillyDES can rely on all that is known about DES.

Is SillyDES an invention? It's more a matter of creativity. It mostly uses well-known techniques to reach its goal. You should see it as an interface to DES. The creativity is in the block expansion technique that makes multiple DES iterations worthwhile. The result is a block cipher that is wider and slower than DES. Both work in the defender's favour.

---

## 3. How does it work?

Encryption is done in independent steps. Besides the DES steps there are block expansion steps. The block expansion steps widen the block to 2048 bits and spread every input bit over the whole block. They are keyless, so they do not add key strength.

Total encryption is performed on 2048-bit blocks. Standard DES uses 64-bit blocks and has a key space of 2^56. SillyDES uses eight 64-bit keys, 2^512 values in all (see section 2).

Two more ingredients tie the DES steps together. Before each DES step, and once more after the last one, the whole 2048-bit block is XORed with a *whitening* value. The nine whitening values are fixed for one file: they are computed with HMAC-SHA-512 from all eight keys and the file's random salt. This means every bit of every key influences every step, including the eight parity bits per key that DES itself ignores, and two files encrypted with the same keys still use different whitening.

On top of that, every 2048-bit block gets its own *tweak*, again an HMAC-SHA-512 of the keys, the salt and the block number. The tweak is XORed into the block before the sixteen steps and into the result afterwards. So no two blocks, within one file or across files, are ever encrypted by the same permutation, which is what rules out the usual block-matching attacks on a large file. The blocks are also chained (CBC) and the whole output is protected by an HMAC-SHA-512 tag, so a changed file is rejected rather than decrypted to garbage.

On completion of encryption, the result can be translated into Low-ASCII (e-mail style) using the following characters:

```
0123456789:; ABCDEFGHIJKLMNOPQRSTUVWXYZ abcdefghijklmnopqrstuvwxyz
```

This makes the output file about 133% of the size of the input file. Very small files will grow more. Start and end lines are added, and also a newline (LF) after every 60th character.

---

## 4. The encryption scheme

Encryption is performed in sixteen steps.

Block expansion swaps the upper 4 bits of a byte in the first half block with the lower 4 bits of the corresponding byte in the second half block. Thus, to decrypt the first half block, you must include the second half block as well, and vice versa.

Although DES is supposed to have a multiplying property, SillyDES doesn't rely on it. Block expansion inputs new data in each 64-bit block before a new encryption is done.

```
Step  0: Rounding the file size up to a multiple of 256 bytes.
         The missing bytes are filled up with random information
         from the system random generator; the last byte holds
         the masked length. Every 256-byte block is then XORed
         with the previous ciphertext block (a random 256-byte
         IV for the first one) and with a 2048-bit tweak that is
         unique to that block, and goes through steps 1-16. The
         same tweak is XORed into the result. This is Cipher
         Block Chaining (CBC) around the whole cipher, with a
         different cipher instance for every block, so no two
         blocks are ever encrypted by the same permutation.
Step  1: Block expansion 2048 bits.
Step  2: Whitening 1, DES encryption with key1.
Step  3: Block expansion 128 bits.
Step  4: Whitening 2, DES encryption with key2.
Step  5: Block expansion 256 bits.
Step  6: Whitening 3, DES encryption with key3.
Step  7: Block expansion 512 bits.
Step  8: Whitening 4, DES encryption with key4.
Step  9: Block expansion 1024 bits.
Step 10: Whitening 5, DES encryption with key5.
Step 11: Block expansion 2048 bits.
Step 12: Whitening 6, DES encryption with key6.
Step 13: Block expansion 128 bits.
Step 14: Whitening 7, DES encryption with key7.
Step 15: Block expansion 256 bits.
Step 16: Whitening 8, DES encryption with key8, then a final
         whitening 9.
```

Each whitening is 2048 bits and is made from all eight keys and the salt with HMAC-SHA-512, so every bit of every key matters, including the bits that DES itself ignores, and two files made with the same key file share no whitening. The tweak of step 0 is made the same way from the keys, the salt and the block number. [VISUALIZATION.md](VISUALIZATION.md) draws these sixteen steps byte by byte.

The output consists of: a 4-byte header (S, D, 5, 16: the file format's major version, then minor times 16 plus patch), the phrase hashing parameters (4 bytes), the salt (16 bytes), the IV (256 bytes), the encrypted blocks, and a 64-byte HMAC-SHA-512 tag over all of it. The MAC key is 512 bits, taken from the same keys or phrase as the DES keys. Decryption checks the tag first and stops with error 13 if it does not match.

The salt and the IV come from the system random generator on every encryption; there is no option to choose or repeat them, and the program stops with error 14 if the generator fails. Encrypting the same file twice therefore gives two unrelated outputs. This is deliberate: it is what guarantees that no two blocks, in one file or across files, are ever encrypted by the same cipher instance.

---

## 5. How to use SillyDES with e-mail software

Encrypt whatever you like to transmit, using the `act=em` option. Copy the result into a message, and send the message. The recipient must export the message into a file, and decrypt that file using the `act=dm` option. SillyDES can search for the code in the file, since the code is encapsulated by identification lines.

SillyDES always writes the message with LF line endings, on every system. It reads it back however a mail program or an editor on another system saved it: with CR LF or CR line endings, with a byte order mark, as UTF-16 (with its byte order mark; this is what Windows PowerShell 5.1 writes with `>`), and with other text before and after it.

---

## 6. How to use SillyDES normal style

Encrypt using the `act=e` option, and decrypt using the `act=d` option. The output file now contains High-ASCII and should be treated as binary data. Your own data is never translated either: a text file with CR LF line endings decrypts to exactly that file on every system, Windows included (the program opens files as bytes there, not as text). File names are given to the system as they are, never normalised; a name may hold any character the system allows.

---

## 7. Keys

There are two sorts of keys: a key file with eight random keys, or a phrase from which the keys are derived. Everything that matters about choosing and handling them is in this section.

### Key file

```sh
key=sample.key
```

Examine the file `sample.key` to see how to construct a key file. It's an ASCII file with eight 64-bit keys in hexadecimal. Its lines may end in LF, CR LF or CR, and it may start with a byte order mark or be UTF-16 with one, as some editors and shells on other systems write it. Fill it with random values, for example from `/dev/urandom` (Linux, macOS) or a password manager; eight random keys give the cipher its full 512 bits. A key file written by Windows PowerShell 5.1 with `>` is UTF-16 with a byte order mark, which the program reads; so is one from PowerShell 7 (UTF-8) or a Windows editor.

**NEVER use `sample.key` for real data.** It is published together with this program, so anyone can decrypt what you encrypt with it. It is meant for the demonstration in section 1 only.

### Phrase

Put `phrase` on the command line instead of `key=`. The program prompts for a phrase of at least 20 characters; there is no upper limit. The keys are derived with Argon2id (RFC 9106), a slow function that needs 2 GiB of memory, and a random salt, so the same phrase gives different keys for every file and every guess costs an attacker that memory as well. If the machine cannot provide 2 GiB, the program stops with error 7 rather than running with less (section 9 says how each system decides that). Deriving the keys takes about 2 seconds on Linux and on a Mac with Apple silicon and 3 to 6 seconds on the other systems that have been measured (Windows, an Intel Mac); the same time passes again when a file is opened.

On a terminal the phrase is read with the echo off and, when encrypting, asked twice; from a pipe or a file it is read as it comes, and in a Windows console as Unicode text.

Before the keys are derived, the phrase is brought into one canonical form, so that the same phrase gives the same keys whatever system, keyboard, terminal or pipe it comes from:

- The line ending (LF or CR LF) and trailing spaces are not part of the phrase. Leading spaces are.
- The phrase must be valid UTF-8 and must not hold a control character, such as a tab or what an arrow key sends. Otherwise it is refused, for encryption and for decryption alike, before anything is derived: on a terminal the program asks again, otherwise it stops with error 10.
- Characters that can be entered in more than one way become one (Unicode normalisation form NFKC, Unicode 18.0.0): an accented letter typed as one character or as a letter followed by its accent, full-width and half-width forms, no-break and other spaces, ligatures.
- Invisible characters are removed: zero width spaces and joiners, soft hyphens, direction marks, variation selectors, a byte order mark.
- The 20 characters are counted after all this, as characters and not as bytes.

What stays different: upper and lower case, and characters that only look alike, such as straight and curly quotes, a hyphen and a dash, or a Latin and a Cyrillic letter. When a phrase is piped in, the pipe must carry UTF-8; a shell that converts the phrase to another character set before SillyDES sees it gives another phrase, and SillyDES cannot tell. A phrase of random printable ASCII characters avoids all of this.

Where a phrase is piped in, the pipe decides whether it arrives intact:

- **Linux and macOS:** a UTF-8 terminal and shell pipe UTF-8, which is what the program wants.
- **Windows PowerShell 5.1** (`powershell.exe`) pipes ASCII to a program by default, so every other character becomes a `?` and the program derives the keys of another phrase, with no error. Such a file does not open with the real phrase. Set `$OutputEncoding = New-Object System.Text.UTF8Encoding $false` first, or use PowerShell 7 (`pwsh`), which pipes UTF-8. Typing the phrase at the prompt avoids the problem, and so does a phrase of ASCII only.
- **Windows `cmd.exe`** pipes in the code page of the console: run `chcp 65001` first. Under another code page the bytes are not valid UTF-8 and the program refuses the phrase with error 10, so there is no wrong key, only an error.
- **Windows terminals:** the console is supported (tested through a pseudo-console, which Windows Terminal uses as well). A terminal that presents standard input as a plain pipe (for example mintty without a pseudo-console) shows the phrase as it is typed and does not ask twice; the keys are still right.
- In a Windows console, Ctrl+Z at the start of a line ends the input, as Ctrl+D does in a Unix terminal; either gives error 10 when no phrase was typed.

Characters assigned in Unicode after version 18.0.0 are not folded, and the folding stays as it is for the whole of format 5.2.0.

**The phrase is the weak point of the system, because a person chooses it.** The cipher cannot be stronger than the phrase, and a phrase a person can remember follows the patterns of a language, which is exactly what a guessing program tries first: ordinary text carries only 1 to 1.5 bits per character, so a 20-character sentence is worth 20 to 30 bits and even a long one stays far below the cipher. Typing errors, reuse of a phrase from elsewhere, and writing it down where it can be found are the other usual ways a phrase fails, and no cipher fixes them.

**So: let a password manager generate a random string, store it there, and use that as the phrase.** The 20-character minimum is sized for such random input. How long the string must be depends on the characters it draws from:

| Target | Printable ASCII (95 characters) | Letters and digits (62) | Hexadecimal (16) | Diceware words (7776) |
|---|---|---|---|---|
| 128 bits | 20 | 22 | 32 | 10 |
| 256 bits | 39 | 43 | 64 | 20 |
| 512 bits (the cipher's ceiling) | 78 | 86 | 128 | 40 |

Against a quantum computer the effective strength of a phrase halves (Grover's algorithm): for 128 bits of post-quantum security take the 256-bit row, for the cipher's full post-quantum level the 512-bit row. Details are in [ANALYSIS.md](ANALYSIS.md), section 8. If you must rely on memory alone, use a long sentence that exists nowhere else, and treat it as the weaker option it is.

### Handling

- Don't send keys or phrases through insecure channels.
- Don't use the same key or phrase for everything.
- Don't write your keys on your keyboard, and don't pipe a phrase in from a shell command line that ends up in your history.
- Don't share your keys with others, unless they need them.

---

## 8. Intramural security

This kind of security is not trivial because, for example, original files won't be destroyed. If you work on a computer connected to a LAN or WAN, it's also possible for someone else to peek at your computer. SillyDES keeps your data in a single buffer that is encrypted or decrypted in place and wiped after writing, and erases keys and the phrase from memory when it is done with them, also when it stops with an error. It reads the phrase and the key file without stdio, so no library buffer keeps a copy. It asks the system to keep the keys, the phrase and the working variables of the cipher in RAM, and the 2 GiB of the phrase derivation as well when the system allows it. Your data is not locked, because it can be as large as the file, and without enough locked memory the system can still swap any of this to disk; encrypted swap is the remedy, and hibernation (suspend to disk) writes all of RAM to disk whatever a program locked, so do not hibernate while you work with secrets, or encrypt the disk. The DES layers are bitsliced, so their running time and memory access pattern do not depend on the key or the data; the Argon2id phrase derivation reads memory at data-dependent addresses after its first half pass, see the remark in [ANALYSIS.md](ANALYSIS.md), section 8.

What the program does about crash dumps and other processes differs per system. All of it is best effort: a failing call is ignored and the program carries on, and none of it is a boundary against an administrator or root, who can read any process.

| | Linux | macOS | Windows |
|---|---|---|---|
| Core and crash dumps | `RLIMIT_CORE` is 0; the process is marked non-dumpable; blocks of 64 KiB and more are excluded from dumps | `RLIMIT_CORE` is 0 | the error dialog of a crash is switched off; the 2 GiB table, the locked pages and the stack window are registered with Windows Error Reporting as excluded from dumps (not verified: no call reads that back) |
| A debugger of the same user | refused (non-dumpable) | refused (`PT_DENY_ATTACH`; not verified, see below), and the build is signed with the hardened runtime and without `get-task-allow` | refused: the access list of the process gives its owner only the right to query, wait for and end it, none to read or write its memory; an administrator, and any process that has the debug privilege enabled, still gets in |
| Code from outside | - | the hardened runtime refuses injected libraries and code that is not signed in | the process allows no code generated at run time, no extension points (hooks, AppInit DLLs), no images from network shares and no child process |
| Keys and phrase kept in RAM | `mlock`, as far as `RLIMIT_MEMLOCK` (`ulimit -l`) allows | `mlock`, as far as the system allows | `VirtualLock`, after raising the working set when needed |
| Files written | mode 0600 for a new file; a symbolic link as output is refused | the same | a new file inherits the access list of its folder; a link as output is refused |

The tests read the access list and the mitigation policies back from the running Windows process, and the limits and the hardened-runtime signature on Linux and macOS. That a debugger cannot attach on macOS is not verified: the test machines refuse every debugger, so there is nothing to compare with. Security software may slow the 2 GiB derivation. Nothing here protects against malware that runs as you.

---

## 9. Error levels

The program can generate fourteen error levels. You can use these in a shell script or in a parent program.

| Level | Meaning |
|------:|---------|
| 0 | Normal program termination. |
| 1 | Unable to read from a certain file. |
| 2 | Unable to write to a certain file. |
| 3 | Wrong number of parameters. |
| 4 | Wrong option. |
| 5 | Faulty key file. |
| 6 | Input file and output file must differ. |
| 7 | Not enough memory; phrase mode needs 2 GiB free (see below). |
| 8 | Can't find beginning of code. |
| 9 | Duplicate argument on command line. |
| 10 | Argument missing on command line, or no usable phrase (too short, not valid UTF-8, or with a control character; also when the input ends before a phrase was typed). |
| 11 | Can't find end of code. |
| 12 | CRC error, e-mail style only. |
| 13 | Authentication failed: wrong key, or data damaged or altered. |
| 14 | System random generator failed. |

**Level 7** is decided before the memory is taken, from what is free and from the limits set on the process: on Linux the `MemAvailable` of the kernel and the `ulimit -v` and `-d` limits; on Windows the smaller of the free physical memory, the free commit limit and the memory limit of a job object the program runs in; on macOS the free, inactive and purgeable pages, which is an estimate (a heavily loaded Mac may report too little although macOS would have swapped; then error 7 is a false alarm, and closing something helps). The program never runs with less and never lets the system kill it for lack of memory. Level 4 on Windows also covers an argument that is not valid UTF-16.

---

## 10. Disclaimer

SillyDES performs a DES8 encryption (works on 2048-bit blocks) on text files or executables. Intramural security is not trivial.

The Data Encryption Standard (DES) was issued by the U.S. National Bureau of Standards.

SillyDES is free of charge, and provided as is. Andy van Wezel makes no claims and offers no warranties of any sort with SillyDES. Andy van Wezel also assumes no responsibility for any sort of damage resulting from apparent or actual use of SillyDES. The user accepts all responsibility for the use and distribution of the program. In some countries there are laws concerning encryption.

SillyDES is released under the MIT License; see the [LICENSE](LICENSE) file for the full terms. You may use, copy, modify, merge, publish, distribute, sublicense and sell copies of it, provided the copyright and permission notice are kept in all copies or substantial portions of the software.

The tables in `src/unicode_tables.h`, which the program uses to bring a phrase into its canonical form, are derived from the Unicode Character Database and come under the Unicode License v3; see [LICENSE.Unicode](LICENSE.Unicode).
