# SillyDES 5.1.0

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

See also [VISUALIZATION.md](VISUALIZATION.md) for diagrams of one block going through the cipher, [ANALYSIS.md](ANALYSIS.md) for the security reasoning and [STRUCTURE.md](STRUCTURE.md) for the code layout. The analysis in ANALYSIS.md was written by Claude Fable 5.1 (Anthropic), working from the source code; it is not an independent human review.

---

## Introduction

**THIS IS A HOBBY PROJECT**

SillyDES gives you a way to protect your data, whether you keep it at home or send it throughout the world. The program provides two sorts of output, High-ASCII and Low-ASCII. You can use the first for security at home. The second one is aimed at e-mail. SillyDES was originally released as Odette, a DOS program (1993 - 1994).

The program uses the Data Encryption Standard (DES). See section 2 for the reasoning behind this choice.

Features:

- DES eight times over, with 2048-bit whitening between layers.
- A 2048-bit tweak per block, so every block is encrypted by its own instance of the cipher.
- HMAC-SHA-512 authentication (512-bit key and tag), checked before decryption.
- CRC-32 check on e-mail output.
- Key phrase (Argon2id, 2 GiB of memory, salted) or key file.
- Constant-time DES: no key- or data-dependent memory access or branch during encryption.
- Easy to use.
- Slow! Which is good!

---

## History

The first experiments with block expansion, the idea this project is built around, date from the early nineties, when the USA lifted the export embargo on DES and AES did not exist yet. I worked it out on my own at the time; related ideas have been explored by others before and since, and I make no claim to priority. Big Blue, IBM, placed an example implementation of DES into the public domain. I found it on Fidonet. My first program was called Lowkeyed. Lowkeyed used a home-brew DES3 variant based on block expansion. To transport cipher text in e-mails, I added a translation to low-ASCII. Hence, low-keyed. This translation was common in those days, since e-mail attachments only came later. Then came the General Privacy Guard, GPG. GPG used 6 layers of DES. I kept developing the project inside my head, but didn't make updates for a long time. GPG is nowadays a synonym for GnuPG and not General Privacy Guard. So here comes SillyDES! Its first name, Odette, was an ode to Tchaikovsky's Swan Lake.

---

## Ethics

Technology does not choose its users. Strong encryption protects people, and it can also shield people who do harm. That tension is why this section exists.

If the estimates in [ANALYSIS.md](ANALYSIS.md) hold, the key length puts SillyDES in the same range as AES-256; they are estimates from the author, not a review. Strength was the goal from the first version on, and for a long time I was not comfortable publishing a tool like this as a private person. With quantum computers on the horizon and encryption increasingly seen as a matter of human rights, I came to see it differently and decided to finish it and put it out.

---

## 1. Quick start

For a quick e-mail style demonstration:

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

Files made by SillyDES 5.1.0 cannot be read by older versions, and the other way around. This includes files made by the program under its former name, Odette 5.1.0.

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

The output consists of: a 4-byte header (O, D, 5, 16: major version, then minor times 16 plus patch), the phrase hashing parameters (4 bytes), the salt (16 bytes), the IV (256 bytes), the encrypted blocks, and a 64-byte HMAC-SHA-512 tag over all of it. The MAC key is 512 bits, taken from the same keys or phrase as the DES keys. Decryption checks the tag first and stops with error 13 if it does not match.

The salt and the IV come from the system random generator on every encryption; there is no option to choose or repeat them, and the program stops with error 14 if the generator fails. Encrypting the same file twice therefore gives two unrelated outputs. This is deliberate: it is what guarantees that no two blocks, in one file or across files, are ever encrypted by the same cipher instance.

---

## 5. How to use SillyDES with e-mail software

Encrypt whatever you like to transmit, using the `act=em` option. Copy the result into a message, and send the message. The recipient must export the message into a file, and decrypt that file using the `act=dm` option. SillyDES can search for the code in the file, since the code is encapsulated by identification lines.

---

## 6. How to use SillyDES normal style

Encrypt using the `act=e` option, and decrypt using the `act=d` option. The output file now contains High-ASCII and should be treated as binary data.

---

## 7. Keys

There are two sorts of keys: a key file with eight random keys, or a phrase from which the keys are derived. Everything that matters about choosing and handling them is in this section.

### Key file

```sh
key=sample.key
```

Examine the file `sample.key` to see how to construct a key file. It's an ASCII file with eight 64-bit keys in hexadecimal. Fill it with random values, for example from `/dev/urandom` or a password manager; eight random keys give the cipher its full 512 bits.

**NEVER use `sample.key` for real data.** It is published together with this program, so anyone can decrypt what you encrypt with it. It is meant for the demonstration in section 1 only.

### Phrase

Put `phrase` on the command line instead of `key=`. The program prompts for a phrase of at least 20 characters; there is no upper limit, trailing spaces are ignored, and every character your computer accepts is allowed. At decryption, type the phrase exactly as at encryption. The keys are derived with Argon2id (RFC 9106), a slow function that needs 2 GiB of memory, and a random salt, so the same phrase gives different keys for every file and every guess costs an attacker that memory as well. If the machine cannot provide 2 GiB, the program stops with error 7 rather than running with less.

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

This kind of security is not trivial because, for example, original files won't be destroyed. If you work on a computer connected to a LAN or WAN, it's also possible for someone else to peek at your computer. SillyDES disables core dumps, blocks debugger attachment by other processes of your user, keeps your data in a single buffer that is encrypted or decrypted in place and wiped after writing, and erases keys and the phrase from memory when it is done with them, but it cannot stop the system from swapping its memory to disk. The DES layers are bitsliced, so their running time and memory access pattern do not depend on the key or the data; the Argon2id phrase derivation reads memory at data-dependent addresses after its first half pass, see the remark in [ANALYSIS.md](ANALYSIS.md), section 8.

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
| 7 | Not enough memory; phrase mode needs 2 GiB free. |
| 8 | Can't find beginning of code. |
| 9 | Duplicate argument on command line. |
| 10 | Argument missing on command line. |
| 11 | Can't find end of code. |
| 12 | CRC error, e-mail style only. |
| 13 | Authentication failed: wrong key, or data damaged or altered. |
| 14 | System random generator failed. |

---

## 10. Disclaimer

SillyDES performs a DES8 encryption (works on 2048-bit blocks) on text files or executables. Intramural security is not trivial.

The Data Encryption Standard (DES) was issued by the U.S. National Bureau of Standards.

SillyDES is free of charge, and provided as is. Andy van Wezel makes no claims and offers no warranties of any sort with SillyDES. Andy van Wezel also assumes no responsibility for any sort of damage resulting from apparent or actual use of SillyDES. The user accepts all responsibility for the use and distribution of the program. In some countries there are laws concerning encryption.

SillyDES is released under the MIT License; see the [LICENSE](LICENSE) file for the full terms. You may use, copy, modify, merge, publish, distribute, sublicense and sell copies of it, provided the copyright and permission notice are kept in all copies or substantial portions of the software.
