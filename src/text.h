// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Andy van Wezel

#pragma once

#include "common.h"

// Text that the program reads comes from other systems and other editors. This unit makes it the
// same bytes wherever it was made: the key file and the e-mail text by undoing their encoding, the
// phrase by a canonical form that is part of the file format.

// Key file and e-mail text only, never data: removes a UTF-8 byte order mark, and turns UTF-16
// with a byte order mark into bytes (a code unit above 0x7F becomes '?'). Works in place on the
// n bytes at p and returns the new length.
size_t decode_text(uint8_t *p, size_t n);

enum PhraseFault { PHRASE_OK, PHRASE_NOT_UTF8, PHRASE_CONTROL, PHRASE_SHORT };

// Brings one line of input into the canonical form of the file format, in place:
//   1. one trailing CR is removed;
//   2. it must be well-formed UTF-8;
//   3. it must hold no control character (U+0000-001F, U+007F-009F);
//   4. NFKC without invisible characters: compatibility decomposition, removal of the
//      default-ignorable code points, canonical ordering, composition;
//   5. trailing spaces are removed;
//   6. at least 20 characters (code points) must be left.
// What two systems deliver for the same typed phrase then gives the same bytes, and so the same
// keys. Anything but PHRASE_OK means that the phrase cannot be used; s is then unspecified.
PhraseFault canonical_phrase(SecretBuf &s);

// Step 4 on its own, for the tests. With drop_ignorable false this is plain NFKC.
typedef std::vector<uint32_t, LockedAllocator<uint32_t>> CodePoints;
void normalize(CodePoints &cp, bool drop_ignorable);
