// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include "common.h"
#include "keys.h"

// Pads, encrypts and authenticates `data` in place into a complete container.
void seal(Buf &data, const KeyInput &keys, const KdfParams &kdf);

// Verifies and decrypts a container in place; exits with error 13 on any mismatch.
void unseal(Buf &data, const KeyInput &keys);
