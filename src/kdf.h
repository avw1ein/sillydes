// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

#include "common.h"

// Argon2id (RFC 9106, version 0x13). m_kib is the memory in KiB, t the number of passes,
// p the number of lanes; secret and ad are optional and only exist for the published test vector.
// Exits with error 7 if the machine cannot provide the memory. The 2 GiB are wiped when released and
// kept in RAM where the OS allows it (a secret mapping, else mlock within RLIMIT_MEMLOCK); otherwise they
// can be swapped out, which is error 15 when require_lock is set.
SecretBuf argon2id(const uint8_t *pw, size_t pwlen, const uint8_t *salt, size_t slen, uint32_t m_kib, uint32_t t, uint32_t p, size_t outlen,
             const uint8_t *secret = nullptr, size_t seclen = 0, const uint8_t *ad = nullptr, size_t adlen = 0, bool require_lock = false);
