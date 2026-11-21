// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel

#pragma once

// The program. Changes with every release.
#define PACKAGE_VERSION "5.1.1"

// The file format, named after the release that introduced it. FORMAT_NAME is hashed into the
// keys and written in the e-mail tags, and MAGIC starts every container, so changing either one
// makes existing files unreadable. Change them together, and only when the bytes on disk or
// their meaning change; the files in test/format-* must keep decrypting until then.
#define FORMAT_NAME "SillyDES 5.1.0"
static const char MAGIC[4] = { 'S', 'D', 5, 0x10 };  // 'S' 'D', then format major, minor*16+patch
