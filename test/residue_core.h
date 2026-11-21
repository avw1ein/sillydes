// SPDX-License-Identifier: MIT
// Copyright (c) 1993-1994, 2026 Andy van Wezel
//
// The residue scanner of test_e2e (residue_core.cpp).

#pragma once

// True if SCAN_MARKS names something to search for.
bool residue_scan_enabled();
// Searches the writable memory of this process for the marks and prints "RESIDUE-SCAN: <n> hit(s)" to
// the error stream. Does nothing if there are no marks, and runs once.
void residue_scan_at_exit();
