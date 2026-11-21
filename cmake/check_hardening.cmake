# SPDX-License-Identifier: MIT
# Copyright (c) 1993-1994, 2026 Andy van Wezel
#
# Checks that the program carries the hardening of PORTPLAN.md 4.2: that the build did what
# cmake/harden.cmake says, not just that the flags were passed.
#   ELF (Linux): position independent, non-executable stack, read-only relocations, bound at load,
#                stack protector, and IBT and shadow stack (x86-64) or BTI (arm64).
#   PE (Windows): ASLR, high-entropy ASLR, DEP, and with MSVC control flow guard.
#   Mach-O (macOS): nothing is checked; PIE is the default there.
#
#   cmake -DBINARY=<file> -DCOMPILER_ID=<id> -P check_hardening.cmake

function(fail what)
  message(FATAL_ERROR "${BINARY}: ${what}")
endfunction()

file(READ "${BINARY}" head HEX LIMIT 4096)
string(SUBSTRING "${head}" 0 8 magic)

if(magic STREQUAL "7f454c46")
  find_program(READELF readelf)
  if(NOT READELF)
    message(STATUS "hardening: readelf not found, nothing checked")
    return()
  endif()
  function(readelf_out out)
    execute_process(COMMAND "${READELF}" ${ARGN} "${BINARY}" OUTPUT_VARIABLE text RESULT_VARIABLE rc)
    if(NOT rc EQUAL 0)
      fail("readelf ${ARGN} failed")
    endif()
    set(${out} "${text}" PARENT_SCOPE)
  endfunction()

  readelf_out(header -h)
  if(NOT header MATCHES "Type: +DYN")
    fail("not a position-independent executable")
  endif()
  readelf_out(segments -lW)
  if(NOT segments MATCHES "GNU_STACK[^\n]* RW  ")
    fail("the stack is executable or GNU_STACK is missing")
  endif()
  if(NOT segments MATCHES "GNU_RELRO")
    fail("no read-only relocations (GNU_RELRO)")
  endif()
  readelf_out(dynamic -dW)
  if(NOT dynamic MATCHES "BIND_NOW|FLAGS[^\n]*NOW")
    fail("symbols are not bound at load (-z now)")
  endif()
  readelf_out(symbols -sW)
  if(NOT symbols MATCHES "__stack_chk_fail")
    fail("no stack protector")
  endif()
  readelf_out(notes -n)
  if(header MATCHES "X86-64")
    if(NOT notes MATCHES "IBT" OR NOT notes MATCHES "SHSTK")
      fail("no IBT and SHSTK markers (-fcf-protection)")
    endif()
  elseif(header MATCHES "AArch64")
    # PAC is left out: the marker is only set when every object, the C runtime's too, was built with it.
    if(NOT notes MATCHES "BTI")
      fail("no BTI marker (-mbranch-protection); the notes are:\n${notes}")
    endif()
  endif()
  message(STATUS "hardening: ELF ok")

elseif(magic MATCHES "^4d5a")
  # PE: e_lfanew at 0x3C, then "PE\0\0", the 20-byte file header and the optional header, whose
  # DllCharacteristics (16 bits) sit at offset 70 of a PE32+ image.
  function(byte_at offset out)
    math(EXPR at "${offset} * 2")
    string(SUBSTRING "${head}" ${at} 2 b)
    math(EXPR v "0x${b}")
    set(${out} ${v} PARENT_SCOPE)
  endfunction()
  byte_at(60 b0)
  byte_at(61 b1)
  math(EXPR pe "${b0} + ${b1} * 256")
  math(EXPR chars_at "${pe} + 24 + 70")
  byte_at(${chars_at} lo)
  math(EXPR hi_at "${chars_at} + 1")
  byte_at(${hi_at} hi)
  math(EXPR chars "${lo} + ${hi} * 256")
  set(flags "0x20;high-entropy ASLR;0x40;ASLR (dynamic base);0x100;DEP (NX compatible)")
  if(COMPILER_ID STREQUAL "MSVC")
    list(APPEND flags "0x4000;control flow guard")
  endif()
  while(flags)
    list(POP_FRONT flags bit what)
    math(EXPR set "${chars} & ${bit}")
    if(set EQUAL 0)
      fail("the image has no ${what}")
    endif()
  endwhile()
  message(STATUS "hardening: PE ok (DllCharacteristics ${chars})")
else()
  message(STATUS "hardening: not ELF or PE, nothing checked")
endif()
