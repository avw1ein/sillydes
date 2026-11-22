# SPDX-License-Identifier: MIT
# Copyright (c) 1993-1994, 2026 Andy van Wezel
#
# Hardening flags (PORTPLAN.md 4.2), for the compilers and systems the project builds on. Every flag
# is tried first and left out where the compiler does not know it. test/ has a check that the
# result is in the binary (cmake/check_hardening.cmake).

if(SILLYDES_SANITIZE)
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
  endif()
endif()

if(NOT SILLYDES_HARDEN)
  return()
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  include(CheckCXXCompilerFlag)
  function(sillydes_add_flag flag)
    string(MAKE_C_IDENTIFIER "SILLYDES_HAS${flag}" var)
    check_cxx_compiler_flag("${flag}" ${var})
    if(${var})
      add_compile_options("${flag}")
    endif()
  endfunction()

  sillydes_add_flag(-fstack-protector-strong)
  # Mach-O and PE have no use for these: clang accepts the flags there and reports them unused.
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    sillydes_add_flag(-fstack-clash-protection)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
      sillydes_add_flag(-fcf-protection=full)  # IBT and shadow stack markers
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
      sillydes_add_flag(-mbranch-protection=standard)  # PAC and BTI
    endif()
  endif()

  # Checks of the C library on buffer sizes. Needs optimisation, clashes with the sanitizers, and
  # the distribution may define it already, hence -U first.
  if(NOT SILLYDES_SANITIZE AND NOT WIN32)
    if(APPLE)
      set(fortify 2)
    else()
      set(fortify 3)
    endif()
    add_compile_options("$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>" "$<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=${fortify}>")
  endif()

  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Position-independent executables, every symbol bound at load, read-only relocations, and a
    # stack that cannot be executed (on every compiler: Ubuntu's gcc does the first three by default).
    include(CheckPIESupported)
    check_pie_supported(LANGUAGES CXX)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    string(APPEND CMAKE_EXE_LINKER_FLAGS " -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack")
  elseif(MINGW)
    add_link_options(-Wl,--dynamicbase -Wl,--nxcompat -Wl,--high-entropy-va)
  endif()
elseif(MSVC)
  # /GS is the default; /sdl turns on more checks of the compiler, /guard:cf control flow guard,
  # /Qspectre the mitigation of Spectre variant 1 in the compiled code.
  add_compile_options(/GS /sdl /guard:cf /Qspectre)
  add_link_options(/DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /GUARD:CF)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86")
    add_link_options(/CETCOMPAT)
  endif()
endif()
