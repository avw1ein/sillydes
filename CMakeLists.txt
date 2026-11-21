# SPDX-License-Identifier: MIT
# Copyright (c) 1993-1994, 2026 Andy van Wezel
#
# Build:  cmake --preset default && cmake --build --preset default && ctest --preset default
# The Makefile still works and stays until CMake is the only build (PORTPLAN.md, todo 13).

cmake_minimum_required(VERSION 3.16)
project(SillyDES LANGUAGES CXX)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "SillyDES builds for 64-bit targets only")
endif()

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(SILLYDES_WERROR "Treat compiler warnings as errors" OFF)
option(SILLYDES_BUILD_TESTS "Build the tests" ON)
option(SILLYDES_HARDEN "Compile and link with the hardening flags of PORTPLAN.md 4.2" ON)
set(SILLYDES_OPT_LEVEL "2" CACHE STRING "Optimisation level (-O<level>) of the Release build; the constant-time checks run it at 0, 2 and 3")
option(SILLYDES_TIMING_TESTS "Add the statistical timing test ct_timing (takes seconds and is sensitive to a busy machine; the constant-time workflow turns it on)" OFF)
set(SILLYDES_TIMING_SCALE "1" CACHE STRING "Sample multiplier of ct_timing; 10 for the nightly run")
option(SILLYDES_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer (GCC and Clang)" OFF)
option(SILLYDES_REGENERATE_SBOX "Add the target regenerate_sbox, which rewrites src/des_sbox_ct.h" OFF)
set(SILLYDES_REGENERATE_UNICODE "" CACHE PATH
    "Directory with the Unicode data files of the pinned version (tools/fetch_ucd.sh fills it); adds the targets regenerate_unicode and check_unicode and the test unicode_check")

# The same -O2 as the Makefile (not -O3), and no -DNDEBUG.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  set(CMAKE_CXX_FLAGS_RELEASE "-O${SILLYDES_OPT_LEVEL}")
  add_compile_options(-Wall -Wextra)
  if(SILLYDES_WERROR)
    add_compile_options(-Werror)
  endif()
  # No DLLs to ship next to the program: the C and C++ runtimes are linked in.
  if(MINGW)
    add_link_options(-static)
  endif()
elseif(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  set(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2")  # no /DNDEBUG, as on Linux
  add_compile_options(/W4 /utf-8)
  if(SILLYDES_WERROR)
    add_compile_options(/WX)
  endif()
endif()

# One platform file per OS (src/platform.h): the only code that includes OS headers.
if(WIN32)
  set(SILLYDES_PLATFORM_SOURCE src/platform_win32.cpp)
  set(SILLYDES_TEST_OS_SOURCE test/test_os_win32.cpp)
else()
  set(SILLYDES_PLATFORM_SOURCE src/platform_posix.cpp)
  set(SILLYDES_TEST_OS_SOURCE test/test_os_posix.cpp)
endif()

include(cmake/harden.cmake)

set(SILLYDES_CORE_SOURCES
  src/armor.cpp
  src/blake2b.cpp
  src/common.cpp
  src/container.cpp
  src/crc32.cpp
  src/des.cpp
  src/kdf.cpp
  src/keys.cpp
  ${SILLYDES_PLATFORM_SOURCE}
  src/sha512.cpp
  src/sillydes_cipher.cpp
  src/text.cpp)

add_library(sillydes_core STATIC ${SILLYDES_CORE_SOURCES})
target_include_directories(sillydes_core PUBLIC src)

add_executable(sillydes src/main.cpp)
target_link_libraries(sillydes PRIVATE sillydes_core)

if(WIN32)
  target_link_libraries(sillydes_core PUBLIC bcrypt)
  if(MINGW)
    target_link_options(sillydes PRIVATE -municode)  # wmain, the wide arguments
  endif()
endif()
install(TARGETS sillydes RUNTIME DESTINATION bin)
install(FILES README.md LICENSE LICENSE.Unicode DESTINATION share/doc/sillydes)

# Runs TOOL with ARGS and writes what it prints to a file (a shell redirection that works everywhere).
set(SILLYDES_GENERATE ${CMAKE_CURRENT_SOURCE_DIR}/cmake/generate.cmake)

if(SILLYDES_REGENERATE_SBOX)
  add_executable(gen_des_sbox EXCLUDE_FROM_ALL tools/gen_des_sbox.cpp)
  # The output is committed, so this is never part of a normal build.
  add_custom_target(regenerate_sbox
    COMMAND ${CMAKE_COMMAND} -DTOOL=$<TARGET_FILE:gen_des_sbox> -DOUT=${CMAKE_BINARY_DIR}/des_sbox_ct.h -P ${SILLYDES_GENERATE}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_BINARY_DIR}/des_sbox_ct.h ${CMAKE_CURRENT_SOURCE_DIR}/src/des_sbox_ct.h
    DEPENDS gen_des_sbox
    COMMENT "Regenerating src/des_sbox_ct.h"
    VERBATIM)
endif()

if(SILLYDES_REGENERATE_UNICODE)
  set(UCD "${SILLYDES_REGENERATE_UNICODE}")
  add_executable(gen_unicode EXCLUDE_FROM_ALL tools/gen_unicode.cpp)
  add_executable(unicode_conformance EXCLUDE_FROM_ALL test/unicode_conformance.cpp)
  target_link_libraries(unicode_conformance PRIVATE sillydes_core)
  set(GENERATED_TABLES ${CMAKE_BINARY_DIR}/unicode_tables.h)
  # The tables are part of the file format: regenerating them is for a new format only.
  add_custom_target(regenerate_unicode
    COMMAND ${CMAKE_COMMAND} -DTOOL=$<TARGET_FILE:gen_unicode> "-DARGS=${UCD}$<SEMICOLON>${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.Unicode"
            -DOUT=${GENERATED_TABLES} -P ${SILLYDES_GENERATE}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${GENERATED_TABLES} ${CMAKE_CURRENT_SOURCE_DIR}/src/unicode_tables.h
    COMMAND unicode_conformance ${UCD}/NormalizationTest.txt
    DEPENDS gen_unicode unicode_conformance
    COMMENT "Regenerating src/unicode_tables.h"
    VERBATIM)
  # The committed tables must be what the generator makes of the data, and must pass the conformance file.
  add_custom_target(check_unicode
    COMMAND ${CMAKE_COMMAND} -DTOOL=$<TARGET_FILE:gen_unicode> "-DARGS=${UCD}$<SEMICOLON>${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.Unicode"
            -DOUT=${GENERATED_TABLES} -P ${SILLYDES_GENERATE}
    COMMAND ${CMAKE_COMMAND} -E compare_files ${GENERATED_TABLES} ${CMAKE_CURRENT_SOURCE_DIR}/src/unicode_tables.h
    COMMAND unicode_conformance ${UCD}/NormalizationTest.txt
    DEPENDS gen_unicode unicode_conformance
    COMMENT "Checking src/unicode_tables.h against the Unicode data"
    VERBATIM)
endif()

# CycloneDX SBOM of the binary just built; it holds the binary's hash, so it is generated, not committed.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_program(SILLYDES_BASH bash)
  if(SILLYDES_BASH)
    add_custom_target(sbom
      COMMAND ${CMAKE_COMMAND} -DTOOL=${SILLYDES_BASH} -DCXX=${CMAKE_CXX_COMPILER}
              "-DARGS=${CMAKE_CURRENT_SOURCE_DIR}/tools/gen_sbom.sh$<SEMICOLON>$<TARGET_FILE:sillydes>"
              -DOUT=${CMAKE_BINARY_DIR}/sillydes.cdx.json -P ${SILLYDES_GENERATE}
      DEPENDS sillydes
      COMMENT "Writing sillydes.cdx.json"
      VERBATIM)
  endif()
endif()

if(SILLYDES_BUILD_TESTS)
  enable_testing()

  add_executable(test_primitives test/test_primitives.cpp ${SILLYDES_TEST_OS_SOURCE})
  target_link_libraries(test_primitives PRIVATE sillydes_core)
  if(WIN32)
    target_link_libraries(test_primitives PRIVATE psapi)  # QueryWorkingSetEx: which pages are locked
  endif()
  if(MSVC)
    # The test blocks reuse the names msg, a, b on purpose; each block stands alone.
    target_compile_options(test_primitives PRIVATE /wd4456)
  endif()
  add_test(NAME primitives COMMAND test_primitives)
  if(SILLYDES_HARDEN)
    add_test(NAME hardening
      COMMAND ${CMAKE_COMMAND} -DBINARY=$<TARGET_FILE:sillydes> -DCOMPILER_ID=${CMAKE_CXX_COMPILER_ID}
              -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/check_hardening.cmake)
  endif()
  # End-to-end tests: the real binary, on every OS the same way.
  add_executable(test_e2e test/test_e2e.cpp ${SILLYDES_TEST_OS_SOURCE})
  target_link_libraries(test_e2e PRIVATE sillydes_core)
  if(MSVC)
    target_compile_options(test_e2e PRIVATE /wd4456)
  endif()
  set(SILLYDES_E2E_ARGS $<TARGET_FILE:sillydes> ${CMAKE_CURRENT_SOURCE_DIR})
  if(SILLYDES_SANITIZE)
    # The sanitizers reserve address space (a limit would stop them).
    list(APPEND SILLYDES_E2E_ARGS --no-address-limit)
  endif()
  if(NOT SILLYDES_SANITIZE)
    # The residue scan (does a secret survive in the memory of the exited process?). The scan binary is
    # the program built so that exit_process searches the memory first (SILLYDES_RESIDUE_SCAN); it works
    # on every OS. The preload library does the same to the real binary and is Linux only. Both share
    # test/residue_core.cpp. A sanitizer brings its own allocator and shadow memory: no scan there.
    add_library(sillydes_core_scan STATIC ${SILLYDES_CORE_SOURCES})
    target_include_directories(sillydes_core_scan PUBLIC src)
    target_compile_definitions(sillydes_core_scan PUBLIC SILLYDES_RESIDUE_SCAN)
    add_executable(sillydes_scan src/main.cpp test/residue_core.cpp)
    target_link_libraries(sillydes_scan PRIVATE sillydes_core_scan)
    if(WIN32)
      target_link_libraries(sillydes_core_scan PUBLIC bcrypt)
      if(MINGW)
        target_link_options(sillydes_scan PRIVATE -municode)
      endif()
    endif()
    list(APPEND SILLYDES_E2E_ARGS --scan-exe $<TARGET_FILE:sillydes_scan>)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      add_library(residue_scan SHARED test/residue_scan.cpp test/residue_core.cpp)
      set_target_properties(residue_scan PROPERTIES PREFIX "" SUFFIX ".so" POSITION_INDEPENDENT_CODE ON)
      list(APPEND SILLYDES_E2E_ARGS --scan-lib $<TARGET_FILE:residue_scan>)
    endif()
  endif()
  add_test(NAME e2e COMMAND test_e2e ${SILLYDES_E2E_ARGS})

  # Constant-time check with Valgrind's Memcheck (ctgrind style, PORTPLAN.md 5.3); needs valgrind.
  find_program(SILLYDES_VALGRIND valgrind)
  include(CheckIncludeFileCXX)
  check_include_file_cxx(valgrind/memcheck.h SILLYDES_HAVE_MEMCHECK_H)
  if(SILLYDES_VALGRIND AND SILLYDES_HAVE_MEMCHECK_H AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(ct_valgrind test/ct_valgrind.cpp)
    target_link_libraries(ct_valgrind PRIVATE sillydes_core)
    add_test(NAME ct_valgrind COMMAND ${SILLYDES_VALGRIND} --error-exitcode=99 --exit-on-first-error=no -q $<TARGET_FILE:ct_valgrind>)
    add_test(NAME ct_valgrind_detects_a_leak COMMAND ${SILLYDES_VALGRIND} --error-exitcode=99 -q $<TARGET_FILE:ct_valgrind> --leak)
    set_tests_properties(ct_valgrind_detects_a_leak PROPERTIES WILL_FAIL TRUE)
    set_tests_properties(ct_valgrind ct_valgrind_detects_a_leak PROPERTIES LABELS constant-time)
  endif()

  if(SILLYDES_TIMING_TESTS)
    add_executable(ct_timing test/ct_timing.cpp ${SILLYDES_TEST_OS_SOURCE})
    target_link_libraries(ct_timing PRIVATE sillydes_core)
    add_test(NAME ct_timing COMMAND ct_timing ${SILLYDES_TIMING_SCALE})
    set_tests_properties(ct_timing PROPERTIES LABELS constant-time)
  endif()

  # The disassembly gate: conditional branches per function, enforced for the branch-free ones.
  if(SILLYDES_BASH AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_test(NAME ct_branches COMMAND ${SILLYDES_BASH} ${CMAKE_CURRENT_SOURCE_DIR}/tools/ct_branches.sh $<TARGET_FILE:sillydes>)
    set_tests_properties(ct_branches PROPERTIES LABELS constant-time)
  endif()

  if(SILLYDES_REGENERATE_UNICODE)
    add_test(NAME unicode_check
      COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target check_unicode --config $<CONFIG>)
  endif()
endif()
