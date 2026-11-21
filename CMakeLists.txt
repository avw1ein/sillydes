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
option(SILLYDES_REGENERATE_SBOX "Add the target regenerate_sbox, which rewrites src/des_sbox_ct.h" OFF)
set(SILLYDES_REGENERATE_UNICODE "" CACHE PATH
    "Directory with the Unicode data files of the pinned version (tools/fetch_ucd.sh fills it); adds the targets regenerate_unicode and check_unicode and the test unicode_check")

# The same -O2 as the Makefile (not -O3), and no -DNDEBUG.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  set(CMAKE_CXX_FLAGS_RELEASE "-O2")
  add_compile_options(-Wall -Wextra)
  if(SILLYDES_WERROR)
    add_compile_options(-Werror)
  endif()
elseif(MSVC)
  add_compile_options(/W4 /utf-8)
  if(SILLYDES_WERROR)
    add_compile_options(/WX)
  endif()
endif()

set(SILLYDES_CORE_SOURCES
  src/armor.cpp
  src/blake2b.cpp
  src/common.cpp
  src/container.cpp
  src/crc32.cpp
  src/des.cpp
  src/kdf.cpp
  src/keys.cpp
  src/platform_posix.cpp
  src/sha512.cpp
  src/sillydes_cipher.cpp
  src/text.cpp)

add_library(sillydes_core STATIC ${SILLYDES_CORE_SOURCES})
target_include_directories(sillydes_core PUBLIC src)

add_executable(sillydes src/main.cpp)
target_link_libraries(sillydes PRIVATE sillydes_core)
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

  add_executable(test_primitives test/test_primitives.cpp)
  target_link_libraries(test_primitives PRIVATE sillydes_core)
  add_test(NAME primitives COMMAND test_primitives)

  if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND SILLYDES_BASH)
    # LD_PRELOAD helper of test.sh: searches the process for leftover secrets as it exits.
    add_library(residue_scan SHARED test/residue_scan.cpp)
    set_target_properties(residue_scan PROPERTIES PREFIX "" SUFFIX ".so" POSITION_INDEPENDENT_CODE ON)
    # test.sh works from the root of the source tree and calls ./sillydes there; run_test_sh.cmake
    # builds such a tree of links in the build directory so that the source tree stays clean.
    add_test(NAME e2e_shell
      COMMAND ${CMAKE_COMMAND} -DSRC=${CMAKE_CURRENT_SOURCE_DIR} -DROOT=${CMAKE_BINARY_DIR}/test_root
              -DBASH=${SILLYDES_BASH} -DSILLYDES=$<TARGET_FILE:sillydes> -DRESIDUE_SCAN=$<TARGET_FILE:residue_scan>
              -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/run_test_sh.cmake)
  endif()

  if(SILLYDES_REGENERATE_UNICODE)
    add_test(NAME unicode_check
      COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target check_unicode --config $<CONFIG>)
  endif()
endif()
