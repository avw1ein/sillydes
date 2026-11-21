# SPDX-License-Identifier: MIT
# Copyright (c) 1993-1994, 2026 Andy van Wezel
#
# A first end-to-end check that runs on every OS, from CMake itself, until test_e2e.cpp (PORTPLAN.md
# todo 10) replaces test.sh and takes this over: the binary and armored round trips with a key file,
# a plaintext with CR, LF and 0x1A that must come back as it went in, an armor text without CR, the
# decryption of the committed fixtures, and a phrase from a file.
#
#   cmake -DSILLYDES=<binary> -DSRC=<source dir> -DWORK=<scratch dir> -P smoke.cmake

file(REMOVE_RECURSE "${WORK}")
file(MAKE_DIRECTORY "${WORK}")

function(sd expect_rc)
  cmake_parse_arguments(A "" "INPUT" "ARGS" ${ARGN})
  set(input)
  if(A_INPUT)
    set(input INPUT_FILE "${A_INPUT}")
  endif()
  execute_process(COMMAND "${SILLYDES}" ${A_ARGS} ${input} RESULT_VARIABLE rc OUTPUT_VARIABLE out ERROR_VARIABLE err)
  if(NOT rc EQUAL expect_rc)
    message(FATAL_ERROR "sillydes ${A_ARGS}: exit code ${rc}, expected ${expect_rc}\n${out}${err}")
  endif()
endfunction()

function(same a b what)
  execute_process(COMMAND "${CMAKE_COMMAND}" -E compare_files "${a}" "${b}" RESULT_VARIABLE rc)
  if(NOT rc EQUAL 0)
    message(FATAL_ERROR "${what}: the files differ")
  endif()
endfunction()

set(key "${SRC}/sample.key")

# Usage text without arguments.
sd(3)

# Data is bytes: CR, LF and 0x1A must survive. (file(WRITE) is a text-mode write on Windows, so the
# file differs per OS; what matters is that decryption returns it exactly.)
string(ASCII 13 10 26 eol)
file(WRITE "${WORK}/plain.txt" "Hello,${eol}second line${eol}third")
sd(0 ARGS act=e in=${WORK}/plain.txt out=${WORK}/plain.bin key=${key})
sd(0 ARGS act=d in=${WORK}/plain.bin out=${WORK}/plain.out key=${key})
same("${WORK}/plain.txt" "${WORK}/plain.out" "binary round trip")

sd(0 ARGS act=em in=${WORK}/plain.txt out=${WORK}/plain.asc key=${key})
sd(0 ARGS act=dm in=${WORK}/plain.asc out=${WORK}/plain.out2 key=${key})
same("${WORK}/plain.txt" "${WORK}/plain.out2" "armored round trip")

# The armor is LF only on every OS.
file(READ "${WORK}/plain.asc" asc_hex HEX)
string(REGEX MATCHALL "[0-9a-f][0-9a-f]" asc_bytes "${asc_hex}")
list(FIND asc_bytes 0d cr_at)
if(NOT cr_at EQUAL -1)
  message(FATAL_ERROR "the armored text contains a CR")
endif()

# The committed fixtures: decrypting them proves the format is the same on this OS.
sd(0 ARGS act=dm in=${SRC}/hello.sdes out=${WORK}/hello.txt key=${key})
file(READ "${WORK}/hello.txt" hello)
if(NOT hello MATCHES "^Hello,")
  message(FATAL_ERROR "hello.sdes decrypts to something else")
endif()
sd(0 ARGS act=d in=${SRC}/test/format-5.2.0/hello.bin out=${WORK}/hello2.txt key=${key})
same("${WORK}/hello.txt" "${WORK}/hello2.txt" "hello.bin against hello.sdes")

# A phrase from a pipe or file. file(WRITE) writes in text mode, so on Windows the line ends in
# CR LF and elsewhere in LF: both must be accepted (the byte-exact variants wait for test_e2e.cpp).
set(phrase "this phrase has more than twenty characters")
file(WRITE "${WORK}/phrase.txt" "${phrase}\n")
sd(0 ARGS act=e in=${WORK}/plain.txt out=${WORK}/phrase.bin phrase INPUT "${WORK}/phrase.txt")
sd(0 ARGS act=d in=${WORK}/phrase.bin out=${WORK}/phrase.out phrase INPUT "${WORK}/phrase.txt")
same("${WORK}/plain.txt" "${WORK}/phrase.out" "phrase round trip")

# A directory, the same file twice and a missing file are errors with their numbers.
sd(1 ARGS act=e in=${WORK} out=${WORK}/x key=${key})
sd(6 ARGS act=e in=${WORK}/plain.txt out=${WORK}/plain.txt key=${key})
sd(1 ARGS act=e in=${WORK}/missing out=${WORK}/x key=${key})

message(STATUS "smoke: ok")
