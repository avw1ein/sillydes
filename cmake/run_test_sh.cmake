# SPDX-License-Identifier: MIT
# Copyright (c) 1993-1994, 2026 Andy van Wezel
#
# Runs test/test.sh against a build that lives outside the source tree. test.sh works from the
# root of the source tree and calls ./sillydes there, so this makes a tree of links in ROOT:
# the data files and sources of SRC, the binary and the residue scanner of this build.
# test.sh is replaced by a C++ test in PORTPLAN.md todo 10; this script goes with it.
#
#   cmake -DSRC=<source dir> -DROOT=<scratch dir> -DBASH=<bash> -DSILLYDES=<binary>
#         -DRESIDUE_SCAN=<residue_scan.so> -P run_test_sh.cmake

file(REMOVE_RECURSE "${ROOT}")
file(MAKE_DIRECTORY "${ROOT}/test")

foreach(entry hello.sdes sample.key Makefile CMakeLists.txt CMakePresets.json cmake src tools)
  file(CREATE_LINK "${SRC}/${entry}" "${ROOT}/${entry}" SYMBOLIC)
endforeach()
file(CREATE_LINK "${SILLYDES}" "${ROOT}/sillydes" SYMBOLIC)

file(GLOB test_entries RELATIVE "${SRC}/test" "${SRC}/test/*")
foreach(entry ${test_entries})
  file(CREATE_LINK "${SRC}/test/${entry}" "${ROOT}/test/${entry}" SYMBOLIC)
endforeach()
file(CREATE_LINK "${RESIDUE_SCAN}" "${ROOT}/test/residue_scan.so" SYMBOLIC)

execute_process(COMMAND "${BASH}" "${ROOT}/test/test.sh" RESULT_VARIABLE result)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "test.sh failed (${result})")
endif()
