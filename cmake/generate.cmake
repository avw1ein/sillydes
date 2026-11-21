# SPDX-License-Identifier: MIT
# Copyright (c) 1993-1994, 2026 Andy van Wezel
#
# Runs TOOL with ARGS (a list) and writes what it prints to OUT, replacing OUT only if the tool
# succeeds. Used by the generator and SBOM targets, so that no shell redirection is needed.
#
#   cmake -DTOOL=<program> [-DARGS=<a;b;c>] [-DCXX=<compiler>] -DOUT=<file> -P generate.cmake
#
# CXX is handed to the tool in the environment (gen_sbom.sh names the compiler that built the binary).

if(CXX)
  set(ENV{CXX} "${CXX}")
endif()

execute_process(COMMAND ${TOOL} ${ARGS}
                OUTPUT_FILE "${OUT}.tmp"
                RESULT_VARIABLE result)
if(NOT result EQUAL 0)
  file(REMOVE "${OUT}.tmp")
  message(FATAL_ERROR "${TOOL} failed (${result})")
endif()
file(RENAME "${OUT}.tmp" "${OUT}")
