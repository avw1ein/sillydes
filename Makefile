# SPDX-License-Identifier: MIT
# Copyright (c) 1993-1994, 2026 Andy van Wezel

CXX      ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra

SRCS     := $(filter-out src/main.cpp,$(wildcard src/*.cpp))
OBJS     := $(SRCS:src/%.cpp=obj/%.o)

sillydes: obj/main.o $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

test/test_primitives: test/test_primitives.cpp $(OBJS)
	$(CXX) $(CXXFLAGS) -Isrc -o $@ $^

test/residue_scan.so: test/residue_scan.cpp
	$(CXX) $(CXXFLAGS) -shared -fPIC -o $@ $<

obj/%.o: src/%.cpp
	@mkdir -p obj
	$(CXX) $(CXXFLAGS) -MMD -MP -c -o $@ $<

-include obj/*.d

test: sillydes test/test_primitives test/residue_scan.so
	./test/test_primitives
	bash test/test.sh

# Regenerates the S-box circuits; the output is committed, so this is not part of a normal build.
gen: tools/gen_des_sbox
	./tools/gen_des_sbox > src/des_sbox_ct.h

tools/gen_des_sbox: tools/gen_des_sbox.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

# CycloneDX SBOM of the binary just built; the file holds its hash, so it is generated, not committed.
sbom: sillydes
	bash tools/gen_sbom.sh ./sillydes > sillydes.cdx.json.tmp
	mv sillydes.cdx.json.tmp sillydes.cdx.json

clean:
	rm -rf obj sillydes test/test_primitives test/residue_scan.so tools/gen_des_sbox sillydes.cdx.json sillydes.cdx.json.tmp

.PHONY: test gen sbom clean
