# SPDX-License-Identifier: MIT
# Copyright (c) 1993-1994, 2026 Andy van Wezel

CXX      ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra

SRCS     := $(filter-out src/main.cpp,$(wildcard src/*.cpp))
OBJS     := $(SRCS:src/%.cpp=obj/%.o)

sillydes: obj/main.o $(OBJS)
	$(CXX) $(CXXFLAGS) -Wl,-z,relro,-z,now -o $@ $^

# -z now binds every symbol at load time and -z relro makes the relocations read-only (PORTPLAN.md 4.2);
# Ubuntu's gcc does this by default, clang does not.

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

# Regenerates the Unicode tables from the data files in the directory $(UCD) and checks the result.
# The output is committed and is part of the file format, so this is not part of a normal build:
# see the comment at the top of src/unicode_tables.h. tools/fetch_ucd.sh fills $(UCD).
unicode: tools/gen_unicode
	./tools/gen_unicode $(UCD) LICENSE.Unicode > src/unicode_tables.h.tmp
	mv src/unicode_tables.h.tmp src/unicode_tables.h
	$(MAKE) unicode-check UCD=$(UCD)

# The committed tables must be what the generator makes of $(UCD), and the normalisation must
# pass the conformance file of that Unicode version.
unicode-check: tools/gen_unicode test/unicode_conformance
	./tools/gen_unicode $(UCD) LICENSE.Unicode | cmp - src/unicode_tables.h
	./test/unicode_conformance $(UCD)/NormalizationTest.txt

tools/gen_unicode: tools/gen_unicode.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

test/unicode_conformance: test/unicode_conformance.cpp obj/text.o obj/common.o obj/platform_posix.o
	$(CXX) $(CXXFLAGS) -Isrc -o $@ $^

# CycloneDX SBOM of the binary just built; the file holds its hash, so it is generated, not committed.
sbom: sillydes
	bash tools/gen_sbom.sh ./sillydes > sillydes.cdx.json.tmp
	mv sillydes.cdx.json.tmp sillydes.cdx.json

clean:
	rm -rf obj sillydes test/test_primitives test/residue_scan.so test/unicode_conformance tools/gen_des_sbox tools/gen_unicode \
	  src/unicode_tables.h.tmp sillydes.cdx.json sillydes.cdx.json.tmp

.PHONY: test gen unicode unicode-check sbom clean
