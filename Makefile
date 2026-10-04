# crypt68k - make (the library, test_kat, bench); make test
#
# For a 68k machine, name its compiler, and the CPU for the mulu.l loop
# (-m68020, -m68030 or -m68040; -m68060 and -m68020-60 get the C one):
#   make CC=m68k-atari-mint-gcc CFLAGS="-O2 -m68030"
#   make CC=m68k-amigaos-gcc CFLAGS="-O2 -m68030 -noixemul"
# then run test_kat and bench there.
#
# With BearSSL (its source directory, built): make BEARSSL=../BearSSL
# adds the drop-ins (crypt68k_bearssl.h) and test_bearssl. BEARSSL_LIB
# names its libbearssl.a if that isn't in $(BEARSSL)/build.

CC	?= cc
AR	?= ar
CFLAGS	?= -O2
# (CFLAGS on the command line replaces the file's, so ours are apart)
ALL	= $(CFLAGS) -Wall -Wextra -Iinclude -Isrc
LIBOBJ	= src/mont.o src/sigmath.o src/ecdsa.o

BEARSSL_LIB ?= $(BEARSSL)/build/libbearssl.a

ifneq ($(BEARSSL),)
LIBOBJ	+= src/bearssl.o
ALL	+= -I$(BEARSSL)/inc
EXTRA	= test_bearssl
endif

all: libcrypt68k.a test_kat bench $(EXTRA)

libcrypt68k.a: $(LIBOBJ)
	$(AR) rcs $@ $^

src/%.o: src/%.c include/crypt68k.h include/crypt68k_bearssl.h src/mont.h src/curves.h
	$(CC) $(ALL) -c $< -o $@

test_kat: tests/test_kat.c tests/vectors.h libcrypt68k.a
	$(CC) $(ALL) -o $@ tests/test_kat.c libcrypt68k.a

bench: tests/bench.c tests/vectors.h libcrypt68k.a
	$(CC) $(ALL) -Itests -o $@ tests/bench.c libcrypt68k.a

test_bearssl: tests/test_bearssl.c libcrypt68k.a
	$(CC) $(ALL) -o $@ tests/test_bearssl.c libcrypt68k.a $(BEARSSL_LIB)

test: test_kat $(EXTRA)
	./test_kat
	$(if $(EXTRA),./test_bearssl)

# the vectors (checked in; Python 3.8+)
vectors:
	python3 tests/gen_vectors.py

clean:
	rm -f src/*.o libcrypt68k.a test_kat bench test_bearssl

.PHONY: all test vectors clean
