# SPDX-License-Identifier: MIT
# Copyright (c) 2020 William Wennerström

.POSIX:
.SUFFIXES:
.SUFFIXES: .c .o
.PHONY: test all

CC = cc
CFLAGS = -std=c99 -Wall -Werror -pedantic -D_XOPEN_SOURCE=700 \
		 `pkg-config --cflags libgcrypt libcurl`
LDLIBS = `pkg-config --libs libgcrypt libcurl`
PREFIX = /usr/local

all: test omut

install: omut
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp omut $(DESTDIR)$(PREFIX)/bin

uninstall: omut
	rm $(DESTDIR)$(PREFIX)/bin/omut

omut: omut.o crypt.o stream.o

omut.o: omut.c

stream_test: stream_test.o stream.o

test: stream_test
	@./stream_test

clean:
	rm -f omut *.o *_test

%.o: %.c %.h

%_test.o: %_test.c

%::
	$(CC)$(LDFLAGS) -o $@ $^ $(LDLIBS)

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@
