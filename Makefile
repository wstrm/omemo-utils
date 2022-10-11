# SPDX-License-Identifier: MIT
# Copyright (c) 2020 William Wennerström

.POSIX:
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
	mkdir -p $(DESTDIR)$(PREFIX)/share/man/man1
	cp omut.1 $(DESTDIR)$(PREFIX)/share/man/man1/omut.1

uninstall: omut
	rm $(DESTDIR)$(PREFIX)/bin/omut

omut: omut.o crypt.o stream.o
	$(CC) $(LDFLAGS) -o omut stream.o crypt.o omut.o $(LDLIBS)

stream_test: stream_test.o stream.o
	$(CC) $(LDFLAGS) -o stream_test stream_test.o stream.o $(LDLIBS)

test: stream_test
	@./stream_test

clean:
	rm -f omut *.o *_test
