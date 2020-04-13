# SPDX-License-Identifier: MIT
# Copyright (c) 2020 William Wennerström

.POSIX:

CC = cc
CFLAGS = -std=c99 -Wall -Werror -pedantic -D_XOPEN_SOURCE=700 \
		 `pkg-config --cflags libgcrypt libcurl`
LDLIBS = `pkg-config --libs libgcrypt libcurl`
PREFIX = /usr/local

all: omut

install: omut
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp omut $(DESTDIR)$(PREFIX)/bin

uninstall: omut
	rm $(DESTDIR)$(PREFIX)/bin/omut

omut: omut.o crypt.o stream.o
	$(CC) $(LDFLAGS) -o omut stream.o crypt.o omut.o $(LDLIBS)

stream.o: stream.c stream.h

crypt.o: crypt.c crypt.h

omut.o: omut.c crypt.h stream.h

clean:
	rm -f omut *.o