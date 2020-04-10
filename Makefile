.POSIX:

CC = cc
CFLAGS = -Wall `pkg-config --cflags libgcrypt`
LDLIBS = `pkg-config --libs libgcrypt`
PREFIX = /usr/local

all: omut

install: omut
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp omut $(DESTDIR)$(PREFIX)/bin

uninstall: omut
	rm $(DESTDIR)$(PREFIX)/bin/omut

omut: omut.o crypt.o
	$(CC) $(LDFLAGS) -o omut crypt.o omut.o $(LDLIBS)

crypt.o: crypt.c crypt.h

omut.o: omut.c crypt.h

clean:
	rm -f omut *.o
