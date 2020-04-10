CC ?= gcc
CFLAGS += -Wall $(shell pkg-config --cflags libgcrypt)
LDFLAGS += $(shell pkg-config --libs libgcrypt)

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))

.PHONY: clean

all: main

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

main: $(OBJECTS) $(LDFLAGS)
	$(CC)$(OBJECTS) $(LDFLAGS) -o $@

clean:
	-rm *.o main
