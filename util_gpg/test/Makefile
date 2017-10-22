#!/usr/bin/make -f

CFLAGS += -D_GNU_SOURCE -g -O3

CFLAGS += $(shell gpgme-config --cflags)
LDFLAGS += $(shell gpgme-config --libs)

OBJECTS = testGgp

all: testGpg

testGpg: mainTestGpg.c ../gpg_session.c
	gcc $(CFLAGS) $(LDFLAGS) -I ../ -std=c11 -pedantic -Wall -Werror -o $@ $^

clean:
	rm -f $(OBJECTS)

.PHONY: all clean
