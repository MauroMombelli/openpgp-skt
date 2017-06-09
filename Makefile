#!/usr/bin/make -f

CFLAGS += -D_GNU_SOURCE -g -O3

CFLAGS += $(shell pkg-config --cflags libqrencode gnutls libuv)
LDFLAGS += $(shell pkg-config --libs libqrencode gnutls libuv)

CFLAGS += $(shell gpgme-config --cflags)
LDFLAGS += $(shell gpgme-config --libs)

OBJECTS = skt-server

all: skt-server

skt-server: skt-server.c
	gcc $(CFLAGS) $(LDFLAGS) -std=c11 -pedantic -Wall -Werror -o $@ $<

clean:
	rm -f $(OBJECTS)

.PHONY: all clean
