#!/usr/bin/make -f

CFLAGS += -D_GNU_SOURCE -g -O3

CFLAGS += $(shell pkg-config --cflags libqrencode)
LDFLAGS += $(shell pkg-config --libs libqrencode)

CFLAGS += $(shell pkg-config --cflags gnutls)
LDFLAGS += $(shell pkg-config --libs gnutls)

OBJECTS = skt-server

all: skt-server

skt-server: skt-server.c
	gcc $(CFLAGS) $(LDFLAGS) -std=c11 -pedantic -Wall -Werror -o $@ $<

clean:
	rm -f $(OBJECTS)
