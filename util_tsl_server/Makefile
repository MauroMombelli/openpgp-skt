#!/usr/bin/make -f

CFLAGS += -D_GNU_SOURCE -g -O3

CFLAGS += $(shell pkg-config --cflags gnutls libqrencode)
LDFLAGS += $(shell pkg-config --libs gnutls libqrencode)

OBJECTS = testTsl

all: testTsl

testTsl: mainTestTSLServer.c tsl_server.c ../util_qr/qr_code.c
	gcc $(CFLAGS) $(LDFLAGS) -std=c11 -pedantic -Wall -Werror -o $@ $^

clean:
	rm -f $(OBJECTS)

.PHONY: all clean
