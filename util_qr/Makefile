#!/usr/bin/make -f

CFLAGS += -D_GNU_SOURCE -g -O3

CFLAGS += $(shell pkg-config --cflags libqrencode)
LDFLAGS += $(shell pkg-config --libs libqrencode)

OBJECTS = testQr

all: testQr

testQr: mainTestQr.c qr_code.c
	gcc $(CFLAGS) $(LDFLAGS) -std=c11 -pedantic -Wall -Werror -o $@ $^

clean:
	rm -f $(OBJECTS)

.PHONY: all clean
