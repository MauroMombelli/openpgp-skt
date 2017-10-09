#!/usr/bin/make -f

CFLAGS += -D_GNU_SOURCE -g -O3

CFLAGS += $(shell pkg-config --cflags libqrencode gnutls)
LDFLAGS += $(shell pkg-config --libs libqrencode gnutls)

CFLAGS += $(shell gpgme-config --cflags)
LDFLAGS += $(shell gpgme-config --libs)

# libiw ships no pkg-config file -- see
# https://github.com/HewlettPackard/wireless-tools/issues/4
LDFLAGS += -liw

OBJECTS = skt-server

all: skt-server

skt-server: skt-server.c util_qr/*.c util_tsl_server/*.c util_network_info/*.c
	gcc $(CFLAGS) $(LDFLAGS) -std=c11 -pedantic -Wall -Werror -o $@ $^

clean:
	rm -f $(OBJECTS)

.PHONY: all clean
