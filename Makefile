#!/usr/bin/make -f

CFLAGS += -D_GNU_SOURCE -g -O3

CFLAGS += $(shell gpgme-config --cflags)
LDFLAGS += $(shell gpgme-config --libs)

CFLAGS += $(shell pkg-config --cflags gnutls libqrencode)
LDFLAGS += $(shell pkg-config --libs gnutls libqrencode)

# libiw ships no pkg-config file -- see
# https://github.com/HewlettPackard/wireless-tools/issues/4
LDFLAGS += -liw

OBJECTS = skt-server

all: skt-server

skt-server: skt-server.c util_qr/*.c util_tsl_server/*.c util_network_info/*.c util_gpg/*.c
	gcc $(CFLAGS) $(LDFLAGS) -I . -std=c11 -pedantic -Wall -Werror -o $@ $^

clean:
	rm -f $(OBJECTS)

.PHONY: all clean
