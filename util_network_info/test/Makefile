#!/usr/bin/make -f

CFLAGS += -D_GNU_SOURCE -g -O3

# libiw ships no pkg-config file -- see
# https://github.com/HewlettPackard/wireless-tools/issues/4
LDFLAGS += -liw

OBJECTS = testNetInfo
all: testNetInfo

testNetInfo: main.c ../network_info.c
	gcc $(CFLAGS) $(LDFLAGS) -I ../../ -std=c11 -pedantic -Wall -Werror -o $@ $^

clean:
	rm -f $(OBJECTS)

.PHONY: all clean
