CC=gcc
CFLAGS=-std=c11 -Wall
LDLIBS=-lwolftpm -lwolfssl -lm -pthread

TARGET=tls_server
SOURCES=main.c tpm_test_keys.c
INCLUDES=.

O = $(shell realpath ./build/)

.PHONY: all clean csr tls_server plain_http_server

all: csr tls_server plain_http_server

csr:
	@O=$(O) $(MAKE) -C $@

tls_server:
	@O=$(O) $(MAKE) -C $@

plain_http_server:
	@O=$(O) $(MAKE) -C $@

clean:
	rm $(TARGET)
