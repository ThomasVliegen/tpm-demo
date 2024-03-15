CC = gcc
CFLAGS = -std=c11 -Wall
LDLIBS = -lwolftpm -lwolfssl -lm -pthread
O ?= build/

TARGET=csr
SOURCES=main.c

.PHONY: all clean

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) -I.. $(LDLIBS)

	@mkdir -p $(O)
	@mv $(TARGET) $(O)/

clean:
	rm -rf $(O)
