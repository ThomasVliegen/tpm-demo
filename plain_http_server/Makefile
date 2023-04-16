CC = gcc
CFLAGS = -std=c99 -Wall
O ?= build/

TARGET=plain_http_server
SOURCES=main.c

.PHONY: all clean install

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES)

	@mkdir -p $(O)
	@mv $(TARGET) $(O)/

clean:
	rm $(O)/$(TARGET)
