CC = gcc
CFLAGS = -std=c99
BUILD_DIR ?= build

TARGET = http_server
SRC = main.c

all: http_server

pre-build:
	@if [ ! -d "$(BUILD_DIR)" ]; then \
		echo [MKDIR] $(BUILD_DIR); \
		mkdir -p $(BUILD_DIR); \
	fi

http_server: pre-build $(SRC)
	@echo [$(CC)] $(SRC)
	@$(CC) $(CFLAGS) -o $(BUILD_DIR)/$(TARGET) $(SRC)

clean:
	@echo [RM] $(BUILD_DIR)
	@rm -rf $(BUILD_DIR)

.PHONY: all pre-build http_server clean

