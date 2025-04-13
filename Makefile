BUILD_DIR = $(shell realpath ./build/)

.PHONY: all clean http_server csr tls_server

all: http_server csr tls_server

http_server:
	@BUILD_DIR=$(BUILD_DIR) $(MAKE) -C $@

csr:
	@O=$(BUILD_DIR) $(MAKE) -C $@

tls_server:
	@O=$(BUILD_DIR) $(MAKE) -C $@

clean:
	@echo [RM] $(BUILD_DIR)
	@rm -rf $(BUILD_DIR)
