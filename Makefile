# Root Makefile - delegates to sub-projects

INSTALL_DIR = /usr/local/lib
LIB_NAME = libcontextfilter.dylib
LIB = cf-module/dist/$(LIB_NAME)

.PHONY: all clean install uninstall test universal debug check-sip

all:
	$(MAKE) -C cf-module all

universal:
	$(MAKE) -C cf-module universal

debug:
	$(MAKE) -C cf-module debug

test:
	$(MAKE) -C cf-module test

clean:
	$(MAKE) -C cf-module clean

install: all
	@echo "Installing to $(INSTALL_DIR)..."
	@sudo mkdir -p $(INSTALL_DIR)
	sudo cp $(LIB) $(INSTALL_DIR)/
	sudo cp scripts/claude-safe /usr/local/bin/ 2>/dev/null || true
	@echo ""
	@echo "Installed to $(INSTALL_DIR)/$(LIB_NAME)"
	@echo "Usage: DYLD_INSERT_LIBRARIES=$(INSTALL_DIR)/$(LIB_NAME) claude"

uninstall:
	sudo rm -f $(INSTALL_DIR)/$(LIB_NAME)
	sudo rm -f /usr/local/bin/claude-safe

check-sip:
	@echo "Checking System Integrity Protection status..."
	@csrutil status
	@echo ""
	@echo "Checking node location..."
	@which node || echo "node not found in PATH"
	@echo ""
	@echo "If node is in /usr/bin/, DYLD_INSERT_LIBRARIES won't work."
	@echo "Use Homebrew or nvm installed Node.js instead."
