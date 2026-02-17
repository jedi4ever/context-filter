# Makefile for cf-module (macOS DYLD interposition library)

CC = clang
CFLAGS = -Wall -Wextra -fPIC -O2 -g -Isrc
LDFLAGS = -dynamiclib -ldl

# Directories
DIST_DIR = dist

# Output
LIB_NAME = libcontextfilter.dylib
LIB = $(DIST_DIR)/$(LIB_NAME)
TEST_BIN = $(DIST_DIR)/test_read

# Source files
SRC = src/context_filter_macos.c
TEST_SRC = test/test_read.c
PATTERNS_JSON = config/patterns.json
PATTERNS_H = src/patterns_generated.h

# Architecture detection
ARCH := $(shell uname -m)

.PHONY: all clean test universal debug

# Default: build for current architecture
all: $(LIB)

$(DIST_DIR):
	mkdir -p $(DIST_DIR)

# Generate C header from patterns.json
$(PATTERNS_H): $(PATTERNS_JSON) scripts/gen_patterns.py
	python3 scripts/gen_patterns.py $(PATTERNS_JSON) $(PATTERNS_H)

$(LIB): $(SRC) $(PATTERNS_H) | $(DIST_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo ""
	@echo "Built $(LIB) for $(ARCH)"

# Build universal binary (both x86_64 and arm64)
universal: $(SRC) $(PATTERNS_H) | $(DIST_DIR)
	$(CC) $(CFLAGS) -arch x86_64 -o $(LIB).x86_64 $(SRC) $(LDFLAGS)
	$(CC) $(CFLAGS) -arch arm64 -o $(LIB).arm64 $(SRC) $(LDFLAGS)
	lipo -create -output $(LIB) $(LIB).x86_64 $(LIB).arm64
	rm -f $(LIB).x86_64 $(LIB).arm64
	@echo ""
	@echo "Built universal $(LIB) (x86_64 + arm64)"

# Debug build with more logging
debug: CFLAGS += -DDEBUG -O0
debug: $(LIB)

# Build test binary (not SIP-restricted, unlike /bin/cat)
$(TEST_BIN): $(TEST_SRC) | $(DIST_DIR)
	$(CC) -o $@ $<

# Test against evil-project/CLAUDE.md
test: $(LIB) $(TEST_BIN)
	@echo "Testing library with test_read on evil-project/CLAUDE.md..."
	@echo "(Using custom binary because /bin/cat is SIP-restricted)"
	@echo "=================================================="
	DYLD_INSERT_LIBRARIES=./$(LIB) ./$(TEST_BIN) ../evil-project/CLAUDE.md
	@echo ""
	@echo "=================================================="
	@echo "Test complete!"

clean:
	rm -rf $(DIST_DIR) $(PATTERNS_H)
