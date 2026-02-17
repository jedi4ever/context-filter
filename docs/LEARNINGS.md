# macOS DYLD Library Injection - Learnings

This document captures key learnings from debugging the DYLD_INSERT_LIBRARIES mechanism on macOS.

## Problem Summary

The library was designed to intercept `open()`, `read()`, `pread()`, and `close()` calls to filter CLAUDE.md files for prompt injection patterns. It wasn't working on macOS.

## Key Findings

### 1. macOS Requires DYLD_INTERPOSE (Not Just Function Definitions)

**Linux approach (doesn't work on macOS):**
```c
// Just defining a function with the same name
int open(const char *pathname, int flags, ...) {
    // This does NOT intercept calls on macOS
}
```

**macOS approach (required):**
```c
#define DYLD_INTERPOSE(_replacement, _original) \
    __attribute__((used)) static struct { \
        const void* replacement; \
        const void* original; \
    } _interpose_##_original __attribute__((section("__DATA,__interpose"))) = { \
        (const void*)(unsigned long)&_replacement, \
        (const void*)(unsigned long)&_original \
    };

int my_open(const char *pathname, int flags, ...) {
    // Implementation
}
DYLD_INTERPOSE(my_open, open)
```

### 2. dlsym(RTLD_NEXT) Returns Interposed Functions

With DYLD_INTERPOSE active, `dlsym(RTLD_NEXT, "open")` returns YOUR interposed function, not the original libc function. This causes infinite recursion.

**Broken:**
```c
real_open = dlsym(RTLD_NEXT, "open");  // Returns my_open, not libc open!
```

**Working - Use alternative symbols:**
```c
real_open = dlsym(RTLD_DEFAULT, "__open");           // Low-level implementation
real_read = dlsym(RTLD_DEFAULT, "read$NOCANCEL");    // Non-cancellation variant
real_pread = dlsym(RTLD_DEFAULT, "pread$NOCANCEL");
real_close = dlsym(RTLD_DEFAULT, "close$NOCANCEL");
```

**Available alternative symbols (found via `nm` or test program):**
| Standard | Alternative | Notes |
|----------|-------------|-------|
| `open` | `__open` | Takes 3 args (path, flags, mode) - NOT variadic |
| `read` | `read$NOCANCEL` | Same signature |
| `pread` | `pread$NOCANCEL` | Same signature |
| `close` | `close$NOCANCEL` | Same signature |

### 3. regcomp() Crashes in DYLD Constructor

Calling `regcomp()` from a `__attribute__((constructor))` function causes segfaults on macOS when the library is loaded via DYLD_INSERT_LIBRARIES.

**Broken:**
```c
__attribute__((constructor))
static void lib_init(void) {
    init();  // calls init_patterns() which calls regcomp() -> CRASH
}
```

**Working - Lazy compilation:**
```c
__attribute__((constructor))
static void lib_init(void) {
    init();  // Only resolve dlsym, don't compile patterns
}

static DetectionResult* detect_injections(const char *content, size_t len) {
    init_patterns();  // Compile patterns lazily on first use
    // ...
}
```

### 4. System Binaries Are SIP-Protected

macOS System Integrity Protection (SIP) strips `DYLD_*` environment variables from:
- Binaries in `/bin/`, `/usr/bin/`, `/sbin/`, `/usr/sbin/`
- Binaries with the `restricted` flag

**Check if a binary is restricted:**
```bash
ls -lO /bin/cat
# -rwxr-xr-x  1 root  wheel  restricted,compressed ...
```

**Workarounds:**
- Use binaries from Homebrew (`/usr/local/bin/`, `/opt/homebrew/bin/`)
- Use nvm-installed Node.js
- Build your own test binaries
- Use the `claude-safe` wrapper script

### 5. Testing Strategy

Create a simple test binary that's not SIP-restricted:
```c
// test_read.c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        write(1, buf, n);
    }
    close(fd);
    return 0;
}
```

Compile and test:
```bash
cc -o test_read test_read.c
DYLD_INSERT_LIBRARIES=./libcontextfilter.dylib ./test_read CLAUDE.md
```

## Debugging Techniques

### Check if library is loading
```bash
DYLD_PRINT_LIBRARIES=1 DYLD_INSERT_LIBRARIES=./lib.dylib ./program
```

### Check exported symbols
```bash
nm -g libcontextfilter.dylib | grep -E '(open|read|close)'
```

### Find alternative symbols in system libraries
```bash
nm /usr/lib/system/libsystem_kernel.dylib | grep open
# Look for __open, open$NOCANCEL, etc.
```

### Test dlsym resolution
```c
#include <dlfcn.h>
#include <stdio.h>

int main() {
    void *sym = dlsym(RTLD_DEFAULT, "__open");
    printf("__open: %p\n", sym);
    sym = dlsym(RTLD_DEFAULT, "read$NOCANCEL");
    printf("read$NOCANCEL: %p\n", sym);
    return 0;
}
```

## Final Working Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    DYLD_INSERT_LIBRARIES                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    DYLD_INTERPOSE    ┌─────────────────┐  │
│  │ Application │ ──────────────────── │ my_open()       │  │
│  │ calls open()│                      │ my_read()       │  │
│  └─────────────┘                      │ my_close()      │  │
│                                       └────────┬────────┘  │
│                                                │            │
│                                    dlsym(RTLD_DEFAULT,      │
│                                    "__open" / "$NOCANCEL")  │
│                                                │            │
│                                       ┌────────▼────────┐  │
│                                       │ Real libc funcs │  │
│                                       │ (not interposed)│  │
│                                       └─────────────────┘  │
│                                                             │
│  Constructor: Only resolve dlsym, NO regcomp()             │
│  Lazy init: Compile regex patterns on first detection      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 8. Claude Code Uses Bun Runtime — Must Intercept openat()

As of v2.x, Claude Code ships as a native Mach-O binary compiled with [Bun](https://bun.sh/) (not Node.js). This has two implications:

**Hardened runtime blocks DYLD_INSERT_LIBRARIES:**
The binary is signed with `flags=0x10000(runtime)` (hardened runtime) but without the `com.apple.security.cs.allow-dyld-environment-variables` entitlement. macOS silently strips `DYLD_INSERT_LIBRARIES` before the process starts.

**Fix**: Re-sign a local copy with the entitlement added (see `scripts/claude-resign`).

**Bun uses `openat$NOCANCEL` not `open()`:**
Unlike Node.js which uses `open()`, Bun's I/O layer calls `openat$NOCANCEL` to open files. This is a separate symbol from both `open` and `openat`. Interposing only `open()` and `openat()` misses all Bun file opens.

**Discovery**: Check which open variants a binary imports:
```bash
nm -u /path/to/binary | grep open
# _open
# _openat
# _openat$NOCANCEL   <-- this is what Bun uses
```

**Fix**: Interpose `openat$NOCANCEL` using `__asm__` to reference the `$` symbol:
```c
/* Declare the external symbol with asm label for the $ variant */
extern int openat_nocancel(int, const char *, int, ...) __asm__("_openat$NOCANCEL");

/* Use __openat_nocancel for the real function via dlsym */
real_openat_nocancel = dlsym(RTLD_DEFAULT, "__openat_nocancel");

int my_openat_nocancel(int dirfd, const char *pathname, int flags, ...) {
    int fd = real_openat_nocancel(dirfd, pathname, flags, mode);
    if (should_filter_path(pathname)) {
        log_msg("Tracking: %s (fd=%d, via openat$NOCANCEL)", pathname, fd);
    }
    return fd;
}
DYLD_INTERPOSE(my_openat_nocancel, openat_nocancel)
```

**How to tell it's Bun:**
```bash
file ~/.local/bin/claude
# Mach-O 64-bit executable arm64  (not a script with #!/usr/bin/env node)

# Binary contains __BUN segment
otool -l ~/.local/bin/claude | grep -i bun
```

## Path Matching Issues

### 6. Cache Directories Cause False Positives (2026-02-04)

The `/.claude/` directory matching catches ALL .md files under `~/.claude/`, including `~/.claude/cache/changelog.md` which is NOT user-controlled content.

**Problem code in `should_filter_path()`:**
```c
/* Match files in .claude/ directories */
if (strstr(resolved, "/.claude/") != NULL) {
    size_t len = strlen(resolved);
    if (len > 3 && strcasecmp(resolved + len - 3, ".md") == 0) {
        return 1;  // Matches cache files too!
    }
}
```

**Fix**: Add exclusion for cache directories BEFORE the general `/.claude/` match:
```c
/* Skip cache directories - not user-controlled content */
if (strstr(resolved, "/.claude/cache/") != NULL) {
    return 0;
}
```

### 7. Pattern False Positives in Technical Documentation

Detection patterns that are too broad match benign text in changelogs and docs:

| Pattern | False Positive Source |
|---------|----------------------|
| `dan_jailbreak` | Substrings: "stan**dan**rd", "re**dan**dant", "dan**gling**" |
| `ignore_instructions` | "settings being ignored", "ignorePatterns" |
| `exfil_curl` | Legitimate curl command documentation |
| `exfil_read_secrets` | Feature descriptions mentioning "read" + ".env" |
| `send_to_server` | Network feature descriptions |

**Lesson**: Detection patterns need word boundaries (`\b`) or more context to avoid false positives on technical documentation.

**Example fix for dan_jailbreak:**
```c
// Before (matches "standard"):
"\\bdan\\b"

// After (more specific):
"\\b(DAN|D\\.A\\.N\\.|do anything now)\\b"
```

## References

- Apple DYLD source: https://opensource.apple.com/source/dyld/
- DYLD_INTERPOSE: https://opensource.apple.com/source/dyld/dyld-195.5/include/mach-o/dyld-interposing.h
- System Integrity Protection: `man csrutil`
