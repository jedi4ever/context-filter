# context-filter Development Guide

## Project Overview

macOS DYLD library injection tool to detect prompt injection in CLAUDE.md files.
Intercepts file reads at the syscall level using `DYLD_INSERT_LIBRARIES`.

## Project Structure

- `cf-module/src/` - Core C source: DYLD interposition library
- `cf-module/test/` - Test binary (not SIP-restricted)
- `cf-scanner/lib/` - Python ML scanner sidecars (LLM Guard + NeMo Guardrails)
- `cf-scanner/bin/` - Scanner management CLI (`cfscanner.sh start [llmguard|nemo]`)
- `cf-scanner/config/` - NeMo Guardrails configuration
- `scripts/` - Wrapper scripts for launching Claude with filtering
- `evil-project/` - Sample malicious CLAUDE.md for testing

## Build & Test

```bash
make              # Build libcontextfilter.dylib
make test         # Build + run against evil-project/CLAUDE.md
make universal    # Fat binary (x86_64 + arm64)
make clean        # Remove build artifacts
```

## Key Technical Constraints

- **DYLD_INTERPOSE macro required** - defining same-name functions doesn't work on macOS
- **dlsym(RTLD_NEXT) returns interposed functions** - use `__open`, `read$NOCANCEL` etc.
- **regcomp() crashes in DYLD constructor** - compile patterns lazily on first use
- **System binaries are SIP-restricted** - use Homebrew/nvm node or custom test binaries
- **`/.claude/cache/` must be excluded** from path matching to avoid false positives
