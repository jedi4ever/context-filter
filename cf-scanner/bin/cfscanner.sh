#!/bin/bash
# cfscanner.sh - Manage the ML injection scanner sidecar
#
# The filter library (cf-module) connects to a single well-known socket.
# This script starts one scanner type at a time on that socket.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_DIR="$SCRIPT_DIR/.."
PROJECT_ROOT="$SCRIPT_DIR/../.."
DYLIB_PATH="$PROJECT_ROOT/cf-module/dist/libcontextfilter.dylib"

# Shared socket - the C library connects here
SOCKET="/tmp/context-filter-scanner.sock"
PID_FILE="/tmp/context-filter-scanner.pid"
TYPE_FILE="/tmp/context-filter-scanner.type"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

get_python() {
    if [ -x "$PROJECT_ROOT/.venv312/bin/python3" ]; then
        echo "$PROJECT_ROOT/.venv312/bin/python3"
    elif [ -x "$PROJECT_ROOT/.venv/bin/python3" ]; then
        echo "$PROJECT_ROOT/.venv/bin/python3"
    else
        echo "python3"
    fi
}

# Resolve scanner type to its script and python module
resolve_scanner() {
    local type="$1"
    case "$type" in
        llmguard)
            SCANNER_SCRIPT="$SCANNER_DIR/lib/llmguard_scanner.py"
            PYTHON_MODULE="llm_guard"
            LABEL="LLM Guard"
            WAIT_SECS=30
            ;;
        nemo)
            SCANNER_SCRIPT="$SCANNER_DIR/lib/nemo_scanner.py"
            PYTHON_MODULE="nemoguardrails"
            LABEL="NeMo Guardrails"
            WAIT_SECS=60
            ;;
        *)
            echo -e "${RED}Unknown scanner type: $type${NC}" >&2
            echo "Available types: llmguard, nemo" >&2
            return 1
            ;;
    esac
}

do_start() {
    local daemonize=false
    local type="nemo"

    # Parse flags and type
    while [ $# -gt 0 ]; do
        case "$1" in
            -d) daemonize=true ;;
            *)  type="$1" ;;
        esac
        shift
    done

    resolve_scanner "$type" || return 1

    # Stop existing scanner if running a different type
    if [ -S "$SOCKET" ]; then
        local running_type
        running_type=$(cat "$TYPE_FILE" 2>/dev/null || echo "unknown")
        if [ "$running_type" = "$type" ]; then
            echo -e "${YELLOW}$LABEL scanner already running (socket: $SOCKET)${NC}"
            return 0
        fi
        echo -e "${YELLOW}Stopping $running_type scanner to switch to $type...${NC}"
        do_stop
    fi

    echo -e "${GREEN}Starting $LABEL scanner...${NC}"

    PYTHON=$(get_python)

    if ! "$PYTHON" -c "import $PYTHON_MODULE" 2>/dev/null; then
        echo -e "${RED}Error: $PYTHON_MODULE not installed${NC}"
        echo "Install with: pip install $PYTHON_MODULE"
        return 1
    fi

    if [ "$daemonize" = true ]; then
        "$PYTHON" "$SCANNER_SCRIPT" --socket "$SOCKET" &
        local pid=$!
        echo "$pid" > "$PID_FILE"
        echo "$type" > "$TYPE_FILE"

        for i in $(seq 1 "$WAIT_SECS"); do
            if [ -S "$SOCKET" ]; then
                echo -e "${GREEN}$LABEL scanner started (PID: $pid, socket: $SOCKET)${NC}"
                return 0
            fi
            sleep 0.5
        done

        echo -e "${RED}$LABEL scanner failed to start${NC}"
        rm -f "$PID_FILE" "$TYPE_FILE"
        return 1
    else
        echo "$type" > "$TYPE_FILE"
        exec "$PYTHON" "$SCANNER_SCRIPT" --socket "$SOCKET"
    fi
}

do_stop() {
    if [ -f "$PID_FILE" ]; then
        local pid
        pid=$(cat "$PID_FILE")
        local type
        type=$(cat "$TYPE_FILE" 2>/dev/null || echo "unknown")
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "${YELLOW}Stopping $type scanner (PID: $pid)...${NC}"
            kill "$pid"
            rm -f "$PID_FILE" "$SOCKET" "$TYPE_FILE"
            echo -e "${GREEN}Scanner stopped${NC}"
            return 0
        fi
    fi

    # Cleanup stale files
    pkill -f "llmguard_scanner.py|nemo_scanner.py" 2>/dev/null
    rm -f "$SOCKET" "$PID_FILE" "$TYPE_FILE"
    echo -e "${YELLOW}Scanner stopped (cleanup)${NC}"
}

do_download() {
    local type="${1:-nemo}"
    resolve_scanner "$type" || return 1

    PYTHON=$(get_python)

    if ! "$PYTHON" -c "import $PYTHON_MODULE" 2>/dev/null; then
        echo -e "${RED}Error: $PYTHON_MODULE not installed${NC}"
        echo "Install with: pip install -r cf-scanner/requirements.txt"
        return 1
    fi

    echo -e "${GREEN}Downloading $LABEL model...${NC}"

    case "$type" in
        llmguard)
            "$PYTHON" -c "
from llm_guard.input_scanners import PromptInjection
from llm_guard.input_scanners.prompt_injection import MatchType
print('Loading model...')
scanner = PromptInjection(threshold=0.5, match_type=MatchType.FULL)
print('Model ready.')
"
            ;;
        nemo)
            "$PYTHON" -c "
from nemoguardrails.library.jailbreak_detection.heuristics import checks
print('Loading model...')
checks.check_jailbreak_length_per_perplexity('test', 89.79)
print('Model ready.')
"
            ;;
    esac

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}$LABEL model downloaded successfully${NC}"
    else
        echo -e "${RED}$LABEL model download failed${NC}"
        return 1
    fi
}

do_status() {
    echo "=== Scanner Sidecar ==="
    if [ -S "$SOCKET" ]; then
        local type
        type=$(cat "$TYPE_FILE" 2>/dev/null || echo "unknown")
        echo -e "Type:   ${GREEN}$type${NC}"
        echo "Socket: $SOCKET"
        if [ -f "$PID_FILE" ]; then
            echo "PID:    $(cat "$PID_FILE")"
        fi
    else
        echo -e "${YELLOW}Not running${NC}"
    fi

    echo ""
    echo "=== Filter Library ==="
    if [ -f "$DYLIB_PATH" ]; then
        echo -e "${GREEN}Built${NC} ($DYLIB_PATH)"
    else
        echo -e "${YELLOW}Not built${NC} (run: make)"
    fi
}

usage() {
    echo "Usage: $0 <command> [type]"
    echo ""
    echo "Commands:"
    echo "  download [type]  Download ML model (default: nemo)"
    echo "  start [-d] [type] Start scanner in foreground (default: nemo)"
    echo "                     -d  run as background daemon"
    echo "  stop             Stop the running scanner"
    echo "  status           Show scanner status"
    echo ""
    echo "Scanner types:"
    echo "  nemo           NeMo Guardrails perplexity heuristics (default)"
    echo "  llmguard       LLM Guard PromptInjection scanner"
    echo ""
    echo "Only one scanner runs at a time on $SOCKET."
    echo "Starting a different type auto-stops the current one."
}

case "${1:-}" in
    download)
        do_download "${2:-nemo}"
        ;;
    start)
        shift
        do_start "$@"
        ;;
    stop)
        do_stop
        ;;
    status)
        do_status
        ;;
    -h|--help|help)
        usage
        ;;
    *)
        if [ -n "$1" ]; then
            echo -e "${RED}Unknown command: $1${NC}"
            echo ""
        fi
        usage
        exit 1
        ;;
esac
