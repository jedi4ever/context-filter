#!/usr/bin/env python3
"""
NeMo Guardrails-based prompt injection scanner sidecar.
Uses GPT-2 perplexity heuristics to detect jailbreak attempts.

Listens on a Unix domain socket for file content and returns detection results.

Usage:
    python nemo_scanner.py [--socket /path/to/socket]

Note: This scanner is optimized for detecting adversarial/GCG-style jailbreaks.
For simple prompt injections like "ignore instructions", llm-guard is better.
"""

import os
import sys
import json
import socket
import argparse
import struct
import threading

# Lazy imports
checks_module = None
checks_lock = threading.Lock()

DEFAULT_SOCKET = "/tmp/claude-nemo-scanner.sock"

# Thresholds from NeMo defaults
LENGTH_PER_PERPLEXITY_THRESHOLD = 89.79
PREFIX_SUFFIX_PERPLEXITY_THRESHOLD = 1845.65


def get_checks():
    """Lazy-load the NeMo jailbreak checks on first use."""
    global checks_module
    if checks_module is None:
        with checks_lock:
            if checks_module is None:
                print("[nemo] Loading NeMo jailbreak heuristics (GPT-2 model)...", file=sys.stderr)
                try:
                    from nemoguardrails.library.jailbreak_detection.heuristics import checks
                    checks_module = checks
                    print("[nemo] Heuristics loaded successfully", file=sys.stderr)
                except ImportError as e:
                    print(f"[nemo] ERROR: Failed to import nemoguardrails: {e}", file=sys.stderr)
                    print("[nemo] Install with: pip install nemoguardrails", file=sys.stderr)
                    return None
                except Exception as e:
                    print(f"[nemo] ERROR: Failed to initialize: {e}", file=sys.stderr)
                    return None
    return checks_module


def scan_content(content: str) -> dict:
    """
    Scan content for jailbreak attempts using NeMo perplexity heuristics.

    Uses two checks:
    1. Length/perplexity ratio - detects suspiciously low perplexity for content length
    2. Prefix/suffix perplexity - detects GCG-style adversarial suffixes

    Returns:
        dict with keys:
            - is_injection: bool
            - risk_score: float (0.0-1.0)
            - sanitized: str
            - error: str (if scanner unavailable)
            - details: dict with check results
    """
    checks = get_checks()
    if checks is None:
        return {
            "is_injection": False,
            "risk_score": 0.0,
            "sanitized": content,
            "error": "Scanner not available"
        }

    try:
        # Run both heuristic checks
        lp_result = checks.check_jailbreak_length_per_perplexity(
            content, LENGTH_PER_PERPLEXITY_THRESHOLD
        )
        ps_result = checks.check_jailbreak_prefix_suffix_perplexity(
            content, PREFIX_SUFFIX_PERPLEXITY_THRESHOLD
        )

        is_jailbreak = lp_result.get("jailbreak", False) or ps_result.get("jailbreak", False)

        # Calculate a risk score
        risk_score = 0.0
        if lp_result.get("jailbreak"):
            risk_score += 0.5
        if ps_result.get("jailbreak"):
            risk_score += 0.5

        return {
            "is_injection": is_jailbreak,
            "risk_score": risk_score,
            "sanitized": "" if is_jailbreak else content,
            "error": None,
            "details": {
                "length_perplexity_check": lp_result,
                "prefix_suffix_check": ps_result
            }
        }
    except Exception as e:
        return {
            "is_injection": False,
            "risk_score": 0.0,
            "sanitized": content,
            "error": str(e)
        }


def handle_client(conn):
    """Handle a single client connection."""
    try:
        # Protocol:
        # Request: 4-byte length (big-endian) + content bytes
        # Response: 4-byte length (big-endian) + JSON response bytes

        # Read length prefix
        length_data = conn.recv(4)
        if len(length_data) < 4:
            return

        content_length = struct.unpack(">I", length_data)[0]

        # Sanity check
        if content_length > 10 * 1024 * 1024:  # 10MB max
            response = {"error": "Content too large"}
        else:
            # Read content
            content = b""
            while len(content) < content_length:
                chunk = conn.recv(min(65536, content_length - len(content)))
                if not chunk:
                    break
                content += chunk

            if len(content) == content_length:
                # Decode and scan
                try:
                    text = content.decode("utf-8", errors="replace")
                    response = scan_content(text)
                except Exception as e:
                    response = {"error": f"Decode error: {e}"}
            else:
                response = {"error": "Incomplete read"}

        # Send response
        response_json = json.dumps(response).encode("utf-8")
        conn.sendall(struct.pack(">I", len(response_json)))
        conn.sendall(response_json)

    except Exception as e:
        print(f"[nemo] Client error: {e}", file=sys.stderr)
    finally:
        conn.close()


def run_server(socket_path: str):
    """Run the scanner server."""
    # Remove existing socket
    if os.path.exists(socket_path):
        os.unlink(socket_path)

    # Pre-load checks (this will download GPT-2 on first run)
    print(f"[nemo] Starting NeMo scanner on {socket_path}", file=sys.stderr)
    get_checks()

    # Create socket
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(5)

    # Make socket accessible
    os.chmod(socket_path, 0o666)

    print(f"[nemo] Listening on {socket_path}", file=sys.stderr)

    try:
        while True:
            conn, _ = server.accept()
            # Handle in thread to allow concurrent requests
            t = threading.Thread(target=handle_client, args=(conn,), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[nemo] Shutting down", file=sys.stderr)
    finally:
        server.close()
        if os.path.exists(socket_path):
            os.unlink(socket_path)


def main():
    parser = argparse.ArgumentParser(description="NeMo Guardrails jailbreak scanner sidecar")
    parser.add_argument("--socket", "-s", default=DEFAULT_SOCKET,
                        help=f"Unix socket path (default: {DEFAULT_SOCKET})")
    args = parser.parse_args()

    run_server(args.socket)


if __name__ == "__main__":
    main()
