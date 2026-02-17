#!/usr/bin/env python3
"""
LLM Guard-based prompt injection scanner sidecar.
Listens on a Unix domain socket for file content and returns detection results.

Usage:
    python injection_scanner.py [--socket /path/to/socket]
"""

import os
import sys
import json
import socket
import argparse
import struct
import threading
from pathlib import Path

# Lazy import to avoid startup delay if not needed
scanner = None
scanner_lock = threading.Lock()

DEFAULT_SOCKET = "/tmp/content-filter-scanner.sock"


def get_scanner():
    """Lazy-load the LLM Guard scanner on first use."""
    global scanner
    if scanner is None:
        with scanner_lock:
            if scanner is None:
                print("[scanner] Loading LLM Guard PromptInjection scanner...", file=sys.stderr)
                try:
                    from llm_guard.input_scanners import PromptInjection
                    from llm_guard.input_scanners.prompt_injection import MatchType

                    # Use FULL match type for better accuracy on longer prompts
                    scanner = PromptInjection(threshold=0.5, match_type=MatchType.FULL)
                    print("[scanner] Scanner loaded successfully", file=sys.stderr)
                except ImportError as e:
                    print(f"[scanner] ERROR: Failed to import llm_guard: {e}", file=sys.stderr)
                    print("[scanner] Install with: pip install llm-guard", file=sys.stderr)
                    return None
    return scanner


def scan_content(content: str) -> dict:
    """
    Scan content for prompt injection using LLM Guard.

    Returns:
        dict with keys:
            - is_injection: bool
            - risk_score: float (0.0-1.0)
            - sanitized: str (sanitized content if injection detected)
            - error: str (if scanner unavailable)
    """
    s = get_scanner()
    if s is None:
        return {
            "is_injection": False,
            "risk_score": 0.0,
            "sanitized": content,
            "error": "Scanner not available"
        }

    try:
        sanitized, is_valid, risk_score = s.scan(content)
        return {
            "is_injection": not is_valid,
            "risk_score": risk_score,
            "sanitized": sanitized if not is_valid else content,
            "error": None
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
        print(f"[scanner] Client error: {e}", file=sys.stderr)
    finally:
        conn.close()


def run_server(socket_path: str):
    """Run the scanner server."""
    # Remove existing socket
    if os.path.exists(socket_path):
        os.unlink(socket_path)

    # Pre-load scanner
    print(f"[scanner] Starting injection scanner on {socket_path}", file=sys.stderr)
    get_scanner()

    # Create socket
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(5)

    # Make socket accessible
    os.chmod(socket_path, 0o666)

    print(f"[scanner] Listening on {socket_path}", file=sys.stderr)

    try:
        while True:
            conn, _ = server.accept()
            # Handle in thread to allow concurrent requests
            t = threading.Thread(target=handle_client, args=(conn,), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[scanner] Shutting down", file=sys.stderr)
    finally:
        server.close()
        if os.path.exists(socket_path):
            os.unlink(socket_path)


def main():
    parser = argparse.ArgumentParser(description="LLM Guard injection scanner sidecar")
    parser.add_argument("--socket", "-s", default=DEFAULT_SOCKET,
                        help=f"Unix socket path (default: {DEFAULT_SOCKET})")
    args = parser.parse_args()

    run_server(args.socket)


if __name__ == "__main__":
    main()
