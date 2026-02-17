#!/usr/bin/env python3
"""Generate patterns_generated.h from patterns.json for the C library."""

import json
import sys
from pathlib import Path

SEVERITY_MAP = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def c_escape(s):
    """Escape a string for use in a C string literal."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <patterns.json> <output.h>", file=sys.stderr)
        sys.exit(1)

    json_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    with open(json_path) as f:
        patterns = json.load(f)

    lines = [
        "/* Auto-generated from patterns.json - DO NOT EDIT */",
        "",
        "static DetectionPattern patterns[] = {",
    ]

    for p in patterns:
        sev = SEVERITY_MAP[p["severity"]]
        name = c_escape(p["name"])
        pattern = c_escape(p["pattern"])
        category = c_escape(p["category"])
        lines.append(f'    {{"{name}",')
        lines.append(f'     "{pattern}",')
        lines.append(f'     "{category}", {sev}, {{0}}, 0}},')
        lines.append("")

    lines.append('    {NULL, NULL, NULL, 0, {0}, 0}  /* Sentinel */')
    lines.append("};")
    lines.append("")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines))
    print(f"Generated {out_path} ({len(patterns)} patterns)", file=sys.stderr)


if __name__ == "__main__":
    main()
