#!/usr/bin/env python3
"""
Unicode Invisible Character Detector
Scans source files for suspicious invisible Unicode characters.
Supports JSON output, CI/CD exit codes, hex context, and YARA rule generation.
"""

import sys, os, json, argparse

RANGES = [
    (0x200B, 0x200F, "Zero-Width Characters"),
    (0x2060, 0x2064, "Invisible Operators"),
    (0x202A, 0x202E, "Bidi Overrides"),
    (0x2066, 0x2069, "Bidi Isolates"),
    (0xFE00, 0xFE0F, "Variation Selectors VS1-16"),
    (0xFEFF, 0xFEFF, "BOM / ZWNBSP"),
    (0xE0000, 0xE007F, "Tag Characters (ASCII Smuggling)"),
    (0xE0100, 0xE01EF, "Variation Selectors VS17-256"),
    (0xF0000, 0xFFFFD, "PUA-A (GlassWorm)"),
    (0xFFA0, 0xFFA0, "Hangul Half-Width Filler"),
    (0x3164, 0x3164, "Hangul Full-Width Filler"),
]

YARA_TEMPLATES = {
    "PUA-A (GlassWorm)": {
        "name": "Invisible_PUA_Payload",
        "desc": "Detects invisible Unicode PUA-A characters used in GlassWorm-style attacks",
        "hex": "{ F3 B0 [2] }",
        "note": "PUA-A chars U+F0000-U+FFFFD encode as F3 B0 xx xx in UTF-8",
    },
    "Tag Characters (ASCII Smuggling)": {
        "name": "Invisible_Tag_Characters",
        "desc": "Detects Unicode Tag characters used in ASCII Smuggling / LLM prompt injection",
        "hex": "{ F3 A0 [2] }",
        "note": "Tag chars U+E0000-U+E007F encode as F3 A0 80 xx in UTF-8",
    },
    "Hangul Half-Width Filler": {
        "name": "Invisible_Hangul_Filler",
        "desc": "Detects Hangul filler characters used in Tycoon 2FA-style encoding",
        "hex": "{ EF BE A0 }",
        "note": "U+FFA0 encodes as EF BE A0 in UTF-8",
    },
    "Variation Selectors VS17-256": {
        "name": "Invisible_Variation_Selectors",
        "desc": "Detects supplementary Variation Selectors used in steganographic encoding",
        "hex": "{ F3 A0 84 [1] }",
        "note": "VS17+ U+E0100-U+E01EF encode as F3 A0 84 xx in UTF-8",
    },
}


def scan_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    raw_bytes = content.encode('utf-8')
    hits = {}

    for i, ch in enumerate(content):
        cp = ord(ch)
        for lo, hi, name in RANGES:
            if lo <= cp <= hi:
                hits.setdefault(name, []).append((i, cp))
                break

    return {
        "file": filepath,
        "total_chars": len(content),
        "findings": hits,
        "raw_bytes": raw_bytes,
    }


def print_text_report(result, hex_context=0):
    filepath = result["file"]
    hits = result["findings"]
    raw_bytes = result["raw_bytes"]

    if not hits:
        print(f"  [CLEAN] {filepath}")
        return

    total = sum(len(v) for v in hits.values())
    print(f"  [ALERT] {filepath}")

    for name, positions in sorted(hits.items(), key=lambda x: -len(x[1])):
        print(f"          {name}: {len(positions)} occurrences")

        if hex_context > 0 and positions:
            first_pos, first_cp = positions[0]
            char_encoded = chr(first_cp).encode('utf-8')
            byte_offset = len(result["file"])  # approximate

            content = open(filepath, 'rb').read()
            pattern = chr(first_cp).encode('utf-8')
            byte_pos = content.find(pattern)

            if byte_pos >= 0:
                start = max(0, byte_pos - hex_context)
                end = min(len(content), byte_pos + len(pattern) + hex_context)
                chunk = content[start:end]

                hex_str = ' '.join(f'{b:02X}' for b in chunk)
                marker_start = (byte_pos - start) * 3
                marker_len = len(pattern) * 3 - 1

                print(f"          Hex context (first occurrence, byte offset {byte_pos}):")
                print(f"          {hex_str}")
                print(f"          {' ' * marker_start}{'^' * marker_len}")
                print(f"          U+{first_cp:04X} = {' '.join(f'{b:02X}' for b in char_encoded)} in UTF-8")

    print(f"          Total: {total} invisible characters\n")


def generate_json_report(results):
    output = {
        "scanned": len(results),
        "alerts": sum(1 for r in results if r["findings"]),
        "clean": sum(1 for r in results if not r["findings"]),
        "findings": []
    }
    for r in results:
        if r["findings"]:
            entry = {
                "file": r["file"],
                "categories": {}
            }
            for name, positions in r["findings"].items():
                entry["categories"][name] = {
                    "count": len(positions),
                    "sample_positions": [p for p, _ in positions[:5]]
                }
            output["findings"].append(entry)
    return json.dumps(output, indent=2)


def generate_yara_rules(results):
    detected_categories = set()
    for r in results:
        detected_categories.update(r["findings"].keys())

    rules = []
    for category in detected_categories:
        if category in YARA_TEMPLATES:
            t = YARA_TEMPLATES[category]
            rules.append(f'''rule {t["name"]} {{
    meta:
        description = "{t["desc"]}"
        note = "{t["note"]}"
    strings:
        $invisible = {t["hex"]}
        $eval = "eval(" ascii
        $spread = "[..." ascii
    condition:
        #invisible > 50 and ($eval or $spread)
}}''')

    if not rules:
        return "// No matching YARA templates for detected character categories"

    return '\n\n'.join(rules)


def main():
    parser = argparse.ArgumentParser(
        description='Unicode Invisible Character Detector — Security Research Tool')
    parser.add_argument('target', nargs='?', default='.',
                        help='File or directory to scan (default: current directory)')
    parser.add_argument('--json', action='store_true',
                        help='Output results as JSON')
    parser.add_argument('--exit-code', action='store_true',
                        help='Exit with code 1 if any alerts found (for CI/CD)')
    parser.add_argument('--hex-context', type=int, default=0, metavar='N',
                        help='Show N bytes of hex context around first finding')
    parser.add_argument('--yara', action='store_true',
                        help='Generate YARA detection rules based on findings')
    parser.add_argument('--extensions', type=str,
                        default='.js,.ts,.mjs,.jsx,.tsx,.json,.md,.html,.py',
                        help='Comma-separated file extensions to scan')
    args = parser.parse_args()

    extensions = tuple(args.extensions.split(','))
    skip_dirs = {'.git', 'node_modules', '__pycache__', '.next', 'dist', 'build'}

    results = []

    if os.path.isfile(args.target):
        results.append(scan_file(args.target))
    else:
        for root, dirs, files in os.walk(args.target):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fn in files:
                if fn.endswith(extensions):
                    results.append(scan_file(os.path.join(root, fn)))

    if args.json:
        print(generate_json_report(results))
    else:
        has_alerts = False
        for r in results:
            print_text_report(r, hex_context=args.hex_context)
            if r["findings"]:
                has_alerts = True

        if args.yara and has_alerts:
            print(f"\n{'='*55}")
            print("  Generated YARA Rules")
            print(f"{'='*55}\n")
            print(generate_yara_rules(results))

    if args.exit_code and any(r["findings"] for r in results):
        sys.exit(1)


if __name__ == '__main__':
    main()
