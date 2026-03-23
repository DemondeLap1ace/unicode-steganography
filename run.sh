#!/bin/bash
set -e
cd "$(dirname "$0")/pua-npm"

echo "======================================================"
echo "  Unicode PUA Invisible Payload — npm PoC"
echo "======================================================"
echo ""

echo "[1/4] Building invisible payload..."
python3 build.py
echo ""

echo "[2/4] Installing package (triggers postinstall)..."
cd consumer && npm install --foreground-scripts
cd ..
echo ""

echo "[3/4] Running detection scan..."
python3 detect.py invisible-utils/ --hex-context 8
echo ""

echo "[4/4] Testing legitimate functionality..."
cd consumer && node app.js
echo ""

echo "======================================================"
echo "  Complete. Check your Desktop for the HTML file."
echo "======================================================"
