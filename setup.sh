#!/bin/bash
# PYC2 Setup Script
# Automated setup for C2 framework

set -e

echo "======================================"
echo "  PYC2 Framework Setup"
echo "======================================"
echo ""

# Check Python version
echo "[*] Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "[!] Python 3.8 or higher is required. Current version: $PYTHON_VERSION"
    exit 1
fi

echo "[+] Python version: $PYTHON_VERSION"

# Install dependencies
echo ""
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "[!] Failed to install dependencies. Trying with --user flag..."
    pip3 install --user -r requirements.txt
fi

# Create necessary directories
echo ""
echo "[*] Creating directory structure..."
mkdir -p agents
mkdir -p lolbas_templates
mkdir -p screenshots
mkdir -p icons

# Set permissions
echo ""
echo "[*] Setting file permissions..."
chmod +x c2_gui.py
chmod +x agents/*.py 2>/dev/null || true

# Test imports
echo ""
echo "[*] Testing imports..."
python3 << EOF
try:
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QIcon
    print("[+] PyQt6 imported successfully")
except ImportError as e:
    print(f"[!] Failed to import PyQt6: {e}")
    exit(1)
EOF

if [ $? -ne 0 ]; then
    echo "[!] Setup failed. Please check the error messages above."
    exit 1
fi

# Display success message
echo ""
echo "======================================"
echo "  Setup Complete!"
echo "======================================"
echo ""
echo "To start the C2 framework:"
echo "  python3 c2_gui.py"
echo ""
echo "Quick Start:"
echo "  1. Set LHOST and LPORT"
echo "  2. Click 'Start Listener'"
echo "  3. Generate payload"
echo "  4. Deploy on target"
echo ""
echo "Documentation:"
echo "  - README.md       : Full documentation"
echo "  - QUICKSTART.md   : Quick start guide"
echo "  - DEPLOYMENT.md   : Agent deployment guide"
echo ""
echo "⚠️  IMPORTANT: Use only with proper authorization!"
echo "======================================"
