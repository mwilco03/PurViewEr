#!/bin/bash
# PurView Forensic Analyzer - macOS/Linux Installer
set -e

echo "Installing PurView Forensic Analyzer..."

ZIP_URL="https://github.com/mwilco03/PurViewEr/archive/refs/heads/main.zip"
INSTALL_DIR="$HOME/Downloads/PurViewEr"
ZIP_PATH="/tmp/PurViewEr.zip"

# Download the repo zip
if command -v curl &> /dev/null; then
    curl -fsSL "$ZIP_URL" -o "$ZIP_PATH" || {
        echo "Error: Download failed" >&2
        exit 1
    }
elif command -v wget &> /dev/null; then
    wget -q "$ZIP_URL" -O "$ZIP_PATH" || {
        echo "Error: Download failed" >&2
        exit 1
    }
else
    echo "Error: Neither curl nor wget found" >&2
    exit 1
fi

# Verify download
if [[ ! -f "$ZIP_PATH" ]] || [[ $(wc -c < "$ZIP_PATH") -le 10240 ]]; then
    echo "Error: Download verification failed" >&2
    exit 1
fi

# Extract and clean up
rm -rf "$INSTALL_DIR"
unzip -qo "$ZIP_PATH" -d "$HOME/Downloads"
mv "$HOME/Downloads/PurViewEr-main" "$INSTALL_DIR"
rm -f "$ZIP_PATH"

# Open in default browser
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$INSTALL_DIR/index.html" 2>/dev/null
elif command -v xdg-open &> /dev/null; then
    xdg-open "$INSTALL_DIR/index.html" 2>/dev/null
fi

echo ""
echo "Installation complete. Application opened in your browser."
echo "File location: $INSTALL_DIR/index.html"
echo ""
echo "How to start:"
echo "  1. Drag and drop Purview CSV files onto the browser window"
echo "  2. Classify IPs and import IOCs as needed"
echo "  3. Use filters to investigate activity"
