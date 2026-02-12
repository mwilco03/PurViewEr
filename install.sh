#!/bin/bash
# PurView Forensic Analyzer - macOS/Linux Installer
set -e

echo "Installing PurView Forensic Analyzer..."

GITHUB_RAW_URL="https://raw.githubusercontent.com/mwilco03/PurViewEr/main/index.html"
LOCAL_PATH="$HOME/Downloads/purview-forensic-analyzer.html"

# Download the HTML file
if command -v curl &> /dev/null; then
    curl -fsSL "$GITHUB_RAW_URL" -o "$LOCAL_PATH" || {
        echo "Error: Download failed" >&2
        exit 1
    }
elif command -v wget &> /dev/null; then
    wget -q "$GITHUB_RAW_URL" -O "$LOCAL_PATH" || {
        echo "Error: Download failed" >&2
        exit 1
    }
else
    echo "Error: Neither curl nor wget found" >&2
    exit 1
fi

# Verify download
if [[ ! -f "$LOCAL_PATH" ]] || [[ $(wc -c < "$LOCAL_PATH") -le 10240 ]]; then
    echo "Error: Download verification failed" >&2
    exit 1
fi

# Open in default browser
if [[ "$OSTYPE" == "darwin"* ]]; then
    open "$LOCAL_PATH" 2>/dev/null
elif command -v xdg-open &> /dev/null; then
    xdg-open "$LOCAL_PATH" 2>/dev/null
fi

echo ""
echo "Installation complete. Application opened in your browser."
echo "File location: $LOCAL_PATH"
echo ""
echo "How to start:"
echo "  1. Drag and drop Purview CSV files onto the browser window"
echo "  2. Classify IPs and import IOCs as needed"
echo "  3. Use filters to investigate activity"
