#!/bin/bash
# PurView Forensic Analyzer - macOS/Linux Installer
# Downloads and launches the offline application

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  PurView Forensic Analyzer Installer  ${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Configuration
GITHUB_RAW_URL="https://raw.githubusercontent.com/mwilco03/PurViewEr/main/index.html"

# Determine download location
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    LOCAL_PATH="$HOME/Downloads/purview-forensic-analyzer.html"
else
    # Linux
    LOCAL_PATH="$HOME/Downloads/purview-forensic-analyzer.html"
fi

echo -e "${YELLOW}[1/3] Downloading application...${NC}"

# Download the HTML file
if command -v curl &> /dev/null; then
    if curl -fsSL "$GITHUB_RAW_URL" -o "$LOCAL_PATH"; then
        echo -e "      ${GREEN}✓ Downloaded to: $LOCAL_PATH${NC}"
    else
        echo -e "      ${RED}✗ Download failed${NC}"
        echo ""
        echo -e "${YELLOW}Troubleshooting:${NC}"
        echo "  1. Check your internet connection"
        echo "  2. Verify the GitHub repository is accessible"
        echo "  3. Try downloading manually from:"
        echo "     $GITHUB_RAW_URL"
        echo ""
        exit 1
    fi
elif command -v wget &> /dev/null; then
    if wget -q "$GITHUB_RAW_URL" -O "$LOCAL_PATH"; then
        echo -e "      ${GREEN}✓ Downloaded to: $LOCAL_PATH${NC}"
    else
        echo -e "      ${RED}✗ Download failed${NC}"
        echo ""
        echo -e "${YELLOW}Troubleshooting:${NC}"
        echo "  1. Check your internet connection"
        echo "  2. Verify the GitHub repository is accessible"
        echo "  3. Try downloading manually from:"
        echo "     $GITHUB_RAW_URL"
        echo ""
        exit 1
    fi
else
    echo -e "      ${RED}✗ Neither curl nor wget found${NC}"
    echo "      Please install curl or wget and try again"
    exit 1
fi

echo -e "${YELLOW}[2/3] Verifying download...${NC}"

if [[ -f "$LOCAL_PATH" ]]; then
    FILE_SIZE=$(wc -c < "$LOCAL_PATH")
    if [[ $FILE_SIZE -gt 10240 ]]; then
        FILE_SIZE_KB=$((FILE_SIZE / 1024))
        echo -e "      ${GREEN}✓ File verified (${FILE_SIZE_KB} KB)${NC}"
    else
        echo -e "      ${RED}✗ File too small, download may have failed${NC}"
        exit 1
    fi
else
    echo -e "      ${RED}✗ File not found at $LOCAL_PATH${NC}"
    exit 1
fi

echo -e "${YELLOW}[3/3] Launching application...${NC}"

# Open in default browser
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    if open "$LOCAL_PATH"; then
        echo -e "      ${GREEN}✓ Application opened in your default browser${NC}"
    else
        echo -e "      ${RED}✗ Failed to open browser${NC}"
        echo -e "      ${YELLOW}→ Please open manually: $LOCAL_PATH${NC}"
    fi
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    if command -v xdg-open &> /dev/null; then
        if xdg-open "$LOCAL_PATH" 2>/dev/null; then
            echo -e "      ${GREEN}✓ Application opened in your default browser${NC}"
        else
            echo -e "      ${RED}✗ Failed to open browser${NC}"
            echo -e "      ${YELLOW}→ Please open manually: $LOCAL_PATH${NC}"
        fi
    else
        echo -e "      ${YELLOW}→ Please open manually: $LOCAL_PATH${NC}"
    fi
else
    echo -e "      ${YELLOW}→ Please open manually: $LOCAL_PATH${NC}"
fi

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${GREEN}  Installation Complete!                ${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""
echo -e "${NC}File Location: ${LOCAL_PATH}${NC}"
echo ""
echo -e "${YELLOW}Usage:${NC}"
echo "  • Drag and drop Purview CSV files onto the browser window"
echo "  • All processing happens locally in your browser"
echo "  • Internet required for first load, then works offline"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "  1. Export audit logs from Microsoft 365 Compliance Center"
echo "  2. Drag CSV files onto the application"
echo "  3. Classify IPs and import IOCs as needed"
echo "  4. Use filters to investigate suspicious activity"
echo ""
echo -e "${CYAN}Bookmark this file for future use: $LOCAL_PATH${NC}"
echo ""
