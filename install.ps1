# PurView Forensic Analyzer - Windows Installer
# Downloads and launches the offline application

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PurView Forensic Analyzer Installer  " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$GithubRawUrl = "https://raw.githubusercontent.com/mwilco03/PurViewEr/main/index.html"
$LocalPath = "$env:USERPROFILE\Downloads\purview-forensic-analyzer.html"

Write-Host "[1/3] Downloading application..." -ForegroundColor Yellow

try {
    # Download the HTML file
    Invoke-WebRequest -Uri $GithubRawUrl -OutFile $LocalPath -UseBasicParsing
    Write-Host "      ✓ Downloaded to: $LocalPath" -ForegroundColor Green
} catch {
    Write-Host "      ✗ Download failed: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Check your internet connection" -ForegroundColor White
    Write-Host "  2. Verify the GitHub repository is accessible" -ForegroundColor White
    Write-Host "  3. Try downloading manually from:" -ForegroundColor White
    Write-Host "     $GithubRawUrl" -ForegroundColor White
    Write-Host ""
    exit 1
}

Write-Host "[2/3] Verifying download..." -ForegroundColor Yellow

if (Test-Path $LocalPath) {
    $FileSize = (Get-Item $LocalPath).Length
    if ($FileSize -gt 10KB) {
        Write-Host "      ✓ File verified ($([math]::Round($FileSize/1KB, 2)) KB)" -ForegroundColor Green
    } else {
        Write-Host "      ✗ File too small, download may have failed" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "      ✗ File not found at $LocalPath" -ForegroundColor Red
    exit 1
}

Write-Host "[3/3] Launching application..." -ForegroundColor Yellow

try {
    # Open in default browser
    Start-Process $LocalPath
    Write-Host "      ✓ Application opened in your default browser" -ForegroundColor Green
} catch {
    Write-Host "      ✗ Failed to open browser: $_" -ForegroundColor Red
    Write-Host "      → Please open manually: $LocalPath" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Installation Complete!                " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "File Location: $LocalPath" -ForegroundColor White
Write-Host ""
Write-Host "Usage:" -ForegroundColor Yellow
Write-Host "  • Drag and drop Purview CSV files onto the browser window" -ForegroundColor White
Write-Host "  • All processing happens locally in your browser" -ForegroundColor White
Write-Host "  • Internet required for first load, then works offline" -ForegroundColor White
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  1. Export audit logs from Microsoft 365 Compliance Center" -ForegroundColor White
Write-Host "  2. Drag CSV files onto the application" -ForegroundColor White
Write-Host "  3. Classify IPs and import IOCs as needed" -ForegroundColor White
Write-Host "  4. Use filters to investigate suspicious activity" -ForegroundColor White
Write-Host ""
Write-Host "Bookmark this file for future use: $LocalPath" -ForegroundColor Cyan
Write-Host ""
