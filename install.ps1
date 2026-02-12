# PurView Forensic Analyzer - Windows Installer
$ErrorActionPreference = "Stop"

Write-Host "Installing PurView Forensic Analyzer..."

$GithubRawUrl = "https://raw.githubusercontent.com/mwilco03/PurViewEr/main/index.html"
$LocalPath = "$env:USERPROFILE\Downloads\purview-forensic-analyzer.html"

try {
    Invoke-WebRequest -Uri $GithubRawUrl -OutFile $LocalPath -UseBasicParsing -ErrorAction Stop | Out-Null

    if (!(Test-Path $LocalPath) -or (Get-Item $LocalPath).Length -le 10KB) {
        throw "Download verification failed"
    }

    Start-Process $LocalPath -ErrorAction Stop

    Write-Host ""
    Write-Host "Installation complete. Application opened in your browser."
    Write-Host "File location: $LocalPath"
    Write-Host ""
    Write-Host "How to start:"
    Write-Host "  1. Drag and drop Purview CSV files onto the browser window"
    Write-Host "  2. Classify IPs and import IOCs as needed"
    Write-Host "  3. Use filters to investigate activity"
} catch {
    Write-Error "Installation failed: $_"
    exit 1
}
