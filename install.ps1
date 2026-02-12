# PurView Forensic Analyzer - Windows Installer
$ErrorActionPreference = "Stop"

Write-Host "Installing PurView Forensic Analyzer..."

$ZipUrl = "https://github.com/mwilco03/PurViewEr/archive/refs/heads/main.zip"
$InstallDir = "$env:USERPROFILE\Downloads\PurViewEr"
$ZipPath = "$env:TEMP\PurViewEr.zip"

try {
    Invoke-WebRequest -Uri $ZipUrl -OutFile $ZipPath -UseBasicParsing -ErrorAction Stop | Out-Null

    if (!(Test-Path $ZipPath) -or (Get-Item $ZipPath).Length -le 10KB) {
        throw "Download verification failed"
    }

    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
    Expand-Archive -Path $ZipPath -DestinationPath "$env:USERPROFILE\Downloads" -Force
    Rename-Item "$env:USERPROFILE\Downloads\PurViewEr-main" $InstallDir -Force
    Remove-Item $ZipPath -Force

    Start-Process "$InstallDir\index.html" -ErrorAction Stop

    Write-Host ""
    Write-Host "Installation complete. Application opened in your browser."
    Write-Host "File location: $InstallDir\index.html"
    Write-Host ""
    Write-Host "How to start:"
    Write-Host "  1. Drag and drop Purview CSV files onto the browser window"
    Write-Host "  2. Classify IPs and import IOCs as needed"
    Write-Host "  3. Use filters to investigate activity"
} catch {
    Write-Error "Installation failed: $_"
    exit 1
}
