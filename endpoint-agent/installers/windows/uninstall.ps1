# ==============================================================================
# SecureWatch Windows Endpoint Agent - Uninstallation Script
# ==============================================================================
# Transparent removal with documented uninstallation process.
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Yellow
Write-Host " SecureWatch Endpoint Agent Uninstaller                  " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Yellow

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Please run PowerShell as Administrator to uninstall SecureWatch."
    exit 1
}

$installDir = "C:\Program Files\SecureWatch"
$configDir = "$env:ProgramData\SecureWatch"

# 1. Stop any running python agent processes
$procs = Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*SecureWatch*" }
if ($procs) {
    Write-Host "[*] Stopping running agent processes..." -ForegroundColor Yellow
    $procs | Stop-Process -Force
}

# 2. Remove files
if (Test-Path $installDir) {
    Remove-Item -Path $installDir -Recurse -Force
    Write-Host "[+] Removed application directory: $installDir" -ForegroundColor Green
}

if (Test-Path $configDir) {
    Remove-Item -Path $configDir -Recurse -Force
    Write-Host "[+] Removed configuration & credentials from: $configDir" -ForegroundColor Green
}

Write-Host "`n[+] SecureWatch Agent has been completely removed from this system." -ForegroundColor Green
