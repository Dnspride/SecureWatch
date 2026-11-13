# ==============================================================================
# SecureWatch Windows Endpoint Agent - Installation Script
# ==============================================================================
# Requires Administrator privileges.
# ==============================================================================

param (
    [Parameter(Mandatory=$false)]
    [string]$ServerUrl = "https://soc.company.com",

    [Parameter(Mandatory=$false)]
    [string]$EnrollmentToken = ""
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " SecureWatch Endpoint Agent Installer (Windows 10/11)    " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check Administrator Elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This installer must be run as an Administrator. Please run PowerShell as Administrator."
    exit 1
}

# 2. Check Python installation
$pythonCmd = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    Write-Warning "Python 3 is not found in PATH. Please install Python 3.9+ before continuing."
    exit 1
}

# 3. Create target directory
$installDir = "C:\Program Files\SecureWatch"
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Write-Host "[+] Created installation directory: $installDir" -ForegroundColor Green
}

# 4. Copy Agent Files
$sourceDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Copy-Item -Path "$sourceDir\*" -Destination $installDir -Recurse -Force
Write-Host "[+] Copied SecureWatch agent files." -ForegroundColor Green

# 5. Install dependencies
Write-Host "[*] Installing Python dependencies..." -ForegroundColor Yellow
& python -m pip install -r "$installDir\requirements.txt" --quiet

# 6. Prompt for enrollment if not provided
if (-not $EnrollmentToken) {
    $ServerUrl = Read-Host "Enter SecureWatch Central Server URL (e.g. https://soc.company.com)"
    $EnrollmentToken = Read-Host "Enter Enrollment Token provided by Security Administrator"
}

# 7. Perform Enrollment
Write-Host "[*] Enrolling device..." -ForegroundColor Yellow
Set-Location $installDir
& python main.py --enroll --server-url $ServerUrl --token $EnrollmentToken

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n[+] SecureWatch Agent successfully installed and enrolled!" -ForegroundColor Green
    Write-Host "To start the agent service:"
    Write-Host "    python main.py --start" -ForegroundColor Cyan
} else {
    Write-Error "Device enrollment failed. Please check your token and server URL."
}
