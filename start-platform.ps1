<#
.SYNOPSIS
    SecureWatch Platform Launcher for Windows.
.DESCRIPTION
    Launches Docker Desktop if not already running, waits for the daemon to become ready,
    and boots all 8 SecureWatch microservices via Docker Compose.
#>

$ErrorActionPreference = "Continue"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "         SecureWatch Platform Startup Assistant             " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Check if Docker is responding
Write-Host "[*] Checking Docker daemon status..." -ForegroundColor Yellow
$dockerOk = $false
try {
    $info = docker info 2>&1
    if ($LASTEXITCODE -eq 0) {
        $dockerOk = $true
        Write-Host "[+] Docker daemon is currently RUNNING." -ForegroundColor Green
    }
} catch {
    $dockerOk = $false
}

# 2. If Docker is not running, launch Docker Desktop
if (-not $dockerOk) {
    Write-Host "[!] Docker daemon is not running. Attempting to start Docker Desktop..." -ForegroundColor Yellow
    $dockerPath = "C:\Users\DHANUZZ\AppData\Local\Programs\DockerDesktop\Docker Desktop.exe"
    
    if (-not (Test-Path $dockerPath)) {
        $dockerPath = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    }

    if (Test-Path $dockerPath) {
        Write-Host "[*] Launching: $dockerPath" -ForegroundColor Cyan
        Start-Process -FilePath $dockerPath
        Write-Host "[*] Waiting for Docker engine to initialize (this may take 30-45 seconds)..." -ForegroundColor Yellow

        $maxAttempts = 30
        $attempt = 0
        while ($attempt -lt $maxAttempts) {
            Start-Sleep -Seconds 3
            $attempt++
            Write-Host "    Attempt $attempt/$maxAttempts: checking Docker daemon..." -ForegroundColor Gray
            $test = docker info 2>&1
            if ($LASTEXITCODE -eq 0) {
                $dockerOk = $true
                Write-Host "[+] Docker engine is now ONLINE and ready!" -ForegroundColor Green
                break
            }
        }
    } else {
        Write-Host "[!] Docker Desktop executable not found automatically." -ForegroundColor Red
        Write-Host "    Please start Docker Desktop manually from the Windows Start menu." -ForegroundColor Red
    }
}

if (-not $dockerOk) {
    Write-Host "`n[!] Could not connect to Docker engine. Please ensure Docker Desktop is open and the engine is running, then re-run this script." -ForegroundColor Red
    exit 1
}

# 3. Launch Docker Compose
Write-Host "`n[*] Starting all SecureWatch services via Docker Compose..." -ForegroundColor Cyan
docker compose up -d

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n============================================================" -ForegroundColor Green
    Write-Host " SecureWatch Platform Services Started Successfully!       " -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Web Dashboard:        http://localhost:3000" -ForegroundColor White
    Write-Host "  Backend API:          http://localhost:8000" -ForegroundColor White
    Write-Host "  Interactive OpenAPI:  http://localhost:8000/docs" -ForegroundColor White
    Write-Host "  OpenSearch SIEM:      http://localhost:9200" -ForegroundColor White
    Write-Host "  OpenSearch Dashboards:http://localhost:5601" -ForegroundColor White
    Write-Host ""
    Write-Host "  Default Admin Credentials:" -ForegroundColor Yellow
    Write-Host "    Username: admin" -ForegroundColor Yellow
    Write-Host "    Password: SecureWatch@2026!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  Endpoint Agent Enrollment Instructions:" -ForegroundColor Cyan
    Write-Host "------------------------------------------------------------" -ForegroundColor Cyan
    Write-Host "  1. Log into http://localhost:3000 with admin credentials" -ForegroundColor White
    Write-Host "  2. Go to 'Devices' -> 'Generate Enrollment Token'" -ForegroundColor White
    Write-Host "  3. Enroll and start your agent in PowerShell:" -ForegroundColor White
    Write-Host "       cd endpoint-agent" -ForegroundColor Gray
    Write-Host "       python main.py --enroll --server-url http://localhost:8000 --token <YOUR_TOKEN>" -ForegroundColor Gray
    Write-Host "       python main.py --start" -ForegroundColor Gray
    Write-Host "============================================================" -ForegroundColor Green
} else {
    Write-Host "[!] Docker Compose failed to start containers. Check docker logs." -ForegroundColor Red
}
