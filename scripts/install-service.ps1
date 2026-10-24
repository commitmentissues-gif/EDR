<#
.SYNOPSIS
    Installs the LocalEDR Endpoint Agent as a native Windows Service.
.DESCRIPTION
    Configures LocalEDR_Agent with SERVICE_AUTO_START so it launches automatically
    on Windows boot. Sets automatic failure recovery actions to restart after unexpected crashes.
#>

[CmdletBinding()]
param (
    [string]$ServiceName = "LocalEDR_Agent",
    [string]$DisplayName = "LocalEDR Endpoint Defense Agent",
    [string]$BinaryPath = ""
)

# 1. Require Administrator Privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[!] Administrator privileges required. Please right-click PowerShell and choose 'Run as Administrator'."
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         LocalEDR Windows Service Installation            " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$AppDir = Split-Path -Parent $PSScriptRoot

# 2. Locate Executable Binary
if (-not $BinaryPath) {
    $dotnetExe = Join-Path $AppDir "agent\windows\bin\Release\net8.0\win-x64\publish\LocalEDR_Agent.exe"
    $nodeExe = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
    $serverScript = Join-Path $AppDir "server.js"

    if (Test-Path $dotnetExe) {
        $BinaryPath = $dotnetExe
        Write-Host "[+] Found compiled native .NET agent binary: $BinaryPath" -ForegroundColor Green
    } elseif ($nodeExe -and (Test-Path $serverScript)) {
        $BinaryPath = "`"$nodeExe`" `"$serverScript`""
        Write-Host "[+] Found Node.js service host: $BinaryPath" -ForegroundColor Green
    } else {
        # Fallback to local worker host
        $BinaryPath = "`"$nodeExe`" `"$AppDir\server.ts`""
        Write-Host "[+] Using server runtime: $BinaryPath" -ForegroundColor Yellow
    }
}

# 3. Check for existing service
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[*] Service '$ServiceName' already exists. Stopping and replacing..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# 4. Create Service with Automatic Startup
Write-Host "[*] Registering service with SCM (Startup: Automatic)..." -ForegroundColor Cyan
& sc.exe create $ServiceName binPath= $BinaryPath start= auto DisplayName= "$DisplayName" | Out-Null

if ($LASTEXITCODE -ne 0) {
    Write-Error "[!] sc.exe create failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

# 5. Set Description
$Description = "LocalEDR lightweight defensive endpoint agent providing local health monitoring, crash resilience, and autonomous defense."
& sc.exe description $ServiceName "$Description" | Out-Null

# 6. Configure Failure Recovery Actions (Survive Crashes & Unexpected Failures)
# Restart after 5s on 1st failure, 5s on 2nd failure, 10s on subsequent failures; reset failure count after 86400s (24h)
Write-Host "[*] Configuring crash resilience & automatic restart rules..." -ForegroundColor Cyan
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/5000/restart/10000 | Out-Null
& sc.exe failureflag $ServiceName 1 | Out-Null

# 7. Register EventLog Source for LocalEDR
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists("LocalEDR")) {
        [System.Diagnostics.EventLog]::CreateEventSource("LocalEDR", "Application")
        Write-Host "[+] Registered Windows Event Log source 'LocalEDR'" -ForegroundColor Green
    }
} catch {
    Write-Warning "Could not register EventLog source: $_"
}

# 8. Start Service
Write-Host "[*] Starting $ServiceName..." -ForegroundColor Cyan
Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# 9. Verify Installation Status
$status = Get-Service -Name $ServiceName
Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "  Service Name  : $($status.Name)" -ForegroundColor Green
Write-Host "  Display Name  : $($status.DisplayName)" -ForegroundColor Green
Write-Host "  Status        : $($status.Status)" -ForegroundColor Green
Write-Host "  Startup Type  : Automatic (Starts on boot)" -ForegroundColor Green
Write-Host "  Failure Action: Auto-restart after 5s" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
