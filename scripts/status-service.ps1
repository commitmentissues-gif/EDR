<#
.SYNOPSIS
    Queries detailed health, configuration, and runtime status of LocalEDR_Agent.
#>

[CmdletBinding()]
param (
    [string]$ServiceName = "LocalEDR_Agent"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "          LocalEDR Windows Service Status Report          " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. SCM Query
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Warning "Service '$ServiceName' is NOT installed on this machine."
    exit 1
}

$statusColor = if ($svc.Status -eq 'Running') { 'Green' } else { 'Red' }
Write-Host "Service Name   : $($svc.Name)"
Write-Host "Display Name   : $($svc.DisplayName)"
Write-Host "Service State  : " -NoNewline
Write-Host "$($svc.Status)" -ForegroundColor $statusColor
Write-Host "Start Type     : $($svc.StartType)"

# 2. Query SCM Failure Recovery Rules (Survives Crashes)
$qfail = & sc.exe qfailure $ServiceName
$recoveryActions = ($qfail | Select-String "RESTART") -join "; "
if ($recoveryActions) {
    Write-Host "Failure Action : $recoveryActions (Auto-restarts after crash)" -ForegroundColor Green
} else {
    Write-Host "Failure Action : Default SCM" -ForegroundColor Yellow
}

# 3. Process & Memory Inspection
$AppDir = Split-Path -Parent $PSScriptRoot
$healthFile = Join-Path $AppDir "data\service-health.json"

if (Test-Path $healthFile) {
    try {
        $health = Get-Content $healthFile -Raw | ConvertFrom-Json
        Write-Host ""
        Write-Host "--- Internal Health Diagnostics ---" -ForegroundColor Cyan
        Write-Host "Health Status  : $($health.status)" -ForegroundColor Green
        Write-Host "Process PID    : $($health.processId)"
        Write-Host "Uptime (sec)   : $($health.uptimeSeconds)s"
        Write-Host "Working Set MB : $($health.memory.workingSetMb) MB"
        Write-Host "Private RAM MB : $($health.memory.privateMemoryMb) MB"
        Write-Host "Database Check : $($health.database.accessible) (Size: $($health.database.sizeBytes) bytes)"
        Write-Host "Last Check-in  : $($health.timestamp)"
    } catch {
        Write-Warning "Could not parse health diagnostics file."
    }
}

# 4. Recent Service Log Snippet
$logFile = Join-Path $AppDir "data\logs\service.log"
if (Test-Path $logFile) {
    Write-Host ""
    Write-Host "--- Recent Service Log Entries ---" -ForegroundColor Cyan
    Get-Content $logFile -Tail 5 | ForEach-Object {
        Write-Host "  $_" -ForegroundColor DarkGray
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
