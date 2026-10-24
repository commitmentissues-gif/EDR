<#
.SYNOPSIS
    Uninstalls the LocalEDR Endpoint Agent Windows Service.
.DESCRIPTION
    Gracefully halts the running service and removes it from Windows Service Control Manager.
#>

[CmdletBinding()]
param (
    [string]$ServiceName = "LocalEDR_Agent"
)

# Require Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[!] Administrator privileges required. Please right-click PowerShell and choose 'Run as Administrator'."
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "        LocalEDR Windows Service Uninstallation           " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Warning "Service '$ServiceName' is not installed."
    exit 0
}

# 1. Gracefully Stop if Running
if ($svc.Status -eq 'Running') {
    Write-Host "[*] Stopping running service '$ServiceName'..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(10))
}

# 2. Delete Service Registration
Write-Host "[*] Deleting service from Service Control Manager..." -ForegroundColor Cyan
& sc.exe delete $ServiceName

if ($LASTEXITCODE -eq 0) {
    Write-Host "[+] Service '$ServiceName' successfully uninstalled." -ForegroundColor Green
} else {
    Write-Error "[!] Failed to delete service. Exit code: $LASTEXITCODE"
}
