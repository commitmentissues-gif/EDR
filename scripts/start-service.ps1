<#
.SYNOPSIS
    Starts the LocalEDR Endpoint Agent Windows Service.
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

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Error "[!] Service '$ServiceName' is not installed. Run scripts\install-service.ps1 first."
    exit 1
}

if ($svc.Status -eq 'Running') {
    Write-Host "[*] Service '$ServiceName' is already running." -ForegroundColor Green
    exit 0
}

Write-Host "[*] Starting $ServiceName..." -ForegroundColor Cyan
Start-Service -Name $ServiceName

$svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(10))
$svc.Refresh()

if ($svc.Status -eq 'Running') {
    Write-Host "[+] Service '$ServiceName' started successfully." -ForegroundColor Green
} else {
    Write-Error "[!] Failed to start service. Current status: $($svc.Status)"
    exit 1
}
