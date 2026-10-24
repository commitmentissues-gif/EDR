<#
.SYNOPSIS
    Gracefully stops the LocalEDR Endpoint Agent Windows Service.
#>

[CmdletBinding()]
param (
    [string]$ServiceName = "LocalEDR_Agent",
    [int]$TimeoutSeconds = 15
)

# Require Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[!] Administrator privileges required. Please right-click PowerShell and choose 'Run as Administrator'."
    exit 1
}

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Warning "Service '$ServiceName' is not installed."
    exit 0
}

if ($svc.Status -eq 'Stopped') {
    Write-Host "[*] Service '$ServiceName' is already stopped." -ForegroundColor Yellow
    exit 0
}

Write-Host "[*] Requesting graceful stop for '$ServiceName' (Timeout: ${TimeoutSeconds}s)..." -ForegroundColor Cyan
Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue

try {
    $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds($TimeoutSeconds))
    Write-Host "[+] Service '$ServiceName' stopped gracefully." -ForegroundColor Green
} catch {
    Write-Warning "Service did not stop within ${TimeoutSeconds}s. Terminating forcefully..."
    Stop-Service -Name $ServiceName -Force
}
