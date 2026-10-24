<#
.SYNOPSIS
    Restarts the LocalEDR Endpoint Agent Windows Service.
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
    Write-Error "[!] Service '$ServiceName' is not installed."
    exit 1
}

Write-Host "[*] Restarting $ServiceName..." -ForegroundColor Cyan
Restart-Service -Name $ServiceName -Force

$svc.WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
$svc.Refresh()

if ($svc.Status -eq 'Running') {
    Write-Host "[+] Service '$ServiceName' restarted and running." -ForegroundColor Green
} else {
    Write-Error "[!] Restart failed. Current status: $($svc.Status)"
    exit 1
}
